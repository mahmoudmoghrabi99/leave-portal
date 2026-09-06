/* ────────────────────────────────────────────────────────────
   Leave portal — server
   No npm packages. Node 18+.

   Storage:
     • Local  — data.json beside this file (default)
     • Hosted — Upstash Redis over HTTP, when KV_URL and KV_TOKEN are set

   Sessions are signed cookies, so a restart does not sign anyone out.
   Set SECRET in production; without it a random one is made each boot.
   ──────────────────────────────────────────────────────────── */

const http = require("http");
const fs   = require("fs");
const path = require("path");
const os   = require("os");
const crypto = require("crypto");

const PORT      = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, "data.json");
const PUBLIC    = path.join(__dirname, "public");
const KV_URL    = process.env.KV_URL || "";
const KV_TOKEN  = process.env.KV_TOKEN || "";
const KV_KEY    = process.env.KV_KEY || "leaveportal";
const USE_KV    = Boolean(KV_URL && KV_TOKEN);
const SECRET    = process.env.SECRET || crypto.randomBytes(32).toString("hex");
const SESSION_DAYS = 30;

/* ── storage ─────────────────────────────────────────────── */
let db = { users: [], requests: [] };
let dirty = false;

async function kvGet() {
  const r = await fetch(`${KV_URL}/get/${KV_KEY}`, {
    headers: { Authorization: `Bearer ${KV_TOKEN}` },
  });
  if (!r.ok) throw new Error(`KV read failed (${r.status})`);
  const j = await r.json();
  return j.result ? JSON.parse(j.result) : null;
}
async function kvSet(obj) {
  const r = await fetch(`${KV_URL}/set/${KV_KEY}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${KV_TOKEN}`, "Content-Type": "text/plain" },
    body: JSON.stringify(obj),
  });
  if (!r.ok) throw new Error(`KV write failed (${r.status})`);
}

async function loadDb() {
  if (USE_KV) {
    try {
      const v = await kvGet();
      if (v) db = v;
      console.log("  Storage: Upstash Redis");
    } catch (e) {
      console.error("  Storage: KV unreachable —", e.message);
      console.error("  Not starting with an empty database. Check KV_URL and KV_TOKEN.");
      process.exit(1);
    }
    return;
  }
  try {
    if (fs.existsSync(DATA_FILE)) db = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    console.log(`  Storage: ${DATA_FILE}`);
  } catch {
    console.error("  data.json unreadable — kept as data.json.broken, starting empty");
    try { fs.renameSync(DATA_FILE, DATA_FILE + ".broken"); } catch {}
  }
}

let saving = false;
async function saveDb() {
  dirty = true;
  if (saving) return;
  saving = true;
  while (dirty) {
    dirty = false;
    try {
      if (USE_KV) await kvSet(db);
      else {
        const tmp = DATA_FILE + ".tmp";
        fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
        fs.renameSync(tmp, DATA_FILE);
      }
    } catch (e) { console.error("Save failed:", e.message); }
  }
  saving = false;
}

/* ── passwords ───────────────────────────────────────────── */
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return salt + ":" + crypto.scryptSync(pw, salt, 64).toString("hex");
}
function checkPw(pw, stored) {
  try {
    const [salt, key] = stored.split(":");
    const a = Buffer.from(key, "hex");
    const b = crypto.scryptSync(pw, salt, 64);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}

/* ── signed session cookies ──────────────────────────────── */
const b64 = (s) => Buffer.from(s).toString("base64url");
const unb64 = (s) => Buffer.from(s, "base64url").toString();
function sign(payload) {
  const body = b64(JSON.stringify(payload));
  return `${body}.${crypto.createHmac("sha256", SECRET).update(body).digest("base64url")}`;
}
function verify(token) {
  if (typeof token !== "string" || !token.includes(".")) return null;
  const [body, mac] = token.split(".");
  const want = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  const a = Buffer.from(mac || ""), b = Buffer.from(want);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(unb64(body));
    return (!p.exp || p.exp < Date.now()) ? null : p;
  } catch { return null; }
}
function cookieFor(uid) {
  const t = sign({ uid, exp: Date.now() + SESSION_DAYS * 86400000 });
  const secure = process.env.NODE_ENV === "production" ? " Secure;" : "";
  return `lp_session=${t}; Path=/; Max-Age=${SESSION_DAYS * 86400}; HttpOnly;${secure} SameSite=Lax`;
}
function userFrom(req) {
  const m = (req.headers.cookie || "").match(/(?:^|;\s*)lp_session=([^;]+)/);
  if (!m) return null;
  const p = verify(decodeURIComponent(m[1]));
  return p ? (db.users.find((u) => u.id === p.uid) || null) : null;
}

/* ── login throttle ──────────────────────────────────────── */
const fails = new Map();
const blocked = (ip) => { const f = fails.get(ip); return f && f.until > Date.now(); };
function noteFail(ip) {
  const f = fails.get(ip) || { n: 0, until: 0 };
  if (++f.n >= 8) { f.until = Date.now() + 300000; f.n = 0; }
  fails.set(ip, f);
}

/* ── domain ──────────────────────────────────────────────── */
const WEEKEND = [5, 6];
const parseD = (s) => { const [y,m,d] = s.split("-").map(Number); return new Date(y, m-1, d); };
const validDate = (s) => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s);
function workdays(a, b) {
  let s = parseD(a), e = parseD(b), n = 0;
  if (e < s) return 0;
  while (s <= e) { if (!WEEKEND.includes(s.getDay())) n++; s.setDate(s.getDate() + 1); }
  return n;
}
const publicUser = (u) => ({ id: u.id, name: u.name, admin: !!u.admin, allowance: u.allowance });

/* ── http plumbing ───────────────────────────────────────── */
function send(res, code, obj, headers = {}) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store", ...headers });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let d = "", size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > 1e5) { reject(new Error("too large")); req.destroy(); return; }
      d += c;
    });
    req.on("end", () => { try { resolve(d ? JSON.parse(d) : {}); } catch { reject(new Error("bad json")); } });
    req.on("error", reject);
  });
}
const MIME = { ".html":"text/html; charset=utf-8", ".js":"text/javascript; charset=utf-8",
  ".css":"text/css; charset=utf-8", ".ico":"image/x-icon", ".svg":"image/svg+xml",
  ".png":"image/png", ".jpg":"image/jpeg", ".jpeg":"image/jpeg", ".webp":"image/webp",
  ".woff2":"font/woff2" };
function serveStatic(req, res) {
  let rel = req.url.split("?")[0];
  if (rel === "/" || rel === "") rel = "/index.html";
  const file = path.join(PUBLIC, path.normalize(rel).replace(/^(\.\.[/\\])+/, ""));
  if (!file.startsWith(PUBLIC)) { res.writeHead(403); return res.end("Forbidden"); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, { "Content-Type": "text/plain" }); return res.end("Not found"); }
    const ext = path.extname(file);
    const cache = [".png",".jpg",".jpeg",".svg",".webp",".ico",".woff2"].includes(ext)
      ? "public, max-age=86400" : "no-cache";
    res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream",
      "Cache-Control": cache });
    res.end(buf);
  });
}

/* ── api ─────────────────────────────────────────────────── */
async function api(req, res, url) {
  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim()
    || req.socket.remoteAddress || "?";
  const me = userFrom(req);
  const withBody = req.method === "POST" || req.method === "DELETE";
  const body = withBody ? await readBody(req).catch(() => null) : {};
  if (withBody && body === null) return send(res, 400, { error: "Bad request body." });

  if (url === "/api/health") return send(res, 200, { ok: true });

  if (url === "/api/state" && req.method === "GET") {
    if (!db.users.length) return send(res, 200, { stage: "setup" });
    if (!me) return send(res, 200, { stage: "login" });
    return send(res, 200, { stage: "in", me: publicUser(me),
      users: db.users.map(publicUser), requests: db.requests });
  }

  if (url === "/api/setup" && req.method === "POST") {
    if (db.users.length) return send(res, 409, { error: "Already set up." });
    const { name, id, password } = body;
    if (!name?.trim() || !id?.trim() || !password || password.length < 6)
      return send(res, 400, { error: "Name, ID and a password of at least 6 characters are needed." });
    db.users.push({ id: id.trim(), name: name.trim(), pw: hashPw(password), admin: true, allowance: 30 });
    await saveDb();
    return send(res, 200, { ok: true }, { "Set-Cookie": cookieFor(id.trim()) });
  }

  if (url === "/api/login" && req.method === "POST") {
    if (blocked(ip)) return send(res, 429, { error: "Too many attempts. Try again in five minutes." });
    const u = db.users.find((x) => x.id === String(body.id || "").trim());
    if (!u || !checkPw(String(body.password || ""), u.pw)) {
      noteFail(ip);
      return send(res, 401, { error: "That ID and password don't match." });
    }
    fails.delete(ip);
    return send(res, 200, { ok: true }, { "Set-Cookie": cookieFor(u.id) });
  }
  if (url === "/api/logout" && req.method === "POST")
    return send(res, 200, { ok: true },
      { "Set-Cookie": "lp_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax" });

  if (!me) return send(res, 401, { error: "Sign in first." });

  if (url === "/api/me/password" && req.method === "POST") {
    if (!checkPw(String(body.current || ""), me.pw))
      return send(res, 400, { error: "Current password is wrong." });
    if (!body.next || body.next.length < 6)
      return send(res, 400, { error: "New password must be at least 6 characters." });
    me.pw = hashPw(body.next); await saveDb();
    return send(res, 200, { ok: true });
  }

  if (url === "/api/requests" && req.method === "POST") {
    const { type, from, to, note } = body;
    if (!["annual", "sick"].includes(type)) return send(res, 400, { error: "Pick a leave type." });
    if (!validDate(from) || !validDate(to)) return send(res, 400, { error: "Both dates are needed." });
    if (parseD(to) < parseD(from)) return send(res, 400, { error: "The last day is before the first day." });
    const days = workdays(from, to);
    if (!days) return send(res, 400, { error: "That range has no working days in it." });
    db.requests.push({ id: "r" + Date.now().toString(36) + crypto.randomBytes(3).toString("hex"),
      uid: me.id, name: me.name, type, from, to, days,
      note: String(note || "").slice(0, 300), status: "pending", at: Date.now(), by: null });
    await saveDb();
    return send(res, 200, { ok: true });
  }

  let m;
  if ((m = url.match(/^\/api\/requests\/(\w+)\/decide$/)) && req.method === "POST") {
    if (!me.admin) return send(res, 403, { error: "Managers only." });
    const r = db.requests.find((x) => x.id === m[1]);
    if (!r) return send(res, 404, { error: "That request no longer exists." });
    if (!["approved", "rejected"].includes(body.status))
      return send(res, 400, { error: "Unknown decision." });
    r.status = body.status; r.by = me.name; r.decidedAt = Date.now();
    await saveDb();
    return send(res, 200, { ok: true });
  }
  if ((m = url.match(/^\/api\/requests\/(\w+)$/)) && req.method === "DELETE") {
    const r = db.requests.find((x) => x.id === m[1]);
    if (!r) return send(res, 404, { error: "That request no longer exists." });
    if (r.uid !== me.id || r.status !== "pending")
      return send(res, 403, { error: "You can only withdraw your own pending requests." });
    db.requests = db.requests.filter((x) => x.id !== m[1]); await saveDb();
    return send(res, 200, { ok: true });
  }

  if (url === "/api/users" && req.method === "POST") {
    if (!me.admin) return send(res, 403, { error: "Managers only." });
    const { name, id, password, allowance, admin } = body;
    if (!name?.trim() || !id?.trim() || !password || password.length < 6)
      return send(res, 400, { error: "Name, ID and a password of at least 6 characters are needed." });
    if (db.users.some((u) => u.id === id.trim()))
      return send(res, 409, { error: "That employee ID is already in use." });
    db.users.push({ id: id.trim(), name: name.trim(), pw: hashPw(password),
      admin: !!admin, allowance: Math.max(0, Math.min(90, Number(allowance) || 30)) });
    await saveDb();
    return send(res, 200, { ok: true });
  }
  if ((m = url.match(/^\/api\/users\/([^/]+)\/password$/)) && req.method === "POST") {
    if (!me.admin) return send(res, 403, { error: "Managers only." });
    const u = db.users.find((x) => x.id === decodeURIComponent(m[1]));
    if (!u) return send(res, 404, { error: "No such person." });
    if (!body.password || body.password.length < 6)
      return send(res, 400, { error: "Password must be at least 6 characters." });
    u.pw = hashPw(body.password); await saveDb();
    return send(res, 200, { ok: true });
  }
  if ((m = url.match(/^\/api\/users\/([^/]+)$/)) && req.method === "DELETE") {
    if (!me.admin) return send(res, 403, { error: "Managers only." });
    const id = decodeURIComponent(m[1]);
    if (id === me.id) return send(res, 400, { error: "You can't remove your own account." });
    db.users = db.users.filter((u) => u.id !== id); await saveDb();
    return send(res, 200, { ok: true });
  }

  if (url === "/api/export.csv" && req.method === "GET") {
    if (!me.admin) return send(res, 403, { error: "Managers only." });
    const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const rows = [["Employee ID","Name","Type","First day","Last day","Working days",
      "Status","Decided by","Note","Submitted"].map(q).join(",")];
    for (const r of db.requests)
      rows.push([r.uid, r.name, r.type, r.from, r.to, r.days, r.status, r.by || "",
        r.note || "", new Date(r.at).toISOString().slice(0,10)].map(q).join(","));
    res.writeHead(200, { "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": 'attachment; filename="leave-requests.csv"' });
    return res.end("\uFEFF" + rows.join("\r\n"));
  }

  return send(res, 404, { error: "Unknown endpoint." });
}

/* ── boot ────────────────────────────────────────────────── */
(async () => {
  console.log("\n  Leave portal");
  await loadDb();
  if (!process.env.SECRET)
    console.log("  Note: SECRET not set — everyone is signed out when the server restarts.");

  http.createServer((req, res) => {
    const url = req.url.split("?")[0];
    if (url.startsWith("/api/")) {
      api(req, res, url).catch((e) => {
        console.error(e);
        if (!res.headersSent) send(res, 500, { error: "Something went wrong on the server." });
      });
    } else serveStatic(req, res);
  }).listen(PORT, "0.0.0.0", () => {
    console.log(`\n  Listening on port ${PORT}`);
    console.log(`  Local:  http://localhost:${PORT}`);
    const nets = os.networkInterfaces();
    for (const name of Object.keys(nets))
      for (const n of nets[name])
        if (n.family === "IPv4" && !n.internal) console.log(`  LAN:    http://${n.address}:${PORT}`);
    console.log("");
  });
})();
