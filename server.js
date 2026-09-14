/* ────────────────────────────────────────────────────────────
   Leave portal — server
   No npm packages. Node 18+.

   Roles
     admin    super user — everything
     manager  sees the whole team, approves and rejects
     member   own requests only

   Environment
     PORT            listening port (Render sets this)
     SECRET          signs the login cookie — set it, or restarts sign everyone out
     KV_URL/KV_TOKEN Upstash REST credentials; both set = hosted storage
     KV_KEY          key name in Redis (default "leaveportal")
     NODE_ENV        "production" marks the cookie Secure
     ADMIN_RESET     "employeeId:newPassword" — resets that account's password
                     once at boot, then REMOVE IT and redeploy
     RESEND_API_KEY  enables email (resend.com)
     MAIL_FROM       e.g. "Leave portal <leave@yourdomain.sa>"
     APP_URL         public URL, used for links inside emails
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
const RESEND    = process.env.RESEND_API_KEY || "";
const MAIL_FROM = process.env.MAIL_FROM || "";
const APP_URL   = (process.env.APP_URL || "").replace(/\/+$/, "");
const SESSION_DAYS = 30;

/* ── storage ─────────────────────────────────────────────── */
let db = { users: [], requests: [] };

async function kvGet() {
  const r = await fetch(`${KV_URL}/get/${KV_KEY}`, { headers: { Authorization: `Bearer ${KV_TOKEN}` } });
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

/* older records used admin:true/false and had no email or openingTaken */
function migrate() {
  let changed = false;
  for (const u of db.users) {
    if (!u.role) { u.role = u.admin ? "admin" : "member"; changed = true; }
    if (u.admin !== undefined) { delete u.admin; changed = true; }
    if (u.openingTaken === undefined) { u.openingTaken = 0; changed = true; }
    if (u.email === undefined) { u.email = ""; changed = true; }
  }
  return changed;
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
  } else {
    try {
      if (fs.existsSync(DATA_FILE)) db = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
      console.log(`  Storage: ${DATA_FILE}`);
    } catch {
      console.error("  data.json unreadable — kept as data.json.broken, starting empty");
      try { fs.renameSync(DATA_FILE, DATA_FILE + ".broken"); } catch {}
    }
  }
  if (migrate()) { await saveDb(); console.log("  Records upgraded to the new user format."); }
}

let saving = false, dirty = false;
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

/* ── passwords & sessions ────────────────────────────────── */
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return salt + ":" + crypto.scryptSync(pw, salt, 64).toString("hex");
}
function checkPw(pw, stored) {
  try {
    const [salt, key] = stored.split(":");
    const a = Buffer.from(key, "hex"), b = crypto.scryptSync(pw, salt, 64);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}
const b64 = (s) => Buffer.from(s).toString("base64url");
const unb64 = (s) => Buffer.from(s, "base64url").toString();
function sign(p) {
  const body = b64(JSON.stringify(p));
  return `${body}.${crypto.createHmac("sha256", SECRET).update(body).digest("base64url")}`;
}
function verify(token) {
  if (typeof token !== "string" || !token.includes(".")) return null;
  const [body, mac] = token.split(".");
  const want = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  const a = Buffer.from(mac || ""), b = Buffer.from(want);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const p = JSON.parse(unb64(body)); return (!p.exp || p.exp < Date.now()) ? null : p; }
  catch { return null; }
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

const isAdmin   = (u) => u && u.role === "admin";
const canReview = (u) => u && (u.role === "admin" || u.role === "manager");

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
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email || "",
  role: u.role, allowance: u.allowance, openingTaken: u.openingTaken || 0 });

/* ── email (Resend REST, no package needed) ──────────────── */
function mailEnabled() { return Boolean(RESEND && MAIL_FROM); }
async function sendMail(to, subject, lines) {
  if (!mailEnabled() || !to) return;
  const link = APP_URL ? `<p style="margin-top:18px"><a href="${APP_URL}"
      style="background:#3B2F84;color:#fff;padding:9px 16px;border-radius:3px;
      text-decoration:none;font-size:14px">Open the portal</a></p>` : "";
  const html = `<div style="font-family:Arial,sans-serif;color:#12082E;font-size:15px;
      line-height:1.6;max-width:520px">
      ${lines.map((l) => `<p style="margin:0 0 10px">${l}</p>`).join("")}
      ${link}
      <p style="margin-top:26px;font-size:12px;color:#9B96AC">
        National Center for Inspection &amp; Monitoring — leave portal</p></div>`;
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${RESEND}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: MAIL_FROM, to: [to], subject, html }),
    });
    if (!r.ok) console.error("Mail rejected:", r.status, (await r.text()).slice(0, 200));
  } catch (e) { console.error("Mail failed:", e.message); }
}
function reviewers() {
  return db.users.filter((u) => canReview(u) && u.email).map((u) => u.email);
}
const dateRange = (r) => `${r.from} → ${r.to} (${r.days} working day${r.days > 1 ? "s" : ""})`;

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
  ".css":"text/css; charset=utf-8", ".png":"image/png", ".ico":"image/x-icon", ".svg":"image/svg+xml" };
function serveStatic(req, res) {
  let rel = req.url.split("?")[0];
  if (rel === "/" || rel === "") rel = "/index.html";
  const file = path.join(PUBLIC, path.normalize(rel).replace(/^(\.\.[/\\])+/, ""));
  if (!file.startsWith(PUBLIC)) { res.writeHead(403); return res.end("Forbidden"); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, { "Content-Type": "text/plain" }); return res.end("Not found"); }
    res.writeHead(200, { "Content-Type": MIME[path.extname(file)] || "application/octet-stream" });
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

  if (url === "/api/health") return send(res, 200, { ok: true, mail: mailEnabled() });

  if (url === "/api/state" && req.method === "GET") {
    if (!db.users.length) return send(res, 200, { stage: "setup" });
    if (!me) return send(res, 200, { stage: "login" });
    const mine = me.role === "member";
    return send(res, 200, {
      stage: "in",
      me: publicUser(me),
      mail: mailEnabled(),
      users: db.users.map(publicUser),
      requests: mine ? db.requests.filter((r) => r.uid === me.id) : db.requests,
    });
  }

  if (url === "/api/setup" && req.method === "POST") {
    if (db.users.length) return send(res, 409, { error: "Already set up." });
    const { name, id, password, email } = body;
    if (!name?.trim() || !id?.trim() || !password || password.length < 6)
      return send(res, 400, { error: "Name, ID and a password of at least 6 characters are needed." });
    db.users.push({ id: id.trim(), name: name.trim(), email: (email || "").trim(),
      pw: hashPw(password), role: "admin", allowance: 30, openingTaken: 0 });
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
  if (url === "/api/me/email" && req.method === "POST") {
    me.email = String(body.email || "").trim(); await saveDb();
    return send(res, 200, { ok: true });
  }

  /* ---- requests ---- */
  if (url === "/api/requests" && req.method === "POST") {
    const { type, from, to, note, forUser } = body;
    let owner = me;
    if (forUser && isAdmin(me)) {
      owner = db.users.find((u) => u.id === forUser);
      if (!owner) return send(res, 404, { error: "No such person." });
    }
    if (!["annual", "sick"].includes(type)) return send(res, 400, { error: "Pick a leave type." });
    if (!validDate(from) || !validDate(to)) return send(res, 400, { error: "Both dates are needed." });
    if (parseD(to) < parseD(from)) return send(res, 400, { error: "The last day is before the first day." });
    const days = workdays(from, to);
    if (!days) return send(res, 400, { error: "That range has no working days in it." });
    const rec = { id: "r" + Date.now().toString(36) + crypto.randomBytes(3).toString("hex"),
      uid: owner.id, name: owner.name, type, from, to, days,
      note: String(note || "").slice(0, 300),
      status: owner.id !== me.id && isAdmin(me) ? "approved" : "pending",
      at: Date.now(), by: owner.id !== me.id && isAdmin(me) ? me.name : null };
    db.requests.push(rec); await saveDb();

    if (rec.status === "pending")
      sendMail(reviewers().join(","), `Leave request — ${owner.name}`,
        [`<b>${owner.name}</b> has requested ${type} leave.`, dateRange(rec),
         rec.note ? `Note: ${rec.note}` : "", "It is waiting for a decision."].filter(Boolean));
    else
      sendMail(owner.email, `Leave recorded — ${rec.from}`,
        [`${me.name} has recorded ${type} leave on your behalf.`, dateRange(rec)]);

    return send(res, 200, { ok: true });
  }

  let m;
  if ((m = url.match(/^\/api\/requests\/(\w+)\/decide$/)) && req.method === "POST") {
    if (!canReview(me)) return send(res, 403, { error: "Managers only." });
    const r = db.requests.find((x) => x.id === m[1]);
    if (!r) return send(res, 404, { error: "That request no longer exists." });
    if (!["approved", "rejected", "pending"].includes(body.status))
      return send(res, 400, { error: "Unknown decision." });
    r.status = body.status;
    if (body.status === "pending") { r.by = null; delete r.decidedAt; }
    else { r.by = me.name; r.decidedAt = Date.now(); }
    await saveDb();

    const owner = db.users.find((u) => u.id === r.uid);
    if (owner && body.status !== "pending")
      sendMail(owner.email, `Leave ${body.status} — ${r.from}`,
        [`Your ${r.type} leave request has been <b>${body.status}</b> by ${me.name}.`,
         dateRange(r)]);
    return send(res, 200, { ok: true });
  }

  if ((m = url.match(/^\/api\/requests\/(\w+)\/edit$/)) && req.method === "POST") {
    const r = db.requests.find((x) => x.id === m[1]);
    if (!r) return send(res, 404, { error: "That request no longer exists." });
    if (!isAdmin(me) && (r.uid !== me.id || r.status !== "pending"))
      return send(res, 403, { error: "You can only change your own pending requests." });
    const { type, from, to, note } = body;
    if (!["annual", "sick"].includes(type)) return send(res, 400, { error: "Pick a leave type." });
    if (!validDate(from) || !validDate(to)) return send(res, 400, { error: "Both dates are needed." });
    if (parseD(to) < parseD(from)) return send(res, 400, { error: "The last day is before the first day." });
    const days = workdays(from, to);
    if (!days) return send(res, 400, { error: "That range has no working days in it." });
    r.type = type; r.from = from; r.to = to; r.days = days;
    r.note = String(note || "").slice(0, 300);
    r.editedBy = me.name; r.editedAt = Date.now();
    await saveDb();
    const owner = db.users.find((u) => u.id === r.uid);
    if (owner && owner.id !== me.id)
      sendMail(owner.email, `Leave request changed — ${r.from}`,
        [`${me.name} has changed your ${r.type} leave request.`, dateRange(r)]);
    return send(res, 200, { ok: true });
  }

  if ((m = url.match(/^\/api\/requests\/(\w+)$/)) && req.method === "DELETE") {
    const r = db.requests.find((x) => x.id === m[1]);
    if (!r) return send(res, 404, { error: "That request no longer exists." });
    if (!isAdmin(me) && (r.uid !== me.id || r.status !== "pending"))
      return send(res, 403, { error: "You can only withdraw your own pending requests." });
    db.requests = db.requests.filter((x) => x.id !== m[1]); await saveDb();
    const owner = db.users.find((u) => u.id === r.uid);
    if (owner && owner.id !== me.id)
      sendMail(owner.email, `Leave removed — ${r.from}`,
        [`${me.name} has removed your ${r.type} leave from the records.`, dateRange(r)]);
    return send(res, 200, { ok: true });
  }

  /* ---- team administration (admin only) ---- */
  if (url === "/api/users" && req.method === "POST") {
    if (!isAdmin(me)) return send(res, 403, { error: "Super user only." });
    const { name, id, password, allowance, role, email, openingTaken } = body;
    if (!name?.trim() || !id?.trim() || !password || password.length < 6)
      return send(res, 400, { error: "Name, ID and a password of at least 6 characters are needed." });
    if (db.users.some((u) => u.id === id.trim()))
      return send(res, 409, { error: "That employee ID is already in use." });
    const r = ["admin", "manager", "member"].includes(role) ? role : "member";
    db.users.push({ id: id.trim(), name: name.trim(), email: (email || "").trim(),
      pw: hashPw(password), role: r,
      allowance: Math.max(0, Math.min(90, Number(allowance) || 30)),
      openingTaken: Math.max(0, Math.min(90, Number(openingTaken) || 0)) });
    await saveDb();
    if (email) sendMail(email.trim(), "You've been added to the leave portal",
      [`${me.name} has set up an account for you.`,
       `Your employee ID is <b>${id.trim()}</b>. Ask ${me.name} for your password.`,
       "Please change it once you sign in."]);
    return send(res, 200, { ok: true });
  }

  if ((m = url.match(/^\/api\/users\/([^/]+)\/(password|allowance|taken|role|email)$/))
      && req.method === "POST") {
    if (!isAdmin(me)) return send(res, 403, { error: "Super user only." });
    const u = db.users.find((x) => x.id === decodeURIComponent(m[1]));
    if (!u) return send(res, 404, { error: "No such person." });
    const field = m[2];

    if (field === "password") {
      if (!body.password || body.password.length < 6)
        return send(res, 400, { error: "Password must be at least 6 characters." });
      u.pw = hashPw(body.password);
      sendMail(u.email, "Your leave portal password was reset",
        [`${me.name} has reset your password. Ask them for the new one.`]);
    }
    else if (field === "allowance" || field === "taken") {
      const n = Number(field === "allowance" ? body.allowance : body.taken);
      if (!Number.isFinite(n) || n < 0 || n > 90)
        return send(res, 400, { error: "Give a number between 0 and 90." });
      if (field === "allowance") u.allowance = Math.round(n);
      else u.openingTaken = Math.round(n);
    }
    else if (field === "role") {
      if (!["admin", "manager", "member"].includes(body.role))
        return send(res, 400, { error: "Unknown role." });
      if (u.id === me.id && body.role !== "admin")
        return send(res, 400, { error: "You can't remove your own super user access." });
      u.role = body.role;
    }
    else if (field === "email") {
      u.email = String(body.email || "").trim();
    }
    await saveDb();
    return send(res, 200, { ok: true });
  }

  if ((m = url.match(/^\/api\/users\/([^/]+)$/)) && req.method === "DELETE") {
    if (!isAdmin(me)) return send(res, 403, { error: "Super user only." });
    const id = decodeURIComponent(m[1]);
    if (id === me.id) return send(res, 400, { error: "You can't remove your own account." });
    if (db.users.filter((u) => u.role === "admin").length === 1
        && db.users.find((u) => u.id === id)?.role === "admin")
      return send(res, 400, { error: "That is the only super user. Promote someone else first." });
    db.users = db.users.filter((u) => u.id !== id); await saveDb();
    return send(res, 200, { ok: true });
  }

  /* ---- csv ---- */
  if (url === "/api/export.csv" && req.method === "GET") {
    if (!canReview(me)) return send(res, 403, { error: "Managers only." });
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

  /* one-shot password recovery */
  if (process.env.ADMIN_RESET) {
    const i = process.env.ADMIN_RESET.indexOf(":");
    const id = process.env.ADMIN_RESET.slice(0, i).trim();
    const pw = process.env.ADMIN_RESET.slice(i + 1);
    const u = db.users.find((x) => x.id === id);
    if (i < 1 || pw.length < 6) {
      console.log("  ADMIN_RESET ignored — use the form  employeeId:newPassword  (6+ chars)");
    } else if (!u) {
      console.log(`  ADMIN_RESET: no account with ID ${id}. Known IDs: ${
        db.users.map((x) => x.id).join(", ") || "(none)"}`);
    } else {
      u.pw = hashPw(pw); u.role = "admin"; await saveDb();
      console.log(`  ADMIN_RESET: password reset for ${u.name} (${id}), role set to admin.`);
      console.log("  >>> Remove the ADMIN_RESET variable and redeploy. <<<");
    }
  }

  if (!process.env.SECRET)
    console.log("  Note: SECRET not set — everyone is signed out when the server restarts.");
  console.log(`  Email: ${mailEnabled() ? "on" : "off (set RESEND_API_KEY and MAIL_FROM)"}`);

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
