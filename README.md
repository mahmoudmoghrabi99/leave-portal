# Leave portal

A small website for annual and sick leave requests. You approve, the team submits.

No npm packages. Node 18+ is the only requirement.

---

## Put it online — Render + Upstash

About fifteen minutes. Both free, neither asks for a card.

### 1. Somewhere to keep the data

Free hosts wipe their disk whenever the app restarts, so the records live in a
hosted store instead.

1. Sign up at **upstash.com** → **Create Database** → Redis
2. Pick a region near you (Bahrain or Frankfurt for Saudi)
3. Open the database → **REST API** section
4. Copy `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`

### 2. Get the code onto GitHub

1. Sign up at **github.com**
2. **New repository** → name it `leave-portal` → Private → Create
3. On the next page use **uploading an existing file** and drag in everything
   from this folder (including the `public` folder)
4. Commit

### 3. Deploy

1. Sign up at **render.com** with your GitHub account
2. **New** → **Web Service** → pick your `leave-portal` repository
3. Settings:
   - Runtime: **Node**
   - Build command: leave blank
   - Start command: `node server.js`
   - Instance type: **Free**
4. Open **Environment** and add four variables:

   | Key | Value |
   |---|---|
   | `KV_URL` | the Upstash REST URL |
   | `KV_TOKEN` | the Upstash REST token |
   | `SECRET` | any long random string you invent |
   | `NODE_ENV` | `production` |

5. **Create Web Service**

Two or three minutes later you get a URL like
`https://leave-portal-xxxx.onrender.com`. That is the link for the team, and it
works from anywhere — office, home, phone.

### 4. First use

Open the link. It asks you to create the manager account: your name, your
employee ID, a password. Then go to **Team** and add everyone else with their
own ID and a starting password.

---

## Running it on your own machine instead

Windows: double-click `start-windows.bat`
Mac/Linux: `./start-mac-linux.sh`
Or: `node server.js`

With no `KV_URL` set it keeps everything in `data.json` beside `server.js`.
Only people on the same network can reach it.

---

## What it does

- Working days exclude Friday and Saturday
- Sick leave doesn't come off the annual balance
- Warns the requester when their dates overlap someone already off
- Warns when a request goes past the remaining balance — it still submits, and
  you see the shortfall when deciding
- Coverage strip showing who is away across a month
- **Download all as CSV** on the Approvals tab

---

## Things to know

**Render's free tier sleeps.** After fifteen minutes with nobody on it, the
first visit takes about thirty seconds to wake up. Subsequent visits are
instant. Paid tiers start around $7 a month if that becomes annoying.

**No email.** Nobody is notified when a request is raised or decided. The
Approvals tab shows a count and the page refreshes every thirty seconds, but
people have to look.

**Back up occasionally.** Use the CSV export, or read the `leaveportal` key
straight from the Upstash console.

**Anyone with the link can reach the sign-in page.** Passwords are hashed and
there's a lockout after eight wrong attempts, but this is a public URL. Use
real passwords, and keep anything sensitive out of the notes field.

**It isn't the official record.** If leave also goes through SuccessFactors,
that stays authoritative. Running two systems in parallel is how balances end
up disagreeing — worth deciding which one counts before the team settles in.

---

## Settings

| Variable | Effect |
|---|---|
| `PORT` | Port to listen on. Default 3000. Render sets this itself. |
| `SECRET` | Signs the login cookie. Set it, or everyone is signed out on restart. |
| `KV_URL` / `KV_TOKEN` | Upstash REST credentials. Both set = hosted storage. |
| `KV_KEY` | Key name in Redis. Default `leaveportal`. |
| `NODE_ENV` | Set to `production` so the cookie is marked Secure. |
