# Leave portal — NCIM

Annual and sick leave requests. Node 18+, no npm packages.

---

## 1. Getting your account back

If you've forgotten the super user password, there's a one-shot recovery built in.

**On Render:** your service → **Environment** → add

| Key | Value |
|---|---|
| `ADMIN_RESET` | `10432:YourNewPassword` |

Use your own employee ID before the colon and a password of at least 6
characters after it. Save — Render redeploys automatically.

Open the **Logs** tab. You should see:

```
ADMIN_RESET: password reset for <your name> (10432), role set to admin.
>>> Remove the ADMIN_RESET variable and redeploy. <<<
```

If instead it says *no account with ID …*, the log lists every ID that does
exist — use one of those.

Sign in with the new password, then **delete the `ADMIN_RESET` variable** and
redeploy. Leaving it in place means anyone who can see your Render settings can
read that password.

The reset also sets the account back to super user, so it recovers lost
privileges as well as a lost password.

---

## 2. Who can do what

| | Super user | Manager | Team member |
|---|---|---|---|
| Raise own request | ✓ | ✓ | ✓ |
| See the whole team's leave and balances | ✓ | ✓ | — |
| Approve and reject | ✓ | ✓ | — |
| Reopen a decided request | ✓ | ✓ | — |
| Edit or delete any request | ✓ | — | — |
| Record leave on someone's behalf | ✓ | — | — |
| Add and remove people | ✓ | — | — |
| Reset passwords | ✓ | — | — |
| Change allowances and days taken | ✓ | — | — |
| Download the CSV | ✓ | ✓ | — |

Set someone's role from the **Team** tab — the dropdown next to their name saves
as soon as you change it. You can't remove your own super user access, and the
last remaining super user can't be deleted.

---

## 3. Balances

Each person has two numbers you control directly from the Team table:

- **Allowance** — annual entitlement in days
- **Opening taken** — days already used before the portal existed, or any
  manual correction

**Left = Allowance − (Opening taken + approved annual days)**

So to correct someone's balance you don't have to hunt through their requests —
adjust one of those two numbers and the figure updates immediately. Both accept
0 to 90. Sick leave never affects the annual balance.

Recording leave for someone else (super user only): on **Raise a request**,
pick their name in the **For** dropdown. It's approved automatically, since
you're the one entering it.

---

## 4. Email notifications

Off by default. To switch them on you need a sending service — **Resend** has a
free tier and a plain REST API, so no package is needed.

1. Sign up at **resend.com**
2. Add and verify your sending domain (or use their test domain to try it)
3. Create an API key
4. In Render → **Environment**, add:

| Key | Value |
|---|---|
| `RESEND_API_KEY` | the key from Resend |
| `MAIL_FROM` | `Leave portal <leave@yourdomain.sa>` |
| `APP_URL` | `https://leave-portal-9aek.onrender.com` |

`APP_URL` just puts a working button in the emails.

**What gets sent:**

| When | To |
|---|---|
| A request is raised | every manager and super user with an email |
| It's approved or rejected | the person who raised it |
| A request is edited or deleted by someone else | the person it belongs to |
| Someone is added to the team | them, with their employee ID |
| A password is reset | them, without the password |

Passwords are never emailed. Hand those over in person or by message.

Addresses go in the **Team** table and save as you type them. Anyone without an
address simply gets no email; everything else still works. The Team tab shows a
banner while email is switched off.

---

## 5. Running it locally

Windows: `start-windows.bat` · Mac/Linux: `./start-mac-linux.sh` · or `node server.js`

With no `KV_URL` set it keeps everything in `data.json` next to `server.js`.

---

## 6. Settings

| Variable | Effect |
|---|---|
| `PORT` | Listening port. Render sets this itself. |
| `SECRET` | Signs the login cookie. Without it, restarts sign everyone out. |
| `KV_URL` / `KV_TOKEN` | Upstash REST credentials. Both set = hosted storage. |
| `KV_KEY` | Key name in Redis. Default `leaveportal`. |
| `NODE_ENV` | `production` marks the cookie Secure. |
| `ADMIN_RESET` | One-shot password recovery. Remove after use. |
| `RESEND_API_KEY`, `MAIL_FROM`, `APP_URL` | Email. |

---

## 7. Worth knowing

**Existing records upgrade themselves.** The first start after this update
converts old accounts to the new role format and adds the email and opening-taken
fields. The log says *Records upgraded to the new user format.* Nothing is lost.

**Render's free tier sleeps** after fifteen minutes idle; the first visit takes
about thirty seconds to wake.

**Deleting a request removes it from the CSV too.** There's no audit trail of
what was deleted. Reopening rather than deleting keeps the history.

**This isn't the official record.** If leave also goes through SuccessFactors,
decide which one is authoritative before the team settles in.
