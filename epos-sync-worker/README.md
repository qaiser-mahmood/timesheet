# 🤖 Epos Now Autonomous Cloud Sync Worker

An autonomous, 100% free cloud background worker running Playwright and Telegram bot polling to continuously sync live transactions from Epos Now into Supabase (`hourly_sales` and `raw_transactions`) without needing any PC or device in the shop.

---

## ✨ Features
- **Headless Cloud Playwright**: Runs on Render.com's free Docker tier.
- **Telegram 2FA SMS Forwarding**: When Epos Now sends an SMS verification code, the bot asks you on Telegram (`@anatolya_epos_bot`), you reply with the 6-digit code, and it signs in & remembers the session.
- **Persistent Session & Keep-Alive**: Saves browser session cookies and sends sliding heartbeats so 2FA is only needed once.
- **Automatic Scheduled Sync**: Scrapes transactions every 15 minutes and upserts into Supabase.
- **Instant On-Demand Telegram Commands**:
  - `/sync` - Run an immediate sync and get total sales & transactions breakdown in Telegram.
  - `/status` - Check current session status and last sync report.
  - `/screenshot` - View a live screenshot of Epos Now inside the cloud browser.
  - `/login` - Force a fresh login sequence.

---

## 🚀 5-Minute Free Setup on Render.com

### Step 1: Push this repo to GitHub
(Already pushed to your `qaiser-mahmood/timesheet` repo).

### Step 2: Create a Web Service on Render
1. Go to [dashboard.render.com](https://dashboard.render.com/) (create a free account if you haven't already).
2. Click **New +** -> **Web Service**.
3. Select your GitHub repository: `timesheet`.
4. Configure the service settings:
   - **Name**: `epos-sync-worker`
   - **Region**: Singapore (closest to Perth) or Oregon/Frankfurt.
   - **Branch**: `main`
   - **Root Directory**: `epos-sync-worker`
   - **Runtime**: `Docker`
   - **Instance Type**: `Free`

### Step 3: Add Environment Variables
Under **Environment Variables** in Render, add:

| Key | Value | Notes |
|---|---|---|
| `EPOS_USERNAME` | `your_epos_email` | Your Epos Now login email |
| `EPOS_PASSWORD` | `your_epos_password` | Your Epos Now password |
| `TELEGRAM_BOT_TOKEN` | `your_bot_token` | Token from @BotFather |
| `TELEGRAM_CHAT_ID` | `your_chat_id` | Your Telegram chat ID |
| `SUPABASE_URL` | `https://your-project.supabase.co` | Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | `your_service_role_key` | Supabase secret key |
| `AUTHORIZED_MANAGERS` | `manager1@gmail.com,manager2@gmail.com` | Whitelisted manager Google accounts |
| `PORT` | `3000` | Render HTTP port |
| `TZ` | `Australia/Perth` | Timezone |

Click **Create Web Service**.

---

## 📱 Initial 2FA Login
1. Once Render finishes building the Docker container (~2 minutes), you will receive a Telegram message:
   > 🚀 *Epos Now Sync Worker Online*
2. Send `/login` or `/sync` to the bot in Telegram.
3. The worker loads Epos Now. When Epos sends an SMS code to your phone, the Telegram bot will say:
   > 📱 *Epos Now SMS 2FA Code Required*
   > *Reply directly with your 6-digit code*
4. Reply with the code (e.g. `482910`).
5. The worker enters the code, logs in, checks "Trust this device", and saves the session!

---

## ⚡ Free 24/7 Keep-Alive (Preventing Render Sleep)
Render's free tier spins down after 15 minutes of inactivity. To keep your sync active throughout business hours:
1. Go to [cron-job.org](https://cron-job.org/) (100% free).
2. Create a new cron job pointing to: `https://your-app-name.onrender.com/health`
3. Set schedule: **Every 10 minutes** between **8:00 AM and 9:00 PM AWST**.
This keeps the worker active and syncing transactions live throughout the workday at zero cost!

## Security and reliability update

The portal now uses the authenticated worker for all reads and saves. A timed-out save is not automatically resubmitted through Supabase; refresh and check the saved records before retrying an unconfirmed save.

- Deploy the worker and frontend together. The frontend requires the new /api/bookmarklet-token endpoint.
- Public runtime JavaScript evaluators have been removed. Diagnostics, sync status, reset, and document parsing require an authorized Firebase manager token. /health remains public for uptime checks and no longer exposes sales or login state.
- Bookmarklet code must be copied fresh before each import. Its upload-only access expires after 15 minutes or a worker restart. Existing saved bookmarklets must be replaced.
- Roster upserts require the database uniqueness constraint (date, name, store_id); hourly sales require (date, store_id). Schema errors now fail instead of discarding shop identity. Verify these constraints before rollout.
- Epos range selection is applied in chunks of at most 31 days. Filter failures, stalled pagination, out-of-range results, and database errors surface as failures instead of a green success message.
- Loyverse follows all receipt pages. Repeated cursors or safety-limit exhaustion fail before incomplete totals are written.
- The BAS screen is a worksheet. This custom worksheet excludes cash sales from G1 and the matching GST estimate; delivery and other non-cash sales remain included. The same scope is used in period, venue and monthly subtotals. It is not a complete statutory BAS. GST remains an estimate from category rules. Enter actual W1/W2 totals from payroll; blank values remain unknown. Inputs stay in the current page only and reset when the shop, financial year, or quarter changes. Roster audit figures do not establish actual withholding.
- Supabase access policies and deployed credentials are outside this repository. Verify anonymous database access is denied. Because the previous version exposed runtime code execution, review access logs and rotate backend/POS/bot credentials during rollout.

### Regression tests

From the repository root with Node.js 20 or newer:

~~~sh
node --test tests/regressions.cjs tests/roster.cjs tests/bas-print.cjs
node --check epos-sync-worker/server.js
~~~

Tests use isolated DOM/API/database substitutes and do not contact the live POS, Firebase, or Supabase. They cover authentication gates, upload token scope and expiry, safe shop-specific mutations, complete pagination, date handling, rendering, failure messages, payroll worksheet behavior, and ten roster duration-edit scenarios. Verify live Google sign-in, database constraints, Epos selectors, and POS connectivity in staging before deploying.


### Accountant printout
The BAS Print / Save PDF action produces a dedicated two-page A4 working paper, separate from the dashboard. Page 1 follows the GST and PAYG label structure (G1, 1A, 1B, W1-W5, 4, 8A, 8B and 9). Page 2 contains cash-excluded sales reconciliation, monthly figures, the expense/GST-credit schedule, and adjustment notes.

Defaults: Alhamd Enterprises Pty Ltd, ABN 64 647 160 030, cash GST accounting method. Accountant print details allow contact information and notes to be added. W3 and W4 require actual amounts, including explicit zero if not applicable. Missing payroll leaves W5 and the payment/refund unconfirmed. Whole-dollar summary figures drop cents; detailed schedules retain cents. The report is an accountant working paper, not an ATO-issued form; cash exclusions and estimated credits are disclosed for reconciliation before lodgment.
