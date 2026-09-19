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
| `EPOS_USERNAME` | `hqmahmood@gmail.com` | Your Epos Now email |
| `EPOS_PASSWORD` | `your_epos_password` | Your Epos Now password |
| `TELEGRAM_BOT_TOKEN` | `8950563751:AAH9lqUWbWDipbZI4xmLmyXL1fCuQcfQDps` | Bot token |
| `TELEGRAM_CHAT_ID` | `8717773730` | Your Telegram chat ID |
| `SUPABASE_URL` | `https://ckyutsdgpdamnhsqoail.supabase.co` | Supabase project URL |
| `SUPABASE_KEY` | `sb_publishable_ZOJOaDyvy3SKzTADZrzgIg_6h44R8sf` | Supabase public key |
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
