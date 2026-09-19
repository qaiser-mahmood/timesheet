require('dotenv').config();
const express = require('express');
const cron = require('node-cron');
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

// Configuration
const PORT = process.env.PORT || 3000;
const EPOS_USERNAME = process.env.EPOS_USERNAME || 'hqmahmood@gmail.com';
const EPOS_PASSWORD = process.env.EPOS_PASSWORD || '';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '8950563751:AAH9lqUWbWDipbZI4xmLmyXL1fCuQcfQDps';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '8717773730';
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://ckyutsdgpdamnhsqoail.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'sb_publishable_ZOJOaDyvy3SKzTADZrzgIg_6h44R8sf';
const CRON_SCHEDULE = process.env.CRON_SCHEDULE || '*/15 * * * *'; // Every 15 mins default
const STORAGE_STATE_PATH = path.join(__dirname, 'storageState.json');
const TARGET_URL = 'https://reporting.eposnowhq.com/transactions';

// State tracker
const appState = {
  browser: null,
  context: null,
  isSyncing: false,
  isLoggingIn: false,
  pending2FACode: null,
  lastSyncTime: null,
  lastSyncResult: null,
  isAuthenticated: false,
  consecutiveFailures: 0,
  telegramOffset: 0
};

// Express App
const app = express();
app.use(express.json());

// Health endpoint for keep-alive cron & monitoring
app.get(['/', '/health'], (req, res) => {
  res.json({
    status: 'ok',
    service: 'epos-sync-worker',
    time: new Date().toISOString(),
    lastSyncTime: appState.lastSyncTime,
    lastSyncResult: appState.lastSyncResult,
    isAuthenticated: appState.isAuthenticated,
    isSyncing: appState.isSyncing,
    uptimeSeconds: Math.floor(process.uptime())
  });
});

// Manual HTTP trigger
app.get('/sync', async (req, res) => {
  if (appState.isSyncing) {
    return res.json({ status: 'in_progress', message: 'Sync already underway' });
  }
  runSync(true).catch(console.error);
  res.json({ status: 'triggered', message: 'Sync process initiated' });
});

// ----------------------------------------------------
// Telegram Bot Helpers
// ----------------------------------------------------
async function sendTelegramMessage(text, parseMode = 'Markdown') {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: TELEGRAM_CHAT_ID,
        text,
        parse_mode: parseMode
      })
    });
    return await res.json();
  } catch (err) {
    console.error('Failed to send Telegram message:', err.message);
  }
}

async function sendTelegramPhoto(photoBuffer, caption = '') {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendPhoto`;
    const formData = new FormData();
    formData.append('chat_id', TELEGRAM_CHAT_ID);
    formData.append('photo', new Blob([photoBuffer], { type: 'image/png' }), 'screen.png');
    if (caption) formData.append('caption', caption);

    await fetch(url, {
      method: 'POST',
      body: formData
    });
  } catch (err) {
    console.error('Failed to send Telegram photo:', err.message);
  }
}

// Telegram polling loop
async function pollTelegram() {
  if (!TELEGRAM_BOT_TOKEN) return;
  const pollUrl = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates?offset=${appState.telegramOffset}&timeout=25`;
  try {
    const res = await fetch(pollUrl);
    const data = await res.json();
    if (data.ok && Array.isArray(data.result)) {
      for (const update of data.result) {
        appState.telegramOffset = update.update_id + 1;
        if (!update.message || !update.message.text) continue;
        const fromId = String(update.message.from.id);
        const text = update.message.text.trim();

        // Only respond to authorized chat ID
        if (fromId !== String(TELEGRAM_CHAT_ID)) {
          console.log(`Ignored message from unauthorized chat: ${fromId}`);
          continue;
        }

        console.log(`Telegram command received: "${text}"`);

        // Check if 2FA is pending and user entered 6 digits
        if (appState.pending2FACode && /^\d{4,8}$/.test(text.replace(/\s+/g, ''))) {
          const code = text.replace(/\s+/g, '');
          console.log(`Received 2FA code from user: ${code}`);
          appState.pending2FACode.resolve(code);
          appState.pending2FACode = null;
          await sendTelegramMessage(`👍 Code received (${code})! Submitting to Epos Now...`);
          continue;
        }

        const cmd = text.toLowerCase();
        if (cmd === '/start' || cmd === '/help') {
          await sendTelegramMessage(
            `🤖 *Epos Now Autonomous Sync Worker*\n\n` +
            `Available Commands:\n` +
            `• /sync - Run immediate sync to Supabase\n` +
            `• /status - Check status & last sync\n` +
            `• /login - Re-authenticate / trigger 2FA\n` +
            `• /screenshot - View current browser screen\n\n` +
            `When 2FA SMS is requested, reply directly with your 6-digit code.`
          );
        } else if (cmd === '/status') {
          await sendTelegramMessage(
            `📊 *Worker Status*\n\n` +
            `• Authenticated: ${appState.isAuthenticated ? '✅ Yes' : '⚠️ No'}\n` +
            `• Sync in progress: ${appState.isSyncing ? '⏳ Yes' : 'No'}\n` +
            `• Last Sync: ${appState.lastSyncTime || 'None yet'}\n` +
            `• Last Result: ${appState.lastSyncResult ? '`' + JSON.stringify(appState.lastSyncResult) + '`' : 'N/A'}\n` +
            `• Target: ${TARGET_URL}`
          );
        } else if (cmd === '/sync') {
          await sendTelegramMessage('⏳ Starting manual sync...');
          runSync(true).catch(async (e) => {
            await sendTelegramMessage(`❌ Sync failed: ${e.message}`);
          });
        } else if (cmd === '/login') {
          await sendTelegramMessage('🔐 Initiating fresh login...');
          ensureLoggedIn(true).catch(async (e) => {
            await sendTelegramMessage(`❌ Login error: ${e.message}`);
          });
        } else if (cmd === '/screenshot') {
          try {
            if (appState.context) {
              const pages = appState.context.pages();
              if (pages.length > 0) {
                const buf = await pages[0].screenshot();
                await sendTelegramPhoto(buf, `📸 Current screen (${new Date().toLocaleTimeString('en-AU', { timeZone: 'Australia/Perth' })})`);
              } else {
                await sendTelegramMessage('No browser pages currently active.');
              }
            } else {
              await sendTelegramMessage('Browser context not initialized yet.');
            }
          } catch (err) {
            await sendTelegramMessage(`Error capturing screenshot: ${err.message}`);
          }
        }
      }
    }
  } catch (err) {
    // Network hiccup during poll
  } finally {
    setTimeout(pollTelegram, 2000);
  }
}

// ----------------------------------------------------
// Playwright Browser & Session Management
// ----------------------------------------------------
async function getBrowserContext() {
  if (!appState.browser) {
    appState.browser = await chromium.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--disable-gpu'
      ]
    });
  }

  if (!appState.context) {
    const contextOptions = {
      viewport: { width: 1280, height: 800 },
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
    };

    if (fs.existsSync(STORAGE_STATE_PATH)) {
      try {
        contextOptions.storageState = STORAGE_STATE_PATH;
        console.log('Loaded existing session state from storageState.json');
      } catch (err) {
        console.error('Failed to load storageState:', err.message);
      }
    }

    appState.context = await appState.browser.newContext(contextOptions);
  }

  return appState.context;
}

// Wait for user to send 6-digit SMS code via Telegram
function waitFor2FACode(timeoutMs = 300000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      appState.pending2FACode = null;
      reject(new Error('Timed out waiting for 2FA code from Telegram (5 minutes expired)'));
    }, timeoutMs);

    appState.pending2FACode = {
      resolve: (code) => {
        clearTimeout(timer);
        resolve(code);
      },
      reject: (err) => {
        clearTimeout(timer);
        reject(err);
      }
    };
  });
}

// Ensure user is logged in
async function ensureLoggedIn(force = false) {
  if (appState.isLoggingIn) return;
  appState.isLoggingIn = true;

  const context = await getBrowserContext();
  const page = (await context.pages())[0] || (await context.newPage());

  try {
    console.log(`Checking session on ${TARGET_URL}...`);
    await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded', timeout: 45000 });
    await page.waitForTimeout(3000);

    const currentUrl = page.url();
    console.log(`Current page URL: ${currentUrl}`);

    // If redirected to login
    const isLoginPage = currentUrl.toLowerCase().includes('login') ||
      (await page.$('input[type="password"]')) !== null;

    if (!isLoginPage && !force) {
      console.log('Already logged in to Epos Now.');
      appState.isAuthenticated = true;
      return page;
    }

    console.log('Login required. Filling credentials...');
    if (!EPOS_PASSWORD) {
      const err = new Error('EPOS_PASSWORD environment variable is not configured!');
      await sendTelegramMessage(`⚠️ *Configuration Error*: EPOS_PASSWORD is missing in worker environment variables.`);
      throw err;
    }

    // Fill Username
    const emailInput = await page.waitForSelector('input[type="email"], input[name*="user" i], input[name*="email" i], input[id*="user" i]', { timeout: 15000 });
    await emailInput.fill(EPOS_USERNAME);

    // Fill Password
    const passInput = await page.waitForSelector('input[type="password"]', { timeout: 10000 });
    await passInput.fill(EPOS_PASSWORD);

    // Click Remember Me if present
    try {
      const rememberCheckbox = await page.$('input[type="checkbox"]');
      if (rememberCheckbox) await rememberCheckbox.check();
    } catch (_) {}

    // Click Submit
    const submitBtn = await page.waitForSelector('button[type="submit"], input[type="submit"], button:has-text("Log In"), button:has-text("Sign In"), button:has-text("Login")', { timeout: 10000 });
    await submitBtn.click();
    console.log('Submitted credentials, waiting for redirect or 2FA challenge...');

    await page.waitForTimeout(4000);

    // Check for 2FA screen
    const afterUrl = page.url();
    const pageText = await page.innerText('body');
    const is2FA = afterUrl.toLowerCase().includes('twofactor') ||
      afterUrl.toLowerCase().includes('verification') ||
      afterUrl.toLowerCase().includes('challenge') ||
      pageText.toLowerCase().includes('verification code') ||
      pageText.toLowerCase().includes('enter code') ||
      pageText.toLowerCase().includes('security code') ||
      pageText.toLowerCase().includes('sent a code');

    if (is2FA) {
      console.log('2FA Challenge detected!');
      await sendTelegramMessage(
        `📱 *Epos Now SMS 2FA Code Required*\n\n` +
        `Epos Now has sent a verification code via SMS to your phone for account *${EPOS_USERNAME}*.\n\n` +
        `➡️ *Reply to this bot directly with the 6-digit code* within 5 minutes.`
      );

      // Wait for user to message code
      const code = await waitFor2FACode(300000);
      console.log(`Submitting 2FA code ${code} to Epos Now...`);

      // Fill code input
      const codeInput = await page.waitForSelector('input[type="text"], input[type="tel"], input[type="number"], input[name*="code" i], input[id*="code" i]', { timeout: 15000 });
      await codeInput.fill(code);

      // Check remember device if present
      try {
        const trustDevice = await page.$('input[type="checkbox"], input[id*="remember" i], input[id*="trust" i]');
        if (trustDevice) await trustDevice.check();
      } catch (_) {}

      // Submit 2FA
      const verifyBtn = await page.waitForSelector('button[type="submit"], input[type="submit"], button:has-text("Verify"), button:has-text("Submit"), button:has-text("Continue")', { timeout: 10000 });
      await verifyBtn.click();

      await page.waitForNavigation({ waitUntil: 'networkidle', timeout: 30000 }).catch(() => {});
      await page.waitForTimeout(3000);
    }

    // Save session storage
    await context.storageState({ path: STORAGE_STATE_PATH });
    console.log('Saved new authenticated session to storageState.json');
    appState.isAuthenticated = true;

    await sendTelegramMessage(`✅ *Logged in successfully!* Epos Now session is active and saved.`);
    return page;
  } catch (err) {
    appState.isAuthenticated = false;
    console.error('Login flow failed:', err.message);
    throw err;
  } finally {
    appState.isLoggingIn = false;
  }
}

// ----------------------------------------------------
// Sync Engine (Runs Scraper & Upserts to Supabase)
// ----------------------------------------------------
async function runSync(isManual = false) {
  if (appState.isSyncing) {
    console.log('Sync is already running. Skipping.');
    return;
  }
  appState.isSyncing = true;

  try {
    console.log(`\n============================\nStarting sync run at ${new Date().toISOString()}...\n============================`);
    const page = await ensureLoggedIn();

    // Ensure we are on transactions page
    if (!page.url().includes('transactions')) {
      await page.goto(TARGET_URL, { waitUntil: 'networkidle', timeout: 45000 });
      await page.waitForTimeout(2000);
    }

    // Run in-browser scraping engine
    const scrapeResult = await page.evaluate(async () => {
      function getAllDocs() {
        var docs = [document];
        var ifrs = document.querySelectorAll('iframe');
        for (var i = 0; i < ifrs.length; i++) {
          try {
            var d = ifrs[i].contentDocument || ifrs[i].contentWindow.document;
            if (d && d.body) docs.push(d);
          } catch (e) {}
        }
        return docs;
      }

      function countCurrentTxRows() {
        var docs = getAllDocs();
        var total = 0;
        for (var di = 0; di < docs.length; di++) {
          var rows = docs[di].querySelectorAll('tr, [role="row"], tbody tr');
          total += rows.length;
        }
        return total;
      }

      function scrollAllToBottom() {
        try { window.scrollTo({ top: 9999999, behavior: 'instant' }); } catch (e) { window.scrollTo(0, 9999999); }
        var docs = getAllDocs();
        for (var di = 0; di < docs.length; di++) {
          var doc = docs[di];
          try { doc.documentElement.scrollTop = 9999999; } catch (e) {}
          try { doc.body.scrollTop = 9999999; } catch (e) {}
          var rows = doc.querySelectorAll('tr, [role="row"], tbody tr');
          if (rows && rows.length > 0) {
            try { rows[rows.length - 1].scrollIntoView({ behavior: 'instant', block: 'end' }); } catch (e) {}
          }
          var scrollables = doc.querySelectorAll('main, section, article, table, tbody, div');
          for (var s = 0; s < scrollables.length; s++) {
            var el = scrollables[s];
            if (el.scrollHeight > el.clientHeight + 25 && el.clientHeight > 70) {
              try {
                el.scrollTop = el.scrollHeight;
                el.dispatchEvent(new Event('scroll', { bubbles: true }));
              } catch (e) {}
            }
          }
        }
      }

      function findMoreTxBtn() {
        var docs = getAllDocs();
        for (var di = 0; di < docs.length; di++) {
          var doc = docs[di];
          var primaryBtns = doc.querySelectorAll('button, a, [role="button"], input[type="button"]');
          for (var i = 0; i < primaryBtns.length; i++) {
            var btn = primaryBtns[i];
            var txt = (btn.innerText || btn.textContent || btn.value || '').replace(/\s+/g, ' ').trim().toLowerCase();
            if (txt.includes('more transaction') || txt.includes('more transactions') || txt.includes('load more') || txt.includes('show more') || txt.includes('more entries')) {
              return btn;
            }
          }
        }
        return null;
      }

      // Auto-load 5 pages for routine updates
      var maxBatches = 8;
      for (var pageIdx = 0; pageIdx < maxBatches; pageIdx++) {
        scrollAllToBottom();
        await new Promise(r => setTimeout(r, 400));
        var btn = findMoreTxBtn();
        if (btn) {
          btn.click();
          await new Promise(r => setTimeout(r, 800));
        } else {
          break;
        }
      }

      scrollAllToBottom();
      await new Promise(r => setTimeout(r, 600));

      var docs = getAllDocs();
      var fullText = '';
      for (var di = 0; di < docs.length; di++) {
        if (docs[di].body) fullText += docs[di].body.innerText + '\n';
      }

      var monthNames = ["january","february","march","april","may","june","july","august","september","october","november","december"];
      var shortMonths = ["jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"];

      function toIso(y, m, d) {
        return String(y) + '-' + String(m).padStart(2, '0') + '-' + String(d).padStart(2, '0');
      }

      function parseAnyDate(str) {
        if (!str) return null;
        var now = new Date();
        var curYear = now.getFullYear();
        if (/\btoday\b/i.test(str)) return toIso(curYear, now.getMonth() + 1, now.getDate());
        if (/\byesterday\b/i.test(str)) {
          var yDate = new Date(now.getTime() - 86400000);
          return toIso(yDate.getFullYear(), yDate.getMonth() + 1, yDate.getDate());
        }
        var mIso = str.match(/\b(\d{4})-(\d{2})-(\d{2})\b/);
        if (mIso) return mIso[0];
        var mWord1 = str.match(/\b(\d{1,2})(?:st|nd|rd|th)?[\s\-\/]+([A-Za-z]{3,9})(?:[\s\-\/,]+(\d{2,4}))?\b/i);
        if (mWord1) {
          var mStr = mWord1[2].toLowerCase();
          var mIdx = monthNames.indexOf(mStr);
          if (mIdx === -1) mIdx = shortMonths.indexOf(mStr.slice(0, 3));
          if (mIdx !== -1) {
            var yr = mWord1[3] ? (mWord1[3].length === 2 ? '20' + mWord1[3] : mWord1[3]) : String(curYear);
            return toIso(yr, mIdx + 1, mWord1[1]);
          }
        }
        var mSlash = str.match(/\b(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})\b/);
        if (mSlash) {
          var d = parseInt(mSlash[1], 10);
          var mo = parseInt(mSlash[2], 10);
          if (d >= 1 && d <= 31 && mo >= 1 && mo <= 12) {
            var yr3 = mSlash[3].length === 2 ? '20' + mSlash[3] : mSlash[3];
            return toIso(yr3, mo, d);
          }
        }
        return null;
      }

      var datePatternRegex = /(?:\b(?:Today|Yesterday)\b|\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}(?:st|nd|rd|th)?[\s\-\/]+(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)(?:[\s\-\/,]+\d{2,4})?\b|\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b)/gi;
      var dateMarkers = [];
      var dMatch;
      while ((dMatch = datePatternRegex.exec(fullText)) !== null) {
        var iso = parseAnyDate(dMatch[0]);
        if (iso) dateMarkers.push({ index: dMatch.index, date: iso, raw: dMatch[0] });
      }

      function parseTimeStr(timeStr) {
        var tm = timeStr.match(/(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([apAP][mM])?/i);
        if (!tm) return null;
        var h = parseInt(tm[1], 10);
        var ampm = tm[4] ? tm[4].toUpperCase() : '';
        if (ampm === 'PM' && h < 12) h += 12;
        if (ampm === 'AM' && h === 12) h = 0;
        return String(h).padStart(2, '0') + ':00';
      }

      var eposRowRegex = /(\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b|\b\d{4}-\d{2}-\d{2}\b)[,\s]+(\d{1,2}:\d{2}(?::\d{2})?\s*[apAP][mM]?)[,\s]+[\$£€]?\s*([0-9]+\.[0-9]{2})/g;
      var timeAmtRegex = /(\d{1,2}:\d{2}(?::\d{2})?\s*[apAP][mM]?)[,\s]+[\$£€]?\s*([0-9]+\.[0-9]{2})/g;
      var amtTimeRegex = /[\$£€]?\s*([0-9]+\.[0-9]{2})[,\s]+(\d{1,2}:\d{2}(?::\d{2})?\s*[apAP][mM]?)/g;

      var txList = [];
      var tMatch;
      while ((tMatch = eposRowRegex.exec(fullText)) !== null) {
        var rowDate = parseAnyDate(tMatch[1]);
        var rowTime = tMatch[2];
        var rowHour = parseTimeStr(rowTime);
        var rowAmt = parseFloat(tMatch[3]);
        if (rowDate && rowHour !== null && !isNaN(rowAmt)) {
          txList.push({ index: tMatch.index, date: rowDate, time: rowTime, hour: rowHour, amount: rowAmt, raw: tMatch[0].replace(/\s+/g, ' ').trim() });
        }
      }

      if (txList.length === 0) {
        while ((tMatch = timeAmtRegex.exec(fullText)) !== null) {
          var timeStr = tMatch[1];
          var hourStr = parseTimeStr(timeStr);
          var amt = parseFloat(tMatch[2]);
          if (hourStr !== null && !isNaN(amt)) {
            txList.push({ index: tMatch.index, time: timeStr, hour: hourStr, amount: amt, raw: tMatch[0].replace(/\s+/g, ' ').trim() });
          }
        }
      }

      if (txList.length === 0) {
        while ((tMatch = amtTimeRegex.exec(fullText)) !== null) {
          var amt2 = parseFloat(tMatch[1]);
          var timeStr2 = tMatch[2];
          var hourStr2 = parseTimeStr(timeStr2);
          if (hourStr2 !== null && !isNaN(amt2)) {
            txList.push({ index: tMatch.index, time: timeStr2, hour: hourStr2, amount: amt2, raw: tMatch[0].replace(/\s+/g, ' ').trim() });
          }
        }
      }

      var defaultDate = dateMarkers.length > 0 ? dateMarkers[0].date : (new Date().toISOString().split('T')[0]);
      var daysGroup = {};

      for (var i = 0; i < txList.length; i++) {
        var tx = txList[i];
        var matchedDate = tx.date;
        if (!matchedDate) {
          matchedDate = defaultDate;
          for (var j = dateMarkers.length - 1; j >= 0; j--) {
            if (dateMarkers[j].index <= tx.index) {
              matchedDate = dateMarkers[j].date;
              break;
            }
          }
          tx.date = matchedDate;
        }
        if (!daysGroup[matchedDate]) {
          daysGroup[matchedDate] = { totalSales: 0, count: 0, hourly: {} };
        }
        daysGroup[matchedDate].count++;
        daysGroup[matchedDate].totalSales += tx.amount;
        daysGroup[matchedDate].hourly[tx.hour] = (daysGroup[matchedDate].hourly[tx.hour] || 0) + tx.amount;
      }

      var daysBatch = [];
      var sortedDays = Object.keys(daysGroup).sort().reverse();
      for (var d = 0; d < sortedDays.length; d++) {
        var dKey = sortedDays[d];
        daysGroup[dKey].totalSales = Math.round(daysGroup[dKey].totalSales * 100) / 100;
        for (var hk in daysGroup[dKey].hourly) {
          daysGroup[dKey].hourly[hk] = Math.round(daysGroup[dKey].hourly[hk] * 100) / 100;
        }
        daysBatch.push({ date: dKey, totalSales: daysGroup[dKey].totalSales, count: daysGroup[dKey].count, hourly: daysGroup[dKey].hourly });
      }

      var txRows = txList.map(function(t) {
        var rawC = (t.raw || '').replace(/\s+/g, ' ').trim();
        var uid = (t.date + '_' + (t.time || '').replace(/[^a-zA-Z0-9]/g, '') + '_' + t.amount.toFixed(2) + '_' + rawC).slice(0, 120).toLowerCase().replace(/[^a-z0-9_]/g, '-');
        return { id: uid, date: t.date, time: t.time || '', amount: t.amount, raw_line: rawC };
      });

      return { daysBatch, txRows, totalTx: txList.length, sample: fullText.slice(0, 200) };
    });

    console.log(`Scraped ${scrapeResult.totalTx} transactions across ${scrapeResult.daysBatch.length} day(s).`);

    if (scrapeResult.totalTx === 0) {
      console.warn('No transactions parsed on page.');
      if (isManual) {
        await sendTelegramMessage('⚠️ Scrape completed, but 0 transactions were found on the current Epos Now report page.');
      }
      return;
    }

    // Upsert hourly_sales to Supabase
    const hsPayload = scrapeResult.daysBatch.map(d => ({
      date: d.date,
      total_sales: d.totalSales,
      hourly: d.hourly,
      updated_at: new Date().toISOString()
    }));

    const hsRes = await fetch(`${SUPABASE_URL}/rest/v1/hourly_sales?on_conflict=date`, {
      method: 'POST',
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'resolution=merge-duplicates'
      },
      body: JSON.stringify(hsPayload)
    });

    if (!hsRes.ok) {
      const txt = await hsRes.text();
      console.error('Supabase hourly_sales upsert failed:', txt);
    } else {
      console.log(`Successfully upserted ${hsPayload.length} day(s) to hourly_sales.`);
    }

    // Upsert raw_transactions in chunks of 100
    let insertedTx = 0;
    for (let i = 0; i < scrapeResult.txRows.length; i += 100) {
      const chunk = scrapeResult.txRows.slice(i, i + 100);
      const txRes = await fetch(`${SUPABASE_URL}/rest/v1/raw_transactions?on_conflict=id`, {
        method: 'POST',
        headers: {
          'apikey': SUPABASE_KEY,
          'Authorization': `Bearer ${SUPABASE_KEY}`,
          'Content-Type': 'application/json',
          'Prefer': 'resolution=merge-duplicates'
        },
        body: JSON.stringify(chunk)
      });
      if (txRes.ok) insertedTx += chunk.length;
    }
    console.log(`Successfully upserted ${insertedTx} raw transactions.`);

    // Update state
    appState.lastSyncTime = new Date().toISOString();
    appState.lastSyncResult = {
      days: scrapeResult.daysBatch.length,
      txCount: scrapeResult.totalTx,
      topDay: scrapeResult.daysBatch[0] ? `${scrapeResult.daysBatch[0].date}: $${scrapeResult.daysBatch[0].totalSales}` : 'N/A'
    };
    appState.consecutiveFailures = 0;

    // Send summary to Telegram if manually triggered
    if (isManual) {
      const summaryLines = scrapeResult.daysBatch.map(d => `• *${d.date}*: $${d.totalSales.toFixed(2)} (${d.count} txs)`);
      await sendTelegramMessage(
        `✅ *Sync Complete!*\n\n` +
        `Synced *${scrapeResult.totalTx}* transactions across *${scrapeResult.daysBatch.length}* day(s) to Supabase:\n\n` +
        summaryLines.join('\n')
      );
    }
  } catch (err) {
    appState.consecutiveFailures++;
    console.error('Sync failed:', err);
    if (isManual || appState.consecutiveFailures === 3) {
      await sendTelegramMessage(`⚠️ *Epos Sync Error*: ${err.message}`);
    }
  } finally {
    appState.isSyncing = false;
  }
}

// ----------------------------------------------------
// Keep-Alive Heartbeat (Pings session every 4 minutes)
// ----------------------------------------------------
async function sessionHeartbeat() {
  if (appState.isSyncing || appState.isLoggingIn) return;
  try {
    if (appState.context) {
      const pages = appState.context.pages();
      if (pages.length > 0) {
        // Quick lightweight check
        await pages[0].evaluate(() => document.title).catch(() => {});
      }
    }
  } catch (_) {}
}

// Schedule Cron (Every 15 minutes during operating hours)
cron.schedule(CRON_SCHEDULE, () => {
  console.log('Scheduled cron triggered.');
  runSync(false).catch(console.error);
});

// Schedule Heartbeat every 4 minutes
cron.schedule('*/4 * * * *', () => {
  sessionHeartbeat().catch(() => {});
});

// ----------------------------------------------------
// Start Application
// ----------------------------------------------------
app.listen(PORT, '0.0.0.0', () => {
  console.log(`=============================================`);
  console.log(`Epos Now Sync Worker listening on port ${PORT}`);
  console.log(`Supabase Target: ${SUPABASE_URL}`);
  console.log(`Epos Username: ${EPOS_USERNAME}`);
  console.log(`Cron: ${CRON_SCHEDULE}`);
  console.log(`=============================================`);

  // Start Telegram polling
  pollTelegram();

  // Send boot notification
  sendTelegramMessage(
    `🚀 *Epos Now Sync Worker Online*\n\n` +
    `Worker booted on Render / Cloud.\n` +
    `Type /status to check status or /sync to start.`
  ).catch(console.error);
});
