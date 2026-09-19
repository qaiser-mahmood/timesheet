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
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://ckyutsdgpdamnhsqoail.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'sb_publishable_ZOJOaDyvy3SKzTADZrzgIg_6h44R8sf';
const CRON_SCHEDULE = process.env.CRON_SCHEDULE || '*/15 * * * *';
const STORAGE_STATE_PATH = path.join(__dirname, 'storageState.json');
const TARGET_URL = 'https://reporting.eposnowhq.com/transactions';

// State tracker
const appState = {
  browser: null,
  context: null,
  activePage: null,
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
    isLoggingIn: appState.isLoggingIn,
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
// Telegram Bot Helpers (Resilient with auto plain-text fallback)
// ----------------------------------------------------
async function sendTelegramMessage(text, parseMode = 'Markdown') {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: TELEGRAM_CHAT_ID,
        text,
        ...(parseMode ? { parse_mode: parseMode } : {})
      })
    });
    const data = await res.json();
    if (!data.ok && parseMode) {
      console.warn('Telegram Markdown parse error, retrying plain text:', data.description);
      const plainText = text.replace(/[*_`\[\]]/g, '');
      const retryRes = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: TELEGRAM_CHAT_ID,
          text: plainText
        })
      });
      return await retryRes.json();
    }
    return data;
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
    if (caption) formData.append('caption', caption.slice(0, 1024));

    const res = await fetch(url, {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    if (!data.ok) {
      console.error('Telegram photo upload error:', data.description);
    }
    return data;
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

        // Check if 2FA is pending and user entered 4-8 digits
        const cleanDigits = text.replace(/\s+/g, '');
        if (appState.pending2FACode && /^\d{4,8}$/.test(cleanDigits)) {
          console.log(`Received 2FA code from user: ${cleanDigits}`);
          appState.pending2FACode.resolve(cleanDigits);
          appState.pending2FACode = null;
          await sendTelegramMessage(`👍 Code received (${cleanDigits})! Submitting to Epos Now...`);
          continue;
        }

        const cmd = text.toLowerCase();
        if (cmd === '/start' || cmd === '/help') {
          await sendTelegramMessage(
            `🤖 *Epos Now Cloud Sync Bot*\n\n` +
            `Commands:\n` +
            `• /login - Start fresh login and trigger SMS 2FA\n` +
            `• /sync - Run immediate sync to Supabase\n` +
            `• /status - Check status & last sync\n` +
            `• /screenshot - View live browser screen\n\n` +
            `When 2FA SMS is requested, reply directly here with your 6-digit code.`
          );
        } else if (cmd === '/status') {
          await sendTelegramMessage(
            `📊 *Worker Status*\n\n` +
            `• Authenticated: ${appState.isAuthenticated ? '✅ Yes' : '⚠️ No'}\n` +
            `• Login in progress: ${appState.isLoggingIn ? '⏳ Yes' : 'No'}\n` +
            `• Sync in progress: ${appState.isSyncing ? '⏳ Yes' : 'No'}\n` +
            `• Last Sync: ${appState.lastSyncTime || 'None yet'}\n` +
            `• Last Result: ${appState.lastSyncResult ? JSON.stringify(appState.lastSyncResult) : 'N/A'}\n` +
            `• Account: ${EPOS_USERNAME}`
          );
        } else if (cmd === '/sync') {
          await sendTelegramMessage('⏳ Starting sync process...');
          runSync(true).catch(async (e) => {
            await sendTelegramMessage(`❌ Sync failed: ${e.message}`);
          });
        } else if (cmd === '/login') {
          if (appState.isLoggingIn) {
            await sendTelegramMessage('⏳ Login is already in progress. Please wait a moment...');
          } else {
            await sendTelegramMessage('🔐 Initiating fresh login flow...');
            ensureLoggedIn(true).catch(async (e) => {
              const stackTop = e.stack ? e.stack.split('\n')[1].trim() : '';
              await sendTelegramMessage(`❌ Login error: ${e.message}\n${stackTop}`);
            });
          }
        } else if (cmd === '/screenshot') {
          await sendTelegramMessage('📸 Capturing screenshot...');
          try {
            const page = await getActivePage();
            const buf = await page.screenshot({ fullPage: false });
            const title = await page.title().catch(() => 'Epos Now');
            const url = page.url();
            await sendTelegramPhoto(buf, `📸 ${title}\nURL: ${url}`);
          } catch (err) {
            await sendTelegramMessage(`❌ Screenshot failed: ${err.message}`);
          }
        } else if (cmd === '/screentext') {
          try {
            const page = await getActivePage();
            const text = await page.innerText('body');
            const clean = text.replace(/\n\s*\n/g, '\n').slice(0, 900);
            await sendTelegramMessage(`📄 *Current Screen Text:*\n\n${clean}`);
          } catch (err) {
            await sendTelegramMessage(`❌ Error reading text: ${err.message}`);
          }
        } else if (cmd.startsWith('/click ')) {
          const target = text.slice(7).trim();
          try {
            const page = await getActivePage();
            const el = page.locator(`button:has-text("${target}"), a:has-text("${target}"), input[value*="${target}" i]`).first();
            if (await el.count() > 0) {
              await el.click();
              await page.waitForTimeout(2500);
              const buf = await page.screenshot();
              await sendTelegramPhoto(buf, `✅ Clicked "${target}"`);
            } else {
              await sendTelegramMessage(`⚠️ Button matching "${target}" not found on screen.`);
            }
          } catch (err) {
            await sendTelegramMessage(`❌ Click error: ${err.message}`);
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
    console.log('Launching Playwright Chromium browser...');
    appState.browser = await chromium.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-first-run',
        '--no-zygote'
      ]
    });
    console.log('Browser launched successfully.');
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

async function getActivePage() {
  const context = await getBrowserContext();
  const pages = context.pages();
  if (pages.length > 0) {
    appState.activePage = pages[0];
  } else {
    appState.activePage = await context.newPage();
  }
  return appState.activePage;
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

  try {
    const page = await getActivePage();

    console.log(`Checking session on ${TARGET_URL}...`);
    await sendTelegramMessage(`🌐 Opening Epos Now...`);

    // Wait for full load including HTTP and JS redirects
    await page.goto(TARGET_URL, { waitUntil: 'load', timeout: 45000 });
    await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});

    const currentUrl = page.url();
    console.log(`Current page URL: ${currentUrl}`);

    // If redirected to login - use safe locator check
    const hasLoginInputs = await page.locator('#username, input[name="username"], input[type="password"]').count() > 0;
    const isLoginPage = currentUrl.toLowerCase().includes('login') || hasLoginInputs;

    if (!isLoginPage && !force) {
      console.log('Already logged in to Epos Now.');
      appState.isAuthenticated = true;
      await sendTelegramMessage('✅ Already logged in! Session is active.');
      return page;
    }

    console.log('Login required. Checking credentials...');
    if (!EPOS_PASSWORD) {
      const msg = '❌ EPOS_PASSWORD is not configured in Render environment variables! Please add EPOS_PASSWORD in Render Dashboard -> Environment.';
      await sendTelegramMessage(msg);
      throw new Error(msg);
    }

    await sendTelegramMessage(`🔑 Entering credentials for ${EPOS_USERNAME}...`);

    // Target inputs on https://login.eposnowhq.com using safe locators
    const userField = page.locator('#username, input[name="username"], input[type="email"]');
    await userField.first().waitFor({ state: 'visible', timeout: 20000 });
    await userField.first().fill(EPOS_USERNAME);

    const passField = page.locator('#password, input[name="password"], input[type="password"]');
    await passField.first().waitFor({ state: 'visible', timeout: 15000 });
    await passField.first().fill(EPOS_PASSWORD);

    // Submit form and cleanly wait for page navigation
    await sendTelegramMessage('🖱️ Submitting login credentials...');
    const submitBtn = page.locator('button[type="submit"], .submission-form__btn, input[type="submit"]');
    
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'load', timeout: 35000 }).catch(() => {}),
      submitBtn.first().click()
    ]);

    // Give page time to settle after redirect
    await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
    await page.waitForTimeout(3000);

    // Safely retrieve URL and text with retry if still navigating
    let afterUrl = '';
    let pageText = '';
    for (let attempt = 0; attempt < 6; attempt++) {
      try {
        await page.waitForLoadState('domcontentloaded').catch(() => {});
        afterUrl = page.url();
        pageText = await page.innerText('body');
        break;
      } catch (e) {
        console.log(`Waiting for navigation to settle (attempt ${attempt + 1})...`);
        await page.waitForTimeout(1500);
      }
    }
    console.log(`URL after submission: ${afterUrl}`);

    // Check for login error (e.g. invalid password)
    if (pageText.toLowerCase().includes('invalid username or password') ||
        pageText.toLowerCase().includes('incorrect username or password') ||
        pageText.toLowerCase().includes('check your details')) {
      const authErr = '❌ Epos Now rejected credentials (Invalid username or password). Please double check EPOS_PASSWORD in Render.';
      await sendTelegramMessage(authErr);
      throw new Error(authErr);
    }

    // Detect 2FA SMS challenge
    const is2FA = afterUrl.toLowerCase().includes('twofactor') ||
      afterUrl.toLowerCase().includes('verification') ||
      afterUrl.toLowerCase().includes('challenge') ||
      afterUrl.toLowerCase().includes('2fa') ||
      pageText.toLowerCase().includes('verification code') ||
      pageText.toLowerCase().includes('enter code') ||
      pageText.toLowerCase().includes('security code') ||
      pageText.toLowerCase().includes('sent a code') ||
      pageText.toLowerCase().includes('sms');

    if (is2FA) {
      console.log('2FA Challenge detected on screen!');

      // Check if there is an explicit button to send the SMS
      try {
        const sendSmsTrigger = page.locator('button:has-text("Send SMS"), button:has-text("Send code"), a:has-text("Send SMS"), a:has-text("Send code"), button:has-text("Text me")');
        if (await sendSmsTrigger.count() > 0) {
          console.log('Triggering SMS delivery button...');
          await sendSmsTrigger.first().click();
          await page.waitForTimeout(2000);
        }
      } catch (_) {}

      // Extract instructions text from the 2FA screen
      let screenSummary = '';
      try {
        const raw = await page.innerText('main, form, body');
        const lines = raw.split('\n')
          .map(l => l.trim())
          .filter(l => l.length > 5 && !l.toLowerCase().includes('copyright') && !l.toLowerCase().includes('terms') && !l.toLowerCase().includes('privacy'));
        screenSummary = lines.slice(0, 4).join('\n');
      } catch (_) {}

      // Take screenshot of 2FA screen and send to user
      try {
        await page.waitForTimeout(500);
        const buf = await page.screenshot();
        await sendTelegramPhoto(buf, '📱 2FA Verification Screen');
      } catch (_) {}

      await sendTelegramMessage(
        `📱 *Epos Now 2FA Code Required*\n\n` +
        (screenSummary ? `*Screen says:*\n_${screenSummary}_\n\n` : '') +
        `➡️ *Reply directly with your 6-digit code*.\n\n` +
        `💡 *Note*: If the screen asks for an *Authenticator App* code (e.g. Google Authenticator) or an *Email code*, please check those!\n` +
        `💡 Type */screentext* to view full screen text, or */click Resend* if there is a resend button.`
      );

      // Wait for user code from Telegram
      const code = await waitFor2FACode(300000);
      await sendTelegramMessage(`👍 Received code ${code}. Entering into Epos Now...`);

      // Fill code into 2FA input
      const codeInput = page.locator('input[name*="code" i], input[id*="code" i], input[type="text"], input[type="tel"], input[type="number"]');
      await codeInput.first().waitFor({ state: 'visible', timeout: 15000 });
      await codeInput.first().fill(code);

      // Check "Remember this device" if present
      try {
        const trustDevice = page.locator('input[type="checkbox"], input[id*="remember" i], input[id*="trust" i]');
        if (await trustDevice.count() > 0) await trustDevice.first().check();
      } catch (_) {}

      // Click verify / submit button and wait for redirect
      const verifyBtn = page.locator('button[type="submit"], input[type="submit"], button:has-text("Verify"), button:has-text("Submit"), button:has-text("Continue")');
      await Promise.all([
        page.waitForNavigation({ waitUntil: 'load', timeout: 35000 }).catch(() => {}),
        verifyBtn.first().click()
      ]);

      await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
      await page.waitForTimeout(3000);
    }

    // Save authenticated session state
    const context = await getBrowserContext();
    await context.storageState({ path: STORAGE_STATE_PATH });
    console.log('Saved authenticated session to storageState.json');
    appState.isAuthenticated = true;

    // Send confirmation & screenshot
    try {
      const finalBuf = await page.screenshot();
      await sendTelegramPhoto(finalBuf, '✅ Logged In Screen');
    } catch (_) {}

    await sendTelegramMessage(`🎉 *Logged in successfully!* Epos Now session is active and saved for future syncs.`);
    return page;
  } catch (err) {
    appState.isAuthenticated = false;
    const stackTop = err.stack ? err.stack.split('\n').slice(0, 3).join('\n') : '';
    console.error('Login flow failed:', err.message, stackTop);
    try {
      if (appState.activePage) {
        await appState.activePage.waitForTimeout(1000);
        const errBuf = await appState.activePage.screenshot();
        await sendTelegramPhoto(errBuf, `❌ Login Error: ${err.message.slice(0, 100)}\n${stackTop.slice(0, 120)}`);
      }
    } catch (_) {}
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

    // Always open a fresh view of the transactions report page
    console.log('Loading fresh transactions report page...');
    await sendTelegramMessage('⚡ Auto-loading all transactions from Epos Now...');
    await page.goto(TARGET_URL, { waitUntil: 'load', timeout: 45000 });
    await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
    await page.waitForTimeout(2500);

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

      function countCurrentTxRows() {
        var docs = getAllDocs();
        var total = 0;
        for (var di = 0; di < docs.length; di++) {
          var rows = docs[di].querySelectorAll('tr, [role="row"], tbody tr');
          total += rows.length;
        }
        return total;
      }

      function clickBtn(el) {
        try { el.scrollIntoView({ behavior: 'instant', block: 'center' }); } catch (e) {}
        try { el.focus(); } catch (e) {}
        try { el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true })); } catch (e) {}
        try { el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true })); } catch (e) {}
        try { el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true })); } catch (e) {}
        try { el.click(); } catch (e) {}
      }

      // 1. Try to expand page size to 50 or 100 if dropdown exists on desktop
      try {
        var selects = document.querySelectorAll('select');
        for (var si = 0; si < selects.length; si++) {
          var s = selects[si];
          var opts = Array.from(s.options).map(function(o) { return parseInt(o.value || o.text, 10); }).filter(function(n) { return !isNaN(n); });
          if (opts.includes(10) && opts.some(function(n) { return n >= 25; })) {
            var highest = Math.max.apply(Math, opts.filter(function(n) { return n <= 100; }));
            s.value = String(highest);
            s.dispatchEvent(new Event('change', { bubbles: true }));
            await new Promise(function(r) { setTimeout(r, 2000); });
            break;
          }
        }
      } catch (_) {}

      function findNextBtn() {
        var docs = getAllDocs();
        for (var di = 0; di < docs.length; di++) {
          var doc = docs[di];
          var candidates = doc.querySelectorAll('button, a, [role="button"], input[type="button"], li, span');
          for (var i = 0; i < candidates.length; i++) {
            var el = candidates[i];
            if (el.id === 'epos-sync-banner' || (el.closest && el.closest('#epos-sync-banner'))) continue;

            // Ignore disabled buttons
            var isDisabled = el.disabled ||
              el.classList.contains('disabled') ||
              el.getAttribute('aria-disabled') === 'true' ||
              el.getAttribute('disabled') !== null;
            if (isDisabled) continue;

            var aria = (el.getAttribute('aria-label') || '').toLowerCase();
            var title = (el.getAttribute('title') || '').toLowerCase();
            var txt = (el.innerText || el.textContent || el.value || '').trim();
            var cls = (el.className || '').toString().toLowerCase();

            // Next page indicators on desktop table
            if (aria.includes('next') || title.includes('next') || aria.includes('forward') || title.includes('forward')) {
              return el;
            }
            if (cls.includes('paginate_button next') || cls.includes('page-next') || cls.includes('next-page') || cls.includes('pagination-next') || cls.includes('btn-next')) {
              return el;
            }
            if (txt === '>' || txt === '›' || txt === '»' || txt === 'Next' || txt === 'Next >' || txt === 'Next ›' || txt === 'Next Page') {
              return el;
            }
            // Right chevron / arrow icon
            var html = el.innerHTML || '';
            var hasRightIcon = (html.includes('chevron-right') || html.includes('arrow-right') || html.includes('angle-right') || html.includes('fa-chevron-right') || html.includes('bi-chevron-right')) &&
              !cls.includes('prev') && !aria.includes('prev') && !title.includes('prev');
            if (hasRightIcon) {
              return el;
            }
          }

          // Fallback to "more transactions" infinite scroll button
          for (var j = 0; j < candidates.length; j++) {
            var c = candidates[j];
            var cTxt = (c.innerText || c.textContent || '').replace(/\s+/g, ' ').trim().toLowerCase();
            if (cTxt.includes('more transaction') || cTxt.includes('more transactions') || cTxt.includes('load more') || cTxt.includes('show more')) {
              return c;
            }
          }
        }
        return null;
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

      function parseTimeStr(timeStr) {
        var tm = timeStr.match(/(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([apAP][mM])?/i);
        if (!tm) return null;
        var h = parseInt(tm[1], 10);
        var ampm = tm[4] ? tm[4].toUpperCase() : '';
        if (ampm === 'PM' && h < 12) h += 12;
        if (ampm === 'AM' && h === 12) h = 0;
        return String(h).padStart(2, '0') + ':00';
      }

      var datePatternRegex = /(?:\b(?:Today|Yesterday)\b|\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}(?:st|nd|rd|th)?[\s\-\/]+(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)(?:[\s\-\/,]+\d{2,4})?\b|\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b)/gi;
      var eposRowRegex = /(\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b|\b\d{4}-\d{2}-\d{2}\b)[,\s]+(\d{1,2}:\d{2}(?::\d{2})?\s*[apAP][mM]?)[,\s]+[\$£€]?\s*([0-9]+\.[0-9]{2})/g;
      var timeAmtRegex = /(\d{1,2}:\d{2}(?::\d{2})?\s*[apAP][mM]?)[,\s]+[\$£€]?\s*([0-9]+\.[0-9]{2})/g;
      var amtTimeRegex = /[\$£€]?\s*([0-9]+\.[0-9]{2})[,\s]+(\d{1,2}:\d{2}(?::\d{2})?\s*[apAP][mM]?)/g;

      // Scrape page by page to handle desktop table pagination AND infinite scroll
      var collectedTxList = [];
      var maxPages = 40;
      var page = 0;
      var consecutiveMiss = 0;

      while (page < maxPages) {
        page++;
        scrollAllToBottom();
        await new Promise(function(r) { setTimeout(r, 600); });

        // Extract text from all documents/frames on current page
        var docs = getAllDocs();
        var pageText = '';
        for (var di = 0; di < docs.length; di++) {
          if (docs[di].body) pageText += docs[di].body.innerText + '\n';
        }

        // Find date markers on current page
        var pageDateMarkers = [];
        var dMatch;
        datePatternRegex.lastIndex = 0;
        while ((dMatch = datePatternRegex.exec(pageText)) !== null) {
          var iso = parseAnyDate(dMatch[0]);
          if (iso) pageDateMarkers.push({ index: dMatch.index, date: iso, raw: dMatch[0] });
        }
        var defaultDate = pageDateMarkers.length > 0 ? pageDateMarkers[0].date : (new Date().toISOString().split('T')[0]);

        // Parse rows on current page
        var pageTxList = [];
        var tMatch;
        eposRowRegex.lastIndex = 0;
        while ((tMatch = eposRowRegex.exec(pageText)) !== null) {
          var rowDate = parseAnyDate(tMatch[1]);
          var rowTime = tMatch[2];
          var rowHour = parseTimeStr(rowTime);
          var rowAmt = parseFloat(tMatch[3]);
          if (rowDate && rowHour !== null && !isNaN(rowAmt)) {
            pageTxList.push({ date: rowDate, time: rowTime, hour: rowHour, amount: rowAmt, raw: tMatch[0].replace(/\s+/g, ' ').trim() });
          }
        }

        if (pageTxList.length === 0) {
          timeAmtRegex.lastIndex = 0;
          while ((tMatch = timeAmtRegex.exec(pageText)) !== null) {
            var timeStr = tMatch[1];
            var hourStr = parseTimeStr(timeStr);
            var amt = parseFloat(tMatch[2]);
            if (hourStr !== null && !isNaN(amt)) {
              pageTxList.push({ date: defaultDate, time: timeStr, hour: hourStr, amount: amt, raw: tMatch[0].replace(/\s+/g, ' ').trim() });
            }
          }
        }

        if (pageTxList.length === 0) {
          amtTimeRegex.lastIndex = 0;
          while ((tMatch = amtTimeRegex.exec(pageText)) !== null) {
            var amt2 = parseFloat(tMatch[1]);
            var timeStr2 = tMatch[2];
            var hourStr2 = parseTimeStr(timeStr2);
            if (hourStr2 !== null && !isNaN(amt2)) {
              pageTxList.push({ date: defaultDate, time: timeStr2, hour: hourStr2, amount: amt2, raw: tMatch[0].replace(/\s+/g, ' ').trim() });
            }
          }
        }

        // Add all rows from this page (preserves separate transactions with identical amounts at the same minute)
        for (var ti = 0; ti < pageTxList.length; ti++) {
          collectedTxList.push(pageTxList[ti]);
        }

        // Check if there is a next page button (Right Arrow or More Transactions)
        var nextBtn = findNextBtn();
        if (!nextBtn) {
          consecutiveMiss++;
          if (consecutiveMiss >= 2) break;
          await new Promise(function(r) { setTimeout(r, 800); });
          nextBtn = findNextBtn();
          if (!nextBtn) break;
        }

        consecutiveMiss = 0;

        // Remember first row text and total count before click to detect page turn
        var firstRowBefore = '';
        try {
          var r0 = document.querySelector('tbody tr');
          if (r0) firstRowBefore = r0.innerText || '';
        } catch (_) {}
        var rowCountBefore = countCurrentTxRows();

        // Click next page button
        clickBtn(nextBtn);

        // Wait for page turn or table rows to update
        var waitStart = Date.now();
        var changed = false;
        while (Date.now() - waitStart < 4000) {
          await new Promise(function(r) { setTimeout(r, 200); });
          var firstRowAfter = '';
          try {
            var r1 = document.querySelector('tbody tr');
            if (r1) firstRowAfter = r1.innerText || '';
          } catch (_) {}
          if (firstRowAfter && firstRowAfter !== firstRowBefore) {
            changed = true;
            break;
          }
          if (countCurrentTxRows() > rowCountBefore) {
            changed = true;
            break;
          }
        }

        await new Promise(function(r) { setTimeout(r, 500); });
      }

      var txList = collectedTxList;

      // Group into daysGroup
      var daysGroup = {};
      for (var i = 0; i < txList.length; i++) {
        var tx = txList[i];
        var dKey = tx.date;
        if (!daysGroup[dKey]) {
          daysGroup[dKey] = { totalSales: 0, count: 0, hourly: {} };
        }
        daysGroup[dKey].count++;
        daysGroup[dKey].totalSales += tx.amount;
        daysGroup[dKey].hourly[tx.hour] = (daysGroup[dKey].hourly[tx.hour] || 0) + tx.amount;
      }

      var daysBatch = [];
      var sortedDays = Object.keys(daysGroup).sort().reverse();
      for (var d = 0; d < sortedDays.length; d++) {
        var dayDate = sortedDays[d];
        daysGroup[dayDate].totalSales = Math.round(daysGroup[dayDate].totalSales * 100) / 100;
        for (var hk in daysGroup[dayDate].hourly) {
          daysGroup[dayDate].hourly[hk] = Math.round(daysGroup[dayDate].hourly[hk] * 100) / 100;
        }
        daysBatch.push({ date: dayDate, totalSales: daysGroup[dayDate].totalSales, count: daysGroup[dayDate].count, hourly: daysGroup[dayDate].hourly });
      }

      var txRows = txList.map(function(t, idx) {
        var rawC = (t.raw || '').replace(/\s+/g, ' ').trim();
        var uid = (t.date + '_' + (t.time || '').replace(/[^a-zA-Z0-9]/g, '') + '_' + t.amount.toFixed(2) + '_' + idx + '_' + rawC).slice(0, 120).toLowerCase().replace(/[^a-z0-9_]/g, '-');
        return { id: uid, date: t.date, time: t.time || '', amount: t.amount, raw_line: rawC };
      });

      return { daysBatch, txRows, totalTx: txList.length, pagesLoaded: page };
    });

    console.log(`Scraped ${scrapeResult.totalTx} transactions across ${scrapeResult.pagesLoaded} batches for ${scrapeResult.daysBatch.length} day(s).`);

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
      batches: scrapeResult.pagesLoaded,
      topDay: scrapeResult.daysBatch[0] ? `${scrapeResult.daysBatch[0].date}: $${scrapeResult.daysBatch[0].totalSales}` : 'N/A'
    };
    appState.consecutiveFailures = 0;

    // Send summary to Telegram if manually triggered
    if (isManual) {
      const summaryLines = scrapeResult.daysBatch.map(d => `• *${d.date}*: $${d.totalSales.toFixed(2)} (${d.count} txs)`);
      await sendTelegramMessage(
        `✅ *Sync Complete!*\n\n` +
        `Auto-loaded *${scrapeResult.pagesLoaded}* batches.\n` +
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
    `Worker restarted with enhanced Playwright & Telegram error recovery.\n\n` +
    `Type /login to sign in or /screenshot to view screen.`
  ).catch(console.error);
});
