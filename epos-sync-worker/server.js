require('dotenv').config();
const express = require('express');
const cron = require('node-cron');
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Configuration
const PORT = process.env.PORT || 3000;
const EPOS_USERNAME = process.env.EPOS_USERNAME || '';
const EPOS_PASSWORD = process.env.EPOS_PASSWORD || '';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://ckyutsdgpdamnhsqoail.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || '';
const CRON_SCHEDULE = process.env.CRON_SCHEDULE || '*/15 * * * *';
const STORAGE_STATE_PATH = path.join(__dirname, 'storageState.json');
const TARGET_URL = 'https://reporting.eposnowhq.com/transactions';

// Whitelisted management email accounts (Server-enforced, configurable via Render Env Var or code)
const DEFAULT_MANAGERS = [
  'hqmahmood@gmail.com',
  'anatolyakebabs@gmail.com'
];
const AUTHORIZED_MANAGERS = process.env.AUTHORIZED_MANAGERS
  ? process.env.AUTHORIZED_MANAGERS.split(',').map(e => e.trim().toLowerCase()).filter(Boolean)
  : DEFAULT_MANAGERS;

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
  telegramOffset: 0,
  activeSyncProgress: {
    isSyncing: false,
    currentChunk: 0,
    totalChunks: 0,
    currentRange: '',
    totalTx: 0,
    status: 'idle'
  }
};

// Express App
const app = express();
app.use(express.json());

// CORS Middleware for web browser calls from Timesheet dashboard
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Google / Firebase ID Token Verification Cache
let cachedGoogleCerts = null;
let googleCertsExpiry = 0;

async function getGooglePublicCerts() {
  const now = Date.now();
  if (cachedGoogleCerts && now < googleCertsExpiry) {
    return cachedGoogleCerts;
  }
  try {
    const res = await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
    if (!res.ok) throw new Error(`HTTP ${res.status} fetching Google certs`);
    const cacheControl = res.headers.get('cache-control') || '';
    const maxAgeMatch = cacheControl.match(/max-age=(\d+)/);
    const maxAgeMs = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) * 1000 : 6 * 3600 * 1000;
    cachedGoogleCerts = await res.json();
    googleCertsExpiry = now + maxAgeMs;
    return cachedGoogleCerts;
  } catch (err) {
    console.error('Failed to load Google certificates:', err.message);
    if (cachedGoogleCerts) return cachedGoogleCerts;
    throw err;
  }
}

async function verifyGoogleIdToken(token) {
  if (!token || typeof token !== 'string') {
    throw new Error('ID token is missing or invalid');
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed ID token structure');
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  let header, payload;
  try {
    header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch (e) {
    throw new Error('Failed to parse token segments');
  }

  if (header.alg !== 'RS256') {
    throw new Error(`Unsupported token algorithm: ${header.alg}`);
  }
  if (!header.kid) {
    throw new Error('Token header is missing kid');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < nowSeconds) {
    throw new Error('Token has expired');
  }

  const expectedProjectId = 'anatolya-staff-portal';
  if (payload.iss !== `https://securetoken.google.com/${expectedProjectId}`) {
    throw new Error(`Invalid token issuer: ${payload.iss}`);
  }
  if (payload.aud !== expectedProjectId) {
    throw new Error(`Invalid token audience: ${payload.aud}`);
  }

  const certs = await getGooglePublicCerts();
  const cert = certs[header.kid];
  if (!cert) {
    throw new Error(`No certificate found matching key ID ${header.kid}`);
  }

  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(`${headerB64}.${payloadB64}`);
  const isValid = verifier.verify(cert, signatureB64, 'base64url');
  if (!isValid) {
    throw new Error('Cryptographic signature verification failed');
  }

  return payload;
}

// Authentication Middleware: Verifies Google token & enforces manager whitelist
async function requireAuthorizedManager(req, res, next) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Missing or malformed Authorization header. Expected Bearer <ID_TOKEN>.'
    });
  }

  const idToken = authHeader.slice(7).trim();
  try {
    const claims = await verifyGoogleIdToken(idToken);
    const email = (claims.email || '').trim().toLowerCase();

    const isWhitelisted = AUTHORIZED_MANAGERS.some(m => m.toLowerCase() === email);
    if (!isWhitelisted) {
      console.warn(`[Security] Denied access to non-whitelisted account: ${email}`);
      return res.status(403).json({
        error: 'Forbidden',
        message: `Account '${email}' is not authorized to access management data.`
      });
    }

    req.user = claims;
    next();
  } catch (err) {
    console.warn(`[Security] Token verification failed: ${err.message}`);
    return res.status(401).json({
      error: 'Unauthorized',
      message: `Invalid or expired session token: ${err.message}`
    });
  }
}

// Supabase query helper on the server using service role / backend key
async function supabaseServerFetch(path, options = {}) {
  const url = `${SUPABASE_URL}/rest/v1/${path}`;
  const headers = {
    'apikey': SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };
  const res = await fetch(url, { ...options, headers });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Supabase query failed [${res.status}]: ${errText}`);
  }
  const contentType = res.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    return await res.json();
  }
  return null;
}

// Instant reset endpoint if sync ever gets stuck
app.get('/sync-reset', (req, res) => {
  appState.isSyncing = false;
  appState.isLoggingIn = false;
  appState.activeSyncProgress = null;
  res.json({ status: 'ok', message: 'Sync state reset successfully' });
});

// Live debug screenshot endpoint (view in browser)
app.get('/debug/screenshot', async (req, res) => {
  try {
    const page = await getActivePage();
    const buf = await page.screenshot({ fullPage: false });
    res.setHeader('Content-Type', 'image/png');
    res.send(buf);
  } catch (err) {
    res.status(500).send('Screenshot error: ' + err.message);
  }
});

// Live debug screentext endpoint (inspect text in browser)
app.get('/debug/screentext', async (req, res) => {
  try {
    const page = await getActivePage();
    const text = await page.innerText('body');
    const url = page.url();
    res.json({ url, length: text.length, preview: text.slice(0, 3000) });
  } catch (err) {
    res.status(500).send('Screen text error: ' + err.message);
  }
});

// Live debug DOM inspection endpoint
app.get('/debug/dom-inspect', async (req, res) => {
  try {
    const page = await getActivePage();
    const elements = await page.evaluate(() => {
      const items = [];
      const all = document.querySelectorAll('*');
      for (let i = 0; i < all.length; i++) {
        const el = all[i];
        const text = (el.innerText || el.textContent || '').trim();
        const tag = el.tagName.toLowerCase();
        const role = el.getAttribute('role') || '';
        const ariaLabel = el.getAttribute('aria-label') || '';
        const placeholder = el.getAttribute('placeholder') || '';
        const id = el.id || '';
        const cls = el.className ? String(el.className) : '';

        // Only look for relevant UI elements
        if (
          /filters?|today|yesterday|period|custom|apply|search/i.test(text) ||
          /filters?|today|yesterday|period|custom|apply|search/i.test(ariaLabel) ||
          /filters?|today|yesterday|period|custom|apply|search/i.test(placeholder)
        ) {
          const rect = el.getBoundingClientRect();
          if (rect.width > 0 && rect.height > 0 && el.children.length <= 3) {
            items.push({
              tag,
              id,
              cls: cls.slice(0, 80),
              role,
              text: text.slice(0, 80),
              ariaLabel,
              rect: { x: Math.round(rect.x), y: Math.round(rect.y), w: Math.round(rect.width), h: Math.round(rect.height) }
            });
          }
        }
      }
      return items;
    });
    res.json({ url: page.url(), count: elements.length, elements });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Live debug eval endpoint
app.all('/debug/eval', async (req, res) => {
  try {
    const page = await getActivePage();
    const code = req.query.code || (req.body && req.body.code);
    if (!code) return res.status(400).send('Missing code parameter');
    const result = await page.evaluate((c) => {
      try {
        return { success: true, result: eval(c) };
      } catch (e) {
        return { success: false, error: e.message, stack: e.stack };
      }
    }, code);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Health endpoint for keep-alive cron & monitoring (Public)
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

// Real-time sync progress status for Timesheet Dashboard
app.get('/sync-status', (req, res) => {
  const isSyncActive = appState.isSyncing || !!(appState.activeSyncProgress && appState.activeSyncProgress.isSyncing);
  res.json({
    isSyncing: isSyncActive,
    progress: appState.activeSyncProgress,
    lastSyncTime: appState.lastSyncTime,
    lastSyncResult: appState.lastSyncResult
  });
});

// Secure Data Retrieval (Staff, Roster, Hourly Sales, Expenses)
app.post('/api/data', requireAuthorizedManager, async (req, res) => {
  try {
    const [staffRows, rosterRows, salesRows, expenseRows] = await Promise.all([
      supabaseServerFetch('staff?select=*&order=name.asc'),
      supabaseServerFetch('roster?select=*&order=date.asc'),
      supabaseServerFetch('hourly_sales?select=*&order=date.asc'),
      supabaseServerFetch('expenses?select=*&order=date.desc')
    ]);

    const cleanDateStr = (d) => {
      if (!d) return '';
      let str = d.toString().trim();
      if (str.includes('T')) return str.split('T')[0];
      const match = str.match(/(\d{4})-(\d{2})-(\d{2})/);
      return match ? match[0] : str;
    };

    const logs = (rosterRows || []).map(r => ({
      date: r.date,
      weekCommencing: r.week_commencing || r.date,
      name: r.name,
      from: r.shift_from || '',
      to: r.shift_to || '',
      cashRate: Number(r.cash_rate) || 0,
      taxRate: Number(r.tax_rate) || 0,
      totalHours: Number(r.total_hours) || 0,
      cashHours: Number(r.cash_hours) || 0,
      taxHours: Number(r.tax_hours) || 0
    }));

    const staff = (staffRows || []).map(s => {
      const isOwner = (s.name && s.name.toString().trim().toLowerCase() === 'qaiser');
      return {
        name: s.name,
        cashRate: isOwner ? 0 : (Number(s.cash_rate) || 25),
        taxRate: isOwner ? 0 : (Number(s.tax_rate) || 30),
        status: s.status || 'Active'
      };
    });

    const sales = (salesRows || []).map(s => {
      const tot = Number(s.total_sales) || 0;
      let h = s.hourly || {};
      if (typeof h === 'string') {
        try { h = JSON.parse(h); } catch (_) { h = {}; }
      }
      let card = null;
      let cash = null;

      if (s.card_sales !== undefined && s.card_sales !== null && Number(s.card_sales) > 0) {
        card = Number(s.card_sales);
      } else if (h._cardSales !== undefined && h._cardSales !== null) {
        card = Number(h._cardSales);
      }

      if (s.cash_sales !== undefined && s.cash_sales !== null && Number(s.cash_sales) > 0) {
        cash = Number(s.cash_sales);
      } else if (h._cashSales !== undefined && h._cashSales !== null) {
        cash = Number(h._cashSales);
      }

      if (card === null && cash === null) {
        card = tot;
        cash = 0;
      } else if (card === null) {
        card = Math.max(0, tot - (cash || 0));
      } else if (cash === null) {
        cash = Math.max(0, tot - (card || 0));
      }

      return {
        date: s.date,
        totalSales: tot,
        cardSales: Math.round(card * 100) / 100,
        cashSales: Math.round(cash * 100) / 100,
        hourly: h,
        updatedAt: s.updated_at || ''
      };
    });

    const expenses = (expenseRows || []).map(x => ({
      id: x.id,
      date: cleanDateStr(x.date),
      category: x.category || 'Others',
      amount: Number(x.amount) || 0,
      notes: x.notes || ''
    }));

    res.json({ logs, staff, sales, expenses });
  } catch (err) {
    console.error('Error in /api/data:', err);
    res.status(500).json({ error: 'Failed to fetch data', message: err.message });
  }
});

// Secure Data Mutations (Save/Delete shifts, expenses, sales, copy week)
app.post('/api/mutate', requireAuthorizedManager, async (req, res) => {
  const payload = req.body;
  if (!payload || !payload.action) {
    return res.status(400).json({ error: 'Missing mutation action' });
  }

  const cleanDateStr = (d) => {
    if (!d) return '';
    let str = d.toString().trim();
    if (str.includes('T')) return str.split('T')[0];
    const match = str.match(/(\d{4})-(\d{2})-(\d{2})/);
    return match ? match[0] : str;
  };

  const getMondayString = (d) => {
    const dt = new Date(d + 'T12:00:00Z');
    const day = dt.getUTCDay();
    const diff = (day === 0 ? -6 : 1) - day;
    dt.setUTCDate(dt.getUTCDate() + diff);
    return dt.toISOString().split('T')[0];
  };

  const addDaysString = (dateStr, days) => {
    const d = new Date(dateStr + 'T12:00:00Z');
    d.setUTCDate(d.getUTCDate() + days);
    return d.toISOString().split('T')[0];
  };

  try {
    if (payload.action === 'save' && payload.entry) {
      const e = payload.entry;
      const cleanD = cleanDateStr(e.date);
      const row = {
        date: cleanD,
        week_commencing: e.weekCommencing || getMondayString(cleanD),
        name: e.name.toString().trim(),
        shift_from: e.from || '',
        shift_to: e.to || '',
        cash_rate: Number(e.cashRate) || 0,
        tax_rate: Number(e.taxRate) || 0,
        total_hours: Number(e.totalHours) || 0,
        cash_hours: Number(e.cashHours) || 0,
        tax_hours: Number(e.taxHours) || 0,
        updated_at: new Date().toISOString()
      };
      await supabaseServerFetch('roster?on_conflict=date,name', {
        method: 'POST',
        headers: { 'Prefer': 'resolution=merge-duplicates' },
        body: JSON.stringify(row)
      });
      return res.json({ status: 'success' });
    }

    if (payload.action === 'save_expense' && payload.expense) {
      const x = payload.expense;
      const row = {
        date: cleanDateStr(x.date),
        category: x.category || 'Others',
        amount: Number(x.amount) || 0,
        notes: x.notes || ''
      };
      const result = await supabaseServerFetch('expenses', {
        method: 'POST',
        headers: { 'Prefer': 'return=representation' },
        body: JSON.stringify(row)
      });
      return res.json({ status: 'success', item: result && result[0] ? result[0] : row });
    }

    if (payload.action === 'delete_expense' && payload.id) {
      await supabaseServerFetch(`expenses?id=eq.${payload.id}`, {
        method: 'DELETE'
      });
      return res.json({ status: 'success' });
    }

    if (payload.action === 'delete') {
      const cleanD = cleanDateStr(payload.date);
      const nameEnc = encodeURIComponent(payload.name.toString().trim());
      await supabaseServerFetch(`roster?date=eq.${cleanD}&name=eq.${nameEnc}`, {
        method: 'DELETE'
      });
      return res.json({ status: 'success' });
    }

    if (payload.action === 'save_hourly_sales') {
      const cleanD = cleanDateStr(payload.date);
      let h = payload.hourly || {};
      if (typeof h === 'string') {
        try { h = JSON.parse(h); } catch (_) { h = {}; }
      }
      if (payload.cardSales !== undefined) h._cardSales = Number(payload.cardSales) || 0;
      if (payload.cashSales !== undefined) h._cashSales = Number(payload.cashSales) || 0;
      const row = {
        date: cleanD,
        total_sales: Number(payload.totalSales) || 0,
        hourly: h,
        updated_at: new Date().toISOString()
      };
      await supabaseServerFetch('hourly_sales?on_conflict=date', {
        method: 'POST',
        headers: { 'Prefer': 'resolution=merge-duplicates' },
        body: JSON.stringify(row)
      });
      return res.json({ status: 'success' });
    }

    if (payload.action === 'copy_previous_week') {
      const targetMon = payload.targetWeekMonday;
      const prevMon = addDaysString(targetMon, -7);
      const prevShifts = await supabaseServerFetch(`roster?week_commencing=eq.${prevMon}`);
      if (!prevShifts || prevShifts.length === 0) {
        return res.json({ status: 'success', count: 0 });
      }
      const copied = prevShifts.map(s => {
        const nextDate = addDaysString(s.date, 7);
        return {
          date: nextDate,
          week_commencing: targetMon,
          name: s.name,
          shift_from: s.shift_from || '',
          shift_to: s.shift_to || '',
          cash_rate: Number(s.cash_rate) || 0,
          tax_rate: Number(s.tax_rate) || 0,
          total_hours: Number(s.total_hours) || 0,
          cash_hours: Number(s.cash_hours) || 0,
          tax_hours: Number(s.tax_hours) || 0,
          updated_at: new Date().toISOString()
        };
      });
      await supabaseServerFetch('roster?on_conflict=date,name', {
        method: 'POST',
        headers: { 'Prefer': 'resolution=merge-duplicates' },
        body: JSON.stringify(copied)
      });
      return res.json({ status: 'success', count: copied.length });
    }

    return res.status(400).json({ error: `Unknown action ${payload.action}` });
  } catch (err) {
    console.error('Error in /api/mutate:', err);
    res.status(500).json({ error: 'Mutation failed', message: err.message });
  }
});

// Manual HTTP trigger (Protected by manager whitelist)
app.all('/sync', requireAuthorizedManager, async (req, res) => {
  const shouldWait = req.query.wait === 'true' || req.query.wait === '1';
  const notifyTelegram = req.query.notify === 'true' || req.query.notify === '1';
  const startDate = req.query.startDate || req.body.startDate || null;
  const endDate = req.query.endDate || req.body.endDate || null;

  if (appState.isSyncing) {
    if (!shouldWait) {
      return res.json({ 
        status: 'in_progress', 
        message: 'Sync already underway', 
        progress: appState.activeSyncProgress 
      });
    }
    // Wait for the active sync to complete (up to 45 seconds)
    const start = Date.now();
    while (appState.isSyncing && (Date.now() - start < 45000)) {
      await new Promise(r => setTimeout(r, 1000));
    }
    return res.json({
      status: 'ok',
      message: 'Sync completed',
      lastSyncResult: appState.lastSyncResult,
      lastSyncTime: appState.lastSyncTime
    });
  }

  if (shouldWait) {
    try {
      await runSync(true, notifyTelegram, startDate, endDate);
      return res.json({
        status: 'ok',
        message: 'Sync completed',
        lastSyncResult: appState.lastSyncResult,
        lastSyncTime: appState.lastSyncTime
      });
    } catch (err) {
      return res.status(500).json({ status: 'error', message: err.message });
    }
  } else {
    appState.activeSyncProgress = {
      isSyncing: true,
      currentChunk: 1,
      totalChunks: 1,
      currentRange: `${startDate || 'Today'} to ${endDate || 'Today'}`,
      totalTx: 0,
      status: 'starting'
    };
    runSync(true, notifyTelegram, startDate, endDate).catch(console.error);
    return res.json({ 
      status: 'triggered', 
      message: 'Sync process initiated',
      startDate,
      endDate,
      progress: appState.activeSyncProgress
    });
  }
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
        } else if (cmd.startsWith('/sync')) {
          const parts = text.split(/\s+/);
          let sDate = null;
          let eDate = null;
          if (parts.length >= 3 && /^\d{4}-\d{2}-\d{2}$/.test(parts[1]) && /^\d{4}-\d{2}-\d{2}$/.test(parts[2])) {
            sDate = parts[1];
            eDate = parts[2];
            await sendTelegramMessage(`⏳ Starting sync for date range ${sDate} to ${eDate} (chunked in <=31 days)...`);
          } else {
            await sendTelegramMessage('⏳ Starting sync process for today\'s live transactions...');
          }
          runSync(true, true, sDate, eDate).catch(async (e) => {
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
async function ensureLoggedIn(force = false, isManual = false) {
  if (appState.isLoggingIn) return;
  appState.isLoggingIn = true;

  try {
    const page = await getActivePage();

    console.log(`Checking session on ${TARGET_URL}...`);
    if (isManual) await sendTelegramMessage(`🌐 Opening Epos Now...`);

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
      if (isManual) await sendTelegramMessage('✅ Already logged in! Session is active.');
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
// Sync Engine (Runs Scraper, Filter & Upserts to Supabase)
// ----------------------------------------------------

// Splits any date range into sequential chunks of max 31 days (Epos Now limit)
function splitDateRangeIntoChunks(startDateStr, endDateStr, maxDays = 31) {
  const chunks = [];
  const start = new Date(startDateStr + 'T00:00:00Z');
  const end = new Date(endDateStr + 'T00:00:00Z');

  if (isNaN(start.getTime()) || isNaN(end.getTime()) || start > end) {
    return [{ from: startDateStr, to: endDateStr }];
  }

  let currStart = new Date(start);
  while (currStart <= end) {
    let currEnd = new Date(currStart);
    currEnd.setUTCDate(currEnd.getUTCDate() + (maxDays - 1));
    if (currEnd > end) {
      currEnd = new Date(end);
    }

    chunks.push({
      from: currStart.toISOString().split('T')[0],
      to: currEnd.toISOString().split('T')[0]
    });

    currStart = new Date(currEnd);
    currStart.setUTCDate(currStart.getUTCDate() + 1);
  }
  return chunks;
}

// Interacts with Epos Now Filters: Time Period -> Yesterday / Custom -> Start & End Date -> Apply
async function applyEposDateFilter(page, fromIso, toIso) {
  console.log('[EposFilter] ==========================================');
  console.log(`[EposFilter] Setting Epos Now Filter: ${fromIso} to ${toIso}...`);

  // Calculate if this request targets Yesterday
  const now = new Date();
  const yDate = new Date(now);
  yDate.setDate(yDate.getDate() - 1);
  const yesterdayIso = yDate.toISOString().split('T')[0];
  const isYesterday = (fromIso === toIso && fromIso === yesterdayIso);

  const [fYear, fMonth, fDay] = fromIso.split('-');
  const [tYear, tMonth, tDay] = toIso.split('-');
  const fromFormatted = `${fDay}/${fMonth}/${fYear}`;
  const toFormatted = `${tDay}/${tMonth}/${tYear}`;

  try {
    // Step 1: Ensure Filters panel is actually visible on screen
    console.log('[EposFilter] Step 1: Checking if Filters panel is visible...');
    const isPanelVisible = await page.evaluate(() => {
      var applyBtns = document.querySelectorAll('button, input[type="submit"], a');
      for (var i = 0; i < applyBtns.length; i++) {
        var t = (applyBtns[i].innerText || applyBtns[i].value || '').trim().toLowerCase();
        if (t === 'apply' || t === 'run report') {
          var r = applyBtns[i].getBoundingClientRect();
          if (r.width > 0 && r.height > 0) return true;
        }
      }
      return false;
    });

    if (!isPanelVisible) {
      console.log('[EposFilter] Filters panel is closed. Clicking "Filters" button...');
      const filterBtn = page.locator('button, a, [role="button"]').filter({ hasText: /^Filters?$/i }).first();
      if (await filterBtn.count() > 0) {
        await filterBtn.click();
        console.log('[EposFilter] Clicked Filters button.');
        await page.waitForTimeout(1200);
      } else {
        const anyFilterBtn = page.locator('button:has-text("Filter"), a:has-text("Filter"), [aria-label*="Filter" i]').first();
        if (await anyFilterBtn.count() > 0) {
          await anyFilterBtn.click();
          await page.waitForTimeout(1200);
        }
      }
    } else {
      console.log('[EposFilter] Filters panel is already visible.');
    }

    // Step 2: In "Time Period" field, select "Yesterday" or "Custom"
    const targetPeriod = isYesterday ? 'Yesterday' : 'Custom';
    console.log(`[EposFilter] Step 2: Selecting "${targetPeriod}" in Time Period...`);

    // A: Native select element
    const selectRes = await page.evaluate((targetOpt) => {
      var selects = document.querySelectorAll('select');
      for (var i = 0; i < selects.length; i++) {
        var s = selects[i];
        for (var j = 0; j < s.options.length; j++) {
          var optTxt = (s.options[j].text || s.options[j].value || '').trim().toLowerCase();
          if (optTxt === targetOpt.toLowerCase() || optTxt.includes(targetOpt.toLowerCase())) {
            s.selectedIndex = j;
            s.value = s.options[j].value;
            s.dispatchEvent(new Event('input', { bubbles: true }));
            s.dispatchEvent(new Event('change', { bubbles: true }));
            return { success: true, type: 'native_select', value: s.value };
          }
        }
      }
      return { success: false };
    }, targetPeriod);

    console.log('[EposFilter] Native select result:', selectRes);

    // B: Custom dropdown trigger / input field
    if (!selectRes.success) {
      const triggerClicked = await page.evaluate(() => {
        var all = Array.from(document.querySelectorAll('label, div, span, p'));
        for (var i = 0; i < all.length; i++) {
          var t = (all[i].innerText || '').trim().toLowerCase();
          if (t === 'time period' || t.startsWith('time period')) {
            var parent = all[i].closest('.form-group, .field, div.row, div') || all[i].parentElement;
            if (parent) {
              var inputOrBtn = parent.querySelector('input, button, [role="combobox"], [role="button"], .dropdown-toggle, .select2-selection, div[tabindex]');
              if (inputOrBtn) {
                inputOrBtn.click();
                return true;
              }
            }
          }
        }
        var triggers = Array.from(document.querySelectorAll('button, [role="combobox"], div.dropdown-toggle, .select2-selection'));
        for (var j = 0; j < triggers.length; j++) {
          var txt = (triggers[j].innerText || '').toLowerCase();
          if (txt.includes('today') || txt.includes('yesterday') || txt.includes('this week') || txt.includes('custom') || txt.includes('time period')) {
            triggers[j].click();
            return true;
          }
        }
        return false;
      });

      if (triggerClicked) {
        await page.waitForTimeout(600);
        const optLocator = page.locator(`li:has-text("${targetPeriod}"), [role="option"]:has-text("${targetPeriod}"), a:has-text("${targetPeriod}"), span:has-text("${targetPeriod}"), div:has-text("${targetPeriod}")`).first();
        if (await optLocator.count() > 0) {
          await optLocator.click();
          console.log(`[EposFilter] Clicked dropdown option "${targetPeriod}".`);
          await page.waitForTimeout(1000);
        }
      }
    } else {
      await page.waitForTimeout(1000);
    }

    // Step 3: If "Custom", fill Start Date & End Date calendar pickers
    if (!isYesterday) {
      console.log(`[EposFilter] Step 3: Filling Start Date (${fromFormatted}) and End Date (${toFormatted})...`);
      await page.evaluate(({ fromFormatted, toFormatted, fromIso, toIso }) => {
        var inps = Array.from(document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="checkbox"]):not([type="radio"])'))
          .filter(function(el) {
            var r = el.getBoundingClientRect();
            return r.width > 0 && r.height > 0;
          });

        var dateInps = inps.filter(function(el) {
          var id = (el.id || '').toLowerCase();
          var name = (el.name || '').toLowerCase();
          var ph = (el.placeholder || '').toLowerCase();
          var cls = (el.className || '').toLowerCase();
          return el.type === 'date' || cls.includes('date') || ph.includes('date') || ph.includes('/') || ph.includes('from') || ph.includes('to') || ph.includes('start') || ph.includes('end') || id.includes('date') || id.includes('from') || id.includes('to') || id.includes('start') || id.includes('end') || name.includes('date') || name.includes('from') || name.includes('to');
        });

        if (dateInps.length < 2) dateInps = inps.slice(-2);

        function setDateVal(el, formattedVal, isoVal) {
          if (!el) return;
          el.removeAttribute('readonly');
          el.focus();
          el.value = (el.type === 'date') ? isoVal : formattedVal;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
          el.dispatchEvent(new Event('blur', { bubbles: true }));
        }

        if (dateInps.length >= 2) {
          setDateVal(dateInps[0], fromFormatted, fromIso);
          setDateVal(dateInps[1], toFormatted, toIso);
        }
      }, { fromFormatted, toFormatted, fromIso, toIso });

      await page.waitForTimeout(500);
    } else {
      console.log('[EposFilter] Step 3: Selected native "Yesterday" period; skipping date pickers.');
    }

    // Step 4: Click Apply button
    console.log('[EposFilter] Step 4: Clicking "Apply" button...');
    const applyBtn = page.locator('button:has-text("Apply"), input[value*="Apply" i], button[type="submit"]:has-text("Apply"), a:has-text("Apply"), button:has-text("Run Report")').first();
    if (await applyBtn.count() > 0) {
      await applyBtn.click();
      console.log('[EposFilter] Clicked Apply button via locator.');
    } else {
      await page.evaluate(() => {
        var btns = document.querySelectorAll('button, input[type="submit"], a');
        for (var i = 0; i < btns.length; i++) {
          var t = (btns[i].innerText || btns[i].value || '').trim().toLowerCase();
          if (t === 'apply' || t === 'run report' || t === 'filter') {
            btns[i].click();
            break;
          }
        }
      });
      console.log('[EposFilter] Evaluated Apply button click.');
    }

    // Step 5: Wait for table reload
    console.log('[EposFilter] Step 5: Waiting for filtered report table reload...');
    await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
    await page.waitForTimeout(3000);
    console.log('[EposFilter] Filter setup complete.');

  } catch (err) {
    console.warn(`[EposFilter] Warning applying date filter (${fromIso} to ${toIso}):`, err.message);
  }
}

// Scrapes currently displayed transactions from table (and up to 40 pages of pagination)
async function scrapeAndSaveCurrentPage(page, chunkLabel = '') {
  console.log(`Scraping transactions view (${chunkLabel})...`);
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

    // Expand page size to 50 or 100 if dropdown exists
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

          var isDisabled = el.disabled ||
            el.classList.contains('disabled') ||
            el.getAttribute('aria-disabled') === 'true' ||
            el.getAttribute('disabled') !== null;
          if (isDisabled) continue;

          var aria = (el.getAttribute('aria-label') || '').toLowerCase();
          var title = (el.getAttribute('title') || '').toLowerCase();
          var txt = (el.innerText || el.textContent || el.value || '').trim();
          var cls = (el.className || '').toString().toLowerCase();

          if (aria.includes('next') || title.includes('next') || aria.includes('forward') || title.includes('forward')) {
            return el;
          }
          if (cls.includes('paginate_button next') || cls.includes('page-next') || cls.includes('next-page') || cls.includes('pagination-next') || cls.includes('btn-next')) {
            return el;
          }
          if (txt === '>' || txt === '›' || txt === '»' || txt === 'Next' || txt === 'Next >' || txt === 'Next ›' || txt === 'Next Page') {
            return el;
          }
          var html = el.innerHTML || '';
          var hasRightIcon = (html.includes('chevron-right') || html.includes('arrow-right') || html.includes('angle-right') || html.includes('fa-chevron-right') || html.includes('bi-chevron-right')) &&
            !cls.includes('prev') && !aria.includes('prev') && !title.includes('prev');
          if (hasRightIcon) {
            return el;
          }
        }

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

    var collectedTxList = [];
    var maxPages = 40;
    var page = 0;
    var consecutiveMiss = 0;

    while (page < maxPages) {
      page++;
      scrollAllToBottom();
      await new Promise(function(r) { setTimeout(r, 600); });

      var docs = getAllDocs();
      var pageText = '';
      for (var di = 0; di < docs.length; di++) {
        if (docs[di].body) pageText += docs[di].body.innerText + '\n';
      }

      var pageDateMarkers = [];
      var dMatch;
      datePatternRegex.lastIndex = 0;
      while ((dMatch = datePatternRegex.exec(pageText)) !== null) {
        var iso = parseAnyDate(dMatch[0]);
        if (iso) pageDateMarkers.push({ index: dMatch.index, date: iso, raw: dMatch[0] });
      }

      var pageTxList = [];

      // Strategy 1: Direct Table Row (tr and role=row) inspection with cell-level payment method detection
      for (var di = 0; di < docs.length; di++) {
        var trRows = docs[di].querySelectorAll('tr, [role="row"], .dx-data-row, .k-master-row');
        for (var ri = 0; ri < trRows.length; ri++) {
          var rowEl = trRows[ri];
          var rText = (rowEl.innerText || '').replace(/\s+/g, ' ').trim();
          if (!rText) continue;
          // Skip header rows
          if (rText.toLowerCase().includes('transaction report') || (rText.toLowerCase().includes('payment method') && rText.toLowerCase().includes('amount'))) continue;

          // Check individual cells for Payment Method column
          var cells = rowEl.querySelectorAll('td, th, [role="gridcell"], [role="cell"], .cell');
          var rowHasCash = false;
          var rowHasCard = false;
          if (cells.length > 0) {
            for (var ci = 0; ci < cells.length; ci++) {
              var cText = (cells[ci].innerText || '').trim().toLowerCase();
              if (cText === 'cash' || cText.includes('cash')) rowHasCash = true;
              if (cText === 'card' || cText.includes('card') || cText.includes('eftpos') || cText.includes('visa') || cText.includes('mastercard')) rowHasCard = true;
            }
          }

          var dM = rText.match(/(\b\d{1,2}[\/\-\.]\d{1,2}(?:[\/\-\.]\d{2,4})?\b|\b\d{4}-\d{2}-\d{2}\b)/);
          var tM = rText.match(/(\d{1,2}:\d{2}(?::\d{2})?\s*[apAP][mM]?)/);
          var aM = rText.match(/(?:[\$£€]\s*)?([0-9]+\.[0-9]{2})/);
          if (dM && tM && aM) {
            var rDate = parseAnyDate(dM[1]);
            var rTime = tM[1];
            var rHour = parseTimeStr(rTime);
            var rAmt = parseFloat(aM[1]);
            var isCash = rowHasCash || (/\bcash\b/i.test(rText) && !rowHasCard);
            if (rDate && rHour !== null && !isNaN(rAmt)) {
              pageTxList.push({ date: rDate, time: rTime, hour: rHour, amount: rAmt, isCash: isCash, raw: rText });
            }
          }
        }
      }

      // Strategy 2: Line by line inspection of pageText
      var ptLines = pageText.split('\n');
      for (var li = 0; li < ptLines.length; li++) {
        var lText = ptLines[li].replace(/\s+/g, ' ').trim();
        if (!lText || lText.toLowerCase().includes('payment method')) continue;
        var dMl = lText.match(/(\b\d{1,2}[\/\-\.]\d{1,2}(?:[\/\-\.]\d{2,4})?\b|\b\d{4}-\d{2}-\d{2}\b)/);
        var tMl = lText.match(/(\d{1,2}:\d{2}(?::\d{2})?\s*[apAP][mM]?)/);
        var aMl = lText.match(/[\$£€]\s*([0-9]+\.[0-9]{2})/);
        if (dMl && tMl && aMl) {
          var rlDate = parseAnyDate(dMl[1]);
          var rlTime = tMl[1];
          var rlHour = parseTimeStr(rlTime);
          var rlAmt = parseFloat(aMl[1]);
          var islCash = /\bcash\b/i.test(lText);
          if (rlDate && rlHour !== null && !isNaN(rlAmt)) {
            pageTxList.push({ date: rlDate, time: rlTime, hour: rlHour, amount: rlAmt, isCash: islCash, raw: lText });
          }
        }
      }

      // Strategy 3: Global Regex pattern match
      var tMatch;
      eposRowRegex.lastIndex = 0;
      while ((tMatch = eposRowRegex.exec(pageText)) !== null) {
        var rowDate = parseAnyDate(tMatch[1]);
        var rowTime = tMatch[2];
        var rowHour = parseTimeStr(rowTime);
        var rowAmt = parseFloat(tMatch[3]);
        if (rowDate && rowHour !== null && !isNaN(rowAmt)) {
          var afterMatch = pageText.slice(tMatch.index, tMatch.index + 220);
          var isCash = /\bcash\b/i.test(afterMatch);
          pageTxList.push({ date: rowDate, time: rowTime, hour: rowHour, amount: rowAmt, isCash: isCash, raw: tMatch[0].replace(/\s+/g, ' ').trim() });
        }
      }

      var addedThisRound = 0;
      for (var ti = 0; ti < pageTxList.length; ti++) {
        var tx = pageTxList[ti];
        var key = tx.date + '|' + tx.time + '|' + tx.amount.toFixed(2);
        var exists = false;
        for (var cti = 0; cti < collectedTxList.length; cti++) {
          var ctx = collectedTxList[cti];
          if (ctx.date === tx.date && ctx.time === tx.time && Math.abs(ctx.amount - tx.amount) < 0.001) {
            exists = true;
            break;
          }
        }
        if (!exists) {
          collectedTxList.push(tx);
          addedThisRound++;
        }
      }

      if (addedThisRound === 0) {
        if (page === 1 && collectedTxList.length === 0) {
          console.log('No transactions found on page 1. Breaking pagination.');
          break;
        }
        consecutiveMiss++;
        if (consecutiveMiss >= 2) break;
      } else {
        consecutiveMiss = 0;
      }

      var nextBtn = findNextBtn();
      if (!nextBtn) break;

      var rowCountBefore = countCurrentTxRows();
      var firstRowBefore = (document.querySelector('tbody tr') || {}).innerText;
      clickBtn(nextBtn);

      for (var w = 0; w < 10; w++) {
        await new Promise(function(r) { setTimeout(r, 400); });
        var firstRowAfter = (document.querySelector('tbody tr') || {}).innerText;
        if (firstRowAfter && firstRowAfter !== firstRowBefore) break;
        if (countCurrentTxRows() > rowCountBefore) break;
      }
      await new Promise(function(r) { setTimeout(r, 500); });
    }

    var txList = collectedTxList;
    var daysGroup = {};
    for (var i = 0; i < txList.length; i++) {
      var tx = txList[i];
      var dKey = tx.date;
      if (!daysGroup[dKey]) {
        daysGroup[dKey] = { totalSales: 0, cardSales: 0, cashSales: 0, count: 0, hourly: {} };
      }
      daysGroup[dKey].count++;
      daysGroup[dKey].totalSales += tx.amount;
      if (tx.isCash) {
        daysGroup[dKey].cashSales += tx.amount;
      } else {
        daysGroup[dKey].cardSales += tx.amount;
      }
      daysGroup[dKey].hourly[tx.hour] = (daysGroup[dKey].hourly[tx.hour] || 0) + tx.amount;
    }

    var daysBatch = [];
    var sortedDays = Object.keys(daysGroup).sort().reverse();
    for (var d = 0; d < sortedDays.length; d++) {
      var dayDate = sortedDays[d];
      daysGroup[dayDate].totalSales = Math.round(daysGroup[dayDate].totalSales * 100) / 100;
      daysGroup[dayDate].cardSales = Math.round(daysGroup[dayDate].cardSales * 100) / 100;
      daysGroup[dayDate].cashSales = Math.round(daysGroup[dayDate].cashSales * 100) / 100;
      for (var hk in daysGroup[dayDate].hourly) {
        daysGroup[dayDate].hourly[hk] = Math.round(daysGroup[dayDate].hourly[hk] * 100) / 100;
      }
      daysGroup[dayDate].hourly._cardSales = daysGroup[dayDate].cardSales;
      daysGroup[dayDate].hourly._cashSales = daysGroup[dayDate].cashSales;
      daysBatch.push({
        date: dayDate,
        totalSales: daysGroup[dayDate].totalSales,
        cardSales: daysGroup[dayDate].cardSales,
        cashSales: daysGroup[dayDate].cashSales,
        count: daysGroup[dayDate].count,
        hourly: daysGroup[dayDate].hourly
      });
    }

    var txRows = txList.map(function(t, idx) {
      var rawC = (t.raw || '').replace(/\s+/g, ' ').trim();
      var uid = (t.date + '_' + (t.time || '').replace(/[^a-zA-Z0-9]/g, '') + '_' + t.amount.toFixed(2) + '_' + idx + '_' + rawC).slice(0, 120).toLowerCase().replace(/[^a-z0-9_]/g, '-');
      return { 
        id: uid, 
        date: t.date, 
        time: t.time || '', 
        amount: t.amount, 
        payment_method: t.isCash ? 'Cash' : 'Card',
        raw_line: rawC 
      };
    });

    return { daysBatch, txRows, totalTx: txList.length, pagesLoaded: page };
  });

  console.log(`Scraped ${scrapeResult.totalTx} transactions across ${scrapeResult.pagesLoaded} batches for ${scrapeResult.daysBatch.length} day(s) (${chunkLabel}).`);

  if (scrapeResult.totalTx === 0) {
    return scrapeResult;
  }

  // Upsert hourly_sales to Supabase (attempting dedicated card_sales & cash_sales columns with automatic fallback)
  const hsPayloadWithColumns = scrapeResult.daysBatch.map(d => ({
    date: d.date,
    total_sales: d.totalSales,
    card_sales: d.cardSales,
    cash_sales: d.cashSales,
    hourly: d.hourly,
    updated_at: new Date().toISOString()
  }));

  let hsRes = await fetch(`${SUPABASE_URL}/rest/v1/hourly_sales?on_conflict=date`, {
    method: 'POST',
    headers: {
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${SUPABASE_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'resolution=merge-duplicates'
    },
    body: JSON.stringify(hsPayloadWithColumns)
  });

  if (!hsRes.ok) {
    const txt = await hsRes.text();
    if (txt.includes('card_sales') || txt.includes('cash_sales')) {
      console.warn('Supabase hourly_sales table lacks card_sales/cash_sales columns; retrying with standard hourly JSON payload.');
      const fallbackPayload = scrapeResult.daysBatch.map(d => ({
        date: d.date,
        total_sales: d.totalSales,
        hourly: d.hourly,
        updated_at: new Date().toISOString()
      }));
      hsRes = await fetch(`${SUPABASE_URL}/rest/v1/hourly_sales?on_conflict=date`, {
        method: 'POST',
        headers: {
          'apikey': SUPABASE_KEY,
          'Authorization': `Bearer ${SUPABASE_KEY}`,
          'Content-Type': 'application/json',
          'Prefer': 'resolution=merge-duplicates'
        },
        body: JSON.stringify(fallbackPayload)
      });
    } else {
      console.error('Supabase hourly_sales upsert failed:', txt);
    }
  }
  if (hsRes.ok) {
    console.log(`Successfully upserted ${scrapeResult.daysBatch.length} day(s) to hourly_sales.`);
  }

  // Upsert raw_transactions in chunks of 100 (with automatic fallback if payment_method column does not exist)
  let insertedTx = 0;
  for (let i = 0; i < scrapeResult.txRows.length; i += 100) {
    const chunk = scrapeResult.txRows.slice(i, i + 100);
    let txRes = await fetch(`${SUPABASE_URL}/rest/v1/raw_transactions?on_conflict=id`, {
      method: 'POST',
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'resolution=merge-duplicates'
      },
      body: JSON.stringify(chunk)
    });
    if (!txRes.ok) {
      const errTxt = await txRes.text();
      if (errTxt.includes('payment_method')) {
        const strippedChunk = chunk.map(c => ({ id: c.id, date: c.date, time: c.time, amount: c.amount, raw_line: c.raw_line }));
        txRes = await fetch(`${SUPABASE_URL}/rest/v1/raw_transactions?on_conflict=id`, {
          method: 'POST',
          headers: {
            'apikey': SUPABASE_KEY,
            'Authorization': `Bearer ${SUPABASE_KEY}`,
            'Content-Type': 'application/json',
            'Prefer': 'resolution=merge-duplicates'
          },
          body: JSON.stringify(strippedChunk)
        });
      }
    }
    if (txRes.ok) insertedTx += chunk.length;
  }
  console.log(`Successfully upserted ${insertedTx} raw transactions (${chunkLabel}).`);

  return scrapeResult;
}

// Main Sync Engine: Supports both fast 'Today' sync and chunked multi-month date ranges
async function runSync(isManual = false, notifyTelegram = true, startDate = null, endDate = null) {
  if (appState.isSyncing) {
    console.log('Sync is already running. Skipping.');
    return;
  }
  appState.isSyncing = true;

  // Global safety watchdog (resets isSyncing if any operation hangs past 3.5 minutes)
  const syncWatchdog = setTimeout(() => {
    if (appState.isSyncing) {
      console.warn('Sync reached global watchdog timeout (210s). Resetting isSyncing.');
      appState.isSyncing = false;
    }
  }, 210000);

  try {
    console.log(`\n============================\nStarting sync run at ${new Date().toISOString()}...\nRange: ${startDate || 'Today'} to ${endDate || 'Today'}\n============================`);
    const page = await ensureLoggedIn(false, isManual && notifyTelegram);

    // If date range is specified (and not just today's live trade)
    if (startDate && endDate) {
      const chunks = splitDateRangeIntoChunks(startDate, endDate, 31);
      console.log(`Split date range ${startDate} -> ${endDate} into ${chunks.length} chunk(s) (max 31 days each).`);

      appState.activeSyncProgress = {
        isSyncing: true,
        currentChunk: 0,
        totalChunks: chunks.length,
        currentRange: `${startDate} to ${endDate}`,
        totalTx: 0,
        status: 'running'
      };

      if (isManual && notifyTelegram) {
        await sendTelegramMessage(`⚡ Starting sync for *${startDate}* to *${endDate}* (${chunks.length} batch(es) of ≤31 days)...\n\nEpos Now limits queries to 31 days maximum.`);
      }

      let totalTxCount = 0;
      let totalDaysCount = 0;
      let lastDaysBatch = [];

      for (let i = 0; i < chunks.length; i++) {
        const chunk = chunks[i];
        appState.activeSyncProgress.currentChunk = i + 1;
        appState.activeSyncProgress.currentRange = `${chunk.from} to ${chunk.to}`;

        console.log(`\n--- Processing Chunk ${i + 1}/${chunks.length} (${chunk.from} to ${chunk.to}) ---`);
        if (isManual && notifyTelegram) {
          await sendTelegramMessage(`🔄 *Chunk ${i + 1}/${chunks.length}*: Scraping ${chunk.from} to ${chunk.to}...`);
        }

        await page.goto(TARGET_URL, { waitUntil: 'load', timeout: 45000 });
        await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
        await page.waitForTimeout(2000);

        // Apply Epos Now filter for this chunk
        await applyEposDateFilter(page, chunk.from, chunk.to);

        // Scrape and save transactions for this chunk
        const chunkResult = await scrapeAndSaveCurrentPage(page, `${chunk.from} to ${chunk.to}`);
        if (chunkResult) {
          totalTxCount += chunkResult.totalTx;
          totalDaysCount += chunkResult.daysBatch.length;
          lastDaysBatch = chunkResult.daysBatch;
          appState.activeSyncProgress.totalTx = totalTxCount;
        }

        if (i < chunks.length - 1) {
          await page.waitForTimeout(1500);
        }
      }

      appState.activeSyncProgress.status = 'completed';
      appState.lastSyncTime = new Date().toISOString();
      appState.lastSyncResult = {
        days: totalDaysCount,
        txCount: totalTxCount,
        batches: chunks.length,
        topDay: `${startDate} to ${endDate}`
      };
      appState.consecutiveFailures = 0;

      if (isManual && notifyTelegram) {
        await sendTelegramMessage(
          `✅ *Multi-Month Sync Complete!*\n\n` +
          `Date Range: *${startDate}* to *${endDate}*\n` +
          `Processed *${chunks.length}* chunks (≤31 days each).\n` +
          `Synced *${totalTxCount}* transactions across *${totalDaysCount}* day(s) to Supabase.`
        );
      }

      return appState.lastSyncResult;
    }

    // Default: Single Fast Scrape (Today's live transactions)
    console.log('Loading fresh transactions report page for Today...');
    if (isManual && notifyTelegram) await sendTelegramMessage('⚡ Auto-loading all transactions from Epos Now...');
    await page.goto(TARGET_URL, { waitUntil: 'load', timeout: 45000 });
    await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
    await page.waitForTimeout(2500);

    const scrapeResult = await scrapeAndSaveCurrentPage(page, 'Today');
    if (!scrapeResult || scrapeResult.totalTx === 0) {
      console.warn('No transactions parsed on page.');
      if (isManual && notifyTelegram) {
        await sendTelegramMessage('⚠️ Scrape completed, but 0 transactions were found on the current Epos Now report page.');
      }
      return;
    }

    appState.lastSyncTime = new Date().toISOString();
    appState.lastSyncResult = {
      days: scrapeResult.daysBatch.length,
      txCount: scrapeResult.totalTx,
      batches: scrapeResult.pagesLoaded,
      topDay: scrapeResult.daysBatch[0] ? `${scrapeResult.daysBatch[0].date}: $${scrapeResult.daysBatch[0].totalSales}` : 'N/A'
    };
    appState.consecutiveFailures = 0;

    if (isManual && notifyTelegram) {
      const summaryLines = scrapeResult.daysBatch.map(d => `• *${d.date}*: $${d.totalSales.toFixed(2)} (${d.count} txs)`);
      await sendTelegramMessage(
        `✅ *Sync Complete!*\n\n` +
        `Auto-loaded *${scrapeResult.pagesLoaded}* batches.\n` +
        `Synced *${scrapeResult.totalTx}* transactions across *${scrapeResult.daysBatch.length}* day(s) to Supabase:\n\n` +
        summaryLines.join('\n')
      );
    }
    return appState.lastSyncResult;
  } catch (err) {
    appState.consecutiveFailures++;
    console.error('Sync failed:', err);
    if ((isManual && notifyTelegram) || appState.consecutiveFailures === 3) {
      await sendTelegramMessage(`⚠️ *Epos Sync Error*: ${err.message}`);
    }
    throw err;
  } finally {
    clearTimeout(syncWatchdog);
    appState.isSyncing = false;
    if (appState.activeSyncProgress) {
      appState.activeSyncProgress.isSyncing = false;
      appState.activeSyncProgress.status = 'idle';
    }
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
