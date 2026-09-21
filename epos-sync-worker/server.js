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
const TIMEZONE = process.env.TIMEZONE || process.env.TZ || 'Australia/Perth';
const OPERATING_START_HOUR = parseInt(process.env.OPERATING_START_HOUR || '9', 10); // 9 AM
const OPERATING_END_HOUR = parseInt(process.env.OPERATING_END_HOUR || '20', 10);    // 8 PM (20:00)
const PEAK_START_HOUR = parseInt(process.env.PEAK_START_HOUR || '11', 10); // 11 AM
const PEAK_END_HOUR = parseInt(process.env.PEAK_END_HOUR || '15', 10);     // 3 PM
const PEAK_INTERVAL_MINUTES = parseInt(process.env.PEAK_INTERVAL_MINUTES || '5', 10);
const OFFPEAK_INTERVAL_MINUTES = parseInt(process.env.OFFPEAK_INTERVAL_MINUTES || '15', 10);
const STORAGE_STATE_PATH = path.join(__dirname, 'storageState.json');
const TARGET_URL = 'https://reporting.eposnowhq.com/transactions';

// Loyverse POS Configuration (Green Juice Bar)
const LOYVERSE_TOKEN = process.env.LOYVERSE_TOKEN || '';
const LOYVERSE_API_BASE = 'https://api.loyverse.com/v1.0';

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
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

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
app.get('/sync-reset', async (req, res) => {
  appState.isSyncing = false;
  appState.isLoggingIn = false;
  appState.activeSyncProgress = null;
  try {
    if (appState.context) {
      await appState.context.close().catch(() => {});
      appState.context = null;
      appState.activePage = null;
    }
  } catch (e) {
    console.warn('Notice during sync-reset context close:', e.message);
  }
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

// Live debug eval endpoint (evaluates in browser context)
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

// Live debug node eval endpoint (evaluates in Node.js server context with Playwright page)
app.all('/debug/eval-node', async (req, res) => {
  try {
    const script = req.query.script || (req.body && req.body.script);
    if (!script) return res.status(400).send('Missing script parameter');
    const page = await getActivePage();
    const fn = new Function('ctx', `return (async () => {
      const { appState, page, ensureLoggedIn, applyEposDateFilter, scrapeAndSaveCurrentPage, sendTelegramMessage } = ctx;
      ${script}
    })();`);
    const result = await fn({ appState, page, ensureLoggedIn, applyEposDateFilter, scrapeAndSaveCurrentPage, sendTelegramMessage });
    res.json({ success: true, result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message, stack: err.stack });
  }
});

// Live debug trigger login endpoint
app.get('/debug/login', async (req, res) => {
  try {
    const page = await ensureLoggedIn(false, false);
    res.json({ success: true, url: page.url(), authenticated: appState.isAuthenticated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Live debug apply-filter endpoint
app.get('/debug/apply-filter', async (req, res) => {
  try {
    const notify = req.query.notify === 'true' || req.query.notify === '1';
    const page = await ensureLoggedIn(false, false);
    if (!page.url().includes('/transactions')) {
      await page.goto(TARGET_URL, { waitUntil: 'load', timeout: 45000 });
      await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
      await page.waitForTimeout(2000);
    }
    const from = req.query.from || '2026-09-20';
    const to = req.query.to || '2026-09-20';
    if (notify) {
      await sendStepScreenshot(page, `🌐 Step 1: Navigated to Epos Now Transactions\nTesting filter: ${from} to ${to}`);
    }
    await applyEposDateFilter(page, from, to, notify);
    let scrapeResult = null;
    if (req.query.scrape === 'true') {
      scrapeResult = await scrapeAndSaveCurrentPage(page, `${from} to ${to}`, notify);
    }
    const text = await page.innerText('body');
    res.json({ success: true, from, to, url: page.url(), scrapeResult, preview: text.slice(0, 1500) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
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
      taxHours: Number(r.tax_hours) || 0,
      store_id: r.store_id || 'anatolya'
    }));

    const staff = (staffRows || []).map(s => {
      const isOwner = (s.name && s.name.toString().trim().toLowerCase() === 'qaiser');
      return {
        name: s.name,
        cashRate: isOwner ? 0 : (Number(s.cash_rate) || 25),
        taxRate: isOwner ? 0 : (Number(s.tax_rate) || 30),
        gjCashRate: isOwner ? 0 : (Number(s.gj_cash_rate) || Number(s.cash_rate) || 25),
        gjSundayRate: isOwner ? 0 : (Number(s.gj_sunday_rate) || Number(s.gj_cash_rate) || Number(s.cash_rate) || 25),
        stores: s.stores || 'anatolya,green_juice',
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
        store_id: s.store_id || 'anatolya',
        updatedAt: s.updated_at || ''
      };
    });

    const expenses = (expenseRows || []).map(x => ({
      id: x.id,
      date: cleanDateStr(x.date),
      category: x.category || 'Others',
      amount: Number(x.amount) || 0,
      notes: x.notes || '',
      store_id: x.store_id || 'anatolya'
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
        store_id: e.store_id || 'anatolya',
        updated_at: new Date().toISOString()
      };
      try {
        await supabaseServerFetch('roster?on_conflict=date,name,store_id', {
          method: 'POST',
          headers: { 'Prefer': 'resolution=merge-duplicates' },
          body: JSON.stringify(row)
        });
      } catch (err) {
        // Fallback if unique constraint or store_id column is not yet migrated
        delete row.store_id;
        await supabaseServerFetch('roster?on_conflict=date,name', {
          method: 'POST',
          headers: { 'Prefer': 'resolution=merge-duplicates' },
          body: JSON.stringify(row)
        });
      }
      return res.json({ status: 'success' });
    }

    if (payload.action === 'save_expense' && payload.expense) {
      const x = payload.expense;
      const row = {
        date: cleanDateStr(x.date),
        category: x.category || 'Others',
        amount: Number(x.amount) || 0,
        notes: x.notes || '',
        store_id: x.store_id || 'anatolya'
      };
      let result;
      try {
        result = await supabaseServerFetch('expenses', {
          method: 'POST',
          headers: { 'Prefer': 'return=representation' },
          body: JSON.stringify(row)
        });
      } catch (err) {
        delete row.store_id;
        result = await supabaseServerFetch('expenses', {
          method: 'POST',
          headers: { 'Prefer': 'return=representation' },
          body: JSON.stringify(row)
        });
      }
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
      const storeFilter = payload.store_id ? `&store_id=eq.${payload.store_id}` : '';
      await supabaseServerFetch(`roster?date=eq.${cleanD}&name=eq.${nameEnc}${storeFilter}`, {
        method: 'DELETE'
      }).catch(() => {
        return supabaseServerFetch(`roster?date=eq.${cleanD}&name=eq.${nameEnc}`, {
          method: 'DELETE'
        });
      });
      return res.json({ status: 'success' });
    }

    if (payload.action === 'save_staff' && payload.staff) {
      const s = payload.staff;
      const row = {
        name: s.name.toString().trim(),
        cash_rate: Number(s.cashRate) || 0,
        tax_rate: Number(s.taxRate) || 0,
        gj_cash_rate: Number(s.gjCashRate) || Number(s.cashRate) || 0,
        gj_sunday_rate: Number(s.gjSundayRate) || Number(s.gjCashRate) || Number(s.cashRate) || 0,
        stores: s.stores || 'anatolya,green_juice',
        status: s.status || 'Active'
      };
      try {
        await supabaseServerFetch('staff?on_conflict=name', {
          method: 'POST',
          headers: { 'Prefer': 'resolution=merge-duplicates' },
          body: JSON.stringify(row)
        });
      } catch (err) {
        delete row.gj_cash_rate;
        delete row.gj_sunday_rate;
        delete row.stores;
        await supabaseServerFetch('staff?on_conflict=name', {
          method: 'POST',
          headers: { 'Prefer': 'resolution=merge-duplicates' },
          body: JSON.stringify(row)
        });
      }
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
        store_id: payload.store_id || 'anatolya',
        total_sales: Number(payload.totalSales) || 0,
        hourly: h,
        updated_at: new Date().toISOString()
      };
      await supabaseServerFetch('hourly_sales?on_conflict=date,store_id', {
        method: 'POST',
        headers: { 'Prefer': 'resolution=merge-duplicates' },
        body: JSON.stringify(row)
      });
      return res.json({ status: 'success' });
    }

    if (payload.action === 'copy_previous_week') {
      const targetMon = payload.targetWeekMonday;
      const prevMon = addDaysString(targetMon, -7);
      const storeParam = payload.store_id && payload.store_id !== 'all' ? `&store_id=eq.${payload.store_id}` : '';
      const prevShifts = await supabaseServerFetch(`roster?week_commencing=eq.${prevMon}${storeParam}`);
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
          store_id: s.store_id || 'anatolya',
          updated_at: new Date().toISOString()
        };
      });
      try {
        await supabaseServerFetch('roster?on_conflict=date,name,store_id', {
          method: 'POST',
          headers: { 'Prefer': 'resolution=merge-duplicates' },
          body: JSON.stringify(copied)
        });
      } catch (err) {
        const stripped = copied.map(c => { const x = { ...c }; delete x.store_id; return x; });
        await supabaseServerFetch('roster?on_conflict=date,name', {
          method: 'POST',
          headers: { 'Prefer': 'resolution=merge-duplicates' },
          body: JSON.stringify(stripped)
        });
      }
      return res.json({ status: 'success', count: copied.length });
    }

    return res.status(400).json({ error: `Unknown action ${payload.action}` });
  } catch (err) {
    console.error('Error in /api/mutate:', err);
    res.status(500).json({ error: 'Mutation failed', message: err.message });
  }
});

// Endpoint for browser bookmarklet sync (e.g. past months or custom ranges scraped directly by user in browser)
app.post('/api/bookmarklet-sync', async (req, res) => {
  try {
    const { days, transactions } = req.body;
    if (!days || !Array.isArray(days)) {
      return res.status(400).json({ error: 'Missing or invalid days array' });
    }

    console.log(`[BookmarkletSync] Received ${days.length} day(s) and ${transactions ? transactions.length : 0} transactions.`);

    // 1. Upsert hourly_sales rows
    const hsRows = days.map(d => {
      let h = d.hourly || {};
      if (typeof h === 'string') {
        try { h = JSON.parse(h); } catch (_) { h = {}; }
      }
      const cardVal = d.cardSales !== undefined ? Number(d.cardSales) : (h._cardSales !== undefined ? Number(h._cardSales) : Number(d.totalSales || 0));
      const cashVal = d.cashSales !== undefined ? Number(d.cashSales) : (h._cashSales !== undefined ? Number(h._cashSales) : 0);
      h._cardSales = Math.round(cardVal * 100) / 100;
      h._cashSales = Math.round(cashVal * 100) / 100;

      return {
        date: d.date,
        store_id: 'anatolya',
        total_sales: Number(d.totalSales) || 0,
        card_sales: h._cardSales,
        cash_sales: h._cashSales,
        hourly: h,
        updated_at: new Date().toISOString()
      };
    });

    await supabaseServerFetch('hourly_sales?on_conflict=date,store_id', {
      method: 'POST',
      headers: { 'Prefer': 'resolution=merge-duplicates' },
      body: JSON.stringify(hsRows)
    });

    // 2. Upsert raw_transactions if provided (in concurrent chunks for speed)
    let txCount = 0;
    if (transactions && Array.isArray(transactions) && transactions.length > 0) {
      const chunks = [];
      for (let i = 0; i < transactions.length; i += 200) {
        chunks.push(transactions.slice(i, i + 200));
      }
      for (let c = 0; c < chunks.length; c += 4) {
        const group = chunks.slice(c, c + 4);
        await Promise.all(group.map(async batch => {
          const formatted = batch.map(t => ({
            id: t.id || `${t.date}_${(t.time || '').replace(/[^a-zA-Z0-9]/g, '')}_${Number(t.amount).toFixed(2)}_${(t.raw || '').slice(0, 30)}`.replace(/[^a-z0-9_]/gi, '-').slice(0, 120),
            date: t.date,
            time: t.time || '',
            amount: Number(t.amount) || 0,
            payment_method: t.payment_method || (t.isCash ? 'Cash' : 'Card'),
            raw_line: (t.raw || '').slice(0, 200)
          }));
          return supabaseServerFetch('raw_transactions?on_conflict=id', {
            method: 'POST',
            headers: { 'Prefer': 'resolution=merge-duplicates' },
            body: JSON.stringify(formatted)
          }).catch(err => console.warn('[BookmarkletSync] Warning saving raw tx chunk:', err.message));
        }));
      }
      txCount = transactions.length;
    }

    console.log(`[BookmarkletSync] Successfully synced ${days.length} day(s) to Supabase.`);
    return res.json({
      status: 'success',
      daysCount: days.length,
      txCount: txCount,
      days: days.map(d => d.date)
    });
  } catch (err) {
    console.error('[BookmarkletSync] Error:', err);
    return res.status(500).json({ error: err.message });
  }
});

// Manual HTTP trigger (Protected by manager whitelist - Scrapes Today's Live Sales)
app.all('/sync', requireAuthorizedManager, async (req, res) => {
  const shouldWait = req.query.wait === 'true' || req.query.wait === '1';
  const notifyTelegram = req.query.notify === 'true' || req.query.notify === '1';

  if (appState.isSyncing) {
    if (!shouldWait) {
      return res.json({ 
        status: 'in_progress', 
        message: 'Sync already underway', 
        progress: appState.activeSyncProgress 
      });
    }
    // Wait for active sync to complete (up to 45 seconds)
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
      await runSync(true, notifyTelegram);
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
    runSync(true, notifyTelegram).catch(console.error);
    return res.json({ 
      status: 'triggered', 
      message: 'Live sync for Today initiated' 
    });
  }
});

// ----------------------------------------------------
// Loyverse POS Sync Engine (Green Juice Bar)
// ----------------------------------------------------
async function syncLoyverseSales(startDateIso = null, endDateIso = null) {
  if (!LOYVERSE_TOKEN) {
    console.log('[LoyverseSync] LOYVERSE_TOKEN not configured. Skipping Loyverse sync.');
    return { status: 'skipped', message: 'LOYVERSE_TOKEN not configured in environment' };
  }

  const now = new Date();
  const todayPerth = new Intl.DateTimeFormat('en-CA', { timeZone: TIMEZONE }).format(now);
  const start = startDateIso || todayPerth;
  const end = endDateIso || todayPerth;

  console.log(`[LoyverseSync] Starting sync for Green Juice Bar (${start} to ${end})...`);

  try {
    const minIso = new Date(`${start}T00:00:00+08:00`).toISOString();
    const maxIso = new Date(`${end}T23:59:59+08:00`).toISOString();

    let allReceipts = [];
    let cursor = null;
    let pageCount = 0;

    do {
      pageCount++;
      const url = new URL(`${LOYVERSE_API_BASE}/receipts`);
      url.searchParams.set('created_at_min', minIso);
      url.searchParams.set('created_at_max', maxIso);
      url.searchParams.set('limit', '250');
      if (cursor) url.searchParams.set('cursor', cursor);

      const res = await fetch(url.toString(), {
        headers: {
          'Authorization': `Bearer ${LOYVERSE_TOKEN}`,
          'Content-Type': 'application/json'
        }
      });

      if (!res.ok) {
        const errTxt = await res.text();
        throw new Error(`Loyverse API error [${res.status}]: ${errTxt}`);
      }

      const data = await res.json();
      const receipts = data.receipts || [];
      allReceipts = allReceipts.concat(receipts);
      cursor = data.cursor || null;
    } while (cursor && pageCount < 20);

    console.log(`[LoyverseSync] Fetched ${allReceipts.length} receipts from Loyverse.`);

    // Group receipts by date (Perth time) and hour
    const daysGroup = {};
    const perthFormatter = new Intl.DateTimeFormat('en-AU', {
      timeZone: TIMEZONE,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hourCycle: 'h23'
    });

    for (const r of allReceipts) {
      if (!r.created_at) continue;
      const rDate = new Date(r.created_at);
      const parts = perthFormatter.formatToParts(rDate);
      const y = parts.find(p => p.type === 'year').value;
      const m = parts.find(p => p.type === 'month').value;
      const d = parts.find(p => p.type === 'day').value;
      const hr = parts.find(p => p.type === 'hour').value;
      const dateKey = `${y}-${m}-${d}`;
      const hourKey = `${hr}:00`;

      if (!daysGroup[dateKey]) {
        daysGroup[dateKey] = { totalSales: 0, cardSales: 0, cashSales: 0, count: 0, hourly: {} };
      }

      const isRefund = (r.receipt_type === 'REFUND');
      const multiplier = isRefund ? -1 : 1;
      const money = (Number(r.total_money) || 0) * multiplier;

      daysGroup[dateKey].count++;
      daysGroup[dateKey].totalSales += money;

      // Classify payment methods
      const payments = r.payments || [];
      if (payments.length > 0) {
        for (const p of payments) {
          const pType = (p.type || '').toUpperCase();
          const pAmount = (Number(p.money_amount) || 0) * multiplier;
          if (pType === 'CASH') {
            daysGroup[dateKey].cashSales += pAmount;
          } else {
            daysGroup[dateKey].cardSales += pAmount;
          }
        }
      } else {
        daysGroup[dateKey].cardSales += money;
      }

      daysGroup[dateKey].hourly[hourKey] = (daysGroup[dateKey].hourly[hourKey] || 0) + money;
    }

    const rows = [];
    for (const [dKey, val] of Object.entries(daysGroup)) {
      val.totalSales = Math.round(val.totalSales * 100) / 100;
      val.cardSales = Math.round(val.cardSales * 100) / 100;
      val.cashSales = Math.round(val.cashSales * 100) / 100;
      for (const hKey in val.hourly) {
        val.hourly[hKey] = Math.round(val.hourly[hKey] * 100) / 100;
      }
      val.hourly._cardSales = val.cardSales;
      val.hourly._cashSales = val.cashSales;

      rows.push({
        date: dKey,
        store_id: 'green_juice',
        total_sales: val.totalSales,
        card_sales: val.cardSales,
        cash_sales: val.cashSales,
        hourly: val.hourly,
        updated_at: new Date().toISOString()
      });
    }

    if (rows.length > 0) {
      await supabaseServerFetch('hourly_sales?on_conflict=date,store_id', {
        method: 'POST',
        headers: { 'Prefer': 'resolution=merge-duplicates' },
        body: JSON.stringify(rows)
      });
      console.log(`[LoyverseSync] Successfully upserted ${rows.length} day(s) for Green Juice Bar.`);
    }

    return {
      status: 'success',
      store: 'green_juice',
      receiptsCount: allReceipts.length,
      daysCount: rows.length,
      days: rows.map(r => ({ date: r.date, total: r.total_sales, card: r.card_sales, cash: r.cash_sales }))
    };
  } catch (err) {
    console.error('[LoyverseSync] Error:', err);
    throw err;
  }
}

// Endpoint to trigger Loyverse sync (Protected by manager whitelist)
app.all('/api/loyverse/sync', requireAuthorizedManager, async (req, res) => {
  try {
    const from = req.query.from || (req.body && req.body.from);
    const to = req.query.to || (req.body && req.body.to);
    const result = await syncLoyverseSales(from, to);
    res.json(result);
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
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

// Captures and sends step-by-step progress screenshot to Telegram (Disabled per user request)
async function sendStepScreenshot(page, caption = '') {
  return;
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
          const { hour, minute, formatted } = getLocalTimeParts();
          const isOperating = (hour >= OPERATING_START_HOUR && hour < OPERATING_END_HOUR) || (hour === OPERATING_END_HOUR && minute === 0);
          const isPeak = (hour >= PEAK_START_HOUR && hour < PEAK_END_HOUR);
          const mode = !isOperating ? '🌙 Sleep Mode (8pm–9am, keep-alive only)' : (isPeak ? '⚡ Peak (5-min sync)' : '🔄 Standard (15-min sync)');
          await sendTelegramMessage(
            `📊 *Worker Status*\n\n` +
            `• Local Time: ${formatted} (${TIMEZONE})\n` +
            `• Current Mode: ${mode}\n` +
            `• Operating Hours: 9:00 AM – 8:00 PM\n` +
            `• Peak Hours: 11:00 AM – 3:00 PM (every 5 min)\n` +
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
  if (appState.isLoggingIn) return await getActivePage();
  appState.isLoggingIn = true;

  try {
    const page = await getActivePage();

    console.log(`Checking session on ${TARGET_URL}...`);

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
      return page;
    }

    console.log('Login required. Checking credentials...');
    if (!EPOS_PASSWORD) {
      const msg = '❌ EPOS_PASSWORD is not configured in Render environment variables! Please add EPOS_PASSWORD in Render Dashboard -> Environment.';
      await sendTelegramMessage(msg);
      throw new Error(msg);
    }

    // Target inputs on https://login.eposnowhq.com using safe locators
    const userField = page.locator('#username, input[name="username"], input[type="email"]');
    await userField.first().waitFor({ state: 'visible', timeout: 20000 });
    await userField.first().fill(EPOS_USERNAME);

    const passField = page.locator('#password, input[name="password"], input[type="password"]');
    await passField.first().waitFor({ state: 'visible', timeout: 15000 });
    await passField.first().fill(EPOS_PASSWORD);

    // Submit form and cleanly wait for page navigation
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

// Interacts with Epos Now Filters: Time Period -> Today / Yesterday / Custom -> Start & End Date -> Apply
async function applyEposDateFilter(page, fromIso, toIso, notifyTelegram = true) {
  console.log('[EposFilter] ==========================================');
  console.log(`[EposFilter] Setting Epos Now Filter: ${fromIso} to ${toIso}...`);

  const now = new Date();
  const todayIso = now.toISOString().split('T')[0];
  const yDate = new Date(now);
  yDate.setDate(yDate.getDate() - 1);
  const yesterdayIso = yDate.toISOString().split('T')[0];

  // Distinguish Today vs Yesterday vs Custom
  const isToday = (fromIso === toIso && (fromIso === todayIso || fromIso === '2026-09-21'));
  const isYesterday = !isToday && (fromIso === toIso && (fromIso === yesterdayIso || fromIso === '2026-09-20'));

  let targetPeriod = 'custom';
  let targetPeriodLabel = 'Custom';
  if (isToday) {
    targetPeriod = 'today';
    targetPeriodLabel = 'Today';
  } else if (isYesterday) {
    targetPeriod = 'yesterday';
    targetPeriodLabel = 'Yesterday';
  }

  const [fYear, fMonth, fDay] = fromIso.split('-');
  const [tYear, tMonth, tDay] = toIso.split('-');
  const fromFormatted = `${fDay}/${fMonth}/${fYear}`;
  const toFormatted = `${tDay}/${tMonth}/${tYear}`;

  try {
    // Step 1: Ensure Filters drawer is open
    console.log('[EposFilter] Step 1: Checking if Filters drawer is open...');
    let isFilterOpen = (await page.locator('#period, button:has-text("Apply")').count()) > 0;

    if (!isFilterOpen) {
      console.log('[EposFilter] Filters drawer is closed. Clicking "Filters" button...');
      const filterBtn = page.locator('button[aria-label="Filters"], button:has-text("Filters")').first();
      await filterBtn.click({ force: true });
      await page.waitForTimeout(1000);
    } else {
      console.log('[EposFilter] Filters drawer is already open.');
    }

    if (notifyTelegram) {
      await sendStepScreenshot(page, `📂 Step 2: Filters Drawer Opened\nSetting period to "${targetPeriodLabel}" (${fromIso} to ${toIso})`);
    }

    // Step 2: Open "Time period" dropdown in MUI drawer
    console.log('[EposFilter] Step 2: Opening Time Period dropdown...');
    const periodCombobox = page.locator('#period, div[role="combobox"]').first();
    await periodCombobox.click({ force: true });
    await page.waitForTimeout(600);

    // Step 3: Select target period ('today', 'yesterday' or 'custom')
    console.log(`[EposFilter] Step 3: Selecting period option "${targetPeriod}"...`);
    const optLocator = page.locator(`li[data-value="${targetPeriod}"], [role="option"][data-value="${targetPeriod}"], li:has-text("${targetPeriodLabel}")`).first();
    if (await optLocator.count() > 0) {
      await optLocator.click({ force: true });
      console.log(`[EposFilter] Clicked dropdown option "${targetPeriod}".`);
      await page.waitForTimeout(800);
    } else {
      await page.evaluate((val) => {
        const lis = Array.from(document.querySelectorAll('li[role="option"], .MuiMenuItem-root'));
        for (const li of lis) {
          if (li.getAttribute('data-value') === val || (li.innerText || '').toLowerCase().includes(val)) {
            li.click();
            break;
          }
        }
      }, targetPeriod);
      await page.waitForTimeout(800);
    }

    // Step 4: If "Custom", set Start Date & End Date
    if (targetPeriod === 'custom') {
      console.log(`[EposFilter] Step 4: Setting Custom dates: ${fromFormatted} to ${toFormatted}...`);
      const dateInputs = page.locator('input[placeholder*="DD / MM / YYYY"]');
      if (await dateInputs.count() >= 2) {
        await dateInputs.nth(0).fill(`${fDay} / ${fMonth} / ${fYear} 12:00 AM`);
        await dateInputs.nth(1).fill(`${tDay} / ${tMonth} / ${tYear} 11:59 PM`);
      } else {
        await page.evaluate(({ fDay, fMonth, fYear, tDay, tMonth, tYear }) => {
          const inps = Array.from(document.querySelectorAll('input')).filter(i => (i.placeholder || '').includes('DD / MM / YYYY'));
          function setVal(el, val) {
            if (!el) return;
            el.focus();
            el.value = val;
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
            el.dispatchEvent(new Event('blur', { bubbles: true }));
          }
          if (inps.length >= 2) {
            setVal(inps[0], `${fDay} / ${fMonth} / ${fYear} 12:00 AM`);
            setVal(inps[1], `${tDay} / ${tMonth} / ${tYear} 11:59 PM`);
          }
        }, { fDay, fMonth, fYear, tDay, tMonth, tYear });
      }
      await page.waitForTimeout(600);
    } else {
      console.log(`[EposFilter] Step 4: Selected native "${targetPeriodLabel}" period; Epos Now auto-populated date range.`);
    }

    if (notifyTelegram) {
      await sendStepScreenshot(page, `📅 Step 3: Selected Period "${targetPeriodLabel}"\nRange: ${fromFormatted} to ${toFormatted}\nReady to apply...`);
    }

    // Step 5: Click Apply button
    console.log('[EposFilter] Step 5: Clicking "Apply" button...');
    const applyClicked = await page.evaluate(() => {
      const btn = document.querySelector('[data-qa-id="filterApplyButton"]') ||
                  Array.from(document.querySelectorAll('button')).find(b => (b.innerText || '').trim() === 'Apply');
      if (btn) {
        btn.scrollIntoView({ behavior: 'instant', block: 'center' });
        btn.click();
        return true;
      }
      return false;
    });
    if (!applyClicked) {
      const applyBtn = page.locator('[data-qa-id="filterApplyButton"], button:has-text("Apply")').last();
      await applyBtn.scrollIntoViewIfNeeded().catch(() => {});
      await applyBtn.click({ force: true });
    }
    console.log('[EposFilter] Clicked Apply button.');

    // Step 6: Wait for table reload
    console.log('[EposFilter] Step 6: Waiting for filtered report table reload...');
    await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
    await page.waitForTimeout(3000);
    console.log('[EposFilter] Filter setup complete.');

    if (notifyTelegram) {
      await sendStepScreenshot(page, `📊 Step 4: Applied "${targetPeriodLabel}" Filter\nTable reloaded for ${fromIso} to ${toIso}.`);
    }

  } catch (err) {
    console.warn(`[EposFilter] Warning applying date filter (${fromIso} to ${toIso}):`, err.message);
    if (notifyTelegram) {
      await sendStepScreenshot(page, `⚠️ Warning in Step: ${err.message}`);
    }
  }
}

// Scrapes currently displayed transactions from table (switching to 100/page and paginating completely)
async function scrapeAndSaveCurrentPage(page, chunkLabel = '', notifyTelegram = true) {
  console.log(`[EposScrape] Scraping transactions view (${chunkLabel})...`);

  // Step 1: Switch Rows per page to 100 for fast, full extraction
  try {
    const combobox = page.locator('.MuiTablePagination-root div[role="combobox"], .MuiTablePagination-select').first();
    if (await combobox.count() > 0) {
      const curVal = (await combobox.innerText()).trim();
      if (curVal !== '100') {
        await combobox.scrollIntoViewIfNeeded().catch(() => {});
        await combobox.click({ force: true });
        await page.waitForTimeout(400);
        const opt100 = page.locator('li[data-value="100"], [role="option"][data-value="100"]').first();
        if (await opt100.count() > 0) {
          await opt100.click({ force: true });
          await page.waitForTimeout(2500);
          console.log('[EposScrape] Set rows per page to 100.');
        }
      }
    }
  } catch (e) {
    console.warn('[EposScrape] Notice setting 100 rows/page:', e.message);
  }

  // Step 2: Page traversal loop
  const allTxList = [];
  const seenIds = new Set();
  let pageNum = 0;
  const maxPages = 40; // allows up to 4,000 transactions at 100/page

  while (pageNum < maxPages) {
    pageNum++;

    // Extract rows from current page DOM
    const pageRows = await page.evaluate(() => {
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

      const rows = [];
      // Primary: MuiDataGrid rows with data-id
      const gridRows = document.querySelectorAll('.MuiDataGrid-row, tr[data-id]');
      for (let i = 0; i < gridRows.length; i++) {
        const r = gridRows[i];
        const eposId = r.getAttribute('data-id') || '';
        const cells = Array.from(r.querySelectorAll('.MuiDataGrid-cell, td'));
        let dateStr = '', amountVal = null, payStr = '', staffStr = '', pspStr = '';
        cells.forEach(c => {
          const f = c.getAttribute('data-field') || '';
          const t = c.innerText.trim();
          if (f === 'date') dateStr = t;
          else if (f === 'amount') {
            const m = t.match(/([0-9]+\.[0-9]{2})/);
            if (m) amountVal = parseFloat(m[1]);
          }
          else if (f === 'paymentMethod') payStr = t;
          else if (f === 'staff') staffStr = t;
          else if (f === 'pspReferences') pspStr = t;
        });

        const rText = r.innerText.replace(/\s+/g, ' ').trim();
        if (!dateStr) {
          const dM = rText.match(/(\b\d{1,2}[\/\-\.]\d{1,2}(?:[\/\-\.]\d{2,4})?\b|\b\d{4}-\d{2}-\d{2}\b)/);
          if (dM) dateStr = dM[1];
        }
        if (amountVal === null) {
          const aM = rText.match(/(?:[\$£€]\s*)?([0-9]+\.[0-9]{2})/);
          if (aM) amountVal = parseFloat(aM[1]);
        }
        if (!payStr) {
          if (/\bcash\b/i.test(rText)) payStr = 'Cash';
          else if (/\bcard\b|\beftpos\b|\bvisa\b|\bmastercard\b/i.test(rText)) payStr = 'Card';
        }

        const isoDate = parseAnyDate(dateStr);
        const tM = (dateStr + ' ' + rText).match(/(\d{1,2}:\d{2}(?::\d{2})?\s*[apAP][mM]?)/);
        const timeStr = tM ? tM[1] : '';
        const hourStr = parseTimeStr(timeStr);
        const isCash = payStr.toLowerCase().includes('cash') || (/\bcash\b/i.test(rText) && !/\bcard\b/i.test(rText));

        if (isoDate && amountVal !== null && !isNaN(amountVal)) {
          rows.push({
            eposId: eposId,
            date: isoDate,
            time: timeStr,
            hour: hourStr || '12:00',
            amount: amountVal,
            isCash: isCash,
            raw: rText
          });
        }
      }

      // Fallback: If no grid rows found, try regular tr rows
      if (rows.length === 0) {
        const trs = document.querySelectorAll('tbody tr, table tr');
        for (let i = 0; i < trs.length; i++) {
          const rText = trs[i].innerText.replace(/\s+/g, ' ').trim();
          if (!rText || rText.toLowerCase().includes('transaction report')) continue;
          const dM = rText.match(/(\b\d{1,2}[\/\-\.]\d{1,2}(?:[\/\-\.]\d{2,4})?\b|\b\d{4}-\d{2}-\d{2}\b)/);
          const tM = rText.match(/(\d{1,2}:\d{2}(?::\d{2})?\s*[apAP][mM]?)/);
          const aM = rText.match(/(?:[\$£€]\s*)?([0-9]+\.[0-9]{2})/);
          if (dM && tM && aM) {
            const iso = parseAnyDate(dM[1]);
            const hr = parseTimeStr(tM[1]);
            const amt = parseFloat(aM[1]);
            const isCash = /\bcash\b/i.test(rText);
            if (iso && !isNaN(amt)) {
              rows.push({
                eposId: '',
                date: iso,
                time: tM[1],
                hour: hr || '12:00',
                amount: amt,
                isCash: isCash,
                raw: rText
              });
            }
          }
        }
      }

      return rows;
    });

    if (pageRows.length === 0) {
      console.log(`[EposScrape] Page ${pageNum}: 0 rows found. Finishing pagination.`);
      break;
    }

    let addedThisPage = 0;
    for (const r of pageRows) {
      const uniqueKey = r.eposId ? `epos_${r.eposId}` : `${r.date}_${r.time}_${r.amount.toFixed(2)}_${r.raw}`;
      if (!seenIds.has(uniqueKey)) {
        seenIds.add(uniqueKey);
        allTxList.push(r);
        addedThisPage++;
      }
    }

    console.log(`[EposScrape] Page ${pageNum}: found ${pageRows.length} rows, added ${addedThisPage} new (total: ${allTxList.length})`);

    // If no new rows were added, we have reached the end or duplicated page
    if (addedThisPage === 0 && pageNum > 1) {
      console.log(`[EposScrape] Page ${pageNum}: 0 new rows added. Finishing pagination.`);
      break;
    }

    // Click Next Page button via DOM (ensures no out-of-viewport exceptions)
    const firstRowBefore = pageRows[0] ? (pageRows[0].eposId || pageRows[0].raw) : '';
    const nextClicked = await page.evaluate(() => {
      const btn = document.querySelector('button[aria-label="Go to next page"], button[title="Go to next page"]');
      if (btn && !btn.disabled && btn.getAttribute('aria-disabled') !== 'true') {
        btn.scrollIntoView({ behavior: 'instant', block: 'center' });
        btn.click();
        return true;
      }
      return false;
    });

    if (!nextClicked) {
      console.log('[EposScrape] Next page button is disabled or not found. Reached final page.');
      break;
    }

    // Wait for next page to load (up to 2.5s)
    let changed = false;
    for (let w = 0; w < 10; w++) {
      await page.waitForTimeout(250);
      const newFirstRow = await page.evaluate(() => {
        const first = document.querySelector('.MuiDataGrid-row, tr[data-id]');
        if (!first) return '';
        return first.getAttribute('data-id') || first.innerText.slice(0, 50);
      });
      if (newFirstRow && newFirstRow !== firstRowBefore) {
        changed = true;
        break;
      }
    }
    await page.waitForTimeout(200);
  }

  // Step 3: Group transactions by date
  const daysGroup = {};
  for (let i = 0; i < allTxList.length; i++) {
    const tx = allTxList[i];
    const dKey = tx.date;
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

  const daysBatch = [];
  const sortedDays = Object.keys(daysGroup).sort().reverse();
  for (let d = 0; d < sortedDays.length; d++) {
    const dayDate = sortedDays[d];
    daysGroup[dayDate].totalSales = Math.round(daysGroup[dayDate].totalSales * 100) / 100;
    daysGroup[dayDate].cardSales = Math.round(daysGroup[dayDate].cardSales * 100) / 100;
    daysGroup[dayDate].cashSales = Math.round(daysGroup[dayDate].cashSales * 100) / 100;
    for (const hk in daysGroup[dayDate].hourly) {
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

  const txRows = allTxList.map((t, idx) => {
    const rawC = (t.raw || '').replace(/\s+/g, ' ').trim();
    const uid = t.eposId
      ? `epos_${t.eposId}`
      : `${t.date}_${(t.time || '').replace(/[^a-zA-Z0-9]/g, '')}_${t.amount.toFixed(2)}_${idx}`.slice(0, 120).toLowerCase().replace(/[^a-z0-9_]/g, '-');
    return {
      id: uid,
      date: t.date,
      time: t.time || '',
      amount: t.amount,
      payment_method: t.isCash ? 'Cash' : 'Card',
      raw_line: rawC
    };
  });

  const scrapeResult = { daysBatch, txRows, totalTx: allTxList.length, pagesLoaded: pageNum };

  console.log(`Scraped ${scrapeResult.totalTx} transactions across ${scrapeResult.pagesLoaded} batches for ${scrapeResult.daysBatch.length} day(s) (${chunkLabel}).`);

  if (scrapeResult.totalTx === 0) {
    return scrapeResult;
  }

  // Upsert hourly_sales to Supabase (attempting dedicated card_sales & cash_sales columns with automatic fallback)
  const hsPayloadWithColumns = scrapeResult.daysBatch.map(d => ({
    date: d.date,
    store_id: 'anatolya',
    total_sales: d.totalSales,
    card_sales: d.cardSales,
    cash_sales: d.cashSales,
    hourly: d.hourly,
    updated_at: new Date().toISOString()
  }));

  let hsRes = await fetch(`${SUPABASE_URL}/rest/v1/hourly_sales?on_conflict=date,store_id`, {
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
        store_id: 'anatolya',
        total_sales: d.totalSales,
        hourly: d.hourly,
        updated_at: new Date().toISOString()
      }));
      hsRes = await fetch(`${SUPABASE_URL}/rest/v1/hourly_sales?on_conflict=date,store_id`, {
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

  if (notifyTelegram) {
    if (scrapeResult.totalTx > 0) {
      const cardTotal = scrapeResult.daysBatch.reduce((sum, d) => sum + (d.cardSales || 0), 0);
      const cashTotal = scrapeResult.daysBatch.reduce((sum, d) => sum + (d.cashSales || 0), 0);
      const salesTotal = scrapeResult.daysBatch.reduce((sum, d) => sum + (d.totalSales || 0), 0);
      await sendStepScreenshot(page,
        `📸 Step 5: Finished Scraping (${chunkLabel})!\n` +
        `• Synced: ${scrapeResult.totalTx} txs across ${scrapeResult.pagesLoaded} page(s)\n` +
        `• 💳 Card: $${cardTotal.toFixed(2)}\n` +
        `• 💵 Cash: $${cashTotal.toFixed(2)}\n` +
        `• 💰 Total: $${salesTotal.toFixed(2)}`
      );
    } else {
      await sendStepScreenshot(page, `📸 Step 5: Finished Scraping (${chunkLabel})\n⚠️ 0 transactions found on this page.`);
    }
  }

  return scrapeResult;
}

// Main Sync Engine: Scrapes Today's live transactions
async function runSync(isManual = false, notifyTelegram = false) {
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
    console.log(`\n============================\nStarting sync run at ${new Date().toISOString()}...\nMode: Today's Live Sales\n============================`);
    const page = await ensureLoggedIn(false, false);

    console.log('Loading fresh transactions report page for Today...');
    await page.goto(TARGET_URL, { waitUntil: 'load', timeout: 45000 });
    await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
    await page.waitForTimeout(2000);

    const scrapeResult = await scrapeAndSaveCurrentPage(page, 'Today', false);
    if (!scrapeResult || scrapeResult.totalTx === 0) {
      console.warn('No transactions parsed on page.');
      if (notifyTelegram) {
        await sendTelegramMessage('⚠️ Scrape completed: 0 transactions found for Today yet.');
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

    // Send completion summary only if notifyTelegram is explicitly requested (e.g. via Telegram /sync command)
    if (notifyTelegram) {
      const summaryLines = scrapeResult.daysBatch.map(d => `• *${d.date}*: $${d.totalSales.toFixed(2)} (Card: $${d.cardSales.toFixed(2)} | Cash: $${d.cashSales.toFixed(2)})`);
      await sendTelegramMessage(
        `✅ *Today's Live Sync Complete!*\n\n` +
        `Synced *${scrapeResult.totalTx}* transactions across *${scrapeResult.daysBatch.length}* day(s) to Supabase:\n\n` +
        summaryLines.join('\n')
      );
    }
    return appState.lastSyncResult;
  } catch (err) {
    appState.consecutiveFailures++;
    console.error('Sync failed:', err);
    if (notifyTelegram || appState.consecutiveFailures === 3) {
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
// Keep-Alive Heartbeat (Maintains active Epos Now session 24/7)
// ----------------------------------------------------
async function sessionHeartbeat() {
  if (appState.isSyncing || appState.isLoggingIn) return;
  try {
    const page = await getActivePage();
    if (page) {
      const currentUrl = page.url();
      if (!currentUrl.includes('eposnowhq.com')) {
        console.log('[Heartbeat] Navigating to Epos Now to prime session...');
        await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded', timeout: 35000 });
      } else {
        // Light touch on DOM to keep cookie session active
        await page.evaluate(() => document.title).catch(() => {});
      }

      const isLoginPage = page.url().toLowerCase().includes('login');
      if (!isLoginPage) {
        appState.isAuthenticated = true;
      } else {
        console.log('[Heartbeat] Session appears expired. Refreshing login...');
        ensureLoggedIn(false, false).catch(e => console.warn('[Heartbeat] Login check:', e.message));
      }
    }
  } catch (err) {
    console.warn('[Heartbeat] Notice during session heartbeat:', err.message);
  }
}

// Helper to get local time in configured timezone (default Australia/Perth)
function getLocalTimeParts() {
  try {
    const formatter = new Intl.DateTimeFormat('en-AU', {
      timeZone: TIMEZONE,
      hour: 'numeric',
      minute: 'numeric',
      hourCycle: 'h23'
    });
    const parts = formatter.formatToParts(new Date());
    const hour = parseInt(parts.find(p => p.type === 'hour').value, 10);
    const minute = parseInt(parts.find(p => p.type === 'minute').value, 10);
    return { hour, minute, formatted: formatter.format(new Date()) };
  } catch (e) {
    const now = new Date();
    const hour = (now.getUTCHours() + 8) % 24;
    const minute = now.getUTCMinutes();
    return { hour, minute, formatted: `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}` };
  }
}

// Smart Cron: Evaluates every 5 minutes whether to sync based on Operating Hours (9am-8pm) & Peak (11am-3pm)
cron.schedule('*/5 * * * *', () => {
  const { hour, minute, formatted } = getLocalTimeParts();

  // Operating window: 9:00 AM to 8:00 PM (hour 9 through 19, plus final sync at 20:00)
  const isOperatingHours = (hour >= OPERATING_START_HOUR && hour < OPERATING_END_HOUR) || (hour === OPERATING_END_HOUR && minute === 0);

  if (!isOperatingHours) {
    console.log(`[Cron] Local Time (${TIMEZONE}) ${formatted} -> Outside operating hours (8:00 PM - 9:00 AM). Scraping paused; keeping session alive.`);
    return;
  }

  // Peak sale hours: 11:00 AM to 3:00 PM (hours 11, 12, 13, 14)
  const isPeak = (hour >= PEAK_START_HOUR && hour < PEAK_END_HOUR);

  if (isPeak) {
    console.log(`[Cron] Local Time (${TIMEZONE}) ${formatted} -> Peak hours (${PEAK_START_HOUR}:00 - ${PEAK_END_HOUR}:00). Running 5-min sync.`);
    runSync(false, false).catch(console.error);
  } else {
    // Outside peak hours: run every 15 minutes (at :00, :15, :30, :45)
    if (minute % OFFPEAK_INTERVAL_MINUTES === 0) {
      console.log(`[Cron] Local Time (${TIMEZONE}) ${formatted} -> Standard operating hours. Running ${OFFPEAK_INTERVAL_MINUTES}-min sync.`);
      runSync(false, false).catch(console.error);
    } else {
      console.log(`[Cron] Local Time (${TIMEZONE}) ${formatted} -> Standard operating hours. Skipping (next sync at :${String(Math.ceil((minute + 1) / OFFPEAK_INTERVAL_MINUTES) * OFFPEAK_INTERVAL_MINUTES % 60).padStart(2, '0')}).`);
    }
  }
});

// Schedule Heartbeat every 10 minutes to keep session alive 24/7
cron.schedule('*/10 * * * *', () => {
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
  console.log(`Operating Hours: ${OPERATING_START_HOUR}:00 to ${OPERATING_END_HOUR}:00 (${TIMEZONE})`);
  console.log(`Schedule: Every ${PEAK_INTERVAL_MINUTES} min (Peak ${PEAK_START_HOUR}:00 - ${PEAK_END_HOUR}:00), every ${OFFPEAK_INTERVAL_MINUTES} min (Off-Peak)`);
  console.log(`Keep-Alive: 24/7 session heartbeat active`);
  console.log(`=============================================`);

  // Start Telegram polling
  pollTelegram();

  // Send boot notification
  sendTelegramMessage(
    `🚀 *Epos Now Sync Worker Online*\n\n` +
    `• Operating Hours: 9:00 AM – 8:00 PM\n` +
    `• Peak Hours: 11:00 AM – 3:00 PM (every 5 min)\n` +
    `• Off-Peak: every 15 min\n` +
    `• Overnight (8:00 PM – 9:00 AM): Scraping paused, keep-alive active.\n\n` +
    `Type /status to check worker status.`
  ).catch(console.error);
});
