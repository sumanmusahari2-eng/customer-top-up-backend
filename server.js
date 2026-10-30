// TopUp Hub — auth service (email + password + Google login for the store).
// Serves the static storefront's sign-up / sign-in: register, login, me,
// plus Google sign-in (redirect to Google, callback finds-or-creates the
// account and returns the store to its origin with #token=<jwt>).
// Stateless JWT auth: the store keeps the token and sends it as a Bearer token.
// Env: DATABASE_URL (Neon Postgres), JWT_SECRET (long random string),
//      CORS_ORIGIN (comma-separated allowed origins; defaults to the Render store),
//      GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET (for Google sign-in),
//      GOOGLE_REDIRECT_URI (optional; defaults to this service's callback URL).
const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const busan = require('./busan');

const app = express();
app.use(express.json({ limit: '10mb' })); // store snapshots carry inlined game/banner artwork (several MB) — 512kb rejected every admin save with 413

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '';
const CORS_ORIGINS = (process.env.CORS_ORIGIN || 'https://customer-top-up-store.vercel.app')
  .split(',').map((s) => s.trim()).filter(Boolean);

if (!process.env.DATABASE_URL) console.warn('WARNING: DATABASE_URL is not set — auth routes will fail until it is.');
if (!JWT_SECRET) console.warn('WARNING: JWT_SECRET is not set — set a long random value before real use.');

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && CORS_ORIGINS.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    return res.status(204).end();
  }
  next();
});

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : null;

async function ensureSchema() {
  if (!pool) return;
  await pool.query(
    `CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );`
  );
  await pool.query(
    `CREATE TABLE IF NOT EXISTS store_data (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );`
  );
  await pool.query(
    `CREATE TABLE IF NOT EXISTS wallets (
      user_id INTEGER PRIMARY KEY REFERENCES users(id),
      balance INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );`
  );
  await pool.query(
    `CREATE TABLE IF NOT EXISTS wallet_ledger (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      delta INTEGER NOT NULL,
      kind TEXT NOT NULL,
      ref TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );`
  );
  await pool.query(
    `CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      game TEXT NOT NULL,
      pack TEXT NOT NULL,
      price INTEGER NOT NULL CHECK (price >= 0),
      player_id TEXT NOT NULL DEFAULT '',
      zone_id TEXT NOT NULL DEFAULT '',
      payment_method TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );`
  );
  await pool.query(
    `CREATE TABLE IF NOT EXISTS topup_requests (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      amount INTEGER NOT NULL CHECK (amount > 0),
      note TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );`
  );
  await pool.query('CREATE INDEX IF NOT EXISTS orders_user_idx ON orders (user_id, id DESC);');
  await pool.query('CREATE INDEX IF NOT EXISTS wallet_ledger_user_idx ON wallet_ledger (user_id, id DESC);');
  await pool.query('CREATE INDEX IF NOT EXISTS topup_requests_status_idx ON topup_requests (status, id DESC);');
  // Phase 4: coupons + order coupon fields (idempotent; existing DBs gain them on boot).
  await pool.query(
    `CREATE TABLE IF NOT EXISTS coupons (
      id SERIAL PRIMARY KEY,
      code TEXT NOT NULL UNIQUE,
      kind TEXT NOT NULL CHECK (kind IN ('percent', 'flat')),
      value INTEGER NOT NULL CHECK (value > 0),
      max_uses INTEGER,
      used_count INTEGER NOT NULL DEFAULT 0,
      expires_at TIMESTAMPTZ,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );`
  );
  await pool.query('ALTER TABLE orders ADD COLUMN IF NOT EXISTS coupon_code TEXT NOT NULL DEFAULT \'\';');
  await pool.query('ALTER TABLE orders ADD COLUMN IF NOT EXISTS discount INTEGER NOT NULL DEFAULT 0;');
  // Phase 3: Busan fulfilment outcome per order (idempotent; existing DBs gain them on boot).
  await pool.query('ALTER TABLE orders ADD COLUMN IF NOT EXISTS busan_status TEXT NOT NULL DEFAULT \'\';');
  await pool.query('ALTER TABLE orders ADD COLUMN IF NOT EXISTS busan_order_id TEXT NOT NULL DEFAULT \'\';');
  await pool.query('ALTER TABLE orders ADD COLUMN IF NOT EXISTS busan_error TEXT NOT NULL DEFAULT \'\';');
  // PaySafe UPI (XtraGateway) fields on orders (idempotent; existing DBs gain them on boot).
  await pool.query('ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_mobile TEXT NOT NULL DEFAULT \'\';');
  await pool.query('ALTER TABLE orders ADD COLUMN IF NOT EXISTS xtra_order_id TEXT NOT NULL DEFAULT \'\';');
  await pool.query('ALTER TABLE orders ADD COLUMN IF NOT EXISTS xtra_payment_url TEXT NOT NULL DEFAULT \'\';');
  await pool.query('ALTER TABLE orders ADD COLUMN IF NOT EXISTS xtra_status TEXT NOT NULL DEFAULT \'\';');
  await pool.query('ALTER TABLE orders ADD COLUMN IF NOT EXISTS xtra_utr TEXT NOT NULL DEFAULT \'\';');
  // Reseller flag (idempotent; existing DBs gain it on boot).
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS is_reseller BOOLEAN NOT NULL DEFAULT FALSE;');
}

// Tiny in-memory rate limiter for the auth routes (per IP, rolling window).
const hits = new Map();
function rateLimit(req, res, next) {
  const now = Date.now();
  const key = req.ip || 'unknown';
  const list = (hits.get(key) || []).filter((t) => now - t < 15 * 60 * 1000);
  list.push(now);
  hits.set(key, list);
  if (list.length > 30) return res.status(429).json({ error: 'Too many attempts, try again later.' });
  next();
}

function validEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function publicUser(row) {
  return { id: row.id, email: row.email, name: row.name, created_at: row.created_at, is_reseller: !!row.is_reseller, is_admin: ADMIN_EMAILS.includes((row.email || '').toLowerCase()) };
}

function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

function requirePool(res) {
  if (!pool) {
    res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
    return false;
  }
  if (!JWT_SECRET) {
    res.status(503).json({ error: 'Auth service is not configured yet.' });
    return false;
  }
  return true;
}

app.get('/', (req, res) => res.json({ service: 'customer-top-up-backend', ok: true }));
app.get('/api/health', (req, res) => res.json({ ok: true, db: !!pool }));

app.post('/api/auth/register', rateLimit, async (req, res) => {
  if (!requirePool(res)) return;
  const name = typeof req.body.name === 'string' ? req.body.name.trim().slice(0, 100) : '';
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = req.body.password;
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id, email, name, created_at',
      [email, hash, name]
    );
    const user = publicUser(rows[0]);
    res.status(201).json({ user, token: signToken(user) });
  } catch (err) {
    if (err && err.code === '23505') {
      return res.status(409).json({ error: 'That email is already registered. Try signing in.' });
    }
    console.error('register failed:', err);
    res.status(500).json({ error: 'Could not create the account. Try again.' });
  }
});

app.post('/api/auth/login', rateLimit, async (req, res) => {
  if (!requirePool(res)) return;
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = req.body.password;
  if (!validEmail(email) || typeof password !== 'string') {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid email or password.' });
    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password.' });
    const user = publicUser(rows[0]);
    res.json({ user, token: signToken(user) });
  } catch (err) {
    console.error('login failed:', err);
    res.status(500).json({ error: 'Could not sign in. Try again.' });
  }
});

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token || !JWT_SECRET) return res.status(401).json({ error: 'Not signed in.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired. Sign in again.' });
  }
}

app.get('/api/auth/me', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  try {
    const { rows } = await pool.query('SELECT id, email, name, created_at, is_reseller FROM users WHERE id = $1', [req.user.id]);
    if (rows.length === 0) return res.status(401).json({ error: 'Account not found.' });
    res.json({ user: publicUser(rows[0]) });
  } catch (err) {
    console.error('me failed:', err);
    res.status(500).json({ error: 'Could not load the account.' });
  }
});

// ---- Store data (admin together with the store login) ----
// The storefront loads its live catalogue/settings from here when present
// and falls back to its built-in data otherwise. Only the store admin
// (an admin email, signed in) may save.
const ADMIN_EMAILS = ['kwsalmusahari@gmail.com'];

app.get('/api/store', async (req, res) => {
  if (!pool) return res.json({ configured: false });
  try {
    const { rows } = await pool.query('SELECT data FROM store_data WHERE id = 1');
    if (rows.length === 0) return res.json({ configured: false });
    const data = rows[0].data;
    // Reseller prices are privileged: only a signed-in reseller or the admin
    // receives them. Everyone else gets the same data with resellerPrice
    // stripped, so regular visitors can never read reseller rates.
    let privileged = false;
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (token && JWT_SECRET) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (ADMIN_EMAILS.includes(decoded.email)) {
          privileged = true;
        } else {
          const u = await pool.query('SELECT is_reseller FROM users WHERE id = $1', [decoded.id]);
          if (u.rows.length && u.rows[0].is_reseller) privileged = true;
        }
      } catch {
        // Bad/expired token: fall through as an anonymous visitor.
      }
    }
    if (privileged) return res.json({ configured: true, ...data });
    const stripped = JSON.parse(JSON.stringify(data));
    if (Array.isArray(stripped.games)) {
      for (const g of stripped.games) {
        if (g && Array.isArray(g.packs)) {
          for (const p of g.packs) delete p.resellerPrice;
        }
      }
    }
    res.json({ configured: true, ...stripped });
  } catch (err) {
    console.error('store read failed:', err);
    res.status(500).json({ error: 'Could not load store data.' });
  }
});

app.put('/api/admin/store', requireAuth, async (req, res) => { // no shared rate limiter here: admin saves are large, legitimate, and repeated Apply taps were hitting the shared 30/15min cap with a 429
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!req.user || !ADMIN_EMAILS.includes(req.user.email)) {
    return res.status(403).json({ error: 'Admin access only.' });
  }
  const data = req.body;
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return res.status(400).json({ error: 'Invalid store data.' });
  }
  try {
    await pool.query(
      `INSERT INTO store_data (id, data, updated_at) VALUES (1, $1::jsonb, NOW())
       ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
      [JSON.stringify(data)]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('store save failed:', err);
    res.status(500).json({ error: 'Could not save store data.' });
  }
});
// Banner-only save: the banner Apply sends just the banner fields instead
// of the whole multi-MB store snapshot, so a banner save lands fast even
// though the full-store save stays as the flow for every other admin tab.
app.put('/api/admin/banner', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!req.user || !ADMIN_EMAILS.includes(req.user.email)) {
    return res.status(403).json({ error: 'Admin access only.' });
  }
  const b = req.body || {};
  try {
    const { rows } = await pool.query('SELECT data FROM store_data WHERE id = 1');
    const data = rows.length ? (rows[0].data || {}) : {};
    const prevSecs = (data.banner && typeof data.banner.slideSecs === 'number') ? data.banner.slideSecs : 4;
    const banner = {
      img: typeof b.img === 'string' ? b.img.slice(0, 2000000) : '',
      title: typeof b.title === 'string' ? b.title.slice(0, 100) : '',
      hl: typeof b.hl === 'string' ? b.hl.slice(0, 100) : '',
      sub: typeof b.sub === 'string' ? b.sub.slice(0, 500) : '',
      cta: typeof b.cta === 'string' ? b.cta.slice(0, 100) : '',
      slideSecs: (typeof b.slideSecs === 'number' && isFinite(b.slideSecs)) ? Math.min(60, Math.max(2, b.slideSecs)) : prevSecs,
    };
    data.banner = banner;
    await pool.query(
      `INSERT INTO store_data (id, data, updated_at) VALUES (1, $1::jsonb, NOW())
       ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
      [JSON.stringify(data)]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('banner save failed:', err);
    res.status(500).json({ error: 'Could not save the banner.' });
  }
});


// ---- Phase 1: orders, wallet, top-up requests ----
// Coins: 1 coin = ₹1. Wallet payments deduct immediately and the order
// becomes paid (awaiting delivery); WhatsApp orders stay pending until the
// admin confirms payment. Only an admin may change order
// status or approve top-ups; cancelling a paid wallet order refunds it.
function isAdmin(req) {
  return !!(req.user && ADMIN_EMAILS.includes(req.user.email));
}

function cleanStr(v, max) {
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}

function orderOut(row) {
  return {
    id: row.id,
    code: `TP-${row.id}`,
    game: row.game,
    pack: row.pack,
    price: row.price,
    player_id: row.player_id,
    zone_id: row.zone_id,
    payment_method: row.payment_method,
    coupon_code: row.coupon_code || '',
    discount: row.discount || 0,
    busan_status: row.busan_status || '',
    busan_order_id: row.busan_order_id || '',
    busan_error: row.busan_error || '',
    customer_mobile: row.customer_mobile || '',
    xtra_order_id: row.xtra_order_id || '',
    xtra_payment_url: row.xtra_payment_url || '',
    xtra_status: row.xtra_status || '',
    xtra_utr: row.xtra_utr || '',
    status: row.status,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

app.get('/api/wallet/me', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  try {
    await pool.query('INSERT INTO wallets (user_id, balance) VALUES ($1, 0) ON CONFLICT (user_id) DO NOTHING', [req.user.id]);
    const bal = await pool.query('SELECT balance FROM wallets WHERE user_id = $1', [req.user.id]);
    const led = await pool.query('SELECT id, delta, kind, ref, created_at FROM wallet_ledger WHERE user_id = $1 ORDER BY id DESC LIMIT 50', [req.user.id]);
    res.json({ balance: bal.rows[0] ? bal.rows[0].balance : 0, ledger: led.rows });
  } catch (err) {
    console.error('wallet read failed:', err);
    res.status(500).json({ error: 'Could not load the wallet.' });
  }
});

app.post('/api/wallet/topup-request', requireAuth, rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  const amount = Number(req.body.amount);
  const note = cleanStr(req.body.note, 200);
  if (!Number.isInteger(amount) || amount <= 0 || amount > 100000) {
    return res.status(400).json({ error: 'Enter a top-up amount between 1 and 100000 coins.' });
  }
  try {
    const { rows } = await pool.query(
      'INSERT INTO topup_requests (user_id, amount, note) VALUES ($1, $2, $3) RETURNING id, amount, note, status, created_at',
      [req.user.id, amount, note]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('topup request failed:', err);
    res.status(500).json({ error: 'Could not create the top-up request.' });
  }
});

app.post('/api/orders', requireAuth, rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  const game = cleanStr(req.body.game, 200);
  const pack = cleanStr(req.body.pack, 200);
  const playerId = cleanStr(req.body.player_id, 100);
  const zoneId = cleanStr(req.body.zone_id, 100);
  let price = Number(req.body.price);
  const method = req.body.payment_method;
  let mobile = cleanStr(req.body.customer_mobile, 20).replace(/\D/g, '');
  if (mobile.length === 12 && mobile.startsWith('91')) mobile = mobile.slice(2);
  if (mobile && !/^\d{10}$/.test(mobile)) mobile = '';
  const couponCode = cleanStr(req.body.coupon_code, 50).toUpperCase();
  if (!game || !pack || !playerId || !Number.isInteger(price) || price < 0 || (method !== 'wallet' && method !== 'whatsapp' && method !== 'upi')) {
    return res.status(400).json({ error: 'Invalid order details.' });
  }
  // Reseller pricing: the charged price is resolved server-side from the
  // saved store data, never taken from the client. A reseller pays the
  // pack's reseller price when one is set, otherwise the regular price;
  // everyone else always pays the regular price.
  try {
    const me = await pool.query('SELECT is_reseller FROM users WHERE id = $1', [req.user.id]);
    const buyerIsReseller = !!(me.rows.length && me.rows[0].is_reseller);
    const sd = await pool.query('SELECT data FROM store_data WHERE id = 1');
    if (sd.rows.length) {
      const games = sd.rows[0].data && sd.rows[0].data.games;
      let resolved = null;
      if (Array.isArray(games)) {
        const g = games.find((x) => x && x.name === game);
        const p = g && Array.isArray(g.packs)
          ? g.packs.find((x) => x && (x.amt === pack || x.name === pack || x.label === pack || x.title === pack))
          : null;
        if (p && Number.isFinite(Number(p.price))) {
          const regular = Number(p.price);
          const rp = p.resellerPrice !== undefined && p.resellerPrice !== '' && p.resellerPrice !== null ? Number(p.resellerPrice) : null;
          resolved = (buyerIsReseller && rp !== null && Number.isFinite(rp) && rp >= 0) ? rp : regular;
        }
      }
      if (resolved === null) {
        return res.status(400).json({ error: 'Price could not be verified for this pack. Refresh the store and try again.' });
      }
      price = Math.trunc(resolved);
    }
  } catch (err) {
    console.error('order price resolve failed:', err);
    return res.status(500).json({ error: 'Could not verify the price.' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Phase 4: optional coupon — validated and consumed inside the same
    // transaction as the order, so a code can never be double-spent.
    let finalPrice = price;
    let discountAmt = 0;
    let couponRow = null;
    if (couponCode) {
      const c = await client.query('SELECT * FROM coupons WHERE code = $1 FOR UPDATE', [couponCode]);
      if (c.rows.length === 0 || !c.rows[0].active ||
          (c.rows[0].expires_at && new Date(c.rows[0].expires_at) <= new Date()) ||
          (c.rows[0].max_uses !== null && c.rows[0].used_count >= c.rows[0].max_uses)) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Invalid or expired coupon.' });
      }
      couponRow = c.rows[0];
      discountAmt = couponRow.kind === 'percent'
        ? Math.floor(price * couponRow.value / 100)
        : Math.min(couponRow.value, price);
      finalPrice = price - discountAmt;
    }
    if (method === 'upi' && finalPrice <= 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'UPI payment needs an amount above \u20B90.' });
    }
    if (method === 'upi' && !mobile) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Enter a valid 10-digit mobile number for UPI payment.' });
    }
    const ins = await client.query(
      `INSERT INTO orders (user_id, game, pack, price, player_id, zone_id, payment_method, status, coupon_code, discount, customer_mobile)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [req.user.id, game, pack, finalPrice, playerId, zoneId, method, method === 'wallet' ? 'paid' : 'pending', couponCode, discountAmt, mobile]
    );
    const order = ins.rows[0];
    if (couponRow) {
      await client.query('UPDATE coupons SET used_count = used_count + 1 WHERE id = $1', [couponRow.id]);
    }
    if (method === 'wallet') {
      await client.query('INSERT INTO wallets (user_id, balance) VALUES ($1, 0) ON CONFLICT (user_id) DO NOTHING', [req.user.id]);
      const w = await client.query('SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE', [req.user.id]);
      if (w.rows[0].balance < finalPrice) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Not enough coins in the wallet.' });
      }
      await client.query('UPDATE wallets SET balance = balance - $1, updated_at = NOW() WHERE user_id = $2', [finalPrice, req.user.id]);
      await client.query('INSERT INTO wallet_ledger (user_id, delta, kind, ref) VALUES ($1, $2, $3, $4)', [req.user.id, -finalPrice, 'order_payment', `TP-${order.id}`]);
    }
    await client.query('COMMIT');
    if (method === 'wallet') fulfilBusanOrder(order.id).catch((e) => console.error('busan fulfil failed:', e.message));
    res.status(201).json(orderOut(order));
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('order create failed:', err);
    res.status(500).json({ error: 'Could not place the order.' });
  } finally {
    client.release();
  }
});

// ---- PaySafe UPI (XtraGateway) ----
// Flow: customer places a 'upi' order (pending) -> POST /api/payments/upi/create
// returns the gateway payment_url -> customer pays -> gateway redirects back to
// https://customer-top-up-store.vercel.app/?payment_return=<orderId> -> storefront polls
// GET /api/payments/upi/status, which asks the gateway and flips the order to
// paid on COMPLETED, firing the same Busan fulfil hook as other paid orders.
// Env: XTRA_USER_TOKEN (gateway merchant token, required), XTRA_BASE_URL
// (default https://paysafe.mlbbstore.in).
const XTRA_BASE = (process.env.XTRA_BASE_URL || 'https://paysafe.mlbbstore.in').replace(/\/+$/, '');
function xtraEnabled() { return !!((process.env.XTRA_USER_TOKEN || '').trim()); }
async function xtraPost(path, params) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 25000);
  try {
    const body = new URLSearchParams({ user_token: (process.env.XTRA_USER_TOKEN || '').trim(), ...params });
    const res = await fetch(XTRA_BASE + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      signal: ctrl.signal,
    });
    const text = await res.text();
    try { return JSON.parse(text); } catch (_) { return { status: 'ERROR', message: 'Invalid response from payment gateway.' }; }
  } catch (e) {
    return { status: 'ERROR', message: 'Could not reach the payment gateway. Please try again.' };
  } finally { clearTimeout(timer); }
}
function xtraCompleted(gw) {
  const st = String(gw.status || '').toUpperCase();
  const txn = String((gw.result && gw.result.txnStatus) || gw.txnStatus || '').toUpperCase();
  return st === 'COMPLETED' || st === 'SUCCESS' || txn === 'COMPLETED' || txn === 'SUCCESS';
}
function xtraFailed(gw) {
  const st = String(gw.status || '').toUpperCase();
  const txn = String((gw.result && gw.result.txnStatus) || gw.txnStatus || '').toUpperCase();
  return st === 'FAILED' || st === 'ERROR' || txn === 'FAILED' || txn === 'ERROR';
}

app.post('/api/payments/upi/create', requireAuth, rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!xtraEnabled()) return res.status(503).json({ error: 'UPI payment is not enabled on this store yet.' });
  const orderId = Number(req.body.order_id);
  if (!Number.isInteger(orderId)) return res.status(400).json({ error: 'Invalid order.' });
  try {
    const { rows } = await pool.query('SELECT * FROM orders WHERE id = $1', [orderId]);
    if (rows.length === 0 || (rows[0].user_id !== req.user.id && !isAdmin(req))) return res.status(404).json({ error: 'Order not found.' });
    const order = rows[0];
    if (order.status !== 'pending' || order.payment_method !== 'upi') {
      return res.status(400).json({ error: 'Only pending UPI orders can be paid online.' });
    }
    if (order.price <= 0) return res.status(400).json({ error: 'UPI payment needs an amount above \u20B90.' });
    let mobile = String(req.body.customer_mobile || order.customer_mobile || '').replace(/\D/g, '');
    if (mobile.length === 12 && mobile.startsWith('91')) mobile = mobile.slice(2);
    if (!/^\d{10}$/.test(mobile)) return res.status(400).json({ error: 'Enter a valid 10-digit mobile number.' });
    if (mobile !== order.customer_mobile) {
      await pool.query('UPDATE orders SET customer_mobile = $1 WHERE id = $2', [mobile, orderId]);
    }
    // Reuse a live gateway order; a FAILED one gets a fresh gateway order.
    if (order.xtra_order_id && order.xtra_payment_url && order.xtra_status !== 'FAILED') {
      return res.json({ payment_url: order.xtra_payment_url, order_id: orderId, reused: true });
    }
    const gwOrderId = 'TP' + orderId + Date.now().toString().slice(-8);
    const gw = await xtraPost('/api/create-order', {
      customer_mobile: mobile,
      amount: String(order.price),
      order_id: gwOrderId,
      redirect_url: 'https://customer-top-up-store.vercel.app/?payment_return=' + orderId,
      remark1: 'TopUp Hub order TP-' + orderId,
      remark2: req.user.email || '',
    });
    if (gw.status !== true || !gw.result || !gw.result.payment_url) {
      const msg = String((gw && gw.message) || 'Payment gateway did not create the order.').slice(0, 200);
      return res.status(502).json({ error: msg });
    }
    await pool.query('UPDATE orders SET xtra_order_id = $1, xtra_payment_url = $2, xtra_status = $3, updated_at = NOW() WHERE id = $4',
      [String(gw.result.orderId || gwOrderId), String(gw.result.payment_url), 'created', orderId]);
    res.json({ payment_url: String(gw.result.payment_url), order_id: orderId });
  } catch (err) {
    console.error('upi create failed:', err);
    res.status(500).json({ error: 'Could not start UPI payment.' });
  }
});

app.get('/api/payments/upi/status', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!xtraEnabled()) return res.status(503).json({ error: 'UPI payment is not enabled on this store yet.' });
  const orderId = Number(req.query.order_id);
  if (!Number.isInteger(orderId)) return res.status(400).json({ error: 'Invalid order.' });
  try {
    const { rows } = await pool.query('SELECT * FROM orders WHERE id = $1', [orderId]);
    if (rows.length === 0 || (rows[0].user_id !== req.user.id && !isAdmin(req))) return res.status(404).json({ error: 'Order not found.' });
    const order = rows[0];
    // Terminal statuses never flip back from a later gateway check.
    if (order.status === 'paid' || order.status === 'delivered' || order.status === 'cancelled' || order.status === 'refunded') {
      return res.json({ order_id: orderId, status: order.status, gateway: order.xtra_status || null, utr: order.xtra_utr || null });
    }
    if (!order.xtra_order_id) {
      return res.json({ order_id: orderId, status: order.status, gateway: null });
    }
    const gw = await xtraPost('/api/check-order-status', { order_id: order.xtra_order_id });
    if (xtraCompleted(gw)) {
      const utr = (gw.result && gw.result.utr) || gw.utr || null;
      await pool.query("UPDATE orders SET status = 'paid', xtra_status = 'COMPLETED', xtra_utr = $1, updated_at = NOW() WHERE id = $2", [utr || '', orderId]);
      fulfilBusanOrder(orderId).catch((e) => console.error('busan fulfil failed:', e.message));
      return res.json({ order_id: orderId, status: 'paid', gateway: 'COMPLETED', utr });
    }
    const failed = xtraFailed(gw);
    await pool.query('UPDATE orders SET xtra_status = $1, updated_at = NOW() WHERE id = $2', [failed ? 'FAILED' : 'PENDING', orderId]);
    res.json({
      order_id: orderId, status: order.status, gateway: failed ? 'FAILED' : 'PENDING',
      message: typeof gw.message === 'string' ? gw.message.slice(0, 200) : null,
    });
  } catch (err) {
    console.error('upi status failed:', err);
    res.status(500).json({ error: 'Could not check payment status.' });
  }
});

// ---- Region checker ----
// POST /api/region-check {player_id, zone_id} validates the ID against one
// small product from each MLBB regional route and reports which routes
// validate it. Validation never spends money (only orders do). A specific
// regional match wins over the generic route; the generic route alone maps
// to the store's MLBB India game (proven 2026-10-29: generic validates an
// India account while Global/Indonesia families reject it). No numeric
// Zone ID -> region table is used or claimed anywhere.
const REGION_PROBES = [
  { route: 'Philippines', game: 'Mobile Legends — Philippines', productId: 'mobile-legends-philippines888_5-diamonds363' },
  { route: 'Philippines', game: 'Mobile Legends — Philippines', productId: 'mlbbph643_mlbbph11928' },
  { route: 'Global', game: 'Mobile Legends — Global', productId: 'mlbbglobal202_mlbbglobal5186' },
  { route: 'Brazil', game: 'Mobile Legends — Brazil', productId: 'mlbbbr178_mlbbbr55992' },
  { route: 'Russia', game: 'Mobile Legends — Russia', productId: 'mlbb-russia46_mlbbru35714' },
  { route: 'Turkey', game: 'Mobile Legends — Turkey', productId: 'mlbbtr112_mlbbtr16786' },
  { route: 'United States', game: 'Mobile Legends — United States', productId: 'mobile-legends-united-states41_mlbbus55672' },
  { route: 'SG / MY', game: 'Mobile Legends — SG / MY (All Region)', productId: 'sgmy-mlbb893_mlbbspecial14557' },
  { route: 'SG / MY', game: 'Mobile Legends — SG / MY (All Region)', productId: 'mlbbsgmy885_mlbbsgmy14755' },
  { route: 'Indonesia', game: null, productId: 'mlbbid35_mlbbid5500' },
  { route: 'Generic', game: 'Mobile Legends — India', productId: 'mobile-legends114_86990' },
];
app.post('/api/region-check', rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  const playerId = cleanStr(req.body.player_id, 100);
  const zoneId = cleanStr(req.body.zone_id, 100);
  if (!playerId || !zoneId) return res.status(400).json({ error: 'Enter your User ID and Zone ID.' });
  if (!/^\d+$/.test(playerId) || !/^\d+$/.test(zoneId)) return res.status(400).json({ error: 'User ID and Zone ID must be numbers.' });
  if (!busan.configured()) return res.json({ configured: false });
  const validated = [];
  let username = '';
  let upstreamFailed = false;
  for (const probe of REGION_PROBES) {
    try {
      const v = await busan.validatePlayer(probe.productId, playerId, zoneId);
      const vd = (v && v.data) || {};
      if (vd.valid === true) {
        if (!validated.some((x) => x.route === probe.route)) {
          validated.push({ route: probe.route, game: probe.game });
        }
        if (!username && vd.username && String(vd.username) !== playerId) username = String(vd.username);
      }
    } catch (err) {
      // A 400 "Invalid player ID or server ID" means this route does not
      // serve the account — that is a NO for this route, not an error.
      const msg = String(err.message || '');
      if (!/Invalid player ID or server ID/i.test(msg)) upstreamFailed = true;
    }
  }
  if (validated.length === 0 && upstreamFailed) {
    return res.status(502).json({ error: 'Region check is unavailable right now. Try again later.' });
  }
  const specific = validated.filter((x) => x.route !== 'Generic' && x.route !== 'Indonesia');
  let recommended = null;
  let note = '';
  if (specific.length === 1) {
    recommended = specific[0].game;
  } else if (specific.length > 1) {
    // Validation alone cannot pinpoint a region when several routes validate
    // the same ID (proven 2026-10-29: an India account validated on
    // Philippines, Brazil, US, SG/MY and Generic). Recommending the first
    // match would send the customer to the wrong game, so recommend nothing
    // and let the customer pick the country where the account was created.
    note = 'This ID validated on more than one route, so validation alone cannot pinpoint your region. Pick the country where the account was created.';
  } else if (validated.some((x) => x.route === 'Generic')) {
    recommended = 'Mobile Legends — India';
    note = 'Only the generic route validated this ID. On this store that route is used for MLBB India.';
  } else if (validated.some((x) => x.route === 'Indonesia')) {
    note = 'This ID validated on the Indonesia route, which has no matching game on this store yet.';
  } else {
    note = 'No route validated this ID. Double-check your User ID and Zone ID.';
  }
  res.json({ username, validated: validated.map((x) => x.route), recommended, note });
});

app.get('/api/leaderboard', async (req, res) => {
  if (!pool) return res.json({ leaders: [] });
  try {
    const { rows } = await pool.query(
      `SELECT u.name AS name, u.email AS email, COALESCE(SUM(o.price), 0) AS total_spent, COUNT(*) AS order_count
       FROM orders o JOIN users u ON u.id = o.user_id
       WHERE o.status IN ('paid', 'delivered')
       GROUP BY u.id, u.name, u.email
       ORDER BY total_spent DESC, order_count DESC
       LIMIT 10`
    );
    const leaders = rows.map((r) => {
      const raw = (r.name || '').trim() || (r.email || '').split('@')[0] || 'Player';
      const clean = raw.replace(/\s+/g, ' ');
      const masked = clean.length <= 2 ? clean[0] + '***' : clean[0] + '***' + clean[clean.length - 1];
      return { name: masked, total_spent: Number(r.total_spent) || 0, order_count: Number(r.order_count) || 0 };
    });
    res.json({ leaders });
  } catch (err) {
    console.error('leaderboard failed:', err);
    res.json({ leaders: [] });
  }
});

app.get('/api/orders/me', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  try {
    const { rows } = await pool.query('SELECT * FROM orders WHERE user_id = $1 ORDER BY id DESC LIMIT 100', [req.user.id]);
    res.json({ orders: rows.map(orderOut) });
  } catch (err) {
    console.error('orders read failed:', err);
    res.status(500).json({ error: 'Could not load orders.' });
  }
});

app.get('/api/orders/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(404).json({ error: 'Order not found.' });
  try {
    const { rows } = await pool.query('SELECT * FROM orders WHERE id = $1', [id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Order not found.' });
    if (rows[0].user_id !== req.user.id && !isAdmin(req)) return res.status(404).json({ error: 'Order not found.' });
    res.json(orderOut(rows[0]));
  } catch (err) {
    console.error('order read failed:', err);
    res.status(500).json({ error: 'Could not load the order.' });
  }
});

app.get('/api/admin/orders', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin access only.' });
  const status = typeof req.query.status === 'string' ? req.query.status : '';
  try {
    const args = [];
    let where = '';
    if (['pending', 'paid', 'delivered', 'cancelled', 'refunded'].includes(status)) {
      where = 'WHERE o.status = $1';
      args.push(status);
    }
    const { rows } = await pool.query(
      `SELECT o.*, u.email AS user_email FROM orders o JOIN users u ON u.id = o.user_id ${where} ORDER BY o.id DESC LIMIT 200`,
      args
    );
    res.json({ orders: rows.map((r) => ({ ...orderOut(r), user_email: r.user_email })) });
  } catch (err) {
    console.error('admin orders read failed:', err);
    res.status(500).json({ error: 'Could not load orders.' });
  }
});

app.post('/api/admin/orders/:id/status', requireAuth, rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin access only.' });
  const id = Number(req.params.id);
  const next = req.body.status;
  const allowed = { pending: ['paid', 'delivered', 'cancelled'], paid: ['delivered', 'cancelled', 'refunded'], delivered: ['refunded'] };
  if (!Number.isInteger(id) || typeof next !== 'string') return res.status(400).json({ error: 'Invalid status change.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const cur = await client.query('SELECT * FROM orders WHERE id = $1 FOR UPDATE', [id]);
    if (cur.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Order not found.' });
    }
    const order = cur.rows[0];
    if (!allowed[order.status] || !allowed[order.status].includes(next)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Cannot move an order from ${order.status} to ${next}.` });
    }
    await client.query('UPDATE orders SET status = $1, updated_at = NOW() WHERE id = $2', [next, id]);
    // Wallet refund: cancelling a paid wallet order refunds it (existing behaviour),
    // and marking a paid OR delivered wallet order as refunded credits the price back.
    // UPI/WhatsApp refunds are a status record only — the money itself is returned
    // outside the system, so no wallet credit happens for those methods.
    const walletRefund = order.payment_method === 'wallet' &&
      ((next === 'cancelled' && order.status === 'paid') ||
       (next === 'refunded' && (order.status === 'paid' || order.status === 'delivered')));
    if (walletRefund) {
      await client.query(
        `INSERT INTO wallets (user_id, balance) VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE SET balance = wallets.balance + EXCLUDED.balance, updated_at = NOW()`,
        [order.user_id, order.price]
      );
      await client.query('INSERT INTO wallet_ledger (user_id, delta, kind, ref) VALUES ($1, $2, $3, $4)', [order.user_id, order.price, 'order_refund', `TP-${order.id}`]);
    }
    await client.query('COMMIT');
    if (next === 'paid') fulfilBusanOrder(id).catch((e) => console.error('busan fulfil failed:', e.message));
    res.json({ ok: true, status: next });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('order status failed:', err);
    res.status(500).json({ error: 'Could not update the order.' });
  } finally {
    client.release();
  }
});

app.get('/api/admin/topup-requests', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin access only.' });
  try {
    const { rows } = await pool.query(
      `SELECT t.*, u.email AS user_email FROM topup_requests t JOIN users u ON u.id = t.user_id
       ORDER BY (t.status = 'pending') DESC, t.id DESC LIMIT 200`
    );
    res.json({ requests: rows });
  } catch (err) {
    console.error('admin topups read failed:', err);
    res.status(500).json({ error: 'Could not load top-up requests.' });
  }
});

app.post('/api/admin/topup-requests/:id/decision', requireAuth, rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin access only.' });
  const id = Number(req.params.id);
  const decision = req.body.decision;
  if (!Number.isInteger(id) || (decision !== 'approved' && decision !== 'rejected')) {
    return res.status(400).json({ error: 'Invalid decision.' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const cur = await client.query('SELECT * FROM topup_requests WHERE id = $1 FOR UPDATE', [id]);
    if (cur.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Request not found.' });
    }
    const reqRow = cur.rows[0];
    if (reqRow.status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'This request was already decided.' });
    }
    await client.query('UPDATE topup_requests SET status = $1, updated_at = NOW() WHERE id = $2', [decision, id]);
    if (decision === 'approved') {
      await client.query(
        `INSERT INTO wallets (user_id, balance) VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE SET balance = wallets.balance + EXCLUDED.balance, updated_at = NOW()`,
        [reqRow.user_id, reqRow.amount]
      );
      await client.query('INSERT INTO wallet_ledger (user_id, delta, kind, ref) VALUES ($1, $2, $3, $4)', [reqRow.user_id, reqRow.amount, 'topup', `topup-${reqRow.id}`]);
    }
    await client.query('COMMIT');
    res.json({ ok: true, status: decision });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('topup decision failed:', err);
    res.status(500).json({ error: 'Could not decide the request.' });
  } finally {
    client.release();
  }
});

// ---- Phase 4: best sellers (real delivered counts) + coupons ----
// Best sellers is aggregate-only (game + delivered count), no buyer data.
app.get('/api/stats/best-sellers', async (req, res) => {
  if (!pool) return res.json({ games: [] });
  try {
    const { rows } = await pool.query(
      `SELECT game, COUNT(*)::int AS delivered FROM orders
       WHERE status = 'delivered' GROUP BY game ORDER BY delivered DESC LIMIT 10`
    );
    res.json({ games: rows });
  } catch (err) {
    console.error('best sellers failed:', err);
    res.status(500).json({ error: 'Could not load best sellers.' });
  }
});

function couponUsable(row) {
  if (!row || !row.active) return false;
  if (row.expires_at && new Date(row.expires_at) <= new Date()) return false;
  if (row.max_uses !== null && row.used_count >= row.max_uses) return false;
  return true;
}

function couponDiscount(row, price) {
  return row.kind === 'percent'
    ? Math.floor(price * row.value / 100)
    : Math.min(row.value, price);
}

app.post('/api/coupons/validate', requireAuth, rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  const code = cleanStr(req.body.code, 50).toUpperCase();
  const price = Number(req.body.price);
  if (!code || !Number.isInteger(price) || price < 0) {
    return res.status(400).json({ error: 'Invalid coupon check.' });
  }
  try {
    const { rows } = await pool.query('SELECT * FROM coupons WHERE code = $1', [code]);
    if (!couponUsable(rows[0])) return res.json({ valid: false, error: 'Invalid or expired coupon.' });
    const discount = couponDiscount(rows[0], price);
    res.json({ valid: true, code, discount, final_price: price - discount });
  } catch (err) {
    console.error('coupon validate failed:', err);
    res.status(500).json({ error: 'Could not check the coupon.' });
  }
});

app.get('/api/admin/coupons', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin access only.' });
  try {
    const { rows } = await pool.query('SELECT * FROM coupons ORDER BY id DESC LIMIT 200');
    res.json({ coupons: rows });
  } catch (err) {
    console.error('admin coupons read failed:', err);
    res.status(500).json({ error: 'Could not load coupons.' });
  }
});

app.post('/api/admin/coupons', requireAuth, rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin access only.' });
  const code = cleanStr(req.body.code, 50).toUpperCase();
  const kind = req.body.kind;
  const value = Number(req.body.value);
  const maxUses = req.body.max_uses === null || req.body.max_uses === undefined || req.body.max_uses === ''
    ? null
    : Number(req.body.max_uses);
  const expiresAt = req.body.expires_at ? new Date(req.body.expires_at) : null;
  if (!code || (kind !== 'percent' && kind !== 'flat') || !Number.isInteger(value) || value <= 0 ||
      (kind === 'percent' && value > 100) ||
      (maxUses !== null && (!Number.isInteger(maxUses) || maxUses <= 0)) ||
      (req.body.expires_at && Number.isNaN(expiresAt.getTime()))) {
    return res.status(400).json({ error: 'Invalid coupon details.' });
  }
  try {
    const { rows } = await pool.query(
      'INSERT INTO coupons (code, kind, value, max_uses, expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [code, kind, value, maxUses, expiresAt ? expiresAt.toISOString() : null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err && err.code === '23505') {
      return res.status(409).json({ error: 'That coupon code already exists.' });
    }
    console.error('coupon create failed:', err);
    res.status(500).json({ error: 'Could not create the coupon.' });
  }
});

app.post('/api/admin/coupons/:id/toggle', requireAuth, rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin access only.' });
  const id = Number(req.params.id);
  const active = req.body.active;
  if (!Number.isInteger(id) || typeof active !== 'boolean') {
    return res.status(400).json({ error: 'Invalid toggle.' });
  }
  try {
    const { rows } = await pool.query('UPDATE coupons SET active = $1 WHERE id = $2 RETURNING *', [active, id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Coupon not found.' });
    res.json(rows[0]);
  } catch (err) {
    console.error('coupon toggle failed:', err);
    res.status(500).json({ error: 'Could not update the coupon.' });
  }
});

// ---- Phase 3: Busan (1gamestopup) connection ----
// Key-gated: with no BUSAN_API_KEY set, every Busan path degrades
// gracefully (check-id reports unmapped/unconfigured, fulfilment skips,
// admin status reports configured:false) and orders behave exactly as
// before — manual delivery by the admin. Nothing here ever throws into a
// payment or status flow, and a failed Busan attempt never marks an order
// delivered: the order stays paid with busan_status='failed' so the admin
// can fix the cause (key, balance, mapping) and retry.
//
// Mapping: each pack in the admin-saved store_data games list may carry a
// busanProductId. Orders store game/pack as display names, so the mapping
// lookup matches those names (trimmed, case-insensitive) against the saved
// catalogue.
// Check-ID-only mapping: a pack's busanCheckProductId is used for the
// Check ID button only and never triggers auto-fulfilment. Fulfilment still
// requires busanProductId, so a check mapping can never cause a wallet spend.
async function findBusanCheckMapping(game, pack) {
  if (!pool) return '';
  try {
    const { rows } = await pool.query('SELECT data FROM store_data WHERE id = 1');
    if (rows.length === 0) return '';
    const games = rows[0].data && Array.isArray(rows[0].data.games) ? rows[0].data.games : [];
    const g = games.find((x) => String((x && x.name) || '').trim().toLowerCase() === String(game || '').trim().toLowerCase());
    if (!g || !Array.isArray(g.packs)) return '';
    const packName = (x) => String((x && (x.amt || x.name || x.label || x.title)) || '').trim().toLowerCase();
    const p = g.packs.find((x) => packName(x) === String(pack || '').trim().toLowerCase());
    if (!p) return '';
    return String(p.busanCheckProductId || p.busanProductId || '').trim();
  } catch (err) {
    console.error('busan check mapping lookup failed:', err);
    return '';
  }
}

async function findBusanMapping(game, pack) {
  if (!pool) return '';
  try {
    const { rows } = await pool.query('SELECT data FROM store_data WHERE id = 1');
    if (rows.length === 0) return '';
    const games = rows[0].data && Array.isArray(rows[0].data.games) ? rows[0].data.games : [];
    const g = games.find((x) => String((x && x.name) || '').trim().toLowerCase() === String(game || '').trim().toLowerCase());
    if (!g || !Array.isArray(g.packs)) return '';
    // Pack display names live in `amt` ("3 Diamonds"), not `name` — match
    // amt first, with name/label/title as fallbacks so older saves still work.
    const packName = (x) => String((x && (x.amt || x.name || x.label || x.title)) || '').trim().toLowerCase();
    const p = g.packs.find((x) => packName(x) === String(pack || '').trim().toLowerCase());
    if (!p) return '';
    return String(p.busanProductId || '').trim();
  } catch (err) {
    console.error('busan mapping lookup failed:', err);
    return '';
  }
}

// Fulfil one paid order through Busan. Idempotent: an order already marked
// busan_status='success' is never re-sent (real wallet spend per duplicate).
// Returns { status } where status is 'success' | 'failed' | 'skipped'.
async function fulfilBusanOrder(orderId) {
  if (!pool) return { status: 'skipped', reason: 'no_db' };
  const { rows } = await pool.query('SELECT * FROM orders WHERE id = $1', [orderId]);
  if (rows.length === 0) return { status: 'skipped', reason: 'not_found' };
  const order = rows[0];
  if (order.status !== 'paid') return { status: 'skipped', reason: 'not_paid' };
  if (order.busan_status === 'success') return { status: 'skipped', reason: 'already_fulfilled' };
  const productId = await findBusanMapping(order.game, order.pack);
  if (!productId) return { status: 'skipped', reason: 'unmapped' };
  if (!busan.configured()) return { status: 'skipped', reason: 'not_configured' };
  try {
    // Validate first so wallet balance is never burned on a bad player ID.
    const v = await busan.validatePlayer(productId, order.player_id, order.zone_id || undefined);
    const vd = (v && v.data) || {};
    if (vd.valid === false) throw new Error('player validation failed');
    const res = await busan.createOrder(productId, order.player_id, order.zone_id || undefined);
    const d = (res && res.data) || {};
    const busanOrderId = d.orderId || d.order_id || '';
    if (!busan.isSuccess(res)) {
      throw new Error('Busan non-success response: ' + JSON.stringify(res).slice(0, 200));
    }
    await pool.query(
      `UPDATE orders SET status = 'delivered', busan_status = 'success', busan_order_id = $1, busan_error = '', updated_at = NOW() WHERE id = $2`,
      [String(busanOrderId), orderId]
    );
    return { status: 'success', busan_order_id: String(busanOrderId) };
  } catch (err) {
    const msg = String((err && err.message) || 'unknown error').slice(0, 300);
    console.error(`[busan] order ${orderId} failed:`, msg);
    await pool.query(
      `UPDATE orders SET busan_status = 'failed', busan_error = $1, updated_at = NOW() WHERE id = $2`,
      [msg, orderId]
    ).catch(() => {});
    return { status: 'failed', error: msg };
  }
}

// Player ID check for the top-up panel. Public but rate-limited; the
// browser never sees the Busan mapping — it sends game/pack names and the
// backend resolves the mapped product. Unmapped packs and a missing key
// return a plain status instead of an error so checkout is never blocked.
// ---- Resellers: admin grants/revokes reseller status per account ----
// A reseller pays the per-pack reseller price (when the admin set one)
// instead of the regular price. Status is admin-only; the storefront never
// decides it.
app.get('/api/admin/resellers', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin access only.' });
  try {
    const { rows } = await pool.query('SELECT id, email, name, created_at FROM users WHERE is_reseller = TRUE ORDER BY email');
    res.json({ resellers: rows });
  } catch (err) {
    console.error('resellers list failed:', err);
    res.status(500).json({ error: 'Could not load resellers.' });
  }
});

app.post('/api/admin/resellers', requireAuth, rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin access only.' });
  const email = cleanStr(req.body.email, 200).toLowerCase();
  const make = req.body.reseller === true;
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email.' });
  try {
    const { rows } = await pool.query('UPDATE users SET is_reseller = $2 WHERE email = $1 RETURNING id, email, name', [email, make]);
    if (rows.length === 0) return res.status(404).json({ error: 'No account with that email.' });
    res.json({ ok: true, user: rows[0], reseller: make });
  } catch (err) {
    console.error('reseller set failed:', err);
    res.status(500).json({ error: 'Could not update reseller status.' });
  }
});

// ---- Users panel: admin lists every registered account ----
// Explicit columns only — password hashes are never returned. Order counts
// come from a single grouped join so the panel needs no second round-trip.
app.get('/api/admin/users', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin access only.' });
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.email, u.name, u.created_at, u.is_reseller, COUNT(o.id)::int AS order_count
       FROM users u LEFT JOIN orders o ON o.user_id = u.id
       GROUP BY u.id ORDER BY u.created_at DESC`
    );
    res.json({ users: rows });
  } catch (err) {
    console.error('users list failed:', err);
    res.status(500).json({ error: 'Could not load users.' });
  }
});

app.post('/api/games/check-id', rateLimit, async (req, res) => {
  const game = cleanStr(req.body.game, 200);
  const pack = cleanStr(req.body.pack, 200);
  const playerId = cleanStr(req.body.player_id, 100);
  const zoneId = cleanStr(req.body.zone_id, 100);
  if (!game || !pack || !playerId) return res.status(400).json({ error: 'Game, pack and player ID are required.' });
  const productId = await findBusanCheckMapping(game, pack);
  if (!productId) return res.json({ mapped: false });
  if (!busan.configured()) return res.json({ configured: false });
  try {
    const v = await busan.validatePlayer(productId, playerId, zoneId || undefined);
    const vd = (v && v.data) || {};
    res.json({
      mapped: true,
      valid: vd.valid !== false,
      username: vd.username ? String(vd.username) : '',
      player_id: vd.playerId ? String(vd.playerId) : playerId,
      zone_id: vd.zoneId ? String(vd.zoneId) : zoneId,
    });
  } catch (err) {
    console.error('busan check-id failed:', err);
    const msg = String(err.message || '');
    const supplierDown = /non-JSON|timed out|HTTP 50|HTTP 429|fetch failed|network/i.test(msg);
    const plain = supplierDown
      ? 'ID check is temporarily unavailable. Please try again in a bit.'
      : 'Your User ID or Zone ID is wrong. Please check your in-game profile and try again.';
    res.status(502).json({ error: plain });
  }
});

app.get('/api/admin/busan/status', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin access only.' });
  if (!busan.configured()) return res.json({ configured: false });
  try {
    const bal = await busan.getBalance();
    res.json({ configured: true, balance: bal.balance, currency: bal.currency });
  } catch (err) {
    console.error('busan balance failed:', err);
    res.json({ configured: true, error: String(err.message || 'unknown error').slice(0, 200) });
  }
});

app.get('/api/admin/busan/products', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin access only.' });
  if (!busan.configured()) return res.status(400).json({ error: 'Busan is not connected yet.' });
  try {
    const list = await busan.getProducts();
    res.json({
      products: list.map((p) => ({
        productId: p.productId != null ? String(p.productId) : '',
        productName: p.productName != null ? String(p.productName) : '',
        price: p.price != null ? String(p.price) : '',
      })),
    });
  } catch (err) {
    console.error('busan products failed:', err);
    res.status(502).json({ error: 'Could not load the Busan catalogue: ' + String(err.message || 'unknown error').slice(0, 200) });
  }
});

app.post('/api/admin/orders/:id/fulfil', requireAuth, rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Auth service is not connected to a database yet.' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin access only.' });
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(404).json({ error: 'Order not found.' });
  try {
    const { rows } = await pool.query('SELECT * FROM orders WHERE id = $1', [id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Order not found.' });
    const order = rows[0];
    if (order.status !== 'paid') return res.status(400).json({ error: 'Only paid orders can be fulfilled.' });
    if (order.busan_status === 'success') return res.status(400).json({ error: 'This order was already fulfilled through Busan.' });
    const productId = await findBusanMapping(order.game, order.pack);
    if (!productId) return res.status(400).json({ error: 'This pack is not mapped to a Busan product yet.' });
    if (!busan.configured()) return res.status(400).json({ error: 'Busan is not connected yet — add the API key first.' });
    const result = await fulfilBusanOrder(id);
    if (result.status === 'success') return res.json({ ok: true, busan_status: 'success', busan_order_id: result.busan_order_id || '' });
    return res.status(502).json({ ok: false, busan_status: 'failed', error: result.error || 'Fulfilment failed.' });
  } catch (err) {
    console.error('busan fulfil retry failed:', err);
    res.status(500).json({ error: 'Could not fulfil the order.' });
  }
});

// ---- Google sign-in ----
// GET /api/auth/google starts the flow; Google redirects back to
// /api/auth/google/callback, which finds or creates the account by email,
// then returns the browser to the store with #token=<jwt> in the URL hash
// (a hash, so the token never lands in server logs). The storefront reads
// the hash on load, saves the token, and clears it from the address bar.
function googleRedirectUri(req) {
  if (process.env.GOOGLE_REDIRECT_URI) return process.env.GOOGLE_REDIRECT_URI;
  return `https://${req.get('host')}/api/auth/google/callback`;
}

app.get('/api/auth/google', (req, res) => {
  if (!process.env.GOOGLE_CLIENT_ID) {
    return res.status(503).send('Google sign-in is not configured yet.');
  }
  const state = crypto.randomBytes(16).toString('hex');
  res.cookie('gstate', state, {
    httpOnly: true, sameSite: 'lax', secure: true,
    maxAge: 10 * 60 * 1000, path: '/api/auth/google',
  });
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: googleRedirectUri(req),
    response_type: 'code',
    scope: 'openid email profile',
    state,
    prompt: 'select_account',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/api/auth/google/callback', async (req, res) => {
  const storeOrigin = CORS_ORIGINS[0] || '';
  const fail = (msg) => res.redirect(`${storeOrigin}/#auth_error=${encodeURIComponent(msg)}`);
  try {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !pool || !JWT_SECRET) {
      return fail('Google sign-in is not configured yet.');
    }
    const cookieHeader = req.headers.cookie || '';
    const stateCookie = cookieHeader.split(';').map((s) => s.trim()).find((s) => s.startsWith('gstate='));
    if (!req.query.code || !req.query.state || !stateCookie || req.query.state !== stateCookie.slice(7)) {
      return fail('Google sign-in failed. Try again.');
    }
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: req.query.code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: googleRedirectUri(req),
        grant_type: 'authorization_code',
      }),
    });
    const tokens = await tokenRes.json();
    if (!tokens.access_token) return fail('Google sign-in failed. Try again.');
    const meRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const profile = await meRes.json();
    if (!profile.email) return fail('Google sign-in failed. Try again.');
    const email = String(profile.email).toLowerCase();
    const name = typeof profile.name === 'string' ? profile.name.slice(0, 100) : '';
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    let user;
    if (rows.length > 0) {
      user = publicUser(rows[0]);
    } else {
      // Google accounts carry no password: store a random unusable hash so
      // nobody can sign in to this account with a guessed password.
      const hash = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10);
      const ins = await pool.query(
        'INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id, email, name, created_at',
        [email, hash, name]
      );
      user = publicUser(ins.rows[0]);
    }
    res.clearCookie('gstate', { path: '/api/auth/google' });
    res.redirect(`${storeOrigin}/#token=${signToken(user)}`);
  } catch (err) {
    console.error('google callback failed:', err);
    fail('Google sign-in failed. Try again.');
  }
});


ensureSchema()
  .catch((err) => console.error('schema setup failed (will retry per-request):', err))
  .finally(() => app.listen(PORT, () => console.log(`customer-top-up-backend listening on ${PORT}`)));
