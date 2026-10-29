// Busan API client (https://1gamestopup.com/api/v1) for TopUp Hub.
//
// Auth: x-api-key header, read ONLY from process.env.BUSAN_API_KEY.
// The key is never logged, never returned to the browser, and never written
// to any file. When it is missing every call throws a clear "not configured"
// error so callers degrade gracefully (skip auto-fulfilment, report the
// connection as off). Busan calls use USD: the merchant's Busan wallet is
// USD-funded.

const BASE = 'https://1gamestopup.com/api/v1';
const TIMEOUT_MS = 25000;
const BUSAN_CURRENCY = 'USD';

function configured() {
  return !!((process.env.BUSAN_API_KEY || '').trim());
}

function ensureKey() {
  const k = (process.env.BUSAN_API_KEY || '').trim();
  if (!k) throw new Error('Busan not configured: set the BUSAN_API_KEY environment variable.');
  return k;
}

async function busanFetch(path, { method = 'GET', body } = {}) {
  const key = ensureKey(); // throws when not configured
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(BASE + path, {
      method,
      headers: { 'Content-Type': 'application/json', 'x-api-key': key },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (_) {
      throw new Error(`Busan returned a non-JSON response (HTTP ${res.status}).`);
    }
    if (!res.ok) {
      const msg = data && (data.message || data.error);
      const err = new Error(
        'Busan request failed (HTTP ' + res.status + ')' +
        (msg ? ': ' + String(msg).slice(0, 200) : '.')
      );
      err.upstreamStatus = res.status;
      throw err;
    }
    if (data && data.success === false) {
      const msg = data.message || data.error;
      const err = new Error('Busan request failed' + (msg ? ': ' + String(msg).slice(0, 200) : '.'));
      err.upstreamStatus = res.status;
      throw err;
    }
    return data;
  } catch (e) {
    if (e && e.name === 'AbortError') throw new Error('Busan request timed out.');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// GET /api-service/balance?currency=USD -> { data: { balance: "50.00 USD" } }
async function getBalance() {
  const d = await busanFetch('/api-service/balance?currency=' + BUSAN_CURRENCY);
  const raw = d && d.data && d.data.balance;
  return { balance: raw != null ? String(raw) : null, currency: BUSAN_CURRENCY };
}

// GET /api-service/products?currency=USD -> { data: [{ productId, productName, price }] }
let productsCache = null;
let productsCacheAt = 0;
const PRODUCTS_CACHE_MS = 10 * 60 * 1000;

async function getProducts() {
  const now = Date.now();
  if (productsCache && now - productsCacheAt < PRODUCTS_CACHE_MS) return productsCache;
  const d = await busanFetch('/api-service/products?currency=' + BUSAN_CURRENCY);
  const list = Array.isArray(d && d.data) ? d.data : [];
  productsCache = list;
  productsCacheAt = now;
  return list;
}

// POST /api-service/validate { productId, playerId, zoneId? }
// -> { data: { valid, username, playerId, zoneId } }
async function validatePlayer(productId, playerId, zoneId) {
  if (!productId || !playerId) throw new Error('productId and playerId are required to validate a player.');
  const body = { productId: String(productId), playerId: String(playerId) };
  if (zoneId !== undefined && zoneId !== null && String(zoneId).trim() !== '') {
    body.zoneId = String(zoneId).trim();
  }
  return busanFetch('/api-service/validate', { method: 'POST', body });
}

// POST /api-service/order { productId, playerId, zoneId?, currency: "USD" }
// -> { data: { orderId, status: "success", ... } }
async function createOrder(productId, playerId, zoneId) {
  if (!productId || !playerId) throw new Error('productId and playerId are required to create a Busan order.');
  const body = { productId: String(productId), playerId: String(playerId), currency: BUSAN_CURRENCY };
  if (zoneId !== undefined && zoneId !== null && String(zoneId).trim() !== '') {
    body.zoneId = String(zoneId).trim();
  }
  return busanFetch('/api-service/order', { method: 'POST', body });
}

// True when a Busan order response means the top-up went through.
function isSuccess(data) {
  if (!data || typeof data !== 'object') return false;
  const d = data.data || data;
  const s = String(d.status || '').toLowerCase();
  return d.success === true || ['success', 'completed', 'delivered'].includes(s);
}

module.exports = {
  configured,
  BUSAN_CURRENCY,
  getBalance,
  getProducts,
  validatePlayer,
  createOrder,
  isSuccess,
};
