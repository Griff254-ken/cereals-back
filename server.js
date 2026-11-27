'use strict';
/* =====================================================================
   Golden Harvest Cereals — API server (Express + MongoDB Atlas + IntaSend M-Pesa)

   Matches the storefront (cereals.html) and admin console (admin.html):
     Public : GET  /health
              GET  /api/products
              GET  /api/products/:id/image
              POST /api/orders                    (Idempotency-Key header)
              POST /api/intasend/stkpush
              GET  /api/orders/:id/status
              POST /api/intasend/webhook          (set this URL in IntaSend)
     Admin  : HTTP Basic auth (ADMIN_USERNAME / ADMIN_PASSWORD)
              GET/POST/PUT/DELETE /api/admin/products[/:id]
              GET  /api/admin/orders?status=all
              POST /api/admin/orders/:id/confirm | /reject | /resolve-review
              DELETE /api/admin/orders/:id

   Why payments are fast and reliable here:
     * The HTTP port opens immediately; MongoDB connects in the background
       (no Render "no open port" timeouts, /health reports db state).
     * The status endpoint ACTIVELY asks IntaSend about a pending payment
       (throttled), so the customer sees "paid" in seconds even if the
       webhook is late. The webhook is verified against IntaSend's status
       API before anything is marked paid.
     * A background reconciler settles payments for customers who closed
       the page, and every state change is atomic and idempotent.
     * Product photos are served from their own cacheable URL, so the
       product list stays tiny.
   ===================================================================== */

const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { MongoClient, ObjectId } = require('mongodb');

/* ------------------------------ Config ------------------------------ */
const env = process.env;
const int = (v, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : d; };
const bool = (v, d = false) => (v == null || v === '' ? d : /^(1|true|yes|on)$/i.test(String(v)));
const trimSlash = s => String(s || '').trim().replace(/\/+$/, '');

const CFG = {
  PORT: int(env.PORT, 3000),
  NODE_ENV: env.NODE_ENV || 'production',
  MONGODB_URI: env.MONGODB_URI || '',
  DB_NAME: env.DB_NAME || 'golden_harvest',
  MONGO_POOL: int(env.MONGO_POOL_SIZE, 10),
  ALLOWED_ORIGINS: String(env.ALLOWED_ORIGINS || '').split(',').map(s => trimSlash(s).toLowerCase()).filter(Boolean),
  PUBLIC_URL: trimSlash(env.PUBLIC_URL),
  ADMIN_USERNAME: env.ADMIN_USERNAME || '',
  ADMIN_PASSWORD: env.ADMIN_PASSWORD || '',
  INTASEND_PUBLISHABLE_KEY: env.INTASEND_PUBLISHABLE_KEY || '',
  INTASEND_SECRET_KEY: env.INTASEND_SECRET_KEY || '',
  INTASEND_WEBHOOK_CHALLENGE: env.INTASEND_WEBHOOK_CHALLENGE || '',
  INTASEND_TEST: bool(env.INTASEND_TEST, false),          // true = sandbox.intasend.com
  SEED_SAMPLE_PRODUCTS: bool(env.SEED_SAMPLE_PRODUCTS, false),
  STK_COOLDOWN_MS: int(env.STK_COOLDOWN_MS, 25000),       // min gap between prompts for one order
  STATUS_CHECK_MS: int(env.STATUS_CHECK_MS, 4000),        // min gap between IntaSend lookups per order
  RECONCILE_MS: int(env.RECONCILE_MS, 60000),
  MAX_QTY: int(env.MAX_QTY, 1000),
  MAX_LINES: int(env.MAX_LINES, 50)
};

const ANY_ORIGIN = CFG.ALLOWED_ORIGINS.length === 0;
const IS = {
  configured: !!(CFG.INTASEND_PUBLISHABLE_KEY && CFG.INTASEND_SECRET_KEY && CFG.INTASEND_WEBHOOK_CHALLENGE),
  base: CFG.INTASEND_TEST ? 'https://sandbox.intasend.com' : 'https://payment.intasend.com'
};

/* ------------------------------ Utils ------------------------------- */
const sleep = ms => new Promise(r => setTimeout(r, ms));
const log = (level, msg, extra) => {
  const line = JSON.stringify({ t: new Date().toISOString(), level, msg, ...extra });
  (level === 'error' ? console.error : console.log)(line);
};
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; this.expose = true; }
}
const bad = m => new HttpError(400, m);
const ah = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const round2 = n => Math.round(n * 100) / 100;
const isObjectId = s => /^[a-f0-9]{24}$/i.test(s);
const isOrderId = s => /^[a-f0-9]{32}$/.test(s);
const toBuf = b => (Buffer.isBuffer(b) ? b : Buffer.from(b.buffer));
const stable = v => Array.isArray(v) ? v.map(stable)
  : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, stable(v[k])])) : v;
const cleanText = (v, max) => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);

function normPhone(v) {
  v = String(v || '').replace(/[\s\-+()]/g, '');
  if (/^0[17]\d{8}$/.test(v)) return '254' + v.slice(1);
  if (/^254[17]\d{8}$/.test(v)) return v;
  if (/^[17]\d{8}$/.test(v)) return '254' + v;
  return null;
}

const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function newReference() {
  const ymd = new Date().toISOString().slice(2, 10).replace(/-/g, '');
  let s = '';
  for (const b of crypto.randomBytes(4)) s += ALPHA[b % ALPHA.length];
  return `GH-${ymd}-${s}`;
}

/* ------------------------------ Database ---------------------------- */
let client = null, db = null, dbReady = false, shuttingDown = false;
const col = {};

async function ensureIndexes() {
  try {
    await Promise.all([
      col.products.createIndex({ category: 1, name: 1 }),
      col.orders.createIndex({ createdAt: -1 }),
      col.orders.createIndex({ reference: 1 }, { unique: true }),
      col.orders.createIndex({ idempotencyKey: 1 }, { unique: true, partialFilterExpression: { idempotencyKey: { $type: 'string' } } }),
      col.orders.createIndex({ paymentStatus: 1, adminConfirmed: 1 }),
      col.orders.createIndex({ paymentStatus: 1, stkSentAt: 1 }),
      col.events.createIndex({ receivedAt: 1 }, { expireAfterSeconds: 90 * 86400 }),
      col.audit.createIndex({ at: -1 })
    ]);
  } catch (e) { log('warn', 'index creation problem', { err: e.message }); }
}

async function connectDb() {
  let delay = 1000;
  while (!shuttingDown) {
    try {
      client = new MongoClient(CFG.MONGODB_URI, {
        maxPoolSize: CFG.MONGO_POOL, minPoolSize: 1,
        serverSelectionTimeoutMS: 8000, connectTimeoutMS: 10000, socketTimeoutMS: 45000,
        retryWrites: true, appName: 'golden-harvest-api'
      });
      await client.connect();
      db = client.db(CFG.DB_NAME);
      col.products = db.collection('products');
      col.orders = db.collection('orders');
      col.events = db.collection('paymentEvents');
      col.audit = db.collection('audit');
      await ensureIndexes();
      if (CFG.SEED_SAMPLE_PRODUCTS) await seedProducts();
      dbReady = true;
      log('info', 'mongodb connected', { db: CFG.DB_NAME });
      return;
    } catch (e) {
      log('error', 'mongodb connection failed, retrying', { err: e.message, retryInMs: delay });
      try { await client?.close(); } catch { /* ignore */ }
      await sleep(delay);
      delay = Math.min(delay * 2, 30000);
    }
  }
}

async function dbPing() {
  if (!dbReady) return false;
  try {
    await Promise.race([db.command({ ping: 1 }), sleep(3000).then(() => { throw new Error('timeout'); })]);
    return true;
  } catch { return false; }
}

const requireDb = (status = 503) => (req, res, next) =>
  dbReady ? next() : next(new HttpError(status, 'The store is starting up. Please try again in a few seconds.'));

const audit = (admin, action, target, detail) =>
  dbReady && col.audit.insertOne({ at: new Date(), admin, action, target: String(target || ''), detail: detail || null }).catch(() => {});

/* ------------------------------ Products ---------------------------- */
const DEFAULT_GRADIENT = ['#c9a24a', '#7a5c1a'];
const DATA_URL = /^data:image\/(png|jpe?g|webp|gif);base64,([A-Za-z0-9+/=]+)$/;
const MAX_IMAGE_BYTES = 1024 * 1024;

function sniffImage(buf, ext) {
  const h = buf.subarray(0, 12);
  if (/^jpe?g$/.test(ext)) return h[0] === 0xff && h[1] === 0xd8;
  if (ext === 'png') return h[0] === 0x89 && h[1] === 0x50 && h[2] === 0x4e && h[3] === 0x47;
  if (ext === 'gif') return h.subarray(0, 4).toString('latin1') === 'GIF8';
  if (ext === 'webp') return h.subarray(0, 4).toString('latin1') === 'RIFF' && h.subarray(8, 12).toString('latin1') === 'WEBP';
  return false;
}

function parseImage(v) {
  if (v == null || v === '') return { image: '', imageData: null, imageMime: null, imageBuf: null };
  if (typeof v !== 'string') throw bad('Photo is not valid.');
  if (v.startsWith('data:')) {
    if (v.length > 1.5 * 1024 * 1024) throw bad('That photo is too large. Please choose a smaller one.');
    const m = DATA_URL.exec(v);
    if (!m) throw bad('Photo must be a PNG, JPG, WebP or GIF image.');
    const ext = m[1].toLowerCase();
    const buf = Buffer.from(m[2], 'base64');
    if (!buf.length || buf.length > MAX_IMAGE_BYTES) throw bad('That photo is too large. Please choose a smaller one.');
    if (!sniffImage(buf, ext)) throw bad('That file is not a valid image.');
    return { image: '', imageData: buf, imageMime: 'image/' + (ext === 'jpg' ? 'jpeg' : ext), imageBuf: buf };
  }
  if (/^https:\/\/\S+$/i.test(v) && v.length <= 2048) return { image: v, imageData: null, imageMime: null, imageBuf: null };
  throw bad('Photo must be an uploaded picture or an https:// link.');
}

function cleanProduct(b, existing) {
  if (!b || typeof b !== 'object' || Array.isArray(b)) throw bad('Invalid product.');
  const name = cleanText(b.name, 120);
  const unit = cleanText(b.unit, 60);
  if (!name) throw bad('Product name is required.');
  if (!unit) throw bad('Unit is required (for example "per kg").');
  const priceRaw = typeof b.price === 'number' ? b.price : parseFloat(String(b.price ?? '').trim());
  if (!Number.isFinite(priceRaw) || priceRaw < 0 || priceRaw > 10000000) throw bad('Enter a valid price.');

  const gradient = Array.isArray(b.gradient) && b.gradient.length === 2 && b.gradient.every(c => /^#[0-9a-f]{3,8}$/i.test(String(c)))
    ? b.gradient.map(String) : DEFAULT_GRADIENT;

  const specs = (Array.isArray(b.specs) ? b.specs : []).slice(0, 20)
    .map(s => Array.isArray(s) ? [cleanText(s[0], 60), cleanText(s[1], 200)] : null)
    .filter(s => s && s[0] && s[1]);

  const options = (Array.isArray(b.options) ? b.options : []).slice(0, 6).map(g => {
    const key = cleanText(g?.key, 40);
    const seen = new Set();
    const choices = (Array.isArray(g?.choices) ? g.choices : []).slice(0, 12).map(c => {
      const value = cleanText(c?.value, 60);
      const a = Number(c?.priceAdjust);
      return { value, priceAdjust: Number.isFinite(a) ? round2(Math.max(-1e6, Math.min(1e6, a))) : 0 };
    }).filter(c => c.value && !seen.has(c.value) && seen.add(c.value));
    return { key, choices };
  }).filter(g => g.key && g.choices.length);
  if (new Set(options.map(o => o.key)).size !== options.length) throw bad('Option names must be different from each other.');

  const img = parseImage(b.image);
  const now = new Date();
  const doc = {
    name, unit, price: round2(priceRaw),
    category: cleanText(b.category, 60) || 'Other',
    description: cleanText(b.description, 600),
    emoji: cleanText(b.emoji, 8) || '🌾',
    inStock: b.inStock === true || b.inStock === 'true',
    gradient, specs, options,
    image: img.image, imageData: img.imageData, imageMime: img.imageMime, imageVer: null,
    updatedAt: now
  };
  if (img.imageData) {
    const same = existing?.imageData && toBuf(existing.imageData).equals(img.imageBuf);
    doc.imageVer = same ? existing.imageVer : now.getTime();
  }
  return doc;
}

function serProduct(p, { admin = false, base = '' } = {}) {
  let image = p.image || '';
  if (p.imageData) {
    image = admin
      ? `data:${p.imageMime};base64,${toBuf(p.imageData).toString('base64')}`
      : `${base}/api/products/${p._id}/image?v=${p.imageVer || 0}`;
  }
  return {
    id: String(p._id), name: p.name, category: p.category, emoji: p.emoji, unit: p.unit, price: p.price,
    description: p.description, gradient: p.gradient, image, inStock: p.inStock !== false,
    specs: p.specs || [], options: p.options || []
  };
}

function seedList() {
  const mk = (name, category, emoji, price, description, specs, gradient) => ({
    name, category, emoji, unit: 'per pack', price, description, inStock: true, gradient, specs, image: '', imageData: null, imageMime: null, imageVer: null,
    options: [{ key: 'Pack size', choices: [1, 2, 5, 10].map(n => ({ value: `${n} kg`, priceAdjust: round2(price * (n - 1)) })) }]
  });
  const t = new Date();
  return [
    mk('Pishori Rice', 'Rice', '🍚', 220, 'Aromatic long-grain rice, sorted and cleaned.', [['Origin', 'Mwea'], ['Grade', 'Premium']], ['#e9d8a6', '#b08968']),
    mk('Dry Maize (White)', 'Maize', '🌽', 90, 'Clean dry white maize for ugali flour or githeri.', [['Grade', 'A'], ['Moisture', '≤ 13.5%']], ['#f4d35e', '#b8860b']),
    mk('Yellow Maize', 'Maize', '🌽', 85, 'Dry yellow maize, ideal for feeds and flour.', [['Grade', 'A']], ['#f6c945', '#c58a00']),
    mk('Whole Wheat Grain', 'Wheat', '🌾', 120, 'Whole wheat grain for flour, porridge or baking.', [['Grade', 'A']], ['#d9b26f', '#8c6a2f']),
    mk('Finger Millet (Wimbi)', 'Millet', '🌾', 180, 'Nutritious finger millet for porridge and ugali.', [['Grade', 'Premium']], ['#a98467', '#6c4f3d']),
    mk('Sorghum', 'Sorghum', '🌾', 130, 'Clean red sorghum grain.', [['Grade', 'A']], ['#c97b63', '#7f3b2c']),
    mk('Green Grams (Ndengu)', 'Beans & Legumes', '🫘', 200, 'Sorted green grams, quick to cook.', [['Grade', 'A']], ['#a7c957', '#4f772d']),
    mk('Rosecoco Beans', 'Beans & Legumes', '🫘', 190, 'Popular rosecoco beans, clean and graded.', [['Grade', 'A']], ['#d08c60', '#8a4b2a'])
  ].map(p => ({ ...p, createdAt: t, updatedAt: t }));
}
async function seedProducts() {
  if ((await col.products.estimatedDocumentCount()) === 0) {
    await col.products.insertMany(seedList());
    log('info', 'seeded sample products');
  }
}

/* ------------------------------ Orders ------------------------------ */
const serOrder = o => ({
  id: o._id, reference: o.reference, customer: o.customer, items: o.items, total: o.total,
  paymentStatus: o.paymentStatus, adminConfirmed: !!o.adminConfirmed,
  confirmedAt: o.confirmedAt || null, paidAt: o.paidAt || null,
  needsReview: !!o.needsReview, reviewNote: o.reviewNote || '', paymentMessage: o.paymentMessage || '',
  intasendReceipt: o.intasendReceipt || '', providerRef: o.providerRef || '', mpesaReceipt: o.intasendReceipt || '',
  createdAt: o.createdAt
});
const orderSummary = o => ({ orderId: o._id, reference: o.reference, total: o.total });

function cleanCustomer(c) {
  if (!c || typeof c !== 'object') throw bad('Customer details are missing.');
  const name = cleanText(c.name, 80), location = cleanText(c.location, 160), phone = normPhone(c.phone);
  if (name.length < 2) throw bad('Please enter your name.');
  if (!phone) throw bad('Enter a valid Safaricom number, e.g. 0712 345 678.');
  if (location.length < 2) throw bad('Please enter a delivery location.');
  return { name, phone, location };
}

function cleanItems(raw) {
  if (!Array.isArray(raw) || !raw.length) throw bad('Your cart is empty.');
  if (raw.length > CFG.MAX_LINES) throw bad('Too many different items in one order.');
  return raw.map(i => {
    const productId = String(i?.productId ?? '');
    const quantity = Number(i?.quantity);
    if (!isObjectId(productId)) throw bad('One of the items in your cart is invalid.');
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > CFG.MAX_QTY) throw bad(`Quantity must be a whole number from 1 to ${CFG.MAX_QTY}.`);
    const options = {};
    if (i.options && typeof i.options === 'object' && !Array.isArray(i.options)) {
      const keys = Object.keys(i.options).slice(0, 10);
      for (const k of keys) options[cleanText(k, 40)] = cleanText(i.options[k], 60);
    }
    return { productId, quantity, options, note: cleanText(i.note, 200) };
  });
}

function priceLine(product, item) {
  const chosen = {};
  let adj = 0;
  for (const k of Object.keys(item.options)) {
    if (!product.options.some(o => o.key === k)) throw bad(`"${k}" is not an option for ${product.name}.`);
  }
  for (const g of product.options) {
    const want = item.options[g.key] ?? g.choices[0].value;
    const c = g.choices.find(x => x.value === want);
    if (!c) throw bad(`"${want}" is no longer available for ${product.name}.`);
    chosen[g.key] = c.value;
    adj += c.priceAdjust || 0;
  }
  const unitPrice = round2(product.price + adj);
  if (unitPrice < 0) throw bad(`Price for ${product.name} is invalid.`);
  return {
    productId: String(product._id), name: product.name, unitPrice, quantity: item.quantity,
    lineTotal: round2(unitPrice * item.quantity), options: chosen, note: item.note
  };
}

/* ---------------------------- IntaSend client ----------------------- */
class UpstreamError extends Error {
  constructor(message, status, detail) { super(message); this.status = status; this.detail = detail || ''; }
}
const upstreamDetail = d => {
  const e = d?.errors?.[0]?.detail || d?.detail || d?.message;
  return e ? String(e).slice(0, 160) : '';
};

async function intasend(path, body, { timeout = 15000, retries = 0 } = {}) {
  let last;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const r = await fetch(IS.base + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${CFG.INTASEND_SECRET_KEY}` },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeout)
      });
      const text = await r.text();
      let data = null; try { data = JSON.parse(text); } catch { /* non-JSON */ }
      if (r.ok) return data || {};
      last = new UpstreamError(`IntaSend responded ${r.status}`, r.status, upstreamDetail(data));
      if (r.status < 500) throw last;                  // client errors are never retried
    } catch (e) {
      if (e instanceof UpstreamError && e.status < 500) throw e;
      last = e instanceof UpstreamError ? e : new UpstreamError('IntaSend unreachable: ' + (e.name || e.message), 0);
    }
    if (attempt < retries) await sleep(600);
  }
  throw last;
}

const normInvoice = r => {
  const i = r?.invoice || r || {};
  const value = parseFloat(i.value ?? i.net_amount ?? '');
  return {
    id: String(i.invoice_id || i.id || ''),
    state: String(i.state || '').toUpperCase(),
    value: Number.isFinite(value) ? value : NaN,
    currency: String(i.currency || 'KES').toUpperCase(),
    apiRef: String(i.api_ref || ''),
    receipt: String(i.mpesa_reference || i.invoice_id || ''),
    failedCode: i.failed_code != null && i.failed_code !== '' ? String(i.failed_code) : null,
    failedReason: i.failed_reason ? String(i.failed_reason).slice(0, 200) : ''
  };
};
const checkInvoice = async invoiceId =>
  normInvoice(await intasend('/api/v1/payment/status/', { invoice_id: invoiceId }, { timeout: 8000, retries: 1 }));

/* Apply a VERIFIED invoice state to its order. Atomic + idempotent: safe to
   call from webhook, status polling and the reconciler at the same time. */
async function applyInvoice(inv) {
  if (!inv.id || !isOrderId(inv.apiRef)) return null;
  const order = await col.orders.findOne({ _id: inv.apiRef });
  if (!order) return null;
  const now = new Date();

  if (inv.state === 'COMPLETE') {
    const issues = [];
    if (Number.isFinite(inv.value) && inv.value + 0.009 < order.total) issues.push(`Underpaid: received ${inv.value}, expected ${order.total}.`);
    if (inv.currency !== 'KES') issues.push(`Unexpected currency ${inv.currency}.`);
    const set = {
      paymentStatus: 'paid', paidAt: now, intasendReceipt: inv.receipt, providerRef: inv.id,
      paidAmount: Number.isFinite(inv.value) ? inv.value : null, failedCode: null, paymentMessage: null, updatedAt: now
    };
    if (issues.length) { set.needsReview = true; set.reviewNote = issues.join(' ') + ' Check this payment in the IntaSend dashboard.'; }

    const paid = await col.orders.findOneAndUpdate(
      { _id: order._id, paymentStatus: { $in: ['pending', 'failed'] } },
      { $set: set, $addToSet: { paidInvoices: inv.id, invoiceIds: inv.id } },
      { returnDocument: 'after' });
    if (paid) { log('info', 'order paid', { order: order.reference, source: 'verified' }); return paid; }

    // Money arrived for an order that is already paid (second payment) or was cancelled.
    const note = order.paymentStatus === 'cancelled'
      ? 'Money was received after this order was cancelled. Refund the customer in the IntaSend dashboard.'
      : 'The customer paid more than once for this order. Refund the extra payment in the IntaSend dashboard.';
    const flagged = await col.orders.findOneAndUpdate(
      { _id: order._id, paymentStatus: order.paymentStatus, paidInvoices: { $ne: inv.id } },
      { $set: { needsReview: true, reviewNote: `${note} (Ref ${inv.receipt})`, updatedAt: now }, $addToSet: { paidInvoices: inv.id, invoiceIds: inv.id } },
      { returnDocument: 'after' });
    if (flagged) log('warn', 'payment flagged for review', { order: order.reference, status: order.paymentStatus });
    return flagged || order;
  }

  if (inv.state === 'FAILED') {
    return col.orders.findOneAndUpdate(
      { _id: order._id, paymentStatus: 'pending', currentInvoiceId: inv.id },
      { $set: { paymentStatus: 'failed', failedCode: inv.failedCode, paymentMessage: inv.failedReason || 'The payment was cancelled or failed.', updatedAt: now } },
      { returnDocument: 'after' });
  }
  return order; // PENDING / PROCESSING: nothing to change yet
}

/* ------------------------------ App setup --------------------------- */
const app = express();
app.set('trust proxy', 1);          // Render sits behind one proxy
app.set('etag', 'weak');

app.use((req, res, next) => {       // request id + access log
  req.id = crypto.randomUUID().slice(0, 8);
  res.setHeader('X-Request-Id', req.id);
  const t0 = process.hrtime.bigint();
  res.on('finish', () => {
    if (req.path === '/health') return;
    log('info', 'req', { id: req.id, method: req.method, path: req.path, status: res.statusCode, ms: Number((process.hrtime.bigint() - t0) / 1000000n) });
  });
  next();
});
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(compression());

const originAllowed = o => !o || ANY_ORIGIN || CFG.ALLOWED_ORIGINS.includes(String(o).toLowerCase());
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const ok = originAllowed(origin);
  res.setHeader('Vary', 'Origin');
  const isHealth = req.path === '/health' || req.path === '/healthz';
  if (origin && (ok || isHealth)) res.setHeader('Access-Control-Allow-Origin', ok ? origin : '*');
  if (!ok && !isHealth) return res.status(403).json({ error: 'This website is not allowed to use this server.' });
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,Idempotency-Key');
    res.setHeader('Access-Control-Max-Age', '86400');
    return res.sendStatus(204);
  }
  next();
});

const limiter = (windowMs, limit, extra = {}) => rateLimit({
  windowMs, limit, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down and try again shortly.' }, ...extra
});
const apiLimiter = limiter(60000, 300);
const orderLimiter = limiter(10 * 60000, 30);
const stkLimiter = limiter(5 * 60000, 15);
const statusLimiter = limiter(60000, 120);
const webhookLimiter = limiter(60000, 300);
const adminLimiter = limiter(60000, 300);
const authFailLimiter = limiter(15 * 60000, 20, {
  requestWasSuccessful: (req, res) => res.statusCode !== 401,
  message: { error: 'Too many failed sign-in attempts. Please try again in 15 minutes.' }
});

const json = express.json({ limit: '64kb' });
const jsonBig = express.json({ limit: '2mb' });   // product photos

/* -------------------------------- Health ---------------------------- */
app.get('/', (req, res) => res.json({ service: 'golden-harvest-api', ok: true }));
app.get(['/health', '/healthz'], ah(async (req, res) => {
  const database = await dbPing();
  res.set('Cache-Control', 'no-store').json({
    ok: true, db: database, intasend: IS.configured, sandbox: CFG.INTASEND_TEST,
    adminConfigured: !!(CFG.ADMIN_USERNAME && CFG.ADMIN_PASSWORD),
    originAllowed: originAllowed(req.headers.origin),
    allowedOrigins: ANY_ORIGIN ? 'ANY' : CFG.ALLOWED_ORIGINS,
    uptime: Math.round(process.uptime())
  });
}));

/* ---------------------------- Public: catalogue --------------------- */
const baseUrl = req => CFG.PUBLIC_URL || `${req.protocol}://${req.get('host')}`;

app.get('/api/products', apiLimiter, requireDb(), ah(async (req, res) => {
  const list = await col.products.find({}, { projection: { imageData: 0 } }).sort({ category: 1, name: 1 }).toArray();
  // imageData is excluded for speed, so flag its presence via imageVer.
  const base = baseUrl(req);
  const products = list.map(p => {
    const s = serProduct({ ...p, imageData: null }, { base });
    if (p.imageVer) s.image = `${base}/api/products/${p._id}/image?v=${p.imageVer}`;
    return s;
  });
  res.set('Cache-Control', 'no-cache').json({ products });
}));

app.get('/api/products/:id/image', apiLimiter, requireDb(), ah(async (req, res) => {
  if (!isObjectId(req.params.id)) throw new HttpError(404, 'Not found.');
  const p = await col.products.findOne({ _id: new ObjectId(req.params.id) }, { projection: { imageData: 1, imageMime: 1, imageVer: 1 } });
  if (!p?.imageData) throw new HttpError(404, 'Not found.');
  const etag = `"${p.imageVer}"`;
  res.set({ 'Cache-Control': 'public, max-age=604800', ETag: etag, 'Content-Type': p.imageMime });
  if (req.headers['if-none-match'] === etag) return res.sendStatus(304);
  res.send(toBuf(p.imageData));
}));

/* ------------------------------ Public: orders ---------------------- */
app.post('/api/orders', orderLimiter, json, requireDb(), ah(async (req, res) => {
  const customer = cleanCustomer(req.body?.customer);
  const items = cleanItems(req.body?.items);
  const key = req.get('Idempotency-Key') || '';
  if (key && !/^[A-Za-z0-9_\-:.]{8,100}$/.test(key)) throw bad('Invalid Idempotency-Key.');
  const requestHash = crypto.createHash('sha256').update(JSON.stringify(stable({ customer, items }))).digest('hex');

  const replay = async () => {
    const ex = await col.orders.findOne({ idempotencyKey: key });
    if (!ex) return null;
    if (ex.requestHash !== requestHash) throw new HttpError(422, 'This request was already used with different order details.');
    return res.status(200).json(orderSummary(ex));
  };
  if (key && (await replay())) return;

  const ids = [...new Set(items.map(i => i.productId))].map(id => new ObjectId(id));
  const products = await col.products.find({ _id: { $in: ids } }, { projection: { imageData: 0 } }).toArray();
  const byId = new Map(products.map(p => [String(p._id), p]));
  const lines = items.map(i => {
    const p = byId.get(i.productId);
    if (!p) throw bad('One of the items in your cart is no longer available.');
    if (p.inStock === false) throw bad(`${p.name} is out of stock.`);
    return priceLine(p, i);
  });
  const total = round2(lines.reduce((s, l) => s + l.lineTotal, 0));
  if (total < 1) throw bad('The order total must be at least KSh 1.');

  const now = new Date();
  for (let attempt = 0; attempt < 5; attempt++) {
    const doc = {
      _id: crypto.randomBytes(16).toString('hex'), reference: newReference(),
      customer, items: lines, total,
      paymentStatus: 'pending', adminConfirmed: false, needsReview: false,
      requestHash, invoiceIds: [], paidInvoices: [], currentInvoiceId: null, stkSentAt: null, lastCheckAt: null,
      createdAt: now, updatedAt: now
    };
    if (key) doc.idempotencyKey = key;
    try {
      await col.orders.insertOne(doc);
      log('info', 'order created', { order: doc.reference, total });
      return res.status(201).json(orderSummary(doc));
    } catch (e) {
      if (e.code !== 11000) throw e;
      if (e.keyPattern?.idempotencyKey && (await replay())) return;
      // else: reference collision, loop and try a new reference
    }
  }
  throw new HttpError(500, 'Could not place the order. Please try again.');
}));

app.post('/api/intasend/stkpush', stkLimiter, json, requireDb(502), ah(async (req, res) => {
  if (!IS.configured) throw new HttpError(503, 'Payments are not configured on this server.');
  const orderId = String(req.body?.orderId || '');
  const phone = normPhone(req.body?.phone);
  if (!isOrderId(orderId)) throw bad('Invalid order.');
  if (!phone) throw bad('Enter a valid Safaricom number, e.g. 0712 345 678.');

  const now = new Date();
  const order = await col.orders.findOneAndUpdate(
    { _id: orderId, paymentStatus: { $in: ['pending', 'failed'] }, $or: [{ stkSentAt: null }, { stkSentAt: { $lt: new Date(now.getTime() - CFG.STK_COOLDOWN_MS) } }] },
    { $set: { paymentStatus: 'pending', stkSentAt: now, payPhone: phone, failedCode: null, paymentMessage: null, lastCheckAt: null, updatedAt: now } },
    { returnDocument: 'after' });
  if (!order) {
    const cur = await col.orders.findOne({ _id: orderId }, { projection: { paymentStatus: 1 } });
    if (!cur) throw new HttpError(404, 'Order not found.');
    if (cur.paymentStatus === 'paid') throw new HttpError(409, 'This order has already been paid.');
    if (cur.paymentStatus === 'cancelled') throw new HttpError(409, 'This order was cancelled. Please place a new order.');
    throw new HttpError(429, 'An M-Pesa prompt was just sent. Please wait a moment before trying again.');
  }

  try {
    const data = await intasend('/api/v1/payment/mpesa-stk-push/', {
      public_key: CFG.INTASEND_PUBLISHABLE_KEY,
      amount: order.total,
      phone_number: phone,
      api_ref: order._id,
      narrative: `Golden Harvest ${order.reference}`.slice(0, 60),
      first_name: order.customer.name.split(' ')[0].slice(0, 40)
    }, { timeout: 30000 });                               // never auto-retried: could double-prompt
    const invoiceId = normInvoice(data).id;
    if (!invoiceId) throw new UpstreamError('No invoice id returned', 502);
    await col.orders.updateOne({ _id: order._id }, { $set: { currentInvoiceId: invoiceId, updatedAt: new Date() }, $addToSet: { invoiceIds: invoiceId } });
    res.json({ ok: true });
  } catch (e) {
    await col.orders.updateOne({ _id: order._id, paymentStatus: 'pending' }, { $set: { stkSentAt: null } }).catch(() => {});
    log('error', 'stk push failed', { order: order.reference, status: e.status, detail: e.detail, err: e.message });
    throw new HttpError(502, `Couldn't send the M-Pesa prompt${e.detail ? ': ' + e.detail : ''}. Please check the phone number and try again.`);
  }
}));

app.get('/api/orders/:id/status', statusLimiter, requireDb(), ah(async (req, res) => {
  const id = String(req.params.id);
  if (!isOrderId(id)) throw new HttpError(404, 'Order not found.');
  let order = await col.orders.findOne({ _id: id });
  if (!order) throw new HttpError(404, 'Order not found.');

  // Don't wait for the webhook: ask IntaSend directly (throttled, one caller wins the claim).
  if (IS.configured && order.paymentStatus === 'pending' && order.currentInvoiceId) {
    const claim = await col.orders.updateOne(
      { _id: id, paymentStatus: 'pending', $or: [{ lastCheckAt: null }, { lastCheckAt: { $lt: new Date(Date.now() - CFG.STATUS_CHECK_MS) } }] },
      { $set: { lastCheckAt: new Date() } });
    if (claim.modifiedCount) {
      try {
        order = (await applyInvoice(await checkInvoice(order.currentInvoiceId))) || order;
      } catch (e) { log('warn', 'status lookup failed', { order: order.reference, err: e.message }); }
    }
  }

  const paid = order.paymentStatus === 'paid';
  res.set('Cache-Control', 'no-store').json({
    orderId: order._id, reference: order.reference, total: order.total,
    paymentStatus: order.paymentStatus, status: order.paymentStatus,
    adminConfirmed: !!order.adminConfirmed,
    mpesaReceipt: paid ? order.intasendReceipt : undefined,
    receipt: paid ? order.intasendReceipt : undefined,
    intasendReceipt: paid ? order.intasendReceipt : undefined,
    providerRef: paid ? order.providerRef : undefined,
    message: order.paymentStatus === 'failed' ? order.paymentMessage || 'The payment failed.' : undefined,
    failed_code: order.paymentStatus === 'failed' ? order.failedCode : undefined,
    failedCode: order.paymentStatus === 'failed' ? order.failedCode : undefined
  });
}));

/* IntaSend webhook: authenticate with the challenge, then VERIFY with IntaSend
   before trusting anything in the body. Non-2xx makes IntaSend retry. */
app.post('/api/intasend/webhook', webhookLimiter, json, requireDb(), ah(async (req, res) => {
  if (!IS.configured) throw new HttpError(503, 'Payments are not configured.');
  const b = req.body || {};
  if (!safeEq(b.challenge ?? '', CFG.INTASEND_WEBHOOK_CHALLENGE)) throw new HttpError(401, 'Invalid challenge.');
  const invoiceId = String(b.invoice_id || '');
  if (!invoiceId) return res.json({ ok: true, ignored: true });
  col.events.insertOne({ invoiceId, state: String(b.state || ''), apiRef: String(b.api_ref || ''), receivedAt: new Date() }).catch(() => {});
  let inv;
  try { inv = await checkInvoice(invoiceId); }
  catch (e) { throw new HttpError(502, 'Could not verify the payment yet.'); }
  await applyInvoice(inv);
  res.json({ ok: true });
}));

/* ------------------------------ Admin ------------------------------- */
function adminAuth(req, res, next) {
  if (!CFG.ADMIN_USERNAME || !CFG.ADMIN_PASSWORD) return next(new HttpError(503, 'Admin login is not configured on this server.'));
  const h = req.headers.authorization || '';
  let u = '', p = '';
  if (/^Basic /i.test(h)) {
    const raw = Buffer.from(h.slice(6).trim(), 'base64').toString('utf8');
    const i = raw.indexOf(':');
    if (i >= 0) { u = raw.slice(0, i); p = raw.slice(i + 1); }
  }
  const ok = safeEq(u, CFG.ADMIN_USERNAME) & safeEq(p, CFG.ADMIN_PASSWORD);   // no short-circuit
  if (!ok) return next(new HttpError(401, 'Wrong username or password.'));
  req.admin = u;
  res.set('Cache-Control', 'no-store');
  next();
}

const admin = express.Router();
admin.use(authFailLimiter, adminAuth, adminLimiter, requireDb());

const FILTERS = {
  all: {}, paid: { paymentStatus: 'paid', adminConfirmed: { $ne: true } }, released: { adminConfirmed: true },
  pending: { paymentStatus: { $in: ['pending', 'failed'] } }, cancelled: { paymentStatus: 'cancelled' }, review: { needsReview: true }
};
const orderIdParam = req => {
  const id = String(req.params.id);
  if (!isOrderId(id)) throw new HttpError(404, 'Order not found.');
  return id;
};
const productIdParam = req => {
  if (!isObjectId(req.params.id)) throw new HttpError(404, 'Product not found.');
  return new ObjectId(req.params.id);
};

admin.get('/orders', ah(async (req, res) => {
  const filter = FILTERS[String(req.query.status || 'all')] || {};
  const limit = Math.min(Math.max(int(req.query.limit, 500), 1), 1000);
  const orders = await col.orders.find(filter).sort({ createdAt: -1 }).limit(limit).toArray();
  res.json({ orders: orders.map(serOrder) });
}));

admin.post('/orders/:id/confirm', ah(async (req, res) => {
  const id = orderIdParam(req), now = new Date();
  const o = await col.orders.findOneAndUpdate(
    { _id: id, paymentStatus: 'paid', adminConfirmed: { $ne: true } },
    { $set: { adminConfirmed: true, confirmedAt: now, confirmedBy: req.admin, needsReview: false, updatedAt: now } },
    { returnDocument: 'after' });
  if (!o) {
    const cur = await col.orders.findOne({ _id: id }, { projection: { adminConfirmed: 1, paymentStatus: 1 } });
    if (!cur) throw new HttpError(404, 'Order not found.');
    if (cur.adminConfirmed) throw new HttpError(409, 'This order was already released.');
    throw new HttpError(409, 'No payment has been received for this order yet.');
  }
  audit(req.admin, 'order.confirm', o.reference);
  res.json({ order: serOrder(o) });
}));

admin.post('/orders/:id/reject', ah(async (req, res) => {
  const id = orderIdParam(req), now = new Date();
  const prev = await col.orders.findOneAndUpdate(
    { _id: id, adminConfirmed: { $ne: true }, paymentStatus: { $ne: 'cancelled' } },
    { $set: { paymentStatus: 'cancelled', cancelledAt: now, cancelledBy: req.admin, updatedAt: now } },
    { returnDocument: 'before' });
  if (!prev) {
    const cur = await col.orders.findOne({ _id: id }, { projection: { adminConfirmed: 1 } });
    if (!cur) throw new HttpError(404, 'Order not found.');
    throw new HttpError(409, cur.adminConfirmed ? 'Released orders cannot be cancelled.' : 'This order is already cancelled.');
  }
  audit(req.admin, 'order.cancel', prev.reference, { wasPaymentStatus: prev.paymentStatus });
  res.json({ ok: true });
}));

admin.post('/orders/:id/resolve-review', ah(async (req, res) => {
  const id = orderIdParam(req);
  const r = await col.orders.updateOne({ _id: id }, { $set: { needsReview: false, updatedAt: new Date() } });
  if (!r.matchedCount) throw new HttpError(404, 'Order not found.');
  audit(req.admin, 'order.resolveReview', id);
  res.json({ ok: true });
}));

admin.delete('/orders/:id', ah(async (req, res) => {
  const id = orderIdParam(req);
  const o = await col.orders.findOne({ _id: id });
  if (!o) throw new HttpError(404, 'Order not found.');
  if (o.adminConfirmed || !['cancelled', 'failed'].includes(o.paymentStatus)) throw new HttpError(409, 'Only cancelled or failed orders can be deleted.');
  if (o.needsReview || o.paidAt || (o.paidInvoices || []).length) throw new HttpError(409, 'Money was received for this order, so it must be kept for your records.');
  await col.orders.deleteOne({ _id: id, paymentStatus: o.paymentStatus });
  audit(req.admin, 'order.delete', o.reference);
  res.json({ ok: true });
}));

admin.get('/products', ah(async (req, res) => {
  const list = await col.products.find({}).sort({ category: 1, name: 1 }).toArray();
  res.json({ products: list.map(p => serProduct(p, { admin: true })) });
}));

admin.post('/products', jsonBig, ah(async (req, res) => {
  const doc = cleanProduct(req.body);
  doc.createdAt = doc.updatedAt;
  const r = await col.products.insertOne(doc);
  audit(req.admin, 'product.create', r.insertedId, { name: doc.name });
  res.status(201).json({ product: serProduct({ ...doc, _id: r.insertedId }, { admin: true }) });
}));

admin.put('/products/:id', jsonBig, ah(async (req, res) => {
  const _id = productIdParam(req);
  const existing = await col.products.findOne({ _id });
  if (!existing) throw new HttpError(404, 'Product not found.');
  const doc = cleanProduct(req.body, existing);
  const p = await col.products.findOneAndUpdate({ _id }, { $set: doc }, { returnDocument: 'after' });
  audit(req.admin, 'product.update', _id, { name: doc.name });
  res.json({ product: serProduct(p, { admin: true }) });
}));

admin.delete('/products/:id', ah(async (req, res) => {
  const _id = productIdParam(req);
  const r = await col.products.findOneAndDelete({ _id }, { projection: { name: 1 } });
  if (!r) throw new HttpError(404, 'Product not found.');
  audit(req.admin, 'product.delete', _id, { name: r.name });
  res.json({ ok: true });
}));

app.use('/api/admin', admin);

/* ----------------------- 404 + central error handler ---------------- */
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  let status = err.status || err.statusCode || 500;
  let msg = err.expose ? err.message : null;
  if (err.type === 'entity.parse.failed') { status = 400; msg = 'Invalid JSON.'; }
  else if (err.type === 'entity.too.large') { status = 413; msg = 'That request is too large.'; }
  else if (/^Mongo(Server|Network|Topology)/.test(err.name || '')) { status = 503; msg = 'The database is temporarily unavailable. Please try again.'; }
  if (status >= 500) log('error', 'request failed', { id: req.id, path: req.path, err: err.message, stack: CFG.NODE_ENV === 'production' ? undefined : err.stack });
  res.status(status).json({ error: msg || (status >= 500 ? 'Something went wrong on the server. Please try again.' : 'Request failed.'), requestId: req.id });
});

/* ------------------------------ Reconciler -------------------------- */
let reconciling = false;
async function reconcile() {
  if (reconciling || !dbReady || !IS.configured) return;
  reconciling = true;
  try {
    const now = Date.now();
    const list = await col.orders.find({
      paymentStatus: 'pending', currentInvoiceId: { $ne: null },
      stkSentAt: { $gte: new Date(now - 48 * 3600e3), $lt: new Date(now - 45000) }
    }).limit(20).toArray();
    for (const o of list) {
      try { await applyInvoice(await checkInvoice(o.currentInvoiceId)); }
      catch (e) { log('warn', 'reconcile lookup failed', { order: o.reference, err: e.message }); }
    }
  } catch (e) { log('error', 'reconcile failed', { err: e.message }); }
  finally { reconciling = false; }
}

/* -------------------------------- Boot ------------------------------ */
if (!CFG.MONGODB_URI) { log('error', 'MONGODB_URI is not set'); process.exit(1); }
if (!CFG.ADMIN_USERNAME || !CFG.ADMIN_PASSWORD) log('warn', 'ADMIN_USERNAME / ADMIN_PASSWORD not set: admin login is disabled');
else if (CFG.ADMIN_PASSWORD.length < 10) log('warn', 'ADMIN_PASSWORD is short; use at least 12 characters');
if (!IS.configured) log('warn', 'IntaSend not fully configured (need INTASEND_PUBLISHABLE_KEY, INTASEND_SECRET_KEY, INTASEND_WEBHOOK_CHALLENGE)');
if (ANY_ORIGIN) log('warn', 'ALLOWED_ORIGINS is empty: any website may call this API. Set it to your storefront/admin origins.');

const server = app.listen(CFG.PORT, '0.0.0.0', () => {
  log('info', 'server listening', { port: CFG.PORT, sandbox: CFG.INTASEND_TEST, webhook: CFG.PUBLIC_URL ? `${CFG.PUBLIC_URL}/api/intasend/webhook` : '(set PUBLIC_URL)' });
});
server.keepAliveTimeout = 65000;   // longer than the load balancer's idle timeout
server.headersTimeout = 66000;
server.requestTimeout = 60000;

connectDb();
const reconTimer = setInterval(reconcile, CFG.RECONCILE_MS);
reconTimer.unref();

async function shutdown(sig) {
  if (shuttingDown) return;
  shuttingDown = true;
  log('info', 'shutting down', { sig });
  clearInterval(reconTimer);
  const force = setTimeout(() => process.exit(1), 10000); force.unref();
  server.close(async () => {
    try { await client?.close(); } catch { /* ignore */ }
    process.exit(0);
  });
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', e => log('error', 'unhandledRejection', { err: String(e?.message || e) }));
process.on('uncaughtException', e => { log('error', 'uncaughtException', { err: e.message, stack: e.stack }); shutdown('uncaughtException'); });
