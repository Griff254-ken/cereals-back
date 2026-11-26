'use strict';
/* =====================================================================
   Golden Harvest Cereals — backend
   Express + MongoDB Atlas (mongoose) + IntaSend (M-Pesa STK Push)
   Requires Node 18+.
   ===================================================================== */
require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const env = process.env;
const PORT = Number(env.PORT) || 3000;

const INTASEND = {
  env: (env.INTASEND_ENV || 'sandbox').toLowerCase() === 'production' ? 'production' : 'sandbox',
  pubKey: (env.INTASEND_PUBLISHABLE_KEY || '').trim(),
  secretKey: (env.INTASEND_SECRET_KEY || '').trim(),
  webhookChallenge: (env.INTASEND_WEBHOOK_CHALLENGE || '').trim(),
  publicUrl: (env.PUBLIC_URL || '').trim().replace(/\/+$/, '')
};
INTASEND.base = INTASEND.env === 'production' ? 'https://payment.intasend.com' : 'https://sandbox.intasend.com';
const intasendReady = () =>
  !!(INTASEND.pubKey && INTASEND.secretKey && INTASEND.publicUrl && INTASEND.webhookChallenge);

/* ---------------- Helpers ---------------- */
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const ah = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const sha256 = s => crypto.createHash('sha256').update(s).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha256(String(a)), sha256(String(b)));
const str = (v, max) => String(v ?? '').trim().slice(0, max);
const isObjectId = v => typeof v === 'string' && /^[a-f\d]{24}$/i.test(v);

function normPhone(v) {
  v = String(v || '').replace(/[\s\-+()]/g, '');
  if (/^0[17]\d{8}$/.test(v)) return '254' + v.slice(1);
  if (/^254[17]\d{8}$/.test(v)) return v;
  if (/^[17]\d{8}$/.test(v)) return '254' + v;
  return null;
}

const REF_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function newReference() {
  let r = 'GH-';
  for (let i = 0; i < 8; i++) r += REF_CHARS[crypto.randomInt(REF_CHARS.length)];
  return r;
}

/* ---------------- Models ---------------- */
const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 120 },
  category: { type: String, default: 'Other', trim: true, maxlength: 60 },
  emoji: { type: String, default: '🌾', maxlength: 16 },
  unit: { type: String, required: true, trim: true, maxlength: 40 },
  price: { type: Number, required: true, min: 0 },
  description: { type: String, default: '', maxlength: 1000 },
  gradient: { type: [String], default: ['#c9a24a', '#7a5c1a'] },
  image: { type: String, default: '' },
  inStock: { type: Boolean, default: true },
  specs: { type: [[String]], default: [] },
  options: {
    type: [{
      _id: false,
      key: { type: String, required: true },
      choices: [{ _id: false, value: { type: String, required: true }, priceAdjust: { type: Number, default: 0 } }]
    }],
    default: []
  }
}, { timestamps: true });

const OrderSchema = new mongoose.Schema({
  id: { type: String, default: () => crypto.randomUUID(), unique: true },
  reference: { type: String, unique: true },
  idempotencyKey: { type: String },
  requestHash: String,
  customer: { name: String, phone: String, location: String },
  items: [{
    _id: false,
    productId: String,
    name: String,
    quantity: Number,
    unitPrice: Number,
    lineTotal: Number,
    options: [{ _id: false, key: String, value: String }],
    note: { type: String, default: '' }
  }],
  total: { type: Number, required: true },
  paymentStatus: { type: String, enum: ['pending', 'paid', 'failed', 'cancelled'], default: 'pending', index: true },
  paymentMessage: { type: String, default: '' },
  failedCode: { type: Number, default: null },
  adminConfirmed: { type: Boolean, default: false },
  confirmedAt: Date,
  confirmedBy: String,
  cancelledAt: Date,
  paidAt: Date,
  paidVia: String,
  mpesaReceipt: { type: String, default: '' },
  intasendReceipt: { type: String, default: '' },
  providerRef: { type: String, default: '' },
  intasendTrackingId: { type: String, default: '' },
  payerPhone: String,
  stkRequestedAt: { type: Date, default: null },
  stkAttempts: { type: Number, default: 0 },
  lastQueryAt: { type: Date, default: null },
  checkoutRequestId: String,
  checkoutRequestIds: { type: [String], index: true },
  invoiceId: String,
  needsReview: { type: Boolean, default: false },
  reviewNote: String
}, { timestamps: true });
OrderSchema.index({ idempotencyKey: 1 }, { unique: true, partialFilterExpression: { idempotencyKey: { $type: 'string' } } });
OrderSchema.index({ createdAt: -1 });

const PREFIX = (env.COLLECTION_PREFIX || '').trim();
const Product = mongoose.model('Product', ProductSchema, PREFIX + 'products');
const Order = mongoose.model('Order', OrderSchema, PREFIX + 'orders');

/* ---------------- Mappers ---------------- */
const productOut = p => ({
  id: String(p._id),
  name: p.name,
  category: p.category,
  emoji: p.emoji,
  unit: p.unit,
  price: p.price,
  description: p.description,
  gradient: p.gradient,
  image: p.image,
  inStock: p.inStock,
  specs: p.specs || [],
  options: (p.options || []).map(o => ({
    key: o.key,
    choices: (o.choices || []).map(c => ({ value: c.value, priceAdjust: c.priceAdjust || 0 }))
  }))
});

const receiptOf = o => o.intasendReceipt || o.providerRef || o.mpesaReceipt || '';

const orderOut = o => ({
  id: o.id,
  reference: o.reference,
  customer: o.customer,
  items: (o.items || []).map(i => ({
    productId: i.productId,
    name: i.name,
    quantity: i.quantity,
    unitPrice: i.unitPrice,
    lineTotal: i.lineTotal,
    options: Object.fromEntries((i.options || []).map(x => [x.key, x.value])),
    note: i.note || ''
  })),
  total: o.total,
  paymentStatus: o.paymentStatus,
  paymentMessage: o.paymentMessage || '',
  failedCode: o.failedCode ?? null,
  adminConfirmed: !!o.adminConfirmed,
  mpesaReceipt: receiptOf(o),
  intasendReceipt: o.intasendReceipt || o.providerRef || '',
  providerRef: o.providerRef || '',
  needsReview: !!o.needsReview,
  reviewNote: o.reviewNote || '',
  createdAt: o.createdAt,
  paidAt: o.paidAt || null,
  confirmedAt: o.confirmedAt || null
});

/* ---------------- Product validation ---------------- */
function cleanProduct(b) {
  if (!b || typeof b !== 'object') throw new HttpError(400, 'Invalid product data.');
  const name = str(b.name, 120);
  if (!name) throw new HttpError(400, 'Product name is required.');
  const unit = str(b.unit, 40);
  if (!unit) throw new HttpError(400, 'Unit is required.');
  const price = Number(b.price);
  if (b.price === '' || b.price === null || !Number.isFinite(price) || price < 0 || price > 1e9)
    throw new HttpError(400, 'Price must be a number of 0 or more.');

  const image = typeof b.image === 'string' ? b.image.trim() : '';
  if (image) {
    const okData = /^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(image);
    const okUrl = /^https:\/\/\S+$/i.test(image);
    if (!okData && !okUrl) throw new HttpError(400, 'Image must be an uploaded photo or an https link.');
    if (image.length > 2_000_000) throw new HttpError(413, 'That photo is too large. Try a smaller one.');
  }

  const gradient = Array.isArray(b.gradient) && b.gradient.length === 2 &&
    b.gradient.every(c => typeof c === 'string' && /^#[0-9a-f]{3,8}$/i.test(c))
    ? b.gradient : ['#c9a24a', '#7a5c1a'];

  const specs = (Array.isArray(b.specs) ? b.specs : [])
    .filter(Array.isArray)
    .map(s => [str(s[0], 60), str(s[1], 120)])
    .filter(s => s[0] && s[1])
    .slice(0, 30);

  const options = (Array.isArray(b.options) ? b.options : []).slice(0, 10).map(g => ({
    key: str(g && g.key, 60),
    choices: (Array.isArray(g && g.choices) ? g.choices : []).slice(0, 20).map(c => ({
      value: str(c && c.value, 80),
      priceAdjust: Number.isFinite(Number(c && c.priceAdjust)) ? Number(c.priceAdjust) : 0
    })).filter(c => c.value)
  })).filter(g => g.key && g.choices.length);

  const emoji = Array.from(String(b.emoji || '').trim()).slice(0, 4).join('') || '🌾';

  return {
    name, unit, price, emoji,
    category: str(b.category, 60) || 'Other',
    description: str(b.description, 1000),
    inStock: b.inStock !== false && b.inStock !== 'false',
    image, gradient, specs, options
  };
}

/* ---------------- IntaSend API ---------------- */
function authHeaders() {
  return {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    Authorization: `Bearer ${INTASEND.secretKey}`
  };
}

/* POST — used for STK push and status queries. */
async function intasendPost(path, payload, timeoutMs = 25000) {
  const r = await fetch(INTASEND.base + path, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(timeoutMs)
  });
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, data };
}

/* GET — fallback for status queries. Short timeout keeps the storefront poll snappy. */
async function intasendGet(path, timeoutMs = 8000) {
  const r = await fetch(INTASEND.base + path, {
    method: 'GET',
    headers: authHeaders(),
    signal: AbortSignal.timeout(timeoutMs)
  });
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, data };
}

function mapState(s) {
  s = String(s || '').toUpperCase();
  if (['SUCCESS', 'COMPLETE', 'COMPLETED', 'PAID'].includes(s)) return 'paid';
  if (['FAILED', 'CANCELLED', 'CANCELED', 'REVERSED'].includes(s)) return 'failed';
  return 'pending';
}

function intasendError(data) {
  if (!data || typeof data !== 'object') return '';
  if (Array.isArray(data.errors) && data.errors[0]) return data.errors[0].detail || data.errors[0].message || '';
  return data.error || data.message || data.detail || '';
}

async function intasendStkPush(order, phone) {
  const r = await intasendPost('/api/v1/payment/mpesa-stk-push/', {
    public_key: INTASEND.pubKey,
    phone_number: phone,
    amount: Math.ceil(order.total),
    currency: 'KES',
    api_ref: order.reference,
    narrative: `Order ${order.reference}`
  });
  if (!r.ok) {
    const err = new Error(intasendError(r.data) || 'IntaSend rejected the request.');
    err.data = r.data;
    err.status = r.status;
    throw err;
  }
  return r.data;
}

/* IntaSend documents the status check as POST /payment/status/ with { invoice_id }.
   Try that first; if the account/endpoint answers 404/405, fall back to GET. */
async function intasendQuery(invoiceId) {
  if (!invoiceId) return null;
  try {
    const p = await intasendPost('/api/v1/payment/status/', { invoice_id: invoiceId }, 8000);
    if (p.ok) return p.data;
    if (p.status === 404 || p.status === 405) {
      const g = await intasendGet(`/api/v1/payment/status/?invoice_id=${encodeURIComponent(invoiceId)}`);
      if (g.ok) return g.data;
      console.warn('[intasend query] GET fallback failed', g.status, intasendError(g.data));
      return null;
    }
    console.warn('[intasend query] failed', p.status, intasendError(p.data));
    return null;
  } catch (e) {
    console.warn('[intasend query]', e.message);
    return null;
  }
}

/* ---------------- Payment result handling (shared) ---------------- */
async function applyPaymentResult(orderId, r) {
  const order = await Order.findOne({ id: orderId });
  if (!order) return;
  const mapped = mapState(r.state);
  const receipt = r.providerRef || '';

  if (mapped === 'paid') {
    if (order.paymentStatus === 'paid') {
      if (!receiptOf(order) && receipt) {
        await Order.updateOne({ id: order.id }, { $set: { intasendReceipt: receipt, providerRef: receipt, mpesaReceipt: receipt } });
      }
      return;
    }
    if (order.paymentStatus === 'cancelled') {
      await Order.updateOne({ id: order.id }, { $set: {
        intasendReceipt: receipt, providerRef: receipt, mpesaReceipt: receipt,
        paidAt: new Date(), needsReview: true,
        reviewNote: 'Customer paid via IntaSend after the order was cancelled. Refund required.'
      } });
      console.warn('[payment] paid on cancelled order', order.reference, receipt);
      return;
    }
    if (r.value > 0 && r.value + 0.001 < order.total) {
      await Order.updateOne({ id: order.id }, { $set: {
        intasendReceipt: receipt, providerRef: receipt, mpesaReceipt: receipt,
        needsReview: true,
        reviewNote: `Underpayment: received KSh ${r.value}, expected KSh ${order.total}.`
      } });
      console.warn('[payment] amount mismatch', order.reference, r.value, order.total);
      return;
    }
    await Order.updateOne(
      { id: order.id, paymentStatus: { $in: ['pending', 'failed'] } },
      { $set: {
        paymentStatus: 'paid',
        paidAt: new Date(),
        paidVia: r.via || 'intasend',
        intasendReceipt: receipt,
        providerRef: receipt,
        mpesaReceipt: receipt,
        intasendTrackingId: r.trackingId || order.intasendTrackingId || '',
        paymentMessage: '',
        failedCode: null
      } }
    );
    console.log(`[payment] recorded ${order.reference} KSh ${order.total} ref ${receipt || '-'} via ${r.via || 'intasend'}`);
    return;
  }

  if (mapped === 'failed') {
    /* Ignore failures from an older invoice once a newer STK push has been sent. */
    if (r.invoiceId && order.invoiceId && r.invoiceId !== order.invoiceId) return;
    await Order.updateOne(
      { id: order.id, paymentStatus: 'pending' },
      { $set: {
        paymentStatus: 'failed',
        paymentMessage: String(r.failedReason || 'The M-Pesa payment was not completed.'),
        failedCode: Number.isFinite(r.failedCode) ? r.failedCode : null,
        stkRequestedAt: null
      } }
    );
  }
}

/* Webhook body: { invoice_id, state, provider, mpesa_reference, value, api_ref, failed_code, failed_reason, challenge, ... } */
async function processWebhook(body) {
  if (!body || typeof body !== 'object') return;
  const invoiceId = String(body.invoice_id || body.invoice || '');
  const trackingId = String(body.tracking_id || body.intasend_tracking_id || '');
  const apiRef = String(body.api_ref || '');

  const or = [];
  if (invoiceId) or.push({ checkoutRequestIds: invoiceId });
  if (trackingId) or.push({ checkoutRequestIds: trackingId });
  if (apiRef) or.push({ reference: apiRef });
  const order = or.length ? await Order.findOne({ $or: or }) : null;
  if (!order) { console.warn('[intasend webhook] no order for', invoiceId || trackingId || apiRef); return; }

  if (invoiceId || trackingId) {
    await Order.updateOne({ id: order.id }, {
      $addToSet: { checkoutRequestIds: { $each: [invoiceId, trackingId].filter(Boolean) } }
    });
  }

  await applyPaymentResult(order.id, {
    state: body.state,
    providerRef: String(body.mpesa_reference || body.provider_reference || body.providerReference || ''),
    trackingId,
    invoiceId,
    value: Number(body.value || body.amount || 0),
    failedCode: Number(body.failed_code ?? body.failedCode ?? NaN),
    failedReason: body.failed_reason || body.failedReason || body.message || '',
    via: 'intasend-webhook'
  });
}

/* Fallback when the webhook is late or never arrives. First query 4 s after the
   prompt, at most one query per 3.5 s per order. */
async function reconcile(order) {
  if (!intasendReady() || order.paymentStatus !== 'pending' || !order.checkoutRequestId) return;
  const now = Date.now();
  if (!order.stkRequestedAt || now - order.stkRequestedAt.getTime() < 4000) return;
  const claimed = await Order.findOneAndUpdate(
    {
      id: order.id, paymentStatus: 'pending',
      $or: [{ lastQueryAt: null }, { lastQueryAt: { $lt: new Date(now - 3500) } }]
    },
    { $set: { lastQueryAt: new Date() } }, { new: true }
  );
  if (!claimed) return;
  try {
    const data = await intasendQuery(order.checkoutRequestId);
    if (!data) return;
    const inv = data.invoice || data;
    await applyPaymentResult(order.id, {
      state: inv.state || data.state,
      providerRef: String(inv.mpesa_reference || inv.provider_reference || ''),
      invoiceId: String(inv.invoice_id || order.checkoutRequestId),
      value: Number(inv.value || 0),
      failedCode: Number(inv.failed_code ?? NaN),
      failedReason: inv.failed_reason || '',
      via: 'intasend-query'
    });
  } catch (e) { console.warn('[reconcile]', e.message); }
}

/* ---------------- App ---------------- */
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));

const toOrigin = v => {
  v = String(v || '').trim().replace(/^["']|["']$/g, '').trim();
  if (!v) return '';
  if (v === '*' || v === 'null') return v;
  try { return new URL(/^https?:\/\//i.test(v) ? v : 'https://' + v).origin; } catch { return ''; }
};
const allowed = [...new Set((env.ALLOWED_ORIGINS || '').split(',').map(toOrigin).filter(Boolean))];
const allowAll = !allowed.length || allowed.includes('*');
const originAllowed = origin => !origin || allowAll || allowed.includes(toOrigin(origin));

app.get('/health', cors({ origin: true }), (req, res) => res.json({
  status: 'ok',
  db: mongoose.connection.readyState === 1,
  intasend: intasendReady(),
  intasendEnv: INTASEND.env,
  yourOrigin: req.get('Origin') || null,
  originAllowed: originAllowed(req.get('Origin'))
}));

app.use(cors({
  origin: (origin, cb) => {
    if (originAllowed(origin)) return cb(null, true);
    console.warn(`[cors] blocked origin "${origin}". Add it to ALLOWED_ORIGINS (current: ${allowed.join(', ')})`);
    cb(new HttpError(403, `This website (${origin}) is not allowed to use the server. Add it to ALLOWED_ORIGINS.`));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Idempotency-Key'],
  maxAge: 86400
}));

app.use(express.json({ limit: '3mb' }));

const limiter = (windowMs, limit, message) =>
  rateLimit({ windowMs, limit, standardHeaders: true, legacyHeaders: false, message: { error: message } });
const orderLimiter = limiter(60e3, 20, 'Too many orders. Please wait a minute.');
const stkLimiter = limiter(60e3, 10, 'Too many payment requests. Please wait a minute.');
const statusLimiter = limiter(60e3, 60, 'Too many status checks. Please slow down.');
/* IntaSend retries on 5xx. Keep a generous cap so a broken deploy can't self-DDoS. */
const webhookLimiter = limiter(60e3, 300, 'Too many webhook calls.');
const adminLimiter = rateLimit({
  windowMs: 15 * 60e3, limit: 60, skipSuccessfulRequests: true, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many failed attempts. Try again in 15 minutes.' }
});

app.get('/', (req, res) => res.json({ name: 'Golden Harvest Cereals server', ok: true }));

/* ---- Public: products ---- */
app.get('/api/products', ah(async (req, res) => {
  const list = await Product.find().sort({ category: 1, name: 1 }).lean();
  res.json({ products: list.map(productOut) });
}));

/* ---- Public: create order ---- */
app.post('/api/orders', orderLimiter, ah(async (req, res) => {
  const key = req.get('Idempotency-Key') || '';
  if (key.length < 8 || key.length > 100) throw new HttpError(400, 'Missing or invalid Idempotency-Key header.');
  const body = req.body || {};
  const requestHash = sha256(JSON.stringify(body)).toString('hex');

  const summary = o => ({ orderId: o.id, reference: o.reference, total: o.total, paymentStatus: o.paymentStatus });
  const prior = await Order.findOne({ idempotencyKey: key });
  if (prior) {
    if (prior.requestHash !== requestHash) throw new HttpError(422, 'This Idempotency-Key was already used with different data.');
    return res.json(summary(prior));
  }

  const c = body.customer || {};
  const name = str(c.name, 100), location = str(c.location, 200), phone = normPhone(c.phone);
  if (name.length < 2) throw new HttpError(400, 'Please enter your name.');
  if (!phone) throw new HttpError(400, 'Enter a valid Safaricom number, e.g. 0712 345 678.');
  if (location.length < 2) throw new HttpError(400, 'Please enter a delivery location.');

  const rawItems = Array.isArray(body.items) ? body.items : [];
  if (!rawItems.length) throw new HttpError(400, 'Your cart is empty.');
  if (rawItems.length > 50) throw new HttpError(400, 'Too many items in one order.');
  const ids = [...new Set(rawItems.map(i => i && i.productId))];
  if (!ids.every(isObjectId)) throw new HttpError(400, 'One of the products in your cart is no longer available.');
  const prods = await Product.find({ _id: { $in: ids } }).lean();
  const byId = new Map(prods.map(p => [String(p._id), p]));

  const items = [];
  let sum = 0;
  for (const it of rawItems) {
    const p = byId.get(String(it && it.productId));
    if (!p) throw new HttpError(400, 'One of the products in your cart is no longer available.');
    if (!p.inStock) throw new HttpError(400, `${p.name} is currently out of stock.`);

    const q = Number(it.quantity);
    if (!Number.isInteger(q) || q < 1 || q > 100000) throw new HttpError(400, `Invalid quantity for ${p.name}.`);

    const given = it.options && typeof it.options === 'object' && !Array.isArray(it.options) ? it.options : {};
    const chosen = [];
    let adj = 0;
    for (const g of p.options || []) {
      if (!g.choices || !g.choices.length) continue;
      const want = typeof given[g.key] === 'string' ? given[g.key] : g.choices[0].value;
      const ch = g.choices.find(x => x.value === want);
      if (!ch) throw new HttpError(400, `"${want}" is not available for ${g.key} on ${p.name}. Please refresh the page.`);
      chosen.push({ key: g.key, value: ch.value });
      adj += ch.priceAdjust || 0;
    }
    const unitPrice = Math.max(0, p.price + adj);
    const lineTotal = Math.round(unitPrice * q * 100) / 100;
    sum += lineTotal;
    items.push({
      productId: String(p._id), name: p.name, quantity: q, unitPrice, lineTotal,
      options: chosen, note: str(it.note, 200)
    });
  }
  const total = Math.round(sum);
  if (total <= 0) throw new HttpError(400, 'Order total must be greater than zero.');

  let order;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      order = await Order.create({
        reference: newReference(), idempotencyKey: key, requestHash,
        customer: { name, phone, location }, items, total
      });
      break;
    } catch (e) {
      if (e && e.code === 11000) {
        const dup = await Order.findOne({ idempotencyKey: key });
        if (dup) return res.json(summary(dup));
        continue;
      }
      throw e;
    }
  }
  if (!order) throw new HttpError(500, 'Could not create the order. Please try again.');
  res.status(201).json(summary(order));
}));

/* ---- Public: IntaSend STK push ---- */
app.post('/api/intasend/stkpush', stkLimiter, ah(async (req, res) => {
  if (!intasendReady()) throw new HttpError(503, 'IntaSend is not configured on the server yet.');
  const { orderId, phone } = req.body || {};
  if (typeof orderId !== 'string' || orderId.length > 64) throw new HttpError(400, 'Missing order.');

  const existing = await Order.findOne({ id: orderId });
  if (!existing) throw new HttpError(404, 'Order not found.');
  let ph = existing.customer.phone;
  if (phone) {
    ph = normPhone(phone);
    if (!ph) throw new HttpError(400, 'Enter a valid Safaricom number, e.g. 0712 345 678.');
  }

  const cutoff = new Date(Date.now() - 45000);
  const order = await Order.findOneAndUpdate(
    {
      id: orderId, adminConfirmed: false, paymentStatus: { $in: ['pending', 'failed'] },
      $or: [{ stkRequestedAt: null }, { stkRequestedAt: { $lt: cutoff } }]
    },
    { $set: { paymentStatus: 'pending', paymentMessage: '', failedCode: null, stkRequestedAt: new Date(), payerPhone: ph } },
    { new: true }
  );
  if (!order) {
    const o = await Order.findOne({ id: orderId });
    if (!o) throw new HttpError(404, 'Order not found.');
    if (o.adminConfirmed || o.paymentStatus === 'paid') throw new HttpError(409, 'This order has already been paid.');
    if (o.paymentStatus === 'cancelled') throw new HttpError(409, 'This order was cancelled.');
    throw new HttpError(429, 'A payment prompt was just sent. Please wait a moment before trying again.');
  }

  let r;
  try {
    r = await intasendStkPush(order, ph);
  } catch (e) {
    await Order.updateOne({ id: orderId }, { $set: { stkRequestedAt: null } }).catch(() => {});
    console.error('[intasend stkpush]', e.message, JSON.stringify(e.data || {}));
    throw new HttpError(502, e.message || 'Could not reach IntaSend. Please try again.');
  }

  const inv = r.invoice || {};
  const invoiceId = String(inv.invoice_id || r.invoice_id || '');
  const trackingId = String(r.id || r.tracking_id || '');
  const state = String(inv.state || r.state || '');

  await Order.updateOne({ id: orderId }, {
    $set: {
      checkoutRequestId: invoiceId || trackingId,
      invoiceId: invoiceId || trackingId,
      intasendTrackingId: trackingId
    },
    $addToSet: { checkoutRequestIds: { $each: [invoiceId, trackingId].filter(Boolean) } },
    $inc: { stkAttempts: 1 }
  });

  if (mapState(state) === 'paid') {
    await applyPaymentResult(orderId, {
      state, providerRef: String(inv.mpesa_reference || ''), trackingId, invoiceId,
      value: Number(inv.value || 0), via: 'intasend-stk'
    });
  }

  res.json({
    ok: true,
    message: 'Prompt sent. Enter your M-Pesa PIN on your phone.',
    checkoutRequestId: invoiceId || trackingId
  });
}));

/* ---- IntaSend webhook ---- */
function verifyIntasendWebhook(req) {
  const secret = INTASEND.webhookChallenge;
  if (!secret) return false;
  const candidates = [req.params.secret, req.body && req.body.challenge, req.body && req.body.secret]
    .filter(v => typeof v === 'string' && v);
  return candidates.some(v => safeEq(v, secret));
}

const webhookHandler = ah(async (req, res) => {
  if (!verifyIntasendWebhook(req)) {
    console.warn('[intasend webhook] challenge mismatch');
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  try { await processWebhook(req.body); }
  catch (e) {
    console.error('[intasend webhook]', e);
    return res.status(500).json({ error: 'Processing failed.' });
  }
  res.json({ ok: true });
});
app.post(['/api/intasend/webhook', '/api/intasend/webhook/:secret'], webhookLimiter, webhookHandler);

/* ---- Public: order status (polled by the storefront) ---- */
app.get('/api/orders/:id/status', statusLimiter, ah(async (req, res) => {
  const id = req.params.id;
  if (typeof id !== 'string' || id.length > 64) throw new HttpError(404, 'Order not found.');
  let o = await Order.findOne({ id });
  if (!o) throw new HttpError(404, 'Order not found.');
  if (o.paymentStatus === 'pending') {
    await reconcile(o);
    o = await Order.findOne({ id });
    if (!o) throw new HttpError(404, 'Order not found.');
  }
  const paid = o.paymentStatus === 'paid';
  res.json({
    orderId: o.id,
    reference: o.reference,
    paymentStatus: o.paymentStatus,
    adminConfirmed: !!o.adminConfirmed,
    mpesaReceipt: paid ? receiptOf(o) : '',
    intasendReceipt: paid ? (o.intasendReceipt || o.providerRef || '') : '',
    message: o.paymentMessage || '',
    failed_code: o.failedCode ?? null
  });
}));

/* ---- Admin auth ---- */
function adminAuth(req, res, next) {
  const user = (env.ADMIN_USERNAME || '').trim(), pass = (env.ADMIN_PASSWORD || '').trim();
  if (!user || !pass) return next(new HttpError(503, 'Admin login is not configured on the server.'));
  const h = req.get('Authorization') || '';
  if (!h.startsWith('Basic ')) return next(new HttpError(401, 'Authentication required.'));
  let decoded = '';
  try { decoded = Buffer.from(h.slice(6), 'base64').toString('utf8'); } catch { /* ignore */ }
  const i = decoded.indexOf(':');
  const u = i < 0 ? '' : decoded.slice(0, i), p = i < 0 ? '' : decoded.slice(i + 1);
  const okU = safeEq(u, user), okP = safeEq(p, pass);
  if (!(okU && okP)) return next(new HttpError(401, 'Wrong username or password.'));
  req.admin = u;
  next();
}
app.use('/api/admin', adminLimiter, adminAuth);

/* ---- Admin: products ---- */
app.get('/api/admin/products', ah(async (req, res) => {
  const list = await Product.find().sort({ category: 1, name: 1 }).lean();
  res.json({ products: list.map(productOut) });
}));
app.post('/api/admin/products', ah(async (req, res) => {
  const p = await Product.create(cleanProduct(req.body));
  res.status(201).json({ product: productOut(p.toObject()) });
}));
app.put('/api/admin/products/:id', ah(async (req, res) => {
  if (!isObjectId(req.params.id)) throw new HttpError(404, 'Product not found.');
  const p = await Product.findByIdAndUpdate(req.params.id, { $set: cleanProduct(req.body) }, { new: true, runValidators: true }).lean();
  if (!p) throw new HttpError(404, 'Product not found.');
  res.json({ product: productOut(p) });
}));
app.delete('/api/admin/products/:id', ah(async (req, res) => {
  if (!isObjectId(req.params.id)) throw new HttpError(404, 'Product not found.');
  const r = await Product.deleteOne({ _id: req.params.id });
  if (!r.deletedCount) throw new HttpError(404, 'Product not found.');
  res.json({ ok: true });
}));

/* ---- Admin: orders ---- */
const ORDER_FILTERS = {
  all: {},
  paid: { paymentStatus: 'paid', adminConfirmed: false },
  pending: { paymentStatus: { $in: ['pending', 'failed'] } },
  cancelled: { paymentStatus: 'cancelled' },
  released: { adminConfirmed: true }
};
app.get('/api/admin/orders', ah(async (req, res) => {
  const k = String(req.query.status || 'all');
  const f = Object.hasOwn(ORDER_FILTERS, k) ? ORDER_FILTERS[k] : ORDER_FILTERS.all;
  const list = await Order.find(f).sort({ createdAt: -1 }).limit(500).lean();
  res.json({ orders: list.map(orderOut) });
}));
app.post('/api/admin/orders/:id/confirm', ah(async (req, res) => {
  const o = await Order.findOneAndUpdate(
    { id: req.params.id, paymentStatus: 'paid', adminConfirmed: false },
    { $set: { adminConfirmed: true, confirmedAt: new Date(), confirmedBy: req.admin } },
    { new: true }
  ).lean();
  if (o) return res.json({ order: orderOut(o) });
  const cur = await Order.findOne({ id: req.params.id }).lean();
  if (!cur) throw new HttpError(404, 'Order not found.');
  if (cur.adminConfirmed) throw new HttpError(409, 'This order has already been released.');
  if (cur.paymentStatus === 'cancelled') throw new HttpError(409, 'This order was cancelled.');
  throw new HttpError(409, 'The customer has not paid yet.');
}));
app.post('/api/admin/orders/:id/reject', ah(async (req, res) => {
  const o = await Order.findOneAndUpdate(
    { id: req.params.id, adminConfirmed: false, paymentStatus: { $ne: 'cancelled' } },
    { $set: { paymentStatus: 'cancelled', cancelledAt: new Date(), paymentMessage: 'This order was cancelled by the store.' } },
    { new: true }
  ).lean();
  if (o) {
    /* The customer already paid: flag it so the refund is not forgotten. */
    if (o.paidAt) {
      o.needsReview = true;
      o.reviewNote = 'Order was cancelled after the customer paid. Refund required.';
      await Order.updateOne({ id: o.id }, { $set: { needsReview: true, reviewNote: o.reviewNote } });
    }
    return res.json({ order: orderOut(o) });
  }
  const cur = await Order.findOne({ id: req.params.id }).lean();
  if (!cur) throw new HttpError(404, 'Order not found.');
  if (cur.adminConfirmed) throw new HttpError(409, 'This order has already been released and cannot be cancelled.');
  throw new HttpError(409, 'This order is already cancelled.');
}));
app.delete('/api/admin/orders/:id', ah(async (req, res) => {
  const cur = await Order.findOne({ id: req.params.id }).lean();
  if (!cur) throw new HttpError(404, 'Order not found.');
  if (cur.adminConfirmed) throw new HttpError(409, 'Released orders cannot be deleted. They are kept as a record.');
  if (cur.paymentStatus === 'paid') throw new HttpError(409, 'Paid orders cannot be deleted. Cancel (and refund) the order first.');
  await Order.deleteOne({ id: req.params.id });
  res.json({ ok: true });
}));

/* ---- 404 + errors ---- */
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON.' });
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'The request is too large.' });
  if (err && (err.name === 'ValidationError' || err.name === 'CastError')) return res.status(400).json({ error: err.message });
  console.error('[error]', err);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

/* ---------------- Start ---------------- */
const SAMPLE = [
  { name: 'Pishori Rice', category: 'Rice', emoji: '🍚', unit: 'per kg', price: 220,
    description: 'Aromatic, clean-milled Pishori rice. Cooks fluffy and fragrant.',
    specs: [['Origin', 'Mwea'], ['Grade', 'Premium']],
    options: [{ key: 'Pack size', choices: [{ value: '1 kg', priceAdjust: 0 }, { value: '2 kg', priceAdjust: 0 }, { value: '5 kg', priceAdjust: 0 }] }] },
  { name: 'Dry Maize (Grain)', category: 'Maize', emoji: '🌽', unit: 'per kg', price: 70,
    description: 'Clean, sorted dry maize grain for posho, githeri or milling.',
    specs: [['Moisture', '13% max']], options: [] },
  { name: 'Finger Millet', category: 'Millet', emoji: '🌾', unit: 'per kg', price: 150,
    description: 'Nutritious finger millet, perfect for porridge and ugali.', specs: [['Type', 'Wimbi']], options: [] },
  { name: 'Wheat Grain', category: 'Wheat', emoji: '🌾', unit: 'per kg', price: 90,
    description: 'Cleaned wheat grain, ready for milling or cooking.', specs: [], options: [] }
];

async function main() {
  if (!env.MONGODB_URI) { console.error('MONGODB_URI is required.'); process.exit(1); }
  if (/^["']|["']$/.test((env.ADMIN_USERNAME || '') + (env.ADMIN_PASSWORD || ''))) console.warn('⚠️  ADMIN_USERNAME/ADMIN_PASSWORD contain quote characters. In Render, enter values WITHOUT quotes.');
  if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD) console.warn('⚠️  ADMIN_USERNAME / ADMIN_PASSWORD not set: admin login is disabled.');
  else if (env.ADMIN_PASSWORD.length < 10) console.warn('⚠️  ADMIN_PASSWORD is short. Use at least 12 characters.');
  if (!intasendReady()) console.warn('⚠️  IntaSend is not fully configured (need INTASEND_PUBLISHABLE_KEY, INTASEND_SECRET_KEY, INTASEND_WEBHOOK_CHALLENGE, PUBLIC_URL). Payments disabled.');
  else {
    console.log(`💳 IntaSend ${INTASEND.env}.`);
    console.log(`   Webhook URL: ${INTASEND.publicUrl}/api/intasend/webhook`);
    console.log(`   Challenge length: ${INTASEND.webhookChallenge.length} chars (must match the dashboard exactly).`);
    if (/\s/.test(INTASEND.webhookChallenge)) console.warn('⚠️  INTASEND_WEBHOOK_CHALLENGE contains whitespace. IntaSend will send a different value — fix the env var.');
    if (/^["']|["']$/.test(INTASEND.webhookChallenge)) console.warn('⚠️  INTASEND_WEBHOOK_CHALLENGE has quote characters. Remove them in Render.');
  }
  console.log('🌐 Allowed origins:', allowAll ? 'ANY' : allowed.join(', '));
  if (!allowed.length) console.warn('⚠️  ALLOWED_ORIGINS is empty: any website can call this API. Set it in production.');

  await mongoose.connect(env.MONGODB_URI, { serverSelectionTimeoutMS: 20000 });
  await Promise.all([Product.init(), Order.init()]);
  console.log('✅ MongoDB connected');

  if (env.SEED_SAMPLE_PRODUCTS === 'true' && (await Product.countDocuments()) === 0) {
    await Product.insertMany(SAMPLE);
    console.log('🌱 Seeded sample products');
  }

  const server = app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server listening on :${PORT} (IntaSend: ${intasendReady() ? INTASEND.env : 'off'})`));
  const stop = () => {
    setTimeout(() => process.exit(0), 10000).unref();
    server.close(() => mongoose.connection.close().then(() => process.exit(0), () => process.exit(1)));
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}
process.on('unhandledRejection', e => console.error('[unhandledRejection]', e));
main().catch(e => { console.error('Failed to start:', e.message); process.exit(1); });
