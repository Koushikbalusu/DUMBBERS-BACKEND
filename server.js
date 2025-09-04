// server.js
// Production-grade gymwear backend: single file, hardened security, rich filters/enums, Razorpay payments/webhooks, admin ops.
// Dependencies: express, mongoose, bcryptjs, jsonwebtoken, express-async-handler, razorpay, crypto, dotenv
// Extra prod deps: helmet, cors, compression, morgan, hpp, express-rate-limit
// npm i express mongoose bcryptjs jsonwebtoken express-async-handler razorpay dotenv helmet cors compression morgan hpp express-rate-limit

'use strict';

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const asyncHandler = require('express-async-handler');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const dotenv = require('dotenv');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const morgan = require('morgan');
const hpp = require('hpp');
const rateLimit = require('express-rate-limit');

dotenv.config();

// ----- Config & Startup -----
const {
  NODE_ENV = 'development',
  PORT = 5000,
  MONGODB_URI = 'mongodb://localhost:27017/gymwear',
  JWT_SECRET = 'change_me',
  CORS_ORIGINS = '', // comma-separated
  TRUST_PROXY = 'true',
  // Razorpay
  RAZORPAY_KEY_ID,
  RAZORPAY_KEY_SECRET,
  RAZORPAY_WEBHOOK_SECRET,
  // Admin seeding
  ADMIN_EMAIL,
  ADMIN_PASSWORD,
  ADMIN_NAME = 'Admin',
  ADMIN_MOBILE = '9000000000',
  // Commerce
  DEFAULT_TAX_PERCENT = '0', // e.g., 12 or 18 for GST if needed
  DEFAULT_SHIP_RUPEES = '0', // fallback shipping
} = process.env;

if (!MONGODB_URI || !JWT_SECRET) {
  console.error('Missing required environment variables (MONGODB_URI, JWT_SECRET)');
  process.exit(1);
}

const app = express();

if (TRUST_PROXY === 'true') app.set('trust proxy', 1);

// Capture raw body only for the Razorpay webhook for HMAC verification
app.use(express.json({
  limit: '1mb',
  verify: (req, res, buf) => {
    if (req.originalUrl === '/api/payments/webhook' && req.method === 'POST') {
      req.rawBody = buf;
    }
  }
}));

// --- Security & Ops middleware ---
app.use(helmet()); // secure headers
app.use(hpp()); // prevent HTTP Parameter Pollution
const origins = (CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors());
app.use(compression());
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));

// Rate limits
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(generalLimiter);

// Global helpers
const ok = (res, message = 'OK', data = {}, status = 200) =>
  res.status(status).json({ success: true, message, data });
const fail = (res, message = 'Error', status = 400, data = {}) =>
  res.status(status).json({ success: false, message, data });

// ----- Enums & Constants -----
const CATEGORY_ENUM = [
  'T_SHIRTS',
  'BOTTOMS',
  'VESTS',
  'COMPRESSION_T_SHIRTS'
];

const SIZE_ENUM = ['XS', 'S', 'M', 'L', 'XL', 'XXL'];
const GENDER_ENUM = ['MEN', 'WOMEN', 'UNISEX'];
const FIT_ENUM = ['SLIM', 'REGULAR', 'RELAXED', 'COMPRESSION'];
const SLEEVE_ENUM = ['SLEEVELESS', 'SHORT', 'LONG'];
const NECK_ENUM = ['CREW', 'V', 'POLO', 'SCOOP'];
const MATERIAL_ENUM = ['COTTON', 'POLYESTER', 'SPANDEX', 'NYLON', 'BLEND'];
const PATTERN_ENUM = ['SOLID', 'GRAPHIC', 'STRIPES', 'CAMOUFLAGE', 'COLORBLOCK', 'MESH'];

// ----- DB Connection -----
mongoose
  .connect(MONGODB_URI, { autoIndex: true })
  .then(async () => {
    console.log('MongoDB connected');
    // Admin seed
    try {
      if (ADMIN_EMAIL && ADMIN_PASSWORD) {
        const existing = await User.findOne({ email: ADMIN_EMAIL.toLowerCase() });
        if (!existing) {
          const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
          const adminUser = await User.create({
            name: ADMIN_NAME,
            email: ADMIN_EMAIL.toLowerCase(),
            mobilenum: ADMIN_MOBILE,
            password: hash,
            role: 'admin',
          });
          console.log(`Seeded admin: ${adminUser.email}`);
        } else {
          console.log(`Admin exists: ${existing.email}`);
        }
      } else {
        console.warn('ADMIN_EMAIL/ADMIN_PASSWORD not set; skipping admin seeding');
      }
    } catch (e) {
      console.error('Admin seeding error:', e.message);
    }
  })
  .catch((err) => {
    console.error('MongoDB connection error', err);
    process.exit(1);
  });

// ----- Schemas & Models -----
const addressSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  line1: { type: String, required: true, trim: true },
  line2: { type: String, trim: true, default: '' },
  city: { type: String, required: true, trim: true },
  state: { type: String, required: true, trim: true },
  pincode: { type: String, required: true, trim: true },
  country: { type: String, default: 'IN' },
  phone: { type: String, required: true, trim: true },
  isDefault: { type: Boolean, default: false },
}, { _id: true });

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    mobilenum: { type: String, required: true },
    password: { type: String, required: true, select: false },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    addresses: { type: [addressSchema], default: [] },
    wishlist: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
  },
  { timestamps: true }
);
userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

const variantSchema = new mongoose.Schema(
  {
    size: { type: String, enum: SIZE_ENUM, required: true },
    color: { type: String, required: true },
    colorCode: { type: String, default: '#000000' },
    sku: { type: String, required: true },
    barcode: { type: String, default: '' },
    mrp: { type: Number, required: true, min: 0 }, // rupees
    price: { type: Number, required: true, min: 0 }, // rupees
    stock: { type: Number, required: true, min: 0 },
    weightGrams: { type: Number, default: 0 },
    dimsCm: {
      l: { type: Number, default: 0 },
      w: { type: Number, default: 0 },
      h: { type: Number, default: 0 },
    },
    images: { type: [String], default: [] },
  },
  { _id: true }
);

const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, index: true },
    slug: { type: String, required: true, unique: true, trim: true },
    description: { type: String, default: '' },
    brand: { type: String, default: 'Generic' },
    gender: { type: String, enum: GENDER_ENUM, default: 'UNISEX', index: true },
    category: { type: String, enum: CATEGORY_ENUM, required: true, index: true },
    tags: { type: [String], default: [] },
    attributes: {
      fit: { type: String, enum: FIT_ENUM, default: 'REGULAR' },
      sleeve: { type: String, enum: SLEEVE_ENUM, default: 'SHORT' },
      neck: { type: String, enum: NECK_ENUM, default: 'CREW' },
      material: { type: String, enum: MATERIAL_ENUM, default: 'BLEND' },
      pattern: { type: String, enum: PATTERN_ENUM, default: 'SOLID' },
      stretch: { type: String, default: 'MEDIUM' }, // LOW|MEDIUM|HIGH
      climate: { type: String, default: 'ALL' }, // HOT|COLD|ALL
      activity: { type: String, default: 'GYM' }, // GYM|RUNNING|YOGA|TRAINING|CASUAL
    },
    images: {
      type: [String],
      validate: {
        validator: (arr) => Array.isArray(arr) && arr.every((u) => /^https?:\/\//i.test(u)),
        message: 'All images must be valid URLs',
      },
      default: [],
    },
    variants: { type: [variantSchema], default: [] },
    ratingAverage: { type: Number, default: 0, min: 0, max: 5 },
    ratingCount: { type: Number, default: 0, min: 0 },
    salesCount: { type: Number, default: 0, min: 0 },
    isActive: { type: Boolean, default: true, index: true },
  },
  { timestamps: true }
);
productSchema.index({ name: 'text', description: 'text', brand: 'text', tags: 'text' });

const reviewSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', index: true, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true, required: true },
  rating: { type: Number, min: 1, max: 5, required: true },
  title: { type: String, default: '' },
  body: { type: String, default: '' },
  approved: { type: Boolean, default: true },
}, { timestamps: true });
reviewSchema.index({ product: 1, user: 1 }, { unique: true });

const cartItemSchema = new mongoose.Schema(
  {
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    variantId: { type: mongoose.Schema.Types.ObjectId, required: true },
    quantity: { type: Number, required: true, min: 1 },
    priceSnapshot: { type: Number, required: true }, // rupees per unit
  },
  { _id: false }
);

const cartSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true, required: true },
    items: { type: [cartItemSchema], default: [] },
  },
  { timestamps: true }
);

const orderItemSchema = new mongoose.Schema(
  {
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    variantId: { type: mongoose.Schema.Types.ObjectId, required: true },
    name: { type: String, required: true },
    size: { type: String, required: true },
    color: { type: String, required: true },
    price: { type: Number, required: true }, // rupees
    quantity: { type: Number, required: true, min: 1 },
  },
  { _id: false }
);

const orderSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    items: { type: [orderItemSchema], default: [] },
    currency: { type: String, default: 'INR' },
    status: {
      type: String,
      enum: ['created', 'payment_pending', 'paid', 'fulfilled', 'cancelled', 'refund_pending', 'refunded', 'failed'],
      default: 'created',
      index: true
    },
    couponCode: { type: String, default: null },
    discountPercent: { type: Number, default: 0 },
    subtotalPaise: { type: Number, required: true }, // paise
    taxPaise: { type: Number, required: true, default: 0 },
    shippingPaise: { type: Number, required: true, default: 0 },
    amountPaise: { type: Number, required: true }, // subtotal - discount + tax + shipping
    razorpayOrderId: { type: String, default: null, index: true },
    razorpayPaymentId: { type: String, default: null },
    razorpaySignature: { type: String, default: null },
    shippingAddress: { type: addressSchema, required: true },
    billingAddress: { type: addressSchema, required: true },
  },
  { timestamps: true }
);

const couponSchema = new mongoose.Schema(
  {
    code: { type: String, required: true, unique: true, uppercase: true },
    discountPercent: { type: Number, required: true, min: 0, max: 100 },
    active: { type: Boolean, default: true },
    startsAt: { type: Date, default: null },
    endsAt: { type: Date, default: null },
    minOrderRupees: { type: Number, default: 0 },
    usageLimitTotal: { type: Number, default: 0 }, // 0 = unlimited
    usageLimitPerUser: { type: Number, default: 0 }, // 0 = unlimited
    usedCount: { type: Number, default: 0 },
    appliesToCategories: { type: [String], default: [] }, // empty = all
    excludesCategories: { type: [String], default: [] },
  },
  { timestamps: true }
);

const inventoryLogSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true, index: true },
  variantId: { type: mongoose.Schema.Types.ObjectId, required: true },
  delta: { type: Number, required: true },
  reason: { type: String, default: 'ADJUSTMENT' }, // ORDER, REFUND, ADJUSTMENT
  note: { type: String, default: '' },
  byUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

const pincodeSchema = new mongoose.Schema({
  pincode: { type: String, unique: true, required: true, index: true },
  codAvailable: { type: Boolean, default: false },
  etaDays: { type: Number, default: 5 },
  shippingRupees: { type: Number, default: Number(DEFAULT_SHIP_RUPEES) || 0 },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const Cart = mongoose.model('Cart', cartSchema);
const Order = mongoose.model('Order', orderSchema);
const Coupon = mongoose.model('Coupon', couponSchema);
const InventoryLog = mongoose.model('InventoryLog', inventoryLogSchema);
const Pincode = mongoose.model('Pincode', pincodeSchema);

// ----- Auth Helpers -----
const signToken = (user) =>
  jwt.sign({ sub: user._id.toString(), role: user.role }, JWT_SECRET, { expiresIn: '7d' });
const auth = asyncHandler(async (req, res, next) => {
  const hdr = req.headers.authorization || '';
  const [, token] = hdr.split(' ');
  if (!hdr.startsWith('Bearer ') || !token) {
    res.setHeader('WWW-Authenticate', 'Bearer realm="api"');
    return fail(res, 'Unauthorized', 401);
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.sub);
    if (!user) return fail(res, 'Unauthorized', 401);
    req.user = user;
    next();
  } catch {
    res.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
    return fail(res, 'Invalid token', 401);
  }
});
const adminOnly = (req, res, next) => {
  if (req.user?.role !== 'admin') return fail(res, 'Forbidden', 403);
  next();
};

// ----- Health -----
app.get('/health', (req, res) => ok(res, 'OK', { uptime: process.uptime(), env: NODE_ENV }));

// ----- Auth -----
app.post('/api/auth/register', authLimiter, asyncHandler(async (req, res) => {
  const { name, email, mobilenum, password } = req.body || {};
  if (!name || !email || !mobilenum || !password) return fail(res, 'Missing fields', 400);
  const exists = await User.findOne({ email: email.toLowerCase() });
  if (exists) return fail(res, 'Email already registered', 400);
  const hash = await bcrypt.hash(password, 10);
  const user = await User.create({ name, email: email.toLowerCase(), mobilenum, password: hash });
  const token = signToken(user);
  return ok(res, 'Registered', { token, user });
}));

app.post('/api/auth/login', authLimiter, asyncHandler(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return fail(res, 'Missing fields', 400);
  const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
  if (!user) return fail(res, 'Invalid credentials', 401);
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return fail(res, 'Invalid credentials', 401);
  const token = signToken(user);
  return ok(res, 'Logged in', { token, user: user.toJSON() });
}));

app.get('/api/auth/profile', auth, asyncHandler(async (req, res) => {
  return ok(res, 'Profile', { user: req.user });
}));

app.put('/api/auth/profile', auth, asyncHandler(async (req, res) => {
  const { name, mobilenum } = req.body || {};
  const update = {};
  if (name) update.name = name;
  if (mobilenum) update.mobilenum = mobilenum;
  const user = await User.findByIdAndUpdate(req.user._id, { $set: update }, { new: true });
  return ok(res, 'Profile updated', { user });
}));

app.post('/api/auth/change-password', auth, asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return fail(res, 'Missing fields', 400);
  const u = await User.findById(req.user._id).select('+password');
  const okPass = await bcrypt.compare(currentPassword, u.password);
  if (!okPass) return fail(res, 'Invalid current password', 400);
  u.password = await bcrypt.hash(newPassword, 10);
  await u.save();
  return ok(res, 'Password changed', {});
}));

// ----- Addresses -----
app.get('/api/user/addresses', auth, asyncHandler(async (req, res) => {
  const u = await User.findById(req.user._id);
  return ok(res, 'Addresses', { addresses: u.addresses || [] });
}));
app.post('/api/user/addresses', auth, asyncHandler(async (req, res) => {
  const addr = req.body || {};
  if (!addr.name || !addr.line1 || !addr.city || !addr.state || !addr.pincode || !addr.phone) {
    return fail(res, 'Missing address fields', 400);
  }
  const u = await User.findById(req.user._id);
  if (addr.isDefault) u.addresses.forEach(a => (a.isDefault = false));
  u.addresses.push(addr);
  await u.save();
  return ok(res, 'Address added', { addresses: u.addresses });
}));
app.put('/api/user/addresses/:addrId', auth, asyncHandler(async (req, res) => {
  const u = await User.findById(req.user._id);
  const a = u.addresses.id(req.params.addrId);
  if (!a) return fail(res, 'Not found', 404);
  Object.assign(a, req.body || {});
  if (a.isDefault) u.addresses.forEach(x => { if (x._id.toString() !== a._id.toString()) x.isDefault = false; });
  await u.save();
  return ok(res, 'Address updated', { addresses: u.addresses });
}));
app.delete('/api/user/addresses/:addrId', auth, asyncHandler(async (req, res) => {
  const u = await User.findById(req.user._id);
  const a = u.addresses.id(req.params.addrId);
  if (!a) return fail(res, 'Not found', 404);
  a.deleteOne();
  await u.save();
  return ok(res, 'Address deleted', { addresses: u.addresses });
}));

// ----- Wishlist -----
app.get('/api/wishlist', auth, asyncHandler(async (req, res) => {
  const u = await User.findById(req.user._id).populate('wishlist');
  return ok(res, 'Wishlist', { items: u.wishlist || [] });
}));
app.post('/api/wishlist/:productId', auth, asyncHandler(async (req, res) => {
  const { productId } = req.params;
  const p = await Product.findById(productId);
  if (!p) return fail(res, 'Product not found', 404);
  await User.updateOne({ _id: req.user._id }, { $addToSet: { wishlist: p._id } });
  return ok(res, 'Added to wishlist', {});
}));
app.delete('/api/wishlist/:productId', auth, asyncHandler(async (req, res) => {
  const { productId } = req.params;
  await User.updateOne({ _id: req.user._id }, { $pull: { wishlist: new mongoose.Types.ObjectId(productId) } });
  return ok(res, 'Removed from wishlist', {});
}));

// ----- Meta (Enums/Facets) -----
app.get('/api/meta', asyncHandler(async (req, res) => {
  return ok(res, 'Meta', {
    categories: CATEGORY_ENUM,
    sizes: SIZE_ENUM,
    genders: GENDER_ENUM,
    fits: FIT_ENUM,
    sleeves: SLEEVE_ENUM,
    necks: NECK_ENUM,
    materials: MATERIAL_ENUM,
    patterns: PATTERN_ENUM,
  });
}));

// ----- Products & Search -----
app.get('/api/products', asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 12,
    q,
    category,
    gender,
    size,
    color,
    brand,
    fit,
    sleeve,
    neck,
    material,
    pattern,
    minPrice,
    maxPrice,
    inStock,
    minRating,
    tags,
    onSale,
    sort // price_asc|price_desc|newest|popularity|rating|sales
  } = req.query;

  const filter = { isActive: true };
  if (q) filter.$text = { $search: q };
  if (category && CATEGORY_ENUM.includes(category)) filter.category = category;
  if (gender && GENDER_ENUM.includes(gender)) filter.gender = gender;
  if (brand) filter.brand = brand;
  if (fit && FIT_ENUM.includes(fit)) filter['attributes.fit'] = fit;
  if (sleeve && SLEEVE_ENUM.includes(sleeve)) filter['attributes.sleeve'] = sleeve;
  if (neck && NECK_ENUM.includes(neck)) filter['attributes.neck'] = neck;
  if (material && MATERIAL_ENUM.includes(material)) filter['attributes.material'] = material;
  if (pattern && PATTERN_ENUM.includes(pattern)) filter['attributes.pattern'] = pattern;
  if (tags) filter.tags = { $in: String(tags).split(',').map(s => s.trim()).filter(Boolean) };

  // Price/variant/stock filters via variants array
  if (minPrice || maxPrice || size || color || inStock || onSale) {
    filter.variants = { $elemMatch: {} };
    if (size) filter.variants.$elemMatch.size = size;
    if (color) filter.variants.$elemMatch.color = color;
    if (inStock === 'true') filter.variants.$elemMatch.stock = { $gt: 0 };
    if (minPrice) filter.variants.$elemMatch.price = Object.assign(filter.variants.$elemMatch.price || {}, { $gte: Number(minPrice) });
    if (maxPrice) filter.variants.$elemMatch.price = Object.assign(filter.variants.$elemMatch.price || {}, { $lte: Number(maxPrice) });
    if (onSale === 'true') filter.variants.$elemMatch.$expr = { $lt: ['$price', '$mrp'] }; // best-effort
  }

  if (minRating) filter.ratingAverage = { $gte: Number(minRating) };

  const sortSpec =
    sort === 'price_asc' ? { 'variants.price': 1 } :
    sort === 'price_desc' ? { 'variants.price': -1 } :
    sort === 'popularity' ? { salesCount: -1 } :
    sort === 'rating' ? { ratingAverage: -1, ratingCount: -1 } :
    sort === 'sales' ? { salesCount: -1 } :
    { createdAt: -1 };

  const docs = await Product.find(filter)
    .sort(sortSpec)
    .skip((Number(page) - 1) * Number(limit))
    .limit(Number(limit));

  const total = await Product.countDocuments(filter);

  return ok(res, 'Products', {
    items: docs,
    page: Number(page),
    limit: Number(limit),
    total,
    pages: Math.ceil(total / Number(limit)),
  });
}));

app.get('/api/products/slug/:slug', asyncHandler(async (req, res) => {
  const p = await Product.findOne({ slug: req.params.slug, isActive: true });
  if (!p) return fail(res, 'Not found', 404);
  // Optional: bump popularity indicator
  await Product.updateOne({ _id: p._id }, { $inc: { salesCount: 0 } });
  return ok(res, 'Product', { product: p });
}));

app.get('/api/products/:id', asyncHandler(async (req, res) => {
  const p = await Product.findById(req.params.id);
  if (!p) return fail(res, 'Not found', 404);
  return ok(res, 'Product', { product: p });
}));

app.get('/api/products/suggest', asyncHandler(async (req, res) => {
  const { q } = req.query;
  if (!q) return ok(res, 'Suggestions', { items: [] });
  const items = await Product.find({ $text: { $search: q }, isActive: true })
    .select('name slug brand category')
    .limit(10);
  return ok(res, 'Suggestions', { items });
}));

// ----- Reviews -----
app.get('/api/products/:id/reviews', asyncHandler(async (req, res) => {
  const { page = 1, limit = 10 } = req.query;
  const items = await Review.find({ product: req.params.id, approved: true })
    .sort({ createdAt: -1 })
    .skip((Number(page) - 1) * Number(limit))
    .limit(Number(limit));
  const total = await Review.countDocuments({ product: req.params.id, approved: true });
  return ok(res, 'Reviews', { items, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
}));
app.post('/api/products/:id/reviews', auth, asyncHandler(async (req, res) => {
  const { rating, title, body } = req.body || {};
  if (!rating) return fail(res, 'Missing rating', 400);
  const p = await Product.findById(req.params.id);
  if (!p) return fail(res, 'Product not found', 404);
  const r = await Review.create({ product: p._id, user: req.user._id, rating, title, body, approved: true });
  // Recompute rating aggregates
  const agg = await Review.aggregate([
    { $match: { product: p._id, approved: true } },
    { $group: { _id: '$product', avg: { $avg: '$rating' }, count: { $sum: 1 } } }
  ]);
  const { avg = 0, count = 0 } = agg || {};
  p.ratingAverage = Math.round((avg + Number.EPSILON) * 10) / 10;
  p.ratingCount = count;
  await p.save();
  return ok(res, 'Review added', { review: r });
}));

// ----- Models registration for Review (needed after Product)
const Review = mongoose.model('Review', reviewSchema);

// ----- Cart -----
const getOrCreateCart = async (userId) => {
  let cart = await Cart.findOne({ user: userId });
  if (!cart) cart = await Cart.create({ user: userId, items: [] });
  return cart;
};
app.get('/api/cart', auth, asyncHandler(async (req, res) => {
  const cart = await getOrCreateCart(req.user._id);
  return ok(res, 'Cart', { cart });
}));
app.post('/api/cart', auth, asyncHandler(async (req, res) => {
  const { productId, variantId, quantity } = req.body || {};
  if (!productId || !variantId || !quantity) return fail(res, 'Missing fields', 400);
  const product = await Product.findById(productId);
  if (!product) return fail(res, 'Product not found', 404);
  const variant = product.variants.id(variantId);
  if (!variant) return fail(res, 'Variant not found', 404);
  if (quantity < 1) return fail(res, 'Quantity must be >= 1', 400);
  const cart = await getOrCreateCart(req.user._id);
  const idx = cart.items.findIndex(
    (i) => i.product.toString() === productId && i.variantId.toString() === variantId
  );
  const priceSnapshot = variant.price;
  if (idx >= 0) {
    cart.items[idx].quantity = quantity;
    cart.items[idx].priceSnapshot = priceSnapshot;
  } else {
    cart.items.push({ product: product._id, variantId: variant._id, quantity, priceSnapshot });
  }
  await cart.save();
  return ok(res, 'Cart updated', { cart });
}));
app.delete('/api/cart/item', auth, asyncHandler(async (req, res) => {
  const { productId, variantId } = req.body || {};
  const cart = await getOrCreateCart(req.user._id);
  cart.items = cart.items.filter(i => !(i.product.toString() === productId && i.variantId.toString() === variantId));
  await cart.save();
  return ok(res, 'Item removed', { cart });
}));
app.delete('/api/cart', auth, asyncHandler(async (req, res) => {
  const cart = await getOrCreateCart(req.user._id);
  cart.items = [];
  await cart.save();
  return ok(res, 'Cart cleared', { cart });
}));

// ----- Coupons -----
const isCouponActive = (c, now = new Date()) => {
  if (!c.active) return false;
  if (c.startsAt && now < c.startsAt) return false;
  if (c.endsAt && now > c.endsAt) return false;
  return true;
};
app.post('/api/coupons/validate', auth, asyncHandler(async (req, res) => {
  const { code, rupeesTotal, categoryHints = [] } = req.body || {};
  if (!code) return fail(res, 'Missing code', 400);
  const c = await Coupon.findOne({ code: code.toUpperCase() });
  if (!c || !isCouponActive(c)) return fail(res, 'Invalid or inactive coupon', 400);
  if (c.minOrderRupees && rupeesTotal < c.minOrderRupees) return fail(res, 'Order value too low', 400);
  if (c.appliesToCategories?.length && !c.appliesToCategories.some(cat => categoryHints.includes(cat))) {
    return fail(res, 'Coupon not applicable to items', 400);
  }
  if (c.excludesCategories?.length && c.excludesCategories.some(cat => categoryHints.includes(cat))) {
    return fail(res, 'Coupon excluded for items', 400);
  }
  return ok(res, 'Coupon valid', { discountPercent: c.discountPercent });
}));

// ----- Shipping / Pincode -----
app.get('/api/shipping/serviceability', asyncHandler(async (req, res) => {
  const { pincode } = req.query || {};
  if (!pincode) return fail(res, 'Missing pincode', 400);
  const svc = await Pincode.findOne({ pincode });
  if (!svc) return ok(res, 'Serviceability', { codAvailable: false, etaDays: 7, shippingRupees: Number(DEFAULT_SHIP_RUPEES) || 0 });
  return ok(res, 'Serviceability', svc.toObject());
}));

// ----- Orders & Payments -----
let razorpay = null;
if (RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET) {
  razorpay = new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });
}

// Create order from cart
app.post('/api/orders', auth, asyncHandler(async (req, res) => {
  const { addressId, couponCode } = req.body || {};
  const user = await User.findById(req.user._id);
  const shipAddr = user.addresses.id(addressId) || user.addresses.find(a => a.isDefault) || user.addresses;
  if (!shipAddr) return fail(res, 'No shipping address found', 400);

  const cart = await getOrCreateCart(req.user._id);
  if (!cart.items.length) return fail(res, 'Cart is empty', 400);

  const items = [];
  let rupeesSubtotal = 0;
  const categoryHints = new Set();

  for (const ci of cart.items) {
    const p = await Product.findById(ci.product);
    if (!p) return fail(res, 'Product in cart not found', 400);
    const v = p.variants.id(ci.variantId);
    if (!v) return fail(res, 'Variant in cart not found', 400);
    if (v.stock < ci.quantity) return fail(res, 'Insufficient stock', 400);

    items.push({
      product: p._id,
      variantId: v._id,
      name: p.name,
      size: v.size,
      color: v.color,
      price: v.price,
      quantity: ci.quantity,
    });
    rupeesSubtotal += v.price * ci.quantity;
    if (p.category) categoryHints.add(p.category);
  }

  let discountPercent = 0;
  let appliedCode = null;
  if (couponCode) {
    const c = await Coupon.findOne({ code: couponCode.toUpperCase() });
    if (c && isCouponActive(c) && (!c.minOrderRupees || rupeesSubtotal >= c.minOrderRupees)) {
      const hints = Array.from(categoryHints);
      const includeOk = !c.appliesToCategories?.length || c.appliesToCategories.some(cat => hints.includes(cat));
      const excludeHit = c.excludesCategories?.length && c.excludesCategories.some(cat => hints.includes(cat));
      if (includeOk && !excludeHit) {
        discountPercent = c.discountPercent;
        appliedCode = c.code;
      }
    }
  }

  const discountedRupees = Math.round(rupeesSubtotal * (1 - discountPercent / 100));
  // Shipping
  const svc = await Pincode.findOne({ pincode: shipAddr.pincode });
  const shippingRupees = svc ? svc.shippingRupees : (Number(DEFAULT_SHIP_RUPEES) || 0);

  // Tax (simple)
  const taxPercent = Number(DEFAULT_TAX_PERCENT) || 0;
  const taxRupees = Math.round(discountedRupees * (taxPercent / 100));

  const subtotalPaise = rupeesSubtotal * 100;
  const shippingPaise = shippingRupees * 100;
  const taxPaise = taxRupees * 100;
  const amountPaise = (discountedRupees * 100) + shippingPaise + taxPaise;

  const order = await Order.create({
    user: req.user._id,
    items,
    currency: 'INR',
    status: 'created',
    couponCode: appliedCode,
    discountPercent,
    subtotalPaise,
    taxPaise,
    shippingPaise,
    amountPaise,
    shippingAddress: shipAddr,
    billingAddress: shipAddr,
  });

  return ok(res, 'Order created', { order });
}));

app.get('/api/orders', auth, asyncHandler(async (req, res) => {
  const { page = 1, limit = 20, status } = req.query;
  const filter = { user: req.user._id };
  if (status) filter.status = status;
  const items = await Order.find(filter)
    .sort({ createdAt: -1 })
    .skip((Number(page) - 1) * Number(limit))
    .limit(Number(limit));
  const total = await Order.countDocuments(filter);
  return ok(res, 'Orders', { items, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
}));

// Create Razorpay order
app.post('/api/payments/create-order', auth, asyncHandler(async (req, res) => {
  if (!razorpay) return fail(res, 'Razorpay not configured', 500);
  const { orderId } = req.body || {};
  if (!orderId) return fail(res, 'Missing orderId', 400);
  const order = await Order.findById(orderId);
  if (!order || order.user.toString() !== req.user._id.toString())
    return fail(res, 'Order not found', 404);

  const rzpOrder = await razorpay.orders.create({
    amount: order.amountPaise,
    currency: order.currency,
    receipt: order._id.toString(),
    notes: { userId: req.user._id.toString() },
  });

  order.status = 'payment_pending';
  order.razorpayOrderId = rzpOrder.id;
  await order.save();

  return ok(res, 'Razorpay order created', {
    razorpayOrderId: rzpOrder.id,
    amount: rzpOrder.amount,
    currency: rzpOrder.currency,
    receipt: rzpOrder.receipt,
    keyId: RAZORPAY_KEY_ID,
    orderId: order._id,
  });
}));

// Verify payment signature
app.post('/api/payments/verify', auth, asyncHandler(async (req, res) => {
  const { orderId, razorpay_payment_id, razorpay_signature } = req.body || {};
  if (!orderId || !razorpay_payment_id || !razorpay_signature) return fail(res, 'Missing fields', 400);
  if (!RAZORPAY_KEY_SECRET) return fail(res, 'Razorpay not configured', 500);
  const order = await Order.findById(orderId);
  if (!order || order.user.toString() !== req.user._id.toString())
    return fail(res, 'Order not found', 404);
  if (!order.razorpayOrderId) return fail(res, 'No Razorpay order to verify against', 400);
  if (order.status === 'paid') return ok(res, 'Already verified', { order });

  const bodyToSign = `${order.razorpayOrderId}|${razorpay_payment_id}`;
  const expected = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET).update(bodyToSign).digest('hex');
  const signatureValid = expected === razorpay_signature;
  if (!signatureValid) {
    order.status = 'failed';
    order.razorpayPaymentId = razorpay_payment_id;
    order.razorpaySignature = razorpay_signature;
    await order.save();
    return fail(res, 'Signature verification failed', 400);
  }

  // Safe stock decrement on transition to paid
  if (order.status !== 'paid') {
    for (const it of order.items) {
      const p = await Product.findById(it.product);
      if (!p) continue;
      const v = p.variants.id(it.variantId);
      if (!v) continue;
      v.stock = Math.max(0, v.stock - it.quantity);
      await p.save();
      await InventoryLog.create({ product: p._id, variantId: v._id, delta: -it.quantity, reason: 'ORDER', byUser: req.user._id });
    }
    // bump product sales counters
    await Product.updateMany(
      { _id: { $in: order.items.map(i => i.product) } },
      { $inc: { salesCount: 1 } }
    );
  }
  order.status = 'paid';
  order.razorpayPaymentId = razorpay_payment_id;
  order.razorpaySignature = razorpay_signature;
  await order.save();

  await Cart.updateOne({ user: req.user._id }, { $set: { items: [] } });

  return ok(res, 'Payment verified', { order });
}));

// Razorpay webhook (HMAC with raw body)
app.post('/api/payments/webhook', webhookLimiter, asyncHandler(async (req, res) => {
  const signature = req.headers['x-razorpay-signature'];
  if (!RAZORPAY_WEBHOOK_SECRET) return fail(res, 'Webhook not configured', 500);
  if (!signature || !req.rawBody) return fail(res, 'Missing signature/body', 400);
  const expected = crypto
    .createHmac('sha256', RAZORPAY_WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest('hex');
  if (expected !== signature) return fail(res, 'Invalid webhook signature', 400);

  const event = req.body;
  try {
    if (event.event === 'payment.captured') {
      const payment = event.payload.payment.entity;
      const rzpOrderId = payment.order_id;
      const rzpPaymentId = payment.id;
      const order = await Order.findOne({ razorpayOrderId: rzpOrderId });
      if (order && order.status !== 'paid') {
        for (const it of order.items) {
          const p = await Product.findById(it.product);
          if (!p) continue;
          const v = p.variants.id(it.variantId);
          if (!v) continue;
          v.stock = Math.max(0, v.stock - it.quantity);
          await p.save();
          await InventoryLog.create({ product: p._id, variantId: v._id, delta: -it.quantity, reason: 'ORDER' });
        }
        await Product.updateMany(
          { _id: { $in: order.items.map(i => i.product) } },
          { $inc: { salesCount: 1 } }
        );
        order.status = 'paid';
        order.razorpayPaymentId = rzpPaymentId;
        await order.save();
      }
    }
    // Optionally: handle refunds/failed etc.
  } catch (e) {
    console.error('Webhook handling error', e);
  }
  res.status(200).json({ received: true });
}));

// Refund a paid order
app.post('/api/orders/:id/refund', auth, asyncHandler(async (req, res) => {
  if (!razorpay) return fail(res, 'Razorpay not configured', 500);
  const { amountPaise } = req.body || {}; // optional: full refund if absent
  const order = await Order.findById(req.params.id);
  if (!order) return fail(res, 'Order not found', 404);
  if (order.user.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
    return fail(res, 'Forbidden', 403);
  }
  if (order.status !== 'paid' || !order.razorpayPaymentId) {
    return fail(res, 'Refund allowed only for paid orders with a payment id', 400);
  }
  const opts = {};
  if (amountPaise != null) {
    const val = Number(amountPaise);
    if (!Number.isInteger(val) || val <= 0 || val > order.amountPaise) {
      return fail(res, 'Invalid amountPaise', 400);
    }
    opts.amount = val;
  }
  const refund = await razorpay.payments.refund(order.razorpayPaymentId, opts);
  order.status = 'refund_pending';
  await order.save();
  return ok(res, 'Refund initiated', { refund });
}));

// ----- Admin Router -----
const admin = express.Router();
admin.use(auth, adminOnly);

// Admin: Products
admin.get('/products', asyncHandler(async (req, res) => {
  const { page = 1, limit = 20, q, category, gender, brand, isActive } = req.query;
  const filter = {};
  if (q) filter.$text = { $search: q };
  if (category) filter.category = category;
  if (gender) filter.gender = gender;
  if (brand) filter.brand = brand;
  if (isActive != null) filter.isActive = isActive === 'true';
  const items = await Product.find(filter)
    .sort({ createdAt: -1 })
    .skip((Number(page) - 1) * Number(limit))
    .limit(Number(limit));
  const total = await Product.countDocuments(filter);
  return ok(res, 'Admin products', { items, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
}));

admin.get('/products/:id', asyncHandler(async (req, res) => {
  const p = await Product.findById(req.params.id);
  if (!p) return fail(res, 'Not found', 404);
  return ok(res, 'Admin product', { product: p });
}));

admin.post('/products', asyncHandler(async (req, res) => {
  const { name, slug, brand, gender, category, attributes = {}, variants = [], images = [], description = '', tags = [] } = req.body || {};
  if (!name || !slug || !category || !gender) return fail(res, 'Missing fields', 400);
  if (!Array.isArray(variants) || variants.length === 0) return fail(res, 'At least one variant required', 400);
  const created = await Product.create({ name, slug, brand, gender, category, attributes, variants, images, description, tags, isActive: true });
  return ok(res, 'Product created', { product: created }, 201);
}));

admin.put('/products/:id', asyncHandler(async (req, res) => {
  const update = req.body || {};
  const updated = await Product.findByIdAndUpdate(req.params.id, { $set: update }, { new: true, runValidators: true });
  if (!updated) return fail(res, 'Not found', 404);
  return ok(res, 'Product updated', { product: updated });
}));

admin.patch('/products/:id/variants/:variantId/stock', asyncHandler(async (req, res) => {
  const { stock, note } = req.body || {};
  if (stock == null || Number(stock) < 0) return fail(res, 'Invalid stock', 400);
  const p = await Product.findById(req.params.id);
  if (!p) return fail(res, 'Product not found', 404);
  const v = p.variants.id(req.params.variantId);
  if (!v) return fail(res, 'Variant not found', 404);
  const delta = Number(stock) - v.stock;
  v.stock = Number(stock);
  await p.save();
  await InventoryLog.create({ product: p._id, variantId: v._id, delta, reason: 'ADJUSTMENT', note, byUser: req.user._id });
  return ok(res, 'Variant stock updated', { product: p });
}));

admin.delete('/products/:id', asyncHandler(async (req, res) => {
  const del = await Product.findByIdAndDelete(req.params.id);
  if (!del) return fail(res, 'Not found', 404);
  return ok(res, 'Product deleted', { id: req.params.id });
}));

admin.post('/products/bulk', asyncHandler(async (req, res) => {
  const { items } = req.body || {};
  if (!Array.isArray(items) || items.length === 0) return fail(res, 'No items', 400);
  const created = await Product.insertMany(items, { ordered: false });
  return ok(res, 'Bulk inserted', { count: created.length });
}));

// Admin: Orders
admin.get('/orders', asyncHandler(async (req, res) => {
  const { page = 1, limit = 20, status, user, from, to } = req.query;
  const filter = {};
  if (status) filter.status = status;
  if (user) filter.user = user;
  if (from || to) {
    filter.createdAt = {};
    if (from) filter.createdAt.$gte = new Date(from);
    if (to) filter.createdAt.$lte = new Date(to);
  }
  const items = await Order.find(filter).sort({ createdAt: -1 }).skip((Number(page)-1)*Number(limit)).limit(Number(limit));
  const total = await Order.countDocuments(filter);
  return ok(res, 'Admin orders', { items, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
}));

admin.get('/orders/:id', asyncHandler(async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return fail(res, 'Not found', 404);
  return ok(res, 'Admin order', { order });
}));

admin.patch('/orders/:id/status', asyncHandler(async (req, res) => {
  const { status } = req.body || {};
  const allowed = ['created', 'payment_pending', 'paid', 'fulfilled', 'cancelled', 'refund_pending', 'refunded', 'failed'];
  if (!allowed.includes(status)) return fail(res, 'Invalid status', 400);
  const order = await Order.findById(req.params.id);
  if (!order) return fail(res, 'Not found', 404);
  order.status = status;
  await order.save();
  return ok(res, 'Order status updated', { order });
}));

admin.post('/orders/:id/refund', asyncHandler(async (req, res) => {
  if (!razorpay) return fail(res, 'Razorpay not configured', 500);
  const { amountPaise } = req.body || {};
  const order = await Order.findById(req.params.id);
  if (!order) return fail(res, 'Order not found', 404);
  if (order.status !== 'paid' || !order.razorpayPaymentId) {
    return fail(res, 'Refund allowed only for paid orders with a payment id', 400);
  }
  const opts = {};
  if (amountPaise != null) {
    const val = Number(amountPaise);
    if (!Number.isInteger(val) || val <= 0 || val > order.amountPaise) {
      return fail(res, 'Invalid amountPaise', 400);
    }
    opts.amount = val;
  }
  const refund = await razorpay.payments.refund(order.razorpayPaymentId, opts);
  order.status = 'refund_pending';
  await order.save();
  return ok(res, 'Refund initiated', { refund });
}));

// Admin: Users
admin.get('/users', asyncHandler(async (req, res) => {
  const { page = 1, limit = 20, q } = req.query;
  const filter = {};
  if (q) {
    filter.$or = [
      { name: { $regex: q, $options: 'i' } },
      { email: { $regex: q, $options: 'i' } },
      { mobilenum: { $regex: q, $options: 'i' } },
    ];
  }
  const items = await User.find(filter).sort({ createdAt: -1 }).skip((Number(page)-1)*Number(limit)).limit(Number(limit));
  const total = await User.countDocuments(filter);
  return ok(res, 'Admin users', { items, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
}));
admin.patch('/users/:id/role', asyncHandler(async (req, res) => {
  const { role } = req.body || {};
  if (!['user', 'admin'].includes(role)) return fail(res, 'Invalid role', 400);
  const u = await User.findByIdAndUpdate(req.params.id, { $set: { role } }, { new: true });
  if (!u) return fail(res, 'Not found', 404);
  return ok(res, 'Role updated', { user: u });
}));

// Admin: Coupons
admin.post('/coupons', asyncHandler(async (req, res) => {
  const { code, discountPercent, active = true, startsAt, endsAt, minOrderRupees, usageLimitTotal, usageLimitPerUser, appliesToCategories = [], excludesCategories = [] } = req.body || {};
  if (!code || discountPercent == null) return fail(res, 'Missing fields', 400);
  const c = await Coupon.create({ code: String(code).toUpperCase(), discountPercent, active, startsAt, endsAt, minOrderRupees, usageLimitTotal, usageLimitPerUser, appliesToCategories, excludesCategories });
  return ok(res, 'Coupon created', { coupon: c }, 201);
}));
admin.get('/coupons', asyncHandler(async (req, res) => {
  const cs = await Coupon.find().sort({ createdAt: -1 });
  return ok(res, 'Coupons', { coupons: cs });
}));
admin.put('/coupons/:id', asyncHandler(async (req, res) => {
  const update = req.body || {};
  if (update.code) update.code = String(update.code).toUpperCase();
  const c = await Coupon.findByIdAndUpdate(req.params.id, { $set: update }, { new: true, runValidators: true });
  if (!c) return fail(res, 'Not found', 404);
  return ok(res, 'Coupon updated', { coupon: c });
}));
admin.delete('/coupons/:id', asyncHandler(async (req, res) => {
  const c = await Coupon.findByIdAndDelete(req.params.id);
  if (!c) return fail(res, 'Not found', 404);
  return ok(res, 'Coupon deleted', { id: req.params.id });
}));

// Admin: Inventory logs
admin.get('/inventory/logs', asyncHandler(async (req, res) => {
  const { page = 1, limit = 50, product } = req.query;
  const filter = {};
  if (product) filter.product = product;
  const items = await InventoryLog.find(filter).sort({ createdAt: -1 }).skip((Number(page)-1)*Number(limit)).limit(Number(limit));
  const total = await InventoryLog.countDocuments(filter);
  return ok(res, 'Inventory logs', { items, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
}));

// Admin: Pincodes
admin.post('/pincodes', asyncHandler(async (req, res) => {
  const { pincode, codAvailable = false, etaDays = 5, shippingRupees = 0 } = req.body || {};
  if (!pincode) return fail(res, 'Missing pincode', 400);
  const doc = await Pincode.findOneAndUpdate({ pincode }, { $set: { codAvailable, etaDays, shippingRupees } }, { new: true, upsert: true });
  return ok(res, 'Pincode upserted', { pincode: doc });
}));
admin.get('/pincodes', asyncHandler(async (req, res) => {
  const { page = 1, limit = 50 } = req.query;
  const items = await Pincode.find({}).sort({ pincode: 1 }).skip((Number(page)-1)*Number(limit)).limit(Number(limit));
  const total = await Pincode.countDocuments({});
  return ok(res, 'Pincodes', { items, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
}));
admin.delete('/pincodes/:pincode', asyncHandler(async (req, res) => {
  await Pincode.deleteOne({ pincode: req.params.pincode });
  return ok(res, 'Pincode deleted', { pincode: req.params.pincode });
}));

// Admin: Reviews moderation
admin.patch('/reviews/:id/approve', asyncHandler(async (req, res) => {
  const r = await Review.findByIdAndUpdate(req.params.id, { $set: { approved: true } }, { new: true });
  if (!r) return fail(res, 'Not found', 404);
  return ok(res, 'Approved', { review: r });
}));
admin.patch('/reviews/:id/reject', asyncHandler(async (req, res) => {
  const r = await Review.findByIdAndUpdate(req.params.id, { $set: { approved: false } }, { new: true });
  if (!r) return fail(res, 'Not found', 404);
  return ok(res, 'Rejected', { review: r });
}));

// Admin: Analytics
admin.get('/stats', asyncHandler(async (req, res) => {
  const lastNDays = Number(req.query.lastNDays || 30);
  const since = new Date(Date.now() - lastNDays * 24 * 60 * 60 * 1000);
  const [usersCount, productsCount, ordersCount] = await Promise.all([
    User.countDocuments({}),
    Product.countDocuments({}),
    Order.countDocuments({}),
  ]);
  const revenueAgg = await Order.aggregate([
    { $match: { status: 'paid', createdAt: { $gte: since } } },
    { $group: { _id: null, totalPaise: { $sum: '$amountPaise' } } },
  ]);
  const totalRevenuePaise = revenueAgg?.totalPaise || 0;
  const byDay = await Order.aggregate([
    { $match: { status: 'paid', createdAt: { $gte: since } } },
    {
      $group: {
        _id: { $dateTrunc: { date: '$createdAt', unit: 'day' } },
        totalPaise: { $sum: '$amountPaise' },
        count: { $sum: 1 },
      }
    },
    { $sort: { '_id': 1 } },
  ]);
  const topProducts = await Order.aggregate([
    { $match: { status: 'paid', createdAt: { $gte: since } } },
    { $unwind: '$items' },
    { $group: {
      _id: '$items.product',
      name: { $first: '$items.name' },
      qty: { $sum: '$items.quantity' },
      revenuePaise: { $sum: { $multiply: ['$items.price', '$items.quantity', 100] } },
    }},
    { $sort: { qty: -1 } },
    { $limit: 10 },
  ]);
  const threshold = Number(req.query.lowStockThreshold || 5);
  const lowStock = await Product.aggregate([
    { $unwind: '$variants' },
    { $match: { 'variants.stock': { $lte: threshold } } },
    { $project: { productId: '$_id', name: 1, size: '$variants.size', color: '$variants.color', stock: '$variants.stock' } },
    { $sort: { stock: 1 } },
    { $limit: 50 },
  ]);
  return ok(res, 'Admin stats', {
    usersCount, productsCount, ordersCount, totalRevenuePaise, byDay, topProducts, lowStock
  });
}));

// Mount admin router
app.use('/api/admin', admin);

// ----- Error Handler -----
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  return fail(res, err.message || 'Server error', err.status || 500);
});

// ----- Listen -----
app.listen(Number(PORT), () => {
  console.log(`API running on http://localhost:${PORT} (${NODE_ENV})`);
});
