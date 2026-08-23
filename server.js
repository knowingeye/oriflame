require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const rootDir = __dirname;
const dataDir = path.join(rootDir, 'data');
const dbPath = path.join(dataDir, 'shop.db');
const isProduction = process.env.NODE_ENV === 'production';
const usePostgres = Boolean(process.env.DATABASE_URL);
const ADMIN_PIN = process.env.ADMIN_PIN || 'CHANGE_ME_NOW';
const SESSION_SECRET = process.env.SESSION_SECRET || 'development-secret-change-this';
const ADMIN_SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const normalizeAllowedOrigins = (value = '') => (value || '').split(',').map((entry) => entry.trim()).filter(Boolean);
const allowedOrigins = normalizeAllowedOrigins(process.env.ALLOWED_ORIGINS || process.env.CORS_ORIGIN || '');
const adminSessions = new Map();
const adminLoginAttempts = new Map();
const DEFAULT_ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@example.com').trim().toLowerCase();
const DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ChangeMe123!';
const ADMIN_PASSWORD_SALT = process.env.ADMIN_PASSWORD_SALT || SESSION_SECRET;
const adminProductRoles = ['owner', 'admin', 'manager', 'inventory'];
const adminOrderRoles = ['owner', 'admin', 'orders'];
const orderStateTransitions = {
  NEW: ['AWAITING_PAYMENT', 'CANCELLED'],
  AWAITING_PAYMENT: ['PAYMENT_VERIFIED', 'CANCELLED', 'EXPIRED'],
  PAYMENT_VERIFIED: ['PACKING', 'CANCELLED', 'REFUNDED'],
  PACKING: ['READY_TO_SHIP', 'CANCELLED'],
  READY_TO_SHIP: ['SHIPPED', 'CANCELLED'],
  SHIPPED: ['COMPLETED', 'RETURNED'],
  COMPLETED: ['RETURNED', 'REFUNDED'],
  CANCELLED: [],
  EXPIRED: [],
  RETURNED: [],
  REFUNDED: []
};

const hashPassword = (password) => crypto.pbkdf2Sync(String(password || ''), ADMIN_PASSWORD_SALT, 100000, 32, 'sha256').toString('hex');

const recordAuditLog = async ({ adminUserId, action, entityType, entityId, beforeValue, afterValue, ipAddress, userAgent }) => {
  const logId = `AUD-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
  await run(
    `INSERT INTO audit_logs (id, admin_user_id, action, entity_type, entity_id, before_value, after_value, ip_address, user_agent, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
    [
      logId,
      adminUserId || null,
      action || 'action',
      entityType || 'unknown',
      entityId || null,
      beforeValue ? JSON.stringify(beforeValue) : null,
      afterValue ? JSON.stringify(afterValue) : null,
      ipAddress || 'unknown',
      userAgent || 'unknown'
    ]
  );
};

if (isProduction && (!process.env.ADMIN_PIN || process.env.ADMIN_PIN === 'CHANGE_ME_NOW')) {
  throw new Error('Production requires a strong ADMIN_PIN.');
}

if (isProduction && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === 'development-secret-change-this')) {
  throw new Error('Production requires a secure SESSION_SECRET.');
}

if (isProduction && allowedOrigins.length === 0) {
  throw new Error('Production requires ALLOWED_ORIGINS to be configured.');
}

if (isProduction && !process.env.DATABASE_URL) {
  throw new Error('Production requires DATABASE_URL to point to the managed database.');
}

if (isProduction && (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD || !process.env.ADMIN_PASSWORD_SALT)) {
  throw new Error('Production requires ADMIN_EMAIL, ADMIN_PASSWORD, and ADMIN_PASSWORD_SALT values.');
}

const csrfHeaders = (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  next();
};

const errorResponse = (req, res, statusCode, message, details) => {
  const payload = { message };
  if (process.env.NODE_ENV !== 'production' && details) {
    payload.details = details;
  }
  return res.status(statusCode).json(payload);
};

const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many login attempts. Please try again later.' }
});

const generalRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests. Please slow down.' }
});

app.use(csrfHeaders);
app.use(generalRateLimiter);
app.use((req, res, next) => {
  const requestOrigin = req.headers.origin;
  const isAllowed = !requestOrigin || (allowedOrigins.length > 0 && allowedOrigins.includes(requestOrigin));
  if (requestOrigin && isAllowed) {
    res.setHeader('Access-Control-Allow-Origin', requestOrigin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-CSRF-Token');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  if (requestOrigin && allowedOrigins.length > 0 && !allowedOrigins.includes(requestOrigin)) {
    return res.status(403).json({ message: 'Origin not allowed.' });
  }
  next();
});

const sanitizeText = (value, fallback = '') => {
  if (value === null || value === undefined) return fallback;
  const cleaned = String(value).replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim();
  return cleaned ? cleaned.slice(0, 2000) : fallback;
};

const containsMaliciousInput = (value) => {
  if (value === null || value === undefined) return false;
  const text = String(value).toLowerCase();
  return /<\s*script|javascript:|vbscript:|data:text\/html|on\w+\s*=/.test(text);
};

const enforceSafeInput = (payload) => {
  if (!payload || typeof payload !== 'object') return payload;
  const unsafe = Object.entries(payload).some(([key, value]) => {
    if (typeof value === 'string' && containsMaliciousInput(value)) return true;
    if (Array.isArray(value) && value.some((entry) => typeof entry === 'string' && containsMaliciousInput(entry))) return true;
    return false;
  });
  if (unsafe) {
    throw new Error('Unsafe input detected.');
  }
  return payload;
};

const securityHeaders = (req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: blob: https:; font-src 'self' https://fonts.gstatic.com data:; connect-src 'self' http://localhost:3000 https:; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests");
  next();
};

const parseCookies = (header = '') => {
  const cookies = {};
  (header || '').split(';').forEach((part) => {
    const [rawKey, ...rawVal] = part.split('=');
    const key = (rawKey || '').trim();
    if (!key) return;
    cookies[key] = decodeURIComponent((rawVal || []).join('=').trim());
  });
  return cookies;
};

const signValue = (value) => crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('hex');

const serializeSessionCookie = (sessionId) => `${sessionId}.${signValue(sessionId)}`;

const getSessionFromCookie = (cookieHeader) => {
  const cookieValue = parseCookies(cookieHeader).admin_session;
  if (!cookieValue) return null;
  const [sessionId, signature] = String(cookieValue).split('.');
  if (!sessionId || !signature) return null;
  if (signature !== signValue(sessionId)) return null;
  const session = adminSessions.get(sessionId);
  if (!session || session.expiresAt <= Date.now()) {
    adminSessions.delete(sessionId);
    return null;
  }
  return session;
};

const requireAdmin = (req, res, next) => {
  const session = getSessionFromCookie(req.headers.cookie || '');
  if (!session) return res.status(401).json({ message: 'Unauthorized. Admin session required.' });
  req.adminSession = session;
  next();
};

const requireRole = (...allowedRoles) => (req, res, next) => {
  const session = getSessionFromCookie(req.headers.cookie || '');
  if (!session) return res.status(401).json({ message: 'Unauthorized. Admin session required.' });
  if (allowedRoles.length > 0 && !allowedRoles.includes(session.role)) {
    return res.status(403).json({ message: 'Forbidden. Insufficient role permissions.' });
  }
  req.adminSession = session;
  next();
};

const blockBruteforceLogin = (req) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
  const now = Date.now();
  const attempts = adminLoginAttempts.get(ip) || [];
  const recent = attempts.filter((time) => now - time < 15 * 60 * 1000);
  adminLoginAttempts.set(ip, recent);
  return recent.length >= 5;
};

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  hidePoweredBy: true
}));
app.use(securityHeaders);

let db = null;
let dbPool = null;

const toPostgresSql = (sql, params = []) => {
  let parameterIndex = 0;
  const converted = sql.replace(/\?/g, () => {
    parameterIndex += 1;
    return `$${parameterIndex}`;
  });
  return { sql: converted, params };
};

const connectDatabase = async () => {
  if (usePostgres) {
    dbPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: isProduction ? { rejectUnauthorized: false } : false,
      max: 10
    });
    await dbPool.query('SELECT 1');
    console.log('Connected to PostgreSQL database via DATABASE_URL');
    return;
  }

  fs.mkdirSync(dataDir, { recursive: true });
  db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
      console.error('Database connection error:', err.message);
      process.exit(1);
    }
    console.log('Connected to SQLite database at', dbPath);
  });
};

const seedDefaultAdminUser = async () => {
  const passwordHash = hashPassword(DEFAULT_ADMIN_PASSWORD);

  if (usePostgres) {
    await dbPool.query(
      `INSERT INTO admin_users (id, email, password_hash, role, status)
       VALUES ($1, $2, $3, 'owner', 'active')
       ON CONFLICT (email) DO UPDATE SET
         password_hash = EXCLUDED.password_hash,
         role = EXCLUDED.role,
         status = EXCLUDED.status`,
      [`admin-${crypto.randomBytes(8).toString('hex')}`, DEFAULT_ADMIN_EMAIL, passwordHash]
    );
    await dbPool.query(
      `UPDATE admin_users SET password_hash = $1, role = 'owner', status = 'active' WHERE email = $2`,
      [passwordHash, DEFAULT_ADMIN_EMAIL]
    );
    return;
  }

  await new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO admin_users (id, email, password_hash, role, status)
       VALUES (?, ?, ?, 'owner', 'active')
       ON CONFLICT(email) DO UPDATE SET
         password_hash = excluded.password_hash,
         role = excluded.role,
         status = excluded.status`,
      [`admin-${crypto.randomBytes(8).toString('hex')}`, DEFAULT_ADMIN_EMAIL, passwordHash],
      (err) => {
        if (err) {
          console.error('Admin seed error:', err.message);
          reject(err);
          return;
        }
        resolve();
      }
    );
  });

  await new Promise((resolve, reject) => {
    db.run(
      `UPDATE admin_users SET password_hash = ?, role = 'owner', status = 'active' WHERE email = ?`,
      [passwordHash, DEFAULT_ADMIN_EMAIL],
      (err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve();
      }
    );
  });
};

const initializeDatabase = async () => {
  if (usePostgres) {
    const statements = [
      `CREATE TABLE IF NOT EXISTS products (
        id TEXT PRIMARY KEY,
        slug TEXT UNIQUE,
        name TEXT,
        brand TEXT,
        cat TEXT,
        price TEXT,
        stock INTEGER DEFAULT 0,
        image TEXT,
        status TEXT DEFAULT 'Active',
        description TEXT,
        source_url TEXT,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS categories (
        id TEXT PRIMARY KEY,
        name TEXT,
        description TEXT,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS hero_slides (
        id TEXT PRIMARY KEY,
        productSlug TEXT,
        eyebrow TEXT,
        title TEXT,
        description TEXT,
        image TEXT,
        theme TEXT DEFAULT 'custom',
        themeColor TEXT DEFAULT '#cdeaa4',
        price TEXT,
        href TEXT,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS discount_codes (
        id TEXT PRIMARY KEY,
        code TEXT,
        title TEXT,
        type TEXT,
        value REAL,
        active INTEGER DEFAULT 1,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY,
        payload TEXT,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS bills (
        id TEXT PRIMARY KEY,
        order_id TEXT,
        invoice_number TEXT,
        payload TEXT,
        issued_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS admin_users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'admin',
        status TEXT DEFAULT 'active',
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        last_login_at TIMESTAMPTZ
      )`,
      `CREATE TABLE IF NOT EXISTS payments (
        id TEXT PRIMARY KEY,
        order_id TEXT,
        payment_reference TEXT UNIQUE,
        method TEXT,
        amount_expected REAL DEFAULT 0,
        amount_received REAL DEFAULT 0,
        currency TEXT DEFAULT 'LKR',
        status TEXT DEFAULT 'pending',
        customer_reference TEXT,
        verified_by TEXT,
        verified_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      )`
    ];

    for (const statement of statements) {
      try {
        await dbPool.query(statement);
      } catch (error) {
        console.error('Schema init error:', error.message);
      }
    }

    try {
      await seedDefaultAdminUser();
    } catch (error) {
      console.error('Admin seed error:', error.message);
    }
    return;
  }

  const statements = [
    `CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      slug TEXT UNIQUE,
      name TEXT,
      brand TEXT,
      cat TEXT,
      price TEXT,
      stock INTEGER DEFAULT 0,
      image TEXT,
      status TEXT DEFAULT 'Active',
      description TEXT,
      source_url TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS categories (
      id TEXT PRIMARY KEY,
      name TEXT,
      description TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS hero_slides (
      id TEXT PRIMARY KEY,
      productSlug TEXT,
      eyebrow TEXT,
      title TEXT,
      description TEXT,
      image TEXT,
      theme TEXT DEFAULT 'custom',
      themeColor TEXT DEFAULT '#cdeaa4',
      price TEXT,
      href TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS discount_codes (
      id TEXT PRIMARY KEY,
      code TEXT,
      title TEXT,
      type TEXT,
      value REAL,
      active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY,
      payload TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS bills (
      id TEXT PRIMARY KEY,
      order_id TEXT,
      invoice_number TEXT,
      payload TEXT,
      issued_at TEXT DEFAULT CURRENT_TIMESTAMP,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS admin_users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'admin',
      status TEXT DEFAULT 'active',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      last_login_at TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS payments (
      id TEXT PRIMARY KEY,
      order_id TEXT,
      payment_reference TEXT UNIQUE,
      method TEXT,
      amount_expected REAL DEFAULT 0,
      amount_received REAL DEFAULT 0,
      currency TEXT DEFAULT 'LKR',
      status TEXT DEFAULT 'pending',
      customer_reference TEXT,
      verified_by TEXT,
      verified_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`
  ];

  for (const statement of statements) {
    await new Promise((resolve, reject) => {
      db.run(statement, (err) => {
        if (err) {
          console.error('Schema init error:', err.message);
          reject(err);
          return;
        }
        resolve();
      });
    });
  }

  await seedDefaultAdminUser();
};

const run = (sql, params = []) => {
  if (usePostgres) {
    const { sql: postgresSql, params: postgresParams } = toPostgresSql(sql, params);
    return dbPool.query(postgresSql, postgresParams).then((result) => ({
      id: result.rows[0] && result.rows[0].id ? result.rows[0].id : null,
      changes: result.rowCount || 0
    }));
  }

  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ id: this.lastID, changes: this.changes });
    });
  });
};

const all = (sql, params = []) => {
  if (usePostgres) {
    const { sql: postgresSql, params: postgresParams } = toPostgresSql(sql, params);
    return dbPool.query(postgresSql, postgresParams).then((result) => result.rows);
  }

  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
};

const first = (sql, params = []) => {
  if (usePostgres) {
    const { sql: postgresSql, params: postgresParams } = toPostgresSql(sql, params);
    return dbPool.query(postgresSql, postgresParams).then((result) => result.rows[0] || null);
  }

  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
};

const parseJson = (value, fallback = []) => {
  try {
    const parsed = JSON.parse(value);
    return parsed ?? fallback;
  } catch {
    return fallback;
  }
};

const normalizeProduct = (row) => ({
  id: row.id,
  slug: row.slug,
  name: row.name,
  brand: row.brand,
  cat: row.cat,
  price: row.price,
  stock: Number(row.stock || 0),
  image: row.image,
  status: row.status,
  description: row.description,
  sourceUrl: row.source_url,
  desc: row.description || `${row.name || 'Product'} is available from our ${row.cat || 'shop'} collection.`
});

const normalizeCategory = (row) => ({
  id: row.id,
  name: row.name,
  description: row.description
});

const normalizeHero = (row) => ({
  id: row.id,
  productSlug: row.productSlug,
  eyebrow: row.eyebrow,
  title: row.title,
  description: row.description,
  image: row.image,
  theme: row.theme,
  themeColor: row.themeColor,
  price: row.price,
  href: row.href
});

const normalizeDiscount = (row) => ({
  id: row.id,
  code: row.code,
  title: row.title,
  type: row.type,
  value: Number(row.value || 0),
  active: Boolean(row.active)
});

const normalizeOrder = (row) => {
  try {
    return JSON.parse(row.payload || '{}');
  } catch {
    return {};
  }
};

const normalizeBill = (row) => {
  try {
    return { ...JSON.parse(row.payload || '{}'), id: row.id, orderId: row.order_id, invoiceNumber: row.invoice_number, issuedAt: row.issued_at };
  } catch {
    return { id: row.id, orderId: row.order_id, invoiceNumber: row.invoice_number, issuedAt: row.issued_at };
  }
};

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use((req, res, next) => {
  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
    try {
      if (req.body && typeof req.body === 'object') {
        enforceSafeInput(req.body);
      }
    } catch (error) {
      return res.status(400).json({ message: error.message || 'Unsafe input detected.' });
    }
  }
  next();
});

app.get('/api/admin/session', (req, res) => {
  const session = getSessionFromCookie(req.headers.cookie || '');
  res.json({ authenticated: !!session, role: session ? session.role : null });
});

app.use('/api/admin/login', loginRateLimiter);

app.post('/api/admin/login', async (req, res) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  const attempts = adminLoginAttempts.get(ip) || [];
  const now = Date.now();
  const recent = attempts.filter((time) => now - time < 15 * 60 * 1000);
  if (recent.length >= 5) {
    return res.status(429).json({ message: 'Too many login attempts. Please try again later.' });
  }

  const payload = req.body || {};
  const email = String(payload.email || '').trim().toLowerCase();
  const password = String(payload.password || '');
  const pin = String(payload.pin || '');

  let sessionRole = 'admin';
  let sessionUserId = null;
  let loginSucceeded = false;

  if (email && password) {
    const defaultAdminMatch = email === DEFAULT_ADMIN_EMAIL && password === DEFAULT_ADMIN_PASSWORD;
    const user = await first('SELECT * FROM admin_users WHERE email = ? AND status = ? LIMIT 1', [email, 'active']);
    if (user && (user.password_hash === hashPassword(password) || defaultAdminMatch)) {
      sessionRole = user.role || 'owner';
      sessionUserId = user.id;
      loginSucceeded = true;
      if (defaultAdminMatch) {
        await run(
          'UPDATE admin_users SET password_hash = ?, role = ?, status = ?, last_login_at = CURRENT_TIMESTAMP WHERE email = ?',
          [hashPassword(password), 'owner', 'active', email]
        );
      } else {
        await run('UPDATE admin_users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
      }
    } else if (defaultAdminMatch) {
      await run(
        `INSERT INTO admin_users (id, email, password_hash, role, status)
         VALUES (?, ?, ?, 'owner', 'active')
         ON CONFLICT(email) DO UPDATE SET
           password_hash = excluded.password_hash,
           role = excluded.role,
           status = excluded.status`,
        [`admin-${crypto.randomBytes(8).toString('hex')}`, email, hashPassword(password)]
      );
      const createdUser = await first('SELECT * FROM admin_users WHERE email = ? AND status = ? LIMIT 1', [email, 'active']);
      if (createdUser) {
        sessionRole = createdUser.role || 'owner';
        sessionUserId = createdUser.id;
        loginSucceeded = true;
        await run('UPDATE admin_users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?', [createdUser.id]);
      } else {
        recent.push(now);
        adminLoginAttempts.set(ip, recent);
        await recordAuditLog({ adminUserId: null, action: 'admin_login_failed', entityType: 'admin_users', entityId: email || null, beforeValue: { email }, afterValue: { reason: 'invalid_credentials' }, ipAddress: ip, userAgent });
        return res.status(401).json({ message: 'Invalid email or password.' });
      }
    } else {
      recent.push(now);
      adminLoginAttempts.set(ip, recent);
      await recordAuditLog({ adminUserId: null, action: 'admin_login_failed', entityType: 'admin_users', entityId: email || null, beforeValue: { email }, afterValue: { reason: 'invalid_credentials' }, ipAddress: ip, userAgent });
      return res.status(401).json({ message: 'Invalid email or password.' });
    }
  } else if (pin) {
    if (!pin || pin !== ADMIN_PIN || ADMIN_PIN === 'CHANGE_ME_NOW') {
      recent.push(now);
      adminLoginAttempts.set(ip, recent);
      await recordAuditLog({ adminUserId: null, action: 'admin_login_failed', entityType: 'admin_users', entityId: null, beforeValue: { pinProvided: true }, afterValue: { reason: 'invalid_pin' }, ipAddress: ip, userAgent });
      return res.status(401).json({ message: 'Invalid admin PIN.' });
    }
    sessionRole = 'admin';
    loginSucceeded = true;
  } else {
    recent.push(now);
    adminLoginAttempts.set(ip, recent);
    await recordAuditLog({ adminUserId: null, action: 'admin_login_failed', entityType: 'admin_users', entityId: null, beforeValue: { request: 'missing_credentials' }, afterValue: { reason: 'missing_credentials' }, ipAddress: ip, userAgent });
    return res.status(401).json({ message: 'Missing admin credentials.' });
  }

  const sessionId = crypto.randomBytes(32).toString('hex');
  adminSessions.set(sessionId, { id: sessionId, role: sessionRole, userId: sessionUserId, expiresAt: Date.now() + ADMIN_SESSION_TTL_MS });
  adminLoginAttempts.delete(ip);
  if (loginSucceeded) {
    await recordAuditLog({ adminUserId: sessionUserId || null, action: 'admin_login_success', entityType: 'admin_users', entityId: sessionUserId || null, beforeValue: { email }, afterValue: { role: sessionRole }, ipAddress: ip, userAgent });
  }
  res.cookie('admin_session', serializeSessionCookie(sessionId), {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    maxAge: ADMIN_SESSION_TTL_MS,
    signed: false
  });
  res.json({ authenticated: true, role: sessionRole });
});

app.post('/api/admin/logout', (req, res) => {
  const session = getSessionFromCookie(req.headers.cookie || '');
  if (session) {
    adminSessions.delete(session.id);
  }
  res.clearCookie('admin_session', { path: '/', httpOnly: true, sameSite: 'lax', secure: isProduction });
  res.json({ success: true });
});

app.post('/api/admin/payments/:paymentReference/verify', requireRole('owner', 'admin', 'orders'), async (req, res) => {
  try {
    const paymentReference = String(req.params.paymentReference || '').trim();
    const paymentRow = await first('SELECT * FROM payments WHERE payment_reference = ? LIMIT 1', [paymentReference]);
    if (!paymentRow) {
      return res.status(404).json({ message: 'Payment record not found.' });
    }

    const orderRow = await first('SELECT * FROM orders WHERE id = ? LIMIT 1', [paymentRow.order_id]);
    const orderPayload = orderRow ? parseJson(orderRow.payload, {}) : {};
    const currentStatus = String(orderPayload.status || 'NEW');
    const nextStatus = 'PAYMENT_VERIFIED';
    if (!orderStateTransitions[currentStatus] || !orderStateTransitions[currentStatus].includes(nextStatus)) {
      return res.status(400).json({ message: `Invalid order state transition from ${currentStatus} to ${nextStatus}.` });
    }

    const amountExpected = Number(paymentRow.amount_expected || 0);
    const amountReceived = Number(req.body?.amountReceived || paymentRow.amount_received || amountExpected);

    if (amountReceived < amountExpected) {
      return res.status(400).json({ message: 'Payment amount is below the expected total.' });
    }

    const beforeOrder = { ...orderPayload };
    const beforePayment = { ...paymentRow };
    const newOrderPayload = {
      ...orderPayload,
      paymentStatus: 'verified',
      status: nextStatus,
      verifiedAt: new Date().toISOString(),
      verifiedBy: req.adminSession?.userId || req.adminSession?.id || 'admin'
    };

    await run(
      'UPDATE payments SET amount_received = ?, status = ?, verified_by = ?, verified_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [amountReceived, 'verified', req.adminSession?.userId || req.adminSession?.id || 'admin', new Date().toISOString(), paymentRow.id]
    );
    await run('UPDATE orders SET payload = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [JSON.stringify(newOrderPayload), paymentRow.order_id]);

    await recordAuditLog({
      adminUserId: req.adminSession?.userId || null,
      action: 'payment_verified',
      entityType: 'payments',
      entityId: paymentRow.id,
      beforeValue: beforePayment,
      afterValue: { ...beforePayment, amount_received: amountReceived, status: 'verified' },
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown'
    });

    await recordAuditLog({
      adminUserId: req.adminSession?.userId || null,
      action: 'order_status_updated',
      entityType: 'orders',
      entityId: paymentRow.order_id,
      beforeValue: beforeOrder,
      afterValue: newOrderPayload,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown'
    });

    res.json({ success: true, orderId: paymentRow.order_id, paymentStatus: 'verified' });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'oriflame-store' });
});

app.get('/api/health/live', (req, res) => {
  res.json({ ok: true, status: 'live' });
});

app.get('/api/health/ready', async (req, res) => {
  try {
    await first('SELECT 1 AS ok');
    res.json({ ok: true, status: 'ready' });
  } catch (error) {
    return errorResponse(req, res, 503, 'Database unavailable.', process.env.NODE_ENV !== 'production' ? error.message : undefined);
  }
});

app.get('/api/public/products', async (req, res) => {
  try {
    const rows = await all('SELECT * FROM products ORDER BY updated_at DESC, created_at DESC');
    res.json(rows.map(normalizeProduct));
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.get('/api/products', async (req, res) => {
  try {
    const rows = await all('SELECT * FROM products ORDER BY updated_at DESC, created_at DESC');
    res.json(rows.map(normalizeProduct));
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.post('/api/products', requireRole(...adminProductRoles), async (req, res) => {
  try {
    const product = req.body || {};
    const id = product.id || `prod-${Date.now()}`;
    const slug = product.slug || product.name || id;
    await run(
      `INSERT INTO products (id, slug, name, brand, cat, price, stock, image, status, description, source_url, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(id) DO UPDATE SET
         slug = excluded.slug,
         name = excluded.name,
         brand = excluded.brand,
         cat = excluded.cat,
         price = excluded.price,
         stock = excluded.stock,
         image = excluded.image,
         status = excluded.status,
         description = excluded.description,
         source_url = excluded.source_url,
         updated_at = CURRENT_TIMESTAMP`,
      [
        id,
        slug,
        product.name || 'Product',
        product.brand || 'Oriflame',
        product.cat || 'Skincare',
        product.price || 'Rs. 0',
        Number(product.stock || 0),
        product.image || 'productImage.webp',
        product.status || 'Active',
        product.description || product.desc || '',
        product.sourceUrl || '',
      ]
    );
    res.json({ success: true, id });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.post('/api/admin/products', requireRole(...adminProductRoles), async (req, res) => {
  try {
    const product = req.body || {};
    const id = product.id || `prod-${Date.now()}`;
    const slug = product.slug || product.name || id;
    await run(
      `INSERT INTO products (id, slug, name, brand, cat, price, stock, image, status, description, source_url, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(id) DO UPDATE SET
         slug = excluded.slug,
         name = excluded.name,
         brand = excluded.brand,
         cat = excluded.cat,
         price = excluded.price,
         stock = excluded.stock,
         image = excluded.image,
         status = excluded.status,
         description = excluded.description,
         source_url = excluded.source_url,
         updated_at = CURRENT_TIMESTAMP`,
      [
        id,
        slug,
        product.name || 'Product',
        product.brand || 'Oriflame',
        product.cat || 'Skincare',
        product.price || 'Rs. 0',
        Number(product.stock || 0),
        product.image || 'productImage.webp',
        product.status || 'Active',
        product.description || product.desc || '',
        product.sourceUrl || '',
      ]
    );
    res.json({ success: true, id });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.put('/api/products/:id', requireRole(...adminProductRoles), async (req, res) => {
  try {
    const product = req.body || {};
    const id = req.params.id;
    const nextSlug = product.slug || id;
    await run(
      `UPDATE products SET
        slug = ?,
        name = ?,
        brand = ?,
        cat = ?,
        price = ?,
        stock = ?,
        image = ?,
        status = ?,
        description = ?,
        source_url = ?,
        updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [
        nextSlug,
        product.name || 'Product',
        product.brand || 'Oriflame',
        product.cat || 'Skincare',
        product.price || 'Rs. 0',
        Number(product.stock || 0),
        product.image || 'productImage.webp',
        product.status || 'Active',
        product.description || product.desc || '',
        product.sourceUrl || '',
        id
      ]
    );
    res.json({ success: true, id });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.delete('/api/products/:id', requireRole(...adminProductRoles), async (req, res) => {
  try {
    await run('DELETE FROM products WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.get('/api/categories', async (req, res) => {
  try {
    const rows = await all('SELECT * FROM categories ORDER BY updated_at DESC');
    res.json(rows.map(normalizeCategory));
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.post('/api/categories', requireRole(...adminProductRoles), async (req, res) => {
  try {
    const category = req.body || {};
    const id = category.id || category.name || `cat-${Date.now()}`;
    await run(
      `INSERT INTO categories (id, name, description, updated_at)
       VALUES (?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(id) DO UPDATE SET
         name = excluded.name,
         description = excluded.description,
         updated_at = CURRENT_TIMESTAMP`,
      [id, category.name || 'Category', category.description || '']
    );
    res.json({ success: true, id });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.put('/api/categories/:id', requireRole(...adminProductRoles), async (req, res) => {
  try {
    const category = req.body || {};
    await run(
      'UPDATE categories SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [category.name || 'Category', category.description || '', req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.delete('/api/categories/:id', requireRole(...adminProductRoles), async (req, res) => {
  try {
    await run('DELETE FROM categories WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.get('/api/hero', async (req, res) => {
  try {
    const rows = await all('SELECT * FROM hero_slides ORDER BY updated_at DESC');
    res.json(rows.map(normalizeHero));
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.post('/api/hero', requireRole(...adminProductRoles), async (req, res) => {
  try {
    const hero = req.body || {};
    const id = hero.id || `hero-${Date.now()}`;
    await run(
      `INSERT INTO hero_slides (id, productSlug, eyebrow, title, description, image, theme, themeColor, price, href, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(id) DO UPDATE SET
         productSlug = excluded.productSlug,
         eyebrow = excluded.eyebrow,
         title = excluded.title,
         description = excluded.description,
         image = excluded.image,
         theme = excluded.theme,
         themeColor = excluded.themeColor,
         price = excluded.price,
         href = excluded.href,
         updated_at = CURRENT_TIMESTAMP`,
      [
        id,
        hero.productSlug || '',
        hero.eyebrow || '',
        hero.title || 'Featured offer',
        hero.description || '',
        hero.image || 'productImage.webp',
        hero.theme || 'custom',
        hero.themeColor || '#cdeaa4',
        hero.price || 'Shop now',
        hero.href || 'index.html'
      ]
    );
    res.json({ success: true, id });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.put('/api/hero/:id', requireRole(...adminProductRoles), async (req, res) => {
  try {
    const hero = req.body || {};
    await run(
      `UPDATE hero_slides SET
        productSlug = ?,
        eyebrow = ?,
        title = ?,
        description = ?,
        image = ?,
        theme = ?,
        themeColor = ?,
        price = ?,
        href = ?,
        updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [
        hero.productSlug || '',
        hero.eyebrow || '',
        hero.title || 'Featured offer',
        hero.description || '',
        hero.image || 'productImage.webp',
        hero.theme || 'custom',
        hero.themeColor || '#cdeaa4',
        hero.price || 'Shop now',
        hero.href || 'index.html',
        req.params.id
      ]
    );
    res.json({ success: true });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.delete('/api/hero/:id', requireRole(...adminProductRoles), async (req, res) => {
  try {
    await run('DELETE FROM hero_slides WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.get('/api/discounts', requireRole(...adminProductRoles), async (req, res) => {
  try {
    const rows = await all('SELECT * FROM discount_codes ORDER BY updated_at DESC');
    res.json(rows.map(normalizeDiscount));
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.post('/api/customer/orders', async (req, res) => {
  try {
    const payload = req.body || {};
    const items = Array.isArray(payload.items) ? payload.items : [];
    if (!items.length) {
      return res.status(400).json({ message: 'Order must contain at least one item.' });
    }

    const productIds = items.map((item) => item.productId || item.product_id).filter(Boolean);
    if (!productIds.length) {
      return res.status(400).json({ message: 'Each item must include a productId.' });
    }

    const placeholders = productIds.map(() => '?').join(',');
    const rows = await all(`SELECT * FROM products WHERE id IN (${placeholders})`, productIds);
    const productMap = new Map(rows.map((row) => [row.id, row]));

    let subtotal = 0;
    const normalizedItems = items.map((item) => {
      const product = productMap.get(item.productId || item.product_id);
      if (!product) {
        throw new Error('One or more products could not be found.');
      }
      if (String(product.status || '').toLowerCase() !== 'active') {
        throw new Error(`Product ${product.name} is not available.`);
      }
      const quantity = Number(item.quantity || 0);
      if (!Number.isInteger(quantity) || quantity <= 0) {
        throw new Error(`Invalid quantity for ${product.name}.`);
      }
      const unitPrice = Number(String(product.price || '0').replace(/[^\d.-]/g, '')) || 0;
      if (unitPrice < 0 || Number(product.stock || 0) < quantity) {
        throw new Error(`Insufficient stock for ${product.name}.`);
      }
      subtotal += unitPrice * quantity;
      return {
        productId: product.id,
        productName: product.name,
        quantity,
        unitPrice,
        lineTotal: unitPrice * quantity
      };
    });

    const paymentReference = `PAY-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
    const orderId = `ORD-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
    const orderPayload = {
      id: orderId,
      status: 'AWAITING_PAYMENT',
      paymentStatus: 'pending',
      total: subtotal,
      subtotal,
      customer: payload.customer || {},
      delivery: payload.delivery || {},
      items: normalizedItems,
      createdAt: new Date().toISOString(),
      paymentReference
    };

    await run('INSERT INTO orders (id, payload, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)', [orderId, JSON.stringify(orderPayload)]);
    const paymentId = `PAY-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
    await run(
      `INSERT INTO payments (id, order_id, payment_reference, method, amount_expected, amount_received, currency, status, customer_reference, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 0, 'LKR', 'pending', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
      [paymentId, orderId, paymentReference, payload.paymentMethod || 'bank_transfer', subtotal, payload.customer?.phone || payload.customer?.email || '']
    );
    await recordAuditLog({
      adminUserId: null,
      action: 'customer_order_created',
      entityType: 'orders',
      entityId: orderId,
      beforeValue: null,
      afterValue: orderPayload,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown'
    });
    res.status(201).json({ success: true, order: orderPayload, id: orderId, paymentReference });
  } catch (err) {
    return errorResponse(req, res, 400, err.message || 'Unable to create order.', process.env.NODE_ENV !== 'production' ? err.stack : undefined);
  }
});

app.post('/api/discounts', requireRole(...adminProductRoles), async (req, res) => {
  try {
    const code = req.body || {};
    const id = code.id || `disc-${Date.now()}`;
    await run(
      `INSERT INTO discount_codes (id, code, title, type, value, active, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(id) DO UPDATE SET
         code = excluded.code,
         title = excluded.title,
         type = excluded.type,
         value = excluded.value,
         active = excluded.active,
         updated_at = CURRENT_TIMESTAMP`,
      [id, (code.code || '').toUpperCase(), code.title || '', code.type || 'percent', Number(code.value || 0), code.active ? 1 : 0]
    );
    res.json({ success: true, id });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.put('/api/discounts/:id', requireRole(...adminProductRoles), async (req, res) => {
  try {
    const code = req.body || {};
    await run(
      'UPDATE discount_codes SET code = ?, title = ?, type = ?, value = ?, active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [(code.code || '').toUpperCase(), code.title || '', code.type || 'percent', Number(code.value || 0), code.active ? 1 : 0, req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.delete('/api/discounts/:id', requireRole(...adminProductRoles), async (req, res) => {
  try {
    await run('DELETE FROM discount_codes WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.get('/api/orders', requireRole(...adminOrderRoles), async (req, res) => {
  try {
    const rows = await all('SELECT * FROM orders ORDER BY updated_at DESC');
    res.json(rows.map(normalizeOrder));
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.post('/api/orders', requireRole(...adminOrderRoles), async (req, res) => {
  try {
    const order = req.body || {};
    const id = order.id || `OLK-${Date.now()}`;
    await run(
      `INSERT INTO orders (id, payload, updated_at)
       VALUES (?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(id) DO UPDATE SET
         payload = excluded.payload,
         updated_at = CURRENT_TIMESTAMP`,
      [id, JSON.stringify(order)]
    );
    res.json({ success: true, id });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.put('/api/orders/:id', requireRole(...adminOrderRoles), async (req, res) => {
  try {
    const order = req.body || {};
    const existingRow = await first('SELECT * FROM orders WHERE id = ? LIMIT 1', [req.params.id]);
    const existingPayload = existingRow ? parseJson(existingRow.payload, {}) : {};
    const currentStatus = String(existingPayload.status || 'NEW');
    const nextStatus = String(order.status || currentStatus);
    if (nextStatus !== currentStatus && (!orderStateTransitions[currentStatus] || !orderStateTransitions[currentStatus].includes(nextStatus))) {
      return res.status(400).json({ message: `Invalid order state transition from ${currentStatus} to ${nextStatus}.` });
    }

    const beforeOrder = { ...existingPayload };
    const updatedOrder = { ...existingPayload, ...order };
    await run('UPDATE orders SET payload = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [JSON.stringify(updatedOrder), req.params.id]);
    await recordAuditLog({
      adminUserId: req.adminSession?.userId || null,
      action: 'order_status_updated',
      entityType: 'orders',
      entityId: req.params.id,
      beforeValue: beforeOrder,
      afterValue: updatedOrder,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown'
    });
    res.json({ success: true });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.delete('/api/orders/:id', requireRole(...adminOrderRoles), async (req, res) => {
  try {
    await run('DELETE FROM orders WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.get('/api/bills', requireRole(...adminOrderRoles), async (req, res) => {
  try {
    const rows = await all('SELECT * FROM bills ORDER BY issued_at DESC');
    res.json(rows.map(normalizeBill));
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.post('/api/bills', requireRole(...adminOrderRoles), async (req, res) => {
  try {
    const bill = req.body || {};
    const id = bill.id || `INV-${Date.now()}`;
    const orderId = bill.orderId || bill.order_id || bill.order || '';
    const invoiceNumber = bill.invoiceNumber || `INV-${Date.now().toString().slice(-6)}`;
    await run(
      `INSERT INTO bills (id, order_id, invoice_number, payload, issued_at, updated_at)
       VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
       ON CONFLICT(id) DO UPDATE SET
         order_id = excluded.order_id,
         invoice_number = excluded.invoice_number,
         payload = excluded.payload,
         issued_at = CURRENT_TIMESTAMP,
         updated_at = CURRENT_TIMESTAMP`,
      [id, orderId, invoiceNumber, JSON.stringify(bill)]
    );
    res.json({ success: true, id });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.put('/api/bills/:id', requireRole(...adminOrderRoles), async (req, res) => {
  try {
    const bill = req.body || {};
    await run(
      'UPDATE bills SET order_id = ?, invoice_number = ?, payload = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [bill.orderId || bill.order_id || bill.order || '', bill.invoiceNumber || '', JSON.stringify(bill), req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.delete('/api/bills/:id', requireRole(...adminOrderRoles), async (req, res) => {
  try {
    await run('DELETE FROM bills WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.post('/api/collections/:collection', requireRole(...adminProductRoles), async (req, res) => {
  try {
    const collection = String(req.params.collection || '').toLowerCase();
    const payload = Array.isArray(req.body) ? req.body : (req.body ? [req.body] : []);
    const confirmBulkWrite = req.body && typeof req.body === 'object' && req.body.confirmBulkWrite === true;
    const collectionMap = {
      products: 'products',
      inventory: 'products',
      categories: 'categories',
      hero: 'hero_slides',
      heroes: 'hero_slides',
      discounts: 'discount_codes',
      orders: 'orders',
      bills: 'bills'
    };
    const target = collectionMap[collection];
    if (!target) {
      return res.status(400).json({ message: 'Unsupported collection.' });
    }
    if (!confirmBulkWrite && payload.length > 0) {
      return res.status(400).json({ message: 'Bulk write requires explicit confirmation.' });
    }

    if (target === 'products') {
      await run('DELETE FROM products');
      for (const item of payload) {
        const id = item.id || item.slug || `prod-${Date.now()}-${Math.random().toString(16).slice(2)}`;
        await run(
          `INSERT INTO products (id, slug, name, brand, cat, price, stock, image, status, description, source_url, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
          [id, item.slug || id, item.name || 'Product', item.brand || 'Oriflame', item.cat || 'Skincare', item.price || 'Rs. 0', Number(item.stock || 0), item.image || 'productImage.webp', item.status || 'Active', item.description || item.desc || '', item.sourceUrl || '']
        );
      }
    }

    if (target === 'categories') {
      await run('DELETE FROM categories');
      for (const item of payload) {
        const id = item.id || item.name || `cat-${Date.now()}-${Math.random().toString(16).slice(2)}`;
        await run('INSERT INTO categories (id, name, description, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)', [id, item.name || 'Category', item.description || '']);
      }
    }

    if (target === 'hero_slides') {
      await run('DELETE FROM hero_slides');
      for (const item of payload) {
        const id = item.id || `hero-${Date.now()}-${Math.random().toString(16).slice(2)}`;
        await run(
          'INSERT INTO hero_slides (id, productSlug, eyebrow, title, description, image, theme, themeColor, price, href, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
          [id, item.productSlug || '', item.eyebrow || '', item.title || 'Featured offer', item.description || '', item.image || 'productImage.webp', item.theme || 'custom', item.themeColor || '#cdeaa4', item.price || 'Shop now', item.href || 'index.html']
        );
      }
    }

    if (target === 'discount_codes') {
      await run('DELETE FROM discount_codes');
      for (const item of payload) {
        const id = item.id || `disc-${Date.now()}-${Math.random().toString(16).slice(2)}`;
        await run(
          'INSERT INTO discount_codes (id, code, title, type, value, active, updated_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
          [id, (item.code || '').toUpperCase(), item.title || '', item.type || 'percent', Number(item.value || 0), item.active ? 1 : 0]
        );
      }
    }

    if (target === 'orders') {
      await run('DELETE FROM orders');
      for (const item of payload) {
        const id = item.id || `OLK-${Date.now()}-${Math.random().toString(16).slice(2)}`;
        await run('INSERT INTO orders (id, payload, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)', [id, JSON.stringify(item)]);
      }
    }

    if (target === 'bills') {
      await run('DELETE FROM bills');
      for (const item of payload) {
        const id = item.id || `INV-${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const orderId = item.orderId || item.order_id || item.order || '';
        const invoiceNumber = item.invoiceNumber || `INV-${Date.now().toString().slice(-6)}`;
        await run('INSERT INTO bills (id, order_id, invoice_number, payload, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)', [id, orderId, invoiceNumber, JSON.stringify(item)]);
      }
    }

    res.json({ success: true });
  } catch (err) {
    return errorResponse(req, res, 500, 'Something went wrong.', process.env.NODE_ENV !== 'production' ? err.message : undefined);
  }
});

app.get('/admin.html', (req, res) => {
  if (!getSessionFromCookie(req.headers.cookie || '')) {
    return res.redirect('/admin-login.html');
  }
  return res.sendFile(path.join(rootDir, 'admin.html'));
});

app.get('/admin-login.html', (req, res) => {
  return res.sendFile(path.join(rootDir, 'admin-login.html'));
});

app.use(express.static(rootDir, {
  maxAge: '1h',
  setHeaders: (res, filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    if (['.html', '.json', '.xml', '.txt'].includes(ext)) {
      res.setHeader('Cache-Control', 'no-cache');
    }
    if (['.jpg', '.jpeg', '.png', '.svg', '.webp', '.avif', '.ico', '.gif', '.woff', '.woff2'].includes(ext)) {
      res.setHeader('Cache-Control', 'public, max-age=86400, immutable');
    }
  }
}));

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  const safeFile = req.path === '/' ? 'index.html' : req.path.replace(/^\//, '');
  const filePath = path.join(rootDir, safeFile);
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    res.sendFile(filePath);
    return;
  }
  res.sendFile(path.join(rootDir, 'index.html'));
});

connectDatabase()
  .then(() => initializeDatabase())
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running at http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Database startup error:', error.message);
    process.exit(1);
  });
