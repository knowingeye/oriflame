CREATE TABLE IF NOT EXISTS admin_users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'admin',
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  payment_reference TEXT UNIQUE NOT NULL,
  method TEXT NOT NULL,
  amount_expected REAL NOT NULL DEFAULT 0,
  amount_received REAL NOT NULL DEFAULT 0,
  currency TEXT DEFAULT 'LKR',
  status TEXT DEFAULT 'pending',
  customer_reference TEXT,
  verified_by TEXT,
  verified_at TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  admin_user_id TEXT,
  action TEXT,
  entity_type TEXT,
  entity_id TEXT,
  before_value TEXT,
  after_value TEXT,
  ip_address TEXT,
  user_agent TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
