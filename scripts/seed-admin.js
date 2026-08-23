const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const rootDir = path.join(__dirname, '..');
const dataDir = path.join(rootDir, 'data');
const dbPath = path.join(dataDir, 'shop.db');
const email = (process.env.ADMIN_EMAIL || 'admin@example.com').trim().toLowerCase();
const password = process.env.ADMIN_PASSWORD || 'ChangeMe123!';
const salt = process.env.ADMIN_PASSWORD_SALT || process.env.SESSION_SECRET || 'default-admin-salt';

const hashPassword = (value) => crypto.pbkdf2Sync(String(value || ''), salt, 100000, 32, 'sha256').toString('hex');

fs.mkdirSync(dataDir, { recursive: true });

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Unable to open SQLite database for admin seeding:', err.message);
    process.exit(1);
  }

  db.run(
    `INSERT INTO admin_users (id, email, password_hash, role, status)
     VALUES (?, ?, ?, 'owner', 'active')
     ON CONFLICT(email) DO UPDATE SET
       password_hash = excluded.password_hash,
       role = excluded.role,
       status = excluded.status`,
    [`admin-${crypto.randomBytes(8).toString('hex')}`, email, hashPassword(password)],
    (insertErr) => {
      if (insertErr) {
        console.error('Admin seeding failed:', insertErr.message);
        db.close();
        process.exit(1);
      }

      console.log(`Seeded admin user: ${email}`);
      db.close();
    }
  );
});
