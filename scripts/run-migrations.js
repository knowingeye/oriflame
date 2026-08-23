const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { Pool } = require('pg');

const rootDir = path.join(__dirname, '..');
const dataDir = path.join(rootDir, 'data');
const dbPath = path.join(dataDir, 'shop.db');
const migrationsDir = path.join(rootDir, 'migrations');
const migrationFiles = fs.readdirSync(migrationsDir)
  .filter((file) => file.endsWith('.sql'))
  .sort();

const applySqliteMigrations = () => new Promise((resolve, reject) => {
  fs.mkdirSync(dataDir, { recursive: true });

  const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
      reject(new Error(`Unable to open SQLite database for migrations: ${err.message}`));
      return;
    }

    if (!migrationFiles.length) {
      console.log('No migration files found.');
      db.close();
      resolve();
      return;
    }

    let index = 0;

    const runNext = () => {
      if (index >= migrationFiles.length) {
        console.log(`Applied ${migrationFiles.length} migration file(s).`);
        db.close();
        resolve();
        return;
      }

      const file = migrationFiles[index];
      const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      index += 1;

      db.exec(sql, (execErr) => {
        if (execErr) {
          console.error(`Migration failed for ${file}:`, execErr.message);
          db.close();
          reject(execErr);
          return;
        }
        console.log(`Applied migration: ${file}`);
        runNext();
      });
    };

    runNext();
  });
});

const applyPostgresMigrations = async () => {
  if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL is required to run PostgreSQL migrations.');
  }

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });

  if (!migrationFiles.length) {
    console.log('No migration files found.');
    await pool.end();
    return;
  }

  for (const file of migrationFiles) {
    const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    await pool.query(sql);
    console.log(`Applied migration: ${file}`);
  }

  console.log(`Applied ${migrationFiles.length} migration file(s).`);
  await pool.end();
};

(async () => {
  try {
    if (process.env.DATABASE_URL) {
      await applyPostgresMigrations();
      return;
    }

    await applySqliteMigrations();
  } catch (error) {
    console.error('Migration failed:', error.message);
    process.exit(1);
  }
})();
