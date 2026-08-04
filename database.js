const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

// Use persistent volume if available (Railway) or local file
const dbPath = process.env.DB_PATH || path.join(__dirname, 'circular.db');
const db = new sqlite3.Database(dbPath);

// Initialize tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS years (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS descriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    description TEXT,
    category TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS circulars (
    year_id INTEGER,
    desc_id INTEGER,
    numbers TEXT,
    FOREIGN KEY(year_id) REFERENCES years(id),
    FOREIGN KEY(desc_id) REFERENCES descriptions(id),
    PRIMARY KEY(year_id, desc_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS files (
    year_id INTEGER,
    desc_id INTEGER,
    circular_number TEXT,
    file_name TEXT,
    file_data TEXT,
    file_path TEXT,
    FOREIGN KEY(year_id, desc_id) REFERENCES circulars(year_id, desc_id),
    PRIMARY KEY(year_id, desc_id, circular_number)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS notes (
    desc_id INTEGER PRIMARY KEY,
    note TEXT,
    FOREIGN KEY(desc_id) REFERENCES descriptions(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
  )`);

  // Create default admin user if not exists
  db.get(`SELECT * FROM users WHERE username = 'admin'`, async (err, row) => {
    if (err) {
      console.error('Error checking admin user:', err);
      return;
    }
    if (!row) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      db.run(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, ['admin', hashedPassword], (err) => {
        if (err) {
          console.error('Error creating admin user:', err);
        } else {
          console.log('✅ Default admin user created (username: admin, password: admin123)');
        }
      });
    }
  });
});

module.exports = db;