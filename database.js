const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

const db = new sqlite3.Database(path.join(__dirname, 'circular.db'));

// Initialize tables
db.serialize(() => {
  // Users table (for authentication)
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Years table
  db.run(`CREATE TABLE IF NOT EXISTS years (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE
  )`);

  // Descriptions table
  db.run(`CREATE TABLE IF NOT EXISTS descriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    description TEXT,
    category TEXT
  )`);

  // Circulars table
  db.run(`CREATE TABLE IF NOT EXISTS circulars (
    year_id INTEGER,
    desc_id INTEGER,
    numbers TEXT,
    FOREIGN KEY(year_id) REFERENCES years(id),
    FOREIGN KEY(desc_id) REFERENCES descriptions(id),
    PRIMARY KEY(year_id, desc_id)
  )`);

  // Files table
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

  // Notes table
  db.run(`CREATE TABLE IF NOT EXISTS notes (
    desc_id INTEGER PRIMARY KEY,
    note TEXT,
    FOREIGN KEY(desc_id) REFERENCES descriptions(id)
  )`);

  // Config table
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