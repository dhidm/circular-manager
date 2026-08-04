const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

// Use persistent volume if available (Railway) or local file
const dbPath = process.env.DB_PATH || path.join(__dirname, 'circular.db');
const db = new sqlite3.Database(dbPath);

// ... rest of the code remains unchanged