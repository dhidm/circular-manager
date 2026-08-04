const express = require('express');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcrypt');
const db = require('./database');

const app = express();
const PORT = 3000;

app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Session configuration
app.use(session({
  secret: 'your-secret-key-change-this-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // set to true if using HTTPS
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// =============================================================
// AUTHENTICATION MIDDLEWARE
// =============================================================

function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.status(401).json({ error: 'Unauthorized' });
}

// =============================================================
// AUTH ENDPOINTS
// =============================================================

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Set session
    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({ 
      success: true, 
      user: { id: user.id, username: user.username }
    });
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

// Check session
app.get('/api/session', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ 
      authenticated: true, 
      user: { id: req.session.userId, username: req.session.username }
    });
  } else {
    res.json({ authenticated: false });
  }
});

// Change password (authenticated)
app.post('/api/change-password', isAuthenticated, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }

  db.get(`SELECT * FROM users WHERE id = ?`, [req.session.userId], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.run(`UPDATE users SET password_hash = ? WHERE id = ?`, [hashedPassword, req.session.userId], (err) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to update password' });
      }
      res.json({ success: true, message: 'Password updated successfully' });
    });
  });
});

// =============================================================
// DATA ENDPOINTS (Protected)
// =============================================================

// GET all data
app.get('/api/data', isAuthenticated, (req, res) => {
  db.all(`SELECT name FROM years ORDER BY name`, (err, years) => {
    if (err) return res.status(500).json({ error: err.message });
    const yearNames = years.map(y => y.name);

    db.all(`SELECT * FROM descriptions ORDER BY category, description`, (err, descriptions) => {
      if (err) return res.status(500).json({ error: err.message });

      db.all(`SELECT y.name AS year, c.desc_id, c.numbers
              FROM circulars c
              JOIN years y ON c.year_id = y.id`, (err, circularRows) => {
        if (err) return res.status(500).json({ error: err.message });

        const circulars = {};
        circularRows.forEach(row => {
          if (!circulars[row.year]) circulars[row.year] = {};
          circulars[row.year][row.desc_id] = row.numbers;
        });

        db.all(`SELECT y.name AS year, f.desc_id, f.circular_number, f.file_name, f.file_data, f.file_path
                FROM files f
                JOIN years y ON f.year_id = y.id`, (err, fileRows) => {
          if (err) return res.status(500).json({ error: err.message });

          const files = {};
          fileRows.forEach(row => {
            if (!files[row.year]) files[row.year] = {};
            if (!files[row.year][row.desc_id]) files[row.year][row.desc_id] = {};
            files[row.year][row.desc_id][row.circular_number] = {
              fileName: row.file_name || '',
              fileData: row.file_data || '',
              filePath: row.file_path || ''
            };
          });

          db.all(`SELECT desc_id, note FROM notes`, (err, noteRows) => {
            if (err) return res.status(500).json({ error: err.message });
            const notes = {};
            noteRows.forEach(row => {
              notes[row.desc_id] = row.note;
            });

            db.get(`SELECT value FROM config WHERE key = 'basePath'`, (err, configRow) => {
              const basePath = configRow ? configRow.value : '';

              res.json({
                years: yearNames,
                descriptions,
                circulars,
                files,
                notes,
                basePath
              });
            });
          });
        });
      });
    });
  });
});

// POST /api/data (replace all data)
app.post('/api/data', isAuthenticated, (req, res) => {
  const data = req.body;
  if (!data.years || !data.descriptions || !data.circulars) {
    return res.status(400).json({ error: 'Invalid data structure' });
  }

  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    db.run('DELETE FROM files');
    db.run('DELETE FROM circulars');
    db.run('DELETE FROM notes');
    db.run('DELETE FROM descriptions');
    db.run('DELETE FROM years');
    db.run('DELETE FROM config');

    data.years.forEach(name => {
      db.run('INSERT INTO years (name) VALUES (?)', [name]);
    });

    data.descriptions.forEach(d => {
      db.run('INSERT INTO descriptions (id, description, category) VALUES (?, ?, ?)',
        [d.id, d.description, d.category]);
    });

    const yearMap = {};
    db.each('SELECT id, name FROM years', (err, row) => {
      yearMap[row.name] = row.id;
    }, (err) => {
      if (err) throw err;

      for (const year in data.circulars) {
        const yearId = yearMap[year];
        if (!yearId) continue;
        const descMap = data.circulars[year];
        for (const descId in descMap) {
          const numbers = descMap[descId];
          db.run('INSERT INTO circulars (year_id, desc_id, numbers) VALUES (?, ?, ?)',
            [yearId, parseInt(descId), numbers]);
        }
      }

      if (data.files) {
        for (const year in data.files) {
          const yearId = yearMap[year];
          if (!yearId) continue;
          const descFiles = data.files[year];
          for (const descId in descFiles) {
            const numMap = descFiles[descId];
            for (const num in numMap) {
              const entry = numMap[num];
              db.run(`INSERT INTO files (year_id, desc_id, circular_number, file_name, file_data, file_path)
                      VALUES (?, ?, ?, ?, ?, ?)`,
                [yearId, parseInt(descId), num, entry.fileName || '', entry.fileData || '', entry.filePath || '']);
            }
          }
        }
      }

      if (data.notes) {
        for (const descId in data.notes) {
          db.run('INSERT INTO notes (desc_id, note) VALUES (?, ?)',
            [parseInt(descId), data.notes[descId]]);
        }
      }

      if (data.basePath) {
        db.run('INSERT INTO config (key, value) VALUES (?, ?)', ['basePath', data.basePath]);
      }

      db.run('COMMIT', (err) => {
        if (err) {
          db.run('ROLLBACK');
          return res.status(500).json({ error: err.message });
        }
        res.json({ success: true });
      });
    });
  });
});

// Update basePath
app.post('/api/config/basePath', isAuthenticated, (req, res) => {
  const { basePath } = req.body;
  db.run(`INSERT OR REPLACE INTO config (key, value) VALUES ('basePath', ?)`, [basePath], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log('🔐 Default login: admin / admin123');
  console.log('📂 Open your browser and go to http://localhost:3000');
});