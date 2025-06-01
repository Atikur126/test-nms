const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();

// Use dynamic port from environment variable or default to 3000 for local testing
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Serve index.html for the root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Database setup
const db = new sqlite3.Database(':memory:', (err) => {
  if (err) console.error(err.message);
  console.log('Connected to SQLite database');
});

db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);
  db.run(`CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    type TEXT,
    ip TEXT,
    status TEXT
  )`);
  db.run(`CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    time TEXT,
    severity TEXT
  )`);
  db.run(`CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    time TEXT
  )`);

  // Seed initial data
  const hashedPassword = bcrypt.hashSync('admin123', 8);
  db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, ['admin', hashedPassword, 'Admin']);
  db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, ['operator', bcrypt.hashSync('operator123', 8), 'Operator']);
  db.run(`INSERT INTO devices (name, type, ip, status) VALUES (?, ?, ?, ?)`, ['Huawei MA5800', 'OLT', '192.168.1.10', 'Online']);
  db.run(`INSERT INTO devices (name, type, ip, status) VALUES (?, ?, ?, ?)`, ['VSOL ONU', 'ONU', '192.168.1.11', 'Offline']);
  db.run(`INSERT INTO devices (name, type, ip, status) VALUES (?, ?, ?, ?)`, ['BDCOM GP3600', 'OLT', '192.168.1.12', 'Online']);
  db.run(`INSERT INTO alerts (message, time, severity) VALUES (?, ?, ?)`, ['ONU #2 Offline', '2025-06-02 03:00', 'Critical']);
  db.run(`INSERT INTO logs (message, time) VALUES (?, ?)`, ['System started', '2025-06-02 03:00']);
});

// Authentication middleware
const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token && req.path !== '/api/login' && req.path !== '/') return res.status(401).send('Access denied');
  try {
    if (token) {
      const decoded = jwt.verify(token, 'secret_key');
      req.user = decoded;
    }
    next();
  } catch (err) {
    res.status(400).send('Invalid token');
  }
};

// Routes
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).send('Invalid credentials');
    }
    const token = jwt.sign({ username, role: user.role }, 'secret_key', { expiresIn: '1h' });
    res.json({ token });
  });
});

app.get('/api/devices', authenticate, (req, res) => {
  db.all(`SELECT * FROM devices`, [], (err, rows) => {
    if (err) return res.status(500).send('Server error');
    res.json(rows);
  });
});

app.post('/api/devices', authenticate, (req, res) => {
  if (req.user.role !== 'Admin') return res.status(403).send('Access denied');
  const { name, type, ip, status } = req.body;
  db.run(`INSERT INTO devices (name, type, ip, status) VALUES (?, ?, ?, ?)`, [name, type, ip, status], (err) => {
    if (err) return res.status(500).send('Server error');
    res.status(201).send('Device added');
  });
});

app.get('/api/users', authenticate, (req, res) => {
  if (req.user.role !== 'Admin') return res.status(403).send('Access denied');
  db.all(`SELECT username, role FROM users`, [], (err, rows) => {
    if (err) return res.status(500).send('Server error');
    res.json(rows);
  });
});

app.post('/api/users', authenticate, async (req, res) => {
  if (req.user.role !== 'Admin') return res.status(403).send('Access denied');
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 8);
  db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, [username, hashedPassword, role], (err) => {
    if (err) return res.status(500).send('Server error');
    res.status(201).send('User added');
  });
});

app.get('/api/alerts', authenticate, (req, res) => {
  db.all(`SELECT * FROM alerts`, [], (err> rows) => {
    if (err) return res.status(500).send('Server error');
    res.json(rows);
  });
});

app.get('/api/logs', authenticate, (req, res) => {
  db.all(`SELECT * FROM logs`, [], (err, rows) => {
    if (err) return res.status(500).send('Server error');
    res.json(rows);
  });
});

app.get('/api/logs/export', authenticate, (req, res) => {
  db.all(`SELECT * FROM logs`, [], (err, rows) => {
    if (err) return res.status(500).send('Server error');
    res.json(rows);
  });
});

// Simulate real-time device status updates
setInterval(() => {
  db.all(`SELECT * FROM devices`, [], (err, devices) => {
    devices.forEach(device => {
      const status = Math.random() > 0.2 ? 'Online' : 'Offline';
      db.run(`UPDATE devices SET status = ? WHERE id = ?`, [status, device.id]);
      if (status === 'Offline') {
        db.run(`INSERT INTO alerts (message, time, severity) VALUES (?, ?, ?)`, 
          [`${device.name} went offline`, new Date().toISOString(), 'Critical']);
        db.run(`INSERT INTO logs (message, time) VALUES (?, ?)`, 
          [`${device.name} status changed to ${status}`, new Date().toISOString()]);
      }
    });
  });
}, 60000);

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
