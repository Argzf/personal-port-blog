// api/index.js
require('dotenv').config();
const express = require('express');
const { createClient } = require('@libsql/client');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');

const app = express();

// ─── Turso Database ──────────────────────────────────────
const turso = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

async function initDatabase() {
  // Statuses table
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS statuses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT NOT NULL,
      value TEXT,
      display TEXT,
      timestamp INTEGER,
      date TEXT,
      is_custom INTEGER DEFAULT 0,
      UNIQUE(key, date)
    )
  `);
  
  try {
    await turso.execute(`ALTER TABLE statuses ADD COLUMN is_custom INTEGER DEFAULT 0`);
  } catch (e) {}

  // Custom exhibits table (stores definitions for ALL exhibits)
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS custom_exhibits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT UNIQUE NOT NULL,
      label TEXT NOT NULL,
      icon TEXT,
      options TEXT,
      created_at INTEGER
    )
  `);
  
  // Seed default exhibits
  await seedDefaultExhibits();
}

async function seedDefaultExhibits() {
  const defaults = [
    { key: 'caffeine', label: 'caffeine', icon: '☕', options: JSON.stringify([{ value: 'tea', label: '🍵 Tea' }, { value: 'coffee', label: '☕ Coffee' }]) },
    { key: 'activity', label: 'activity', icon: '👤', options: JSON.stringify([{ value: 'coding', label: '💻 Coding' }, { value: 'reading', label: '📖 Reading' }, { value: 'exploring', label: '🗺️ Exploring' }, { value: 'hiking', label: '🥾 Hiking' }, { value: 'writing', label: '✍️ Writing' }, { value: 'thinking', label: '🤔 Thinking' }, { value: 'resting', label: '😴 Resting' }]) },
    { key: 'mood', label: 'mood', icon: '🎭', options: JSON.stringify([{ value: 'great', label: '😄 Great' }, { value: 'good', label: '🙂 Good' }, { value: 'okay', label: '😐 Okay' }, { value: 'meh', label: '😕 Meh' }, { value: 'bad', label: '😞 Bad' }]) },
  ];
  for (const def of defaults) {
    const exists = await turso.execute({ sql: 'SELECT key FROM custom_exhibits WHERE key = ?', args: [def.key] });
    if (exists.rows.length === 0) {
      await turso.execute({
        sql: 'INSERT INTO custom_exhibits (key, label, icon, options, created_at) VALUES (?, ?, ?, ?, ?)',
        args: [def.key, def.label, def.icon, def.options, Date.now()],
      });
    }
  }
}

initDatabase();

// ─── Middleware ──────────────────────────────────────────
app.use(cors({ 
  origin: process.env.VERCEL_URL || 'http://localhost:3000', 
  credentials: true 
}));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'dev-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.VERCEL === '1',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'lax',
  },
};
app.use(session(sessionConfig));
app.use(passport.initialize());
app.use(passport.session());

// ─── Passport (Discord) ──────────────────────────────────
const ALLOWED_IDS = (process.env.ALLOWED_DISCORD_IDS || '').split(',').map(id => id.trim()).filter(Boolean);

passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_REDIRECT_URI,
  scope: ['identify'],
}, (accessToken, refreshToken, profile, done) => {
  if (!ALLOWED_IDS.includes(profile.id)) {
    return done(null, false, { message: 'Unauthorized' });
  }
  return done(null, profile);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ─── JWT Helpers ─────────────────────────────────────────
function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, avatar: user.avatar },
    process.env.JWT_SECRET || 'dev-jwt-secret',
    { expiresIn: '7d' }
  );
}

function verifyToken(token) {
  try { return jwt.verify(token, process.env.JWT_SECRET || 'dev-jwt-secret'); }
  catch { return null; }
}

// ─── Auth Middleware ─────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.cookies?.auth_token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  const user = verifyToken(token);
  if (!user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user;
  next();
}

function getTehranDate() {
  return new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Tehran' });
}

// ════════════════════════════════════════════════════════════════
//  ROUTES
// ════════════════════════════════════════════════════════════════

// ─── Discord OAuth ──────────────────────────────────────
app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/admin?error=discord_failed' }),
  (req, res) => {
    const user = req.user;
    if (!user) return res.redirect('/admin?error=unauthorized');
    const token = generateToken({ id: user.id, username: user.username, avatar: user.avatar });
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.VERCEL === '1',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
    });
    res.redirect('/admin');
  }
);

// ─── Password fallback login ────────────────────────────
app.post('/auth/password', (req, res) => {
  const { password } = req.body;
  const expectedPassword = process.env.ADMIN_PASSWORD;
  if (!expectedPassword) {
    return res.status(500).json({ error: 'Password authentication not configured.' });
  }
  const trimmedInput = (password || '').trim();
  const trimmedExpected = expectedPassword.trim();
  if (trimmedInput === trimmedExpected) {
    const token = jwt.sign(
      { id: 'admin', username: 'admin', avatar: null },
      process.env.JWT_SECRET || 'dev-jwt-secret',
      { expiresIn: '7d' }
    );
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.VERCEL === '1',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
    });
    return res.json({ success: true });
  }
  res.status(401).json({ error: 'Invalid password' });
});

// ─── API Routes ──────────────────────────────────────────
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/statuses', authMiddleware, async (req, res) => {
  const today = getTehranDate();
  const result = await turso.execute({
    sql: 'SELECT key, value, display, timestamp, date, is_custom FROM statuses WHERE date = ?',
    args: [today],
  });
  const statuses = {};
  for (const row of result.rows) {
    statuses[row.key] = {
      value: row.value,
      display: row.display,
      timestamp: row.timestamp,
      date: row.date,
      is_custom: row.is_custom || 0,
    };
  }
  // Get all exhibit keys from custom_exhibits
  const defs = await turso.execute('SELECT key FROM custom_exhibits');
  for (const row of defs.rows) {
    if (!statuses[row.key]) statuses[row.key] = null;
  }
  res.json({ statuses });
});

app.get('/api/custom-exhibits', authMiddleware, async (req, res) => {
  const result = await turso.execute('SELECT key, label, icon, options, created_at FROM custom_exhibits ORDER BY created_at DESC');
  res.json({ exhibits: result.rows });
});

app.post('/api/custom-exhibits', authMiddleware, async (req, res) => {
  const { key, label, icon, options } = req.body;
  if (!key || !label) {
    return res.status(400).json({ error: 'Key and label are required' });
  }
  if (!/^[a-zA-Z0-9_]+$/.test(key)) {
    return res.status(400).json({ error: 'Key can only contain letters, numbers, and underscores' });
  }
  const existing = await turso.execute({
    sql: 'SELECT key FROM custom_exhibits WHERE key = ?',
    args: [key],
  });
  if (existing.rows.length > 0) {
    return res.status(400).json({ error: 'An exhibit with this key already exists' });
  }
  const optionsStr = options ? JSON.stringify(options) : '[]';
  const now = Date.now();
  await turso.execute({
    sql: 'INSERT INTO custom_exhibits (key, label, icon, options, created_at) VALUES (?, ?, ?, ?, ?)',
    args: [key, label, icon || '📌', optionsStr, now],
  });
  res.json({ success: true, exhibit: { key, label, icon: icon || '📌', options: options || [] } });
});

app.delete('/api/custom-exhibits/:key', authMiddleware, async (req, res) => {
  const { key } = req.params;
  const isDefault = ['caffeine', 'activity', 'mood'].includes(key);
  if (isDefault) {
    return res.status(400).json({ error: 'Cannot delete default exhibits' });
  }
  await turso.execute({
    sql: 'DELETE FROM custom_exhibits WHERE key = ?',
    args: [key],
  });
  await turso.execute({
    sql: 'DELETE FROM statuses WHERE key = ?',
    args: [key],
  });
  res.json({ success: true });
});

// ─── Option management ──────────────────────────────────
app.put('/api/exhibits/:key/options', authMiddleware, async (req, res) => {
  const { key } = req.params;
  const { value, label } = req.body;
  if (!value || !label) {
    return res.status(400).json({ error: 'Value and label are required' });
  }
  // Get current options
  const result = await turso.execute({
    sql: 'SELECT options FROM custom_exhibits WHERE key = ?',
    args: [key],
  });
  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Exhibit not found' });
  }
  let options = [];
  try {
    options = JSON.parse(result.rows[0].options || '[]');
  } catch { options = []; }
  
  // Check if value already exists
  if (options.some(o => o.value === value)) {
    return res.status(400).json({ error: 'Option already exists' });
  }
  
  options.push({ value, label });
  await turso.execute({
    sql: 'UPDATE custom_exhibits SET options = ? WHERE key = ?',
    args: [JSON.stringify(options), key],
  });
  res.json({ success: true, options });
});

app.delete('/api/exhibits/:key/options', authMiddleware, async (req, res) => {
  const { key } = req.params;
  const { value } = req.body;
  if (!value) {
    return res.status(400).json({ error: 'Value is required' });
  }
  const result = await turso.execute({
    sql: 'SELECT options FROM custom_exhibits WHERE key = ?',
    args: [key],
  });
  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Exhibit not found' });
  }
  let options = [];
  try {
    options = JSON.parse(result.rows[0].options || '[]');
  } catch { options = []; }
  
  const filtered = options.filter(o => o.value !== value);
  if (filtered.length === options.length) {
    return res.status(400).json({ error: 'Option not found' });
  }
  await turso.execute({
    sql: 'UPDATE custom_exhibits SET options = ? WHERE key = ?',
    args: [JSON.stringify(filtered), key],
  });
  res.json({ success: true, options: filtered });
});

// ─── Status set/clear ───────────────────────────────────
app.post('/api/status', authMiddleware, async (req, res) => {
  const { key, value, display } = req.body;
  const defCheck = await turso.execute({
    sql: 'SELECT key FROM custom_exhibits WHERE key = ?',
    args: [key],
  });
  if (defCheck.rows.length === 0) {
    return res.status(400).json({ error: 'Invalid status key' });
  }
  const today = getTehranDate();
  const timestamp = Date.now();
  const isCustom = !['caffeine', 'activity', 'mood'].includes(key) ? 1 : 0;
  await turso.execute({
    sql: `INSERT INTO statuses (key, value, display, timestamp, date, is_custom)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(key, date) DO UPDATE SET value = ?, display = ?, timestamp = ?`,
    args: [key, value, display || value, timestamp, today, isCustom, value, display || value, timestamp],
  });
  res.json({ success: true, status: { value, display: display || value, timestamp, date: today, is_custom: isCustom } });
});

app.delete('/api/status', authMiddleware, async (req, res) => {
  const { key } = req.body;
  const defCheck = await turso.execute({
    sql: 'SELECT key FROM custom_exhibits WHERE key = ?',
    args: [key],
  });
  if (defCheck.rows.length === 0) {
    return res.status(400).json({ error: 'Invalid status key' });
  }
  const today = getTehranDate();
  await turso.execute({
    sql: 'DELETE FROM statuses WHERE key = ? AND date = ?',
    args: [key, today],
  });
  res.json({ success: true });
});

app.post('/api/logout', authMiddleware, (req, res) => {
  res.clearCookie('auth_token');
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════════
//  STATIC FILES
// ════════════════════════════════════════════════════════════════

app.use(express.static(path.join(__dirname, '../public')));

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/index.html'));
});

app.get('/admin/*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/index.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

module.exports = app;
