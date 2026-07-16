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
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS statuses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT NOT NULL,
      value TEXT,
      display TEXT,
      timestamp INTEGER,
      date TEXT,
      UNIQUE(key, date)
    )
  `);
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      content TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      date TEXT NOT NULL
    )
  `);
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

// ─── Logging ─────────────────────────────────────────────
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ─── DISABLE CACHING FOR API AND AUTH ROUTES ────────────
app.use((req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/auth')) {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    // Remove ETag to prevent 304
    res.setHeader('ETag', '');
    res.setHeader('Last-Modified', new Date().toUTCString());
  }
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
      path: '/',
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
      path: '/',
    });
    return res.json({ success: true });
  }
  res.status(401).json({ error: 'Invalid password' });
});

// ─── Status Routes ──────────────────────────────────────
app.get('/api/statuses', authMiddleware, async (req, res) => {
  const today = getTehranDate();
  const result = await turso.execute({
    sql: 'SELECT key, value, display, timestamp, date FROM statuses WHERE date = ?',
    args: [today],
  });
  const statuses = {};
  for (const row of result.rows) {
    statuses[row.key] = {
      value: row.value,
      display: row.display,
      timestamp: row.timestamp,
      date: row.date,
    };
  }
  ['caffeine', 'activity', 'mood'].forEach(k => {
    if (!statuses[k]) statuses[k] = null;
  });
  res.json({ statuses });
});

app.post('/api/status', authMiddleware, async (req, res) => {
  const { key, value, display } = req.body;
  if (!['caffeine', 'activity', 'mood'].includes(key)) {
    return res.status(400).json({ error: 'Invalid status key' });
  }
  const today = getTehranDate();
  const timestamp = Date.now();
  await turso.execute({
    sql: `INSERT INTO statuses (key, value, display, timestamp, date)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(key, date) DO UPDATE SET value = ?, display = ?, timestamp = ?`,
    args: [key, value, display || value, timestamp, today, value, display || value, timestamp],
  });
  res.json({ success: true, status: { value, display: display || value, timestamp, date: today } });
});

app.delete('/api/status', authMiddleware, async (req, res) => {
  const { key } = req.body;
  if (!['caffeine', 'activity', 'mood'].includes(key)) {
    return res.status(400).json({ error: 'Invalid status key' });
  }
  const today = getTehranDate();
  await turso.execute({
    sql: 'DELETE FROM statuses WHERE key = ? AND date = ?',
    args: [key, today],
  });
  res.json({ success: true });
});

// ─── Diary Entries Routes ──────────────────────────────
app.get('/api/entries', authMiddleware, async (req, res) => {
  const result = await turso.execute({
    sql: 'SELECT id, content, timestamp, date FROM entries ORDER BY timestamp DESC LIMIT 50',
  });
  res.json({ entries: result.rows });
});

app.post('/api/entries', authMiddleware, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim().length === 0) {
    return res.status(400).json({ error: 'Content is required' });
  }
  const timestamp = Date.now();
  const date = getTehranDate();
  await turso.execute({
    sql: 'INSERT INTO entries (content, timestamp, date) VALUES (?, ?, ?)',
    args: [content.trim(), timestamp, date],
  });
  res.json({ success: true });
});

app.delete('/api/entries/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  await turso.execute({
    sql: 'DELETE FROM entries WHERE id = ?',
    args: [id],
  });
  res.json({ success: true });
});

// ─── Public entries for homepage ────────────────────────
app.get('/api/public-entries', async (req, res) => {
  const result = await turso.execute({
    sql: 'SELECT id, content, timestamp FROM entries ORDER BY timestamp DESC LIMIT 10',
  });
  res.json({ entries: result.rows });
});

app.post('/api/logout', authMiddleware, (req, res) => {
  res.clearCookie('auth_token', { path: '/' });
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
