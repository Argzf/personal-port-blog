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
const rateLimit = require('express-rate-limit');
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
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      content TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      date TEXT
    )
  `);
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS blacklist (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT UNIQUE NOT NULL,
      reason TEXT,
      created_at INTEGER
    )
  `);
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS request_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL,
      user_agent TEXT,
      path TEXT,
      method TEXT,
      timestamp INTEGER,
      is_admin INTEGER DEFAULT 0
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

// ─── Logging (only for requests) ────────────────────────
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ─── Cache‑control for API & auth ──────────────────────
app.use((req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/auth')) {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('ETag', '');
    res.setHeader('Last-Modified', new Date().toUTCString());
  }
  next();
});

// ─── Rate limiting for password login ────────────────────
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  message: { error: 'Too many login attempts. Please try again later.' },
  keyGenerator: (req) => req.ip,
  skipSuccessfulRequests: true,
});

// ─── Real IP helper ──────────────────────────────────────
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const realIp = req.headers['x-real-ip'];
  if (forwarded) return forwarded.split(',')[0].trim();
  if (realIp) return realIp;
  return req.ip || 'unknown';
}

// ─── Blacklist middleware ────────────────────────────────
async function isIpBlacklisted(ip) {
  const result = await turso.execute({
    sql: 'SELECT ip FROM blacklist WHERE ip = ?',
    args: [ip],
  });
  return result.rows.length > 0;
}

app.use(async (req, res, next) => {
  const ip = getClientIp(req);
  if (await isIpBlacklisted(ip)) {
    return res.status(403).send('Your IP has been blocked.');
  }
  next();
});

// ─── Session & Passport ──────────────────────────────────
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

// ─── Helpers ─────────────────────────────────────────────
function getTehranDate() {
  return new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Tehran' });
}

function isExpired(timestamp) {
  return (Date.now() - timestamp) > 24 * 60 * 60 * 1000;
}

// ─── Telegram Logger ──────────────────────────────────────
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

async function sendTelegramMessage(text) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
    console.warn('Telegram credentials missing. Message not sent:', text);
    return;
  }
  try {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: TELEGRAM_CHAT_ID,
        text: text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      }),
    });
  } catch (e) {
    console.error('Telegram send error:', e);
  }
}

function formatIpLink(ip) {
  return `<a href="https://whatismyipaddress.com/ip/${ip}">${ip}</a>`;
}

async function logAction(action, details = {}, req = null) {
  const ip = getClientIp(req);
  const userAgent = req?.get('user-agent') || 'unknown';
  const timestamp = Date.now();

  // Store request log for counting
  if (req) {
    await turso.execute({
      sql: `INSERT INTO request_logs (ip, user_agent, path, method, timestamp, is_admin) 
            VALUES (?, ?, ?, ?, ?, ?)`,
      args: [ip, userAgent, req.path, req.method, timestamp, req.user ? 1 : 0],
    });
  }

  const user = req?.user?.username || 'guest';
  const time = new Date(timestamp).toLocaleString('en-US', { timeZone: 'Asia/Tehran' });
  let msg = `<b>${action}</b>\n`;
  msg += `👤 ${user}\n`;
  msg += `🕒 ${time}\n`;
  if (ip !== 'unknown') msg += `🌐 ${formatIpLink(ip)}\n`;
  msg += `📱 ${userAgent}\n`;
  for (const [key, value] of Object.entries(details)) {
    msg += `🔹 ${key}: ${value}\n`;
  }
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  const countResult = await turso.execute({
    sql: 'SELECT COUNT(*) as count FROM request_logs WHERE ip = ? AND timestamp > ?',
    args: [ip, cutoff],
  });
  const count = countResult.rows[0]?.count || 0;
  msg += `📊 Requests (24h): ${count}`;

  await sendTelegramMessage(msg);
}

// ─── Middleware to log page visits ──────────────────────
app.use(async (req, res, next) => {
  const path = req.path;
  // Only log page views for homepage and admin
  if (path === '/' || path === '/admin' || path === '/admin/') {
    await logAction('Site Visit', { page: path }, req);
  }
  next();
});

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
    logAction('Discord Login', { user: user.username }, req);
    res.redirect('/admin');
  }
);

// ─── Password fallback login (with rate limiting) ──────
app.post('/auth/password', loginLimiter, async (req, res) => {
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
    await logAction('Admin Login', { method: 'password' }, req);
    return res.json({ success: true });
  }
  
  await logAction('Failed Login Attempt', { method: 'password' }, req);
  res.status(401).json({ error: 'Invalid password' });
});

// ─── Public statuses ─────────────────────────────────────
app.get('/api/statuses', async (req, res) => {
  const result = await turso.execute({
    sql: 'SELECT key, value, display, timestamp, date FROM statuses',
  });
  const statuses = {};
  for (const row of result.rows) {
    if (!isExpired(row.timestamp)) {
      statuses[row.key] = {
        value: row.value,
        display: row.display,
        timestamp: row.timestamp,
        date: row.date,
      };
    } else {
      await turso.execute({
        sql: 'DELETE FROM statuses WHERE key = ? AND timestamp = ?',
        args: [row.key, row.timestamp],
      });
    }
  }
  ['caffeine', 'activity', 'mood'].forEach(k => {
    if (!statuses[k]) statuses[k] = null;
  });
  res.json({ statuses });
});

// ─── Admin status operations ────────────────────────────
app.post('/api/status', authMiddleware, async (req, res) => {
  const { key, value, display } = req.body;
  if (!['caffeine', 'activity', 'mood'].includes(key)) {
    return res.status(400).json({ error: 'Invalid status key' });
  }
  const timestamp = Date.now();
  const date = getTehranDate();
  await turso.execute({
    sql: `INSERT INTO statuses (key, value, display, timestamp, date)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(key, date) DO UPDATE SET value = ?, display = ?, timestamp = ?`,
    args: [key, value, display || value, timestamp, date, value, display || value, timestamp],
  });
  await logAction('Status Updated', { key, value: display || value }, req);
  res.json({ success: true });
});

app.delete('/api/status', authMiddleware, async (req, res) => {
  const { key } = req.body;
  if (!['caffeine', 'activity', 'mood'].includes(key)) {
    return res.status(400).json({ error: 'Invalid status key' });
  }
  await turso.execute({
    sql: 'DELETE FROM statuses WHERE key = ?',
    args: [key],
  });
  await logAction('Status Cleared', { key }, req);
  res.json({ success: true });
});

// ─── Notes ──────────────────────────────────────────────
app.get('/api/notes', authMiddleware, async (req, res) => {
  const result = await turso.execute({
    sql: 'SELECT id, content, created_at, updated_at FROM notes ORDER BY created_at DESC',
  });
  const active = result.rows.filter(row => !isExpired(row.created_at));
  res.json({ notes: active });
});

app.post('/api/notes', authMiddleware, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim().length === 0) {
    return res.status(400).json({ error: 'Content is required' });
  }
  const now = Date.now();
  const date = getTehranDate();
  await turso.execute({
    sql: 'INSERT INTO notes (content, created_at, updated_at, date) VALUES (?, ?, ?, ?)',
    args: [content.trim(), now, now, date],
  });
  await logAction('Note Added', { content: content.trim().slice(0, 50) }, req);
  res.json({ success: true });
});

app.put('/api/notes/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { content } = req.body;
  if (!content || content.trim().length === 0) {
    return res.status(400).json({ error: 'Content is required' });
  }
  const now = Date.now();
  await turso.execute({
    sql: 'UPDATE notes SET content = ?, updated_at = ? WHERE id = ?',
    args: [content.trim(), now, id],
  });
  await logAction('Note Edited', { id, content: content.trim().slice(0, 50) }, req);
  res.json({ success: true });
});

app.delete('/api/notes/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const result = await turso.execute({
    sql: 'SELECT content FROM notes WHERE id = ?',
    args: [id],
  });
  const content = result.rows[0]?.content || 'unknown';
  await turso.execute({
    sql: 'DELETE FROM notes WHERE id = ?',
    args: [id],
  });
  await logAction('Note Deleted', { id, content: content.slice(0, 50) }, req);
  res.json({ success: true });
});

// ─── Diary entries ──────────────────────────────────────
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
  await logAction('Diary Entry Added', { content: content.trim().slice(0, 50) }, req);
  res.json({ success: true });
});

app.delete('/api/entries/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  await turso.execute({
    sql: 'DELETE FROM entries WHERE id = ?',
    args: [id],
  });
  await logAction('Diary Entry Deleted', { id }, req);
  res.json({ success: true });
});

app.get('/api/public-entries', async (req, res) => {
  const result = await turso.execute({
    sql: 'SELECT id, content, timestamp FROM entries ORDER BY timestamp DESC LIMIT 10',
  });
  res.json({ entries: result.rows });
});

// ─── Blacklist ──────────────────────────────────────────
app.get('/api/blacklist', authMiddleware, async (req, res) => {
  const result = await turso.execute('SELECT ip, reason, created_at FROM blacklist');
  res.json({ blacklist: result.rows });
});

app.post('/api/blacklist', authMiddleware, async (req, res) => {
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP is required' });
  try {
    await turso.execute({
      sql: 'INSERT INTO blacklist (ip, reason, created_at) VALUES (?, ?, ?)',
      args: [ip, reason || 'No reason provided', Date.now()],
    });
    await logAction('IP Blacklisted', { ip, reason }, req);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: 'IP already blacklisted or invalid' });
  }
});

app.delete('/api/blacklist/:ip', authMiddleware, async (req, res) => {
  const { ip } = req.params;
  await turso.execute({
    sql: 'DELETE FROM blacklist WHERE ip = ?',
    args: [ip],
  });
  await logAction('IP Removed from Blacklist', { ip }, req);
  res.json({ success: true });
});

// ─── Logout ──────────────────────────────────────────────
app.post('/api/logout', authMiddleware, async (req, res) => {
  await logAction('Admin Logout', {}, req);
  res.clearCookie('auth_token', { path: '/' });
  res.json({ success: true });
});

// ─── Current user ────────────────────────────────────────
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
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
