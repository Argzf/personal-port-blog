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
  // Statuses
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
  // Notes
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      content TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      date TEXT
    )
  `);
  // Blacklist
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS blacklist (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT UNIQUE NOT NULL,
      reason TEXT,
      created_at INTEGER
    )
  `);
  // Request logs
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS request_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL,
      user_agent TEXT,
      path TEXT,
      method TEXT,
      timestamp INTEGER,
      status_code INTEGER,
      is_admin INTEGER DEFAULT 0
    )
  `);
  // Entries (diary) – this table is critical
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      content TEXT NOT NULL,
      link TEXT,
      image_url TEXT,
      scheduled_at INTEGER,
      published INTEGER DEFAULT 0,
      timestamp INTEGER NOT NULL,
      date TEXT
    )
  `);
  // Silence logs
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS silence_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT NOT NULL,
      type TEXT DEFAULT 'ip',
      created_at INTEGER
    )
  `);
  // Reviews
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      message TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      date TEXT
    )
  `);
}
initDatabase();

// ─── Rate limiting ──────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please slow down.' },
  keyGenerator: (req) => getClientIp(req),
  skip: (req) => req.path === '/api/public-entries' || req.path === '/api/public-reviews' || req.path === '/api/statuses' || req.path === '/api/public-notes',
});

app.use('/api/', globalLimiter);

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  message: { error: 'Too many login attempts. Please try again later.' },
  keyGenerator: (req) => getClientIp(req),
  skipSuccessfulRequests: true,
});

// ─── Middleware ──────────────────────────────────────────
app.use(cors({ 
  origin: process.env.VERCEL_URL || 'http://localhost:3000', 
  credentials: true 
}));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── Logging with status code ──────────────────────────
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  const oldSend = res.send;
  res.send = function(data) {
    const statusCode = res.statusCode;
    const ip = getClientIp(req);
    const userAgent = req.get('user-agent') || 'unknown';
    const timestamp = Date.now();
    if (req.path.startsWith('/api') || req.path === '/' || req.path === '/admin' || req.path === '/admin/') {
      (async () => {
        try {
          await turso.execute({
            sql: `INSERT INTO request_logs (ip, user_agent, path, method, timestamp, status_code, is_admin)
                  VALUES (?, ?, ?, ?, ?, ?, ?)`,
            args: [ip, userAgent, req.path, req.method, timestamp, statusCode, req.user ? 1 : 0],
          });
        } catch (e) { console.error('Log insert error:', e); }
      })();
    }
    oldSend.apply(res, arguments);
  };
  next();
});

// ─── Cache‑control ──────────────────────────────────────
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

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const realIp = req.headers['x-real-ip'];
  if (forwarded) return forwarded.split(',')[0].trim();
  if (realIp) return realIp;
  return req.ip || 'unknown';
}

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
    return res.status(403).sendFile(path.join(__dirname, '../public/403.html'));
  }
  next();
});

async function shouldSilenceLog(ip, path) {
  const result = await turso.execute({
    sql: 'SELECT target FROM silence_logs WHERE target = ? OR target = ? OR target = ?',
    args: [ip, path, '*'],
  });
  return result.rows.length > 0;
}

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

function isExpired(timestamp) {
  return (Date.now() - timestamp) > 24 * 60 * 60 * 1000;
}

// ─── Telegram Logger ──────────────────────────────────────
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

async function sendTelegramMessage(text) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
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
  } catch (e) { console.error('Telegram error:', e); }
}

function formatIpLink(ip) {
  return `<a href="https://whatismyipaddress.com/ip/${ip}">${ip}</a>`;
}

async function logAction(action, details = {}, req = null, statusCode = 200) {
  const ip = getClientIp(req);
  const path = req?.path || '';
  if (await shouldSilenceLog(ip, path)) return;

  const userAgent = req?.get('user-agent') || 'unknown';
  const timestamp = Date.now();
  const user = req?.user?.username || 'guest';
  const time = new Date(timestamp).toLocaleString('en-US', { timeZone: 'Asia/Tehran' });
  let msg = `<b>${action}</b>\n`;
  msg += `👤 ${user}\n`;
  msg += `🕒 ${time}\n`;
  if (ip !== 'unknown') msg += `🌐 ${formatIpLink(ip)}\n`;
  msg += `📱 ${userAgent}\n`;
  msg += `📊 Status: ${statusCode}\n`;
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
    logAction('Discord Login', { user: user.username }, req, 302);
    res.redirect('/admin');
  }
);

// ─── Password login ──────────────────────────────────────
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
    await logAction('Admin Login', { method: 'password' }, req, 200);
    return res.json({ success: true });
  }
  await logAction('Failed Login Attempt', { method: 'password' }, req, 401);
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
  ['drinks', 'activity', 'mood'].forEach(k => {
    if (!statuses[k]) statuses[k] = null;
  });
  res.json({ statuses });
});

// ─── Admin status operations ────────────────────────────
app.post('/api/status', authMiddleware, async (req, res) => {
  const { key, value, display } = req.body;
  if (!['drinks', 'activity', 'mood'].includes(key)) {
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
  await logAction('Status Updated', { key, value: display || value }, req, 200);
  res.json({ success: true });
});

app.delete('/api/status', authMiddleware, async (req, res) => {
  const { key } = req.body;
  if (!['drinks', 'activity', 'mood'].includes(key)) {
    return res.status(400).json({ error: 'Invalid status key' });
  }
  await turso.execute({
    sql: 'DELETE FROM statuses WHERE key = ?',
    args: [key],
  });
  await logAction('Status Cleared', { key }, req, 200);
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
  await logAction('Note Added', { content: content.trim().slice(0, 50) }, req, 200);
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
  await logAction('Note Edited', { id, content: content.trim().slice(0, 50) }, req, 200);
  res.json({ success: true });
});

app.delete('/api/notes/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  await turso.execute({
    sql: 'DELETE FROM notes WHERE id = ?',
    args: [id],
  });
  await logAction('Note Deleted', { id }, req, 200);
  res.json({ success: true });
});

app.get('/api/public-notes', async (req, res) => {
  const result = await turso.execute({
    sql: 'SELECT id, content, created_at FROM notes ORDER BY created_at DESC LIMIT 20',
  });
  const active = result.rows.filter(row => !isExpired(row.created_at));
  res.json({ notes: active });
});

// ─── Diary entries (FIXED) ──────────────────────────────
app.get('/api/entries', authMiddleware, async (req, res) => {
  try {
    const now = Date.now();
    const result = await turso.execute({
      sql: `SELECT id, title, content, link, image_url, scheduled_at, published, timestamp 
            FROM entries 
            WHERE published = 1 OR (scheduled_at IS NULL OR scheduled_at <= ?)
            ORDER BY timestamp DESC LIMIT 50`,
      args: [now],
    });
    res.json({ entries: result.rows });
  } catch (error) {
    console.error('[Diary] GET /api/entries error:', error);
    res.status(500).json({ error: 'Failed to fetch diary entries' });
  }
});

app.post('/api/entries', authMiddleware, async (req, res) => {
  try {
    const { title, content, link, image_url, scheduled_at } = req.body;
    console.log('[Diary] POST /api/entries called with:', { title, content: content?.slice(0, 30), scheduled_at });

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: 'Content is required' });
    }

    const now = Date.now();
    const date = getTehranDate();
    let scheduled = scheduled_at ? parseInt(scheduled_at) : null;
    const published = (scheduled && scheduled > now) ? 0 : 1;
    if (!scheduled) scheduled = null;

    const result = await turso.execute({
      sql: `INSERT INTO entries (title, content, link, image_url, scheduled_at, published, timestamp, date) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [title || '', content.trim(), link || '', image_url || '', scheduled, published, now, date],
    });

    console.log('[Diary] Insert successful, row id:', result.lastInsertRowid);

    await logAction('Diary Entry Added', { title: title || 'Untitled' }, req, 200);
    res.json({ success: true });
  } catch (error) {
    console.error('[Diary] Error in POST /api/entries:', error);
    res.status(500).json({ error: 'Failed to create diary entry: ' + error.message });
  }
});

app.put('/api/entries/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content, link, image_url, scheduled_at } = req.body;
    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: 'Content is required' });
    }
    const now = Date.now();
    let scheduled = scheduled_at ? parseInt(scheduled_at) : null;
    const published = (scheduled && scheduled > now) ? 0 : 1;
    if (!scheduled) scheduled = null;
    await turso.execute({
      sql: `UPDATE entries 
            SET title = ?, content = ?, link = ?, image_url = ?, scheduled_at = ?, published = ? 
            WHERE id = ?`,
      args: [title || '', content.trim(), link || '', image_url || '', scheduled, published, id],
    });
    await logAction('Diary Entry Edited', { id, title: title || 'Untitled' }, req, 200);
    res.json({ success: true });
  } catch (error) {
    console.error('[Diary] PUT /api/entries/:id error:', error);
    res.status(500).json({ error: 'Failed to update diary entry' });
  }
});

app.delete('/api/entries/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await turso.execute({
      sql: 'DELETE FROM entries WHERE id = ?',
      args: [id],
    });
    await logAction('Diary Entry Deleted', { id }, req, 200);
    res.json({ success: true });
  } catch (error) {
    console.error('[Diary] DELETE /api/entries/:id error:', error);
    res.status(500).json({ error: 'Failed to delete diary entry' });
  }
});

app.get('/api/public-entries', async (req, res) => {
  try {
    const now = Date.now();
    const result = await turso.execute({
      sql: `SELECT id, title, content, link, image_url, timestamp 
            FROM entries 
            WHERE published = 1 AND (scheduled_at IS NULL OR scheduled_at <= ?)
            ORDER BY timestamp DESC LIMIT 10`,
      args: [now],
    });
    res.json({ entries: result.rows });
  } catch (error) {
    console.error('[Diary] GET /api/public-entries error:', error);
    res.status(500).json({ error: 'Failed to fetch public entries' });
  }
});

// ─── Silence logs ──────────────────────────────────────
app.get('/api/silence-logs', authMiddleware, async (req, res) => {
  const result = await turso.execute('SELECT id, target, type, created_at FROM silence_logs');
  res.json({ silenced: result.rows });
});

app.post('/api/silence-logs', authMiddleware, async (req, res) => {
  const { target, type } = req.body;
  if (!target) return res.status(400).json({ error: 'Target is required' });
  await turso.execute({
    sql: 'INSERT INTO silence_logs (target, type, created_at) VALUES (?, ?, ?)',
    args: [target, type || 'ip', Date.now()],
  });
  await logAction('Log Silence Added', { target, type }, req, 200);
  res.json({ success: true });
});

app.delete('/api/silence-logs/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  await turso.execute({
    sql: 'DELETE FROM silence_logs WHERE id = ?',
    args: [id],
  });
  await logAction('Log Silence Removed', { id }, req, 200);
  res.json({ success: true });
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
    await logAction('IP Blacklisted', { ip, reason }, req, 200);
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
  await logAction('IP Removed from Blacklist', { ip }, req, 200);
  res.json({ success: true });
});

// ─── Reviews ─────────────────────────────────────────────
app.get('/api/reviews', authMiddleware, async (req, res) => {
  const result = await turso.execute({
    sql: 'SELECT id, name, message, timestamp FROM reviews ORDER BY timestamp DESC LIMIT 100',
  });
  res.json({ reviews: result.rows });
});

app.post('/api/reviews', authMiddleware, async (req, res) => {
  const { name, message } = req.body;
  if (!name || name.trim().length === 0 || !message || message.trim().length === 0) {
    return res.status(400).json({ error: 'Name and message are required' });
  }
  const now = Date.now();
  const date = getTehranDate();
  await turso.execute({
    sql: 'INSERT INTO reviews (name, message, timestamp, date) VALUES (?, ?, ?, ?)',
    args: [name.trim(), message.trim(), now, date],
  });
  await logAction('Review Added', { name, message: message.trim().slice(0, 50) }, req, 200);
  res.json({ success: true });
});

app.delete('/api/reviews/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  await turso.execute({
    sql: 'DELETE FROM reviews WHERE id = ?',
    args: [id],
  });
  await logAction('Review Deleted', { id }, req, 200);
  res.json({ success: true });
});

app.get('/api/public-reviews', async (req, res) => {
  const result = await turso.execute({
    sql: 'SELECT name, message, timestamp FROM reviews ORDER BY timestamp DESC LIMIT 20',
  });
  res.json({ reviews: result.rows });
});

// ─── Logout ──────────────────────────────────────────────
app.post('/api/logout', authMiddleware, async (req, res) => {
  await logAction('Admin Logout', {}, req, 200);
  res.clearCookie('auth_token', { path: '/' });
  res.json({ success: true });
});

// ─── Current user ────────────────────────────────────────
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// ════════════════════════════════════════════════════════════════
//  STATIC FILES & FALLBACKS
// ════════════════════════════════════════════════════════════════
app.use(express.static(path.join(__dirname, '../public')));

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/index.html'));
});
app.get('/admin/*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/index.html'));
});

app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  res.status(404).sendFile(path.join(__dirname, '../public/404.html'));
});

module.exports = app;