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

if (!ALLOWED_IDS.length) {
  console.warn('⚠️ No Discord IDs allowed — set ALLOWED_DISCORD_IDS');
}

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

// ─── Password fallback login (FIXED) ────────────────────
app.post('/auth/password', (req, res) => {
  const { password } = req.body;
  
  // Log for debugging (without exposing the password)
  console.log('[Auth] Password login attempt received');
  console.log('[Auth] ADMIN_PASSWORD set:', !!process.env.ADMIN_PASSWORD);
  
  // Check if the environment variable is set
  const expectedPassword = process.env.ADMIN_PASSWORD;
  if (!expectedPassword) {
    console.error('[Auth] ADMIN_PASSWORD environment variable is not set!');
    return res.status(500).json({ 
      error: 'Password authentication is not configured. Please set ADMIN_PASSWORD in environment variables.' 
    });
  }
  
  // Trim both passwords to avoid whitespace issues
  const trimmedInput = password?.trim() || '';
  const trimmedExpected = expectedPassword.trim();
  
  console.log('[Auth] Password comparison:', {
    inputLength: trimmedInput.length,
    expectedLength: trimmedExpected.length,
  });
  
  // Compare the trimmed passwords
  if (trimmedInput === trimmedExpected) {
    console.log('[Auth] Password login successful');
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
  
  console.log('[Auth] Password login failed — incorrect password');
  res.status(401).json({ error: 'Invalid password' });
});

// ─── API Routes ──────────────────────────────────────────
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

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

app.post('/api/logout', authMiddleware, (req, res) => {
  res.clearCookie('auth_token');
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════════
//  STATIC FILES
// ════════════════════════════════════════════════════════════════

app.use(express.static(path.join(__dirname, '../public')));

app.get('/admin*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/index.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

module.exports = app;
