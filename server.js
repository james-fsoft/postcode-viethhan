require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const path = require('path');

// Node 18+ có fetch sẵn, Node 16 cần node-fetch
const fetch = globalThis.fetch ?? require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust Vercel / Railway reverse proxy for secure cookies
app.set('trust proxy', 1);

// Parse USERS env: "admin:pass123,user2:secret"
const USERS = {};
const usersEnv = process.env.USERS || `${process.env.ADMIN_USER || 'admin'}:${process.env.ADMIN_PASS || 'admin123'}`;
usersEnv.split(',').forEach(pair => {
  const idx = pair.indexOf(':');
  if (idx > 0) USERS[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
});

const JWT_SECRET = process.env.SESSION_SECRET || 'vh-logistics-change-this-secret';
const COOKIE = 'vh_token';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ── Auth middleware (JWT — stateless, works on Vercel serverless) ────────────
function requireAuth(req, res, next) {
  const token = req.cookies?.[COOKIE];
  if (token) {
    try { jwt.verify(token, JWT_SECRET); return next(); } catch { /* fall through */ }
  }
  if (req.headers.accept?.includes('application/json')) {
    return res.status(401).json({ ok: false, message: 'Unauthorized' });
  }
  res.clearCookie(COOKIE);
  res.redirect('/login');
}

// ── Public assets ────────────────────────────────────────────────────────────
app.get('/logo.png', (req, res) => res.sendFile(path.join(__dirname, 'logo.png')));

// ── Public routes ────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
  const token = req.cookies?.[COOKIE];
  try { if (token && jwt.verify(token, JWT_SECRET)) return res.redirect('/'); } catch { /* ok */ }
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/api/login', (req, res) => {
  const { username, password, remember } = req.body;
  if (USERS[username] && USERS[username] === password) {
    const expiresIn = remember === 'true' ? '30d' : '12h';
    const maxAge    = remember === 'true' ? 30 * 86400 * 1000 : 12 * 3600 * 1000;
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn });
    res.cookie(COOKIE, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge,
    });
    return res.json({ ok: true });
  }
  return res.status(401).json({ ok: false, message: 'Invalid credentials' });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE);
  res.json({ ok: true });
});

// ── Juso proxy (행정안전부 도로명주소 API) ────────────────────────────────────
app.get('/api/juso', requireAuth, async (req, res) => {
  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'Missing query' });

  const confmKey = req.headers['x-juso-key'] || process.env.JUSO_API_KEY;
  if (!confmKey) return res.status(400).json({ error: 'NO_KEY' });

  try {
    const url = `https://www.juso.go.kr/addrlink/addrLinkApi.do`
      + `?currentPage=1&countPerPage=1`
      + `&keyword=${encodeURIComponent(q)}`
      + `&confmKey=${encodeURIComponent(confmKey)}`
      + `&resultType=json`;
    const r = await fetch(url);
    const data = await r.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Protected routes ─────────────────────────────────────────────────────────
app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'app.html'));
});

// ── Start (skipped when imported by Vercel) ──────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Users: ${Object.keys(USERS).join(', ')}`);
  });
}

module.exports = app;
