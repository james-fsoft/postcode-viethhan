require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const https = require('https');
const http  = require('http');

const app = express();
const PORT = process.env.PORT || 3000;

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

// ── Helper: gọi HTTP/HTTPS, tự follow redirect, trả về JSON ─────────────────
function getJson(url, extraHeaders = {}, depth = 0) {
  return new Promise((resolve, reject) => {
    if (depth > 4) return reject(new Error('Too many redirects'));

    const parsed  = new URL(url);
    const lib     = parsed.protocol === 'https:' ? https : http;
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible)',
        'Accept':     'application/json',
        ...extraHeaders,
      },
    };

    const req = lib.request(options, (res) => {
      // Follow redirect
      if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
        res.resume();
        const loc     = res.headers.location || '';
        const nextUrl = loc.startsWith('http') ? loc : `${parsed.protocol}//${parsed.hostname}${loc}`;
        return getJson(nextUrl, extraHeaders, depth + 1).then(resolve).catch(reject);
      }

      let raw = '';
      res.on('data', d => { raw += d; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(raw));
        } catch {
          reject(new Error(`[HTTP ${res.statusCode}] ${raw.slice(0, 500)}`));
        }
      });
    });

    req.on('error', reject);
    req.end();
  });
}

// ── Auth middleware ───────────────────────────────────────────────────────────
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

// ── Public assets ─────────────────────────────────────────────────────────────
app.get('/logo.png', (req, res) => res.sendFile(path.join(__dirname, 'logo.png')));

// ── Public routes ─────────────────────────────────────────────────────────────
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

// ── Kakao Local API proxy ────────────────────────────────────────────────────
app.get('/api/kakao', requireAuth, async (req, res) => {
  const { q, type } = req.query;
  if (!q) return res.status(400).json({ error: 'Missing query' });

  const apiKey = req.headers['x-kakao-key'] || process.env.KAKAO_API_KEY;
  if (!apiKey) return res.status(400).json({ error: 'NO_KEY' });

  const host = type === 'keyword'
    ? 'dapi.kakao.com/v2/local/search/keyword.json'
    : 'dapi.kakao.com/v2/local/search/address.json';

  try {
    const data = await getJson(
      `https://${host}?query=${encodeURIComponent(q)}&size=1`,
      { Authorization: `KakaoAK ${apiKey}` }
    );
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Protected routes ──────────────────────────────────────────────────────────
app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'app.html'));
});

// ── Start (bỏ qua khi Vercel import) ─────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Users: ${Object.keys(USERS).join(', ')}`);
  });
}

module.exports = app;
