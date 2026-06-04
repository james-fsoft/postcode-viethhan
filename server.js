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

// Gửi file HTML kèm header chống cache (tránh trình duyệt giữ bản cũ sau khi deploy)
function sendPage(res, ...parts) {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.sendFile(path.join(__dirname, ...parts));
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
  sendPage(res, 'login.html');
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
    const data = await getJson(
      `https://www.juso.go.kr/addrlink/addrLinkApi.do`
      + `?currentPage=1&countPerPage=1`
      + `&keyword=${encodeURIComponent(q)}`
      + `&confmKey=${encodeURIComponent(confmKey)}`
      + `&resultType=json`
    );
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Gói dịch vụ ───────────────────────────────────────────────────────────────
const PLANS = {
  trial:      { maxLookups: 15, maxPerLookup: 30 },
  pro:        { maxLookups: 0,  maxPerLookup: 2000 },   // 0 = không giới hạn lượt
  enterprise: { maxLookups: 0,  maxPerLookup: 10000 },
};

// USER_PLANS env: "admin:trial,company1:pro" — mặc định trial
function getPlan(username) {
  const map = {};
  (process.env.USER_PLANS || '').split(',').forEach(p => {
    const i = p.indexOf(':');
    if (i > 0) map[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  const name = map[username] || 'trial';
  return { name, ...(PLANS[name] || PLANS.trial) };
}

// ── Bộ đếm lượt phía server (chống bypass) ───────────────────────────────────
// Dùng Redis REST (Vercel Storage / Upstash). Nhận nhiều tên biến môi trường.
const UPSTASH_URL   = process.env.UPSTASH_REDIS_REST_URL   || process.env.KV_REST_API_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
const useRedis = !!(UPSTASH_URL && UPSTASH_TOKEN);
const memUsage = new Map();

async function redisCmd(...parts) {
  const url = `${UPSTASH_URL}/${parts.map(encodeURIComponent).join('/')}`;
  const data = await getJson(url, { Authorization: `Bearer ${UPSTASH_TOKEN}` });
  return data.result;
}
async function getUsage(user) {
  if (useRedis) return parseInt(await redisCmd('get', `usage:${user}`) || '0', 10);
  return memUsage.get(user) || 0;
}
async function incUsage(user) {
  if (useRedis) return parseInt(await redisCmd('incr', `usage:${user}`), 10);
  const n = (memUsage.get(user) || 0) + 1;
  memUsage.set(user, n);
  return n;
}

function userFromReq(req) {
  try { return jwt.verify(req.cookies[COOKIE], JWT_SECRET).username; } catch { return null; }
}

// ── Config endpoint — PUBLIC: khách (chưa login) cũng dùng được ──────────────
app.get('/api/config', async (req, res) => {
  const username = userFromReq(req);
  const contact = process.env.CONTACT_INFO || 'support@transflash.app';
  const jusoKey = process.env.JUSO_API_KEY || null;

  // Khách: vào thẳng — tra tay tối đa 5, upload Excel tối đa 15 địa chỉ
  if (!username) {
    return res.json({
      jusoKey, username: null, plan: 'guest',
      maxLookups: 0, maxPerLookup: 5, maxUpload: 15,
      canUpload: true, isGuest: true, used: 0,
      redis: useRedis, contact,
    });
  }

  const plan = getPlan(username);
  let used = 0;
  try { used = await getUsage(username); } catch { /* ok */ }
  res.json({
    jusoKey, username,
    plan: plan.name,
    maxLookups: plan.maxLookups,
    maxPerLookup: plan.maxPerLookup,
    maxUpload: plan.maxPerLookup,
    canUpload: true, isGuest: false, used,
    redis: useRedis,
    contact,
  });
});

// ── Đăng ký 1 lượt tra cứu (kiểm tra + tăng đếm phía server) ─────────────────
app.post('/api/use', requireAuth, async (req, res) => {
  const username = userFromReq(req);
  if (!username) return res.status(401).json({ ok: false });
  const plan = getPlan(username);
  const count = parseInt(req.body.count || 0, 10);

  if (plan.maxPerLookup > 0 && count > plan.maxPerLookup)
    return res.json({ ok: false, reason: 'tooMany', max: plan.maxPerLookup });

  if (plan.maxLookups === 0)
    return res.json({ ok: true, unlimited: true });

  try {
    const used = await getUsage(username);
    if (used >= plan.maxLookups)
      return res.json({ ok: false, reason: 'limit', used, max: plan.maxLookups });
    const newUsed = await incUsage(username);
    return res.json({ ok: true, used: newUsed, left: Math.max(0, plan.maxLookups - newUsed), max: plan.maxLookups });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ── Trang giới thiệu / landing (PUBLIC, chuẩn SEO) ───────────────────────────
app.get('/about', (req, res) => {
  sendPage(res, 'views', 'landing.html');
});

// ── robots.txt + sitemap.xml (cho Google index) ──────────────────────────────
const SITE = process.env.SITE_URL || 'https://postcode-viethhan.vercel.app';
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(
    `User-agent: *\nAllow: /\nAllow: /about\nDisallow: /api/\nDisallow: /shipping\nDisallow: /login\n\nSitemap: ${SITE}/sitemap.xml\n`
  );
});
app.get('/sitemap.xml', (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  res.type('application/xml').send(
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
    `  <url><loc>${SITE}/about</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>1.0</priority></url>\n` +
    `  <url><loc>${SITE}/</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>\n` +
    `</urlset>\n`
  );
});

// ── Trang chính — PUBLIC: ai cũng vào được (khách hoặc đã login) ─────────────
app.get('/', (req, res) => {
  sendPage(res, 'views', 'app.html');
});

// ── Trang xử lý file vận đơn — chỉ gói Pro / Enterprise ──────────────────────
app.get('/shipping', requireAuth, (req, res) => {
  const username = userFromReq(req);
  const plan = getPlan(username);
  if (plan.name !== 'pro' && plan.name !== 'enterprise') {
    return res.redirect('/');   // không đủ quyền → về trang chính
  }
  sendPage(res, 'views', 'shipping.html');
});

// ── Start (bỏ qua khi Vercel import) ─────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Users: ${Object.keys(USERS).join(', ')}`);
  });
}

module.exports = app;
