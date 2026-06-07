require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs   = require('fs');
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

// ── Helper: gọi HTTP/HTTPS, tự follow redirect, trả về text thô (cho XML) ─────
function getText(url, extraHeaders = {}, depth = 0) {
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
        'Accept':     'application/xml, text/xml, */*',
        ...extraHeaders,
      },
    };

    const req = lib.request(options, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
        res.resume();
        const loc     = res.headers.location || '';
        const nextUrl = loc.startsWith('http') ? loc : `${parsed.protocol}//${parsed.hostname}${loc}`;
        return getText(nextUrl, extraHeaders, depth + 1).then(resolve).catch(reject);
      }
      let raw = '';
      res.on('data', d => { raw += d; });
      res.on('end', () => resolve(raw));
    });

    // Timeout 9s — tránh treo function nếu cổng :38010 bị chặn (Vercel egress)
    req.setTimeout(9000, () => req.destroy(new Error('UPSTREAM_TIMEOUT: không kết nối được tới máy chủ Hải quan (có thể bị chặn cổng/IP)')));
    req.on('error', reject);
    req.end();
  });
}

// Gửi file HTML kèm header chống cache (tránh trình duyệt giữ bản cũ sau khi deploy)
function sendPage(res, ...parts) {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.sendFile(path.join(__dirname, ...parts));
}

// Domain gốc — đổi domain chỉ cần sửa biến môi trường SITE_URL (1 chỗ duy nhất)
const BASE_URL = process.env.SITE_URL || 'https://postcode-viethhan.vercel.app';

// Trả trang HTML và chèn __BASE__ = domain hiện tại (+ các thay thế khác nếu có)
const _tplCache = {};
function sendTpl(res, file, extra = {}) {
  let html = _tplCache[file];
  if (!html || process.env.NODE_ENV !== 'production') {
    html = fs.readFileSync(path.join(__dirname, 'views', file), 'utf8');
    if (process.env.NODE_ENV === 'production') _tplCache[file] = html;
  }
  html = html.split('__BASE__').join(BASE_URL)
             .split('__BASE_HOST__').join(BASE_URL.replace(/^https?:\/\//, ''));
  for (const [k, v] of Object.entries(extra)) html = html.split(k).join(v);
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate').type('html').send(html);
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
app.get('/og.svg', (req, res) => {
  let svg = fs.readFileSync(path.join(__dirname, 'views', 'og.svg'), 'utf8')
    .split('__BASE_HOST__').join(BASE_URL.replace(/^https?:\/\//, ''));
  res.set('Cache-Control', 'public, max-age=86400').type('image/svg+xml').send(svg);
});

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
      + `?currentPage=1&countPerPage=10`
      + `&keyword=${encodeURIComponent(q)}`
      + `&confmKey=${encodeURIComponent(confmKey)}`
      + `&resultType=json`
    );
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── UNI-PASS proxy (관세청 화물통관진행정보 조회) ──────────────────────────────
// Tra trạng thái thông quan hàng nhập theo 화물관리번호 (cargMtNo) hoặc B/L (mblNo/hblNo + blYy)
// PUBLIC: khách (chưa login) cũng tra được đơn lẻ. Upload Excel hàng loạt do client chặn (cần login).
app.get('/api/cargo', async (req, res) => {
  let { cargMtNo, mblNo, hblNo, blYy } = req.query;
  if (!cargMtNo && !mblNo && !hblNo)
    return res.status(400).json({ error: 'Missing query' });

  const key = req.headers['x-unipass-key'] || process.env.UNIPASS_API_KEY;
  if (!key) return res.status(400).json({ error: 'NO_KEY' });

  let qs = `crkyCn=${encodeURIComponent(key)}`;
  if (cargMtNo) {
    qs += `&cargMtNo=${encodeURIComponent(String(cargMtNo).replace(/-/g, '').trim())}`;
  } else if (mblNo) {
    qs += `&mblNo=${encodeURIComponent(String(mblNo).trim())}&blYy=${encodeURIComponent(blYy || '')}`;
  } else if (hblNo) {
    qs += `&hblNo=${encodeURIComponent(String(hblNo).trim())}&blYy=${encodeURIComponent(blYy || '')}`;
  }

  try {
    const xml = await getText(
      `https://unipass.customs.go.kr:38010/ext/rest/cargCsclPrgsInfoQry/retrieveCargCsclPrgsInfo?${qs}`
    );
    res.type('application/xml').send(xml);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Tiện ích: tỷ giá KRW↔VND (proxy + cache 1h) ──────────────────────────────
let fxCache = null;
app.get('/api/fx', async (req, res) => {
  try {
    if (fxCache && Date.now() - fxCache.fetchedAt < 3600 * 1000) return res.json(fxCache);
    const data = await getJson('https://open.er-api.com/v6/latest/KRW');
    if (!data.rates || !data.rates.VND) throw new Error('NO_RATE');
    fxCache = { vnd: data.rates.VND, updated: data.time_last_update_utc || '', fetchedAt: Date.now() };
    res.json(fxCache);
  } catch (e) {
    if (fxCache) return res.json(fxCache);   // dùng bản cũ nếu lỗi
    res.status(500).json({ error: e.message });
  }
});

// ── Tiện ích: tỷ giá Vietcombank KRW (proxy + cache 1h) ──────────────────────
let vcbCache = null;
app.get('/api/vcb', async (req, res) => {
  try {
    if (vcbCache && Date.now() - vcbCache.fetchedAt < 3600 * 1000) return res.json(vcbCache);
    const data = await getJson('https://www.vietcombank.com.vn/api/exchangerates?date=now');
    const krw = (data.Data || []).find(x => x.currencyCode === 'KRW');
    if (!krw) throw new Error('NO_KRW');
    vcbCache = { cash: krw.cash, transfer: krw.transfer, sell: krw.sell, updated: data.UpdatedDate || '', fetchedAt: Date.now() };
    res.json(vcbCache);
  } catch (e) {
    if (vcbCache) return res.json(vcbCache);
    res.status(500).json({ error: e.message });
  }
});

// ── Tiện ích: lịch nghỉ lễ Hàn Quốc (proxy + cache 24h) ──────────────────────
const holCache = {};
app.get('/api/holidays', async (req, res) => {
  const year = /^\d{4}$/.test(req.query.year) ? req.query.year : String(new Date().getFullYear());
  try {
    if (holCache[year] && Date.now() - holCache[year].fetchedAt < 86400 * 1000) return res.json(holCache[year].list);
    const data = await getJson(`https://date.nager.at/api/v3/PublicHolidays/${year}/KR`);
    const list = (Array.isArray(data) ? data : []).map(h => ({ date: h.date, ko: h.localName, en: h.name }));
    holCache[year] = { list, fetchedAt: Date.now() };
    res.json(list);
  } catch (e) {
    if (holCache[year]) return res.json(holCache[year].list);
    res.status(500).json({ error: e.message });
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
  const unipassKey = !!process.env.UNIPASS_API_KEY;   // chỉ báo có/không, không lộ key

  // Khách: vào thẳng — tra tay từng địa chỉ, upload Excel tối đa 5 địa chỉ
  if (!username) {
    return res.json({
      jusoKey, unipassKey, username: null, plan: 'guest',
      maxLookups: 0, maxPerLookup: 5, maxUpload: 5,
      canUpload: true, isGuest: true, used: 0,
      redis: useRedis, contact,
    });
  }

  const plan = getPlan(username);
  let used = 0;
  try { used = await getUsage(username); } catch { /* ok */ }
  res.json({
    jusoKey, unipassKey, username,
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

// ── Trang giới thiệu / landing mã bưu điện (đa ngôn ngữ vi/en/ko) ────────────
app.get('/about', (req, res) => {
  const file = req.query.lang === 'ko' ? 'landing-ko.html'
             : req.query.lang === 'en' ? 'landing-en.html'
             : 'landing.html';
  sendTpl(res, file);
});

// ── Landing SEO cho công cụ tra cứu thông quan (đa ngôn ngữ vi/en/ko) ─────────
app.get('/tracking-info', (req, res) => {
  const file = req.query.lang === 'ko' ? 'tracking-landing-ko.html'
             : req.query.lang === 'en' ? 'tracking-landing-en.html'
             : 'tracking-landing.html';
  sendTpl(res, file);
});

// ── Bài hướng dẫn / glossary thuật ngữ thông quan (SEO + AEO) ─────────────────
app.get('/customs-guide', (req, res) => {
  sendTpl(res, 'customs-guide.html');
});

// ── Tiện ích logistics (tỷ giá, tính cước, lịch lễ, mã sân bay) ───────────────
app.get('/tools', (req, res) => {
  sendTpl(res, 'tools.html');
});

// ── Bài SEO: PCCC, quy định thực phẩm, quy trình XNK ─────────────────────────
app.get('/pccc',         (req, res) => sendTpl(res, 'pccc-guide.html'));
app.get('/food-korea',   (req, res) => sendTpl(res, 'food-korea.html'));
app.get('/import-guide', (req, res) => sendTpl(res, 'import-guide.html'));

// ── Tiện ích/cẩm nang cho người thường (size, du lịch, mua hàng Hàn) ─────────
app.get('/size-korea',     (req, res) => sendTpl(res, 'size-korea.html'));
app.get('/travel-korea',   (req, res) => sendTpl(res, 'travel-korea.html'));
app.get('/shopping-korea', (req, res) => sendTpl(res, 'shopping-korea.html'));
app.get('/ten-tieng-han',  (req, res) => sendTpl(res, 'korean-name.html'));
app.get('/nguoi-viet-o-han', (req, res) => sendTpl(res, 'nguoi-viet-o-han.html'));

// ── Trang tra cứu thông quan (UNI-PASS) — SEO đa ngôn ngữ (vi/en/ko) ──────────
const TRACKING_SEO = {
  vi: {
    title: 'Tra cứu thông quan Hàn Quốc theo số vận đơn (UNI-PASS) | Vietnam - Korea Logistics',
    desc:  'Tra cứu tiến trình thông quan hàng nhập khẩu Hàn Quốc theo số vận đơn HAWB hoặc mã quản lý hàng hóa — dữ liệu trực tiếp từ Hải quan Hàn Quốc (UNI-PASS). Hỗ trợ quét hàng loạt từ Excel, cho logistics Việt - Hàn.',
    kw:    'tra cứu thông quan Hàn Quốc, UNI-PASS, tra cứu vận đơn Hàn Quốc, HAWB, thông quan hàng nhập khẩu, logistics Việt Hàn, mã quản lý hàng hóa',
    locale: 'vi_VN', canon: '',
  },
  en: {
    title: 'Korea customs clearance tracking by B/L number (UNI-PASS) | Vietnam - Korea Logistics',
    desc:  'Track Korea import customs clearance progress by HAWB or cargo management number — data directly from Korea Customs (UNI-PASS). Batch lookup from Excel for Vietnam - Korea logistics.',
    kw:    'Korea customs tracking, UNI-PASS, cargo clearance Korea, HAWB lookup, import clearance status, Vietnam Korea logistics, cargo management number',
    locale: 'en_US', canon: '?lang=en',
  },
  ko: {
    title: '운송장 번호로 한국 통관 진행정보 조회 (UNI-PASS) | Vietnam - Korea Logistics',
    desc:  'HAWB 또는 화물관리번호로 한국 수입 통관 진행정보를 조회합니다. 관세청(UNI-PASS) 직접 연동, 엑셀 대량 조회 지원. 베트남-한국 물류 서비스.',
    kw:    '화물통관진행정보, UNI-PASS, 통관조회, HAWB 조회, 수입통관, 화물관리번호, 베트남 한국 물류',
    locale: 'ko_KR', canon: '?lang=ko',
  },
};
app.get('/tracking', (req, res) => {
  const lang = ['vi', 'en', 'ko'].includes(req.query.lang) ? req.query.lang : 'vi';
  const s = TRACKING_SEO[lang];
  sendTpl(res, 'tracking.html', {
    __LANG__: lang, __TITLE__: s.title, __DESC__: s.desc,
    __KEYWORDS__: s.kw, __LOCALE__: s.locale, __CANON__: s.canon,
  });
});

// ── robots.txt + sitemap.xml (cho Google index) ──────────────────────────────
const SITE = BASE_URL;
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(
    `User-agent: *\nAllow: /\nAllow: /about\nAllow: /tracking\nAllow: /tracking-info\nAllow: /customs-guide\nAllow: /tools\nAllow: /pccc\nAllow: /food-korea\nAllow: /import-guide\nAllow: /size-korea\nAllow: /travel-korea\nAllow: /shopping-korea\nAllow: /ten-tieng-han\nAllow: /nguoi-viet-o-han\nDisallow: /api/\nDisallow: /shipping\nDisallow: /login\n\nSitemap: ${SITE}/sitemap.xml\n`
  );
});
app.get('/sitemap.xml', (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  res.type('application/xml').send(
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n` +
    `  <url><loc>${SITE}/about</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>1.0</priority>` +
    `<xhtml:link rel="alternate" hreflang="vi" href="${SITE}/about"/>` +
    `<xhtml:link rel="alternate" hreflang="en" href="${SITE}/about?lang=en"/>` +
    `<xhtml:link rel="alternate" hreflang="ko" href="${SITE}/about?lang=ko"/></url>\n` +
    `  <url><loc>${SITE}/about?lang=en</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>\n` +
    `  <url><loc>${SITE}/about?lang=ko</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>\n` +
    `  <url><loc>${SITE}/</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>\n` +
    `  <url><loc>${SITE}/tracking</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.9</priority></url>\n` +
    `  <url><loc>${SITE}/tracking-info</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.9</priority>` +
    `<xhtml:link rel="alternate" hreflang="vi" href="${SITE}/tracking-info"/>` +
    `<xhtml:link rel="alternate" hreflang="en" href="${SITE}/tracking-info?lang=en"/>` +
    `<xhtml:link rel="alternate" hreflang="ko" href="${SITE}/tracking-info?lang=ko"/></url>\n` +
    `  <url><loc>${SITE}/tracking-info?lang=en</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>\n` +
    `  <url><loc>${SITE}/tracking-info?lang=ko</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>\n` +
    `  <url><loc>${SITE}/customs-guide</loc><lastmod>${today}</lastmod><changefreq>monthly</changefreq><priority>0.7</priority></url>\n` +
    `  <url><loc>${SITE}/tools</loc><lastmod>${today}</lastmod><changefreq>daily</changefreq><priority>0.7</priority></url>\n` +
    `  <url><loc>${SITE}/pccc</loc><lastmod>${today}</lastmod><changefreq>monthly</changefreq><priority>0.8</priority></url>\n` +
    `  <url><loc>${SITE}/food-korea</loc><lastmod>${today}</lastmod><changefreq>monthly</changefreq><priority>0.8</priority></url>\n` +
    `  <url><loc>${SITE}/import-guide</loc><lastmod>${today}</lastmod><changefreq>monthly</changefreq><priority>0.7</priority></url>\n` +
    `  <url><loc>${SITE}/size-korea</loc><lastmod>${today}</lastmod><changefreq>monthly</changefreq><priority>0.7</priority></url>\n` +
    `  <url><loc>${SITE}/travel-korea</loc><lastmod>${today}</lastmod><changefreq>monthly</changefreq><priority>0.8</priority></url>\n` +
    `  <url><loc>${SITE}/shopping-korea</loc><lastmod>${today}</lastmod><changefreq>monthly</changefreq><priority>0.8</priority></url>\n` +
    `  <url><loc>${SITE}/ten-tieng-han</loc><lastmod>${today}</lastmod><changefreq>monthly</changefreq><priority>0.8</priority></url>\n` +
    `  <url><loc>${SITE}/nguoi-viet-o-han</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.9</priority></url>\n` +
    `</urlset>\n`
  );
});

// ── Trang chính — PUBLIC: ai cũng vào được (khách hoặc đã login) ─────────────
app.get('/', (req, res) => {
  sendTpl(res, 'app.html');
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
