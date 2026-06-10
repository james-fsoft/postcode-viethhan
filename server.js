require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs   = require('fs');
const https = require('https');
const http  = require('http');
const zlib  = require('zlib');

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
// Để trống = chỉ dùng trên domain hiện tại. Đặt '.transflash.app' để dùng CHUNG đăng nhập
// giữa các subdomain (vd app.transflash.app + ketoan.transflash.app) — đăng nhập 1 lần.
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;
function authCookieOpts(extra = {}) {
  return { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/', domain: COOKIE_DOMAIN, ...extra };
}

app.use(express.json({ limit: '12mb' }));   // 12mb: đủ cho dữ liệu kế toán VC24 upload
app.use(express.urlencoded({ extended: true, limit: '12mb' }));
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
  res.clearCookie(COOKIE, authCookieOpts());
  res.redirect('/login');
}

// ── Public assets ─────────────────────────────────────────────────────────────
app.get('/logo.png', (req, res) => res.sendFile(path.join(__dirname, 'logo.png')));
app.get('/logo.svg', (req, res) => {
  res.set('Cache-Control', 'public, max-age=86400').type('image/svg+xml')
     .send(fs.readFileSync(path.join(__dirname, 'views', 'logo.svg'), 'utf8'));
});
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
    res.cookie(COOKIE, token, authCookieOpts({ maxAge }));
    return res.json({ ok: true });
  }
  return res.status(401).json({ ok: false, message: 'Invalid credentials' });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE, authCookieOpts());
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
// Lưu/đọc chuỗi lớn (JSON) — dùng POST body để không vướng giới hạn độ dài URL
async function redisSet(key, value) {
  if (!useRedis) return false;
  try {
    const r = await fetch(`${UPSTASH_URL}/set/${encodeURIComponent(key)}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` },
      body: String(value),
    });
    return r.ok;
  } catch { return false; }
}
async function redisGet(key) {
  if (!useRedis) return null;
  try {
    const r = await fetch(`${UPSTASH_URL}/get/${encodeURIComponent(key)}`, {
      headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` },
    });
    if (!r.ok) return null;
    const j = await r.json();
    return j.result;
  } catch { return null; }
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

// Trang "trung tâm" riêng theo account. Thêm user mới -> thêm 1 dòng tương ứng.
const USER_HUBS = {
  vhpro: { url: '/vc24global-main', label: '🏢 VC24 Global' },
};

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
    hub: USER_HUBS[username] || null,
  });
});

// Script dùng chung: chèn nút nổi dẫn tới "trung tâm" của user (nếu có)
app.get('/userhub.js', (req, res) => {
  res.type('application/javascript').set('Cache-Control', 'public, max-age=300').send(
    `(function(){try{fetch('/api/config').then(function(r){return r.json()}).then(function(c){`
    + `if(!c||!c.hub||!c.hub.url)return;`
    + `if(location.pathname===c.hub.url)return;`
    + `var st=document.createElement('style');`
    + `st.textContent='#userHubBtn{position:fixed;right:18px;bottom:18px;z-index:60;display:inline-flex;align-items:center;gap:7px;font-family:Segoe UI,Arial,sans-serif;font-size:.85rem;font-weight:700;color:#fff;background:linear-gradient(135deg,#4f46e5,#7c3aed);border:none;border-radius:99px;padding:11px 18px;box-shadow:0 8px 24px -6px rgba(79,70,229,.5);text-decoration:none;transition:transform .14s,box-shadow .16s}#userHubBtn:hover{transform:translateY(-2px);box-shadow:0 12px 30px -6px rgba(79,70,229,.6)}@media print{#userHubBtn{display:none}}';`
    + `document.head.appendChild(st);`
    + `var a=document.createElement('a');a.id='userHubBtn';a.href=c.hub.url;a.textContent=c.hub.label||'Trang của tôi';`
    + `(document.body||document.documentElement).appendChild(a);`
    + `}).catch(function(){})}catch(e){}})();`
  );
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

// ── Trang riêng theo công ty — mỗi công ty 1 account + 1 file để tuỳ biến ────
// VC24 Global: chỉ account 'vhpro' mới vào được. Bản sao của /tracking để sau
// này sửa format Excel / cách xử lý riêng mà không ảnh hưởng trang chung.
// Trung tâm điều khiển VC24 (hub) — chỉ account 'vhpro'
app.get('/vc24global-main', requireAuth, (req, res) => {
  if (userFromReq(req) !== 'vhpro') return res.redirect('/');
  sendTpl(res, 'vc24global-main.html');
});
app.get('/vc24global', requireAuth, (req, res) => {
  if (userFromReq(req) !== 'vhpro') return res.redirect('/');
  sendTpl(res, 'vc24global.html');
});
// Kế toán & công nợ VC24 Global — chỉ account 'vhpro'
app.get('/vc24/ke-toan', requireAuth, (req, res) => {
  if (userFromReq(req) !== 'vhpro') return res.redirect('/');
  sendTpl(res, 'ketoan.html');
});

// ── API lưu trữ dữ liệu kế toán VC24 (Redis) — chỉ account 'vhpro' ───────────
function requireVC24(req, res, next) {
  if (userFromReq(req) !== 'vhpro') return res.status(403).json({ ok: false, message: 'forbidden' });
  next();
}
const VK = { orders: 'vc24:ketoan:orders', cfg: 'vc24:ketoan:cfg', ledger: 'vc24:ketoan:ledger',
  draft: 'vc24:ketoan:draft', uploads: 'vc24:ketoan:uploads', log: 'vc24:ketoan:log', rates: 'vc24:ketoan:rates' };
// nén chung cho mọi JSON
function gzPack(o) { try { return 'gz:' + zlib.gzipSync(Buffer.from(JSON.stringify(o), 'utf8')).toString('base64'); } catch { return JSON.stringify(o); } }
function gzUnpack(s, d) { if (!s) return d; try { const j = (typeof s === 'string' && s.startsWith('gz:')) ? zlib.gunzipSync(Buffer.from(s.slice(3), 'base64')).toString('utf8') : s; return JSON.parse(j); } catch { return d; } }
// Ghi nhật ký thao tác (bounded)
async function vcLog(action, detail) {
  if (!useRedis) return;
  let log = gzUnpack(await redisGet(VK.log), []); if (!Array.isArray(log)) log = [];
  log.push({ at: new Date().toISOString(), action: String(action || ''), detail: String(detail || '') });
  if (log.length > 800) log = log.slice(-800);
  await redisSet(VK.log, gzPack(log));
}
const isPaidPay = p => String(p || '').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/đ/gi, 'd').toUpperCase().trim() === 'DA TT';
const VC24_EDITABLE = new Set(['date','status','cust','pay','note','rcv','rcvPh','addr','region','weight','price','won','vnd','phuPhi','ghiChu','staff','paidDate','week']);
const keyOf = r => r && (r.key || r.pkg);
const VC_EMPTY = () => ({ rows: [], fileName: '', uploadedAt: null });
// Nén (gzip→base64) để khối dữ liệu nhỏ hơn nhiều lần, tránh vượt giới hạn ghi của Redis
function vcPack(o) {
  const json = JSON.stringify(o);
  try { return 'gz:' + zlib.gzipSync(Buffer.from(json, 'utf8')).toString('base64'); }
  catch { return json; }
}
function vcUnpack(s) {
  if (!s) return VC_EMPTY();
  try {
    const json = (typeof s === 'string' && s.startsWith('gz:'))
      ? zlib.gunzipSync(Buffer.from(s.slice(3), 'base64')).toString('utf8') : s;
    const o = JSON.parse(json);
    return (o && Array.isArray(o.rows)) ? o : VC_EMPTY();
  } catch { return VC_EMPTY(); }
}
async function vcLoadOrders() { return vcUnpack(await redisGet(VK.orders)); }
const vcSaveOrders = o => redisSet(VK.orders, vcPack(o));   // trả về true/false (ghi thành công?)

app.get('/api/vc24/data', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: true, redis: false, rows: [], cfg: {} });
  const [o, cfg, ledg, drf, rt] = await Promise.all([vcLoadOrders(), redisGet(VK.cfg), redisGet(VK.ledger), redisGet(VK.draft), redisGet(VK.rates)]);
  let c = {}; try { c = cfg ? JSON.parse(cfg) : {}; } catch { /* ok */ }
  let ledger = {}; try { ledger = ledg ? JSON.parse(ledg) : {}; } catch { /* ok */ }
  let rates = {}; try { rates = rt ? JSON.parse(rt) : {}; } catch { /* ok */ }
  const draft = gzUnpack(drf, null);
  res.json({ ok: true, redis: true, rows: o.rows, fileName: o.fileName, uploadedAt: o.uploadedAt, cfg: c, ledger, draft, rates });
});

// Giá vận chuyển/kg theo khu vực cho từng tuần
app.post('/api/vc24/rates', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { week, rates } = req.body || {};
  if (!/^\d{4}-W\d{2}$/.test(String(week || ''))) return res.json({ ok: false, reason: 'week' });
  let all = {}; try { const s = await redisGet(VK.rates); if (s) all = JSON.parse(s); } catch { /* ok */ }
  const clean = {};
  if (rates && typeof rates === 'object') for (const k of Object.keys(rates)) { const v = Math.round(Number(rates[k]) || 0); if (v > 0) clean[k] = v; }
  all[week] = clean;
  const ok = await redisSet(VK.rates, JSON.stringify(all));
  if (!ok) return res.json({ ok: false, reason: 'save' });
  await vcLog('rates', `Cài giá VC tuần ${week}: ${Object.entries(clean).map(([k, v]) => k + '=' + v).join(', ') || '(trống)'}`);
  res.json({ ok: true });
});

// Thu tiền theo SỐ TIỀN (hỗ trợ trả từng phần) + ghi lịch sử
app.post('/api/vc24/payment', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { cust, amount, date, settleAll } = req.body || {};
  const amt = Math.round(Number(amount) || 0);
  if (!cust || amt <= 0) return res.json({ ok: false, message: 'bad' });
  const o = await vcLoadOrders();
  let ledger = {}; try { const s = await redisGet(VK.ledger); if (s) ledger = JSON.parse(s); } catch { /* ok */ }
  const led = ledger[cust] || { credit: 0, history: [] };
  let credit = (Number(led.credit) || 0) + amt;
  const unpaid = o.rows.filter(r => r.cust === cust && !isPaidPay(r.pay)).sort((a, b) => String(a.date).localeCompare(String(b.date)));
  let marked = 0; const markedKeys = [];
  if (settleAll) {
    // Trả đủ/đủ-hơn -> gạch SẠCH mọi đơn (tránh sót vài đồng do số quá lớn mất chính xác)
    const totalUnpaid = unpaid.reduce((s, r) => s + (Number(r.won) || 0), 0);
    unpaid.forEach(r => { r.pay = 'ĐÃ TT'; if (date) r.paidDate = String(date); marked++; markedKeys.push(keyOf(r)); });
    credit = Math.max(0, credit - totalUnpaid);
  } else {
    // Trả từng phần: gạch nợ dần các đơn cũ nhất khi đủ tiền
    for (const r of unpaid) { const w = Number(r.won) || 0; if (w > 0 && credit >= w) { r.pay = 'ĐÃ TT'; if (date) r.paidDate = String(date); credit -= w; marked++; markedKeys.push(keyOf(r)); } }
  }
  led.credit = credit;
  led.history = led.history || [];
  led.history.push({ date: String(date || ''), amount: amt, marked, keys: markedKeys, at: new Date().toISOString() });
  ledger[cust] = led;
  const s1 = await vcSaveOrders(o);
  const s2 = await redisSet(VK.ledger, JSON.stringify(ledger));
  if (!s1 || !s2) return res.json({ ok: false, reason: 'save' });
  await vcLog('payment', `Thu ₩${amt.toLocaleString('en-US')} của ${cust} (gạch ${marked} đơn)`);
  res.json({ ok: true, marked, credit });
});

// Phí phát sinh theo khách hàng (KRW) — ghi trên hóa đơn, lưu lại
app.post('/api/vc24/surcharge', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { cust, amount, note } = req.body || {};
  if (!cust) return res.json({ ok: false, message: 'bad' });
  let ledger = {}; try { const s = await redisGet(VK.ledger); if (s) ledger = JSON.parse(s); } catch { /* ok */ }
  const led = ledger[cust] || { credit: 0, history: [] };
  led.surcharge = Math.round(Number(amount) || 0);
  led.surchargeNote = String(note || '').slice(0, 200);
  ledger[cust] = led;
  const ok = await redisSet(VK.ledger, JSON.stringify(ledger));
  if (!ok) return res.json({ ok: false, reason: 'save' });
  await vcLog('surcharge', `Phí phát sinh ${cust}: ₩${led.surcharge.toLocaleString('en-US')}${led.surchargeNote ? ' (' + led.surchargeNote + ')' : ''}`);
  res.json({ ok: true });
});

// Sửa 1 dòng lịch sử thanh toán — ghi log (thời điểm + lý do) ngay trong dòng đó
app.post('/api/vc24/payment-edit', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { cust, at, amount, date, reason } = req.body || {};
  if (!cust || !at || !String(reason || '').trim()) return res.json({ ok: false, reason: 'bad' });
  let ledger = {}; try { const s = await redisGet(VK.ledger); if (s) ledger = JSON.parse(s); } catch { /* ok */ }
  const led = ledger[cust];
  if (!led || !Array.isArray(led.history)) return res.json({ ok: false, reason: 'notfound' });
  const e = led.history.find(h => h.at === at);
  if (!e) return res.json({ ok: false, reason: 'notfound' });
  const oldAmt = Number(e.amount) || 0, oldDate = e.date || '';
  const newAmt = Math.round(Number(amount) || 0), newDate = String(date || e.date || '');
  led.credit = (Number(led.credit) || 0) + (newAmt - oldAmt); // điều chỉnh dư theo chênh lệch
  e.amount = newAmt; e.date = newDate;
  e.edits = e.edits || [];
  e.edits.push({ at: new Date().toISOString(), by: userFromReq(req), oldAmount: oldAmt, newAmount: newAmt, oldDate, newDate, reason: String(reason).slice(0, 300) });
  ledger[cust] = led;
  const ok = await redisSet(VK.ledger, JSON.stringify(ledger));
  if (!ok) return res.json({ ok: false, reason: 'save' });
  await vcLog('payment-edit', `Sửa lịch sử thu ${cust}: ₩${oldAmt.toLocaleString('en-US')}→₩${newAmt.toLocaleString('en-US')} — ${String(reason).slice(0, 120)}`);
  res.json({ ok: true });
});

// Upload = GỘP theo Mã kiện (key). Trùng -> bỏ qua, báo lại danh sách trùng.
app.post('/api/vc24/upload', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { fileName, rows } = req.body || {};
  if (!Array.isArray(rows)) return res.json({ ok: false, message: 'no rows' });
  const o = await vcLoadOrders();
  const existing = new Set(o.rows.map(keyOf).filter(Boolean));
  let added = 0; const dup = [];
  for (const r of rows) {
    const k = keyOf(r);
    if (k && existing.has(k)) { dup.push(k); continue; }
    if (k) existing.add(k);
    o.rows.push(r); added++;
  }
  o.fileName = String(fileName || o.fileName || ''); o.uploadedAt = new Date().toISOString();
  const saved = await vcSaveOrders(o);
  if (!saved) return res.json({ ok: false, reason: 'save', message: 'Lưu thất bại — kho dữ liệu có thể đã quá lớn.' });
  res.json({ ok: true, added, dup, total: o.rows.length });
});

// ── Lưu BẢN NHÁP (chưa vào dữ liệu tổng) ────────────────────────────────────
app.post('/api/vc24/draft', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { fileName, rows } = req.body || {};
  if (!Array.isArray(rows)) return res.json({ ok: false, message: 'no rows' });
  const ok = await redisSet(VK.draft, gzPack({ fileName: String(fileName || ''), at: new Date().toISOString(), rows }));
  res.json({ ok, count: rows.length });
});
app.post('/api/vc24/draft/clear', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const ok = await redisSet(VK.draft, gzPack(null));
  res.json({ ok });
});

// ── ĐẨY nháp lên dữ liệu tổng (cần mật khẩu) + lưu lịch sử upload + nhật ký ──
app.post('/api/vc24/commit', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { password, week } = req.body || {};
  const user = userFromReq(req);
  if (!password || password !== USERS[user]) return res.json({ ok: false, reason: 'password' });
  const wk = /^\d{4}-W\d{2}$/.test(String(week || '')) ? String(week) : '';
  const draft = gzUnpack(await redisGet(VK.draft), null);
  if (!draft || !Array.isArray(draft.rows) || !draft.rows.length) return res.json({ ok: false, reason: 'empty' });
  const o = await vcLoadOrders();
  const existing = new Set(o.rows.map(keyOf).filter(Boolean));
  let added = 0; const dup = [];
  for (const r of draft.rows) { const k = keyOf(r); if (k && existing.has(k)) { dup.push(k); continue; } if (k) existing.add(k); if (wk) r.week = wk; o.rows.push(r); added++; }
  o.fileName = draft.fileName || o.fileName || ''; o.uploadedAt = new Date().toISOString();
  const saved = await vcSaveOrders(o);
  if (!saved) return res.json({ ok: false, reason: 'save' });
  const id = Date.now().toString();
  await redisSet(VK.uploads + ':' + id, gzPack({ id, fileName: draft.fileName, week: wk, at: new Date().toISOString(), added, rows: draft.rows }));
  let idx = gzUnpack(await redisGet(VK.uploads), []); if (!Array.isArray(idx)) idx = [];
  idx.push({ id, fileName: draft.fileName, week: wk, at: new Date().toISOString(), added, total: draft.rows.length, dup: dup.length });
  if (idx.length > 60) { for (const d of idx.slice(0, idx.length - 60)) await redisSet(VK.uploads + ':' + d.id, gzPack(null)); idx = idx.slice(-60); }
  await redisSet(VK.uploads, gzPack(idx));
  await redisSet(VK.draft, gzPack(null));
  await vcLog('commit', `Đẩy lên tổng: +${added} đơn${wk ? ` [${wk}]` : ''}${dup.length ? `, ${dup.length} trùng bỏ qua` : ''} (file ${draft.fileName || '-'})`);
  res.json({ ok: true, added, dup, total: o.rows.length });
});

// Lịch sử (danh sách upload + nhật ký thao tác)
app.get('/api/vc24/history', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: true, redis: false, uploads: [], log: [] });
  const uploads = gzUnpack(await redisGet(VK.uploads), []);
  const log = gzUnpack(await redisGet(VK.log), []);
  res.json({ ok: true, uploads: Array.isArray(uploads) ? uploads : [], log: Array.isArray(log) ? log : [] });
});
// Lấy lại 1 file đã upload để tải về
app.get('/api/vc24/upload-file', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const rec = gzUnpack(await redisGet(VK.uploads + ':' + String(req.query.id || '')), null);
  if (!rec) return res.json({ ok: false, message: 'not found' });
  res.json({ ok: true, fileName: rec.fileName, at: rec.at, rows: rec.rows || [] });
});

// Sửa 1 ô dữ liệu (lưu online)
app.post('/api/vc24/edit', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { key, field, value } = req.body || {};
  if (!key || !VC24_EDITABLE.has(field)) return res.json({ ok: false, message: 'bad field' });
  const o = await vcLoadOrders();
  const row = o.rows.find(r => keyOf(r) === key);
  if (!row) return res.json({ ok: false, message: 'not found' });
  row[field] = value;
  const saved = await vcSaveOrders(o);
  res.json({ ok: saved, reason: saved ? undefined : 'save' });
});

// Lưu cả 1 dòng (sửa từ popup) — chỉ ghi các trường được phép
app.post('/api/vc24/save', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { key, row } = req.body || {};
  if (!key || !row || typeof row !== 'object') return res.json({ ok: false, message: 'bad' });
  const o = await vcLoadOrders();
  const cur = o.rows.find(r => keyOf(r) === key);
  if (!cur) return res.json({ ok: false, message: 'not found' });
  for (const f of VC24_EDITABLE) { if (Object.prototype.hasOwnProperty.call(row, f)) cur[f] = row[f]; }
  const saved = await vcSaveOrders(o);
  if (saved) await vcLog('edit', 'Sửa đơn ' + key);
  res.json({ ok: saved, reason: saved ? undefined : 'save' });
});

// Cập nhật trạng thái thanh toán cho NHIỀU đơn cùng lúc (thu tiền)
app.post('/api/vc24/bulkpay', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { keys, pay, paidDate } = req.body || {};
  if (!Array.isArray(keys) || !keys.length) return res.json({ ok: false, message: 'no keys' });
  const set = new Set(keys); const val = String(pay == null ? 'ĐÃ TT' : pay);
  const o = await vcLoadOrders(); let n = 0;
  o.rows.forEach(r => { if (set.has(keyOf(r))) { r.pay = val; if (paidDate != null) r.paidDate = String(paidDate); n++; } });
  const saved = await vcSaveOrders(o);
  res.json({ ok: saved, updated: n, reason: saved ? undefined : 'save' });
});

// Xóa 1 đơn — bắt buộc đúng mật khẩu tài khoản
app.post('/api/vc24/delete', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { key, password } = req.body || {};
  const user = userFromReq(req);
  if (!password || password !== USERS[user]) return res.json({ ok: false, reason: 'password' });
  if (!key) return res.json({ ok: false });
  const o = await vcLoadOrders();
  const before = o.rows.length;
  o.rows = o.rows.filter(r => keyOf(r) !== key);
  if (o.rows.length === before) return res.json({ ok: false, reason: 'notfound' });
  const saved = await vcSaveOrders(o);
  if (saved) await vcLog('delete', 'Xóa đơn ' + key);
  res.json({ ok: saved, reason: saved ? undefined : 'save' });
});

// XÓA TOÀN BỘ dữ liệu (kiện hàng + công nợ) — mật khẩu + xác nhận chính xác
app.post('/api/vc24/reset', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { password, confirm } = req.body || {};
  const user = userFromReq(req);
  if (!password || password !== USERS[user]) return res.json({ ok: false, reason: 'password' });
  const norm = s => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/đ/gi, 'd').toUpperCase().replace(/\s+/g, ' ').trim();
  if (norm(confirm) !== 'TOI DONG Y XOA') return res.json({ ok: false, reason: 'confirm' });
  const s1 = await vcSaveOrders({ rows: [], fileName: '', uploadedAt: null });
  const s2 = await redisSet(VK.ledger, '{}');
  await redisSet(VK.draft, gzPack(null));
  if (s1 && s2) await vcLog('reset', 'Xóa TOÀN BỘ dữ liệu kế toán');
  res.json({ ok: s1 && s2 });
});

app.post('/api/vc24/cfg', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const cfg = (req.body && req.body.cfg) || {};
  const ok = await redisSet(VK.cfg, JSON.stringify(cfg));
  res.json({ ok });
});

// ── robots.txt + sitemap.xml (cho Google index) ──────────────────────────────
const SITE = BASE_URL;
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(
    `User-agent: *\nAllow: /\nAllow: /about\nAllow: /tracking\nAllow: /tracking-info\nAllow: /customs-guide\nAllow: /tools\nAllow: /pccc\nAllow: /food-korea\nAllow: /import-guide\nAllow: /size-korea\nAllow: /travel-korea\nAllow: /shopping-korea\nAllow: /ten-tieng-han\nAllow: /nguoi-viet-o-han\nDisallow: /api/\nDisallow: /shipping\nDisallow: /vc24global\nDisallow: /vc24/\nDisallow: /login\nDisallow: /vc24global-main\n\nSitemap: ${SITE}/sitemap.xml\n`
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
  if (userFromReq(req) !== 'vhpro') return res.redirect('/');   // chỉ account VC24 (vhpro)
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
