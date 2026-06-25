require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs   = require('fs');
const https = require('https');
const http  = require('http');
const zlib  = require('zlib');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

// Parse USERS env: "admin:pass123,user2:secret"
// USERS_EXTRA: account bổ sung (gộp vào USERS) — để THÊM account mà KHÔNG cần
// sửa biến USERS sẵn có (vd biến USERS là Sensitive, không xem lại được giá trị cũ).
const USERS = {};
const usersEnv = process.env.USERS || `${process.env.ADMIN_USER || 'admin'}:${process.env.ADMIN_PASS || 'admin123'}`;
[usersEnv, process.env.USERS_EXTRA || ''].join(',').split(',').forEach(pair => {
  const idx = pair.indexOf(':');
  if (idx > 0) USERS[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
});

// Nhóm account được phép vào VC24 Global (kế toán & công nợ). Thêm/bớt qua env
// VC24_USERS="vhpro,vc24a,vc24b,vc24c". 3 account ngang quyền — mọi thao tác đều ghi log kèm tên.
const VC24_USERS = new Set(
  (process.env.VC24_USERS || 'vhpro,vc24a,vc24b,vc24c').split(',').map(s => s.trim()).filter(Boolean)
);
function isVC24(user) { return !!user && VC24_USERS.has(user); }

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
const BASE_URL = process.env.SITE_URL || 'https://logistics.transflash.app';

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

app.post('/api/login', async (req, res) => {
  const { username, password, remember } = req.body;
  if (username && await verifyPassword(username, password)) {
    // Nhóm VC24 (kế toán dùng chung): KHÔNG giữ đăng nhập dài — luôn dùng cookie
    // phiên (đóng trình duyệt là phải nhập lại), bỏ qua "remember 30 ngày".
    if (isVC24(username)) {
      const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '12h' });
      res.cookie(COOKIE, token, authCookieOpts());   // không maxAge → cookie phiên
      return res.json({ ok: true });
    }
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

// Cho biết bản code đang chạy live là commit nào (để kiểm tra deploy đã cập nhật chưa)
app.get('/api/version', (req, res) => {
  res.set('Cache-Control', 'no-store').json({
    commit: (process.env.VERCEL_GIT_COMMIT_SHA || 'local').slice(0, 7),
    msg: process.env.VERCEL_GIT_COMMIT_MESSAGE || '',
  });
});

// Đổi mật khẩu của CHÍNH MÌNH (cần mật khẩu hiện tại)
app.post('/api/change-password', requireAuth, async (req, res) => {
  const user = userFromReq(req);
  const { oldPassword, newPassword } = req.body || {};
  if (!user) return res.json({ ok: false, reason: 'auth' });
  if (!useRedis) return res.json({ ok: false, reason: 'noredis' });
  if (!(await verifyPassword(user, oldPassword))) return res.json({ ok: false, reason: 'oldwrong' });
  if (String(newPassword || '').length < 6) return res.json({ ok: false, reason: 'short' });
  if (!(await setPassword(user, newPassword))) return res.json({ ok: false, reason: 'save' });
  await vcLog('password', 'Đổi mật khẩu của chính mình', user);
  res.json({ ok: true });
});

// Tải file qua server: nhận base64 client dựng, trả về dạng attachment thật.
// Dùng cho trình duyệt trong app (Zalo/Messenger/Kakao) — webview không tải được
// blob do JS tạo, nhưng tải tốt response HTTP có Content-Disposition: attachment.
app.post('/api/download', requireAuth, (req, res) => {
  const { filename, b64, type } = req.body || {};
  if (!b64) return res.status(400).send('no data');
  let buf;
  try { buf = Buffer.from(String(b64), 'base64'); } catch { return res.status(400).send('bad data'); }
  if (!buf.length || buf.length > 15 * 1024 * 1024) return res.status(413).send('size');
  const safe = (String(filename || 'download.xlsx').replace(/[^\w.\-]+/g, '_').slice(0, 120)) || 'download.xlsx';
  const ct = type === 'pdf' ? 'application/pdf'
    : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
  res.setHeader('Content-Type', ct);
  res.setHeader('Content-Disposition', `attachment; filename="${safe}"`);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.send(buf);
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
// ── Mật khẩu: override (băm scrypt) lưu Redis, ưu tiên hơn env USERS ─────────
const PW_KEY = 'auth:pw';
async function loadPwOverrides() {
  if (!useRedis) return {};
  try { const s = await redisGet(PW_KEY); return s ? JSON.parse(s) : {}; } catch { return {}; }
}
function hashPw(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  return { salt, hash: crypto.scryptSync(String(pw), salt, 32).toString('hex') };
}
function pwMatches(rec, pw) {
  if (!rec || !rec.salt || !rec.hash) return false;
  try {
    const h = crypto.scryptSync(String(pw), rec.salt, 32).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(rec.hash, 'hex'), Buffer.from(h, 'hex'));
  } catch { return false; }
}
// Xác thực: nếu có override trong Redis -> so băm; nếu không -> so env USERS
async function verifyPassword(user, pw) {
  if (!user || pw == null) return false;
  const ov = await loadPwOverrides();
  if (ov[user]) return pwMatches(ov[user], pw);
  return !!(USERS[user] && USERS[user] === String(pw));
}
async function setPassword(user, pw) {
  if (!useRedis) return false;
  const ov = await loadPwOverrides();
  ov[user] = hashPw(pw);
  return redisSet(PW_KEY, JSON.stringify(ov));
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
    hub: USER_HUBS[username] || (isVC24(username) ? { url: '/vc24global-main', label: '🏢 VC24 Global' } : null),
    vc24: isVC24(username),
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
// Trung tâm điều khiển VC24 (hub) — nhóm account VC24
app.get('/vc24global-main', requireAuth, (req, res) => {
  if (!isVC24(userFromReq(req))) return res.redirect('/');
  sendTpl(res, 'vc24global-main.html');
});
app.get('/vc24global', requireAuth, (req, res) => {
  if (!isVC24(userFromReq(req))) return res.redirect('/');
  sendTpl(res, 'vc24global.html');
});
// Kế toán & công nợ VC24 Global — nhóm account VC24
app.get('/vc24/ke-toan', requireAuth, (req, res) => {
  if (!isVC24(userFromReq(req))) return res.redirect('/');
  sendTpl(res, 'ketoan.html');
});

// ── API lưu trữ dữ liệu kế toán VC24 (Redis) — chỉ account 'vhpro' ───────────
function requireVC24(req, res, next) {
  if (!isVC24(userFromReq(req))) return res.status(403).json({ ok: false, message: 'forbidden' });
  next();
}
const VK = { orders: 'vc24:ketoan:orders', cfg: 'vc24:ketoan:cfg', ledger: 'vc24:ketoan:ledger',
  draft: 'vc24:ketoan:draft', uploads: 'vc24:ketoan:uploads', log: 'vc24:ketoan:log', rates: 'vc24:ketoan:rates' };
// nén chung cho mọi JSON
function gzPack(o) { try { return 'gz:' + zlib.gzipSync(Buffer.from(JSON.stringify(o), 'utf8')).toString('base64'); } catch { return JSON.stringify(o); } }
function gzUnpack(s, d) { if (!s) return d; try { const j = (typeof s === 'string' && s.startsWith('gz:')) ? zlib.gunzipSync(Buffer.from(s.slice(3), 'base64')).toString('utf8') : s; return JSON.parse(j); } catch { return d; } }
// Ghi nhật ký thao tác (bounded)
async function vcLog(action, detail, user) {
  if (!useRedis) return;
  let log = gzUnpack(await redisGet(VK.log), []); if (!Array.isArray(log)) log = [];
  log.push({ at: new Date().toISOString(), user: String(user || ''), action: String(action || ''), detail: String(detail || '') });
  if (log.length > 1500) log = log.slice(-1500);
  await redisSet(VK.log, gzPack(log));
}
const isPaidPay = p => String(p || '').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/đ/gi, 'd').toUpperCase().trim() === 'DA TT';
const VC24_EDITABLE = new Set(['date','status','cust','pay','note','rcv','rcvPh','addr','region','weight','price','won','vnd','phuPhi','phuPhiWon','ship','ghiChu','staff','paidDate','week']);
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
  res.json({ ok: true, redis: true, rows: o.rows, fileName: o.fileName, uploadedAt: o.uploadedAt, cfg: c, ledger, draft, rates, me: userFromReq(req) });
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
  await vcLog('rates', `Cài giá VC tuần ${week}: ${Object.entries(clean).map(([k, v]) => k + '=' + v).join(', ') || '(trống)'}`, userFromReq(req));
  res.json({ ok: true });
});

// Thu tiền theo SỐ TIỀN (hỗ trợ trả từng phần) + ghi lịch sử
app.post('/api/vc24/payment', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { cust, amount, amountVnd, date, settleAll, settleAllVnd } = req.body || {};
  const amt = Math.round(Number(amount) || 0);
  const amtVnd = Math.round(Number(amountVnd) || 0);
  if (!cust || (amt <= 0 && amtVnd <= 0)) return res.json({ ok: false, message: 'bad' });
  const o = await vcLoadOrders();
  let ledger = {}; try { const s = await redisGet(VK.ledger); if (s) ledger = JSON.parse(s); } catch { /* ok */ }
  const led = ledger[cust] || { credit: 0, history: [] };
  const wonAmt = r => (Number(r.won) || 0) + (Number(r.phuPhiWon) || 0);   // tiền hàng + phụ phí KRW
  const vndAmt = r => (Number(r.vnd) || 0) + (Number(r.phuPhi) || 0);      // tiền hàng + phụ phí VND
  const byDate = (a, b) => String(a.date).localeCompare(String(b.date));
  let marked = 0; const markedKeys = [];

  // ── Thu Won: gạch các đơn Won (wonAmt>0) ─────────────────────────────────
  let credit = Math.max(0, (led.history || []).reduce((s, h) => s + (Number(h.amount) || 0), 0)
    - o.rows.filter(r => r.cust === cust && isPaidPay(r.pay)).reduce((s, r) => s + wonAmt(r), 0)) + amt;
  if (amt > 0) {
    const wonOrders = o.rows.filter(r => r.cust === cust && !isPaidPay(r.pay) && wonAmt(r) > 0).sort(byDate);
    if (settleAll) {
      credit = Math.max(0, credit - wonOrders.reduce((s, r) => s + wonAmt(r), 0));
      wonOrders.forEach(r => { r.pay = 'ĐÃ TT'; if (date) r.paidDate = String(date); marked++; markedKeys.push(keyOf(r)); });
    } else {
      for (const r of wonOrders) { const w = wonAmt(r); if (credit >= w) { r.pay = 'ĐÃ TT'; if (date) r.paidDate = String(date); credit -= w; marked++; markedKeys.push(keyOf(r)); } }
    }
  }

  // ── Thu VND: gạch các đơn VND (vndAmt>0) — song song, độc lập với Won ─────
  let creditVnd = Math.max(0, (led.history || []).reduce((s, h) => s + (Number(h.amountVnd) || 0), 0)
    - o.rows.filter(r => r.cust === cust && isPaidPay(r.pay)).reduce((s, r) => s + vndAmt(r), 0)) + amtVnd;
  if (amtVnd > 0) {
    const vndOrders = o.rows.filter(r => r.cust === cust && !isPaidPay(r.pay) && vndAmt(r) > 0).sort(byDate);
    if (settleAllVnd) {
      creditVnd = Math.max(0, creditVnd - vndOrders.reduce((s, r) => s + vndAmt(r), 0));
      vndOrders.forEach(r => { r.pay = 'ĐÃ TT'; if (date) r.paidDate = String(date); marked++; markedKeys.push(keyOf(r)); });
    } else {
      for (const r of vndOrders) { const v = vndAmt(r); if (creditVnd >= v) { r.pay = 'ĐÃ TT'; if (date) r.paidDate = String(date); creditVnd -= v; marked++; markedKeys.push(keyOf(r)); } }
    }
  }

  led.credit = credit; led.creditVnd = creditVnd;
  led.history = led.history || [];
  led.history.push({ date: String(date || ''), amount: amt, amountVnd: amtVnd, marked, keys: markedKeys, at: new Date().toISOString() });
  ledger[cust] = led;
  const s1 = await vcSaveOrders(o);
  const s2 = await redisSet(VK.ledger, JSON.stringify(ledger));
  if (!s1 || !s2) return res.json({ ok: false, reason: 'save' });
  const parts = []; if (amt > 0) parts.push(`₩${amt.toLocaleString('en-US')}`); if (amtVnd > 0) parts.push(`${amtVnd.toLocaleString('en-US')}đ`);
  await vcLog('payment', `Thu ${parts.join(' + ')} của ${cust} (gạch ${marked} đơn)`, userFromReq(req));
  res.json({ ok: true, marked, credit, creditVnd });
});

// Phí phát sinh theo khách hàng (KRW + VND) — ghi trên hóa đơn, lưu lại
app.post('/api/vc24/surcharge', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { cust, amount, amountVnd, note } = req.body || {};
  if (!cust) return res.json({ ok: false, message: 'bad' });
  let ledger = {}; try { const s = await redisGet(VK.ledger); if (s) ledger = JSON.parse(s); } catch { /* ok */ }
  const led = ledger[cust] || { credit: 0, history: [] };
  led.surcharge = Math.round(Number(amount) || 0);
  led.surchargeVnd = Math.round(Number(amountVnd) || 0);
  led.surchargeNote = String(note || '').slice(0, 200);
  ledger[cust] = led;
  const ok = await redisSet(VK.ledger, JSON.stringify(ledger));
  if (!ok) return res.json({ ok: false, reason: 'save' });
  await vcLog('surcharge', `Phí phát sinh ${cust}: ₩${led.surcharge.toLocaleString('en-US')} + ${led.surchargeVnd.toLocaleString('en-US')}đ${led.surchargeNote ? ' (' + led.surchargeNote + ')' : ''}`, userFromReq(req));
  res.json({ ok: true });
});

// Sửa 1 dòng lịch sử thanh toán — ghi log (thời điểm + lý do) ngay trong dòng đó
app.post('/api/vc24/payment-edit', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { cust, at, amount, amountVnd, date, reason } = req.body || {};
  if (!cust || !at || !String(reason || '').trim()) return res.json({ ok: false, reason: 'bad' });
  let ledger = {}; try { const s = await redisGet(VK.ledger); if (s) ledger = JSON.parse(s); } catch { /* ok */ }
  const led = ledger[cust];
  if (!led || !Array.isArray(led.history)) return res.json({ ok: false, reason: 'notfound' });
  const e = led.history.find(h => h.at === at);
  if (!e) return res.json({ ok: false, reason: 'notfound' });
  const oldAmt = Number(e.amount) || 0, oldVnd = Number(e.amountVnd) || 0, oldDate = e.date || '';
  const newAmt = Math.round(Number(amount) || 0), newVnd = Math.round(Number(amountVnd) || 0), newDate = String(date || e.date || '');
  led.credit = (Number(led.credit) || 0) + (newAmt - oldAmt);       // điều chỉnh dư Won theo chênh lệch
  led.creditVnd = (Number(led.creditVnd) || 0) + (newVnd - oldVnd); // điều chỉnh dư VND theo chênh lệch
  e.amount = newAmt; e.amountVnd = newVnd; e.date = newDate;
  e.edits = e.edits || [];
  e.edits.push({ at: new Date().toISOString(), by: userFromReq(req), oldAmount: oldAmt, newAmount: newAmt, oldVnd, newVnd, oldDate, newDate, reason: String(reason).slice(0, 300) });
  ledger[cust] = led;
  const ok = await redisSet(VK.ledger, JSON.stringify(ledger));
  if (!ok) return res.json({ ok: false, reason: 'save' });
  const chg = [`₩${oldAmt.toLocaleString('en-US')}→₩${newAmt.toLocaleString('en-US')}`];
  if (oldVnd || newVnd) chg.push(`${oldVnd.toLocaleString('en-US')}đ→${newVnd.toLocaleString('en-US')}đ`);
  await vcLog('payment-edit', `Sửa lịch sử thu ${cust}: ${chg.join(', ')} — ${String(reason).slice(0, 120)}`, userFromReq(req));
  res.json({ ok: true });
});

// Xóa 1 dòng thu — bỏ gạch các đơn của lần thu đó, tính lại dư (credit)
app.post('/api/vc24/payment-delete', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { cust, at } = req.body || {};
  if (!cust || !at) return res.json({ ok: false, reason: 'bad' });
  let ledger = {}; try { const s = await redisGet(VK.ledger); if (s) ledger = JSON.parse(s); } catch { /* ok */ }
  const led = ledger[cust];
  if (!led || !Array.isArray(led.history)) return res.json({ ok: false, reason: 'notfound' });
  const i = led.history.findIndex(h => h.at === at);
  if (i < 0) return res.json({ ok: false, reason: 'notfound' });
  const entry = led.history[i];
  const o = await vcLoadOrders();
  const keys = new Set(entry.keys || []);
  o.rows.forEach(r => { if (r.cust === cust && keys.has(keyOf(r)) && isPaidPay(r.pay)) { r.pay = 'CHƯA TT'; r.paidDate = ''; } });
  led.history.splice(i, 1);
  // tính lại dư = tổng đã nhận - tổng won đơn còn Đã TT
  const totalRecv = led.history.reduce((s, h) => s + (Number(h.amount) || 0), 0);
  const paidWon = o.rows.filter(r => r.cust === cust && isPaidPay(r.pay)).reduce((s, r) => s + (Number(r.won) || 0) + (Number(r.phuPhiWon) || 0), 0);
  led.credit = Math.max(0, totalRecv - paidWon);
  ledger[cust] = led;
  const s1 = await vcSaveOrders(o);
  const s2 = await redisSet(VK.ledger, JSON.stringify(ledger));
  if (!s1 || !s2) return res.json({ ok: false, reason: 'save' });
  await vcLog('payment-delete', `Xóa 1 dòng thu của ${cust}: ₩${(Number(entry.amount) || 0).toLocaleString('en-US')} (bỏ gạch ${keys.size} đơn)`, userFromReq(req));
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
  const { week } = req.body || {};
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
  await vcLog('commit', `Đẩy lên tổng: +${added} đơn${wk ? ` [${wk}]` : ''}${dup.length ? `, ${dup.length} trùng bỏ qua` : ''} (file ${draft.fileName || '-'})`, userFromReq(req));
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
  const old = row[field];
  row[field] = value;
  const saved = await vcSaveOrders(o);
  if (saved && String(old ?? '') !== String(value ?? ''))
    await vcLog('edit', `Sửa đơn ${key} · ${field}: "${String(old ?? '')}" → "${String(value ?? '')}"`, userFromReq(req));
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
  const changes = [];
  for (const f of VC24_EDITABLE) {
    if (Object.prototype.hasOwnProperty.call(row, f) && String(cur[f] ?? '') !== String(row[f] ?? '')) {
      changes.push(`${f}: "${String(cur[f] ?? '')}"→"${String(row[f] ?? '')}"`);
      cur[f] = row[f];
    }
  }
  const saved = await vcSaveOrders(o);
  if (saved && changes.length) await vcLog('edit', `Sửa đơn ${key} · ${changes.join('; ')}`, userFromReq(req));
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
  if (saved && n) await vcLog('bulkpay', `Cập nhật TT ${n} đơn → "${val}"${paidDate ? ` (ngày thu ${paidDate})` : ''}`, userFromReq(req));
  res.json({ ok: saved, updated: n, reason: saved ? undefined : 'save' });
});

// Xóa 1 đơn — bắt buộc đúng mật khẩu tài khoản
app.post('/api/vc24/delete', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { key, password } = req.body || {};
  const user = userFromReq(req);
  if (!password || !(await verifyPassword(user, password))) return res.json({ ok: false, reason: 'password' });
  if (!key) return res.json({ ok: false });
  const o = await vcLoadOrders();
  const before = o.rows.length;
  o.rows = o.rows.filter(r => keyOf(r) !== key);
  if (o.rows.length === before) return res.json({ ok: false, reason: 'notfound' });
  const saved = await vcSaveOrders(o);
  if (saved) await vcLog('delete', 'Xóa đơn ' + key, userFromReq(req));
  res.json({ ok: saved, reason: saved ? undefined : 'save' });
});

// XÓA TOÀN BỘ dữ liệu (kiện hàng + công nợ) — mật khẩu + xác nhận chính xác
app.post('/api/vc24/reset', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { password, confirm } = req.body || {};
  const user = userFromReq(req);
  if (!password || !(await verifyPassword(user, password))) return res.json({ ok: false, reason: 'password' });
  const norm = s => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/đ/gi, 'd').toUpperCase().replace(/\s+/g, ' ').trim();
  if (norm(confirm) !== 'TOI DONG Y XOA') return res.json({ ok: false, reason: 'confirm' });
  const s1 = await vcSaveOrders({ rows: [], fileName: '', uploadedAt: null });
  const s2 = await redisSet(VK.ledger, '{}');
  await redisSet(VK.draft, gzPack(null));
  if (s1 && s2) await vcLog('reset', 'Xóa TOÀN BỘ dữ liệu kế toán', userFromReq(req));
  res.json({ ok: s1 && s2 });
});

// Xóa dữ liệu 1 TUẦN (bảo vệ như reset: mật khẩu + "tôi đồng ý xóa")
function vcParseDate(s) { const m = String(s || '').match(/(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})/); if (!m) return null; let y = +m[3]; if (y < 100) y += 2000; const d = new Date(Date.UTC(y, (+m[2]) - 1, +m[1])); return isNaN(d) ? null : d; }
function vcIsoWeek(d) { const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())); const day = (t.getUTCDay() + 6) % 7; t.setUTCDate(t.getUTCDate() - day + 3); const firstThu = new Date(Date.UTC(t.getUTCFullYear(), 0, 4)); const w = 1 + Math.round(((t - firstThu) / 86400000 - 3 + ((firstThu.getUTCDay() + 6) % 7)) / 7); return t.getUTCFullYear() + '-W' + String(w).padStart(2, '0'); }
function vcWeekKey(r) { if (r && /^\d{4}-W\d{2}$/.test(r.week || '')) return r.week; const d = vcParseDate(r && r.date); return d ? vcIsoWeek(d) : ''; }
app.post('/api/vc24/week-delete', requireAuth, requireVC24, async (req, res) => {
  if (!useRedis) return res.json({ ok: false, redis: false });
  const { week, password, confirm } = req.body || {};
  const user = userFromReq(req);
  if (!password || !(await verifyPassword(user, password))) return res.json({ ok: false, reason: 'password' });
  const norm = s => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/đ/gi, 'd').toUpperCase().replace(/\s+/g, ' ').trim();
  if (norm(confirm) !== 'TOI DONG Y XOA') return res.json({ ok: false, reason: 'confirm' });
  if (!/^\d{4}-W\d{2}$/.test(String(week || ''))) return res.json({ ok: false, reason: 'week' });
  const o = await vcLoadOrders();
  const before = o.rows.length;
  o.rows = o.rows.filter(r => vcWeekKey(r) !== week);
  const removed = before - o.rows.length;
  o.uploadedAt = new Date().toISOString();
  const saved = await vcSaveOrders(o);
  if (!saved) return res.json({ ok: false, reason: 'save' });
  await vcLog('week-delete', `Xóa dữ liệu tuần ${week}: ${removed} đơn`, userFromReq(req));
  res.json({ ok: true, removed });
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
    `  <url><loc>${SITE}/</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>1.0</priority>` +
    `<xhtml:link rel="alternate" hreflang="en" href="${SITE}/"/>` +
    `<xhtml:link rel="alternate" hreflang="vi" href="${SITE}/?lang=vi"/>` +
    `<xhtml:link rel="alternate" hreflang="ko" href="${SITE}/?lang=ko"/>` +
    `<xhtml:link rel="alternate" hreflang="x-default" href="${SITE}/"/></url>\n` +
    `  <url><loc>${SITE}/?lang=vi</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.9</priority></url>\n` +
    `  <url><loc>${SITE}/?lang=ko</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.9</priority></url>\n` +
    `  <url><loc>${SITE}/demo</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.7</priority></url>\n` +
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

// ── SEO trang chủ theo ngôn ngữ (đa ngữ index được trên Google/Naver) ────────
const HOME_SEO = {
  en: {
    title: 'Logistics Software & Accounting for Korea–Global Operations | TransFlash Logistics',
    desc:  'Logistics software for businesses: bulk Korean postal code lookup, customs clearance tracking (UNI-PASS), address normalization, Excel waybill automation and logistics accounting. EN · KO · VI.',
    kw:    'logistics software, logistics accounting software, logistics management software, software for logistics company, bulk korean postal code lookup, korea postal code api, korea customs tracking, UNI-PASS, address normalization, waybill automation',
    locale: 'en_US', canon: '',
  },
  vi: {
    title: 'Phần mềm logistics & kế toán cho công ty logistics Hàn – Việt | TransFlash Logistics',
    desc:  'Phần mềm logistics cho doanh nghiệp: tra mã bưu điện Hàn Quốc hàng loạt, tra cứu thông quan (UNI-PASS), chuẩn hóa địa chỉ, xử lý Excel vận đơn và kế toán công ty logistics. Việt · Anh · Hàn.',
    kw:    'phần mềm logistics, phần mềm quản lý logistics, phần mềm kế toán logistics, phần mềm kế toán công ty logistics, tra mã bưu điện hàn quốc hàng loạt, tra cứu thông quan hàn quốc, UNI-PASS, phần mềm vận đơn, chuẩn hóa địa chỉ hàn quốc',
    locale: 'vi_VN', canon: '?lang=vi',
  },
  ko: {
    title: '물류 소프트웨어 & 물류 회계 (한국-글로벌) | TransFlash Logistics',
    desc:  '물류 기업을 위한 소프트웨어: 한국 우편번호 일괄 조회, 통관 조회(UNI-PASS), 주소 정규화, 엑셀 운송장 자동화, 물류 회계. 한국어·영어·베트남어 지원.',
    kw:    '물류 소프트웨어, 물류 회계 소프트웨어, 물류 관리 소프트웨어, 한국 우편번호 일괄 조회, 우편번호 조회 API, 통관 조회, UNI-PASS, 주소 정규화, 운송장 자동화',
    locale: 'ko_KR', canon: '?lang=ko',
  },
};
// ── Trang chính — PUBLIC: ai cũng vào được (khách hoặc đã login) ─────────────
app.get('/', (req, res) => {
  const lang = ['vi', 'en', 'ko'].includes(req.query.lang) ? req.query.lang : 'en';
  const s = HOME_SEO[lang];
  sendTpl(res, 'app.html', {
    __LANG__: lang, __TITLE__: s.title, __DESC__: s.desc,
    __KEYWORDS__: s.kw, __LOCALE__: s.locale, __CANON__: s.canon,
  });
});

// ── Trang DEMO — PUBLIC: gộp 2 tool (mã bưu điện + thông quan) qua iframe embed
app.get('/demo', (req, res) => {
  sendTpl(res, 'demo.html');
});

// ── Trang xử lý file vận đơn — chỉ gói Pro / Enterprise ──────────────────────
app.get('/shipping', requireAuth, (req, res) => {
  if (!isVC24(userFromReq(req))) return res.redirect('/');   // nhóm account VC24
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
