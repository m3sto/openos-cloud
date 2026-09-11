/**
 * OpenOS Cloud — paylaşılan yardımcılar
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Burada tutulan her şey güvenlik sınırının bir parçasıdır. Kural:
 *  · Gizli değerler yalnızca `env` üzerinden gelir; depoda hiçbir sır yoktur.
 *  · İstemciye asla iç hata metni, yığın izi ya da SQL dönmez.
 *  · Karşılaştırmalar sabit zamanlıdır.
 *  · Oturum belirteçleri veritabanında düz değil, SHA-256 özeti olarak durur.
 */

/* ---------------------------------------------------------------- sabitler */
export const LIMITS = {
  emailMax: 254,
  passwordMin: 10,
  passwordMax: 200,
  handleMin: 3,
  handleMax: 24,
  displayMax: 48,
  bioMax: 280,
  appIdMax: 48,
  appNameMax: 60,
  summaryMax: 160,
  sourceMax: 512 * 1024,      // 512 KB
  avatarMax: 96 * 1024,       // 96 KB
  bodyMax: 1024 * 1024,       // 1 MB — her istek gövdesi
  sessionDays: 60,
  pbkdf2: 310_000,            // OWASP 2023 önerisi (PBKDF2-SHA256)
};

export const RATE = {
  'auth:login':   { limit: 8,   window: 300 },   // 5 dk'da 8 deneme
  'auth:signup':  { limit: 4,   window: 3600 },
  'auth:password':{ limit: 5,   window: 3600 },
  'apps:publish': { limit: 30,  window: 3600 },
  'avatar:put':   { limit: 12,  window: 3600 },
  default:        { limit: 240, window: 60 },
};

/* ---------------------------------------------------------------- yanıtlar */
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'geolocation=(), camera=(), microphone=(), payment=()',
  'Cache-Control': 'no-store',
};

/** İzin verilen kaynaklar env.ALLOWED_ORIGINS içinde virgülle ayrılır. */
export function corsHeaders(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allow = (env.ALLOWED_ORIGINS || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  const ok = allow.includes(origin) || (allow.includes('*') && origin);
  return {
    'Access-Control-Allow-Origin': ok ? origin : (allow[0] || 'null'),
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

export function json(data, { status = 200, request, env, headers = {} } = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...SECURITY_HEADERS,
      ...(request ? corsHeaders(request, env) : {}),
      ...headers,
    },
  });
}

/** İstemciye dönen tek hata biçimi. `code` sabittir, `message` kullanıcıya yöneliktir. */
export class ApiError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}
export const fail = (code, message, status) => { throw new ApiError(code, message, status); };

/* ---------------------------------------------------------------- kripto */
const enc = new TextEncoder();
export const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
export const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
export const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

export function randomBytes(n = 32) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}
export const randomToken = (n = 32) => b64url(randomBytes(n));
const b64url = a => btoa(String.fromCharCode(...a)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export async function sha256(input) {
  return hex(await crypto.subtle.digest('SHA-256', typeof input === 'string' ? enc.encode(input) : input));
}

/** PBKDF2-SHA256. Depolanan biçim: pbkdf2$<iter>$<saltB64>$<hashB64> */
export async function hashPassword(password, iterations = LIMITS.pbkdf2, saltBytes) {
  const salt = saltBytes || randomBytes(16);
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256);
  return `pbkdf2$${iterations}$${b64(salt)}$${b64(bits)}`;
}

export async function verifyPassword(password, stored) {
  try {
    const [scheme, iter, salt, hash] = String(stored).split('$');
    if (scheme !== 'pbkdf2') return false;
    const candidate = await hashPassword(password, parseInt(iter, 10), unb64(salt));
    return timingSafeEqual(candidate.split('$')[3], hash);
  } catch { return false; }
}

/** Uzunluk sızdırmayan sabit zamanlı karşılaştırma. */
export function timingSafeEqual(a, b) {
  const A = enc.encode(String(a)), B = enc.encode(String(b));
  let diff = A.length ^ B.length;
  const n = Math.max(A.length, B.length);
  for (let i = 0; i < n; i++) diff |= (A[i] || 0) ^ (B[i] || 0);
  return diff === 0;
}

/** IP'yi ham saklamayız; gizli anahtarla özetleriz (oran sınırı + denetim için). */
export async function clientKey(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '0.0.0.0';
  return (await sha256(ip + '|' + (env.IP_PEPPER || env.JWT_SECRET || 'openos'))).slice(0, 32);
}

/* ---------------------------------------------------------------- doğrulama */
export const isEmail = v => typeof v === 'string' && v.length <= LIMITS.emailMax &&
  /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v);
export const isHandle = v => typeof v === 'string' &&
  new RegExp(`^[a-z0-9_-]{${LIMITS.handleMin},${LIMITS.handleMax}}$`).test(v);
export const isAppId = v => typeof v === 'string' && /^[a-z0-9][a-z0-9_-]{1,47}$/.test(v);

export function str(v, max, name) {
  if (v === undefined || v === null) return '';
  if (typeof v !== 'string') fail('invalid_field', `${name} metin olmalı`);
  const t = v.trim();
  if (t.length > max) fail('too_long', `${name} en fazla ${max} karakter olabilir`);
  return t;
}

/** Sızdırılmış/zayıf parolaları elemek için ucuz ama etkili bir tarama. */
export function passwordProblem(pw) {
  if (typeof pw !== 'string') return 'Şifre gerekli';
  if (pw.length < LIMITS.passwordMin) return `Şifre en az ${LIMITS.passwordMin} karakter olmalı`;
  if (pw.length > LIMITS.passwordMax) return 'Şifre çok uzun';
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(r => r.test(pw)).length;
  if (classes < 3) return 'Şifre küçük harf, büyük harf, rakam ve simgeden en az üçünü içermeli';
  if (/^(.)\1+$/.test(pw)) return 'Şifre çok basit';
  const common = ['password', 'passw0rd', '12345678', 'qwertyui', 'openos', 'iloveyou', 'admin123'];
  if (common.some(c => pw.toLowerCase().includes(c))) return 'Şifre yaygın bir kalıp içeriyor';
  return null;
}

/* ---------------------------------------------------------------- oran sınırı */
export async function rateLimit(env, bucket, key) {
  const cfg = RATE[bucket] || RATE.default;
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - cfg.window;
  const id = `${bucket}:${key}`;
  await env.DB.prepare('DELETE FROM rate_limits WHERE at < ?').bind(windowStart - 3600).run();
  const row = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM rate_limits WHERE id = ? AND at >= ?'
  ).bind(id, windowStart).first();
  if ((row?.n || 0) >= cfg.limit) {
    fail('rate_limited', 'Çok fazla deneme yapıldı. Lütfen biraz sonra tekrar deneyin.', 429);
  }
  await env.DB.prepare('INSERT INTO rate_limits (id, at) VALUES (?, ?)').bind(id, now).run();
}

/* ---------------------------------------------------------------- oturumlar */
export async function createSession(env, userId, request, deviceName) {
  const token = randomToken(32);
  const id = crypto.randomUUID();
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, token_hash, device, platform, ip_hash, created, last_seen, expires)
     VALUES (?,?,?,?,?,?,?,?,?)`
  ).bind(
    id, userId, await sha256(token),
    str(deviceName, 64, 'device') || 'OpenOS',
    labelPlatform(request.headers.get('User-Agent') || ''),
    await clientKey(request, env),
    now, now, now + LIMITS.sessionDays * 864e5,
  ).run();
  return { token, id };
}

export async function requireUser(request, env, { touch = true } = {}) {
  const raw = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
  if (!raw || raw.length > 256) fail('unauthorized', 'Oturum gerekli', 401);
  const th = await sha256(raw);
  const row = await env.DB.prepare(
    `SELECT s.id AS sid, s.expires, u.* FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.revoked = 0`
  ).bind(th).first();
  if (!row) fail('unauthorized', 'Oturum gerekli', 401);
  if (row.expires < Date.now()) {
    await env.DB.prepare('UPDATE sessions SET revoked = 1 WHERE id = ?').bind(row.sid).run();
    fail('session_expired', 'Oturum süresi doldu', 401);
  }
  if (row.suspended) fail('suspended', 'Hesap askıya alınmış', 403);
  if (touch) {
    await env.DB.prepare('UPDATE sessions SET last_seen = ? WHERE id = ?').bind(Date.now(), row.sid).run();
  }
  return { ...row, sessionId: row.sid };
}

export const publicUser = u => ({
  id: u.id, handle: u.handle, display: u.display || u.handle,
  bio: u.bio || '', avatar: u.avatar_emoji || '🧑‍🚀',
  hasAvatarImage: !!u.avatar_image,
  created: u.created, published: u.published ?? undefined,
});

/* ---------------------------------------------------------------- denetim */
export async function audit(env, { userId = null, action, request, detail = '' }) {
  try {
    await env.DB.prepare(
      'INSERT INTO audit (id, user_id, action, ip_hash, detail, at) VALUES (?,?,?,?,?,?)'
    ).bind(crypto.randomUUID(), userId, action, await clientKey(request, env),
           String(detail).slice(0, 200), Date.now()).run();
  } catch { /* denetim kaydı hiçbir zaman isteği düşürmez */ }
}

/* ---------------------------------------------------------------- yardımcı */
export function labelPlatform(ua) {
  const s = String(ua);
  const os = /Windows/.test(s) ? 'Windows' : /Mac OS X|Macintosh/.test(s) ? 'macOS'
    : /Android/.test(s) ? 'Android' : /iPhone|iPad/.test(s) ? 'iOS'
    : /Linux/.test(s) ? 'Linux' : 'Bilinmeyen';
  const br = /OpenBrow/.test(s) ? 'OpenBrow' : /Edg\//.test(s) ? 'Edge'
    : /Chrome\//.test(s) ? 'Chrome' : /Firefox\//.test(s) ? 'Firefox'
    : /Safari\//.test(s) ? 'Safari' : 'Tarayıcı';
  return `${br} · ${os}`;
}

export async function readJson(request) {
  const len = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (len > LIMITS.bodyMax) fail('too_large', 'İstek gövdesi çok büyük', 413);
  const type = request.headers.get('Content-Type') || '';
  if (!type.includes('application/json')) fail('bad_content_type', 'JSON bekleniyor', 415);
  const text = await request.text();
  if (text.length > LIMITS.bodyMax) fail('too_large', 'İstek gövdesi çok büyük', 413);
  try { return text ? JSON.parse(text) : {}; }
  catch { fail('bad_json', 'Geçersiz JSON'); }
}

/** data: URL'inden güvenli görsel çıkarımı. Yalnızca beyaz listedeki türler. */
export function parseDataImage(dataUrl) {
  const m = /^data:(image\/(png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(dataUrl || ''));
  if (!m) fail('bad_image', 'Yalnızca PNG, JPEG ya da WebP kabul edilir');
  const bytes = m[3].length * 0.75;
  if (bytes > LIMITS.avatarMax) fail('too_large', 'Görsel 96 KB sınırını aşıyor', 413);
  /* sihirli baytları da doğrula — uzantı/mime yalanı burada durur */
  const head = unb64(m[3].slice(0, 32));
  const png = head[0] === 0x89 && head[1] === 0x50 && head[2] === 0x4e && head[3] === 0x47;
  const jpg = head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff;
  const webp = head[0] === 0x52 && head[1] === 0x49 && head[2] === 0x46 && head[3] === 0x46;
  if (!(png || jpg || webp)) fail('bad_image', 'Görsel içeriği başlığıyla uyuşmuyor');
  return { mime: m[1], data: m[3], size: Math.round(bytes) };
}
