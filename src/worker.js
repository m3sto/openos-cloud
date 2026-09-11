/**
 * OpenOS Cloud — API
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Cloudflare Worker + D1. Hesaplar, oturumlar, cihazlar, profiller ve
 * OpenSharp uygulama mağazası. Depoda hiçbir gizli değer yoktur; tümü
 * `wrangler secret` ile verilir (bkz. README).
 *
 *   GET    /v1                         servis bilgisi
 *   GET    /v1/stats                   herkese açık sayaçlar
 *
 *   POST   /v1/auth/signup             { email, password, handle, device? }
 *   POST   /v1/auth/login              { email, password, device? }
 *   POST   /v1/auth/logout
 *   GET    /v1/auth/me
 *   PUT    /v1/auth/password           { current, next }
 *
 *   GET    /v1/devices                 oturum açmış OpenOS cihazları
 *   DELETE /v1/devices/:id             cihazın oturumunu kapat
 *
 *   PUT    /v1/profile                 { display, bio, avatar }
 *   PUT    /v1/profile/avatar          { image: "data:image/png;base64,..." }
 *   DELETE /v1/profile/avatar
 *   GET    /v1/users/:handle           herkese açık profil
 *   GET    /v1/users/:handle/avatar    avatar görseli
 *
 *   GET    /v1/apps [?q=&category=&mine=1]
 *   GET    /v1/apps/:id
 *   GET    /v1/apps/:id/source
 *   POST   /v1/apps                    { id, name, source, manifest }
 *   DELETE /v1/apps/:id
 *   POST   /v1/apps/:id/install
 *   GET    /v1/library                 indirdiklerim
 */

import {
  LIMITS, ApiError, fail, json, corsHeaders, rateLimit, clientKey, audit,
  hashPassword, verifyPassword, passwordProblem, createSession, requireUser,
  publicUser, isEmail, isHandle, isAppId, str, readJson, parseDataImage, sha256,
} from './lib.js';

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }
    const url = new URL(request.url);
    const seg = url.pathname.split('/').filter(Boolean);

    try {
      if (!env.DB) fail('not_configured', 'Veritabanı bağlı değil', 503);
      if (seg[0] !== 'v1') {
        return json({ name: 'OpenOS Cloud', version: 1, docs: 'https://github.com/m3sto/openos-cloud' },
          { request, env });
      }

      const ip = await clientKey(request, env);
      await rateLimit(env, 'default', ip);

      const route = `${request.method} /${seg.slice(1).join('/')}`;
      const r = await dispatch(seg, request, env, url, ip, ctx);
      if (r) return r;
      fail('not_found', 'Uç nokta bulunamadı: ' + route, 404);
    } catch (e) {
      if (e instanceof ApiError) {
        return json({ error: e.message, code: e.code }, { status: e.status, request, env });
      }
      /* beklenmeyen hatalar istemciye sızmaz */
      console.error('unhandled', e && e.stack ? e.stack : e);
      return json({ error: 'Sunucu hatası', code: 'internal' }, { status: 500, request, env });
    }
  },
};

async function dispatch(seg, request, env, url, ip, ctx) {
  const [, area, a, b] = seg;          /* v1 / area / a / b */
  const M = request.method;

  /* ----------------------------------------------------------- public */
  if (!area) return json({ name: 'OpenOS Cloud', version: 1 }, { request, env });

  if (area === 'stats' && M === 'GET') {
    const u = await env.DB.prepare('SELECT COUNT(*) n FROM users').first();
    const ap = await env.DB.prepare('SELECT COUNT(*) n FROM apps WHERE visible = 1').first();
    const d = await env.DB.prepare('SELECT COALESCE(SUM(downloads),0) n FROM apps').first();
    const dev = await env.DB.prepare('SELECT COUNT(*) n FROM sessions WHERE revoked = 0 AND expires > ?')
      .bind(Date.now()).first();
    return json({ users: u.n, apps: ap.n, downloads: d.n, devices: dev.n }, { request, env });
  }

  /* ------------------------------------------------------------ auth */
  if (area === 'auth') {
    if (a === 'signup' && M === 'POST') return signup(request, env, ip);
    if (a === 'login' && M === 'POST') return login(request, env, ip);
    if (a === 'logout' && M === 'POST') {
      const user = await requireUser(request, env, { touch: false });
      await env.DB.prepare('UPDATE sessions SET revoked = 1 WHERE id = ?').bind(user.sessionId).run();
      await audit(env, { userId: user.id, action: 'logout', request });
      return json({ ok: true }, { request, env });
    }
    if (a === 'me' && M === 'GET') {
      const user = await requireUser(request, env);
      const pub = await enrich(env, user);
      return json({ user: pub }, { request, env });
    }
    if (a === 'password' && M === 'PUT') {
      const user = await requireUser(request, env);
      await rateLimit(env, 'auth:password', user.id);
      const { current, next } = await readJson(request);
      if (!await verifyPassword(String(current || ''), user.password_hash))
        fail('bad_credentials', 'Mevcut şifre hatalı', 403);
      const problem = passwordProblem(next);
      if (problem) fail('weak_password', problem);
      await env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
        .bind(await hashPassword(next), user.id).run();
      /* diğer tüm oturumları düşür — şifre değişimi bir güvenlik olayıdır */
      await env.DB.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ? AND id != ?')
        .bind(user.id, user.sessionId).run();
      await audit(env, { userId: user.id, action: 'password_changed', request });
      return json({ ok: true }, { request, env });
    }
  }

  /* --------------------------------------------------------- devices */
  if (area === 'devices') {
    const user = await requireUser(request, env);
    if (M === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT id, device, platform, created, last_seen, expires, revoked
         FROM sessions WHERE user_id = ? ORDER BY last_seen DESC LIMIT 100`).bind(user.id).all();
      const now = Date.now();
      return json({
        devices: (results || []).map(s => ({
          id: s.id, name: s.device, platform: s.platform,
          created: s.created, lastSeen: s.last_seen,
          active: !s.revoked && s.expires > now && (now - s.last_seen) < 10 * 60_000,
          current: s.id === user.sessionId,
          revoked: !!s.revoked || s.expires <= now,
        })),
      }, { request, env });
    }
    if (M === 'DELETE' && a) {
      await env.DB.prepare('UPDATE sessions SET revoked = 1 WHERE id = ? AND user_id = ?')
        .bind(a, user.id).run();
      await audit(env, { userId: user.id, action: 'device_revoked', request, detail: a });
      return json({ ok: true }, { request, env });
    }
  }

  /* --------------------------------------------------------- profile */
  if (area === 'profile') {
    const user = await requireUser(request, env);
    if (M === 'PUT' && !a) {
      const body = await readJson(request);
      const display = str(body.display, LIMITS.displayMax, 'Görünen ad');
      const bio = str(body.bio, LIMITS.bioMax, 'Hakkında');
      const avatar = str(body.avatar, 8, 'Avatar');
      await env.DB.prepare('UPDATE users SET display = ?, bio = ?, avatar_emoji = ? WHERE id = ?')
        .bind(display || user.handle, bio, avatar || '🧑‍🚀', user.id).run();
      const fresh = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.id).first();
      return json({ user: publicUser(fresh) }, { request, env });
    }
    if (a === 'avatar' && M === 'PUT') {
      await rateLimit(env, 'avatar:put', user.id);
      const { image } = await readJson(request);
      const img = parseDataImage(image);
      await env.DB.prepare('UPDATE users SET avatar_image = ?, avatar_mime = ? WHERE id = ?')
        .bind(img.data, img.mime, user.id).run();
      await audit(env, { userId: user.id, action: 'avatar_set', request, detail: `${img.size}B` });
      return json({ ok: true, size: img.size }, { request, env });
    }
    if (a === 'avatar' && M === 'DELETE') {
      await env.DB.prepare('UPDATE users SET avatar_image = NULL, avatar_mime = NULL WHERE id = ?')
        .bind(user.id).run();
      return json({ ok: true }, { request, env });
    }
  }

  /* ----------------------------------------------------------- users */
  if (area === 'users' && a) {
    if (!isHandle(a)) fail('not_found', 'Kullanıcı bulunamadı', 404);
    const row = await env.DB.prepare('SELECT * FROM users WHERE handle = ?').bind(a).first();
    if (!row || row.suspended) fail('not_found', 'Kullanıcı bulunamadı', 404);

    if (b === 'avatar' && M === 'GET') {
      if (!row.avatar_image) fail('not_found', 'Avatar yok', 404);
      const bytes = Uint8Array.from(atob(row.avatar_image), c => c.charCodeAt(0));
      return new Response(bytes, {
        headers: {
          'Content-Type': row.avatar_mime || 'image/png',
          'Content-Disposition': 'inline',
          'X-Content-Type-Options': 'nosniff',
          'Cache-Control': 'public, max-age=300',
          ...corsHeaders(request, env),
        },
      });
    }
    if (M === 'GET') {
      const apps = await env.DB.prepare(
        'SELECT COUNT(*) n FROM apps WHERE author_id = ? AND visible = 1').bind(row.id).first();
      return json({ user: { ...publicUser(row), published: apps.n } }, { request, env });
    }
  }

  /* ------------------------------------------------------------ apps */
  if (area === 'apps') return apps(seg, request, env, url, ctx);

  /* --------------------------------------------------------- library */
  if (area === 'library' && M === 'GET') {
    const user = await requireUser(request, env);
    const { results } = await env.DB.prepare(
      `SELECT a.id, a.name, a.summary, a.icon, a.tint, a.category, a.version, a.updated,
              i.at AS installed, u.handle AS author
       FROM installs i JOIN apps a ON a.id = i.app_id
       LEFT JOIN users u ON u.id = a.author_id
       WHERE i.user_id = ? ORDER BY i.at DESC LIMIT 200`).bind(user.id).all();
    return json({ apps: (results || []).map(rowToApp) }, { request, env });
  }

  return null;
}

/* ====================================================================== */
async function signup(request, env, ip) {
  await rateLimit(env, 'auth:signup', ip);
  const body = await readJson(request);
  const email = String(body.email || '').trim().toLowerCase();
  const handle = String(body.handle || '').trim().toLowerCase();

  if (!isEmail(email)) fail('bad_email', 'Geçerli bir e-posta girin');
  if (!isHandle(handle)) fail('bad_handle',
    `Kullanıcı adı ${LIMITS.handleMin}-${LIMITS.handleMax} karakter olmalı; küçük harf, rakam, - ve _ kullanın`);
  const problem = passwordProblem(body.password);
  if (problem) fail('weak_password', problem);
  if (RESERVED.has(handle)) fail('handle_taken', 'Bu kullanıcı adı ayrılmış');

  const exists = await env.DB.prepare('SELECT 1 FROM users WHERE email = ? OR handle = ?')
    .bind(email, handle).first();
  if (exists) fail('taken', 'Bu e-posta ya da kullanıcı adı kullanılıyor', 409);

  const id = crypto.randomUUID();
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO users (id, email, handle, display, password_hash, avatar_emoji, created)
     VALUES (?,?,?,?,?,?,?)`
  ).bind(id, email, handle, handle, await hashPassword(body.password), '🧑‍🚀', now).run();

  const s = await createSession(env, id, request, body.device);
  await audit(env, { userId: id, action: 'signup', request });
  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
  return json({ token: s.token, user: publicUser(user) }, { request, env, status: 201 });
}

async function login(request, env, ip) {
  await rateLimit(env, 'auth:login', ip);
  const body = await readJson(request);
  const email = String(body.email || '').trim().toLowerCase();
  await rateLimit(env, 'auth:login', 'acct:' + await sha256(email));

  const row = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  /* kullanıcı yoksa da parola doğrulama maliyetini öde — zamanlama sızıntısını kapat */
  const ok = row
    ? await verifyPassword(String(body.password || ''), row.password_hash)
    : await verifyPassword('x', 'pbkdf2$310000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');

  if (!row || !ok) {
    await audit(env, { userId: row?.id || null, action: 'login_failed', request });
    fail('bad_credentials', 'E-posta ya da şifre hatalı', 401);
  }
  if (row.suspended) fail('suspended', 'Hesap askıya alınmış', 403);

  const s = await createSession(env, row.id, request, body.device);
  await audit(env, { userId: row.id, action: 'login', request });
  return json({ token: s.token, user: publicUser(row) }, { request, env });
}

async function enrich(env, user) {
  const n = await env.DB.prepare('SELECT COUNT(*) n FROM apps WHERE author_id = ? AND visible = 1')
    .bind(user.id).first();
  const inst = await env.DB.prepare('SELECT COUNT(*) n FROM installs WHERE user_id = ?')
    .bind(user.id).first();
  const dev = await env.DB.prepare(
    'SELECT COUNT(*) n FROM sessions WHERE user_id = ? AND revoked = 0 AND expires > ?')
    .bind(user.id, Date.now()).first();
  return { ...publicUser(user), email: user.email, published: n.n, installed: inst.n, devices: dev.n };
}

/* ====================================================================== */
async function apps(seg, request, env, url, ctx) {
  const [, , id, sub] = seg;
  const M = request.method;

  if (M === 'GET' && !id) {
    const mine = url.searchParams.get('mine');
    const q = (url.searchParams.get('q') || '').trim().slice(0, 60);
    const cat = (url.searchParams.get('category') || '').slice(0, 30);
    let sql = `SELECT a.id, a.name, a.summary, a.icon, a.tint, a.category, a.version,
                      a.updated, a.size, a.downloads, u.handle AS author
               FROM apps a LEFT JOIN users u ON u.id = a.author_id WHERE a.visible = 1`;
    const binds = [];
    if (mine) { const user = await requireUser(request, env); sql += ' AND a.author_id = ?'; binds.push(user.id); }
    if (q) { sql += ' AND (a.name LIKE ? ESCAPE \'\\\' OR a.summary LIKE ? ESCAPE \'\\\')';
             const like = `%${q.replace(/[%_\\]/g, m => '\\' + m)}%`; binds.push(like, like); }
    if (cat) { sql += ' AND a.category = ?'; binds.push(cat); }
    sql += ' ORDER BY a.updated DESC LIMIT 300';
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json({ schema: 1, name: 'OpenOS Cloud App Store', updated: Date.now(),
                  apps: (results || []).map(rowToApp) }, { request, env });
  }

  if (M === 'GET' && id && sub === 'source') {
    if (!isAppId(id)) fail('not_found', 'Uygulama bulunamadı', 404);
    const row = await env.DB.prepare('SELECT source FROM apps WHERE id = ? AND visible = 1').bind(id).first();
    if (!row) fail('not_found', 'Uygulama bulunamadı', 404);
    return new Response(row.source, {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'public, max-age=60',
        ...corsHeaders(request, env),
      },
    });
  }

  if (M === 'POST' && id && sub === 'install') {
    if (!isAppId(id)) fail('not_found', 'Uygulama bulunamadı', 404);
    await env.DB.prepare('UPDATE apps SET downloads = downloads + 1 WHERE id = ?').bind(id).run();
    /* oturum varsa kütüphaneye ekle; yoksa yalnız sayaç artar */
    try {
      const user = await requireUser(request, env, { touch: false });
      await env.DB.prepare(
        'INSERT INTO installs (user_id, app_id, at) VALUES (?,?,?) ON CONFLICT DO UPDATE SET at = excluded.at'
      ).bind(user.id, id, Date.now()).run();
    } catch { /* anonim kurulum */ }
    return json({ ok: true }, { request, env });
  }

  if (M === 'GET' && id) {
    if (!isAppId(id)) fail('not_found', 'Uygulama bulunamadı', 404);
    const row = await env.DB.prepare(
      `SELECT a.*, u.handle AS author FROM apps a LEFT JOIN users u ON u.id = a.author_id
       WHERE a.id = ? AND a.visible = 1`).bind(id).first();
    if (!row) fail('not_found', 'Uygulama bulunamadı', 404);
    return json({ app: rowToApp(row) }, { request, env });
  }

  if (M === 'POST' && !id) {
    const user = await requireUser(request, env);
    await rateLimit(env, 'apps:publish', user.id);
    const body = await readJson(request);
    const appId = String(body.id || '').trim().toLowerCase();
    if (!isAppId(appId)) fail('bad_id', 'Kimlik küçük harf, rakam, - ve _ içerebilir (2-48 karakter)');
    if (RESERVED.has(appId)) fail('bad_id', 'Bu kimlik ayrılmış');
    const name = str(body.name, LIMITS.appNameMax, 'Ad');
    if (!name) fail('bad_name', 'Uygulama adı gerekli');
    const source = String(body.source || '');
    if (!source.trim()) fail('bad_source', 'Kaynak boş olamaz');
    if (source.length > LIMITS.sourceMax) fail('too_large', 'Kaynak 512 KB sınırını aşıyor', 413);

    const m = body.manifest || {};
    const summary = str(m.summary, LIMITS.summaryMax, 'Özet');
    const category = str(m.category, 30, 'Kategori') || 'Araç';
    const version = str(m.version, 20, 'Sürüm') || '1.0.0';
    const iconName = str(m.icon, 40, 'Simge') || 'sparkles';
    const tint = Array.isArray(m.tint) && m.tint.length === 2 &&
      m.tint.every(c => /^#[0-9a-fA-F]{6}$/.test(c)) ? m.tint : ['#5e5ce6', '#bf5af2'];

    const existing = await env.DB.prepare('SELECT author_id, downloads FROM apps WHERE id = ?').bind(appId).first();
    if (existing && existing.author_id !== user.id) fail('conflict', 'Bu kimlik başka bir yazara ait', 409);

    const now = Date.now();
    await env.DB.prepare(
      `INSERT INTO apps (id, name, summary, icon, tint, category, version, source,
                         author_id, created, updated, size, downloads, visible)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1)
       ON CONFLICT(id) DO UPDATE SET
         name=excluded.name, summary=excluded.summary, icon=excluded.icon, tint=excluded.tint,
         category=excluded.category, version=excluded.version, source=excluded.source,
         updated=excluded.updated, size=excluded.size`
    ).bind(appId, name, summary, iconName, JSON.stringify(tint), category, version, source,
           user.id, now, now, source.length, existing?.downloads || 0).run();

    await audit(env, { userId: user.id, action: existing ? 'app_updated' : 'app_published', request, detail: appId });
    const row = await env.DB.prepare(
      `SELECT a.*, u.handle AS author FROM apps a LEFT JOIN users u ON u.id = a.author_id WHERE a.id = ?`
    ).bind(appId).first();
    return json({ ok: true, app: rowToApp(row) }, { request, env, status: existing ? 200 : 201 });
  }

  if (M === 'DELETE' && id) {
    const user = await requireUser(request, env);
    const row = await env.DB.prepare('SELECT author_id, name FROM apps WHERE id = ?').bind(id).first();
    if (!row) fail('not_found', 'Uygulama bulunamadı', 404);
    if (row.author_id !== user.id) fail('forbidden', 'Bu uygulama size ait değil', 403);
    await env.DB.prepare('DELETE FROM apps WHERE id = ?').bind(id).run();
    await audit(env, { userId: user.id, action: 'app_removed', request, detail: id });
    return json({ ok: true }, { request, env });
  }

  return null;
}

const rowToApp = r => ({
  id: r.id, name: r.name, summary: r.summary || '', author: r.author || '',
  icon: r.icon, tint: safeJson(r.tint, ['#5e5ce6', '#bf5af2']),
  category: r.category, version: r.version, updated: r.updated,
  size: r.size, downloads: r.downloads, installed: r.installed,
  source: `/v1/apps/${r.id}/source`,
});
const safeJson = (s, d) => { try { const v = JSON.parse(s); return Array.isArray(v) ? v : d; } catch { return d; } };

const RESERVED = new Set([
  'admin', 'root', 'system', 'openos', 'opensharp', 'openbrow', 'cloud', 'api', 'www',
  'support', 'help', 'security', 'abuse', 'null', 'undefined', 'me', 'you', 'app', 'apps',
  'store', 'official', 'staff', 'moderator', 'mod',
]);
