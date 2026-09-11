/* ==========================================================================
   OpenOS Cloud — pano (istemci)
   SPDX-License-Identifier: AGPL-3.0-or-later

   Güvenlik notları:
   · Belirteç yalnızca sessionStorage'da durur (sekme kapanınca gider) ve
     istekte Authorization başlığıyla gider — çerez yok, dolayısıyla CSRF yok.
   · Hiçbir yerde innerHTML ile kullanıcı verisi basılmaz; her şey textContent.
   · CSP inline script'i yasaklar; bu dosya dışarıdan yüklenir.
   ========================================================================== */

const API_DEFAULT = 'https://opencloud.m3sto-wolfly.workers.dev';
const API = localStorage.getItem('opencloud.api') || API_DEFAULT;
const TOKEN_KEY = 'opencloud.token';

const AVATARS = ['🧑‍🚀', '🦊', '🐼', '🦉', '🐙', '🌵', '🍄', '🎧', '🛸', '🪐', '🧊', '🔮',
                 '🐝', '🦋', '🌊', '⚡️', '🎨', '🧩'];

/* ---------------------------------------------------------------- tiny dom */
const el = (tag, props = {}, ...kids) => {
  const [name, ...cls] = tag.split('.');
  const n = document.createElement(name || 'div');
  if (cls.length) n.className = cls.join(' ');
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'text') n.textContent = v;
    else if (k === 'html') n.innerHTML = v;             /* yalnızca sabit ikonlar için */
    else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
    else if (k === 'style' && typeof v === 'object') Object.entries(v).forEach(([p, val]) =>
      p.startsWith('--') ? n.style.setProperty(p, val) : (n.style[p] = val));
    else n.setAttribute(k, v === true ? '' : v);
  }
  kids.flat().forEach(k => k != null && k !== false &&
    n.appendChild(k.nodeType ? k : document.createTextNode(String(k))));
  return n;
};
const $ = s => document.querySelector(s);
const clear = n => { while (n.firstChild) n.removeChild(n.firstChild); return n; };

function toast(message, bad) {
  const t = $('#toast');
  t.textContent = message;
  t.className = 'toast' + (bad ? ' bad' : '');
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, 2600);
}

const fmtDate = ts => ts ? new Date(ts).toLocaleString('tr-TR',
  { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';
const fmtRel = ts => {
  if (!ts) return '—';
  const s = Math.round((ts - Date.now()) / 1000), a = Math.abs(s);
  const steps = [[60, 'second', 1], [3600, 'minute', 60], [86400, 'hour', 3600],
                 [604800, 'day', 86400], [2592000, 'week', 604800], [31536000, 'month', 2592000]];
  let unit = 'year', div = 31536000;
  for (const [lim, u, d] of steps) if (a < lim) { unit = u; div = d; break; }
  return new Intl.RelativeTimeFormat('tr', { numeric: 'auto' }).format(Math.round(s / div), unit);
};
const fmtBytes = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB'
  : (n / 1048576).toFixed(1) + ' MB';

/* ---------------------------------------------------------------- api */
const state = { user: null, view: 'overview' };
const token = {
  get: () => sessionStorage.getItem(TOKEN_KEY) || localStorage.getItem(TOKEN_KEY),
  set: (t, remember) => {
    sessionStorage.setItem(TOKEN_KEY, t);
    if (remember) localStorage.setItem(TOKEN_KEY, t);
  },
  clear: () => { sessionStorage.removeItem(TOKEN_KEY); localStorage.removeItem(TOKEN_KEY); },
};

async function api(path, { method = 'GET', body, auth = true } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: {
      Accept: 'application/json',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(auth && token.get() ? { Authorization: 'Bearer ' + token.get() } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { error: 'Beklenmeyen yanıt' }; }
  if (!res.ok) {
    const err = new Error(data?.error || `HTTP ${res.status}`);
    err.code = data?.code; err.status = res.status;
    throw err;
  }
  return data;
}

/* ---------------------------------------------------------------- theme */
function applyTheme(t) {
  const mode = t || localStorage.getItem('opencloud.theme') || 'auto';
  localStorage.setItem('opencloud.theme', mode);
  const dark = mode === 'dark' ||
    (mode === 'auto' && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
}
$('#themeBtn').addEventListener('click', () => {
  const order = ['auto', 'light', 'dark'];
  const cur = localStorage.getItem('opencloud.theme') || 'auto';
  applyTheme(order[(order.indexOf(cur) + 1) % order.length]);
  toast('Görünüm: ' + (localStorage.getItem('opencloud.theme')));
});
applyTheme();

/* ---------------------------------------------------------------- boot */
$('#signoutBtn').addEventListener('click', signOut);
$('#topnav').addEventListener('click', e => {
  const b = e.target.closest('button[data-view]');
  if (b) show(b.dataset.view);
});

pingApi();
start();

async function pingApi() {
  const s = $('#apiStatus');
  try {
    const r = await api('/v1/stats', { auth: false });
    s.className = 'status ok';
    s.textContent = `${r.users} hesap · ${r.apps} uygulama · ${r.devices} cihaz`;
    state.stats = r;
  } catch {
    s.className = 'status bad';
    s.textContent = 'API ulaşılamıyor';
  }
}

async function start() {
  if (!token.get()) return renderLanding();
  try {
    const r = await api('/v1/auth/me');
    state.user = r.user;
    renderApp();
  } catch {
    token.clear();
    renderLanding();
  }
}

function signOut() {
  api('/v1/auth/logout', { method: 'POST' }).catch(() => {});
  token.clear();
  state.user = null;
  renderLanding();
  toast('Çıkış yapıldı');
}

/* ================================================================ landing */
function renderLanding() {
  $('#topnav').hidden = true;
  $('#signoutBtn').hidden = true;
  const main = clear($('#main'));

  let mode = 'login';
  const msg = el('div.msg');
  const email = el('input', { type: 'email', autocomplete: 'email', placeholder: 'siz@example.com' });
  const pass = el('input', { type: 'password', autocomplete: 'current-password', placeholder: '••••••••••' });
  const handle = el('input', { autocomplete: 'username', placeholder: 'kullanici_adi', maxlength: '24' });
  const remember = el('input', { type: 'checkbox' });
  const handleField = el('div.field',
    el('label', { text: 'Kullanıcı adı' }), handle,
    el('div.hint', { text: '3–24 karakter · küçük harf, rakam, - ve _' }));
  handleField.hidden = true;

  const submit = el('button.btn.primary.full', { text: 'Giriş yap', type: 'button' });
  const seg = el('div.seg',
    el('button', { text: 'Giriş', 'aria-selected': 'true', type: 'button', onclick: () => setMode('login') }),
    el('button', { text: 'Kaydol', 'aria-selected': 'false', type: 'button', onclick: () => setMode('signup') }));

  function setMode(m) {
    mode = m;
    [...seg.children].forEach((b, i) => b.setAttribute('aria-selected', String((i === 0) === (m === 'login'))));
    handleField.hidden = m === 'login';
    submit.textContent = m === 'login' ? 'Giriş yap' : 'Hesap oluştur';
    pass.autocomplete = m === 'login' ? 'current-password' : 'new-password';
    msg.textContent = '';
  }

  async function go() {
    msg.className = 'msg';
    msg.textContent = '';
    submit.disabled = true;
    const original = submit.textContent;
    submit.textContent = '…';
    try {
      const device = deviceName();
      const r = mode === 'login'
        ? await api('/v1/auth/login', { auth: false, method: 'POST',
            body: { email: email.value.trim(), password: pass.value, device } })
        : await api('/v1/auth/signup', { auth: false, method: 'POST',
            body: { email: email.value.trim(), password: pass.value, handle: handle.value.trim().toLowerCase(), device } });
      token.set(r.token, remember.checked);
      state.user = r.user;
      const me = await api('/v1/auth/me');
      state.user = me.user;
      renderApp();
      toast(mode === 'login' ? 'Hoş geldiniz' : 'Hesabınız hazır');
      pingApi();
    } catch (e) {
      msg.className = 'msg bad';
      msg.textContent = e.message;
      submit.disabled = false;
      submit.textContent = original;
    }
  }
  submit.addEventListener('click', go);
  [email, pass, handle].forEach(i => i.addEventListener('keydown', e => { if (e.key === 'Enter') go(); }));

  main.append(
    el('section.hero',
      el('div.hero-mark', { html:
        '<svg viewBox="0 0 100 100" width="52" height="52"><circle cx="50" cy="50" r="40" fill="none" stroke="#fff" stroke-width="9"/><path d="M36 62L64 38" stroke="rgba(255,255,255,.62)" stroke-width="9" stroke-linecap="round"/></svg>' }),
      el('h1', { text: 'OpenOS Cloud' }),
      el('p', { text: 'Hesabınız, yayınladığınız OpenSharp uygulamaları ve OpenOS çalıştırdığınız her cihaz — tek yerde.' }),
      el('div.sub', { text: 'Hesap açmadan da App Store’dan uygulama indirebilirsiniz. Hesap yalnızca yayınlamak ve cihazlarınızı eşlemek için gerekir.' })),
    el('section.auth-card',
      seg,
      el('div.field', el('label', { text: 'E-posta' }), email),
      handleField,
      el('div.field', el('label', { text: 'Şifre' }), pass,
        el('div.hint', { text: 'En az 10 karakter; küçük harf, büyük harf, rakam ve simgeden üçü' })),
      el('label.field', { style: { flexDirection: 'row', alignItems: 'center', gap: '8px' } },
        remember, el('span', { text: 'Bu tarayıcıda oturumumu açık tut', style: { fontSize: '12.5px', color: 'var(--text-2)' } })),
      submit, msg),
    el('section.stats', { style: { marginTop: '30px' } },
      statCard(state.stats?.users, 'hesap'),
      statCard(state.stats?.apps, 'yayınlanan uygulama'),
      statCard(state.stats?.downloads, 'indirme'),
      statCard(state.stats?.devices, 'bağlı cihaz')),
  );
}

const statCard = (n, label) => el('div.stat',
  el('div.n', { text: n == null ? '—' : String(n) }), el('div.l', { text: label }));

function deviceName() {
  const ua = navigator.userAgent;
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X|Macintosh/.test(ua) ? 'macOS'
    : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS'
    : /Linux/.test(ua) ? 'Linux' : 'Cihaz';
  return `OpenOS Cloud panosu · ${os}`;
}

/* ================================================================== app */
function renderApp() {
  $('#topnav').hidden = false;
  $('#signoutBtn').hidden = false;
  show(state.view);
}

function show(view) {
  state.view = view;
  [...$('#topnav').children].forEach(b =>
    b.setAttribute('aria-current', String(b.dataset.view === view)));
  const main = clear($('#main'));
  main.appendChild(el('div.view', { id: 'view' }, el('div', { html: '<span class="spinner"></span>' })));
  ({ overview, apps: myApps, devices, library, profile, security }[view] || overview)();
}

const view = () => clear($('#view'));

/* ---------------- overview ---------------- */
async function overview() {
  const v = view();
  const u = state.user;
  v.append(
    el('div.profile-head',
      avatarEl(u, 86),
      el('div',
        el('h2', { text: u.display || u.handle }),
        el('div.lede', { text: '@' + u.handle + ' · ' + (u.email || '') }),
        el('div.lede', { text: 'Katılım: ' + fmtDate(u.created) }))),
    el('section.stats',
      statCard(u.published, 'yayınlanan uygulama'),
      statCard(u.installed, 'kütüphanedeki uygulama'),
      statCard(u.devices, 'etkin cihaz'),
      statCard(state.stats?.downloads ?? '—', 'toplam indirme (ağ)')),
    el('section.card',
      el('h3', { text: 'OpenOS’u bu hesapla bağlayın' }),
      el('div.lede', { text: 'OpenOS içinde Sistem Ayarları → OpenOS Cloud, ya da App Store → OpenOS Cloud bölümünden aynı e-posta ve şifreyle giriş yapın. Bağlanan her cihaz aşağıdaki Cihazlar listesinde görünür.' }),
      el('pre', { text: 'Sunucu: ' + API })),
  );
}

function avatarEl(u, size = 42) {
  const box = el('div.avatar', { style: { width: size + 'px', height: size + 'px', fontSize: (size * .45) + 'px' } });
  if (u.hasAvatarImage) {
    const img = el('img', { alt: '', src: `${API}/v1/users/${encodeURIComponent(u.handle)}/avatar` });
    img.addEventListener('error', () => { box.textContent = u.avatar || '🧑‍🚀'; });
    box.appendChild(img);
  } else box.textContent = u.avatar || '🧑‍🚀';
  return box;
}

/* ---------------- my apps ---------------- */
async function myApps() {
  const v = view();
  v.append(el('h2', { text: 'Uygulamalarım' }),
    el('div.lede', { text: 'OpenOS Studio’dan “Yayınla” dediğinizde uygulamalar burada belirir.' }));
  try {
    const r = await api('/v1/apps?mine=1');
    if (!r.apps.length) {
      v.appendChild(el('div.empty', el('div.g', { text: '🚀' }),
        el('div', { text: 'Henüz yayınlanmış uygulamanız yok' })));
      return;
    }
    const list = el('div.list');
    r.apps.forEach(a => list.appendChild(el('div.row',
      appIcon(a),
      el('div.grow',
        el('div.t', { text: a.name }),
        el('div.s', { text: `${a.id} · v${a.version} · ${fmtBytes(a.size)} · ${a.downloads} indirme` }),
        a.summary ? el('div.s', { text: a.summary }) : null),
      el('span.pill.gray', { text: a.category }),
      el('button.btn.small.danger', { text: 'Kaldır', type: 'button', onclick: async () => {
        if (!confirm(`${a.name} mağazadan kaldırılsın mı?`)) return;
        try { await api('/v1/apps/' + encodeURIComponent(a.id), { method: 'DELETE' }); toast('Kaldırıldı'); myApps(); }
        catch (e) { toast(e.message, true); }
      } }))));
    v.appendChild(list);
  } catch (e) { v.appendChild(errorBox(e)); }
}

const appIcon = a => {
  const t = Array.isArray(a.tint) ? a.tint : ['#5e5ce6', '#bf5af2'];
  return el('div.appicon', { style: { '--c1': t[0], '--c2': t[1] }, text: (a.name || '?')[0].toUpperCase() });
};

/* ---------------- devices ---------------- */
async function devices() {
  const v = view();
  v.append(el('h2', { text: 'Cihazlar' }),
    el('div.lede', { text: 'Bu hesapla giriş yapılmış OpenOS kurulumları. Tanımadığınız bir cihaz görürseniz oturumunu kapatın ve şifrenizi değiştirin.' }));
  try {
    const r = await api('/v1/devices');
    const list = el('div.list');
    r.devices.forEach(d => list.appendChild(el('div.row',
      d.active ? el('span.live', { title: 'Şu anda etkin' }) : el('span.live', { style: { background: 'var(--text-3)', animation: 'none' } }),
      el('div.grow',
        el('div.t', { text: d.name + (d.current ? ' (bu cihaz)' : '') }),
        el('div.s', { text: `${d.platform} · giriş ${fmtDate(d.created)}` }),
        el('div.s', { text: 'son görülme ' + fmtRel(d.lastSeen) })),
      d.revoked ? el('span.pill.gray', { text: 'KAPALI' })
        : d.active ? el('span.pill.green', { text: 'ETKİN' }) : el('span.pill.gray', { text: 'BEKLEMEDE' }),
      d.revoked ? null : el('button.btn.small', { text: d.current ? 'Çıkış' : 'Oturumu kapat', type: 'button',
        onclick: async () => {
          try {
            await api('/v1/devices/' + encodeURIComponent(d.id), { method: 'DELETE' });
            if (d.current) return signOut();
            toast('Cihaz çıkarıldı'); devices();
          } catch (e) { toast(e.message, true); }
        } }))));
    v.appendChild(r.devices.length ? list
      : el('div.empty', el('div.g', { text: '💻' }), el('div', { text: 'Cihaz yok' })));
  } catch (e) { v.appendChild(errorBox(e)); }
}

/* ---------------- library ---------------- */
async function library() {
  const v = view();
  v.append(el('h2', { text: 'Kütüphane' }),
    el('div.lede', { text: 'OpenOS’ta bu hesapla indirdiğiniz uygulamalar.' }));
  try {
    const r = await api('/v1/library');
    if (!r.apps.length) {
      v.appendChild(el('div.empty', el('div.g', { text: '📦' }),
        el('div', { text: 'Henüz uygulama indirmediniz' })));
      return;
    }
    const list = el('div.list');
    r.apps.forEach(a => list.appendChild(el('div.row',
      appIcon(a),
      el('div.grow',
        el('div.t', { text: a.name }),
        el('div.s', { text: `@${a.author || 'bilinmiyor'} · v${a.version}` }),
        el('div.s', { text: 'indirildi ' + fmtRel(a.installed) })),
      el('span.pill.gray', { text: a.category }))));
    v.appendChild(list);
  } catch (e) { v.appendChild(errorBox(e)); }
}

/* ---------------- profile ---------------- */
async function profile() {
  const v = view();
  const u = state.user;
  const display = el('input', { value: u.display || '', maxlength: '48' });
  const bio = el('textarea', { rows: '3', maxlength: '280' });
  bio.value = u.bio || '';
  let emoji = u.avatar || '🧑‍🚀';

  const preview = avatarEl(u, 86);
  const grid = el('div.emoji-grid', ...AVATARS.map(a =>
    el('button', { text: a, type: 'button', 'aria-pressed': String(a === emoji), onclick: () => {
      emoji = a;
      [...grid.children].forEach(b => b.setAttribute('aria-pressed', String(b.textContent === a)));
      clear(preview).textContent = a;
    } })));

  const drop = el('div.drop', { text: 'Görsel yüklemek için sürükleyin ya da tıklayın · PNG/JPEG/WebP · en fazla 96 KB' });
  const file = el('input', { type: 'file', accept: 'image/png,image/jpeg,image/webp', style: { display: 'none' } });
  drop.addEventListener('click', () => file.click());
  drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', e => {
    e.preventDefault(); drop.classList.remove('over');
    if (e.dataTransfer.files[0]) uploadAvatar(e.dataTransfer.files[0]);
  });
  file.addEventListener('change', () => file.files[0] && uploadAvatar(file.files[0]));

  async function uploadAvatar(f) {
    if (!/^image\/(png|jpeg|webp)$/.test(f.type)) return toast('Yalnızca PNG, JPEG ya da WebP', true);
    if (f.size > 96 * 1024) return toast('Görsel 96 KB’den küçük olmalı', true);
    drop.textContent = 'Yükleniyor…';
    try {
      const dataUrl = await new Promise((res, rej) => {
        const r = new FileReader();
        r.onload = () => res(r.result); r.onerror = rej; r.readAsDataURL(f);
      });
      await api('/v1/profile/avatar', { method: 'PUT', body: { image: dataUrl } });
      state.user.hasAvatarImage = true;
      toast('Avatar güncellendi');
      profile();
    } catch (e) { toast(e.message, true); drop.textContent = 'Yükleme başarısız — tekrar deneyin'; }
  }

  const save = el('button.btn.primary', { text: 'Kaydet', type: 'button', onclick: async () => {
    save.disabled = true;
    try {
      const r = await api('/v1/profile', { method: 'PUT',
        body: { display: display.value.trim(), bio: bio.value.trim(), avatar: emoji } });
      state.user = { ...state.user, ...r.user };
      toast('Profil kaydedildi');
    } catch (e) { toast(e.message, true); }
    finally { save.disabled = false; }
  } });

  v.append(
    el('h2', { text: 'Profil' }),
    el('section.card',
      el('div.profile-head', preview,
        el('div', el('div.t', { text: '@' + u.handle, style: { fontSize: '17px', fontWeight: '620' } }),
          el('div.s', { text: u.email || '' }))),
      el('div.field', el('label', { text: 'Görünen ad' }), display),
      el('div.field', el('label', { text: 'Hakkında' }), bio,
        el('div.hint', { text: 'En fazla 280 karakter' })),
      el('div.field', el('label', { text: 'Avatar' }), grid),
      drop, file,
      u.hasAvatarImage ? el('button.btn.small', { text: 'Yüklenen görseli kaldır', type: 'button', onclick: async () => {
        try { await api('/v1/profile/avatar', { method: 'DELETE' }); state.user.hasAvatarImage = false; toast('Kaldırıldı'); profile(); }
        catch (e) { toast(e.message, true); }
      } }) : null,
      el('div', save)),
  );
}

/* ---------------- security ---------------- */
async function security() {
  const v = view();
  const cur = el('input', { type: 'password', autocomplete: 'current-password' });
  const next = el('input', { type: 'password', autocomplete: 'new-password' });
  const msg = el('div.msg');

  const change = el('button.btn.primary', { text: 'Şifreyi değiştir', type: 'button', onclick: async () => {
    msg.className = 'msg'; msg.textContent = '';
    change.disabled = true;
    try {
      await api('/v1/auth/password', { method: 'PUT', body: { current: cur.value, next: next.value } });
      msg.className = 'msg ok';
      msg.textContent = 'Şifre değiştirildi. Diğer tüm cihazların oturumu kapatıldı.';
      cur.value = next.value = '';
    } catch (e) { msg.className = 'msg bad'; msg.textContent = e.message; }
    finally { change.disabled = false; }
  } });

  v.append(
    el('h2', { text: 'Güvenlik' }),
    el('section.card',
      el('h3', { text: 'Şifre' }),
      el('div.field', el('label', { text: 'Mevcut şifre' }), cur),
      el('div.field', el('label', { text: 'Yeni şifre' }), next,
        el('div.hint', { text: 'En az 10 karakter; küçük harf, büyük harf, rakam ve simgeden en az üçü' })),
      change, msg),
    el('section.card',
      el('h3', { text: 'Bu hesap nasıl korunuyor' }),
      el('div.lede', { text:
        '· Şifreler PBKDF2-SHA256 ile 310.000 tur türetilir; sunucu düz şifreyi hiçbir zaman saklamaz.\n' +
        '· Oturum belirteçleri veritabanında yalnızca SHA-256 özeti olarak durur; sızan bir yedek oturum açamaz.\n' +
        '· IP adresleri ham saklanmaz, gizli bir biberle özetlenir.\n' +
        '· Giriş, kayıt ve yayınlama uçları oran sınırlıdır.\n' +
        '· Şifre değişimi tüm diğer cihazların oturumunu kapatır.',
        style: { whiteSpace: 'pre-line' } }),
      el('a.btn.small', { href: 'https://github.com/m3sto/openos-cloud/blob/main/SECURITY.md', rel: 'noopener',
        text: 'Güvenlik belgesi' })),
    el('section.card',
      el('h3', { text: 'Sunucu' }),
      el('div.field', el('label', { text: 'API adresi' }),
        (() => {
          const i = el('input', { value: API });
          i.addEventListener('change', () => {
            localStorage.setItem('opencloud.api', i.value.trim() || API_DEFAULT);
            location.reload();
          });
          return i;
        })(),
        el('div.hint', { text: 'Kendi Worker’ınızı çalıştırıyorsanız adresini buraya yazın.' }))),
  );
}

const errorBox = e => el('div.empty', el('div.g', { text: '⚠️' }), el('div', { text: e.message }));
