<div align="center">

# OpenOS Cloud

**Hesaplar · OpenSharp App Store · cihaz eşleme**
[OpenOS](https://github.com/m3sto/openos) için Cloudflare Worker + D1 üzerinde çalışan arka uç
ve GitHub Pages üzerinde çalışan pano.

[Pano](https://m3sto.github.io/openos-cloud/) · [API](https://opencloud.m3sto-wolfly.workers.dev/v1) · [Güvenlik](SECURITY.md)

</div>

---

## Bu depoda ne var

```
src/worker.js        API (Cloudflare Worker)
src/lib.js           kriptografi, doğrulama, oran sınırı, oturum yardımcıları
schema.sql           D1 şeması
wrangler.toml        dağıtım yapılandırması (gizli değer içermez)
docs/                GitHub Pages panosu (statik, bağımlılıksız)
SECURITY.md          tehdit modeli ve bildirim yolu
```

**Depoda hiçbir gizli değer yoktur.** `JWT_SECRET` ve `IP_PEPPER` yalnızca
`wrangler secret` ile Cloudflare'e verilir; `wrangler.toml` içinde yalnızca
gizli olmayan ayarlar (CORS beyaz listesi, D1 kimliği) bulunur.

---

## Kurulum

### 1. Veritabanı

```bash
npx wrangler d1 create openos-cloud
# çıkan database_id'yi wrangler.toml içine yapıştırın
npx wrangler d1 execute openos-cloud --file schema.sql --remote
```

### 2. Gizli değerler

```bash
npx wrangler secret put JWT_SECRET    # oturum/özet anahtarı — uzun ve rastgele
npx wrangler secret put IP_PEPPER     # IP özetleme biberi — uzun ve rastgele
```

Üretmek için: `openssl rand -base64 48`

### 3. CORS beyaz listesi

`wrangler.toml` içindeki `ALLOWED_ORIGINS` değerine panonun ve OpenOS'un
çalıştığı adresleri yazın. Yıldız (`*`) kullanmayın.

```toml
ALLOWED_ORIGINS = "https://m3sto.github.io,https://openos.example.com"
```

### 4. Dağıtım

```bash
npx wrangler deploy
```

### 5. Pano (GitHub Pages)

Depo ayarlarından **Settings → Pages → Source: Deploy from a branch →
main / docs** seçin. Pano `https://<kullanici>.github.io/openos-cloud/`
adresinde yayına girer.

### 6. OpenOS'u bağlayın

OpenOS içinde **Sistem Ayarları → OpenOS Cloud** (ya da App Store → OpenOS Cloud)
bölümüne API adresini yazıp giriş yapın. O andan itibaren cihaz, panodaki
**Cihazlar** listesinde görünür.

---

## API

Tüm yanıtlar JSON'dur. Kimlik doğrulama `Authorization: Bearer <token>`
başlığıyla yapılır — çerez yoktur, dolayısıyla CSRF yüzeyi yoktur.

| Yöntem | Uç nokta | Açıklama |
| --- | --- | --- |
| `GET` | `/v1/stats` | herkese açık sayaçlar |
| `POST` | `/v1/auth/signup` | `{ email, password, handle, device? }` |
| `POST` | `/v1/auth/login` | `{ email, password, device? }` |
| `POST` | `/v1/auth/logout` | mevcut oturumu kapatır |
| `GET` | `/v1/auth/me` | oturum sahibinin profili |
| `PUT` | `/v1/auth/password` | `{ current, next }` — diğer oturumları düşürür |
| `GET` | `/v1/devices` | bağlı OpenOS cihazları |
| `DELETE` | `/v1/devices/:id` | cihazın oturumunu kapatır |
| `PUT` | `/v1/profile` | `{ display, bio, avatar }` |
| `PUT` | `/v1/profile/avatar` | `{ image: "data:image/png;base64,…" }` (≤96 KB) |
| `DELETE` | `/v1/profile/avatar` | yüklenen görseli siler |
| `GET` | `/v1/users/:handle` | herkese açık profil |
| `GET` | `/v1/users/:handle/avatar` | avatar görseli |
| `GET` | `/v1/apps` | katalog (`?q=`, `?category=`, `?mine=1`) |
| `GET` | `/v1/apps/:id` | tek uygulama |
| `GET` | `/v1/apps/:id/source` | OpenSharp kaynağı (düz metin) |
| `POST` | `/v1/apps` | yayınla / güncelle |
| `DELETE` | `/v1/apps/:id` | yayından kaldır |
| `POST` | `/v1/apps/:id/install` | indirme sayacı + kütüphaneye ekleme |
| `GET` | `/v1/library` | indirdiğim uygulamalar |

Hatalar tek biçimdedir: `{ "error": "kullanıcıya gösterilecek metin", "code": "sabit_kod" }`.
İç hata metinleri, yığın izleri ve SQL asla istemciye dönmez.

---

## Yerelde çalıştırma

```bash
npx wrangler d1 execute openos-cloud --file schema.sql --local
npx wrangler dev
```

Gizli değerleri yerelde `.dev.vars` dosyasından okur (bu dosya `.gitignore`dadır):

```
JWT_SECRET="yerel-gelistirme-anahtari"
IP_PEPPER="yerel-biber"
```

---

## Lisans

AGPL-3.0-or-later. "OpenOS", "OpenSharp", "OpenBrow" ve "OpenOS Cloud"
isimleri ile logo lisans kapsamı dışındadır — ayrıntı için
[OpenOS/NOTICE](https://github.com/m3sto/openos/blob/main/NOTICE).
