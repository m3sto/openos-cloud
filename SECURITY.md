# Güvenlik

OpenOS Cloud hesap barındırdığı için bu depo herkese açık olsa da **hiçbir
gizli değer içermez** ve kaynağı okuyan biri hesapları ele geçirebilecek bir
bilgiye ulaşamaz. Aşağıda tasarım kararları ve doğrulanabilir taahhütler var.

## Açığı nasıl bildirirsiniz

Genel bir issue **açmayın**. GitHub'ın **Security → Report a vulnerability**
özelliğini kullanın. 72 saat içinde dönüş yapılır.

---

## Kimlik doğrulama

| Konu | Karar |
| --- | --- |
| Şifre saklama | PBKDF2-SHA256, **310.000 tur**, 16 baytlık rastgele tuz. Biçim: `pbkdf2$<tur>$<tuz>$<özet>` |
| Tur sınırı | Workers çalışma zamanı tek bir `deriveBits` çağrısında 100.000 turu aşmayı reddeder. Tur sayısını düşürmek yerine **zincir parçalara bölünür**: her parçanın çıktısı bir sonrakinin anahtar malzemesi olur. Toplam iş faktörü korunur, sonuç yine yalnızca (şifre, tuz, tur) ile belirlenir. Ölçülen maliyet: giriş/kayıt başına ~1,9 sn |
| Şifre karşılaştırma | Sabit zamanlı (`timingSafeEqual`) — uzunluk bile sızmaz |
| Kullanıcı yokken | Yine de bir PBKDF2 turu koşulur; giriş süresi kullanıcı varlığını ele vermez |
| Şifre kuralı | En az 10 karakter, dört sınıftan en az üçü, yaygın kalıp taraması |
| Oturum belirteci | 32 bayt `crypto.getRandomValues`, base64url. **Veritabanında düz değil, SHA-256 özeti** saklanır |
| Oturum ömrü | 60 gün; süresi dolan oturum ilk kullanımda iptal edilir |
| Şifre değişimi | Diğer **tüm** oturumları düşürür |
| Çerez | Yok. Belirteç `Authorization` başlığıyla taşınır → CSRF yüzeyi yok |

JWT kullanılmamasının nedeni kasıtlıdır: opak belirteç, veritabanından
**anında iptal edilebilir**; imzalı bir JWT iptal edilemez.

## Oran sınırlama

| Uç | Sınır |
| --- | --- |
| `auth/login` | IP başına 5 dk'da 8; ayrıca hesap başına aynı pencere |
| `auth/signup` | IP başına saatte 4 |
| `auth/password` | hesap başına saatte 5 |
| `apps` (yayınlama) | hesap başına saatte 30 |
| `profile/avatar` | hesap başına saatte 12 |
| genel | IP başına dakikada 240 |

Pencere D1'de tutulur ve kendi kendini temizler.

## Girdi doğrulama

- Her istek gövdesi 1 MB ile sınırlıdır ve `Content-Type: application/json` zorunludur.
- Tüm metin alanları uzunluk sınırlıdır (`LIMITS`), `trim` edilir.
- Kullanıcı adı ve uygulama kimliği katı düzenli ifadeyle doğrulanır; ayrılmış
  adlar (`admin`, `system`, `openos`, …) reddedilir.
- Renk değerleri `#rrggbb` biçimiyle sınırlıdır — stil enjeksiyonu mümkün değil.
- Arama sorgusundaki `%`, `_` ve `\` karakterleri kaçırılır (`LIKE … ESCAPE`).
- **Tüm SQL hazırlanmış ifadelerle** çalışır; sorgu metnine hiçbir kullanıcı
  girdisi birleştirilmez.

## Dosya yükleme (avatar)

- Yalnızca `image/png`, `image/jpeg`, `image/webp`.
- 96 KB üst sınır.
- Yalnızca MIME'e güvenilmez: **sihirli baytlar doğrulanır** (PNG imzası,
  JPEG SOI, RIFF/WEBP). Uzantı ya da başlık yalanı burada durur.
- Sunum: `Content-Disposition: inline` + `X-Content-Type-Options: nosniff`,
  yani tarayıcı içeriği yeniden yorumlamaz.

## Gizlilik

- **Ham IP adresi hiçbir tabloda yoktur.** Oran sınırı ve denetim kaydı için
  IP, gizli bir biberle (`IP_PEPPER`) SHA-256'lanır ve ilk 32 karakteri tutulur.
- E-posta yalnızca hesap sahibine gösterilir; herkese açık profilde yer almaz.
- Denetim kaydı (`audit`) yalnızca eylem türü, zaman ve IP özeti tutar.

## Aktarım ve başlıklar

- Cloudflare üzerinden yalnızca HTTPS.
- CORS **beyaz listeyle** çalışır (`ALLOWED_ORIGINS`); `*` kullanılmaz ve
  `Vary: Origin` gönderilir.
- Her yanıtta: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`, `Permissions-Policy` kısıtlaması, `Cache-Control: no-store`.
- Pano `Content-Security-Policy` ile `default-src 'none'` temelli çalışır;
  satır içi script yoktur, `connect-src` yalnızca API adresidir.

## Pano (istemci) tarafı

- Kullanıcı verisi **hiçbir yerde `innerHTML` ile basılmaz**; yalnızca
  `textContent`. `innerHTML` sadece kaynakta sabit olan SVG ikonlar için kullanılır.
- Belirteç varsayılan olarak `sessionStorage`dadır; "oturumumu açık tut"
  seçilmedikçe sekme kapanınca silinir.

## Hata yönetimi

İstemciye dönen tek biçim `{ error, code }`. Yakalanmamış hatalar Worker
günlüğüne yazılır, istemciye `{"error":"Sunucu hatası","code":"internal"}`
döner. Yığın izi, SQL metni ya da dosya yolu asla sızmaz.

## Bilinçli olarak yapılmayanlar

- **E-posta doğrulaması yok.** Bir e-posta sağlayıcısı bağlanana kadar hesap
  açmak e-postaya erişimi kanıtlamaz. Bu nedenle e-posta hiçbir yetki kararında
  kullanılmaz — yalnızca giriş kimliğidir.
- **Şifre sıfırlama yok.** E-posta gönderimi olmadan güvenli bir sıfırlama
  akışı kurulamaz; yarım bir akış açık kapı bırakır.
- **Yönetici arayüzü yok.** Moderasyon gerektiğinde `wrangler d1 execute` ile
  yapılır; ayrıcalıklı bir HTTP yüzeyi yoktur.
