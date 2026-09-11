-- OpenOS Cloud — D1 şeması
-- wrangler d1 execute openos-cloud --file schema.sql --remote

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  handle        TEXT NOT NULL UNIQUE,
  display       TEXT,
  bio           TEXT DEFAULT '',
  password_hash TEXT NOT NULL,           -- pbkdf2$<iter>$<salt>$<hash>
  avatar_emoji  TEXT DEFAULT '🧑‍🚀',
  avatar_image  TEXT,                    -- base64, <= 96 KB
  avatar_mime   TEXT,
  suspended     INTEGER DEFAULT 0,
  created       INTEGER NOT NULL
);

-- Oturumlar = cihazlar. Belirteç düz değil, SHA-256 özeti olarak saklanır.
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  device     TEXT DEFAULT 'OpenOS',
  platform   TEXT DEFAULT '',
  ip_hash    TEXT,                       -- ham IP asla saklanmaz
  created    INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  expires    INTEGER NOT NULL,
  revoked    INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user  ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);

CREATE TABLE IF NOT EXISTS apps (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  summary    TEXT DEFAULT '',
  icon       TEXT DEFAULT 'sparkles',
  tint       TEXT DEFAULT '["#5e5ce6","#bf5af2"]',
  category   TEXT DEFAULT 'Araç',
  version    TEXT DEFAULT '1.0.0',
  source     TEXT NOT NULL,
  author_id  TEXT REFERENCES users(id) ON DELETE SET NULL,
  created    INTEGER NOT NULL,
  updated    INTEGER NOT NULL,
  size       INTEGER DEFAULT 0,
  downloads  INTEGER DEFAULT 0,
  visible    INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_apps_author   ON apps(author_id);
CREATE INDEX IF NOT EXISTS idx_apps_category ON apps(category);
CREATE INDEX IF NOT EXISTS idx_apps_updated  ON apps(updated DESC);

-- Kullanıcının indirdiği uygulamalar
CREATE TABLE IF NOT EXISTS installs (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_id  TEXT NOT NULL REFERENCES apps(id)  ON DELETE CASCADE,
  at      INTEGER NOT NULL,
  PRIMARY KEY (user_id, app_id)
);

-- Oran sınırlama penceresi (kendi kendini temizler)
CREATE TABLE IF NOT EXISTS rate_limits (
  id TEXT NOT NULL,
  at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate ON rate_limits(id, at);

-- Güvenlik denetim kaydı. IP yalnızca özet olarak tutulur.
CREATE TABLE IF NOT EXISTS audit (
  id      TEXT PRIMARY KEY,
  user_id TEXT,
  action  TEXT NOT NULL,
  ip_hash TEXT,
  detail  TEXT DEFAULT '',
  at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit(user_id, at DESC);
