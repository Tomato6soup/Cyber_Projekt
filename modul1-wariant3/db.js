// Warstwa danych: schemat bazy SQLite, role, uprawnienia (RBAC) i ustawienia.
const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'app.db'));
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS roles (
  id    INTEGER PRIMARY KEY,
  name  TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS permissions (
  id    INTEGER PRIMARY KEY,
  code  TEXT UNIQUE NOT NULL,
  description TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS role_permissions (
  role_id       INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);
CREATE TABLE IF NOT EXISTS users (
  id                   INTEGER PRIMARY KEY,
  login                TEXT UNIQUE NOT NULL COLLATE NOCASE,
  full_name            TEXT NOT NULL DEFAULT '',
  password_hash        TEXT NOT NULL,
  role_id              INTEGER NOT NULL REFERENCES roles(id),
  is_blocked           INTEGER NOT NULL DEFAULT 0,
  must_change_password INTEGER NOT NULL DEFAULT 1,
  otp_expires_at       INTEGER,            -- ustawione, gdy aktualne hasło jest jednorazowe
  password_changed_at  INTEGER NOT NULL,
  totp_secret          TEXT,
  totp_enabled         INTEGER NOT NULL DEFAULT 0,
  created_at           INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS password_history (
  id            INTEGER PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS articles (
  id         INTEGER PRIMARY KEY,
  title      TEXT NOT NULL,
  body       TEXT NOT NULL,
  author_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL
);
`);

// Macierz uprawnień (zasada najmniejszych uprawnień).
const PERMISSIONS = {
  'articles.read':   'Odczyt artykułów',
  'articles.write':  'Dodawanie i usuwanie artykułów',
  'users.manage':    'Zarządzanie użytkownikami',
  'settings.manage': 'Zmiana ustawień bezpieczeństwa',
};
const ROLE_PERMISSIONS = {
  'Administrator': ['users.manage', 'settings.manage', 'articles.read'],
  'Redaktor':      ['articles.read', 'articles.write'],
  'Czytelnik':     ['articles.read'],
};
const DEFAULT_SETTINGS = {
  min_length: '15',               // wariant 3: domyślnie 15 znaków
  policy_no_sequences: '1',       // dodatkowa reguła wariantu 3 (włączana przez admina)
  password_validity_days: '0',    // 0 = bez wygasania (NIST nie zaleca okresowej zmiany)
  session_timeout_minutes: '15',
  password_history_count: '5',
};

db.transaction(() => {
  for (const [code, desc] of Object.entries(PERMISSIONS)) {
    db.prepare('INSERT OR IGNORE INTO permissions (code, description) VALUES (?, ?)').run(code, desc);
  }
  for (const [role, perms] of Object.entries(ROLE_PERMISSIONS)) {
    db.prepare('INSERT OR IGNORE INTO roles (name) VALUES (?)').run(role);
    const roleId = db.prepare('SELECT id FROM roles WHERE name = ?').get(role).id;
    for (const p of perms) {
      db.prepare(`INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
                  SELECT ?, id FROM permissions WHERE code = ?`).run(roleId, p);
    }
  }
  for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
    db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)').run(k, v);
  }
})();

function getSettings() {
  const s = {};
  for (const row of db.prepare('SELECT key, value FROM settings').all()) s[row.key] = Number(row.value);
  return s;
}

function setSetting(key, value) {
  db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(String(value), key);
}

function getPermissions(roleId) {
  return db.prepare(`SELECT p.code FROM permissions p
                     JOIN role_permissions rp ON rp.permission_id = p.id
                     WHERE rp.role_id = ?`).all(roleId).map(r => r.code);
}

function roleId(name) {
  const r = db.prepare('SELECT id FROM roles WHERE name = ?').get(name);
  return r ? r.id : null;
}

module.exports = { db, getSettings, setSetting, getPermissions, roleId, ROLE_PERMISSIONS, PERMISSIONS };
