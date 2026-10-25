// Operacje na kontach użytkowników wspólne dla serwera i skryptu seed.js.
//Tworzenie konta i reset hasła, hashowanie Argon2id.
const argon2 = require('argon2');
const { db, roleId } = require('./db');
const { generateOtp, OTP_VALIDITY_MS } = require('./otp');

// Argon2id z parametrami zalecanymi przez OWASP (m=19 MiB, t=2, p=1). Sól dodaje biblioteka.
const HASH_OPTIONS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };

const hashPassword = (pw) => argon2.hash(pw, HASH_OPTIONS);

// Tworzy konto z hasłem jednorazowym; zwraca to hasło (pokazywane tylko raz).
async function createUser(login, fullName, roleName) {
  const otp = generateOtp();
  const now = Date.now();
  const info = db.prepare(`INSERT INTO users
      (login, full_name, password_hash, role_id, must_change_password, otp_expires_at, password_changed_at, created_at)
      VALUES (?, ?, ?, ?, 1, ?, ?, ?)`)
    .run(login, fullName, await hashPassword(otp), roleId(roleName), now + OTP_VALIDITY_MS, now, now);
  return { id: info.lastInsertRowid, otp };
}

// Reset hasła przez administratora: nowe hasło jednorazowe + wymuszona zmiana.
async function resetPassword(userId) {
  const otp = generateOtp();
  const now = Date.now();
  db.prepare(`UPDATE users SET password_hash = ?, must_change_password = 1, otp_expires_at = ?,
              password_changed_at = ? WHERE id = ?`)
    .run(await hashPassword(otp), now + OTP_VALIDITY_MS, now, userId);
  return otp;
}

module.exports = { hashPassword, createUser, resetPassword };
