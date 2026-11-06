// limity nieudanych logowań, dziennik zdarzeń bezpieczeństwa, reCAPTCHA i alerty Canarytokens.
const { db, getSettings } = require('./db');
const config = require('./config');

const LOCK_MS = 15 * 60000;                       
const RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';

// ---------- dziennik zdarzeń ----------

function logEvent(type, req, { login = null, details = '' } = {}) {
  db.prepare('INSERT INTO security_events (type, login, ip, details, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(type, login, req.ip, details, Date.now());
  console.warn(`[ALERT] ${type} login=${login ?? '-'} ip=${req.ip} ${details}`);
}

// ---------- limit prób na konto ----------


function accountLockedUntil(login) {
  const row = db.prepare('SELECT locked_until FROM login_attempts WHERE login = ?').get(login);
  return row && row.locked_until > Date.now() ? row.locked_until : 0;
}

// Zwraca { lockedUntil } po przekroczeniu limitu albo { left } - liczbę pozostałych prób.
function registerFailure(login) {
  const max = getSettings().max_failed_logins;
  const row = db.prepare('SELECT failed FROM login_attempts WHERE login = ?').get(login);
  const failed = (row ? row.failed : 0) + 1;
  if (failed >= max) {
    const lockedUntil = Date.now() + LOCK_MS;
    db.prepare(`INSERT INTO login_attempts (login, failed, locked_until) VALUES (?, 0, ?)
                ON CONFLICT(login) DO UPDATE SET failed = 0, locked_until = excluded.locked_until`).run(login, lockedUntil);
    return { lockedUntil };
  }
  db.prepare(`INSERT INTO login_attempts (login, failed, locked_until) VALUES (?, ?, 0)
              ON CONFLICT(login) DO UPDATE SET failed = excluded.failed`).run(login, failed);
  return { left: max - failed };
}

function clearFailures(login) {
  db.prepare('DELETE FROM login_attempts WHERE login = ?').run(login);
}

// ---------- limit prób z jednego adresu IP (zadanie dodatkowe, ochrona przed password spraying) ----------
// Trzymany w pamięci serwera: restart serwera zeruje blokady IP.

const ipFailures = new Map();                     // ip -> { count, since, lockedUntil }

function ipLockedUntil(ip) {
  const e = ipFailures.get(ip);
  return e && e.lockedUntil > Date.now() ? e.lockedUntil : 0;
}

// Zwraca czas końca blokady, jeśli ta próba przekroczyła limit, w przeciwnym razie 0.
function registerIpFailure(ip) {
  const now = Date.now();
  let e = ipFailures.get(ip);
  if (!e || now - e.since > LOCK_MS) e = { count: 0, since: now, lockedUntil: 0 };
  e.count++;
  if (e.count >= getSettings().ip_max_failed) {
    e.lockedUntil = now + LOCK_MS;
    e.count = 0; e.since = now;
  }
  ipFailures.set(ip, e);
  return e.lockedUntil > now ? e.lockedUntil : 0;
}

function clearAllLocks() {
  db.prepare('DELETE FROM login_attempts').run();
  ipFailures.clear();
}

// ---------- reCAPTCHA (weryfikacja tokenu po stronie serwera) ----------

async function verifyRecaptcha(token, ip) {
  if (typeof token !== 'string' || !token) return false;
  try {
    const r = await fetch(RECAPTCHA_VERIFY_URL, {
      method: 'POST',
      body: new URLSearchParams({ secret: config.recaptchaSecret, response: token, remoteip: ip }),
      signal: AbortSignal.timeout(5000),
    });
    return (await r.json()).success === true;
  } catch (err) {
    console.warn('reCAPTCHA: brak połączenia z Google -', err.message);
    return false;
  }
}

// ---------- Canarytokens ----------

function triggerCanary(url, info) {
  if (!url) return console.warn('Canarytoken: brak adresu tokenu w config.js - alert tylko w dzienniku');
  const u = new URL(url);
  for (const [k, v] of Object.entries(info)) u.searchParams.set(k, v);
  fetch(u, { signal: AbortSignal.timeout(5000) })
    .catch((err) => console.warn('Canarytoken: nie udało się wysłać alertu -', err.message));
}

module.exports = {
  LOCK_MS, logEvent, accountLockedUntil, registerFailure, clearFailures,
  ipLockedUntil, registerIpFailure, clearAllLocks, verifyRecaptcha, triggerCanary,
};
