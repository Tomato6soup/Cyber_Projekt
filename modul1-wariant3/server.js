// Moduł 2 - Zabezpieczenia przed botami, ruchem automatycznym i wyciekiem danych (wariant 3).
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');
const argon2 = require('argon2');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');

const { db, getSettings, setSetting, getPermissions, roleId } = require('./db');
const policy = require('./passwordPolicy');
const { hashPassword, createUser, resetPassword } = require('./users');
const captcha = require('./captcha');
const sec = require('./security');
const config = require('./config');

const PORT = process.env.PORT || 3000;
const LOGIN_ERROR = 'Login lub hasło niepoprawne';
const LOGIN_RE = /^[A-Za-z0-9._-]{3,32}$/;

const app = express();
app.use(express.json({ limit: '20kb' }));
app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' },
}));

// ---------- pomocnicze ----------

const getUser = (id) => db.prepare(`SELECT u.*, r.name AS role FROM users u
                                     JOIN roles r ON r.id = u.role_id WHERE u.id = ?`).get(id);
const isAdminAccount = (u) => u.login === 'ADMIN';


let DUMMY_HASH;

function passwordExpired(user, settings) {
  if (!settings.password_validity_days) return false;
  return Date.now() - user.password_changed_at > settings.password_validity_days * 86400000;
}

function finishLogin(req, user) {
  const settings = getSettings();
  req.session.userId = user.id;
  req.session.lastActivity = Date.now();
  req.session.mustChange = !!user.must_change_password || passwordExpired(user, settings);
  delete req.session.pendingTotpUserId;
  if (req.session.mustChange) return { next: '/change-password.html' };
  return { next: getPermissions(user.role_id).includes('users.manage') ? '/admin' : '/app' };
}

// ---------- middleware: sesja, uwierzytelnienie, autoryzacja ----------


function requireAuth(req, res, next) {
  const s = req.session;
  if (!s.userId) return deny(req, res, 401, 'Nie jesteś zalogowany');
  const timeoutMs = getSettings().session_timeout_minutes * 60000;
  if (Date.now() - s.lastActivity > timeoutMs) {
    return s.destroy(() => deny(req, res, 401, 'Sesja wygasła z powodu bezczynności', true));
  }
  const user = getUser(s.userId);
  if (!user || user.is_blocked) return s.destroy(() => deny(req, res, 401, 'Konto niedostępne'));
  s.lastActivity = Date.now();
  req.user = user;
  req.permissions = getPermissions(user.role_id);
  next();
}

// Przy wymuszonej zmianie hasła wolno tylko zmienić hasło, odczytać /api/me i się wylogować.
function requirePasswordChanged(req, res, next) {
  if (req.session.mustChange) return deny(req, res, 403, 'Wymagana zmiana hasła');
  next();
}

// Autoryzacja RBAC: uprawnienie sprawdzane na serwerze przy każdym żądaniu.
function requirePermission(code) {
  return (req, res, next) => {
    if (!req.permissions.includes(code)) return deny(req, res, 403, 'Brak uprawnień (403 Forbidden)');
    next();
  };
}

function deny(req, res, status, message, expired = false) {
  if (req.path.startsWith('/api/')) return res.status(status).json({ error: message, expired });
  if (status === 401) return res.redirect('/login.html' + (expired ? '?expired=1' : ''));
  return res.status(status).sendFile(path.join(__dirname, 'views', '403.html'));
}

const auth = [requireAuth, requirePasswordChanged];
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------- strony ----------

app.get('/', (req, res) => res.redirect('/login.html'));

// Plik-pułapka wskazany w robots.txt.
app.get(/^\/backup(\/.*)?$/, (req, res) => {
  sec.logEvent('canary-file', req, { details: `Pobranie pliku-pułapki ${req.path}` });
  res.sendFile(path.basename(req.path), { root: path.join(__dirname, 'canary') }, (err) => {
    if (err && !res.headersSent) res.status(404).end();
  });
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('/app', auth, (req, res) => res.sendFile(path.join(__dirname, 'views', 'app.html')));
app.get('/admin', auth, requirePermission('users.manage'),
  (req, res) => res.sendFile(path.join(__dirname, 'views', 'admin.html')));

// ---------- logowanie / wylogowanie ----------

// Publiczna konfiguracja dla przeglądarki (klucz witryny reCAPTCHA nie jest tajny).
app.get('/api/config', (req, res) => res.json({ recaptchaSiteKey: config.recaptchaSiteKey }));

// Nowe wyzwanie CAPTCHA (wariant 3). Odpowiedź zostaje tylko w sesji na serwerze.
app.get('/api/captcha', (req, res) => {
  const { image, question, answer, expiresAt } = captcha.createChallenge();
  req.session.captcha = { answer, expiresAt };
  res.json({ image, question, validSeconds: captcha.VALID_MS / 1000 });
});

function lockedResponse(res, lockedUntil, reason) {
  const retryAfter = Math.ceil((lockedUntil - Date.now()) / 1000);
  res.set('Retry-After', String(retryAfter));
  return res.status(429).json({ error: `${reason} Spróbuj ponownie później.`, lockedUntil, retryAfter });
}

// Rejestruje nieudaną próbę na adresie IP i zapisuje alert, gdy IP właśnie zostało zablokowane.
function ipFailure(req, login) {
  const until = sec.registerIpFailure(req.ip);
  if (until) sec.logEvent('ip-block', req, { login, details: `Adres IP zablokowany na 15 min po ${getSettings().ip_max_failed} nieudanych próbach` });
  return until;
}

app.post('/api/login', wrap(async (req, res) => {
  const { login, password, captcha: captchaAnswer, website } = req.body || {};
  if (typeof login !== 'string' || typeof password !== 'string') return res.status(400).json({ error: LOGIN_ERROR });

  // 1. Limit prób z jednego adresu IP, niezależnie od loginu (zadanie dodatkowe).
  const ipUntil = sec.ipLockedUntil(req.ip);
  if (ipUntil) return lockedResponse(res, ipUntil, 'Zbyt wiele nieudanych prób logowania z tego adresu IP.');

  // 2. Pułapka na boty: ukryte pole "website" wypełni tylko program. Bot dostaje zwykły komunikat,
  //    żeby nie wiedział, że został wykryty.
  if (website) {
    sec.logEvent('honeypot', req, { login, details: 'Wypełnione ukryte pole formularza logowania' });
    ipFailure(req, login);
    return res.status(401).json({ error: LOGIN_ERROR });
  }

  // 3. Konto-pułapka (honeytoken): nikt uprawniony go nie używa, więc każda próba to incydent.
  if (config.decoyLogins.includes(login.toLowerCase())) {
    await argon2.verify(DUMMY_HASH, password);  // taki sam czas odpowiedzi jak dla zwykłego konta
    sec.logEvent('canary-account', req, { login, details: 'Próba logowania na konto-pułapkę' });
    sec.triggerCanary(config.canaryAccountUrl, { login, ip: req.ip });
    ipFailure(req, login);
    return res.status(401).json({ error: LOGIN_ERROR });
  }

  // 4. Czasowa blokada konta po zbyt wielu złych hasłach.
  const accountUntil = sec.accountLockedUntil(login);
  if (accountUntil) return lockedResponse(res, accountUntil, 'Konto jest czasowo zablokowane po zbyt wielu nieudanych próbach.');

  // 5. CAPTCHA wariantu 3. Wyzwanie jest jednorazowe: usuwamy je z sesji przed sprawdzeniem.
  const challenge = req.session.captcha;
  delete req.session.captcha;
  if (!captcha.checkAnswer(challenge, captchaAnswer)) {
    sec.logEvent('captcha', req, { login, details: challenge ? 'Zła odpowiedź lub wyzwanie wygasło' : 'Brak wyzwania CAPTCHA' });
    return res.status(400).json({ error: 'Niepoprawna odpowiedź CAPTCHA. Policz figury na nowym obrazku.' });
  }

  // 6. Hasło.
  const row = db.prepare('SELECT id, password_hash FROM users WHERE login = ?').get(login);
  const ok = await argon2.verify(row ? row.password_hash : DUMMY_HASH, password);
  if (!row || !ok) {
    const ipUntilNow = ipFailure(req, login);
    const f = sec.registerFailure(login);
    if (f.lockedUntil) {
      sec.logEvent('lockout', req, { login, details: `Konto zablokowane na 15 min po ${getSettings().max_failed_logins} nieudanych próbach` });
      return lockedResponse(res, f.lockedUntil, 'Konto zostało czasowo zablokowane po zbyt wielu nieudanych próbach.');
    }
    if (ipUntilNow) return lockedResponse(res, ipUntilNow, 'Zbyt wiele nieudanych prób logowania z tego adresu IP.');
    return res.status(401).json({ error: `${LOGIN_ERROR}. Pozostałe próby: ${f.left}.` });
  }
  sec.clearFailures(login);

  const user = getUser(row.id);
  // Poniższe komunikaty pojawiają się dopiero po poprawnym haśle, więc nie zdradzają istnienia loginu.
  if (user.is_blocked) return res.status(403).json({ error: 'Konto jest zablokowane. Skontaktuj się z administratorem.' });
  if (user.otp_expires_at && Date.now() > user.otp_expires_at) {
    return res.status(401).json({ error: 'Hasło jednorazowe wygasło. Poproś administratora o reset hasła.' });
  }

  // Nowy identyfikator sesji po zalogowaniu (ochrona przed session fixation).
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Błąd sesji' });
    if (user.totp_enabled) {
      req.session.pendingTotpUserId = user.id;
      req.session.pendingSince = Date.now();
      return res.json({ next: 'totp' });
    }
    res.json(finishLogin(req, user));
  });
}));

app.post('/api/login/totp', (req, res) => {
  const { pendingTotpUserId: id, pendingSince } = req.session;
  if (!id || Date.now() - pendingSince > 5 * 60000) return res.status(401).json({ error: 'Zaloguj się ponownie' });
  const user = getUser(id);
  if (!user || !authenticator.check(String(req.body.code || ''), user.totp_secret)) {
    return res.status(401).json({ error: 'Niepoprawny kod weryfikacyjny' });
  }
  res.json(finishLogin(req, user));
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  const u = req.user;
  res.json({
    login: u.login, fullName: u.full_name, role: u.role, permissions: req.permissions,
    mustChange: !!req.session.mustChange, totpEnabled: !!u.totp_enabled,
    sessionTimeoutMinutes: getSettings().session_timeout_minutes,
  });
});

// ---------- zmiana hasła (także pierwsza, wymuszona) ----------

app.post('/api/change-password', requireAuth, wrap(async (req, res) => {
  const { oldPassword, newPassword, newPassword2 } = req.body || {};
  const user = req.user;
  if (![oldPassword, newPassword, newPassword2].every((v) => typeof v === 'string')) {
    return res.status(400).json({ errors: ['Uzupełnij wszystkie pola.'] });
  }
  // Moduł 2: bez poprawnego tokenu reCAPTCHA (sprawdzonego w Google) formularz jest odrzucany.
  if (!(await sec.verifyRecaptcha(req.body.recaptchaToken, req.ip))) {
    sec.logEvent('recaptcha', req, { login: user.login, details: 'Zmiana hasła bez poprawnego tokenu reCAPTCHA' });
    return res.status(400).json({ errors: ['Potwierdź, że nie jesteś robotem (reCAPTCHA).'] });
  }
  if (!(await argon2.verify(user.password_hash, oldPassword))) {
    return res.status(400).json({ errors: ['Obecne hasło jest niepoprawne.'] });
  }
  if (newPassword !== newPassword2) return res.status(400).json({ errors: ['Nowe hasła nie są identyczne.'] });

  const settings = getSettings();
  const errors = policy.validate(newPassword, settings, { login: user.login });
  const history = db.prepare('SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT ?')
    .all(user.id, settings.password_history_count).map((r) => r.password_hash);
  if (await policy.isInHistory(newPassword, [user.password_hash, ...history])) {
    errors.push('Nowe hasło musi różnić się od poprzednich haseł.');
  }
  if (errors.length) return res.status(400).json({ errors });

  const newHash = await hashPassword(newPassword);
  const now = Date.now();
  db.transaction(() => {
    // Hasło jednorazowe nie trafia do historii - nie było wybrane przez użytkownika.
    if (!user.otp_expires_at) {
      db.prepare('INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?, ?, ?)')
        .run(user.id, user.password_hash, now);
    }
    db.prepare(`UPDATE users SET password_hash = ?, must_change_password = 0, otp_expires_at = NULL,
                password_changed_at = ? WHERE id = ?`).run(newHash, now, user.id);
  })();
  req.session.mustChange = false;
  res.json({ ok: true, next: req.permissions.includes('users.manage') ? '/admin' : '/app' });
}));

// ---------- artykuły (demonstracja RBAC dla ról Redaktor / Czytelnik) ----------

app.get('/api/articles', auth, requirePermission('articles.read'), (req, res) => {
  res.json(db.prepare(`SELECT a.id, a.title, a.body, a.created_at, u.login AS author
                       FROM articles a LEFT JOIN users u ON u.id = a.author_id ORDER BY a.id DESC`).all());
});

app.post('/api/articles', auth, requirePermission('articles.write'), (req, res) => {
  const { title, body } = req.body || {};
  if (!title || !body) return res.status(400).json({ error: 'Podaj tytuł i treść' });
  db.prepare('INSERT INTO articles (title, body, author_id, created_at) VALUES (?, ?, ?, ?)')
    .run(String(title).slice(0, 200), String(body).slice(0, 5000), req.user.id, Date.now());
  res.status(201).json({ ok: true });
});

app.delete('/api/articles/:id', auth, requirePermission('articles.write'), (req, res) => {
  db.prepare('DELETE FROM articles WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ---------- panel administratora ----------

const admin = [...auth, requirePermission('users.manage')];

app.get('/api/admin/users', admin, (req, res) => {
  res.json(db.prepare(`SELECT u.id, u.login, u.full_name, r.name AS role, u.is_blocked,
                       u.must_change_password, u.otp_expires_at, u.totp_enabled, u.created_at,
                       COALESCE(la.locked_until, 0) AS locked_until
                       FROM users u JOIN roles r ON r.id = u.role_id
                       LEFT JOIN login_attempts la ON la.login = u.login ORDER BY u.id`).all());
});

// Moduł 2: dziennik zdarzeń bezpieczeństwa i zdejmowanie czasowych blokad.
app.get('/api/admin/security-events', admin, (req, res) => {
  res.json(db.prepare('SELECT * FROM security_events ORDER BY id DESC LIMIT 100').all());
});

app.post('/api/admin/clear-locks', admin, (req, res) => {
  sec.clearAllLocks();
  res.json({ ok: true });
});

app.get('/api/admin/roles', admin, (req, res) => {
  res.json(db.prepare('SELECT name FROM roles ORDER BY id').all().map((r) => r.name));
});

app.post('/api/admin/users', admin, wrap(async (req, res) => {
  const { login, fullName, role } = req.body || {};
  if (!LOGIN_RE.test(login || '')) return res.status(400).json({ error: 'Login: 3-32 znaki (litery, cyfry, . _ -)' });
  if (!roleId(role)) return res.status(400).json({ error: 'Nieznana rola' });
  if (db.prepare('SELECT 1 FROM users WHERE login = ?').get(login)) {
    return res.status(409).json({ error: 'Taki login już istnieje' });
  }
  const { otp } = await createUser(login, String(fullName || '').slice(0, 100), role);
  res.status(201).json({ ok: true, oneTimePassword: otp });
}));

function loadTarget(req, res, next) {
  const target = getUser(req.params.id);
  if (!target) return res.status(404).json({ error: 'Nie znaleziono użytkownika' });
  req.target = target;
  next();
}

const protectAdminAccount = (req, res, next) => isAdminAccount(req.target)
  ? res.status(400).json({ error: 'Konta ADMIN nie można zablokować, usunąć ani zmienić mu roli' })
  : next();

app.put('/api/admin/users/:id', admin, loadTarget, (req, res) => {
  const { fullName, role } = req.body || {};
  if (role && role !== req.target.role) {
    if (isAdminAccount(req.target)) return protectAdminAccount(req, res);
    if (!roleId(role)) return res.status(400).json({ error: 'Nieznana rola' });
    db.prepare('UPDATE users SET role_id = ? WHERE id = ?').run(roleId(role), req.target.id);
  }
  if (typeof fullName === 'string') {
    db.prepare('UPDATE users SET full_name = ? WHERE id = ?').run(fullName.slice(0, 100), req.target.id);
  }
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/block', admin, loadTarget, protectAdminAccount, (req, res) => {
  db.prepare('UPDATE users SET is_blocked = ? WHERE id = ?').run(req.body.blocked ? 1 : 0, req.target.id);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', admin, loadTarget, protectAdminAccount, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.target.id);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/reset-password', admin, loadTarget, wrap(async (req, res) => {
  res.json({ ok: true, oneTimePassword: await resetPassword(req.target.id) });
}));

app.get('/api/admin/settings', [...auth, requirePermission('settings.manage')], (req, res) => res.json(getSettings()));

app.put('/api/admin/settings', [...auth, requirePermission('settings.manage')], (req, res) => {
  const b = req.body || {};
  const limits = {
    min_length: [8, 64], password_validity_days: [0, 3650],
    session_timeout_minutes: [1, 480], password_history_count: [1, 24], policy_no_sequences: [0, 1],
    max_failed_logins: [1, 20], ip_max_failed: [1, 100],
  };
  for (const [key, [min, max]] of Object.entries(limits)) {
    if (b[key] === undefined) continue;
    const v = Number(b[key]);
    if (!Number.isInteger(v) || v < min || v > max) {
      return res.status(400).json({ error: `Wartość ${key} musi być liczbą całkowitą z zakresu ${min}-${max}` });
    }
    setSetting(key, v);
  }
  res.json(getSettings());
});

// ---------- TOTP (zadanie dodatkowe) ----------

app.post('/api/totp/setup', auth, wrap(async (req, res) => {
  const secret = authenticator.generateSecret();
  req.session.totpSetupSecret = secret;
  const uri = authenticator.keyuri(req.user.login, 'Modul1-Wariant3', secret);
  res.json({ secret, qr: await QRCode.toDataURL(uri) });
}));

app.post('/api/totp/enable', auth, (req, res) => {
  const secret = req.session.totpSetupSecret;
  if (!secret || !authenticator.check(String(req.body.code || ''), secret)) {
    return res.status(400).json({ error: 'Niepoprawny kod - spróbuj ponownie' });
  }
  db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?').run(secret, req.user.id);
  delete req.session.totpSetupSecret;
  res.json({ ok: true });
});

app.post('/api/totp/disable', auth, wrap(async (req, res) => {
  if (!(await argon2.verify(req.user.password_hash, String(req.body.password || '')))) {
    return res.status(400).json({ error: 'Niepoprawne hasło' });
  }
  db.prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?').run(req.user.id);
  res.json({ ok: true });
}));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Błąd serwera' });
});

// ---------- start ----------

(async () => {
  DUMMY_HASH = await hashPassword(crypto.randomBytes(16).toString('hex'));
  if (!db.prepare("SELECT 1 FROM users WHERE login = 'ADMIN'").get()) {
    const { otp } = await createUser('ADMIN', 'Administrator systemu', 'Administrator');
    console.log('\n  Utworzono konto ADMIN. Hasło jednorazowe (ważne 24 h):', otp, '\n');
  }
  app.listen(PORT, () => console.log(`Aplikacja działa: http://localhost:${PORT}`));
})();
