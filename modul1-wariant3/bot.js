// Skrypt symulujący bota
// Użycie: w jednym terminalu  npm start,  w drugim  npm run bot
const path = require('path');
const Database = require('better-sqlite3');

const BASE = process.argv[2] || 'http://localhost:3000';
if (!/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(BASE)) {
  console.error('Ten skrypt wolno uruchamiać tylko na własnej aplikacji (localhost).');
  process.exit(1);
}

// ---------- klient HTTP bota (z ciasteczkiem sesji, bo CAPTCHA jest w sesji) ----------

let cookie = '';
async function call(method, url, body) {
  const res = await fetch(BASE + url, {
    method,
    headers: { 'Content-Type': 'application/json', ...(cookie && { Cookie: cookie }) },
    body: body && JSON.stringify(body),
  });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) cookie = setCookie.split(';')[0];
  const text = await res.text();
  let data = text;
  try { data = JSON.parse(text); } catch { }
  return { status: res.status, data };
}

// Bot nie potrafi odczytać obrazka z figurami, więc zgaduje liczbę od 1 do 5.
async function tryLogin(login, password, extra = {}) {
  await call('GET', '/api/captcha');
  return call('POST', '/api/login', {
    login, password, captcha: String(1 + Math.floor(Math.random() * 5)), website: '', ...extra,
  });
}

function classify({ status, data }) {
  const msg = (data && data.error) || '';
  if (status === 200) return 'ZALOGOWANO';
  if (status === 429 && msg.includes('IP')) return 'blokada IP';
  if (status === 429) return 'blokada konta';
  if (status === 400 && msg.includes('CAPTCHA')) return 'odrzucone przez CAPTCHA';
  if (status === 401) return 'odmowa logowania (401)';
  return `HTTP ${status}`;
}

const results = [];
async function scenario(name, attempts, { stopOn } = {}) {
  const counts = {};
  let n = 0;
  for (const [login, password, extra] of attempts) {
    const r = await tryLogin(login, password, extra);
    const c = classify(r);
    counts[c] = (counts[c] || 0) + 1;
    n++;
    if (stopOn && stopOn.includes(c)) break;
  }
  results.push({ name, n, counts });
  console.log(`\n${name} (prób: ${n})`);
  for (const [c, k] of Object.entries(counts)) console.log(`   ${c.padEnd(32)} ${k}`);
}

// ---------- scenariusze ataku ----------

const PASSWORDS = ['123456', 'password', 'qwerty123', 'haslo123', 'Polska2024!', 'iloveyou', 'admin123',
  'zaq12wsx', 'monkey', 'dragon', 'sunshine', 'football', 'kochamcie', 'marcin1', 'superman'];
const LEAK = [['jkowalski', 'Kowalski1990!'], ['anowak', 'anna.nowak.1985'], ['mzielinska', 'Maria2023#'],
  ['pwisniewski', 'piotrek123'], ['ewa.k', 'ewunia1'], ['tomek', 'Tomek!2020']];
const SPRAY_LOGINS = ['anowak', 'pwisniewski', 'mzielinska', 'jan', 'test', 'ewa', 'marek', 'kasia', 'admin', 'user'];

(async () => {
  const startedAt = Date.now();
  console.log(`Bot atakuje ${BASE} (tylko własna aplikacja)`);

  // 1. Brute force: wiele haseł na jedno konto.
  const brute = [];
  for (let i = 0; i < 80; i++) brute.push(['jkowalski', PASSWORDS[i % PASSWORDS.length]]);
  await scenario('1. Brute force na konto jkowalski', brute, { stopOn: ['blokada konta', 'blokada IP', 'ZALOGOWANO'] });

  // 2. Bot wypełnia wszystkie pola formularza, także ukryte pole-pułapkę.
  await scenario('2. Wypełnienie ukrytego pola (honeypot)',
    [['jkowalski', 'haslo123', { website: 'http://tanie-leki.example' }]]);

  // 3. Bot czyta kod strony logowania i znajduje „zapomniane” dane konta w komentarzu HTML.
  const page = (await call('GET', '/login.html')).data;
  const leak = /(\w+)\s*\/\s*(\S+)\s*-->/.exec(page);
  if (leak) await scenario(`3. Dane z komentarza HTML (${leak[1]})`, [[leak[1], leak[2]]]);

  // 4. Bot czyta robots.txt i pobiera „ukryte” pliki.
  const robots = String((await call('GET', '/robots.txt')).data);
  const hidden = [...robots.matchAll(/Disallow:\s*(\/backup\S*)/g)].map((m) => m[1]);
  for (const p of hidden) {
    const r = await call('GET', p);
    console.log(`\n4. Pobranie ${p} z robots.txt: HTTP ${r.status}`);
  }

  // 5. Credential stuffing: pary login/hasło z „wycieku” z innego serwisu.
  await scenario('5. Credential stuffing (pary z wycieku)', LEAK, { stopOn: ['ZALOGOWANO'] });

  // 6. Password spraying: jedno popularne hasło na wielu kontach, aż do blokady IP.
  const spray = [];
  for (let i = 0; i < 100; i++) spray.push([SPRAY_LOGINS[i % SPRAY_LOGINS.length], 'Haslo123456789!']);
  await scenario('6. Password spraying (jedno hasło, wiele kont)', spray, { stopOn: ['blokada IP', 'ZALOGOWANO'] });

  // ---------- zestawienie: odpowiedzi serwera + dziennik zdarzeń aplikacji ----------

  await new Promise((r) => setTimeout(r, 300));
  const db = new Database(path.join(__dirname, 'app.db'), { readonly: true });
  const events = Object.fromEntries(db.prepare(
    'SELECT type, COUNT(*) AS n FROM security_events WHERE created_at >= ? GROUP BY type').all(startedAt)
    .map((r) => [r.type, r.n]));
  const total = (c) => results.reduce((s, r) => s + (r.counts[c] || 0), 0);
  const loggedIn = total('ZALOGOWANO');

  const rows = [
    ['CAPTCHA z figurami (wariant 3)', events.captcha, `odrzucone próby: ${events.captcha || 0}`],
    ['Pułapka na boty (ukryte pole)', events.honeypot, 'alert w dzienniku, bot dostał zwykły komunikat'],
    ['Konto-pułapka (Canarytoken)', events['canary-account'], 'alert w dzienniku + wywołanie tokenu Canarytokens'],
    ['Plik-pułapka z robots.txt', events['canary-file'], 'pobranie zapisane w dzienniku'],
    ['Blokada konta po N próbach', events.lockout, 'konto zablokowane na 15 min'],
    ['Limit prób z jednego IP', events['ip-block'], 'adres IP zablokowany na 15 min'],
  ];
  console.log('\n================ ZESTAWIENIE ================');
  console.log('Zabezpieczenie'.padEnd(34) + 'Zadziałało?  Szczegóły');
  for (const [name, hit, info] of rows) console.log(name.padEnd(34) + (hit ? 'TAK          ' : 'nie          ') + (hit ? info : ''));
  console.log(`\nUdane logowania bota: ${loggedIn}`);
  console.log('\nUwaga: Twoje IP i konto jkowalski są teraz zablokowane na 15 minut.');
  console.log('Aby od razu się zalogować, zrestartuj serwer (Ctrl+C, npm start),');
  console.log('a blokadę konta zdejmij w panelu administratora („Zdejmij blokady logowania”).');
})();
