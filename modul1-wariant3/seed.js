// Tworzy 4 użytkowników testowych i wypisuje ich hasła jednorazowe.
// Użycie:  npm run seed               - użytkownicy testowi
//          node seed.js --reset-admin  - nowe hasło jednorazowe dla konta ADMIN
const { db } = require('./db');
const { createUser, resetPassword } = require('./users');

const TEST_USERS = [
  ['jkowalski', 'Jan Kowalski', 'Redaktor'],
  ['anowak', 'Anna Nowak', 'Redaktor'],
  ['pwisniewski', 'Piotr Wiśniewski', 'Czytelnik'],
  ['mzielinska', 'Maria Zielińska', 'Czytelnik'],
];

(async () => {
  if (process.argv.includes('--reset-admin')) {
    const admin = db.prepare("SELECT id FROM users WHERE login = 'ADMIN'").get();
    if (!admin) return console.log('Brak konta ADMIN - uruchom najpierw serwer (npm start).');
    console.log('Nowe hasło jednorazowe ADMIN:', await resetPassword(admin.id));
    return;
  }
  for (const [login, name, role] of TEST_USERS) {
    if (db.prepare('SELECT 1 FROM users WHERE login = ?').get(login)) {
      console.log(`${login}: już istnieje`);
      continue;
    }
    const { otp } = await createUser(login, name, role);
    console.log(`${login.padEnd(12)} ${role.padEnd(10)} hasło jednorazowe: ${otp}`);
  }
})();
