// Polityka haseł zgodna z NIST SP 800-63B-4 + reguła z wariantu 3.
const argon2 = require('argon2');

// Fragment listy haseł zakazanych (najpopularniejsze hasła z wycieków).
// W wersji produkcyjnej: pełna lista, np. 100k najczęstszych haseł.
const BANNED = new Set([
  '123456789012345', 'password1234567', 'qwertyuiop12345', 'haslohaslohaslo',
  'administrator123', 'zaq12wsxcde34rf', '1q2w3e4r5t6y7u8i', 'iloveyouiloveyou',
  'passwordpassword', 'polska123456789', 'mojehaslo123456', 'abcdefghijklmnop',
  'aaaaaaaaaaaaaaa', '000000000000000', '111111111111111', 'qwerty123456789',
]);

// Ciągi, w których szukamy sekwencji (wariant 3): rzędy klawiatury QWERTY,
// alfabet i cyfry. Sprawdzamy też kierunek odwrotny (ytrewq, 4321, dcba).
const SEQUENCES = [
  '1234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
  'abcdefghijklmnopqrstuvwxyz', '01234567890',
];
const SEQ_LEN = 4; // sekwencja = co najmniej 4 kolejne znaki (qwer, asdf, 1234, abcd)

function findSequence(password) {
  const p = password.toLowerCase();
  for (const base of SEQUENCES) {
    for (const s of [base, [...base].reverse().join('')]) {
      for (let i = 0; i + SEQ_LEN <= s.length; i++) {
        const frag = s.slice(i, i + SEQ_LEN);
        if (p.includes(frag)) return frag;
      }
    }
  }
  return null;
}

// Zwraca listę błędów (pusta lista = hasło spełnia politykę).
function validate(password, settings, { login = '' } = {}) {
  const errors = [];
  const len = [...password].length; // liczymy znaki Unicode, nie bajty
  if (len < settings.min_length) errors.push(`Hasło musi mieć co najmniej ${settings.min_length} znaków.`);
  if (len > 128) errors.push('Hasło może mieć maksymalnie 128 znaków.');
  if (BANNED.has(password.toLowerCase())) errors.push('Hasło znajduje się na liście haseł zakazanych.');
  if (login && password.toLowerCase().includes(login.toLowerCase())) errors.push('Hasło nie może zawierać loginu.');
  if (settings.policy_no_sequences) {
    const seq = findSequence(password);
    if (seq) errors.push(`Hasło zawiera sekwencję klawiaturową lub ciąg rosnący („${seq}”).`);
  }
  return errors;
}

// Czy nowe hasło jest takie samo jak któreś z poprzednich (porównanie przez hash).
async function isInHistory(password, hashes) {
  for (const h of hashes) {
    if (await argon2.verify(h, password)) return true;
  }
  return false;
}

module.exports = { validate, isInHistory, findSequence };
