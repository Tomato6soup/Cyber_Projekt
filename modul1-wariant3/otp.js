
//ONE TIME PASSWORD
// Hasło jednorazowe dla wariantu 3: fraza 4 losowych słów z listy, ważna 24 h.
const crypto = require('crypto');

const WORDS = [
  'koń', 'rower', 'zima', 'lampa', 'okno', 'rzeka', 'góra', 'kawa', 'chmura', 'deszcz',
  'kot', 'pies', 'lato', 'jesień', 'wiosna', 'morze', 'las', 'drzewo', 'kwiat', 'trawa',
  'słońce', 'księżyc', 'gwiazda', 'kamień', 'piasek', 'statek', 'pociąg', 'most', 'zamek', 'wieża',
  'ogród', 'jabłko', 'gruszka', 'śliwka', 'chleb', 'mleko', 'herbata', 'cukier', 'miód', 'ser',
  'książka', 'ołówek', 'zeszyt', 'tablica', 'krzesło', 'stół', 'szafa', 'lustro', 'zegar', 'dzwon',
  'ptak', 'ryba', 'wilk', 'lis', 'sowa', 'jeż', 'żaba', 'motyl', 'pszczoła', 'mrówka',
  'gitara', 'bęben', 'flet', 'piano', 'teatr', 'kino', 'park', 'plac', 'ulica', 'miasto',
  'wiatr', 'burza', 'śnieg', 'lód', 'ogień', 'dym', 'tęcza', 'mgła', 'rosa', 'szron',
  'kubek', 'talerz', 'widelec', 'nóż', 'garnek', 'piec', 'komin', 'dach', 'płot', 'brama',
  'balon', 'latawiec', 'piłka', 'sanki', 'narty', 'łódka', 'wiosło', 'kotwica', 'żagiel', 'mapa',
];

const OTP_VALIDITY_MS = 24 * 60 * 60 * 1000;

function generateOtp() {
  const words = [];
  for (let i = 0; i < 4; i++) words.push(WORDS[crypto.randomInt(WORDS.length)]); // CSPRNG
  return words.join('-');
}

module.exports = { generateOtp, OTP_VALIDITY_MS, WORDS };
