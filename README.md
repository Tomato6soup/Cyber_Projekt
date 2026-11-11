# Bezpieczne logowanie – aplikacja webowa (wariant 3)

Projekt na zajęcia z cyberbezpieczeństwa. Aplikacja webowa w JavaScript (**Node.js + Express + SQLite**) z bezpiecznym logowaniem, rolami i ochroną przed botami.

- **Moduł 1:** identyfikacja, uwierzytelnianie i autoryzacja
- **Moduł 2:** zabezpieczenia przed botami, ruchem automatycznym i wyciekiem danych

## Funkcje

### Moduł 1 – uwierzytelnianie i autoryzacja
- Logowanie z jednym komunikatem błędu („Login lub hasło niepoprawne”) i wyrównanym czasem odpowiedzi.
- Hasła przechowywane jako hash **Argon2id** z solą.
- Polityka haseł zgodna z NIST SP 800-63B-4: min. **15 znaków**, lista haseł zakazanych i reguła wariantu 3, czyli **brak sekwencji** z klawiatury i alfabetu (`qwer`, `asdf`, `1234`, `abcd`, także od tyłu).
- Wymuszona zmiana hasła przy pierwszym logowaniu i historia haseł.
- **Hasło jednorazowe** z 4 losowych słów (np. `koń-rower-zima-lampa`), ważne 24 h.
- **RBAC:** role Administrator, Redaktor i Czytelnik. Uprawnienia sprawdza serwer, a brak uprawnień kończy się błędem **403**.
- Sesja wygasa po bezczynności (sprawdzane na serwerze), a wylogowanie niszczy ją po stronie serwera.
- Panel administratora: konta, role, blokowanie, reset hasła, ustawienia bezpieczeństwa.
- Dodatkowo: logowanie dwuetapowe **TOTP** (Google/Microsoft Authenticator).

### Moduł 2 – ochrona przed botami
- **Blokada konta** na 15 minut po N błędnych hasłach (N ustawia admin). Ekran logowania odlicza pozostały czas.
- **Własna CAPTCHA (wariant 3):** obrazek z losowymi figurami i pytanie typu „Ile jest czerwonych trójkątów?”. Wyzwanie jest jednorazowe i ważne 2 minuty.
- **Google reCAPTCHA v2** przy zmianie hasła, z weryfikacją tokenu na serwerze.
- **Pułapka na boty (honeypot):** ukryte pole w formularzu logowania.
- **Canarytokens:** konto-pułapka `administrator` (token Web bug) i dokument-pułapka w `robots.txt` (token Microsoft Word).
- **Limit prób z jednego adresu IP**, niezależnie od loginu (ochrona przed password spraying).
- Dziennik zdarzeń bezpieczeństwa w panelu administratora.
- **Skrypt bota** do testów, który pokazuje, które zabezpieczenia zadziałały.
- Dwa widoki interfejsu: Standard (minimalistyczny, niebieski) i Pro (w stylu Windows Vista/Aqua).

## Technologie

Node.js, Express, express-session, better-sqlite3, argon2, otplib, qrcode. Frontend to czysty HTML, CSS i JavaScript, bez frameworków.

## Uruchomienie

Wymagany **Node.js 20 lub nowszy**.

```bash
npm install
npm start            # przy pierwszym starcie tworzy konto ADMIN i wypisuje jego hasło jednorazowe
npm run seed         # w drugim terminalu: 4 użytkowników testowych z hasłami jednorazowymi
```

Aplikacja działa pod adresem http://localhost:3000.

- Na Windowsie w PowerShell użyj `npm.cmd` zamiast `npm`.
- Nowe hasło jednorazowe dla ADMIN: `node seed.js --reset-admin`.
- Start od zera: usuń plik `app.db`.

### Użytkownicy testowi

| Login | Rola |
|---|---|
| ADMIN | Administrator |
| jkowalski, anowak | Redaktor |
| pwisniewski, mzielinska | Czytelnik |

## Konfiguracja (`config.js`)

| Ustawienie | Opis |
|---|---|
| `recaptchaSiteKey`, `recaptchaSecret` | Klucze Google reCAPTCHA v2 (typ „Pole wyboru”). Domyślnie są tu publiczne klucze testowe Google. |
| `canaryAccountUrl` | Adres tokenu z [canarytokens.org](https://canarytokens.org) (typ Web bug / URL token), wywoływany przy próbie logowania na konto-pułapkę. |
| `decoyLogins` | Loginy kont-pułapek. |

Każdą wartość można też podać w zmiennej środowiskowej (`RECAPTCHA_SITE_KEY`, `RECAPTCHA_SECRET`, `CANARY_ACCOUNT_URL`). Własnego klucza tajnego reCAPTCHA nie wrzucaj do repozytorium, tylko podaj go w zmiennej środowiskowej.

Dokument-pułapkę z Canarytokens zapisz jako `canary/hasla-administratorow.docx`.

## Test bota

```bash
npm start            # terminal 1
npm run bot          # terminal 2
```

Bot atakuje **wyłącznie** aplikację na `localhost`. Kolejno próbuje: brute force, wypełnienie ukrytego pola, logowanie danymi znalezionymi w kodzie strony, pobranie pliku z `robots.txt`, credential stuffing i password spraying. Na końcu wypisuje zestawienie, które zabezpieczenia zadziałały.

Po teście adres IP jest zablokowany na 15 minut. Restart serwera zdejmuje blokadę IP, a przycisk „Zdejmij blokady logowania” w panelu admina zdejmuje blokady kont.

## Struktura projektu

```
server.js            serwer Express: logowanie, sesja, RBAC, API, panel admina, TOTP
db.js                schemat bazy, role, uprawnienia, ustawienia domyślne
passwordPolicy.js    polityka haseł (NIST + reguła wariantu 3)
otp.js               hasło jednorazowe: 4 losowe słowa, ważne 24 h
users.js             tworzenie kont i reset hasła (Argon2id)
seed.js              użytkownicy testowi / reset hasła ADMIN
captcha.js           własna CAPTCHA z figurami (obrazek PNG bez dodatkowych bibliotek)
security.js          limity prób, blokady, dziennik zdarzeń, reCAPTCHA, Canarytokens
config.js            klucze reCAPTCHA i adres tokenu Canarytokens
bot.js               skrypt symulujący bota
canary/              miejsce na dokument-pułapkę z Canarytokens
public/              strony dostępne bez logowania (logowanie, zmiana hasła, style, robots.txt)
views/               strony wysyłane dopiero po sprawdzeniu uprawnień (aplikacja, panel admina, 403)
```
