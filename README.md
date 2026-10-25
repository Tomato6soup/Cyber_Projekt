# Moduł 1 – Identyfikacja, uwierzytelnianie i autoryzacja (wariant 3)

Aplikacja webowa w JavaScript: **Node.js + Express** (serwer), **SQLite** (baza), **HTML/CSS/JS** (frontend), hasła hashowane **Argon2id**.

## Wymagania
| Wymaganie | Wariant 3 |
|---|---|
| Minimalna długość hasła (domyślna) | **15 znaków** |
| Dodatkowa reguła polityki (włączana przez admina) | **brak sekwencji klawiaturowych i ciągów rosnących** (qwerty, asdf, 1234, abcd) |
| Liczba użytkowników testowych | **4** |
| Role | **Administrator, Redaktor, Czytelnik** |
| Hasło jednorazowe | **fraza 4 losowych słów z listy** (np. `koń-rower-zima-lampa`), **ważna 24 h** |

## Uruchomienie
Aplikacja: http://localhost:3000. Jeśli hasło jednorazowe ADMIN wygaśnie: `node seed.js --reset-admin`.
Żeby zacząć od zera, trzeba usunąć plik `app.db`.

## Jak każdy punkt zadania jest zrealizowany

| Punkt zadania | Realizacja | Gdzie w kodzie |
|---|---|---|
| 1. Logowanie | Login + `type="password"`. Każdy błąd (zły login lub hasło) daje ten sam komunikat „Login lub hasło niepoprawne”. Dla nieistniejącego loginu i tak liczony jest hash, żeby czas odpowiedzi nie zdradzał, czy konto istnieje. Hasła: Argon2id (sól dodaje biblioteka). | `server.js` → `POST /api/login`, `users.js` |
| 2. Pierwsze logowanie | Konto ma `must_change_password = 1`. Po zalogowaniu sesja ma flagę `mustChange`, a serwer blokuje wszystko poza zmianą hasła. Nowe hasło podawane dwukrotnie. | `requirePasswordChanged`, `public/change-password.html` |
| 3. Zmiana hasła | Wymaga starego hasła, sprawdza politykę i porównuje nowe hasło z aktualnym oraz z ostatnimi N hasłami z tabeli `password_history`. | `POST /api/change-password`, `passwordPolicy.js` |
| 4. Panel administratora | Lista, dodawanie, edycja (imię, rola), blokowanie, usuwanie, reset hasła. Ustawienia: włączenie reguły wariantu 3, min. długość, ważność hasła w dniach, czas bezczynności, liczba pamiętanych haseł. Konta ADMIN nie da się zablokować, usunąć ani zmienić mu roli. | `/api/admin/*`, `views/admin.html` |
| 5. Hasło jednorazowe | 4 słowa losowane `crypto.randomInt` (bezpieczny generator) ze 100-wyrazowej listy, łączone myślnikiem. Ważne 24 h (`otp_expires_at`), pokazywane adminowi tylko raz, w bazie tylko hash. | `otp.js`, `users.js` |
| 6. Role i uprawnienia | RBAC: tabele `roles`, `permissions`, `role_permissions`. Każdy endpoint sprawdza uprawnienie na serwerze (`requirePermission`), brak uprawnienia daje **403**. | `db.js`, `server.js` |
| 7. Sesja | Wylogowanie ręczne niszczy sesję na serwerze (`session.destroy`). Bezczynność jest sprawdzana na serwerze przy każdym żądaniu (`lastActivity`), a w przeglądarce timer wylogowuje i pokazuje odliczanie. Po zalogowaniu identyfikator sesji jest wymieniany (ochrona przed session fixation). Ciasteczko `HttpOnly`, `SameSite=Strict`. | `requireAuth`, `public/common.js` |
| Dodatkowe: TOTP | Konfiguracja z kodem QR (Google/Microsoft Authenticator), logowanie dwuetapowe: hasło, potem 6-cyfrowy kod. | `/api/totp/*`, `/api/login/totp` |

### Reguła wariantu 3: sekwencje

`passwordPolicy.js` → `findSequence()` szuka w haśle (bez względu na wielkość liter) dowolnych **4 kolejnych znaków** z:
- rzędów klawiatury: `1234567890`, `qwertyuiop`, `asdfghjkl`, `zxcvbnm`,
- alfabetu `abc…z` i cyfr `0123…9`,
- oraz tych samych ciągów od tyłu (`ytrewq`, `4321`, `dcba`).

Przykłady odrzucone: `mojeqwertyhaslo99` (qwer), `dlugie haslo abcd kot` (abcd). Przyjęte: `zielony smok je pierogi`.

Zawsze działają też (zgodnie z NIST SP 800-63B-4): minimalna długość, maks. 128 znaków, lista haseł zakazanych, zakaz loginu w haśle. Nie ma wymogu dużych liter/cyfr/znaków specjalnych, a okresowa zmiana jest domyślnie wyłączona (ważność = 0 dni).

## Schemat bazy

```
roles(id, name)
permissions(id, code, description)
role_permissions(role_id → roles, permission_id → permissions)
users(id, login UNIQUE, full_name, password_hash, role_id → roles, is_blocked,
      must_change_password, otp_expires_at, password_changed_at,
      totp_secret, totp_enabled, created_at)
password_history(id, user_id → users, password_hash, created_at)
settings(key, value)        -- min_length, policy_no_sequences, password_validity_days,
                            -- session_timeout_minutes, password_history_count
articles(id, title, body, author_id → users, created_at)   -- zasób do pokazania RBAC
```

## Macierz uprawnień ról 

| Uprawnienie | Administrator | Redaktor | Czytelnik |
|---|:-:|:-:|:-:|
| `articles.read` – odczyt artykułów | ✔ | ✔ | ✔ |
| `articles.write` – dodawanie i usuwanie artykułów | ✘ | ✔ | ✘ |
| `users.manage` – zarządzanie użytkownikami | ✔ | ✘ | ✘ |
| `settings.manage` – ustawienia bezpieczeństwa | ✔ | ✘ | ✘ |
| Zmiana własnego hasła, TOTP, wylogowanie | ✔ | ✔ | ✔ |

Zasada najmniejszych uprawnień: administrator zarządza kontami, ale nie publikuje treści. To zadanie redaktora.

## Użytkownicy testowi (4)

| Login | Rola |
|---|---|
| jkowalski | Redaktor |
| anowak | Redaktor |
| pwisniewski | Czytelnik |
| mzielinska | Czytelnik |

Plus stałe konto **ADMIN** (Administrator). Hasła jednorazowe wypisuje `npm run seed`.

##  Struktura projektu

```
server.js            – serwer Express: logowanie, sesja, RBAC, API, panel admina, TOTP
db.js                – schemat bazy, role, uprawnienia, ustawienia domyślne
passwordPolicy.js    – polityka haseł (NIST + reguła wariantu 3)
otp.js               – hasło jednorazowe: 4 losowe słowa, ważne 24 h
users.js             – tworzenie kont i reset hasła (Argon2id)
seed.js              – 4 użytkowników testowych / reset hasła ADMIN
public/              – login.html, change-password.html, common.js, style.css
views/               – app.html, admin.html, 403.html (serwowane dopiero po sprawdzeniu uprawnień)
```

