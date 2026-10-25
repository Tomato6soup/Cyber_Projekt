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

## Odpowiedzi na pytania kontrolne

**1. Dlaczego mechanizmów kryptograficznych nie należy implementować samodzielnie?**

Kryptografia jest dziedziną, w której kod może działać poprawnie z punktu widzenia użytkownika, a mimo to być całkowicie niebezpieczny. Błędu nie widać w testach funkcjonalnych, ujawnia się dopiero podczas ataku. Gotowe biblioteki (np. argon2, express-session, moduł crypto w Node.js) są rozwijane przez specjalistów, przeszły audyty i są stale poprawiane po wykryciu podatności. Własna implementacja nie ma tej historii testów. Przykładowe błędy, które łatwo popełnić:

- Użycie zwykłego generatora liczb losowych (np. Math.random()) do tworzenia tokenów sesji lub haseł jednorazowych. Jego wyniki są przewidywalne, więc atakujący może odgadnąć kolejne wartości. Należy używać kryptograficznie bezpiecznego generatora (w aplikacji: crypto.randomInt przy losowaniu słów hasła jednorazowego).
- Porównywanie hashy lub tokenów zwykłym operatorem ==. Porównanie kończy się na pierwszym różnym znaku, więc czas odpowiedzi zdradza, ile znaków się zgadza (atak czasowy). Biblioteki stosują porównanie w stałym czasie.
- Inne typowe błędy: brak soli lub jedna sól dla wszystkich haseł, użycie szybkiego algorytmu (MD5, SHA) do haseł, brak zmiany identyfikatora sesji po zalogowaniu (session fixation).

**2. Dlaczego SHA-256 nie nadaje się do przechowywania haseł, a Argon2id tak? Jaką rolę pełni sól?**

SHA-256 jest funkcją skrótu zaprojektowaną do szybkiego działania, np. do sprawdzania integralności plików. Ta szybkość jest wadą przy hasłach: po wycieku bazy atakujący może na karcie graficznej sprawdzać miliardy haseł na sekundę i szybko złamać większość z nich atakiem słownikowym lub siłowym.

Argon2id jest algorytmem przeznaczonym do haseł. Jest celowo wolny i wymaga dużej ilości pamięci (memory-hard). Parametry kosztu (czas, pamięć, równoległość) można zwiększać wraz ze wzrostem mocy komputerów. Duże zużycie pamięci sprawia, że ataki na kartach graficznych i układach ASIC są dużo mniej opłacalne. W aplikacji użyto Argon2id z parametrami zalecanymi przez OWASP: 19 MiB pamięci, 2 iteracje, 1 wątek.

Sól to losowa wartość generowana osobno dla każdego hasła i zapisywana razem z hashem. Dzięki niej dwa identyczne hasła mają różne hashe, więc nie widać, którzy użytkownicy mają to samo hasło. Sól uniemożliwia też użycie gotowych tablic tęczowych (rainbow tables) i wymusza łamanie każdego hasła osobno. W aplikacji sól jest częścią zapisu w kolumnie password_hash, np. $argon2id$v=19$m=19456,t=2,p=1$<sól>$<hash>.

**3. Dlaczego NIST odradza wymuszone reguły złożoności i okresową zmianę hasła?**

Badania pokazały, że reguły typu „wielka litera, cyfra i znak specjalny” nie zwiększają realnie bezpieczeństwa. Użytkownicy spełniają je w przewidywalny sposób, np. Haslo1! albo Lato2024!, a atakujący znają te wzorce i uwzględniają je w słownikach. O sile hasła decyduje przede wszystkim jego długość, dlatego NIST SP 800-63B-4 zaleca minimalną długość, zgodę na długie frazy hasłowe i sprawdzanie haseł z listą haseł zakazanych (popularnych lub ujawnionych w wyciekach).

Okresowa wymiana hasła prowadzi do podobnych problemów. Użytkownicy zmieniają hasło minimalnie (Haslo1 na Haslo2), zapisują je na kartkach albo używają tych samych haseł w wielu serwisach. Hasło należy zmieniać tylko wtedy, gdy są dowody lub podejrzenie jego ujawnienia. W aplikacji polityka opiera się na długości (min. 15 znaków), liście haseł zakazanych i zakazie sekwencji klawiaturowych z wariantu 3, a domyślna ważność hasła to 0, czyli bez wygasania.

**4. Dlaczego ukrycie przycisku w interfejsie nie jest mechanizmem autoryzacji?**

Interfejs działa w przeglądarce, którą w pełni kontroluje użytkownik. Ukryty przycisk nadal odpowiada jakiemuś adresowi na serwerze. Użytkownik może go podejrzeć w kodzie strony lub w narzędziach deweloperskich (F12), a potem wysłać żądanie ręcznie, np. przez konsolę przeglądarki, curl albo Postman. Gdyby serwer nie sprawdzał uprawnień, takie żądanie zostałoby wykonane.

Autoryzacja musi więc być sprawdzana po stronie serwera przy każdym żądaniu, na podstawie roli zalogowanego użytkownika zapisanej w sesji. Ukrywanie przycisków to tylko wygoda, bo użytkownik nie widzi opcji, z których nie może skorzystać. W aplikacji Czytelnik nie widzi linku do panelu administratora, ale nawet gdy wywoła ręcznie adres /api/admin/users, serwer sprawdza uprawnienie users.manage i odpowiada kodem 403 Forbidden. Pokazuje to przycisk „Test autoryzacji” na stronie głównej.


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

