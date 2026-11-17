# WPIncidentLens — przewodnik analityka (M7, T-701)

Dla osoby, która przygotowuje materiał, uruchamia analizę i czyta raport. Narzędzie wskazuje **tropy do sprawdzenia**; nie wydaje werdyktu i nigdy nie stwierdza, że witryna jest „czysta”. Instalacja: [INSTALL.md](INSTALL.md); formaty: [FORMATS.md](FORMATS.md); pełny opis reguł i fałszywych alarmów: [RULES.md](RULES.md).

> Do bramki GO/NO-GO (M7) narzędzia używa się wyłącznie na danych syntetycznych (ADR 0002 B10, ADR 0009 pkt 7). Poniższe kroki opisują docelowy sposób pracy z autoryzowaną kopią.

## 1. Przygotowanie autoryzowanej kopii offline

1. **Autoryzacja i zakres.** Analizuj tylko kopię, do której analizy masz pisemne upoważnienie. Narzędzie pracuje offline: nie łączy się z badaną witryną ani z siecią.
2. **Kopia plików witryny.** Skopiuj katalog główny WordPressa z zachowaniem czasów modyfikacji (`mtime` jest jedynym źródłem czasu plików na osi czasu i w korelacji). Kopia z deduplikacją przez dowiązania twarde wymaga `--allow-hardlinks` — bez niej takie pliki są pomijane z luką `SKIPPED_HARDLINK`. Dowiązań symbolicznych narzędzie nie czyta.
3. **Zrzut bazy.** Zrzut SQL w postaci `INSERT INTO … VALUES` (mysqldump / mariadb-dump) albo eksport JSONL według kontraktu (FORMATS.md). Zrzut musi obejmować tabele `<prefiks>users`, `<prefiks>usermeta`, `<prefiks>options`.
4. **Logi dostępu** w formacie `combined`, `common` albo `json` — wskaż go flagą `--log-format`. Jeżeli serwer stoi za proxy, ustal sieci zaufanych proxy (`--trusted-proxy`) i, jeśli znasz, niepewność zegara serwera (`--log-clock-skew`).
5. **Referencje zaufane**, pozyskane **spoza** badanej kopii:
   - baseline (`--baseline`): SHA-256 plików z migawki sprzed incydentu i lista `known_admins`;
   - manifest sum rdzenia (`--core-checksums`): plik pobrany wcześniej na innej maszynie z `api.wordpress.org/core/checksums/1.0` dla wersji i locale witryny, z dopisanym `locale`.
   Bez referencji każdy plik kodu ma status `NOT_CHECKED` i wynik nie może być pełny (rozdział 5).
6. **Montowanie.** Materiał montuj tylko do odczytu, z `nodev`; dla materiału wysokiego ryzyka użyj osobnej VM albo kontenera z `docker/run-flags.txt`. Katalog wyników (`--output`) przygotuj poza materiałem dowodowym, z prawami `0700` — nigdy `777`.
7. **Ścieżki rzeczywiste.** Ścieżki źródeł nie mogą być dowiązaniami symbolicznymi (kod 2).

## 2. Uruchomienie analizy

```bash
python -m wpincidentlens --files /mnt/case/site --database /mnt/case/db.sql --logs /mnt/case/logs \
  --baseline /mnt/ref/baseline.json --core-checksums /mnt/ref/core-6.5.2-pl_PL.json \
  --known-admin admin --case-id CASE-2026-001 --operator-id analyst-7 --pseudonymize --output /srv/results/CASE-2026-001
```

- `--case-id` i `--operator-id`: 1–64 znaki `A-Z a-z 0-9 . _ -`, pierwszy znak inny niż kropka i łącznik. `--operator-id` to pseudonim; narzędzie nie odczytuje nazwy użytkownika systemu ani hosta.
- `--known-admin` (powtarzalna) uzupełnia `known_admins` z baseline.
- `--pseudonymize` — rozdział 8.
- Na stdout narzędzie wypisuje jeden wiersz JSON: `assessment`, `scope_complete`, liczba ustaleń i luk, `exit_code`, ścieżka `report.html`. Bez `--pseudonymize` na stderr pojawia się ostrzeżenie o danych osobowych, jeśli raport je zawiera.

## 3. Jak czytać raport — kolejność

1. **`assessment` i `scope_complete`** (`report.html` u góry albo `coverage.json`).
2. **Pokrycie i luki** (`coverage`, `coverage_gaps`): czego narzędzie nie widziało. Przeczytaj je **przed** ustaleniami — brak ustaleń w źródle `PARTIAL` niewiele znaczy.
3. **Ustalenia** (`findings`): reguła, `severity`, `confidence`, wyjaśnienie, wskazane obserwacje.
4. **Obserwacje** (`observations`, tylko w JSON): położenie (ścieżka, wiersz logu, tabela) i atrybuty, np. `offset` i `length` trafienia — fragment odczytujesz sam, z kopii dowodowej. Dopasowana treść nie trafia do raportu.
5. **Oś czasu** (`timeline`): orientacyjna, z podstawą każdego czasu.
6. **`case.json`**: limity, flagi, wersja rejestru reguł, skróty plików wyniku (`outputs`) — plik o innym skrócie jest nieaktualny.

## 4. Ocena (`assessment`) — dokładne reguły

Jedna funkcja `models.assess(findings, coverage)`, sprawdzana w tej kolejności:

| Etykieta | Warunek |
|---|---|
| `STRONG_INDICATORS` | istnieje ustalenie o `severity` `high` lub `critical` **i** `confidence` `high` — także przy niepełnym zakresie |
| `SUSPICIOUS` | istnieje jakiekolwiek inne ustalenie |
| `NO_INDICATORS_IN_ANALYZED_SCOPE` | brak ustaleń i `scope_complete` jest prawdą |
| `INCONCLUSIVE` | brak ustaleń i zakres niepełny |

`scope_complete` (`models.scope_complete`): `files`, `database` i `logs` mają status `ANALYZED`, a `baseline` — `ANALYZED` albo `NOT_PROVIDED`.

- Liczba ustaleń ani ich korelacja niczego nie sumują: dziesięć ustaleń `medium`/`medium` to nadal `SUSPICIOUS`.
- **Żadna obecna reguła nie ma jednocześnie wagi `high` i pewności `high`**, więc `STRONG_INDICATORS` jest dziś nieosiągalny (ADR 0003 §6). Najwyższa realna etykieta to `SUSPICIOUS`.
- `NO_INDICATORS_IN_ANALYZED_SCOPE` znaczy tylko: reguły PoC niczego nie znalazły w tym, co przeanalizowano w całości. To nie jest „czysto”.

## 5. Waga i pewność

- **`severity`** (`low`, `medium`, `high`, `critical`): możliwy skutek faktu, gdyby znaczył to, co sugeruje reguła. Nie jest prawdopodobieństwem ataku.
- **`confidence`** (`low`, `medium`, `high`): siła dowodu, że fakt znaczy to, co sugeruje reguła. Reguły treści dopasowują tekst, nie składnię PHP, więc nigdy nie mają `high`; pewność `high` mają tylko porównania z zaufaną referencją (fakt „plik inny niż w referencji” jest pewny, jego znaczenie — nie).
- Obie skale są niezależne: `BASELINE_FILE_CHANGED` ma wagę `medium` i pewność `high` (zmiana na pewno jest, ale bywa legalna), `HTTP_EXECUTABLE_IN_UPLOADS` — wagę `high` i pewność `medium` albo `low`.
- Pewność części reguł zależy od położenia pliku: w core, wtyczce i motywie słabsze heurystyki mają `low`. Położenie to wskazówka, nie dowód pochodzenia.

## 6. Pokrycie i luki — dlaczego `INCONCLUSIVE` jest częste

| Status | Znaczenie | Typowe przyczyny |
|---|---|---|
| `ANALYZED` | źródło przeanalizowane w całości | — |
| `PARTIAL` | część materiału nie została przeanalizowana albo zweryfikowana | plik kodu bez referencji (`NOT_CHECKED`), pominięty wpis (dowiązanie, hardlink, brak uprawnień), limit, niesparsowane wiersze logu, instrukcja SQL poza gramatyką, zmiana pliku w trakcie analizy (`CHANGED`), błąd reguły |
| `NOT_PROVIDED` | źródła nie podano | brak `--database`, `--logs`, referencji |
| `FAILED` | źródło podano, ale nic z niego nie przeanalizowano | logi w innym formacie, pusty katalog, zrzut bez tabel rdzenia, plik nieczytelny |

`INCONCLUSIVE` (brak ustaleń przy niepełnym zakresie) jest najczęstszym wynikiem, bo pełny zakres wymaga naraz bazy, logów i **porównania każdego pliku kodu z zaufaną referencją**. Plik kodu (PHP i pokrewne, `.htaccess`, `.user.ini`, `php.ini`), którego nie porównano z baseline ani z manifestem, obniża `files` do `PARTIAL` (ADR 0005 pkt 6). Manifest rdzenia nie obejmuje wtyczek, motywów, uploads ani `wp-config.php`, więc zwykle potrzebny jest też baseline.

Co zrobić z luką — kolejno:

1. Przeczytaj `coverage_gaps`: każda luka nazywa źródło i przyczynę (np. `NOT_CHECKED: … klasy PLUGIN`, `MAX_FILES`, `SKIPPED_HARDLINK`, „Nie sparsowano X/Y wierszy logów”).
2. Brakujące źródło — dołącz bazę albo logi; brak referencji — dostarcz baseline z `files` albo manifest sum rdzenia.
3. Limit — podnieś odpowiednią flagę (`--max-files`, `--max-entries`, `--max-seconds` …), pamiętając o pamięci (`bench/RESULTS.md`).
4. Pominięte dowiązania twarde w kopii z deduplikacją — `--allow-hardlinks`.
5. Odrzucone wiersze logu — sprawdź `--log-format`; formaty spoza listy wymagają konwersji do `json@1` poza narzędziem.
6. Jeśli luki nie da się usunąć, opisz ją w notatce z analizy jako ograniczenie wniosku.

## 7. Rodziny reguł — co sprawdzić dalej

Każde ustalenie to heurystyka. Kolumna „Następny krok” mówi, czego szukać w kopii dowodowej; wszystkie reguły i ich fałszywe alarmy opisuje [RULES.md](RULES.md).

### Pliki — ścieżka

| Reguła | Następny krok |
|---|---|
| `EXECUTABLE_IN_UPLOADS` | Otwórz plik z kopii (nie wykonuj go); sprawdź, czy jakaś wtyczka legalnie trzyma kod w uploads; szukaj żądań do tej ścieżki w logach |
| `DOUBLE_EXTENSION_IN_UPLOADS` | Sprawdź treść pliku i konfigurację serwera: czy podwójne rozszerzenie jest przekazywane do PHP |
| `CODE_IN_UNEXPECTED_LOCATION` | Porównaj z pakietem dystrybucji danej wersji WordPressa i paczką językową |

### Pliki — treść kodu i konfiguracji

| Reguła | Następny krok |
|---|---|
| `SUSPICIOUS_PHP_EVAL_DECODE` | Odczytaj fragment po `offset`; ustal, czy to licencjonowany paker, sygnatura skanera, czy wstrzyknięty kod; porównaj z oryginalną wersją pliku |
| `REQUEST_TO_COMMAND_EXEC` | Sprawdź, czy dane żądania faktycznie trafiają do polecenia (reguła mierzy bliskość w tekście, nie przepływ) |
| `REQUEST_TO_CODE_EVAL` | Odczytaj fragment; sprawdź, czy to komentarz lub dokumentacja |
| `REQUEST_VARIABLE_FUNCTION_CALL` | W legalnym kodzie bardzo rzadkie — priorytet; ustal pochodzenie pliku |
| `PHP_PREG_REPLACE_EVAL` | Sprawdź wiek kodu i wersję PHP serwera (na PHP 7+ `/e` nie działa) |
| `LONG_ENCODED_BLOB` | Sprawdź, czy to osadzony zasób (obraz, font, tablica) czy zakodowany ładunek |
| `REQUEST_INPUT_TO_INCLUDE` | Podatność LFI albo backdoor; ustal, czy plik pochodzi z wtyczki i z której wersji |
| `REQUEST_CONTROLLED_FILE_WRITE` | Ustal, czy to edytor plików / narzędzie deweloperskie, czy wstrzyknięty kod |
| `HTACCESS_ENABLES_PHP_IN_UPLOADS` | Sprawdź, kto i kiedy dodał dyrektywę; szukaj plików kodu w tym katalogu |
| `PHP_AUTO_PREPEND_CONFIG` | Sprawdź wskazany plik prepend/append; zapory aplikacyjne (np. Wordfence) robią to legalnie |
| `YARA_MATCH` | Jakość zależy od pakietu operatora; odczytaj fragment po `offset`, sprawdź regułę w pakiecie (`pack_sha256`) |

### Pliki — integralność względem referencji

| Reguła | Następny krok |
|---|---|
| `BASELINE_FILE_CHANGED` | Porównaj treść z wersją z migawki; sprawdź historię aktualizacji i wdrożeń po dacie migawki |
| `BASELINE_FILE_MISSING` | Ustal, czy plik usunięto legalnie (odinstalowanie) albo czy kopia jest niepełna |
| `NEW_FILE_SINCE_BASELINE` | mu-plugins i drop-iny ładują się automatycznie — priorytet; sprawdź treść i datę |
| `CORE_CHECKSUM_MISMATCH` | Plik rdzenia inny niż w dystrybucji: porównaj z oryginałem tej wersji |
| `CORE_FILE_NOT_IN_MANIFEST` | Plik kodu w katalogu rdzenia spoza dystrybucji: skrypt hostingu, plik weryfikacyjny czy wstrzyknięty kod |
| `CORE_FILE_MISSING` | Ustal, czy kopia jest pełna; usunięty plik rdzenia bywa skutkiem „sprzątania” po ataku |
| `CORE_MANIFEST_MISMATCH` | Upewnij się, że manifest dotyczy wersji i locale witryny; jeśli tak, `version.php` mógł zostać zmieniony, by ukryć zmiany rdzenia — powtórz analizę z właściwym manifestem |
| `REFERENCE_FILE_UNREADABLE` | Ustal, dlaczego wpis nie został odczytany (status w wyjaśnieniu); wykonaj kopię ponownie albo użyj `--allow-hardlinks` |

### Baza danych

| Reguła | Następny krok |
|---|---|
| `UNRECOGNIZED_ADMIN` | Lista `--known-admin` może być niepełna; potwierdź konto u właściciela witryny |
| `NEW_SINCE_BASELINE` | Konto administratora nowe względem migawki: sprawdź datę rejestracji (atrybut `registered`) i aktywność w logach |
| `SUSPICIOUS_DB_MARKUP` | Odczytaj opcję w zrzucie (cytat `excerpt` jest po redakcji); odróżnij analitykę i osadzone media od wstrzykniętego skryptu |

Inwentarz bazy (`ADMINISTRATOR_ACCOUNT`, `CRON_HOOK`, `ACTIVE_PLUGIN`) to obserwacje bez ustalenia — przejrzyj go ręcznie: nieznane zadanie cron albo nieznana aktywna wtyczka nie dają alertu.

### Logi HTTP i korelacja

| Reguła | Następny krok |
|---|---|
| `HTTP_EXECUTABLE_IN_UPLOADS` | Sprawdź, czy plik istnieje w kopii (status 404 też daje ustalenie: skanery odpytują typowe ścieżki); porównaj adresy klientów i czasy |
| `CORRELATED_UPLOAD_REQUEST` | Ten sam plik kodu w uploads jest w kopii i w logu — priorytet; ustal pierwsze żądanie i adres klienta, szukaj wcześniejszego zapisu pliku |
| `CORRELATED_FILE_REQUEST` | Ruch do pliku z ustaleniem plikowym: odróżnij zwykły ruch od wywołań z nietypowych adresów |
| `REQUEST_NEAR_FILE_CHANGE` | Bliskość w czasie żądania i `mtime`: zweryfikuj, czy `mtime` jest wiarygodny (rozpakowanie kopii, `touch`) i jaki jest zegar serwera |

## 8. Korelacja i czas — zastrzeżenia

- Korelacja (`SAME_PATH`, `NEAR_IN_TIME`) **nigdy nie dowodzi przyczynowości**, zapisu pliku, wykonania kodu ani tego, że plik istniał w chwili żądania. HTTP 200 nie jest dowodem wykonania.
- `mtime` jest zmienialny (napastnik, `touch`, rozpakowanie kopii) — oś czasu oznacza go jako „zmienialny”.
- Zegar serwera logów nie jest weryfikowany. `--log-clock-skew` to Twoja deklaracja: poszerza okno korelacji (`--correlation-window`, domyślnie 900 s) i trafia do podstawy czasu na osi. Czas logu bez strefy nie jest sprowadzany do UTC.
- Porównanie ścieżek jest dokładne i względne do `--files`: witryna w podkatalogu URL (`/blog/…`) i multisite nie są dopasowywane.

## 9. Dane osobowe i `--pseudonymize`

Bez flagi raport zawiera jawnie adresy IP klientów i loginy kont (także w postaci e-mail) — to dane osobowe; HTML i stderr ostrzegają o tym. `--pseudonymize` zastępuje je pseudonimami `ip-`, `user-`, `uid-<16 hex>` (HMAC-SHA256 z kluczem losowanym na jedno uruchomienie i nigdzie niezapisywanym):

- ten sam adres lub login ma ten sam pseudonim w jednym raporcie, więc korelacja działa; między uruchomieniami pseudonimy są różne i nie da się ich odwrócić ani porównać;
- porównanie z `--known-admin` i `known_admins` odbywa się przed pseudonimizacją;
- jawne pozostają m.in. czas rejestracji konta, nazwy w ścieżkach i kluczach (np. slug autora w URL), domeny e-mail w cytatach.

Niezależnie od flagi teksty swobodne przechodzą redakcję sekretów (`redact`): query string w `uri` jest usuwany w całości, dane logowania w URL i rozpoznane wzorce sekretów są zastępowane. Redakcja nie jest zupełna, a nazwy plików i ścieżki nie są redagowane. Przechowuj raport jak materiał dowodowy i przejrzyj go przed przekazaniem.

## 10. Ograniczenia i znane fałszywe wyniki

- **Fałszywe alarmy**: pakery i obfuskatory komercyjnych wtyczek, osadzone zasoby (`LONG_ENCODED_BLOB`), zapory aplikacyjne (`PHP_AUTO_PREPEND_CONFIG`), legalne aktualizacje po migawce (`BASELINE_FILE_CHANGED`), skanery i boty w logach (`HTTP_EXECUTABLE_IN_UPLOADS`), analityka i osadzone media w opcjach (`SUSPICIOUS_DB_MARKUP`). Pomiar na 21 publicznych pakietach z wordpress.org: [FP_MEASUREMENT.md](FP_MEASUREMENT.md) — korpus bez wtyczek komercyjnych, pakowanych i bez uploads.
- **Fałszywe negatywy**: brak parsera PHP (łączenie łańcuchów, komentarz w środku wywołania, zmienne pośrednie omijają reguły); kod ukryty w obrazie o zwykłej nazwie; pliki ponad 4 MiB nie są skanowane treścią; rola administratora nadana inaczej niż kluczem `administrator` (uprawnienia wprost, rola niestandardowa); znaczniki zapisane encjami w opcjach; tabele `posts`/`postmeta` nie są sprawdzane; witryny podrzędne multisite; rozszerzenia skonfigurowane jako PHP spoza listy (np. `.html`).
- **Poza zakresem**: logi błędów, IIS/W3C, `vhost_combined`; wektor ataku nie jest ustalany; brak chain of custody i podpisu raportu; brak wykonywania PHP i uczenia maszynowego.
- Wartości z `wp-config.php` i `version.php` (wersja, locale, prefiks) to kandydaci z plików, które napastnik mógł zmienić.

## 11. Lista kontrolna triage

1. Czy materiał jest autoryzowaną kopią, zamontowaną tylko do odczytu, a `--output` leży poza nim?
2. Kod wyjścia: `2` — popraw wywołanie; `4` — które podane źródło ma `FAILED` i dlaczego?
3. `scope_complete` i każda pozycja `coverage_gaps` — czy luki da się usunąć (rozdział 6)? Jeśli tak, powtórz analizę.
4. Ustalenia od najwyższej wagi; dla każdego: obserwacja, położenie, odczyt fragmentu z kopii po `offset`, zestawienie ze znanymi fałszywymi alarmami (RULES.md).
5. Ustalenia korelacyjne i oś czasu — z zastrzeżeniami z rozdziału 8.
6. Inwentarz bazy (administratorzy, cron, aktywne wtyczki) — przegląd ręczny.
7. `case.json`: `ruleset.version`, limity, flagi, zgodność skrótów `outputs` z plikami.
8. Notatka z analizy: ocena, luki jako ograniczenia wniosku, ustalenia potwierdzone i odrzucone z uzasadnieniem.
9. Przed przekazaniem raportu: dane osobowe (rozdział 9).

## 12. Czego narzędzie nigdy nie twierdzi

- Że witryna jest „czysta” albo nie została naruszona — takiej etykiety nie ma; brak ustaleń to `INCONCLUSIVE` albo `NO_INDICATORS_IN_ANALYZED_SCOPE` (tylko w przeanalizowanym zakresie).
- Że plik jest złośliwy, kod został wykonany, a konto utworzył napastnik — ustalenie to trop do sprawdzenia.
- Że korelacja oznacza przyczynę albo że kolejność na osi czasu jest pewna.
- Że kod wyjścia jest oceną — opisuje wyłącznie pełność analizy.
