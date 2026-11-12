# Reguły plików (FileAnalyzer, IntegrityAdapter) i obserwacje WPDetector

Dokument opisuje trzy rzeczy: reguły ścieżki i treści (`wpincidentlens/filerules.py`), reguły integralności względem zaufanej referencji (`wpincidentlens/integrity.py`) oraz obserwacje WPDetector (`wpincidentlens/wpdetect.py`), które **nie są ustaleniami**. Reguły bazy danych opisuje sekcja „Reguły bazy danych” na końcu; reguła logów (`wpincidentlens/cli.py`) nie jest tu opisana.

Źródło prawdy dla reguł ścieżki i treści: tabela `RULES` w `wpincidentlens/filerules.py` (`RULESET_VERSION = "2026.11.1"`). Test `tests/test_filerules.py` pilnuje, żeby każda reguła z tabeli była tu opisana i miała przypadek pozytywny, negatywny oraz fałszywy alarm wzorowany na legalnym kodzie.

## Jak czytać trafienie

- Każda reguła to **heurystyka**, nie dowód. `severity` (możliwy skutek) i `confidence` (pewność, że fakt znaczy to, co sugeruje reguła) są niezależne.
- Reguły treści dopasowują **tekst**, nie składnię PHP. Trafienie w komentarzu, w łańcuchu znaków albo w sygnaturze skanera bezpieczeństwa liczy się tak samo jak w kodzie. Dlatego żadna reguła treści nie nadaje pewności `high` i sama nie daje oceny `STRONG_INDICATORS`.
- Jedno ustalenie na regułę i plik. Obserwacja reguły treści ma atrybuty `rule_version`, `offset` (bajtowy offset pierwszego trafienia w pliku), `length` (długość trafienia w bajtach) i `match_count` (liczba trafień w pliku).
- Do raportu **nie trafia dopasowana treść** — może zawierać sekrety albo znaczniki HTML. Analityk odczytuje fragment sam, z kopii dowodowej, po offsecie.
- Reguły ścieżki działają także dla plików, których nie odczytano (dowiązanie, błąd, limit); ich obserwacje nie mają atrybutów.
- Położenie pliku (`fileclass.classify`) obniża pewność słabszych heurystyk tam, gdzie kod jest oczekiwany: w core, wtyczce i motywie. Położenie to wskazówka, nie dowód pochodzenia — ustalenie zostaje, zmienia się tylko `confidence`.

## Reguły ścieżki

| Reguła | Spec | Wersja | Waga | Pewność | Co wykrywa | Fałszywe alarmy |
|---|---|---|---|---|---|---|
| `EXECUTABLE_IN_UPLOADS` | WP-FILE-001 | 2 | high | medium (low, gdy pliku nie odczytano) | Plik z rozszerzeniem kodu (`.php .phtml .phar .inc .pht .php3 .php4 .php5 .php7 .php8`) w `wp-content/uploads/` | Nietypowe wdrożenia i wtyczki zapisujące kod w uploads (cache, generowane szablony) |
| `DOUBLE_EXTENSION_IN_UPLOADS` | WP-FILE-005 | 1 | medium | low | Nazwa w uploads z rozszerzeniem kodu przed ostatnim rozszerzeniem, np. `photo.php.jpg` | Kopie i eksporty nazwane `plik.php.txt`, `plik.php.bak` |
| `CODE_IN_UNEXPECTED_LOCATION` | WP-FILE-005 | 1 | medium | low w `wp-content/languages`, medium w katalogach zasobów core | Plik kodu w `wp-content/languages/` (poza `*.l10n.php`) albo w `wp-includes/{images,fonts,css}/`, `wp-admin/{images,css}/` | Starsze paczki językowe z plikiem `<locale>.php` |

## Reguły treści plików kodu

Dotyczą plików z rozszerzeniem kodu oraz plików z podwójnym rozszerzeniem w uploads.

| Reguła | Spec | Wersja | Waga | Pewność | Co wykrywa | Fałszywe alarmy |
|---|---|---|---|---|---|---|
| `SUSPICIOUS_PHP_EVAL_DECODE` | WP-FILE-004 | 2 | high | medium | `eval`/`assert`/`create_function('', …)` zasilane wprost dekoderem (`base64_decode`, `gzinflate`, `gzuncompress`, `gzdecode`, `str_rot13`, `strrev`, `hex2bin`, `convert_uudecode`) | Licencjonowane pakery i obfuskatory, stare wtyczki komercyjne, tekst wzorca w komentarzu lub sygnaturze skanera |
| `REQUEST_TO_COMMAND_EXEC` | — | 2 | high | medium | Wywołanie `system`/`exec`/`shell_exec`/`passthru`/`popen`/`proc_open`/`pcntl_exec`, przy którym dane żądania (`$_GET/$_POST/$_REQUEST/$_COOKIE[`, `$_SERVER['HTTP_…`) występują do 300 B wcześniej albo do 60 B później | Wtyczki kopii zapasowych i narzędzia administracyjne; to bliskość w tekście, nie przepływ danych |
| `REQUEST_TO_CODE_EVAL` | — | 1 | high | medium | `eval`/`assert` z danymi żądania jako argumentem, także przez najwyżej trzy funkcje pośrednie | Tekst wzorca w komentarzu, dokumentacji albo sygnaturze skanera |
| `REQUEST_VARIABLE_FUNCTION_CALL` | — | 1 | high | medium | Wartość z żądania wywołana jak funkcja: `$_POST[…](…)` | Tekst wzorca w komentarzu albo sygnaturze; w legalnym kodzie bardzo rzadkie |
| `PHP_PREG_REPLACE_EVAL` | WP-FILE-004 | 1 | high | medium; low w core, wtyczce i motywie | `preg_replace` z modyfikatorem `/e` | Stary, legalny kod sprzed PHP 5.5; na PHP 7+ modyfikator nie działa |
| `LONG_ENCODED_BLOB` | WP-FILE-004 | 1 | medium | medium; low w core, wtyczce i motywie | Nieprzerwany ciąg ≥ 4096 znaków base64/hex albo ≥ 64 kolejnych sekwencji `\x..` | Osadzone obrazy, fonty i ikony (data URI), tablice kryptograficzne, zminifikowane zasoby |
| `REQUEST_INPUT_TO_INCLUDE` | — | 1 | high | medium; low w core, wtyczce i motywie | `include`/`require(_once)` ze ścieżką wprost z danych żądania | Stary, podatny (LFI), ale niezłośliwy kod |
| `REQUEST_CONTROLLED_FILE_WRITE` | — | 1 | high | medium; low w core, wtyczce i motywie | `file_put_contents`, którego pierwszym argumentem (ścieżką) są dane żądania | Podatny, ale niezłośliwy kod edytorów plików i narzędzi deweloperskich |

## Reguły treści plików konfiguracji

| Reguła | Spec | Wersja | Waga | Pewność | Co wykrywa | Fałszywe alarmy |
|---|---|---|---|---|---|---|
| `HTACCESS_ENABLES_PHP_IN_UPLOADS` | WP-FILE-006 | 1 | high | medium | `.htaccess` w uploads: `AddHandler`/`AddType`/`SetHandler` z typem lub handlerem PHP albo `php_flag engine on` | Nietypowa konfiguracja hostingu. Dyrektywy **wyłączające** PHP (`php_flag engine off`, `AddType text/plain .php`, `RemoveHandler`, `deny from all`) i wiersze zakomentowane nie są zgłaszane |
| `PHP_AUTO_PREPEND_CONFIG` | WP-FILE-006 | 1 | high | low | `.htaccess`, `.user.ini` albo `php.ini` w dowolnym katalogu z niepustym `auto_prepend_file`/`auto_append_file` (wartość `none` jest pomijana) | Zapory aplikacyjne (np. tryb rozszerzonej ochrony Wordfence) i ustawienia hostingu — trafienie jest wtedy prawdziwe, ale niezłośliwe |

## Reguły integralności (IntegrityAdapter)

Źródło prawdy: `wpincidentlens/integrity.py` (klasa `ReferenceComparison`); testy: `tests/test_integrity.py`. Reguły porównują pliki z **zaufaną referencją dostarczoną przez operatora**: z baseline (`--baseline`, SHA-256) i z lokalnym manifestem sum rdzenia WordPress.org (`--core-checksums`, MD5). Narzędzie niczego nie pobiera z sieci.

- MD5 służy wyłącznie do porównania z publicznym manifestem i występuje tylko w atrybutach obserwacji (`observed_md5`, `reference_md5`). Skrótem dowodu pozostaje SHA-256.
- Reguły integralności są zapisane w kodzie i **nie mają wersji** (w odróżnieniu od tabeli `RULES`); `RULESET_VERSION` ich nie obejmuje.
- Obserwacje niosą opis referencji, jeśli operator go podał: `reference_version` (`wordpress_version` z baseline albo z manifestu), `reference` (wolny opis) i — dla manifestu — `reference_file`.
- Różnica względem referencji **nie przesądza o ataku**: aktualizacja, zmiana administratora albo referencja innej wersji dają ten sam obraz. Zgodność z referencją mówi tylko, że plik jest taki jak w referencji.
- `BASELINE_FILE_MISSING` i `CORE_FILE_MISSING` powstają tylko po pełnym przejściu drzewa. Wpis, który istnieje, ale nie został odczytany (albo leży pod nieodczytanym katalogiem), nie jest zgłaszany jako brakujący.
- Każda reguła integralności daje najwyżej **200 ustaleń** na przebieg (`MAX_FINDINGS_PER_RULE`). Nadmiar nie znika: powstaje luka z nazwą reguły i łączną liczbą wykryć, a pokrycie `files` spada do `PARTIAL`.

| Reguła | Spec | Waga | Pewność | Rodzaj obserwacji | Co wykrywa | Fałszywe alarmy |
|---|---|---|---|---|---|---|
| `BASELINE_FILE_CHANGED` | — | medium | high | `FILE_DIFFERS_FROM_BASELINE` (`baseline_sha256`) | Odczytany plik ma inny SHA-256 niż wpis w `baseline.files` | Legalna aktualizacja lub zmiana administratora po wykonaniu migawki; baseline innej wersji |
| `BASELINE_FILE_MISSING` | — | low | high | `BASELINE_ENTRY_NOT_IN_FILES` (na dowodzie baseline) | Plik wymieniony w baseline nie występuje w materiale | Plik usunięty legalnie (np. odinstalowana wtyczka); kopia obejmująca tylko część witryny |
| `NEW_FILE_SINCE_BASELINE` | WP-FILE-003 | medium | medium (low, gdy wpisu nie odczytano) | `FILE_NOT_IN_BASELINE` albo `ENTRY_NOT_IN_BASELINE` (`file_class`) | Plik w miejscu ładowanym automatycznie — `wp-content/mu-plugins/` albo drop-in w `wp-content/` (np. `object-cache.php`, `db.php`, `advanced-cache.php`) — którego niepusty baseline nie wymienia; także nieodczytany katalog `wp-content/mu-plugins` | Baseline starszy niż legalna zmiana: mu-plugin hostingu, drop-in wtyczki cache dodany po migawce |
| `CORE_CHECKSUM_MISMATCH` | WP-FILE-002 | medium | high | `FILE_DIFFERS_FROM_CORE_MANIFEST` (`observed_sha256`, `observed_md5`, `reference_md5`) | Odczytany plik ma inny MD5 niż wpis w manifeście sum rdzenia | Manifest innej wersji lub innego locale WordPressa (narzędzie tego nie sprawdza); poprawka naniesiona przez administratora |
| `CORE_FILE_NOT_IN_MANIFEST` | — | medium | low | `FILE_NOT_IN_CORE_MANIFEST` | Plik kodu lub konfiguracji (rozszerzenie kodu, `.htaccess`, `.user.ini`, `php.ini`) w katalogu głównym, `wp-admin` albo `wp-includes`, którego manifest nie wymienia; także nieodczytany. Nie dotyczy `wp-config.php`, `.htaccess`, `.user.ini` i `php.ini` w katalogu głównym | Manifest innej wersji lub locale; legalne pliki spoza dystrybucji w katalogu głównym (skrypty hostingu, pliki weryfikacyjne, `.htaccess` w `wp-admin`) |
| `CORE_FILE_MISSING` | — | low | high | `CORE_MANIFEST_ENTRY_NOT_IN_FILES` (na dowodzie manifestu, `reference_md5`) | Plik wymieniony w manifeście nie występuje w materiale. Wpisy manifestu pod `wp-content/` (dołączone motywy i wtyczki) nie dają ustalenia, tylko jedną notę z liczbą | Manifest innej wersji; plik rdzenia usunięty celowo przez administratora |
| `REFERENCE_FILE_UNREADABLE` | — | medium | low | `REFERENCE_ENTRY_NOT_READ` (`listed_in`, `listed_as`) | Wpis, który referencja wymienia jako plik albo jako katalog swoich plików, istnieje, ale nie został odczytany: dowiązanie symboliczne, dodatkowe dowiązanie twarde, brak uprawnień, plik specjalny, limit rozmiaru. Wyjaśnienie nazywa status odczytu | Kopie z deduplikacją przez dowiązania twarde (wtedy `--allow-hardlinks`); materiał skopiowany bez uprawnień do odczytu. Sam brak odczytu nie dowodzi zmiany pliku |

Czego reguły integralności **nie** zgłaszają jako ustalenia:

- Plik bez wpisu w żadnej referencji poza miejscami z tabeli (np. nowy plik we wtyczce, motywie albo uploads). Gdy podano referencję, zostaje nota `NO_TRUSTED_REFERENCE` z liczbą takich odczytanych plików i najwyżej trzema przykładami (nazwy cytowane jak łańcuchy JSON); niezależnie od tego plik jest liczony w `NOT_CHECKED` (niżej).
- Katalog pominięty przez limit operatora (głębokość, liczba wpisów) i pliki, do których przerwane przejście nie dotarło: to luka pokrycia, nie ustalenie.

### Brak referencji: `NOT_CHECKED`

Plik, którego nie porównano z żadną referencją, jest liczony w powodzie `NOT_CHECKED: integralność plików klasy <KLASA> (plików: N, w tym kodu: K) niezweryfikowana — brak zaufanej referencji` (klasy z `wpincidentlens/fileclass.py`: `CORE`, `CONFIG`, `DROPIN`, `MU_PLUGIN`, `PLUGIN`, `THEME`, `UPLOAD`, `LANGUAGE`, `OTHER`; klasa wynika z położenia pliku i nie jest dowodem pochodzenia). Powód powstaje dla klas `CORE`, `PLUGIN`, `THEME`, `MU_PLUGIN` i `DROPIN` zawsze, a dla pozostałych wtedy, gdy wśród niezweryfikowanych jest plik kodu; liczba obejmuje też wpisy nieodczytane. Jeżeli wśród takich plików jest choć jeden plik kodu (rozszerzenie kodu, `.htaccess`, `.user.ini`, `php.ini`; odczytany albo nie), pokrycie `files` ma status `PARTIAL`: `scope_complete` jest fałszem, przebieg bez ustaleń daje `INCONCLUSIVE`, a kod wyjścia to 3 (ADR 0005 pkt 6). Pliki niebędące kodem (obrazy, CSS, JS) bez referencji zostają notą, która statusu nie obniża. Reguła jest taka sama z referencją i bez niej, więc analiza bez baseline i bez manifestu nigdy nie kończy się kodem 0, jeśli w drzewie jest plik kodu.

## Obserwacje WPDetector (nie ustalenia)

Źródło prawdy: `wpincidentlens/wpdetect.py`; testy: `tests/test_wpdetect.py`. WPDetector zapisuje w `observations` **kandydatów**: wartości odczytane z plików, które napastnik mógł zmienić. Z kandydata nie powstaje ustalenie, nie wpływa on na `assessment`, pokrycie ani kod wyjścia i nie jest używany do wyboru ani sprawdzenia manifestu.

| Rodzaj obserwacji | Skąd (`origin`) | Dozwolona postać wartości |
|---|---|---|
| `WP_VERSION_CANDIDATE` | `$wp_version` w `wp-includes/version.php` (`WP_VERSION_ASSIGNMENT`) | cyfra, potem do 31 znaków `0-9 A-Z a-z . + -` |
| `WP_DB_VERSION_CANDIDATE` | `$wp_db_version` w `wp-includes/version.php` (`WP_DB_VERSION_ASSIGNMENT`) | 1–10 cyfr |
| `WP_LOCALE_CANDIDATE` | `$wp_local_package` w `wp-includes/version.php` (`WP_LOCAL_PACKAGE_ASSIGNMENT`); `define('WPLANG', …)` w `wp-config.php` (`WPLANG_DEFINE`); nazwa pliku `wp-content/languages/<locale>.mo` (`LANGUAGE_FILE_NAME`, najwyżej 16 plików) | kod locale, np. `pl_PL`, `de_DE_formal` |
| `WP_TABLE_PREFIX_CANDIDATE` | `$table_prefix` w `wp-config.php` (`TABLE_PREFIX_ASSIGNMENT`) | 1–64 znaki `A-Z a-z 0-9 _` |

Atrybuty każdej obserwacji: `value`, `confidence`, `origin`, `basis` (uzasadnienie pewności).

- Rozpoznawane jest wyłącznie przypisanie **pojedynczego literału**. Przypisanie zakomentowane, złożone z konkatenacji, wywołania albo zmiennej nie daje kandydata. Wartość spoza wzorca nie jest cytowana.
- `confidence` kandydata: `high` tylko wtedy, gdy plik ma wpis w baseline i jest z nim zgodny; `medium` bez referencji dla pliku; `low`, gdy plik różni się od baseline, gdy ustawienie występuje w pliku więcej niż raz albo gdy źródła wskazują różne locale. Locale z plików nie przekracza `medium`, a z nazwy pliku `.mo` ma zawsze `low`.
- Wszystko, czego nie ustalono (brak pliku, plik nieodczytany, plik większy niż 256 KiB, brak przypisania literału, niejednoznaczność), trafia do jednej noty pokrycia `WPDetector: …`. Nota nie obniża statusu pokrycia.
- Z `wp-config.php` do raportu trafia tylko wartość prefiksu i locale po sprawdzeniu wzorcem. Żadna inna treść tego pliku nie jest kopiowana ani cytowana.

## Ograniczenia

- Brak parsera PHP: łączenie łańcuchów (`'ev'.'al'`), komentarz między nazwą funkcji a nawiasem, zmienne pośrednie i kodowanie nazw omijają reguły. Brak trafienia nie oznacza, że plik jest czysty.
- Odstępy we wzorcach są ograniczone (do 16 znaków), żeby czas dopasowania był liniowy; dłuższa seria odstępów omija regułę.
- `REQUEST_TO_COMMAND_EXEC` bada bliskość w tekście, nie przepływ danych.
- `LONG_ENCODED_BLOB` widzi tylko ciąg bez przerw; blob łamany na wiersze albo sklejany z fragmentów nie jest wykrywany.
- `PHP_PREG_REPLACE_EVAL` nie obejmuje ograniczników nawiasowych (`{…}e`) ani wzorców z cudzysłowem w środku.
- Treść plików multimedialnych w uploads nie jest czytana do pamięci (poza plikami z podwójnym rozszerzeniem), więc kod PHP ukryty w obrazie o zwykłej nazwie nie jest wykrywany.
- Plik większy niż limit skanu treści (4 MiB) nie jest analizowany regułami treści; raport notuje lukę pokrycia. Reguły ścieżki działają nadal.
- `move_uploaded_file` i `file_put_contents` z danymi żądania jako **treścią** nie mają reguły: tak wygląda każda legalna obsługa uploadu i zapisu ustawień.
- YARA-X jest poza zakresem (osobne Issue); kształt wyniku (identyfikator, wersja, offset, długość) jest przygotowany pod adapter.
- Częstości fałszywych alarmów nie mierzono na rzeczywistym zbiorze wtyczek i motywów; przypadki „fałszywy alarm” w testach to krótkie próbki syntetyczne.
- Reguły ścieżki i treści nie mają limitu liczby ustaleń (limit 200 dotyczy tylko reguł integralności): drzewo z wieloma trafieniami daje tyle ustaleń, ile jest par reguła–plik.
- Reguła logów HTTP (`HTTP_EXECUTABLE_IN_UPLOADS` w `wpincidentlens/cli.py`) zna tylko rozszerzenia `.php`, `.phtml` i `.phar`; żądanie do `.pht`, `.php5` albo `photo.php.jpg` w uploads nie daje ustalenia z logu ani korelacji.
- Integralność: narzędzie nie sprawdza, czy manifest sum rdzenia odpowiada wersji i locale witryny (kandydat WPDetector nie jest z nim porównywany); manifestów wtyczek i motywów nie ma; liczba wpisów baseline nie ma limitu poza rozmiarem pliku (64 MiB), manifest ma limit 50 000 wpisów i 8 MiB.
- WPDetector nie jest parserem PHP: heredoc, tekst poza `<?php … ?>`, `$GLOBALS['wp_version']` i `include` nie są modelowane; `wp-config.php` położony katalog wyżej niż witryna nie jest widziany; kandydaci z plików nie są porównywani z bazą (opcja `WPLANG`, prefiks w zrzucie SQL).

## Reguły bazy danych (`dbrules`, T-301)

Źródło prawdy: `wpincidentlens/dbrules.py`; dane serializowane PHP czyta `wpincidentlens/phpserialize.py`, cytaty redaguje `wpincidentlens/redact.py`. Testy: `tests/test_dbrules.py`, `tests/test_phpserialize.py`, `tests/test_redact.py`. Decyzje: [ADR 0006](adr/0006-analiza-bazy-m3.md), pkt 4–8. Reguły bazy są zapisane w kodzie i nie mają wersji.

### Odczyt zrzutu SQL (`sqldump`)

- Obsługiwana jest wyłącznie instrukcja `INSERT INTO <nazwa> [(<kolumny>)] VALUES (…), (…);` z literałami: łańcuch w apostrofach (ucieczki `\x` i `''` jak w MySQL), `NULL`, liczba, `0x…`, `X'…'`, `_binary '…'`. Nazwy: `[A-Za-z0-9_$]{1,64}`, opcjonalnie w odwrotnych apostrofach. Wielkość liter słów kluczowych dowolna.
- Komentarz wykonywalny (`/*!NNNNN … */`, `/*M!NNNNNN … */`) jest oceniany jak kod: klasyfikuje się instrukcję po jego rozwinięciu. `--` zaczyna komentarz, gdy po nim stoi biały znak albo znak sterujący (jak w lekserze serwera).
- Bez śladu pomijane są tylko, w dokładnej postaci: `SET` jako lista prostych przypisań (literał, nazwa albo zmienna; także `SET NAMES`, `SET CHARACTER SET`), `USE <baza>`, `LOCK TABLES …`, `UNLOCK TABLES`, `START TRANSACTION`, `BEGIN`, `COMMIT`, `DROP TABLE|DATABASE|SCHEMA`, `CREATE DATABASE|SCHEMA`, `ALTER TABLE … DISABLE|ENABLE KEYS`, `CREATE TABLE` z samą listą definicji (bez `SELECT`, `LIKE`, `AS`, `UNION`, `VALUES`, `GENERATED`, `RENAME`, `INSERT_METHOD`, silników `MERGE`/`FEDERATED`/`CONNECT`/`SPIDER`), zwykłe komentarze i puste instrukcje. Każda inna postać (np. `SET STATEMENT … FOR`, `BEGIN NOT ATOMIC`, `ALTER TABLE … RENAME`, `CREATE TABLE … SELECT`) jest luką.
- `CREATE TABLE` podaje kolejność kolumn: `INSERT` bez listy kolumn do tej tabeli dostaje kolumny z jej definicji. Nazwy kolumn nie rozróżniają wielkości liter. Wiersz tabeli rdzenia bez kolumny potrzebnej regułom (`users`: `ID`, `user_login`; `usermeta`: `user_id`, `meta_key`, `meta_value`; `options`: `option_name`, `option_value`) jest luką — serwer wstawiłby tam wartość domyślną z definicji tabeli.
- `SET`, który zmienia sposób czytania łańcuchów (`sql_mode` z `NO_BACKSLASH_ESCAPES`, `ANSI_QUOTES` lub `ANSI`; kodowanie klienta spoza `utf8`, `utf8mb3`, `utf8mb4`, `latin1`, `binary`, `ascii`), zatrzymuje analizę: od tej instrukcji reszta zrzutu nie jest analizowana, luka podaje przesunięcie.
- Luki (`PARTIAL`): każda inna instrukcja (liczona pod pierwszym słowem, np. `UPDATE ×1`); `INSERT` poza gramatyką, `REPLACE`, `DELIMITER`, komentarz wykonywalny z `INSERT`/`REPLACE`, polecenie klienta (`\g`, `\d`); wiersz z wyrażeniem zamiast literału (sam wiersz, reszta instrukcji jest czytana); niedomknięta instrukcja na końcu; wartość spoza UTF-8 (dekodowana ze znakiem zastępczym); instrukcja dłuższa niż 16 MiB — od niej reszta zrzutu nie jest analizowana; tabela o nazwie różniącej się od tabeli rdzenia tylko wielkością liter (np. `WP_USERMETA`), bo na serwerze z `lower_case_table_names=1|2` trafiłaby do tabeli rdzenia. Słów kluczowych w luce jest najwyżej 200 różnych, reszta jako „(inne)”.
- Znane fałszywe luki: `INSERT … ON DUPLICATE KEY UPDATE`, `INSERT IGNORE`, widoki (`/*!50001 CREATE … VIEW */`) i rozszerzenia narzędzi hostingowych są poprawnym SQL, ale wychodzą poza gramatykę. Zrzut z `SET NAMES` w kodowaniu wschodnioazjatyckim jest analizowany tylko do tej instrukcji. Długi łańcuch rozcięty granicą porcji jest skanowany ponownie przy każdej porcji (koszt ograniczony limitem 16 MiB instrukcji; zmierzono 6,6 s dla łańcucha 15 MiB). Luka nie jest ustaleniem, obniża jedynie pokrycie.

### Eksport JSONL (`jsonldb`)

- Wybór operatora: `--database-format jsonl` (domyślnie `sql`). Formatu nie zgaduje się po treści; zrzut SQL podany jako JSONL nie jest parsowany jako SQL, tylko odrzucany wiersz po wierszu. Wybór trafia do `case.json` (`sources.database.format`).
- Kontrakt: jeden obiekt JSON na wiersz pliku, dokładnie dwa klucze: `{"table": "<nazwa>", "row": {"<kolumna>": <wartość>, …}}`. Nazwy: `[A-Za-z0-9_$]{1,64}`. Wartość: łańcuch, liczba (zachowuje zapis tekstowy z pliku) albo `null`; `row` niepusty. Ścisłe UTF-8. Wiersz pusty lub z samych spacji i tabulacji jest pomijany bez śladu; końcowe `\r` jest usuwane; ostatni wiersz bez znaku końca jest czytany. Numer wiersza w położeniu faktu to numer wiersza pliku.
- Rozpoznanie tabel rdzenia, prefiks i reguły są takie same jak dla SQL (niżej); reguły nie wiedzą, z jakiego formatu pochodzi wiersz. Brakująca kolumna (np. `meta_key`) jest traktowana jak pusta wartość: taki wiersz zwykle nic nie wnosi do reguł, a luka nie powstaje.
- Wiersz odrzucony (luka `PARTIAL` z liczbą wierszy per powód i numerem pierwszego): niepoprawny JSON (także BOM, kilka obiektów w wierszu, zagnieżdżenie przekraczające limit rekursji), powtórzony klucz na dowolnym poziomie, wartość logiczna, tablica, obiekt, `NaN`/`Infinity`, łańcuch z samotnym surogatem, niepoprawna nazwa tabeli lub kolumny, inna budowa niż powyżej, niepoprawne UTF-8, wiersz dłuższy niż 16 MiB (pomijany do najbliższego znaku końca wiersza, bez buforowania).
- `FAILED`: żaden wiersz pliku nie spełnia kontraktu albo żaden nie należy do tabel `*_users`, `*_usermeta`, `*_options`.
- Znane fałszywe luki: eksport z wartościami logicznymi lub kolumnami JSON zapisanymi jako zagnieżdżony obiekt (zamiast łańcucha) jest poprawnym JSON, ale wychodzi poza kontrakt. Adapter nie wie, czy eksport objął wszystkie tabele i wiersze — kompletność zależy od narzędzia, które go wykonało.

### Które tabele są analizowane

- Prefiks tabel wynika ze zrzutu. Kandydatem jest każda tabela o nazwie `<prefiks>users`, `<prefiks>usermeta` albo `<prefiks>options` (prefiks dowolny, także bez `_` i pusty).
- Wybór prefiksu: (1) para `users` + `usermeta`, w której `usermeta` ma klucz `<prefiks>capabilities`; (2) w razie braku — sama para; (3) w razie braku pary — dowolna tabela rdzenia (zrzut częściowy). Jeżeli kandydatów w danym kroku jest kilku, wygrywa ten, od którego zaczynają się wszystkie pozostałe (tabele wtyczek nazywają się `<prefiks><wtyczka>_…`). Gdy takiego nie ma, reguły bazy **nie są stosowane do żadnego prefiksu** i powstaje luka.
- Tabela wtyczki kończąca się na `users` lub `options` (np. `wp_myplugin_users`) nie jest tabelą rdzenia: jej wiersze są pomijane bez luki.
- Luki (`PARTIAL`): druga para `users` + `usermeta` o innym prefiksie; układ multisite (`<prefiks>blogs`, `<prefiks>sitemeta`, `<prefiks><n>_options|posts|postmeta`) — analizowana jest tylko witryna główna, super administratorzy (`site_admins`) są poza zakresem; wiersz uprawnień z kluczem `…capabilities` o innym prefiksie niż tabele; więcej niż 50 różnych prefiksów.

### Role

- Administratorem jest konto, którego wartość `<prefiks>capabilities` daje się odczytać jako tablica PHP z **kluczem** `administrator` — niezależnie od wartości. Nazwa roli jako wartość, inna wielkość liter albo dłuższy klucz (`not_administrator`) nie są rolą.
- Wartości, której nie da się odczytać (ucięta, zła długość, obiekt zamiast tablicy, śmieci po wartości, ponad 64 KiB), nie przeszukuje się podłańcuchem: powstaje luka z liczbą kont i najwyżej pięcioma `user_id`.
- Klucz `administrator` z wartością fałszywą (`b:0`, `i:0`, pusty łańcuch, `N`): konto **jest** administratorem. WordPress wyznacza role po kluczach tablicy uprawnień (`WP_User::get_role_caps()`), a wartość fałszywa nie odbiera uprawnień roli; inaczej dałoby się w ten sposób ukryć administratora. Obserwacja dostaje atrybut `role_value: "false"`, wyjaśnienie ustalenia — dodatkowe zdanie, a pokrycie — notę z `user_id` (nie obniża statusu). Fałszywy alarm: wiersz pozostawiony przez wtyczkę, która „wyłącza” rolę wartością `false`.
- `<prefiks>user_level` nie jest źródłem roli; trafia tylko jako atrybut pomocniczy do inwentarza konta, które jest administratorem.

### Ustalenia

| Reguła | Waga | Pewność | Rodzaj obserwacji | Co wykrywa | Fałszywe alarmy |
|---|---|---|---|---|---|
| `UNRECOGNIZED_ADMIN` | high | medium | `ADMINISTRATOR_ACCOUNT` | Administrator spoza listy `--known-admin`, gdy baseline nie ma listy `known_admins` | Niepełna lista operatora; konto założone legalnie |
| `NEW_SINCE_BASELINE` | high | medium | `ADMINISTRATOR_ACCOUNT` | Administrator spoza listy `known_admins` z baseline (i spoza `--known-admin`): konto nowe względem migawki | Nieaktualna migawka; konto założone legalnie po jej wykonaniu |
| `SUSPICIOUS_DB_MARKUP` | medium | low | `OPTION_VALUE_WITH_ACTIVE_MARKUP` (`excerpt`, `value_chars`) | Wartość opcji zawiera `<script`, `<iframe`, `<object`, `<embed`, `<meta … http-equiv=refresh`, atrybut zdarzenia (`on…=`) w znaczniku, schemat `javascript:` (także z tabulacją lub końcem wiersza w środku) albo `data:text/html` | Fragmenty analityki i reklam, osadzone filmy i mapy, `onclick=` w widżetach, proza „JavaScript: …” |

- Jedno ustalenie na konto: `NEW_SINCE_BASELINE`, gdy baseline ma niepustą listę `known_admins`, w przeciwnym razie `UNRECOGNIZED_ADMIN`. Nazwa podana przez `--known-admin` jest zaufana także wtedy, gdy nie ma jej w baseline. Bez żadnej listy nie ma ustalenia — jest inwentarz i nota o braku listy porównawczej. Pusta lista `known_admins` w baseline znaczy „brak listy”.
- Jedno ustalenie `SUSPICIOUS_DB_MARKUP` na wiersz opcji. `excerpt` to najwyżej 200 znaków wokół pierwszego trafienia, po redakcji (niżej). Wartość opcji dłuższa niż 1 MiB znaków nie jest sprawdzana: luka z liczbą takich wartości.
- Najwyżej 200 kont administratorów w raporcie (ustalenia i inwentarz razem); nadmiar to luka z łączną liczbą.
- Raport HTML nie pokazuje atrybutów obserwacji, więc cytat jest tylko w `report.json`.

### Inwentarz (obserwacje bez ustalenia)

Nie wpływa na `assessment`. Samo istnienie administratora albo zadania cron nie jest alertem.

| Rodzaj obserwacji | Atrybuty | Skąd |
|---|---|---|
| `ADMINISTRATOR_ACCOUNT` | `username` (do 200 znaków), `user_id`, `registered` (tylko w postaci `RRRR-MM-DD GG:MM:SS`), `user_level`, `role_value` (`"false"`, tylko gdy klucz roli ma wartość fałszywą) | wiersz `<prefiks>capabilities` i wiersz konta w `<prefiks>users`. Bez adresu e-mail, skrótu hasła i innych danych konta. Login bywa adresem e-mail — trafia wtedy do raportu jako login |
| `CRON_HOOK` | `hook` (do 120 znaków), `next_run` (najbliższy czas uruchomienia, liczba) | opcja `cron`; jedna obserwacja na nazwę zadania, najwyżej 200 w całym przebiegu |
| `ACTIVE_PLUGIN` | `plugin` (do 200 znaków) | opcja `active_plugins`; najwyżej 200 |

Nazwa opcji jest w WordPressie unikalna: do inwentarza trafia **pierwszy** wiersz `cron` i pierwszy wiersz `active_plugins` wybranego prefiksu, a powtórzone wiersze to luka z ich liczbą (reguła `SUSPICIOUS_DB_MARKUP` sprawdza każdy wiersz). Limit 200 dotyczy więc całego przebiegu, nie wiersza. Opcja `cron` albo `active_plugins`, której nie da się odczytać, wpis o nieoczekiwanej postaci i przekroczony limit to luki. Administrator bez wiersza w tabeli użytkowników to luka (bez loginu nie da się go porównać z listą).

### Dane serializowane PHP

- Odczytywane: `N`, `b`, `i`, `d`, `s`, `a`. Obiekty (`O:`), serializacja własna (`C:`), wyliczenia (`E:`) i referencje (`R:`, `r:`) zostają nieprzezroczystym znacznikiem; nazwa klasy jest pomijana i nie trafia do raportu. Nic nie jest odtwarzane ani wykonywane.
- Limity: 1 MiB, głębokość 32, 50 000 elementów. Przekroczenie, błąd składni i dane po wartości to błąd, czyli luka w regule, która wartości potrzebowała.
- Długości łańcuchów są w **bajtach UTF-8** i muszą się zgadzać dokładnie. Zrzut przekodowany z innego zestawu znaków (np. tabela latin1 zrzucona jako UTF-8) ma złe długości łańcuchów ze znakami spoza ASCII: taka wartość jest nieczytelna (luka), długość nie jest zgadywana w znakach. Tablice uprawnień są w praktyce w ASCII.

### Redakcja cytatu (`redact`)

Kolejno: dane logowania w adresie (`://użytkownik:hasło@`), wszystko po `?` w adresie, wartość po nazwie zawierającej `key`, `token`, `password`/`passwd`/`pass`/`pwd`, `secret`, `auth`, `sig`, `nonce`, `session`, `credential`, część lokalna adresu e-mail, ciągi ≥ 16 cyfr szesnastkowych i ciągi ≥ 24 znaków `A-Z a-z 0-9 + _ -` z literą i cyfrą, na końcu znaki sterujące i formatujące (zmiana kierunku pisma, zerowa szerokość) → `U+FFFD`. Nazwa hosta po `://` zostaje — jest wskaźnikiem. Cały tekst jest redagowany przed wycięciem fragmentu.

Redakcja jest zachowawcza (usuwa też `author: …` albo długi identyfikator z cyfrą) i nie jest gwarancją: sekret krótki, bez cyfr i poza rozpoznawalnym parametrem zostaje. Funkcja jest przewidziana także dla adresów z logów (T-501).

### Ograniczenia reguł bazy

- Rola `administrator` to jedyne sprawdzane uprawnienie. Konto z uprawnieniem nadanym wprost (np. `manage_options` w tablicy uprawnień), rola niestandardowa o uprawnieniach administratora i zmieniona definicja ról w opcji `<prefiks>user_roles` nie są wykrywane.
- Multisite: witryny podrzędne i `site_admins` nie są analizowane (luka).
- Loginy porównuje się z listą dokładnie, znak po znaku; podobne znaki z innych alfabetów nie są wykrywane.
- `SUSPICIOUS_DB_MARKUP` dopasowuje tekst, nie HTML: nie widzi znaczników zapisanych encjami (`&#60;script`), kodowaniem base64 ani sklejanych w JavaScripcie; obejmuje tylko tabelę opcji (nie `posts`, `postmeta`, `usermeta`).
- Obecność obiektu serializowanego w wartości opcji nie jest ustaleniem ani obserwacją (WordPress sam zapisuje obiekty, np. w transientach aktualizacji).
- Częstości fałszywych alarmów nie mierzono na rzeczywistych bazach.
