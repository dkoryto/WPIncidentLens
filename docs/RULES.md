# Reguły plików (FileAnalyzer, IntegrityAdapter) i obserwacje WPDetector

Dokument opisuje trzy rzeczy: reguły ścieżki i treści (`wpincidentlens/filerules.py`), reguły integralności względem zaufanej referencji (`wpincidentlens/integrity.py`) oraz obserwacje WPDetector (`wpincidentlens/wpdetect.py`), które **nie są ustaleniami**. Reguły bazy danych i logów (`wpincidentlens/cli.py`) nie są tu opisane.

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
