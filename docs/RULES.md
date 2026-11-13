# Reguły plików (FileAnalyzer, IntegrityAdapter) i obserwacje WPDetector

Dokument opisuje trzy rzeczy: reguły ścieżki i treści (`wpincidentlens/filerules.py`), reguły integralności względem zaufanej referencji (`wpincidentlens/integrity.py`) oraz obserwacje WPDetector (`wpincidentlens/wpdetect.py`), które **nie są ustaleniami**. Reguły bazy danych opisuje sekcja „Reguły bazy danych”, logi HTTP — sekcja „Logi HTTP”, korelację — sekcja „Korelacja plik–żądanie”.

Źródło prawdy dla wzorców reguł ścieżki i treści: tabela `RULES` w `wpincidentlens/filerules.py`. Test `tests/test_filerules.py` pilnuje, żeby każda reguła z tabeli była tu opisana i miała przypadek pozytywny, negatywny oraz fałszywy alarm wzorowany na legalnym kodzie.

## Rejestr reguł (`wpincidentlens/rules.py`, ADR 0008 pkt 2)

Jedyny spis wszystkich reguł, z których powstają ustalenia (pliki, integralność, baza, logi HTTP, korelacja): identyfikator, wersja, kategoria, waga (`severity`), dopuszczalne wartości pewności (`confidence`), opis i znane fałszywe alarmy. Reguły plików są przejmowane z `filerules.RULES` bez zmian. Zestaw ma identyfikator `RULESET_ID = "wpincidentlens-poc"`, wersję `RULESET_VERSION = "2026.11.3"` i skrót SHA-256 kanonicznego JSON rejestru (posortowane klucze, bez zbędnych białych znaków); te trzy wartości zapisuje `case.json` w polu `ruleset`.

- Każde ustalenie powstaje w jednej funkcji rejestru (`rules.finding`).
- Kategoria, waga albo pewność spoza deklaracji reguły: ustalenie **zostaje w postaci wyemitowanej** (ocena nie może przez to spaść), a pokrycie źródła reguły (`file` → `files`, `database` → `database`, `http_log` i `correlation` → `logs`) dostaje lukę „Błąd rejestru reguł: ustalenie reguły … ma wartości spoza deklaracji …” i status `PARTIAL` (spec C10: błąd reguły to luka, nie cisza).
- Reguła spoza rejestru to błąd kodu narzędzia, nie danych: analiza przerywa się wyjątkiem (`UnknownRule`), co wychwytują testy i CI.
- Testy (`tests/test_rules.py`): każda reguła emitowana w kodzie jest w rejestrze i odwrotnie; każda stała waga i pewność w kodzie jest zadeklarowana; każda pewność wybierana w czasie analizy ma scenariusz; dwie osobne tabele regresyjne wagi i pewności (spec §9.2); para wersja–skrót jest przypięta; każda reguła rejestru ma wiersz w tabeli „Reguła” tego dokumentu i żaden wiersz nie opisuje reguły spoza rejestru. Każdy raport zapisany w testach nie może mieć luki rejestru reguł.

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
| `CODE_IN_UNEXPECTED_LOCATION` | WP-FILE-005 | 2 | medium | low w `wp-content/languages`, medium w katalogach zasobów core | Plik kodu w `wp-content/languages/` (poza `*.l10n.php`) albo w `wp-includes/{images,css}/`, `wp-admin/{images,css}/` (poza `wp-includes/css/dist/registry.php`, generowanym rejestrem stylów WordPressa 7.x). `wp-includes/fonts/` nie jest sprawdzany: od WordPressa 6.5 są tam klasy biblioteki fontów ([pomiar FP](FP_MEASUREMENT.md)) | Starsze paczki językowe z plikiem `<locale>.php` |

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
- Logika reguł integralności jest w kodzie, a ich wersje, wagi i pewności deklaruje rejestr (`rules.REGISTRY`), objęty `RULESET_VERSION`. `CORE_CHECKSUM_MISMATCH`, `CORE_FILE_NOT_IN_MANIFEST` i `CORE_FILE_MISSING` mają wersję 2 (wstrzymanie przy niezgodnym manifeście); pozostałe — 1.
- Obserwacje niosą opis referencji, jeśli operator go podał: `reference_version` (`wordpress_version` z baseline albo z manifestu), `reference` (wolny opis) i — dla manifestu — `reference_file`.
- Różnica względem referencji **nie przesądza o ataku**: aktualizacja, zmiana administratora albo referencja innej wersji dają ten sam obraz. Zgodność z referencją mówi tylko, że plik jest taki jak w referencji.
- `BASELINE_FILE_MISSING` i `CORE_FILE_MISSING` powstają tylko po pełnym przejściu drzewa. Wpis, który istnieje, ale nie został odczytany (albo leży pod nieodczytanym katalogiem), nie jest zgłaszany jako brakujący.
- Każda reguła integralności daje najwyżej **200 ustaleń** na przebieg (`MAX_FINDINGS_PER_RULE`). Nadmiar nie znika: powstaje luka z nazwą reguły i łączną liczbą wykryć, a pokrycie `files` spada do `PARTIAL`.
- Baseline z więcej niż **200 000** wpisami `files` (`MAX_BASELINE_ENTRIES`, jak domyślny limit liczby plików) nie jest porównywany wcale — obcięty dawałby fałszywe „nowe” i „brakujące” pliki. Powstaje luka „Baseline ma N wpisów files, więcej niż limit …”, pokrycie `files` spada do `PARTIAL`; `known_admins` działa nadal.
- **Zgodność manifestu z witryną (R-46).** Manifest może podać `wordpress_version` (albo wersję jako jedyny klucz `checksums`) i `locale` (np. `"pl_PL"`; api.wordpress.org go nie zwraca — dopisuje je operator, wartość sprawdzana tym samym wzorcem co locale WPDetector). Po przejściu drzewa są porównywane z wersją i locale pakietu według WPDetector: `$wp_version` i `$wp_local_package` z `wp-includes/version.php` (plik przeczytany bez `$wp_local_package` to pakiet `en_US`; język witryny z `WPLANG` i plików `.mo` nie zmienia plików rdzenia i nie jest brany pod uwagę). Wynik:
  - `version.php` o MD5 z manifestu — zgodne bez względu na etykiety (ten sam pakiet);
  - wersja albo locale różne — wykrycia `CORE_CHECKSUM_MISMATCH`, `CORE_FILE_NOT_IN_MANIFEST` i `CORE_FILE_MISSING` są **wstrzymane** i zastępuje je jedna luka `CORE_MANIFEST_MISMATCH: … (wersja manifestu X, witryny Y) … wstrzymane wykrycia: REGUŁA ×N, …`; pokrycie `files` spada do `PARTIAL`, więc przebieg nie kończy się kodem 0 ani oceną „bez wskaźników”. Kandydat z `version.php` mógł zostać zmieniony — luka to mówi; napastnik, który zmieni wersję w tym pliku, ukrywa rozbieżności rdzenia tylko za cenę jawnej luki;
  - brak wersji lub locale po stronie manifestu albo witryny (także kilka różnych kandydatów) — wykrycia zostają, a nota „Zgodność manifestu sum rdzenia z witryną niesprawdzona: …” podaje, czego brakuje (nota nie obniża statusu).

| Reguła | Spec | Waga | Pewność | Rodzaj obserwacji | Co wykrywa | Fałszywe alarmy |
|---|---|---|---|---|---|---|
| `BASELINE_FILE_CHANGED` | — | medium | high | `FILE_DIFFERS_FROM_BASELINE` (`baseline_sha256`) | Odczytany plik ma inny SHA-256 niż wpis w `baseline.files` | Legalna aktualizacja lub zmiana administratora po wykonaniu migawki; baseline innej wersji |
| `BASELINE_FILE_MISSING` | — | low | high | `BASELINE_ENTRY_NOT_IN_FILES` (na dowodzie baseline) | Plik wymieniony w baseline nie występuje w materiale | Plik usunięty legalnie (np. odinstalowana wtyczka); kopia obejmująca tylko część witryny |
| `NEW_FILE_SINCE_BASELINE` | WP-FILE-003 | medium | medium (low, gdy wpisu nie odczytano) | `FILE_NOT_IN_BASELINE` albo `ENTRY_NOT_IN_BASELINE` (`file_class`) | Plik w miejscu ładowanym automatycznie — `wp-content/mu-plugins/` albo drop-in w `wp-content/` (np. `object-cache.php`, `db.php`, `advanced-cache.php`) — którego niepusty baseline nie wymienia; także nieodczytany katalog `wp-content/mu-plugins` | Baseline starszy niż legalna zmiana: mu-plugin hostingu, drop-in wtyczki cache dodany po migawce |
| `CORE_CHECKSUM_MISMATCH` | WP-FILE-002 | medium | high | `FILE_DIFFERS_FROM_CORE_MANIFEST` (`observed_sha256`, `observed_md5`, `reference_md5`) | Odczytany plik ma inny MD5 niż wpis w manifeście sum rdzenia | Manifest innej wersji lub innego locale, gdy manifest albo witryna ich nie wskazuje (przy jawnej niezgodności wykrycia są wstrzymane); poprawka naniesiona przez administratora |
| `CORE_FILE_NOT_IN_MANIFEST` | — | medium | low | `FILE_NOT_IN_CORE_MANIFEST` | Plik kodu lub konfiguracji (rozszerzenie kodu, `.htaccess`, `.user.ini`, `php.ini`) w katalogu głównym, `wp-admin` albo `wp-includes`, którego manifest nie wymienia; także nieodczytany. Nie dotyczy `wp-config.php`, `.htaccess`, `.user.ini` i `php.ini` w katalogu głównym | Manifest innej wersji lub locale; legalne pliki spoza dystrybucji w katalogu głównym (skrypty hostingu, pliki weryfikacyjne, `.htaccess` w `wp-admin`) |
| `CORE_FILE_MISSING` | — | low | high | `CORE_MANIFEST_ENTRY_NOT_IN_FILES` (na dowodzie manifestu, `reference_md5`) | Plik wymieniony w manifeście nie występuje w materiale. Wpisy manifestu pod `wp-content/` (dołączone motywy i wtyczki) nie dają ustalenia, tylko jedną notę z liczbą | Manifest innej wersji; plik rdzenia usunięty celowo przez administratora |
| `REFERENCE_FILE_UNREADABLE` | — | medium | low | `REFERENCE_ENTRY_NOT_READ` (`listed_in`, `listed_as`) | Wpis, który referencja wymienia jako plik albo jako katalog swoich plików, istnieje, ale nie został odczytany: dowiązanie symboliczne, dodatkowe dowiązanie twarde, brak uprawnień, plik specjalny, limit rozmiaru. Wyjaśnienie nazywa status odczytu | Kopie z deduplikacją przez dowiązania twarde (wtedy `--allow-hardlinks`); materiał skopiowany bez uprawnień do odczytu. Sam brak odczytu nie dowodzi zmiany pliku |

Czego reguły integralności **nie** zgłaszają jako ustalenia:

- Plik bez wpisu w żadnej referencji poza miejscami z tabeli (np. nowy plik we wtyczce, motywie albo uploads). Gdy podano referencję, zostaje nota `NO_TRUSTED_REFERENCE` z liczbą takich odczytanych plików i najwyżej trzema przykładami (nazwy cytowane jak łańcuchy JSON); niezależnie od tego plik jest liczony w `NOT_CHECKED` (niżej).
- Katalog pominięty przez limit operatora (głębokość, liczba wpisów) i pliki, do których przerwane przejście nie dotarło: to luka pokrycia, nie ustalenie.

### Brak referencji: `NOT_CHECKED`

Plik, którego nie porównano z żadną referencją, jest liczony w powodzie `NOT_CHECKED: integralność plików klasy <KLASA> (plików: N, w tym kodu: K) niezweryfikowana — brak zaufanej referencji` (klasy z `wpincidentlens/fileclass.py`: `CORE`, `CONFIG`, `DROPIN`, `MU_PLUGIN`, `PLUGIN`, `THEME`, `UPLOAD`, `LANGUAGE`, `OTHER`; klasa wynika z położenia pliku i nie jest dowodem pochodzenia). Powód powstaje dla klas `CORE`, `PLUGIN`, `THEME`, `MU_PLUGIN` i `DROPIN` zawsze, a dla pozostałych wtedy, gdy wśród niezweryfikowanych jest plik kodu; liczba obejmuje też wpisy nieodczytane. Jeżeli wśród takich plików jest choć jeden plik kodu (rozszerzenie kodu, `.htaccess`, `.user.ini`, `php.ini`; odczytany albo nie), pokrycie `files` ma status `PARTIAL`: `scope_complete` jest fałszem, przebieg bez ustaleń daje `INCONCLUSIVE`, a kod wyjścia to 3 (ADR 0005 pkt 6). Pliki niebędące kodem (obrazy, CSS, JS) bez referencji zostają notą, która statusu nie obniża. Reguła jest taka sama z referencją i bez niej, więc analiza bez baseline i bez manifestu nigdy nie kończy się kodem 0, jeśli w drzewie jest plik kodu.

## Obserwacje WPDetector (nie ustalenia)

Źródło prawdy: `wpincidentlens/wpdetect.py`; testy: `tests/test_wpdetect.py`. WPDetector zapisuje w `observations` **kandydatów**: wartości odczytane z plików, które napastnik mógł zmienić. Z kandydata nie powstaje ustalenie. Jedynym miejscem, w którym kandydat wpływa na wynik, jest sprawdzenie zgodności manifestu sum rdzenia (sekcja „Reguły integralności”): jednoznaczna wersja i locale pakietu różne od manifestu zamieniają wykrycia `CORE_*` w lukę pokrycia. Manifest nie jest na podstawie kandydata wybierany.

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
- Fałszywe alarmy zmierzono na korpusie 21 publicznych pakietów z wordpress.org (rdzeń, 15 wtyczek, 5 motywów; [FP_MEASUREMENT.md](FP_MEASUREMENT.md)). Korpus nie obejmuje wtyczek komercyjnych, pakowanych (ionCube) ani uploads; przypadki „fałszywy alarm” w testach to krótkie próbki syntetyczne.
- Reguły ścieżki i treści mają ten sam limit **200 ustaleń** na regułę w przebiegu co reguły integralności (`filerules.MAX_FINDINGS_PER_RULE`); nadmiar to luka z łączną liczbą wykryć i status `PARTIAL`, a ustalenia dostają pierwsze pliki w kolejności przejścia drzewa.
- Reguła logów HTTP (`HTTP_EXECUTABLE_IN_UPLOADS`) korzysta z tych samych rozszerzeń kodu i podwójnych rozszerzeń w uploads co reguły plików; opis i ograniczenia: sekcja „Logi HTTP”.
- Integralność: zgodność manifestu sum rdzenia z witryną opiera się na kandydacie z `version.php`, który mógł zostać zmieniony, i na etykietach podanych przez operatora (bez nich zostaje nota); manifestów wtyczek i motywów nie ma; baseline ma limit 200 000 wpisów i 64 MiB, manifest — 50 000 wpisów i 8 MiB.
- WPDetector nie jest parserem PHP: heredoc, tekst poza `<?php … ?>`, `$GLOBALS['wp_version']` i `include` nie są modelowane; `wp-config.php` położony katalog wyżej niż witryna nie jest widziany; kandydaci z plików nie są porównywani z bazą (opcja `WPLANG`, prefiks w zrzucie SQL).

## Reguły bazy danych (`dbrules`, T-301)

Źródło prawdy: `wpincidentlens/dbrules.py`; dane serializowane PHP czyta `wpincidentlens/phpserialize.py`, cytaty redaguje `wpincidentlens/redact.py`. Testy: `tests/test_dbrules.py`, `tests/test_phpserialize.py`, `tests/test_redact.py`. Decyzje: [ADR 0006](adr/0006-analiza-bazy-m3.md), pkt 4–8. Reguły bazy są zapisane w kodzie i nie mają wersji.

### Odczyt zrzutu SQL (`sqldump`)

- Obsługiwana jest wyłącznie instrukcja `INSERT INTO <nazwa> [(<kolumny>)] VALUES (…), (…);` z literałami: łańcuch w apostrofach (ucieczki `\x` i `''` jak w MySQL), `NULL`, liczba, `0x…`, `X'…'`, `_binary '…'`. Nazwy: `[A-Za-z0-9_$]{1,64}`, opcjonalnie w odwrotnych apostrofach. Wielkość liter słów kluczowych dowolna.
- Komentarz wykonywalny (`/*!NNNNN … */`, `/*M!NNNNNN … */`) jest oceniany jak kod: klasyfikuje się instrukcję po jego rozwinięciu. `--` zaczyna komentarz, gdy po nim stoi biały znak albo znak sterujący (jak w lekserze serwera).
- Bez śladu pomijane są tylko, w dokładnej postaci: `SET` jako lista prostych przypisań (literał, nazwa albo zmienna; także `SET NAMES`, `SET CHARACTER SET`), `USE <baza>`, `LOCK TABLES …`, `UNLOCK TABLES`, `START TRANSACTION`, `BEGIN`, `COMMIT`, `DROP TABLE|DATABASE|SCHEMA`, `CREATE DATABASE|SCHEMA`, `ALTER TABLE … DISABLE|ENABLE KEYS`, `CREATE TABLE` z samą listą definicji (bez `SELECT`, `LIKE`, `AS`, `UNION`, `VALUES`, `GENERATED`, `RENAME`, `INSERT_METHOD`) i po niej wyłącznie znanymi opcjami tabeli (`ENGINE` InnoDB/MyISAM/Aria/MEMORY, kodowanie, `COLLATE`, `AUTO_INCREMENT`, `ROW_FORMAT`, `COMMENT` i podobne; bez `PARTITION`, `TABLE`, innych silników) — sprawdzane po usunięciu komentarzy, zwykłe komentarze i puste instrukcje. Każda inna postać (np. `SET STATEMENT … FOR`, `BEGIN NOT ATOMIC`, `ALTER TABLE … RENAME`, `CREATE TABLE … SELECT`) jest luką.
- `CREATE TABLE` podaje kolejność kolumn: `INSERT` bez listy kolumn do tej tabeli dostaje kolumny z jej definicji. Nazwy kolumn nie rozróżniają wielkości liter. Wiersz tabeli rdzenia bez kolumny potrzebnej regułom (`users`: `ID`, `user_login`; `usermeta`: `user_id`, `meta_key`, `meta_value`; `options`: `option_name`, `option_value`) jest luką — serwer wstawiłby tam wartość domyślną z definicji tabeli.
- `SET`, który zmienia sposób czytania łańcuchów (`sql_mode` z `NO_BACKSLASH_ESCAPES`, `ANSI_QUOTES` lub `ANSI`; kodowanie klienta spoza `utf8`, `utf8mb3`, `utf8mb4`, `latin1`, `binary`, `ascii`), zatrzymuje analizę: od tej instrukcji reszta zrzutu nie jest analizowana, luka podaje przesunięcie. Wartość `sql_mode` i kodowania musi być znana: łańcuch (także sklejony z kilku), nazwa, kopia zmiennej systemowej (`@@…`) albo zmienna użytkownika przypisana wcześniej w zrzucie; liczba (maska bitowa), zapis szesnastkowy i nieznana zmienna też zatrzymują analizę. Kopia `@@x` ma wartość ustawioną wcześniej w zrzucie albo pierwotną wartość sesji. Po każdej nierozpoznanej instrukcji lub wierszu z wyrażeniem wartości zmiennych są nieznane, a nierozpoznany `SET` dotyczący `sql_mode` albo kodowania zatrzymuje analizę. Przekroczenie limitu 5000 nazw tabel lub definicji to luka. Definicja tabeli w innej wielkości liter (`CREATE TABLE WP_USERMETA`) ustala kolejność kolumn dla `INSERT` do `wp_usermeta` i daje lukę.
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

## Logi HTTP (`httplog`, `logformats`, T-401)

Źródło prawdy: `wpincidentlens/logformats.py` (parsery wiersza, ścieżka, adres klienta) i `wpincidentlens/httplog.py` (odczyt, pokrycie, reguła); decyzja: [ADR 0007](adr/0007-logi-i-korelacja-m4.md), pkt 1–7; testy: `tests/test_logformats.py`, `tests/test_httplog.py`.

### Formaty (`--log-format`, domyślnie `combined`)

Format wybiera operator; parser nie zgaduje go po treści. Identyfikator z wersją trafia do atrybutu `log_format` obserwacji, a wybór — do `case.json` (`sources.logs.format`).

| Format | Układ wiersza |
|---|---|
| `combined@1` | `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"` (Apache i Nginx `combined`) |
| `common@1` | `%h %l %u %t "%r" %>s %b` |
| `json@1` | jeden obiekt JSON na wiersz (kontrakt niżej) |

- Pola rozdziela jedna spacja. `%t` to `[dd/Mon/rrrr:gg:mm:ss ±hhmm]` z angielską nazwą miesiąca (niezależnie od locale procesu). `%r` to `METODA cel HTTP/x.y` albo `METODA cel` (HTTP/0.9); metoda to token RFC 7230 (1–32 znaki: litery, cyfry, grawis i `!#$%&'*+.^_|~-`, np. `GET_X`, `M-SEARCH`, `get`: serwer przekazuje do PHP każdą taką metodę), cel bez białych znaków. W polach w cudzysłowie `\"` jest częścią pola. Ucieczki, którymi Apache i Nginx zapisują w `%r` bajty spoza ASCII drukowalnego (`\xNN`, `\"`, `\\`, `\n`, `\t` …), są odwracane na bajtach przed dekodowaniem `%XX` (`sh\xc3\xa9ll.php` → `shéll.php`); nieznana ucieczka zostaje dosłownie. W `json@1` ucieczki odwraca już dekoder JSON. Status: trzy cyfry 100–599; `%b`: liczba bajtów albo `-` (`bytes: null`).
- `%h` to adres połączenia: IP (zapisywany w postaci kanonicznej, np. `2001:db8::1`) albo nazwa hosta (`HostnameLookups`).
- Pola po polach formatu (po spacji) są ignorowane i nie trafiają do raportu — także `X-Forwarded-For` dopisany w konfiguracji serwera. Dlatego `common` przyjmuje też wiersz `combined`.
- Czas nie do sprowadzenia do UTC (brak strefy, strefa niemożliwa, zły zapis) nie odrzuca wiersza: obserwacja ma `timestamp_raw`, `timestamp_utc: null`, a pokrycie notę „Nie można znormalizować czasu logu do UTC w N wierszach” z pierwszym zapisem.

### Kontrakt `json@1`

Jeden obiekt JSON na wiersz pliku, ścisłe UTF-8:

| Pole | Wymagane | Typ |
|---|---|---|
| `time` | tak | łańcuch ISO 8601 `RRRR-MM-DDTgg:mm:ss[.ułamek][Z lub ±gg:mm]`; bez przesunięcia strefy → `timestamp_utc: null` (jak wyżej); precyzja z liczby cyfr ułamka (`second`, `millisecond`, `microsecond`) |
| `remote_addr` | tak | łańcuch: adres połączenia (IP bez portu albo nazwa hosta) |
| `method` | tak | łańcuch: token RFC 7230, 1–32 znaki |
| `uri` | tak | łańcuch: cel żądania bez białych znaków |
| `status` | tak | liczba całkowita 100–599 (nie `true`, nie `200.0`, nie `"200"`) |
| `bytes` | nie | liczba całkowita ≥ 0 albo `null` |
| `forwarded_for` | nie | łańcuch (`X-Forwarded-For`) albo `null`; używany tylko przez zaufane proxy (niżej) |

Inne pola są dozwolone i ignorowane, o ile mają wartość prostą (łańcuch, liczba, wartość logiczna, `null`). Przykład konfiguracji Nginx: `log_format wpil escape=json '{"time":"$time_iso8601","remote_addr":"$remote_addr","method":"$request_method","uri":"$request_uri","status":$status,"bytes":$body_bytes_sent,"forwarded_for":"$http_x_forwarded_for"}';`.

### Odczyt i powody odrzucenia

- Każdy plik źródła `logs` jest czytany strumieniowo w tym samym odczycie, który liczy SHA-256 (`ingest.Session.read(..., sink_factory=...)`); rozmiar ogranicza tylko `--max-file-bytes`. Znak końca wiersza to `\n`, końcowe `\r` jest usuwane, wiersz pusty (spacje, tabulacje) nie jest liczony, ostatni wiersz bez znaku końca jest czytany.
- Wiersz odrzucony jest liczony pod powodem z numerem pierwszego wystąpienia (`plik:wiersz`): dłuższy niż 64 KiB (pomijany do najbliższego `\n` bez buforowania), układ pól inny niż w formacie, wiersz żądania inny niż `METODA cel [HTTP/x.y]`, adres klienta niebędący IP ani nazwą hosta, status lub liczba bajtów poza zakresem; dla `json@1` także niepoprawny JSON (BOM, dwa obiekty), powtórzony klucz, brak wymaganego pola albo pole złego typu, wartość złożona (obiekt, tablica), `NaN`/`Infinity`, samotny surogat.
- Wiersz spoza UTF-8 jest dekodowany ze znakami zastępczymi i **analizowany** (wskaźnik nie znika), ale liczony osobno: luka `PARTIAL` „N wierszy logów nie jest poprawnym UTF-8” z pierwszym miejscem.

### Pokrycie `logs`

- `FAILED`: źródło bez żadnego odczytanego pliku (pusty katalog, same dowiązania lub pliki pominięte limitem); żaden wiersz nie został sparsowany („Logi nie odpowiadają obsługiwanemu formatowi …”); pliki bez żadnego wiersza.
- `PARTIAL`: odrzucone wiersze — luka „Nie sparsowano X/Y wierszy logów (Z%, format …)” z liczbą per powód, pierwszym miejscem i najwyżej 20 plikami `nazwa (odrzucone/wiersze)`; plik bez żadnego sparsowanego wiersza obok plików poprawnych; stratne dekodowanie; żądanie, którego ścieżki nie da się przypisać do pliku (niżej), a którego zdekodowany cel zawiera rozszerzenie kodu (`.php`, `.phtml` …) — luka z liczbą i pierwszym miejscem; ponad 1000 wykryć reguły `HTTP_EXECUTABLE_IN_UPLOADS` w przebiegu (`MAX_RULE_FINDINGS`; luka z łączną liczbą trafień); ponad 50 000 żądań trzymanych dla korelacji albo 32 Mi znaków ich ścieżek, `uri` i czasu (`MAX_REQUESTS`, `MAX_HELD_CHARS`; nadmiar nie jest sprawdzany korelacją, reguła działa niezależnie od tego limitu); limit czasu analizy (`--max-seconds`) przekroczony w trakcie pliku — luka „Limit czasu analizy … plik X przeanalizowany do wiersza N”. Trzymane są tylko pola obserwacji z `uri` już po redakcji, nie pełny wiersz.
- Limit czasu sesji jest sprawdzany co 256 wierszy (`CLOCK_EVERY_LINES`). Po jego przekroczeniu reszta pliku nie jest parsowana, ale odczyt i SHA-256 pliku idą do końca (skrót zawsze obejmuje cały plik, a odczyt jest ograniczony `--max-file-bytes`); kolejne pliki są pomijane przez SecureIngest z luką `MAX_SECONDS`.
- Noty (bez obniżenia statusu): czas bez UTC, żądania ze ścieżką nieprzypisywalną do pliku, której cel nie wskazuje pliku kodu, ścieżki z bajtami spoza UTF-8 po dekodowaniu (zapisane ze znakiem zastępczym; korelacja z plikiem o takiej nazwie nie jest możliwa), odrzucony `forwarded_for` za zaufanym proxy.

### Ścieżka żądania i atrybuty obserwacji

- Ścieżka (`path`): cel bez schematu i hosta (forma absolutna), bez query i fragmentu; ucieczki logu odwrócone (formaty tekstowe, wyżej); `%XX` dekodowane **raz** na bajtach (UTF-8 ze znakami zastępczymi; `%252e` zostaje `%2e`); `//` scalane; segmenty `.` i `..` rozwiązywane tak, jak robi to serwer przed odwzorowaniem na plik (`/uploads/x/%2e%2e/a.php` → `uploads/a.php`). Nie jest przypisywana do pliku ścieżka wychodząca `..` ponad katalog główny, z bajtem NUL (`%00`), z zakodowanym ukośnikiem `%2F` (Apache domyślnie odpowiada na nie 404, `AllowEncodedSlashes Off`), dłuższa niż 4096 znaków albo cel inny niż ścieżka (np. `*`); gdy zdekodowany cel zawiera rozszerzenie kodu, to luka obniżająca pokrycie, w przeciwnym razie nota z liczbą. Inne znaki sterujące i formatujące (`%09`, `%0a`, NBSP `%C2%A0`, zmiana kierunku pisma `%E2%80%AE`, znaki zerowej szerokości) **nie** wyłączają ścieżki: reguły widzą ścieżkę zdekodowaną, a atrybut `path` przechodzi przez `redact.neutralise` (znaki sterujące i formatujące → U+FFFD, tabulacja → spacja), więc nie zniekształci raportu. Pisownia ścieżki zostaje oryginalna. Pierwszy segment z rozszerzeniem kodu (albo z podwójnym rozszerzeniem w uploads) wyznacza plik, reszta to `PATH_INFO` (jedno przejście po segmentach, czas liniowy względem długości ścieżki): `/uploads/x.php/a.jpg` → `uploads/x.php`, `/index.php/2026/wpis` → `index.php`. Prefiks `wp-content/uploads/` jest porównywany bez względu na wielkość liter (`/WP-CONTENT/UPLOADS/a.php` trafia w regułę, atrybut `path` ma pisownię z logu).
- `uri`: cel żądania, w którym query i fragment są usuwane w całości od pierwszego `?` albo `#` (→ `?[usunięto]`, `#[usunięto]`), a nie wzorcem redakcji, który zatrzymuje się na cudzysłowie, `<` albo `\\`; w formie absolutnej (`http://u:p@host/…`) wszystko od `://` do ostatniego `@` przed `?` albo `#` zastępuje strukturalnie `[usunięto]` — także hasło z `/`, przy którym granica `authority` według RFC wypada wcześniej (PR #50); `@` w samej ścieżce też zostanie wtedy zamaskowany; część przed query przechodzi przez `redact` (niżej), najwyżej 300 znaków.
- Obserwacje żądań (`HTTP_REQUEST`, materiał korelacji) powstają tylko dla ścieżek z rozszerzeniem kodu (`filerules.CODE_SUFFIXES`) i z podwójnym rozszerzeniem w uploads, i tylko dla tych, których korelacja może użyć (`correlate.Focus`, wyznaczany z ustaleń plikowych przed analizą logów): ścieżka równa ścieżce pliku kodu z ustaleniem (`SAME_PATH`) albo czas UTC w oknie `mtime` ± (`--correlation-window` + niepewność zegara) pliku z ustaleniem (`NEAR_IN_TIME`). Zalew żądań do innych ścieżek kodu (404, `wp-login.php`, `xmlrpc.php`) nie wyczerpuje więc limitu żądań. Atrybuty: `path`, `uri`, `method`, `status`, `bytes`, `client_ip`, `client_ip_basis`, `log_format`, `timestamp_precision`, `clock_uncertainty_seconds` (z `--log-clock-skew`, zaokrąglone w górę do pełnych sekund; bez flagi `null`). Do raportu trafiają tylko te, na które wskazuje ustalenie.

### Adres klienta i zaufane proxy (`--trusted-proxy CIDR`, S-14)

- `client_ip` to adres połączenia (`client_ip_basis: connection`). Formaty `combined@1` i `common@1` nie niosą `X-Forwarded-For`.
- Dla `json@1` pole `forwarded_for` jest brane pod uwagę tylko wtedy, gdy adres połączenia należy do sieci z `--trusted-proxy` (powtarzalna, najwyżej 64; adres IPv4 zapisany w IPv6 jest porównywany jako IPv4; nazwa hosta nigdy nie jest zaufana). Klientem jest wtedy ostatni od prawej adres spoza zaufanych sieci, a gdy cały łańcuch jest zaufany — pierwszy od lewej (`forwarded_for_via_trusted_proxy`). Wpisy na lewo od klienta (dopisane przez klienta) są pomijane. Nagłówek dłuższy niż 2048 znaków albo z niepoprawnym wpisem (port, strefa `%eth0`, pusty, tekst) napotkanym przed klientem jest odrzucany w całości, nie skracany (prawy koniec dopisują zaufane proxy, więc ucięcie mogłoby zostawić adres podstawiony przez klienta): klientem jest adres połączenia z `client_ip_basis: connection_forwarded_for_rejected`, a pokrycie dostaje notę z liczbą. Niepoprawna sieć w fladze to błąd wywołania (kod 2); sieć szersza niż `/8` (IPv4) albo `/32` (IPv6) też (kod 2), bo czyniłaby zaufanymi wpisy `forwarded_for` dopisane przez samego klienta.

### Reguła

| Reguła | Waga | Pewność | Rodzaj obserwacji | Co wykrywa | Fałszywe alarmy |
|---|---|---|---|---|---|
| `HTTP_EXECUTABLE_IN_UPLOADS` | high | medium; low dla podwójnego rozszerzenia | `HTTP_REQUEST_FOR_PHP_IN_UPLOADS` (atrybuty jak `HTTP_REQUEST`) | Żądanie dowolną metodą do pliku w `wp-content/uploads/` z rozszerzeniem kodu (`.php`, `.phtml`, `.phar`, `.inc`, `.pht`, `.php3`–`.php8`, bez względu na wielkość liter) albo z podwójnym rozszerzeniem (`shell.php.jpg`) | Skanery i boty proszące o nieistniejące pliki (status 404 też daje ustalenie: żądanie nie dowodzi istnienia ani wykonania pliku); wtyczki trzymające skrypty w uploads; podwójne rozszerzenie wykonuje się tylko przy konfiguracji serwera przekazującej je do PHP |

- Reguła jest sprawdzana przy parsowaniu każdego wiersza, niezależnie od puli żądań korelacji i jej limitu; ma własny limit 1000 wykryć w przebiegu (nadmiar = luka z łączną liczbą trafień).
- Brak ustalenia (test negatywny dla każdego przypadku): kod poza uploads, obraz w uploads, podwójne rozszerzenie bez części kodu (`photo.jpg.bak`), ścieżka uploads tylko w query (`/index.php?file=…/shell.php`), `..` ponad katalog główny, `%00`, katalog o podobnej nazwie (`uploadsX`). Cel z `..` ponad katalogiem głównym albo z `%00`, który zawiera rozszerzenie kodu, obniża pokrycie (wyżej).
- Status HTTP 200 nie jest dowodem wykonania kodu; reguła nie ocenia statusu.

### Ograniczenia logów

- Znane fałszywe luki: formaty z innym układem (np. `vhost_combined`, dodatkowe pole przed `%h`, separator tabulacji), `%u` ze spacją, wiersz żądania ze spacją w celu i logi z `HostnameLookups` z nazwami spoza `[A-Za-z0-9.-]` są odrzucane wiersz po wierszu. Format IIS/W3C, logi PHP-FPM i logi błędów nie są obsługiwane.
- Znane fałszywe alarmy ścieżki: katalog o nazwie z rozszerzeniem kodu (`/uploads/stary.php/obraz.jpg`) jest traktowany jak plik z `PATH_INFO`.
- Znane fałszywe negatywy: witryna w podkatalogu URL (`/blog/wp-content/uploads/x.php`) nie jest rozpoznawana — reguła i korelacja porównują ścieżkę od korzenia URL z prefiksem `wp-content/uploads/` i ze ścieżką względną do `--files`, a narzędzie nie zna podkatalogu instalacji; rozszerzenia skonfigurowane jako PHP spoza `CODE_SUFFIXES` (np. `.html` przez `AddHandler`) nie są brane pod uwagę.
- Czas: zegar serwera nie jest weryfikowany; `--log-clock-skew` to deklaracja operatora. Limit czasu analizy (`--max-seconds`) przerywa parsowanie także w trakcie jednego pliku (co 256 wierszy), ale nie odczyt i skrót tego pliku.
- Fuzz parsera to deterministyczne mutacje syntetycznego pliku (stałe ziarno), bez generatora gramatyki. Częstości fałszywych alarmów nie mierzono na rzeczywistych logach.

## Korelacja plik–żądanie (`correlate`, T-401)

Źródło prawdy: `wpincidentlens/correlate.py`; decyzja: ADR 0007 pkt 8; testy: `tests/test_correlate.py`. Korelacja łączy ustalenie plikowe (plik z obrazu witryny, nie wpis referencji) z żądaniami z logu HTTP. Relacje ze specyfikacji §8.3 są identyfikatorami reguł; kategoria ustaleń to `correlation`.

| Reguła | Relacja | Waga | Pewność | Kiedy | Fałszywe alarmy |
|---|---|---|---|---|---|
| `CORRELATED_UPLOAD_REQUEST` | `SAME_PATH` | high | medium | Plik z `EXECUTABLE_IN_UPLOADS` i wykrycie `HTTP_EXECUTABLE_IN_UPLOADS` o tej samej ścieżce (znormalizowany atrybut `path` po `redact.neutralise`; URI bez query tylko dla wykrycia bez `path`) — reguła sprzed ADR 0007 | Legalny skrypt w uploads wywoływany przez wtyczkę; skaner odpytujący ścieżki z listy |
| `CORRELATED_FILE_REQUEST` | `SAME_PATH` | medium | low | Obserwacja `HTTP_REQUEST` z atrybutem `path` równym ścieżce pliku kodu (rozszerzenie z `CODE_SUFFIXES` albo podwójne rozszerzenie w uploads), który ma ustalenie plikowe. Nie powstaje, gdy tę ścieżkę objęła już `CORRELATED_UPLOAD_REQUEST` | Zwykły ruch do zmienionego pliku wtyczki lub motywu (legalna aktualizacja daje `BASELINE_FILE_CHANGED`); skanery i boty odpytujące znane ścieżki; przepisywanie URL kierujące żądanie do innego pliku |
| `REQUEST_NEAR_FILE_CHANGE` | `NEAR_IN_TIME` | medium | low | Żądanie `HTTP_REQUEST` do dowolnego pliku kodu w oknie ±`--correlation-window` s (domyślnie 900, granica włącznie) od `mtime` pliku z ustaleniem. Okno żądania poszerza jego `clock_uncertainty_seconds` (nieujemna liczba całkowita z deklaracji operatora; inna wartość jest pomijana). Tylko gdy znane są oba czasy: `timestamp_utc` żądania i `mtime_ns` pliku | Każdy ruch w czasie wdrożenia, aktualizacji albo odtwarzania kopii; `mtime` ustawiony przez `touch`, rozpakowanie archiwum lub kopię bez zachowania czasów; przesunięty zegar serwera |

- **Czego korelacja nigdy nie twierdzi:** przyczynowości, sukcesu zapisu, wykonania kodu ani tego, że plik istniał w chwili żądania. Status HTTP 200 nie jest dowodem. Nie ma relacji `PROVEN_EXPLOIT`. Ustalenie korelacyjne nie podnosi pewności ustalenia plikowego. Pewność `low` (poza regułą uploads) wynika z tego, że relacja opiera się na zgodności łańcucha ścieżki albo na zmienialnym `mtime`.
- **Waga `medium`:** relacja wskazuje trop (możliwy wektor zapisu lub wywołania pliku) do sprawdzenia przez analityka; sama nie jest szkodliwym faktem, a szkodliwość pliku opisuje jego własne ustalenie.
- **Agregacja (spec §9.3):** jedno ustalenie na parę (plik, reguła). Wskazuje wszystkie obserwacje ustaleń plikowych tego pliku i najwyżej 20 żądań (`MAX_REQUESTS_PER_FINDING`): dla `SAME_PATH` najwcześniejsze, dla `NEAR_IN_TIME` najbliższe `mtime`. Wyjaśnienie podaje łączną liczbę żądań, zakres ich czasu (UTC) i okno; nie zawiera tekstu z materiału dowodowego (ścieżki są w obserwacjach).
- **Limit:** najwyżej 200 ustaleń na regułę korelacyjną (`MAX_FINDINGS_PER_RULE`, w kolejności ścieżek plików); nadmiar to luka „Limit … wyczerpany: wykryć było N” i pokrycie `logs` = `PARTIAL`.
- **Oś czasu:** każde żądanie wskazane przez ustalenie korelacyjne, które ma czas UTC, jest zdarzeniem `HTTP_REQUEST` (`time_source=log`) z podstawą „HTTP access log; niepewność zegara ±N s (deklaracja operatora, niezweryfikowana)” albo „HTTP access log; zegar niezweryfikowany, niepewność niezadeklarowana”. `mtime` pliku z ustaleniem zostaje zdarzeniem `SUSPICIOUS_FILE_MTIME` z podstawą „zmienialny”. Zdarzenia są uporządkowane po czasie, remisy deterministycznie. Czasu z bazy danych na osi nie ma (ADR 0007 pkt 9).
- **Ograniczenia:** porównanie ścieżek jest dokładne (wielkość liter ma znaczenie) po `redact.neutralise` obu stron (nazwy ze znakami sterującymi lub zmianą kierunku pisma spotykają się w postaci z U+FFFD; dwie różne takie nazwy mogą dać tę samą postać), a ścieżka pliku jest względna do korzenia `--files`, więc witryna w podkatalogu URL albo multisite nie jest dopasowywana. Parser logów trzyma dla korelacji tylko żądania pasujące do `Focus` (ścieżki plików kodu z ustaleniem i okna czasu wokół ich `mtime`), wyznaczonego z ustaleń plików i bazy przed analizą logów. `CORRELATED_FILE_REQUEST` i `REQUEST_NEAR_FILE_CHANGE` wymagają obserwacji `HTTP_REQUEST` z parsera logów (ADR 0007 pkt 7); bez nich powstaje tylko `CORRELATED_UPLOAD_REQUEST`. Wiersz logu, który jest i wykryciem `HTTP_EXECUTABLE_IN_UPLOADS`, i żądaniem wskazanym przez korelację, ma na osi czasu jedno zdarzenie (`HTTP_EXECUTABLE_IN_UPLOADS`). Okno korelacji nie jest zapisywane w `case.json`, tylko w wyjaśnieniu `REQUEST_NEAR_FILE_CHANGE`.
