# Reguły plików (FileAnalyzer)

Źródło prawdy: tabela `RULES` w `wpincidentlens/filerules.py` (`RULESET_VERSION = "2026.11.1"`). Test `tests/test_filerules.py` pilnuje, żeby każda reguła z tabeli była tu opisana i miała przypadek pozytywny, negatywny oraz fałszywy alarm wzorowany na legalnym kodzie.

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
