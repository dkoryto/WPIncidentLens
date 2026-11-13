# Pomiar fałszywych alarmów reguł plików (T-203, #36)

Data pomiaru: **2026-11-13**. Zestaw reguł przed poprawką: `RULESET_VERSION = "2026.11.2"`, po poprawce: `"2026.11.4"`.

Cel: sprawdzić, ile trafień dają reguły ścieżki i treści (`wpincidentlens/filerules.py`) na **legalnym, publicznym** kodzie WordPressa, i poprawić reguły wyraźnie hałaśliwe bez utraty przypadków pozytywnych z `tests/test_filerules.py`. Pomiar nie zawiera danych z incydentów ani kodu z witryn klientów. Kod z korpusu **nie jest częścią repozytorium**: archiwa pobrano i rozpakowano poza nim (katalog roboczy poza Gitem) i niczego z nich nie wykonano.

## Korpus

Źródła: `https://wordpress.org/latest.zip` (rdzeń), `https://downloads.wordpress.org/plugin/<slug>.latest-stable.zip` (wtyczki), `https://downloads.wordpress.org/theme/<slug>.zip` (motywy). Wersje odczytano z nagłówka `Version:` głównego pliku wtyczki lub `style.css`, a gdy go brakowało — z `Stable tag:` w `readme.txt`; wersję rdzenia z `$wp_version` w `wp-includes/version.php` (odczyt tekstu, bez wykonywania).

| Pakiet | Wersja | Plików razem | Plików pod regułami treści |
|---|---|---:|---:|
| WordPress (rdzeń) | 7.1.4 | 3782 | 1513 |
| akismet | 5.7.2 | 47 | 30 |
| all-in-one-wp-migration | 7.113 | 219 | 171 |
| classic-editor | 1.7.0 | 6 | 1 |
| contact-form-7 | 6.2.5 | 218 | 171 |
| duplicate-post | 4.7 | 63 | 51 |
| elementor | 4.4.0 | 3701 | 2262 |
| jetpack | 16.4 | 4296 | 2365 |
| litespeed-cache | 7.9.3 | 321 | 213 |
| really-simple-ssl | 9.8.4 | 746 | 425 |
| updraftplus | 1.26.14 | 1601 | 1203 |
| woocommerce | 11.3.0 | 5452 | 3658 |
| wordfence | 9.1.1 | 638 | 483 |
| wordpress-seo (Yoast SEO) | 28.8 | 1949 | 1676 |
| wp-super-cache | 3.1.5 | 92 | 47 |
| wpforms-lite | 2.0.4 | 4888 | 4127 |
| astra (motyw) | 4.14.3 | 755 | 490 |
| generatepress (motyw) | 3.6.1 | 144 | 77 |
| kadence (motyw) | 1.6.0 | 648 | 373 |
| oceanwp (motyw) | 4.2.8 | 690 | 238 |
| twentytwentyfive (motyw) | 1.5 | 235 | 99 |
| **Razem** | | **30 491** | **19 673** |

„Pod regułami treści” to pliki, dla których `filerules.wants_content` jest prawdą (rozszerzenie kodu, `.htaccess`, `.user.ini`, `php.ini`). Żaden z nich nie przekroczył limitu skanu treści 4 MiB.

## Metoda

1. Każde archiwum rozpakowano do własnego, nowego katalogu; wpisy z `..`, ścieżką bezwzględną, ukośnikiem wstecznym albo typem dowiązania symbolicznego byłyby pominięte (nie wystąpiły).
2. Ścieżki ułożono tak, jak w witrynie: rdzeń w katalogu głównym, wtyczki w `wp-content/plugins/<slug>/`, motywy w `wp-content/themes/<slug>/` — od tego zależą reguły ścieżki i obniżanie pewności w kodzie wtyczek i motywów.
3. Dla każdego pliku wywołano `filerules.path_rules`, a dla plików pod regułami treści także `filerules.content_rules` na bajtach pliku (te same funkcje, które woła `files.scan_files`). Liczono pliki z trafieniem, osobno dla każdej reguły i pakietu.
4. Rdzeń sprawdzono też pełnym przebiegiem `python -m wpincidentlens --files <rdzeń> --core-checksums <manifest>` z manifestem z `https://api.wordpress.org/core/checksums/1.0/?version=<wersja>&locale=en_US`, uzupełnionym o pola `wordpress_version` i `locale`.

## Wyniki: reguły ścieżki i treści

| Reguła | Trafienia przed (2026.11.2) | Trafienia po (2026.11.4) | Gdzie |
|---|---:|---:|---|
| `EXECUTABLE_IN_UPLOADS` | 0 | 0 | — (korpus nie ma uploads) |
| `DOUBLE_EXTENSION_IN_UPLOADS` | 0 | 0 | — (jw.) |
| `CODE_IN_UNEXPECTED_LOCATION` | **6** | 0 | rdzeń 7.1.4 |
| `SUSPICIOUS_PHP_EVAL_DECODE` | 0 | 0 | — |
| `REQUEST_TO_COMMAND_EXEC` | 0 | 0 | — |
| `REQUEST_TO_CODE_EVAL` | 0 | 0 | — |
| `REQUEST_VARIABLE_FUNCTION_CALL` | 0 | 0 | — |
| `PHP_PREG_REPLACE_EVAL` | 0 | 0 | — |
| `LONG_ENCODED_BLOB` | 1 | 1 | updraftplus (pewność `low`) |
| `REQUEST_INPUT_TO_INCLUDE` | 0 | 0 | — |
| `REQUEST_CONTROLLED_FILE_WRITE` | 0 | 0 | — |
| `HTACCESS_ENABLES_PHP_IN_UPLOADS` | 0 | 0 | — (korpus nie ma uploads) |
| `PHP_AUTO_PREPEND_CONFIG` | 0 | 0 | — |

Przykłady trafień (tylko ścieżki):

- `CODE_IN_UNEXPECTED_LOCATION` (pewność `medium`): `wp-includes/fonts/class-wp-font-collection.php`, `wp-includes/fonts/class-wp-font-face-resolver.php`, `wp-includes/fonts/class-wp-font-face.php`, `wp-includes/fonts/class-wp-font-library.php`, `wp-includes/fonts/class-wp-font-utils.php`, `wp-includes/css/dist/registry.php`.
- `LONG_ENCODED_BLOB` (pewność `low`): `wp-content/plugins/updraftplus/vendor/symfony/polyfill-intl-normalizer/Normalizer.php` — łańcuch 128 sekwencji `\x..` będący tablicą znaków w polyfillu Symfony.

### Poprawka: `CODE_IN_UNEXPECTED_LOCATION` (wersja 1 → 2)

Wszystkie 6 trafień to pliki **dystrybucji WordPressa**, więc na każdej aktualnej instalacji reguła dawała 6 fałszywych ustaleń o pewności `medium`:

- `wp-includes/fonts/` od WordPressa 6.5 zawiera klasy PHP biblioteki fontów, więc katalog usunięto z `filerules.STATIC_CORE_DIRS`;
- `wp-includes/css/dist/registry.php` to generowany rejestr stylów (WordPress 7.x). Dodano go do `filerules.CORE_CODE_IN_STATIC_DIRS` jako dokładną ścieżkę; reszta `wp-includes/css/` jest sprawdzana jak dotąd.

Plik podrzucony pod tą nazwą albo do `wp-includes/fonts/` nadal wykrywa porównanie z manifestem sum rdzenia (`CORE_CHECKSUM_MISMATCH`, `CORE_FILE_NOT_IN_MANIFEST`) i z baseline. Testy: nowe przypadki `fp-core-font-library`, `fp-core-style-registry` i `code-in-core-css` w `tests/test_filerules.py`; przypadki pozytywne (`code-in-core-images`, `code-in-languages`) bez zmian.

### Bez zmiany: `LONG_ENCODED_BLOB`

Jedno trafienie na 19 673 pliki, w kodzie wtyczki, więc z pewnością `low`. Odróżnienie tablicy znaków od zakodowanego ładunku wymagałoby dekodowania i oceny treści, co wykracza poza heurystykę tekstową; opis fałszywych alarmów reguły („tablice kryptograficzne, zminifikowane zasoby”) obejmuje ten przypadek.

### Limit ustaleń na regułę

Żadna reguła nie zbliżyła się do limitu 200 ustaleń na przebieg (`filerules.MAX_FINDINGS_PER_RULE`): największa liczba trafień jednej reguły w całym korpusie to 6.

## Wyniki: manifest sum rdzenia (rdzeń 7.1.4)

| Manifest | Przed (2026.11.2) | Po (2026.11.4) |
|---|---|---|
| 7.1.4, `en_US` | 0 ustaleń | 0 ustaleń, bez noty o zgodności (MD5 `version.php` zgodne z manifestem) |
| 7.1.3, `en_US` | 49 ustaleń `CORE_CHECKSUM_MISMATCH` | 1 ustalenie i jedna luka `CORE_MANIFEST_MISMATCH` (wersja manifestu 7.1.3, witryny 7.1.4; wstrzymane wykrycia: `CORE_CHECKSUM_MISMATCH ×49`), pokrycie `files` `PARTIAL`, ocena `SUSPICIOUS` |

Liczba „przed” to liczba wykryć wstrzymanych po poprawce; każde z nich było skutkiem złego manifestu, nie zmiany plików.

## Ograniczenia pomiaru

- Korpus to wyłącznie pakiety z katalogu wordpress.org, które przechodzą przegląd zespołu wtyczek. Wtyczki komercyjne, pakowane (ionCube, SourceGuardian), starsze wersje i kod pisany pod konkretną witrynę mogą dawać więcej trafień — zwłaszcza `LONG_ENCODED_BLOB`, `SUSPICIOUS_PHP_EVAL_DECODE` i `PHP_PREG_REPLACE_EVAL`.
- Korpus nie ma katalogu `wp-content/uploads/` ani konfiguracji hostingu, więc reguły uploads i `.htaccess` w uploads nie zostały tu zmierzone.
- 0 trafień oznacza brak fałszywych alarmów na tym korpusie, nie skuteczność wykrywania: czułość reguł sprawdzają przypadki pozytywne w testach, nie ten pomiar.
- Pomiar wywołuje funkcje reguł bezpośrednio, poza `session.read`; limity SecureIngest (rozmiar, liczba plików, czas) nie miały tu wpływu, bo żaden plik nie przekroczył limitu skanu treści.

## Jak powtórzyć

1. Pobrać archiwa z adresów z sekcji „Korpus” do katalogu poza repozytorium; każde rozpakować do własnego nowego katalogu, bez dowiązań i ścieżek z `..`.
2. Dla każdego pliku zbudować `ingest.Evidence("files", <ścieżka w witrynie>, ingest.ReadStatus.READ, sha256=..., size=..., content=<bajty, gdy filerules.wants_content>)` i policzyć wyniki `filerules.path_rules` oraz `filerules.content_rules` według `Detection.rule`. Skrypt uruchamiać z `python -I` i spoza katalogu korpusu.
3. Dla rdzenia: `python -m wpincidentlens --files <rdzeń> --core-checksums <manifest z wordpress_version i locale> --output <katalog poza korpusem>`.
