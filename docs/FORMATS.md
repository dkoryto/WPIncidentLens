# WPIncidentLens — formaty wejścia i wyjścia (M7, T-701)

Zwięzły przewodnik po tym, co narzędzie przyjmuje i co zapisuje. Szczegóły reguł i wszystkie powody odrzucenia są w [RULES.md](RULES.md); kontrakt raportu w [ADR 0003](adr/0003-schemat-poc-1-i-migracja.md) i [docs/schema/](schema/). Każdy format wybiera operator flagą — **narzędzie nie zgaduje formatu po treści**.

## Wejścia

Każde wejście jest nieufnym materiałem dowodowym (poza referencjami, których treść jest deklaracją operatora) i jest czytane wyłącznie przez SecureIngest. Ścieżka podana w wywołaniu nie może być dowiązaniem symbolicznym (kod 2).

### Drzewo plików witryny (`--files`, wymagane)

Katalog z kopią instalacji WordPressa (katalog główny witryny: `wp-admin/`, `wp-includes/`, `wp-content/` …). Ścieżki w raporcie są względne do tego katalogu, z przedrostkiem źródła w `logical_path` (np. `files/wp-content/uploads/a.php`).

- Czytane są tylko zwykłe pliki i katalogi. Dowiązania symboliczne, pliki specjalne i pliki z `st_nlink > 1` (bez `--allow-hardlinks`) trafiają do `evidence` ze statusem `SKIPPED_SYMLINK`, `SKIPPED_SPECIAL`, `SKIPPED_HARDLINK` i obniżają pokrycie.
- Każdy przeczytany plik ma SHA-256 i rozmiar; reguły treści dostają pliki kodu i konfiguracji (rozszerzenia kodu, `.htaccess`, `.user.ini`, `php.ini`, podwójne rozszerzenie w uploads) do 4 MiB. Większe pliki są haszowane, ale nie skanowane (luka).
- Limity: `--max-files`, `--max-entries`, `--max-file-bytes`, `--max-total-bytes`, `--max-depth`, `--max-path-bytes`, `--max-seconds` (wartości domyślne w README i w `--help`).

### Zrzut bazy (`--database`, `--database-format {sql,jsonl}`, domyślnie `sql`)

Pojedynczy plik. Analizowane są tylko tabele `<prefiks>users`, `<prefiks>usermeta` i `<prefiks>options` witryny głównej; prefiks wynika ze zrzutu (szczegóły wyboru: RULES.md, „Które tabele są analizowane”).

**SQL — obsługiwany podzbiór gramatyki** (`wpincidentlens/sqldump.py`, ADR 0006):

- `INSERT INTO <nazwa> [(<kolumny>)] VALUES (…), (…);` z literałami: łańcuch w apostrofach (ucieczki jak w MySQL), `NULL`, liczba, `0x…`, `X'…'`, `_binary '…'`. Nazwy `[A-Za-z0-9_$]{1,64}`, opcjonalnie w odwrotnych apostrofach; wielkość liter słów kluczowych dowolna.
- Pomijane jawnie (bez luki), tylko w dokładnej postaci: proste `SET` (także `SET NAMES`), `USE`, `LOCK TABLES`/`UNLOCK TABLES`, `START TRANSACTION`/`BEGIN`/`COMMIT`, `DROP TABLE|DATABASE|SCHEMA`, `CREATE DATABASE|SCHEMA`, `ALTER TABLE … DISABLE|ENABLE KEYS`, `CREATE TABLE` z samą listą definicji i znanymi opcjami tabeli, komentarze. `CREATE TABLE` podaje kolejność kolumn dla `INSERT` bez listy kolumn.
- Komentarz wykonywalny (`/*!NNNNN … */`) jest oceniany jak kod. `SET` zmieniający sposób czytania łańcuchów (`sql_mode` z `NO_BACKSLASH_ESCAPES`/`ANSI_QUOTES`/`ANSI`, kodowanie klienta spoza obsługiwanych) zatrzymuje analizę reszty zrzutu (luka).
- Wszystko inne (`UPDATE`, `REPLACE`, `DELIMITER`, procedury, wyzwalacze, `INSERT … ON DUPLICATE KEY UPDATE`, wiersz z wyrażeniem, instrukcja ponad 16 MiB) to luka i status `PARTIAL`. SQL nigdy nie jest wykonywany.

**JSONL — kontrakt** (`wpincidentlens/jsonldb.py`): jeden obiekt na wiersz pliku, dokładnie dwa klucze.

```json
{"table": "wp_users", "row": {"ID": 1, "user_login": "admin"}}
```

- Nazwy tabel i kolumn `[A-Za-z0-9_$]{1,64}`; wartości tylko łańcuch, liczba albo `null`; `row` niepusty; ścisłe UTF-8.
- Odrzucany wiersz po wierszu (luka z liczbą per powód): niepoprawny JSON (także BOM), powtórzony klucz, wartość logiczna, tablica, obiekt, `NaN`/`Infinity`, inna budowa, wiersz ponad 16 MiB. Żaden poprawny wiersz albo żaden wiersz tabel rdzenia → `FAILED`.

### Logi HTTP (`--logs`, `--log-format {combined,common,json}`, domyślnie `combined`)

Plik albo katalog plików logu dostępu, czytany strumieniowo (rozmiar ogranicza `--max-file-bytes`, wiersz do 64 KiB). Identyfikator formatu z wersją trafia do atrybutu `log_format` obserwacji.

| `--log-format` | Identyfikator | Układ wiersza |
|---|---|---|
| `combined` | `combined@1` | `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"` (Apache i Nginx) |
| `common` | `common@1` | `%h %l %u %t "%r" %>s %b` |
| `json` | `json@1` | jeden obiekt JSON na wiersz (niżej) |

Kontrakt `json@1`: wymagane `time` (ISO 8601; bez strefy → `timestamp_utc: null`), `remote_addr`, `method` (token RFC 7230), `uri` (bez białych znaków), `status` (liczba całkowita 100–599); opcjonalne `bytes` (liczba ≥ 0 albo `null`) i `forwarded_for` (łańcuch albo `null`). Inne pola o wartości prostej są ignorowane.

- `--trusted-proxy CIDR` (powtarzalna, najwyżej 64): tylko dla połączeń z tych sieci klientem jest adres z `forwarded_for` (tylko `json@1`). Sieć szersza niż `/8` (IPv4) albo `/32` (IPv6) to błąd wywołania.
- `--log-clock-skew SECONDS`: deklarowana niepewność zegara serwera logów (nieujemna); trafia do atrybutu `clock_uncertainty_seconds` i poszerza okno korelacji. Bez flagi zegar jest niezweryfikowany.
- Wiersze w innym układzie są odrzucane i liczone pod powodem; nieobsługiwane: `vhost_combined`, IIS/W3C, logi błędów, PHP-FPM.

### Baseline (`--baseline`, zaufany JSON operatora)

```json
{"files": {"wp-content/plugins/x/x.php": "<sha256>"}, "known_admins": ["admin"],
 "wordpress_version": "6.5.2", "reference": "migawka z dnia wdrożenia"}
```

- `files`: ścieżki względne do `--files` (ukośniki `/`, bez `..`, do 1024 znaków) → SHA-256 (64 małe cyfry szesnastkowe). Ponad 200 000 wpisów: porównanie nie jest wykonywane (luka).
- `known_admins`: lista zaufanych loginów; niepusta przełącza regułę administratora na `NEW_SINCE_BASELINE`.
- `wordpress_version` (1–32 znaki) i `reference` (do 120 znaków drukowalnych): opcjonalny opis referencji, cytowany w obserwacjach.
- Plik do 64 MiB; powtórzony klucz JSON, zła ścieżka lub skrót, plik nieczytelny → kod 2.

### Manifest sum rdzenia (`--core-checksums`, lokalny plik JSON)

Kształt `api.wordpress.org/core/checksums/1.0`, pobrany wcześniej przez operatora — narzędzie niczego nie pobiera:

```json
{"checksums": {"wp-admin/about.php": "<md5>", "wp-includes/version.php": "<md5>"},
 "wordpress_version": "6.5.2", "locale": "pl_PL", "reference": "pakiet pl_PL 6.5.2"}
```

- Dozwolony też wariant zagnieżdżony `{"checksums": {"6.5.2": {ścieżka: md5}}}` — jedyny klucz musi wyglądać jak numer wersji i zgadzać się z `wordpress_version`, jeśli je podano.
- `locale` (np. `pl_PL`, `de_DE_formal`) dopisuje operator — api.wordpress.org go nie zwraca. Wersja i locale manifestu są porównywane z `$wp_version` i `$wp_local_package` z `wp-includes/version.php` witryny; niezgodność wstrzymuje rozbieżności `CORE_*` i daje jedno ustalenie `CORE_MANIFEST_MISMATCH`.
- 1–50 000 wpisów, plik do 8 MiB, MD5 jako 32 małe cyfry szesnastkowe; nazwa pliku inna niż nazwa pliku `--baseline` (oba są dowodami `baseline/<nazwa>`). MD5 służy tylko do porównania; skrótem dowodu jest SHA-256.

### Pakiet reguł YARA (`--yara-rules PATH`, opcjonalnie)

Plik `*.yar`/`*.yara` albo katalog takich plików (także w podkatalogach) z opcjonalnym plikiem `VERSION` (jeden wiersz, `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}`). Limity: 256 plików, 1 MiB na plik, 8 MiB razem, bez dowiązań; dyrektywa `include` jest wyłączona. Meta `confidence` reguły (`low` albo `medium`) ustala pewność ustalenia `YARA_MATCH`. `--yara-timeout SECONDS` (domyślnie 10, najwyżej 3600) to limit skanu jednego pliku. Pakiet nie może leżeć w źródle dowodów (kod 2); błąd kompilacji to kod 2.

## Wyjścia

`--output` dostaje dziewięć plików, każdy z uprawnieniami `0600`. `report.json` jest źródłem prawdy; pozostałe pliki JSON i `observations.jsonl` to jego widoki (`wpincidentlens/outputs.py`), bez nowych faktów.

| Plik | `schema_version` | Zawartość |
|---|---|---|
| `report.json` | `poc-1` | pełny raport ([schemat](schema/report-poc-1.schema.json)) |
| `report.html` | — | ten sam raport do czytania: ocena, ustalenia, pokrycie, oś czasu, luki; bez atrybutów obserwacji; CSP bez skryptów |
| `evidence-manifest.json` | `evidence-manifest-poc-1` | `case_id`, `evidence` |
| `observations.jsonl` | — (bez nagłówka) | jedna obserwacja na wiersz, w kolejności raportu, wyłącznie ASCII |
| `findings.json` | `findings-poc-1` | `case_id`, `findings` |
| `timeline.json` | `timeline-poc-1` | `case_id`, `timeline` |
| `coverage.json` | `coverage-poc-1` | `case_id`, `assessment`, `scope_complete`, `coverage`, `coverage_gaps` |
| `run.log` | — | wiersze JSON (ASCII) o stałych kluczach (niżej) |
| `case.json` | `case-poc-1` | opis sprawy i przebiegu ([schemat](schema/case-poc-1.schema.json)) |

### `report.json` (`poc-1`)

Pola najwyższego poziomu: `schema_version`, `tool`, `tool_version`, `case_id`, `analyzed_at_utc`, `analyzed_at_time_source` (`tool_clock`), `assessment`, `scope_complete`, `disclaimer`, `findings`, `observations`, `evidence`, `coverage`, `coverage_gaps`, `timeline`; w raporcie przeniesionym z 0.1.0 także `migrated_from`.

| Część | Pola elementu |
|---|---|
| `evidence[]` | `id` (`ev_…`), `origin_kind` (`file`, `sql_dump`, `log`, `baseline`), `logical_path`, `read_status` (`READ`, `SKIPPED_SYMLINK`, `SKIPPED_HARDLINK`, `SKIPPED_SPECIAL`, `SKIPPED_LIMIT`, `ERROR`, `CHANGED`), `read_reason`, `sha256`, `size_bytes`, `mtime_ns`, `hardlinked` |
| `observations[]` | `id` (`obs_…`), `evidence_id`, `kind` (np. `PHP_FILE_IN_UPLOADS`, `HTTP_REQUEST`, `ADMINISTRATOR_ACCOUNT`), `location` (ścieżka, wiersz logu albo tabela), `attributes` (bez dopasowanej treści; reguły treści: `rule_version`, `offset`, `length`, `match_count`), `timestamp_raw`, `timestamp_utc`, `time_source` |
| `findings[]` | `id` (`fnd_…`), `rule_id` (z `rules.REGISTRY`), `category` (`file`, `database`, `http_log`, `correlation`), `severity` (`low`…`critical`), `confidence` (`low`…`high`), `reason`, `observations` (identyfikatory) |
| `coverage` | dla `files`, `database`, `logs`, `baseline`: `status` (`ANALYZED`, `PARTIAL`, `NOT_PROVIDED`, `FAILED`), `entries` (licznik wpisów per `read_status`), `reasons` |
| `coverage_gaps[]` | wszystkie powody ograniczenia analizy jako teksty, alfabetycznie |
| `timeline[]` | `time_utc`, `time_source` (`log`, `mtime`), `timestamp_basis`, `event`, `source`, `confidence`, `evidence_id`, `observation_id` |

Identyfikatory są skrótami treści (ADR 0003 §2), porządek zapisu stały (§3); `validate_report` (`wpincidentlens/models.py`) odrzuca raport niespójny. Znaczenie `assessment`, `severity`, `confidence` i statusów pokrycia: [ANALYST_GUIDE.md](ANALYST_GUIDE.md).

### `case.json` (`case-poc-1`)

Pola wymagane: `schema_version`, `case_id`, `operator_id` (pseudonim albo `null`), `tool`, `tool_version`, `created_at_utc`, `analysis_finished_at_utc`, `sources`, `limits`, `flags`, `report` (`file`, `sha256`), `assessment`, `exit_code`.

- `sources`: dla `files`, `database`, `logs`, `baseline` — `provided` i `name` (tylko ostatni składnik ścieżki, bez ścieżek hosta); podana baza ma `format`; podane logi mają `format`, `trusted_proxies`, `clock_skew_seconds`. Opcjonalnie `core_checksums` (gdy podano `--core-checksums`).
- `limits`: `max_files`, `max_entries`, `max_file_bytes`, `max_total_bytes`, `max_scan_bytes`, `max_path_bytes`, `max_depth`, `max_seconds`.
- `flags`: `allow_hardlinks`, `reverify`, opcjonalnie `pseudonymize`.

Pola opcjonalne w schemacie (narzędzie zapisuje je zawsze, gdy mają zastosowanie; starszy `case.json` ich nie ma): `ruleset` (`id`, `version`, `sha256` rejestru reguł), `outputs` (SHA-256 każdego innego zapisanego pliku po nazwie) i `yara` (tylko z `--yara-rules`: `provided`, `name`, `applied`, `pack_sha256`, `pack_version`, `engine`, `rules`, `file_timeout_seconds`). `case.json` jest zapisywany jako ostatni: plik, którego SHA-256 nie zgadza się z `outputs`, pochodzi z przerwanego albo wcześniejszego zapisu.

### `run.log`

Wiersze JSON w ASCII o stałej liście kluczy (`outputs.RUN_KEYS`, `outputs.COVERAGE_KEYS`), bez treści dowodów, nazw plików i tekstów swobodnych:

- pierwszy wiersz: `event` (`run`), `tool`, `tool_version`, `case_id`, `analyzed_at_utc`, `assessment`, `scope_complete`, `exit_code`, `findings`, `observations`, `evidence`, `coverage_gaps` (cztery ostatnie to liczniki);
- potem po jednym wierszu na źródło: `event` (`coverage`), `source`, `status`, `entries`.

## Wersjonowanie i migracja

- Narzędzie zapisuje wyłącznie najnowszą wersję: `report.json` w `poc-1`, `case.json` w `case-poc-1`, widoki z sufiksem `-poc-1`.
- `poc-1` jest zamknięty (ADR 0003 §10): zmiana, po której poprawny raport przestaje przechodzić walidację albo zmienia się znaczenie pola, wymaga `poc-2` z nowym plikiem schematu, funkcją migracji, testem kompatybilności i ADR. Nowe pola `case.json` dodaje się jako opcjonalne (ADR 0008 pkt 1). Nowy `rule_id` czy rodzaj obserwacji nie zmienia wersji schematu; zmianę rejestru reguł oznacza `RULESET_VERSION` i skrót w `case.json` (`ruleset`).
- Raport 0.1.0 przenosi czysta funkcja `wpincidentlens.migrate.migrate_0_1_0(report: dict) -> dict` (bez wejścia w CLI). Pokrycie i statusy odczytu, których stary raport nie niósł, dostają `UNKNOWN_LEGACY`; ustalenia opierają się na obserwacjach `LEGACY_FINDING`; ocena przechodzi ostrożnie: `INDICATORS_FOUND` → `SUSPICIOUS`, `NO_INDICATORS_IN_ANALYZED_SCOPE` → `INCONCLUSIVE`. Wynik ma `migrated_from: "0.1.0"`; wejście niespójne → `MigrationError`. Test: `tests/test_migrate.py`.

## Kody wyjścia

Kod opisuje **pełność analizy, nie wynik** (`cli.exit_code`, ADR 0003 §7). Ocenę podaje `assessment`.

| Kod | Kiedy |
|---|---|
| `0` | `scope_complete`: `files`, `database`, `logs` mają `ANALYZED`, `baseline` — `ANALYZED` albo `NOT_PROVIDED` |
| `3` | każda inna niepełność: źródło `PARTIAL`, brak `--database` lub `--logs`, plik kodu bez zaufanej referencji (`NOT_CHECKED`), pominięty lub zmieniony wpis, limit, manifest innej wersji lub locale |
| `4` | co najmniej jedno **podane** źródło ma `FAILED` (np. logi w innym formacie, pusty katalog, zrzut bez tabel rdzenia) |
| `2` | błąd wywołania (`argparse`), przed analizą |
| `1` | nieobsłużony wyjątek Pythona (kod `5` ze specyfikacji nie jest wdrożony) |

`SUSPICIOUS` może mieć kod 0, 3 albo 4; `INCONCLUSIVE` nigdy nie ma kodu 0.
