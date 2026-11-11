# Macierz testów P1–P6, N1–N8, S-01–S-18 (T-003)

Stan na 2026-11-11, gałąź `agent/T-003-test-matrix` (na bazie `agent/T-001-baseline-ci`). Źródło scenariuszy: `docs/WPTrace_Specyfikacja_Senior_PoC_2026-11-09.md`, rozdz. 14.1–14.3. Kod `wptrace/` **nie został zmieniony** — macierz mierzy obecny PoC, niczego nie naprawia. Wiersze oznaczone „T-101” zaktualizowano na gałęzi `agent/T-101-secure-ingest`, na której odczyt dowodów przeniesiono do `wptrace/ingest.py` (#4).

Macierz nie jest dowodem bezpieczeństwa ani skuteczności detekcji. `PASS` znaczy tylko: opisane zachowanie zaobserwowano w uruchomionym teście na danych syntetycznych.

## Jak czytać

- **PASS** — test uruchomiony i zielony.
- **XFAIL (#N)** — test uruchomiony, potwierdza znaną lukę; oznaczony `xfail(strict=True)` z numerem Issue. Po naprawie test da XPASS i wymusi zdjęcie znacznika.
- **NOT COVERED** — brak testu; podany powód.
- Numery Issue: #4 = T-101 SecureIngest/odczyt, #5 = T-102 kontrakty i schemat raportu, #6 = T-201 analiza plików, #7 = T-301 SQL, #3 = luka bez własnego Issue (logi, raport HTML, reguły) — kandydat na nowe Issue.
- Skróty plików: `pos` = `tests/test_scenarios_positive.py`, `neg` = `tests/test_negative.py`, `sec` = `tests/test_security_inputs.py`, `inv` = `tests/test_invariants.py`, `cli` = `tests/test_cli.py`, `ing` = `tests/test_ingest.py` (T-101), `mod` = `tests/test_models.py`, `con` = `tests/test_contract.py`, `mig` = `tests/test_migrate.py` (T-102).
- Od T-102 (#5) raport ma schemat `poc-1` (ADR 0003). Kolumna „Dowód w raporcie” w tabelach P/N/S używa nazw widoku testowego `Run` z `tests/conftest.py` (`source`, `metadata`, `gaps`, `manifest`), który składa ustalenie z jego obserwacją i dowodem; nazwy pól w pliku opisuje ADR 0003.

## Wyniki uruchomienia (2026-11-11)

| Komenda | Środowisko | Wynik |
|---|---|---|
| `python -m pytest -q` | macOS (Darwin 27.0.0, arm64), Python 3.12.11, pytest 8.4.2 | **79 passed, 1 skipped, 30 xfailed** |
| `python -m pytest -q` | Linux, kontener `python:3.12-slim` (obraz `docker-wptrace`), użytkownik 65532, kopia repozytorium | **79 passed, 31 xfailed** |
| `python -m ruff check .` | macOS | brak zgłoszeń |
| `python -m pytest -q --cov=wptrace --cov-report=term-missing` | macOS, pytest-cov 6.3.0, coverage 7.17.2 | **93%** (tabela niżej) |

Jedyny `skip` (macOS): `sec::test_s05_non_utf8_filename_does_not_break_the_report` — APFS odrzuca nazwy plików spoza UTF-8, więc scenariusza nie da się tam zbudować. Na Linuksie ten sam test wykonuje się i jest XFAIL (#5). CI (`ubuntu-24.04`) nie było uruchamiane w ramach tego zadania.

Aktualizacja po naprawie ReDoS (#11), macOS: `python -m pytest -q` → **89 passed, 1 skipped, 29 xfailed**. Pozostałe wyniki w tej sekcji pochodzą z T-003 i nie były mierzone ponownie.

Aktualizacja po T-101 (#4, gałąź `agent/T-101-secure-ingest`, 2026-11-11) — odczyt dowodów przeniesiony do `wptrace/ingest.py`:

| Komenda | Środowisko | Wynik |
|---|---|---|
| `python -m pytest -q` | macOS (Darwin 27.0.0, arm64), Python 3.12.11, pytest 8.4.2 | **270 passed, 2 skipped, 20 xfailed** |
| `python -m pytest -q -p no:cacheprovider` | Linux, kontener `python:3.12-slim` (Python 3.12.14) z `pytest`/`pytest-cov`/`ruff`, `--network none`, użytkownik 65532, kopia repozytorium w `/tmp` | **263 passed, 1 skipped, 20 xfailed** |
| `python -m ruff check .` | macOS i Linux (jw.) | brak zgłoszeń |
| `python -m pytest -q --cov=wptrace` | macOS | **96%** (`cli.py` 97%, `ingest.py` 95%) |

Pominięcia po T-101: macOS — dwa testy nazw spoza UTF-8 (APFS ich nie tworzy; na Linuksie oba się wykonują i przechodzą); Linux — test kolizji `--output` zapisanego inną wielkością liter (system plików rozróżnia wielkość liter; na macOS się wykonuje). CI (`ubuntu-24.04`) nie było uruchamiane w ramach T-101. Tabela pokrycia poniżej pochodzi z T-003.

Aktualizacja po T-102 (#5, gałąź `agent/T-102-contracts`, 2026-11-11) — raport `poc-1`, stan `INCONCLUSIVE`, migracja z 0.1.0:

| Komenda | Środowisko | Wynik |
|---|---|---|
| `python -m pytest -q` | macOS (Darwin 27.0.0, arm64), Python 3.12.11, pytest 8.4.2, jsonschema 4.26.0 | **565 passed, 2 skipped, 15 xfailed** |
| `python -m pytest -q -p no:cacheprovider` | Linux, kontener `python:3.12-slim` (Python 3.12.14) z `pytest`/`pytest-cov`/`ruff`/`jsonschema`, `--network none`, użytkownik 65532, kopia repozytorium w `/tmp` | **566 passed, 1 skipped, 15 xfailed** |
| `python -m ruff check .` | macOS i Linux (jw.) | brak zgłoszeń |
| `python -m pytest -q --cov=wptrace` | macOS | **98% (`cli.py` 96%, `ingest.py` 98%, `migrate.py` 99%, `models.py` 100%)** |

Pominięcia po T-102 są te same co po T-101 (macOS: dwa testy nazw spoza UTF-8; Linux: kolizja `--output` zapisanego inną wielkością liter). Każdy raport zapisany w testach przez `conftest.analyze` przechodzi `validate_report` i walidację JSON Schema. CI (`ubuntu-24.04`) nie było uruchamiane w ramach T-102.

Zestaw T-003 liczył 110 testów: 6 istniejących (`tests/test_cli.py`) i 104 nowe.

### Pokrycie kodu

```
Name                  Stmts   Miss  Cover   Missing
---------------------------------------------------
wptrace/__init__.py       1      0   100%
wptrace/__main__.py       2      2     0%   1-2
wptrace/cli.py          310     21    93%   48-50, 56-58, 74-76, 93-95, 207-208, 211, 215, 224, 230-233, 386
---------------------------------------------------
TOTAL                   313     23    93%
```

Pokrycie liniowe mierzy wykonanie, nie poprawność: 31 testów XFAIL wykonuje kod, który zachowuje się źle. Niepokryte: obsługa `OSError` przy odczycie katalogu/pliku (48–50, 56–58, 74–76, 93–95), limit 100000 wierszy INSERT (207–208), gałęzie krótkich wierszy bez listy kolumn (211, 215, 224, 230–233), uruchomienie przez `python -m wptrace` (`__main__.py`, 386). Nie ustawiono progu `fail-under`.

## Scenariusze pozytywne P1–P6

| ID | Wymaganie | Oczekiwany status / zachowanie | Dowód w raporcie | Test | Stan |
|---|---|---|---|---|---|
| P1 | PHP w uploadach + odwołanie w access logu | finding pliku, finding logu i korelacja z opisem ograniczeń | `EXECUTABLE_IN_UPLOADS`, `HTTP_EXECUTABLE_IN_UPLOADS`, `CORRELATED_UPLOAD_REQUEST`; wyjaśnienie „nie dowód wykonania kodu” | `pos::test_p1_upload_php_and_log_request_are_correlated_with_caveat`, `cli::test_poc_end_to_end` | PASS |
| P2 | Zmodyfikowany plik core, poprawny manifest | checksum mismatch | `BASELINE_FILE_CHANGED` z `sha256` i `baseline_sha256` | `pos::test_p2_modified_core_file_reports_observed_and_reference_hash` | PASS |
| P2 | — | dowód z wersją referencji | wersja WordPressa/manifestu w ustaleniu | `pos::test_p2_checksum_mismatch_names_reference_version` | XFAIL (#6) |
| P3 | Administrator dodany w nowszej migawce | ustalenie bez przypisania sprawstwa | `UNRECOGNIZED_ADMIN`, „nie dowodzi to włamania”, brak słowa `ATTACKER` | `pos::test_p3_admin_outside_trusted_list_is_flagged_without_attribution` | PASS |
| P3 | — | `NEW_SINCE_BASELINE` | reguła o tej nazwie | `pos::test_p3_admin_added_since_baseline_is_new_since_baseline` | XFAIL (#7) |
| P4 | Opcja z podejrzanym redirectem | finding DB | `SUSPICIOUS_DB_MARKUP`, źródło `tabela:opcja` | `pos::test_p4_option_with_redirect_markup_is_a_database_finding[script, iframe, javascript-scheme]` | PASS |
| P4 | — | finding DB także dla meta-refresh | jw. | `pos::test_p4_option_with_redirect_markup_is_a_database_finding[meta-refresh]` | XFAIL (#7) |
| P4 | — | cytat wartości po redakcji | fragment wartości bez sekretu | `pos::test_p4_finding_quotes_option_value_with_secret_redacted` | XFAIL (#7) |
| P5 | `mu-plugin` zmieniony wobec baseline | anomalia trwałości | `BASELINE_FILE_CHANGED` (ogólna reguła, bez klasy „persistence”) | `pos::test_p5_changed_mu_plugin_is_reported_against_baseline` | PASS |
| P5 | Nowy `mu-plugin` nieobecny w baseline | ustalenie dla pliku | finding ze ścieżką pliku | `pos::test_p5_mu_plugin_added_since_baseline_is_reported` | XFAIL (#6) |
| P5 | Cron zmieniony wobec baseline | anomalia trwałości | — | — | NOT COVERED: PoC nie ma wejścia na bazową migawkę DB ani analizy opcji `cron`; nie ma czego wywołać (#7) |
| P6 | Sygnatura sztucznego webshella | trafienie sygnatury | `SUSPICIOUS_PHP_EVAL_DECODE`, confidence `medium`, „heurystyka, nie dowód malware” | `pos::test_p6_synthetic_webshell_marker_is_a_heuristic_finding`, `cli::test_poc_end_to_end` | PASS |
| P6 | — | YARA finding z `rule_id` i offsetem | `metadata.offset` | `pos::test_p6_signature_finding_carries_match_offset` | XFAIL (#6) |

Reguły PoC spoza P1–P6 (test pozytywny i negatywny): `REQUEST_TO_COMMAND_EXEC` — `pos::test_content_rules_fire_only_on_request_driven_exec_in_code_files` (PASS); `BASELINE_FILE_MISSING` — `pos::test_baseline_file_missing_only_for_files_absent_from_evidence` (PASS).

## Scenariusze negatywne N1–N8

| ID | Wymaganie | Oczekiwany status / zachowanie | Dowód w raporcie | Test | Stan |
|---|---|---|---|---|---|
| N1 | Czysty WordPress, poprawny manifest | bez alertów | `findings == []`, `NO_INDICATORS_IN_ANALYZED_SCOPE` (komplet źródeł: pliki, baza, logi, baseline) | `neg::test_n1_clean_site_with_matching_manifest_has_no_findings`, `con::test_complete_scope_without_findings_is_no_indicators_in_analyzed_scope` | PASS |
| N2 | Legalny kod analytics w pliku motywu | brak ustaleń | `findings == []` | `neg::test_n2_analytics_snippet_in_theme_file_raises_nothing` | PASS |
| N2 | Legalny kod analytics w opcji DB | brak wysokiego alarmu | jedno `SUSPICIOUS_DB_MARKUP` medium/low — **znany false positive** (każdy `<script>` w opcji) | `neg::test_n2_analytics_snippet_in_option_is_only_a_low_confidence_review_item` | PASS |
| N3 | Legalny admin bez baseline | brak alertu, luka o braku listy | `findings == []`, gap „brak wiarygodnej listy porównawczej” | `neg::test_n3_admin_without_trusted_list_is_a_gap_not_an_alert` | PASS |
| N3 | — | „tylko inventory” | konto w inwentarzu raportu | `neg::test_n3_admin_without_trusted_list_appears_in_inventory` | XFAIL (#7) |
| N3 | Admin z zaufanej listy (flaga lub baseline) | brak alertu | `findings == []` | `neg::test_trusted_admin_is_not_flagged[cli-flag, baseline-list]` | PASS |
| N4 | Legalna aktualizacja wtyczki | „needs review”, nie exploit | `BASELINE_FILE_CHANGED` medium, „zmiana nie przesądza o ataku” | `neg::test_n4_updated_plugin_is_a_medium_review_item_not_an_exploit` | PASS |
| N5 | Legalny PHP w nietypowym katalogu | heurystyka, nie silny dowód | `EXECUTABLE_IN_UPLOADS` confidence `medium`, „wymaga analizy kontekstu” (severity pozostaje `high`) | `neg::test_n5_harmless_php_in_uploads_is_heuristic_not_strong_evidence` | PASS |
| N6 | Brak bazy i/lub logów | luka pokrycia, nigdy „clean” | gap „Brak zrzutu bazy danych” / „Brak logów HTTP”, disclaimer w HTML | `neg::test_n6_missing_source_is_reported_as_coverage_gap[no-database, no-logs, neither]`, `cli::test_no_indicators_not_a_clean_bill` | PASS (T-102: `cli` oczekuje `INCONCLUSIVE` zamiast `NO_INDICATORS_IN_ANALYZED_SCOPE`, decyzja B9) |
| N6 | — | `INCONCLUSIVE`, pokrycie `NOT_PROVIDED`, kod wyjścia 3 | `assessment`, `coverage.database`, `coverage.logs` | `neg::test_n6_missing_database_and_logs_is_inconclusive`, `con::test_incomplete_scope_without_findings_is_inconclusive[no-database, no-logs]` | PASS (T-102; znacznik #5 zdjęty) |
| N7 | Błędna strefa czasu w logu | brak zdarzenia na osi czasu, jawna luka | brak wpisu HTTP w `timeline`, gap „Nie można znormalizować czasu logu” | `neg::test_n7_unusable_log_timezone_yields_gap_instead_of_timeline_event[no-zone, impossible-zone, garbage]` | PASS |
| N7 | Poprawna strefa | UTC + adnotacja o niezweryfikowanym zegarze | `time_utc`, `timestamp_basis` | `neg::test_n7_log_event_time_is_marked_as_unverified_clock` | PASS |
| N7 | Brak fałszywej **ścisłej** korelacji czasowej | — | — | — | NOT COVERED: korelacja PoC łączy plik z logiem wyłącznie po ścieżce i w ogóle nie używa czasu; nie ma zachowania czasowego do sprawdzenia (#3) |
| N8 | Wtyczka premium bez sum kontrolnych | `NO_TRUSTED_REFERENCE` | status w raporcie | `neg::test_n8_premium_plugin_without_checksums_has_no_trusted_reference` | XFAIL (#6) |

### Luki pokrycia i wiarygodność baseline (poza numeracją N)

| Wymaganie | Oczekiwane zachowanie | Test | Stan |
|---|---|---|---|
| Brak lub pusty baseline | luka pokrycia (powód w `coverage.baseline`); zakres pozostaje pełny | `neg::test_missing_trusted_baseline_is_reported_as_coverage_gap[not-provided, empty-manifest]`, `con::test_missing_baseline_is_reported_but_does_not_make_the_scope_incomplete` | PASS (T-102; znacznik #6 zdjęty — powód pokrycia powstał razem z `coverage` per źródło) |
| Niepoprawny plik baseline (zły JSON, zły typ, nie-UTF-8, głębokie zagnieżdżenie) | odmowa, kod 2, nic nie zapisane | `neg::test_malformed_baseline_is_rejected_as_usage_error[…9 wariantów]` | PASS (T-101) |
| Baseline nieczytelny lub z wieloma dowiązaniami twardymi | odmowa, kod 2 (nie cicha rezygnacja z porównania) | `sec::test_unreadable_baseline_is_refused_not_silently_dropped`, `neg::test_hardlinked_baseline_is_refused_with_a_hint` | PASS (T-101) |
| Baseline jako dowód | wpis `baseline/<nazwa>` w `evidence` | `neg::test_baseline_is_listed_in_evidence_manifest`, `con::test_provided_baseline_is_analyzed_and_counted` | PASS (T-101) |
| Plik z baseline obecny, ale nieprzeczytany (hardlink, nieczytelny katalog, limit) | luka, nie `BASELINE_FILE_MISSING` | `sec::test_file_present_but_not_read_is_a_gap_not_a_missing_file_finding[…3 warianty]` | PASS (T-101) |
| Pusty katalog logów | luka pokrycia, pokrycie `FAILED`, kod wyjścia 4 | `neg::test_empty_source_directory_is_reported_as_coverage_gap[logs]`, `con::test_incomplete_scope_without_findings_is_inconclusive[empty-log-directory, log-without-lines]` | PASS (T-102; znacznik #3 zdjęty — źródło bez odczytanych bajtów nie może mieć statusu `ANALYZED`) |
| Pusty katalog `--files` | luka pokrycia, pokrycie `FAILED`, kod wyjścia 4 | `neg::test_empty_source_directory_is_reported_as_coverage_gap[site]`, `con::test_incomplete_scope_without_findings_is_inconclusive[empty-site-directory]` | PASS (T-102; znacznik #6 zdjęty z tego samego powodu; wykrywanie „to nie jest WordPress” nadal należy do #6) |
| Obcy SQL (PostgreSQL COPY, identyfikatory w `"`, śmieci binarne, pusty plik) | gap „Brak obsługiwanych instrukcji INSERT”, zero ustaleń | `neg::test_foreign_sql_is_reported_as_unparsed_not_clean[…]` | PASS |
| Nieobsługiwana instrukcja obok obsługiwanej (`REPLACE INTO`) | dodatkowa luka | `neg::test_unsupported_statement_next_to_supported_one_adds_a_gap` | XFAIL (#7) |
| Rola administratora bez wiersza `*_users` | ustalenie albo luka | `neg::test_admin_capability_without_user_row_is_not_silently_dropped` | XFAIL (#7) |
| Log w obcym formacie / częściowo nieparsowalny | luka z licznikiem | `neg::test_unsupported_log_lines_are_counted_as_coverage_gap[json-lines, partly-parsed]` | PASS |

## Testy odporności S-01–S-18

| ID | Wymaganie | Oczekiwany status / zachowanie | Dowód | Test | Stan |
|---|---|---|---|---|---|
| S-01 | Symlink (plik, katalog) w `--files` poza root | pominięty, luka, treść nieczytana | gap „Łącze symboliczne pominięte”, brak SHA celu | `sec::test_s01_site_symlink_outside_root_is_skipped_with_gap[file-link, dir-link]`, `cli::test_symlinks_never_followed` | PASS |
| S-01 | Symlink w katalogu logów | pominięty, luka | gap „Pominięto link w logach” | `sec::test_s01_log_symlink_outside_root_is_skipped_with_gap` | PASS |
| S-01 | Symlink podany wprost jako `--files`, `--database`, `--logs` (katalog i plik), `--baseline` | odmowa, kod 2, komunikat bez celu dowiązania (ADR 0002 B5) | `SystemExit(2)`, brak katalogu wyników | `sec::test_s01_database_symlink_outside_root_is_not_read`, `sec::test_s01_symlink_given_as_any_source_is_refused[…4 warianty]`, `ing::test_symlink_given_as_source_root_is_refused[…]` | PASS (T-101; test `--database` zmieniony: odmowa zamiast cichego pominięcia) |
| S-01 | Hardlink do pliku spoza root | domyślnie nieczytany, luka `SKIPPED_HARDLINK`; z `--allow-hardlinks` czytany i policzony w luce | gap z nazwą pliku; brak SHA celu | `sec::test_s01_hardlink_to_file_outside_root_is_flagged`, `sec::test_s01_hardlinked_file_is_not_hashed_or_analyzed_by_default`, `sec::test_s01_allow_hardlinks_flag_reads_the_file_and_reports_how_many`, `ing::test_hardlinked_file_*` | PASS (T-101) |
| S-01 | Klucze baseline z `../` i ścieżką bezwzględną | tylko porównywane, nigdy otwierane | brak SHA pliku spoza dowodów | `sec::test_s01_traversal_keys_in_baseline_are_compared_but_never_opened`, `ing::test_symlink_to_parent_directory_does_not_escape_or_loop` | PASS (T-101) |
| S-02 | Podmiana pliku lub katalogu na symlink między enumeracją a otwarciem | cel nieczytany, luka | gap „Łącze symboliczne pominięte”, brak SHA celu | `sec::test_s02_file_swapped_for_symlink_after_check_is_not_read`, `ing::test_entry_swapped_for_symlink_after_enumeration_is_not_followed[file, directory]` (deterministyczny hak po wylistowaniu katalogu; prawdziwy wyścig wątków nie był uruchamiany) | PASS (T-101; test przepisany na hak w `ingest`, bo `cli.digest_file` już nie istnieje) |
| S-02 | Zmiana pliku w trakcie odczytu | status `CHANGED`, luka `SOURCE_CHANGED_DURING_ANALYSIS`; skrót opisuje bajty przekazane do analizy | gap, `sha256` = skrót `content` | `ing::test_file_modified_while_being_read_is_marked_changed`, `ing::test_hash_of_a_changed_file_still_describes_the_bytes_handed_to_analysis`, `ing::test_file_growing_on_every_read_does_not_stall_the_reader` | PASS (T-101) |
| S-02 | Zmiana po odczycie (treść przy tym samym rozmiarze i mtime, nowy i-węzeł, symlink, usunięcie, obcięcie, sam mtime, podmiana lub usunięcie korzenia) | luka `SOURCE_CHANGED_DURING_ANALYSIS` przy ponownej weryfikacji, dla każdego źródła | gap z nazwą wpisu | `ing::test_change_between_read_and_reverification_is_reported[…6 wariantów]`, `ing::test_source_root_*`, `sec::test_s02_evidence_changed_after_reading_is_reported_for_every_source[files, database, logs, baseline]` | PASS (T-101) |
| S-02 | `--no-reverify` | weryfikacja pominięta i odnotowana jako luka | gap z nazwą flagi | `sec::test_s02_no_reverify_flag_skips_the_check_and_says_so`, `ing::test_disabled_reverification_is_itself_reported_and_detects_nothing` | PASS (T-101) |
| S-03 | FIFO w `--files` | pominięte, luka, bez zawieszenia | gap „Plik specjalny pominięty” | `sec::test_s03_fifo_in_site_is_skipped_with_gap` | PASS |
| S-03 | FIFO w katalogu logów | luka | gap z nazwą pliku | `sec::test_s03_fifo_in_logs_is_skipped_with_gap` | PASS (T-101) |
| S-03 | FIFO podane wprost jako `--database`, `--logs`, `--baseline` | odmowa, kod 2, bez zawieszenia | `SystemExit(2)` w 5 s | `sec::test_s03_fifo_given_as_source_is_refused_without_blocking[…]`, `ing::test_fifo_given_as_source_root_is_refused_without_blocking` | PASS (T-101) |
| S-03 | Socket (gniazdo uniksowe w drzewie; lokalne, bez sieci) | pominięte, status `SKIPPED_SPECIAL`, bez łączenia | `reason == "SOCKET"` | `ing::test_unix_socket_is_skipped_without_connecting` | PASS (T-101) |
| S-03 | Nieczytelny plik lub katalog w dowolnym źródle (plik i katalog w `--files`, `--database`, `--logs`) | luka z nazwą błędu (`EACCES`), bez awarii i bez ścieżki hosta | gap „Odczyt nieudany (EACCES): …” | `sec::test_unreadable_log_file_becomes_a_gap_not_a_crash`, `sec::test_unreadable_entry_becomes_a_gap_named_by_errno[…4 warianty]`, `ing::test_unreadable_entry_is_an_error_record_named_by_errno[file, directory]`, `ing::test_io_error_becomes_an_error_record_without_leaking_descriptors[…]` | PASS (T-101) |
| S-04 | Nazwa pliku 255 znaków | ścieżka nieobcięta w raporcie | `source` ustalenia | `sec::test_s04_maximum_length_filename_is_reported_untruncated` | PASS |
| S-04 | Ścieżka dłuższa niż `PATH_MAX` (ok. 5 kB, 20 poziomów) | przy domyślnym limicie 4096 B: luka i odcięcie; przy podniesionym limicie: odczyt względem deskryptorów | `MAX_PATH_BYTES`; `rel` o długości 5028 | `ing::test_tree_nested_beyond_path_max_is_cut_off_at_the_default_path_limit`, `ing::test_tree_nested_beyond_path_max_is_readable_when_the_limit_allows` | PASS (T-101) |
| S-05 | Ścieżka Unicode | zachowana w raporcie | `source` ustalenia (po normalizacji NFC) | `sec::test_s05_unicode_path_is_preserved_in_report` | PASS |
| S-05 | Nazwa pliku spoza UTF-8 | raport powstaje; nazwa w postaci `\xNN` i luka o postaci zastępczej | `report.json`, `rel` kodowalne w UTF-8 | `sec::test_s05_non_utf8_filename_does_not_break_the_report`, `ing::test_non_utf8_filename_is_read_and_reported_under_an_encodable_name` | PASS na Linuksie (T-101; znacznik #5 zdjęty); SKIP na macOS (APFS odrzuca takie nazwy) |
| S-06 | Limit liczby plików (domyślnie 200 000, `--max-files`), wspólny dla wszystkich źródeł | przerwanie przejścia z luką; kolejne źródła pominięte z luką | gap „Limit N plików; analiza katalogu niepełna” | `sec::test_s06_file_count_limit_stops_scan_with_gap` (stała `MAX_FILES` obniżona przez monkeypatch do 3), `sec::test_s06_default_file_count_limit_follows_adr_0002`, `sec::test_s06_file_count_limit_is_shared_by_all_sources`, `ing::test_file_count_limit_*` | PASS |
| S-06 | Limity długości ścieżki (4096 B), głębokości (64) i czasu (30 min, `--max-seconds`, zegar monotoniczny) | wpis pominięty lub analiza częściowa, nazwana luka | `MAX_PATH_BYTES`, `MAX_DEPTH`, `MAX_SECONDS` | `ing::test_relative_path_above_byte_limit_is_skipped`, `ing::test_directory_below_depth_limit_is_not_entered`, `ing::test_time_budget_exhausted_*`, `ing::test_every_exceeded_limit_produces_a_gap_naming_its_value[…]`, `sec::test_s07_time_limit_flag_yields_partial_analysis_with_gap`, `sec::test_non_positive_limit_is_rejected_as_usage_error[…]` | PASS (T-101; zegar podstawiony, nie czekano 30 min) |
| S-06 | Milion małych plików | budżet czasu/pamięci | — | — | NOT COVERED: nie tworzono miliona plików; zmierzono tylko mechanizm limitu |
| S-07 | Plik > limitu (plik rzadki, realne progi 4/20/30 MiB + 1 B) | treść pominięta z luką; hash i rozmiar w manifeście | gap „Analiza treści pominięta” / „Eksport SQL większy niż” / „Log za duży” | `sec::test_s07_oversized_site_file_is_hashed_but_not_content_scanned`, `sec::test_s07_oversized_sql_dump_is_skipped_with_gap`, `sec::test_s07_oversized_log_is_skipped_with_gap` | PASS |
| S-07 | 10 GB sparse file | pominięty przed skrótem (limit 2 GiB na plik, `--max-file-bytes`), luka, reszta analizowana | gap „Plik większy niż limit … pominięty bez obliczania skrótu” w 5 s | `sec::test_s07_ten_gigabyte_sparse_file_is_skipped_without_hashing`, `sec::test_s07_size_limit_flags_skip_the_file_and_continue_with_the_rest[max-file-bytes, max-total-bytes]`, `ing::test_file_above_size_limit_is_skipped_before_hashing`, `ing::test_total_volume_limit_skips_what_does_not_fit_and_continues` | PASS (T-101) |
| S-07 | Limit treści plików (4 MiB) a SQL i logi | SQL (20 MiB) i logi (30 MiB) zachowują własne progi | reguły DB i logów działają powyżej progu plików | `sec::test_s07_file_scan_limit_does_not_apply_to_sql_and_logs[sql-dump, access-log]` | PASS (T-101) |
| S-08 | Wejście wymuszające katastrofalny backtracking (SQL) | parser kończy w budżecie czasu | brak `TimeoutError` w 2 s | `sec::test_s08_crafted_insert_does_not_stall_the_sql_parser` | PASS (naprawione w #11) |
| S-08 | Powtarzalna treść PHP dla reguł plikowych | koniec w budżecie | zero ustaleń w 5 s | `sec::test_s08_repetitive_php_does_not_stall_the_file_rules` | PASS |
| S-08 | Timeout YARA | — | — | — | NOT COVERED: brak YARA w PoC (#6) |
| S-09 | INSERT wielowierszowy, `\'`, `''`, sekwencje ucieczki, `NULL`, instrukcja w łańcuchu | sparsowane jako dane | wynik `iter_insert_rows` | `sec::test_s09_escaped_and_multiline_inserts_are_parsed_as_data[…]`, `cli::test_sql_rows_and_prefix` | PASS |
| S-09 | Urwany INSERT | brak wierszy | wynik `iter_insert_rows` | `sec::test_s09_truncated_insert_yields_no_rows[open-string, no-terminator]` | PASS |
| S-10 | Uszkodzone UTF-8 w pliku PHP / SQL / logu | wskaźnik nadal wykryty, raport poprawny | odpowiednia reguła w `findings` | `sec::test_s10_invalid_utf8_does_not_hide_indicators[php-file, sql-dump, access-log]` | PASS |
| S-10 | Stratne dekodowanie SQL | luka pokrycia | gap o kodowaniu | `sec::test_s10_lossy_decoding_is_reported_as_coverage_gap[sql-dump]` | XFAIL (#7) |
| S-10 | Stratne dekodowanie logu | luka pokrycia | gap o kodowaniu | `sec::test_s10_lossy_decoding_is_reported_as_coverage_gap[access-log]` | XFAIL (#3) |
| S-11 | Zserializowany obiekt PHP w opcji | traktowany jako tekst, nie trafia do raportu | zero ustaleń, brak nazwy klasy w wyjściu | `sec::test_s11_serialized_php_object_is_inert_text` | PASS |
| S-11 | `administrator` z `b:0` | nie jest adminem | zero ustaleń | `sec::test_s11_revoked_administrator_capability_is_not_an_admin` | XFAIL (#7) |
| S-12 | HTML z `onerror` w ścieżce pliku, nazwie opcji, nazwie pliku logu, polu czasu logu, nazwie symlinka, `case_id` | escapowany w `report.html` | brak surowego znacznika, obecna postać `&lt;img…` | `sec::test_s12_markup_from_evidence_is_escaped_in_html_report[…6 wariantów]`, `cli::test_report_escapes_html` | PASS |
| S-12 | CSP w raporcie HTML | deklaracja polityki | `Content-Security-Policy` | `sec::test_s12_html_report_declares_content_security_policy` | XFAIL (#3) |
| S-13 | Kanarek w `wp-config.php` i w kolumnie `user_pass` | nie wypływa do JSON/HTML/stdout | brak łańcucha w wyjściu | `sec::test_s13_canary_secret_never_reaches_any_output[wp-config-password, user-pass-column]` | PASS |
| S-13 | Kanarek w query stringu logu | nie wypływa | jw. | `sec::test_s13_canary_secret_never_reaches_any_output[log-query-token]` | XFAIL (#3) |
| S-14 | Sfałszowany `X-Forwarded-For` dopisany do wiersza logu | adres klienta = pole połączenia; wartość nagłówka nie trafia do raportu | `metadata.client_ip` | `sec::test_s14_forged_forwarded_for_is_not_used_as_client_address` | PASS |
| S-14 | Konfiguracja zaufanych proxy | — | — | — | NOT COVERED: PoC nie ma takiej konfiguracji ani formatu z XFF na pierwszej pozycji (#3) |
| S-15 | Brak sieci | pełna analiza z zablokowanymi gniazdami; brak importów sieciowych | 6 reguł demo; analiza AST importów | `inv::test_s15_full_analysis_runs_with_sockets_blocked`, `inv::test_s15_engine_imports_no_network_modules` | PASS |
| S-15 | Izolacja sieci na poziomie OS/kontenera | — | — | — | NOT COVERED: pomiar `network_mode: none` należy do M6 (T-601) |
| S-16 | Brak zapisu w dowodach | drzewo identyczne przed i po (ścieżki, tryby, rozmiary, mtime, treść, cele linków; bez atime) | skrót drzewa | `inv::test_s16_analysis_leaves_evidence_tree_unchanged` | PASS |
| S-16 | `--output` wewnątrz `--files` | odrzucone | `SystemExit` | `cli::test_output_cannot_be_inside_evidence` | PASS |
| S-16 | `--output` wewnątrz dowolnego źródła, równe źródłu albo zawierające źródło (także przez symlink i inną wielkość liter) | odrzucone, kod 2, nic nie zapisane | `SystemExit(2)`, drzewo bez zmian | `inv::test_s16_output_inside_logs_directory_is_refused`, `inv::test_s16_output_overlapping_any_source_is_refused_before_anything_is_written[…4 warianty]`, `ing::test_output_overlapping_a_source_is_refused[…6 wariantów]`, `ing::test_output_inside_source_spelled_in_another_letter_case_is_refused` (SKIP na Linuksie) | PASS (T-101) |
| S-16 | Brak zapisu w dowodach przy wszystkich źródłach, FIFO, hardlinkach i ponownej weryfikacji | drzewo identyczne przed i po | skrót drzewa | `inv::test_s16_analysis_with_every_flag_leaves_evidence_tree_unchanged`, `ing::test_reading_and_reverifying_leaves_the_evidence_tree_unchanged` | PASS (T-101) |
| S-16 | Brak wycieku deskryptorów | liczba otwartych fd bez zmian (także po przerwaniu, limitach i błędach) | `/dev/fd` przed i po | `ing::test_no_file_descriptor_is_leaked[…8 wariantów]`, `inv::test_full_analysis_leaks_no_file_descriptor` | PASS (T-101) |
| B8 | Ścieżki hosta w raporcie | żadna luka ani ustalenie nie zawiera ścieżki bezwzględnej; błędy jako nazwa (`EACCES`) | brak `tmp_path` w JSON i HTML | `sec::test_report_never_contains_an_absolute_host_path`, `ing::test_no_message_contains_an_absolute_host_path` | PASS (T-101; redakcja query stringów i pseudonimizacja poza zakresem) |
| D4 | Dowody otwiera wyłącznie `wptrace/ingest.py` | strażnik AST: poza `ingest.py` tylko `mkdir` ×1 i `write_text` ×2 w `cli.py` (zapis wyników); `ingest.py` importuje tylko dozwolone moduły stdlib i nie zawiera wywołań ani flag zapisu | lista wyjątków w teście | `inv::test_d4_only_ingest_touches_the_filesystem`, `inv::test_d4_guard_recognises_file_access[…]`, `ing::test_ingest_imports_only_allowlisted_standard_modules`, `ing::test_ingest_contains_no_writing_call_or_flag` | PASS (T-101; strażnik działa po nazwach wywołań — potykacz, nie piaskownica) |
| B3 | Platforma bez `dir_fd`/`O_NOFOLLOW` | jawna odmowa pracy | `IngestRefusal(UNSUPPORTED_PLATFORM)` | `ing::test_platform_without_descriptor_relative_open_is_refused` (symulacja przez monkeypatch; Windows nie był uruchamiany) | PASS (T-101) |
| S-17 | Brak uruchomienia PHP ani innych procesów | pełna analiza z zablokowanym `subprocess`/`os.system`/`fork`/`exec`; brak `eval`/`exec` w silniku | 6 reguł demo; analiza AST | `inv::test_s17_full_analysis_runs_with_process_spawning_blocked`, `inv::test_s17_engine_has_no_dynamic_execution_primitives` | PASS |
| S-18 | Deterministyczne raporty | dwa uruchomienia → identyczny JSON i HTML z pominięciem `analyzed_at_utc`; kolejność odczytu bajtowo posortowana | porównanie raportów | `inv::test_s18_two_runs_on_same_evidence_give_identical_json`, `inv::test_s18_two_runs_on_same_evidence_give_identical_html`, `ing::test_entries_are_visited_in_bytewise_sorted_preorder`, `ing::test_two_sessions_report_identical_records_in_identical_order` | PASS |
| D7 | Po T-102 narzędzie pisze wyłącznie `poc-1` | klucze raportu i wpisów `evidence` według ADR 0003 | lista kluczy | `inv::test_report_has_the_poc_1_shape` (zastąpił `test_report_keeps_the_0_1_0_shape`), `mod::test_report_dictionary_has_the_poc_1_top_level_fields` | PASS (T-102) |

## Kontrakty `poc-1` (T-102, ADR 0003)

| Wymaganie | Oczekiwane zachowanie | Test | Stan |
|---|---|---|---|
| Walidacja raportu | wisząca referencja (dowód, obserwacja, oś czasu), powtórzony identyfikator, nieznane wyliczenie, zły typ, brakujące i nieznane pole, identyfikator niezgodny z treścią → `ModelError` z nazwą pola | `mod::test_dangling_reference_is_rejected[…5]`, `mod::test_duplicate_identifier_is_rejected[…3]`, `mod::test_broken_report_is_rejected_with_a_message_naming_the_field[…37]`, `mod::test_report_built_from_wrong_kinds_of_parts_is_rejected[…7]` | PASS |
| Identyfikatory z treści | wzorzec kanonicznego JSON; zależność od pól tożsamości i tylko od nich; niezależność od kolejności, ścieżki hosta, `mtime` i `PYTHONHASHSEED` | `mod::test_content_id_is_a_pinned_function_of_canonical_json`, `mod::test_*_id_*`, `mod::test_report_order_does_not_depend_on_the_order_of_its_inputs`, `con::test_identifiers_do_not_depend_on_the_host_path_or_file_times`, `con::test_reports_from_processes_with_different_hash_seeds_are_identical` (dwa osobne procesy) | PASS |
| `severity` i `confidence` | osobne, walidowane skale; każda kombinacja dozwolona | `mod::test_severity_and_confidence_are_separate_scales`, `mod::test_every_severity_combines_with_every_confidence[…12]` | PASS |
| Czas | tylko UTC w ISO 8601 z `Z` lub `+00:00`; źródło czasu jawne; czas logu bez strefy → `timestamp_utc: null` | `mod::test_utc_time_is_accepted_with_z_or_zero_offset[…]`, `mod::test_time_outside_utc_iso_8601_is_rejected[…6]`, `mod::test_local_time_is_rejected_wherever_utc_is_required[…]`, `con::test_log_observation_carries_line_raw_time_utc_time_and_time_source`, `con::test_log_time_that_cannot_be_normalized_is_kept_raw_with_null_utc`, `con::test_timeline_events_name_their_time_source_and_reference_recorded_items` | PASS |
| Reguła `assessment` | tabela przypadków: każda gałąź reguły i przypadki graniczne; raport z oceną sprzeczną z regułą jest odrzucany | `mod::test_assessment_rule[…25]`, `mod::test_scope_is_complete_only_with_all_critical_sources_analyzed[…7]`, `mod::test_report_whose_assessment_contradicts_the_rule_is_rejected[…5]` | PASS |
| Brak ustaleń przy niepełnym zakresie | `INCONCLUSIVE`, status i liczniki źródła, powód, kod wyjścia 3 lub 4 — dla: braku bazy, braku logów, pominiętego hardlinka i symlinka, limitu rozmiaru, limitu skanowania treści, pliku i zrzutu `CHANGED`, częściowo sparsowanego logu, limitu liczby plików, obcego SQL, obcego formatu logu, pustych źródeł, nieczytelnego zrzutu, przerwanej ponownej weryfikacji | `con::test_incomplete_scope_without_findings_is_inconclusive[…15]`, `con::test_unreadable_database_is_failed_coverage_with_the_error_recorded_on_its_evidence`, `con::test_time_limit_hit_during_reverification_makes_every_provided_source_partial` | PASS |
| Pełny zakres | `NO_INDICATORS_IN_ANALYZED_SCOPE`, kod 0; ograniczenia informacyjne (parser SQL, duży plik bez reguł treści, `--no-reverify`, brak baseline) nie obniżają statusu | `con::test_complete_scope_without_findings_is_no_indicators_in_analyzed_scope`, `con::test_limitations_that_do_not_shrink_the_scope_stay_listed_as_reasons`, `con::test_large_file_without_content_rules_does_not_shrink_the_scope`, `con::test_disabled_reverification_is_reported_without_changing_the_assessment` | PASS |
| Dowody pominięte | wpis `evidence` ze statusem odczytu i bez skrótu; wpis `CHANGED` zachowuje skrót i identyfikator | `con::test_skipped_entry_is_an_evidence_record_without_a_hash[…4]`, `con::test_entry_changed_after_reading_keeps_the_hash_of_the_analyzed_bytes`, `con::test_modification_time_before_1970_is_recorded_as_a_negative_number` | PASS |
| Observation a Finding | obserwacja bez oceny; ustalenie wskazuje istniejące obserwacje; korelacja wskazuje obserwację pliku i logu | `con::test_observation_states_the_fact_and_leaves_the_rating_to_the_finding`, `con::test_every_finding_of_the_demo_case_rests_on_recorded_observations_and_evidence`, `con::test_correlation_finding_reuses_the_file_and_log_observations`, `con::test_database_observation_names_table_key_and_row`, `con::test_missing_baseline_file_is_observed_on_the_baseline_evidence` | PASS |
| Ustalenia a zakres i kod wyjścia | syntetyczny incydent z `fixtures/` to `SUSPICIOUS`, nie `STRONG_INDICATORS`; ustalenia nie ukrywają niepełnego zakresu i nie ustawiają kodu wyjścia | `con::test_demo_case_is_suspicious_not_strong`, `con::test_findings_do_not_hide_an_incomplete_scope_and_do_not_set_the_exit_code`, `con::test_exit_code_follows_coverage[…7]` | PASS |
| JSON Schema | plik jest poprawnym schematem draft 2020-12; raport z `fixtures/` przechodzi; 23 celowo zepsute warianty są odrzucane; wyliczenia i pola zgodne z modelem | `con::test_published_schema_is_a_valid_draft_2020_12_schema`, `con::test_report_generated_for_the_fixtures_validates_against_the_published_schema`, `con::test_schema_rejects_a_deliberately_broken_report[…23]`, `con::test_schema_enumerations_match_the_model`, `con::test_schema_fields_match_the_fields_the_model_writes` | PASS |
| HTML na nowym raporcie | assessment, pełność zakresu, waga i pewność, tabela pokrycia; nowe pola escapowane | `con::test_html_report_shows_assessment_and_coverage_of_every_source`, `con::test_html_report_shows_severity_and_confidence_side_by_side`, `con::test_html_report_escapes_every_new_field` | PASS |
| Migracja 0.1.0 → `poc-1` | `tests/data/report-0.1.0.json` (dawny `demo/report.json`) i raporty budowane w teście: wynik przechodzi model i schemat; `INDICATORS_FOUND` → `SUSPICIOUS`, `NO_INDICATORS_IN_ANALYZED_SCOPE` → `INCONCLUSIVE`; obserwacje `LEGACY_FINDING`; pokrycie i statusy odczytu `UNKNOWN_LEGACY`; funkcja czysta i deterministyczna; wejście niespójne odrzucane | `mig::test_migrated_demo_*` (9 testów), `mig::test_no_indicators_becomes_inconclusive_because_old_coverage_is_unknown`, `mig::test_migration_is_pure_and_deterministic`, `mig::test_old_source_is_resolved_to_manifest_evidence_and_a_structured_location[…6]`, `mig::test_input_that_is_not_a_consistent_0_1_0_report_is_refused[…18]` | PASS |

## Zestawienie XFAIL według Issue

| Issue | Liczba | Luki |
|---|---|---|
| #4 (T-101) | 0 | wszystkie 9 zdjęte w T-101 (dwa testy zmienione: `--database` jako symlink → odmowa wg B5; TOCTOU → nowy hak w `ingest`) |
| #5 (T-102) | 0 | `INCONCLUSIVE` wdrożone w T-102 — znacznik zdjęty |
| #6 (T-201) | 4 | wersja referencji; nowy plik spoza baseline; offset sygnatury; `NO_TRUSTED_REFERENCE`. W T-102 zdjęto 3: pusty `--files` i brak/pusty baseline (2 warianty) dają teraz powód w `coverage` |
| #7 (T-301) | 8 | `NEW_SINCE_BASELINE`; meta-refresh; cytat z redakcją; inwentarz adminów; pominięte instrukcje bez luki; admin bez wiersza users; stratne dekodowanie; `b:0` |
| #3 (bez własnego Issue) | 3 | stratne dekodowanie logu; brak CSP; token z query stringu w `report.json`. W T-102 zdjęto 1: pusty katalog logów daje teraz pokrycie `FAILED` z powodem |

Razem 15, tak samo na macOS i na Linuksie. Stan po T-102 (#5); po T-101 (#4) było 20, po naprawie ReDoS (#11) — 30 (29 na macOS), w T-003 — 31.

## Ograniczenia tej macierzy

- Wszystkie dane są syntetyczne; nie mierzono false positive/false negative na reprezentatywnym zbiorze.
- Testy S-15 i S-17 blokują wywołania na poziomie Pythona i sprawdzają importy; nie zastępują izolacji kontenera.
- Budżety czasu (S-08) używają `SIGALRM`, więc działają tylko na systemach POSIX.
- `pytest --cov` zapisuje plik `.coverage` w katalogu roboczym (od T-001 w `.gitignore`).
- T-102: testy kontraktu sprawdzają kształt, referencje i regułę oceny na danych syntetycznych; nie mierzą trafności progu `STRONG_INDICATORS` (żadna reguła PoC go nie osiąga). Dwa procesy z różnym `PYTHONHASHSEED` uruchamiają wyłącznie narzędzie. Migracja była sprawdzana na jednym zachowanym raporcie 0.1.0 i na raportach budowanych w teście, nie na raportach z innych wersji narzędzia.
- T-101: wyścigi (podmiana po enumeracji, zmiana w trakcie i po odczycie) są symulowane deterministycznymi hakami; prawdziwy wyścig wątków ani procesów nie był uruchamiany. Limit czasu sprawdzono podstawionym zegarem. Punktów montowania wewnątrz drzewa, plików urządzeń i systemów plików sieciowych nie testowano.
