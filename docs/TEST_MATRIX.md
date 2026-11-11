# Macierz testów P1–P6, N1–N8, S-01–S-18 (T-003)

Stan na 2026-11-11, gałąź `agent/T-003-test-matrix` (na bazie `agent/T-001-baseline-ci`). Źródło scenariuszy: `docs/WPTrace_Specyfikacja_Senior_PoC_2026-11-09.md`, rozdz. 14.1–14.3. Kod `wptrace/` **nie został zmieniony** — macierz mierzy obecny PoC, niczego nie naprawia.

Macierz nie jest dowodem bezpieczeństwa ani skuteczności detekcji. `PASS` znaczy tylko: opisane zachowanie zaobserwowano w uruchomionym teście na danych syntetycznych.

## Jak czytać

- **PASS** — test uruchomiony i zielony.
- **XFAIL (#N)** — test uruchomiony, potwierdza znaną lukę; oznaczony `xfail(strict=True)` z numerem Issue. Po naprawie test da XPASS i wymusi zdjęcie znacznika.
- **NOT COVERED** — brak testu; podany powód.
- Numery Issue: #4 = T-101 SecureIngest/odczyt, #5 = T-102 kontrakty i schemat raportu, #6 = T-201 analiza plików, #7 = T-301 SQL, #3 = luka bez własnego Issue (logi, raport HTML, reguły) — kandydat na nowe Issue.
- Skróty plików: `pos` = `tests/test_scenarios_positive.py`, `neg` = `tests/test_negative.py`, `sec` = `tests/test_security_inputs.py`, `inv` = `tests/test_invariants.py`, `cli` = `tests/test_cli.py`.

## Wyniki uruchomienia (2026-11-11)

| Komenda | Środowisko | Wynik |
|---|---|---|
| `python -m pytest -q` | macOS (Darwin 27.0.0, arm64), Python 3.12.11, pytest 8.4.2 | **79 passed, 1 skipped, 30 xfailed** |
| `python -m pytest -q` | Linux, kontener `python:3.12-slim` (obraz `docker-wptrace`), użytkownik 65532, kopia repozytorium | **79 passed, 31 xfailed** |
| `python -m ruff check .` | macOS | brak zgłoszeń |
| `python -m pytest -q --cov=wptrace --cov-report=term-missing` | macOS, pytest-cov 6.3.0, coverage 7.17.2 | **93%** (tabela niżej) |

Jedyny `skip` (macOS): `sec::test_s05_non_utf8_filename_does_not_break_the_report` — APFS odrzuca nazwy plików spoza UTF-8, więc scenariusza nie da się tam zbudować. Na Linuksie ten sam test wykonuje się i jest XFAIL (#5). CI (`ubuntu-24.04`) nie było uruchamiane w ramach tego zadania.

Aktualizacja po naprawie ReDoS (#11), macOS: `python -m pytest -q` → **89 passed, 1 skipped, 29 xfailed**. Pozostałe wyniki w tej sekcji pochodzą z T-003 i nie były mierzone ponownie.

Zestaw liczy 110 testów: 6 istniejących (`tests/test_cli.py`, bez zmian) i 104 nowe.

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
| N1 | Czysty WordPress, poprawny manifest | bez alertów | `findings == []`, `NO_INDICATORS_IN_ANALYZED_SCOPE` | `neg::test_n1_clean_site_with_matching_manifest_has_no_findings` | PASS |
| N2 | Legalny kod analytics w pliku motywu | brak ustaleń | `findings == []` | `neg::test_n2_analytics_snippet_in_theme_file_raises_nothing` | PASS |
| N2 | Legalny kod analytics w opcji DB | brak wysokiego alarmu | jedno `SUSPICIOUS_DB_MARKUP` medium/low — **znany false positive** (każdy `<script>` w opcji) | `neg::test_n2_analytics_snippet_in_option_is_only_a_low_confidence_review_item` | PASS |
| N3 | Legalny admin bez baseline | brak alertu, luka o braku listy | `findings == []`, gap „brak wiarygodnej listy porównawczej” | `neg::test_n3_admin_without_trusted_list_is_a_gap_not_an_alert` | PASS |
| N3 | — | „tylko inventory” | konto w inwentarzu raportu | `neg::test_n3_admin_without_trusted_list_appears_in_inventory` | XFAIL (#7) |
| N3 | Admin z zaufanej listy (flaga lub baseline) | brak alertu | `findings == []` | `neg::test_trusted_admin_is_not_flagged[cli-flag, baseline-list]` | PASS |
| N4 | Legalna aktualizacja wtyczki | „needs review”, nie exploit | `BASELINE_FILE_CHANGED` medium, „zmiana nie przesądza o ataku” | `neg::test_n4_updated_plugin_is_a_medium_review_item_not_an_exploit` | PASS |
| N5 | Legalny PHP w nietypowym katalogu | heurystyka, nie silny dowód | `EXECUTABLE_IN_UPLOADS` confidence `medium`, „wymaga analizy kontekstu” (severity pozostaje `high`) | `neg::test_n5_harmless_php_in_uploads_is_heuristic_not_strong_evidence` | PASS |
| N6 | Brak bazy i/lub logów | luka pokrycia, nigdy „clean” | gap „Brak zrzutu bazy danych” / „Brak logów HTTP”, disclaimer w HTML | `neg::test_n6_missing_source_is_reported_as_coverage_gap[no-database, no-logs, neither]`, `cli::test_no_indicators_not_a_clean_bill` | PASS |
| N6 | — | `INCONCLUSIVE` | `assessment` | `neg::test_n6_missing_database_and_logs_is_inconclusive` | XFAIL (#5) |
| N7 | Błędna strefa czasu w logu | brak zdarzenia na osi czasu, jawna luka | brak wpisu HTTP w `timeline`, gap „Nie można znormalizować czasu logu” | `neg::test_n7_unusable_log_timezone_yields_gap_instead_of_timeline_event[no-zone, impossible-zone, garbage]` | PASS |
| N7 | Poprawna strefa | UTC + adnotacja o niezweryfikowanym zegarze | `time_utc`, `timestamp_basis` | `neg::test_n7_log_event_time_is_marked_as_unverified_clock` | PASS |
| N7 | Brak fałszywej **ścisłej** korelacji czasowej | — | — | — | NOT COVERED: korelacja PoC łączy plik z logiem wyłącznie po ścieżce i w ogóle nie używa czasu; nie ma zachowania czasowego do sprawdzenia (#3) |
| N8 | Wtyczka premium bez sum kontrolnych | `NO_TRUSTED_REFERENCE` | status w raporcie | `neg::test_n8_premium_plugin_without_checksums_has_no_trusted_reference` | XFAIL (#6) |

### Luki pokrycia i wiarygodność baseline (poza numeracją N)

| Wymaganie | Oczekiwane zachowanie | Test | Stan |
|---|---|---|---|
| Brak lub pusty baseline | luka pokrycia | `neg::test_missing_trusted_baseline_is_reported_as_coverage_gap[not-provided, empty-manifest]` | XFAIL (#6) |
| Niepoprawny plik baseline | błąd wejścia zamiast tracebacku | `neg::test_malformed_baseline_is_rejected_as_usage_error[invalid-json, list, string]` | XFAIL (#4) |
| Pusty katalog logów | luka pokrycia | `neg::test_empty_source_directory_is_reported_as_coverage_gap[logs]` | XFAIL (#3) |
| Pusty katalog `--files` | luka pokrycia | `neg::test_empty_source_directory_is_reported_as_coverage_gap[site]` | XFAIL (#6) |
| Obcy SQL (PostgreSQL COPY, identyfikatory w `"`, śmieci binarne, pusty plik) | gap „Brak obsługiwanych instrukcji INSERT”, zero ustaleń | `neg::test_foreign_sql_is_reported_as_unparsed_not_clean[…]` | PASS |
| Nieobsługiwana instrukcja obok obsługiwanej (`REPLACE INTO`) | dodatkowa luka | `neg::test_unsupported_statement_next_to_supported_one_adds_a_gap` | XFAIL (#7) |
| Rola administratora bez wiersza `*_users` | ustalenie albo luka | `neg::test_admin_capability_without_user_row_is_not_silently_dropped` | XFAIL (#7) |
| Log w obcym formacie / częściowo nieparsowalny | luka z licznikiem | `neg::test_unsupported_log_lines_are_counted_as_coverage_gap[json-lines, partly-parsed]` | PASS |

## Testy odporności S-01–S-18

| ID | Wymaganie | Oczekiwany status / zachowanie | Dowód | Test | Stan |
|---|---|---|---|---|---|
| S-01 | Symlink (plik, katalog) w `--files` poza root | pominięty, luka, treść nieczytana | gap „Łącze symboliczne pominięte”, brak SHA celu | `sec::test_s01_site_symlink_outside_root_is_skipped_with_gap[file-link, dir-link]`, `cli::test_symlinks_never_followed` | PASS |
| S-01 | Symlink w katalogu logów | pominięty, luka | gap „Pominięto link w logach” | `sec::test_s01_log_symlink_outside_root_is_skipped_with_gap` | PASS |
| S-01 | `--database` jako symlink poza dowody | nieczytany | brak SHA celu w manifeście | `sec::test_s01_database_symlink_outside_root_is_not_read` | XFAIL (#4) |
| S-01 | Hardlink do pliku spoza root | adnotacja/luka | gap z nazwą pliku | `sec::test_s01_hardlink_to_file_outside_root_is_flagged` | XFAIL (#4) |
| S-02 | Podmiana pliku na symlink w trakcie skanu | cel nieczytany | brak ustalenia z treści celu | `sec::test_s02_file_swapped_for_symlink_after_check_is_not_read` (deterministyczna symulacja podmiany między `lstat` a odczytem treści; prawdziwy wyścig wątków nie był uruchamiany) | XFAIL (#4) |
| S-03 | FIFO w `--files` | pominięte, luka, bez zawieszenia | gap „Plik specjalny pominięty” | `sec::test_s03_fifo_in_site_is_skipped_with_gap` | PASS |
| S-03 | FIFO w katalogu logów | luka | gap z nazwą pliku | `sec::test_s03_fifo_in_logs_is_skipped_with_gap` | XFAIL (#4) |
| S-03 | Socket | — | — | — | NOT COVERED: test nie tworzy gniazd (zasada „bez sieci”); gałąź kodu wspólna z FIFO (`S_ISREG`) |
| S-03 | Nieczytelny plik logu | luka zamiast awarii | gap z nazwą pliku | `sec::test_unreadable_log_file_becomes_a_gap_not_a_crash` | XFAIL (#4) |
| S-04 | Nazwa pliku 255 znaków | ścieżka nieobcięta w raporcie | `source` ustalenia | `sec::test_s04_maximum_length_filename_is_reported_untruncated` | PASS |
| S-04 | Ścieżka dłuższa niż `PATH_MAX` | — | — | — | NOT COVERED: wymaga zagnieżdżenia zależnego od systemu plików; do T-101 (#4) |
| S-05 | Ścieżka Unicode | zachowana w raporcie | `source` ustalenia (po normalizacji NFC) | `sec::test_s05_unicode_path_is_preserved_in_report` | PASS |
| S-05 | Nazwa pliku spoza UTF-8 | raport powstaje | `report.json` | `sec::test_s05_non_utf8_filename_does_not_break_the_report` | XFAIL (#5) na Linuksie; SKIP na macOS (APFS odrzuca takie nazwy) |
| S-06 | Limit liczby plików | przerwanie z luką | gap „Limit N plików; analiza katalogu niepełna” | `sec::test_s06_file_count_limit_stops_scan_with_gap` (stała `MAX_FILES` obniżona przez monkeypatch do 3) | PASS |
| S-06 | Milion małych plików | budżet czasu/pamięci | — | — | NOT COVERED: nie tworzono miliona plików; zmierzono tylko mechanizm limitu |
| S-07 | Plik > limitu (plik rzadki, realne progi 4/20/30 MiB + 1 B) | treść pominięta z luką; hash i rozmiar w manifeście | gap „Analiza treści pominięta” / „Eksport SQL większy niż” / „Log za duży” | `sec::test_s07_oversized_site_file_is_hashed_but_not_content_scanned`, `sec::test_s07_oversized_sql_dump_is_skipped_with_gap`, `sec::test_s07_oversized_log_is_skipped_with_gap` | PASS |
| S-07 | 10 GB sparse file | budżet czasu hashowania | — | — | NOT COVERED: PoC hashuje cały plik bez limitu; test 10 GB trwałby zbyt długo dla zestawu jednostkowego. Do T-101 (#4) |
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
| S-16 | `--output` wewnątrz `--logs` | odrzucone | `SystemExit` | `inv::test_s16_output_inside_logs_directory_is_refused` | XFAIL (#4) |
| S-17 | Brak uruchomienia PHP ani innych procesów | pełna analiza z zablokowanym `subprocess`/`os.system`/`fork`/`exec`; brak `eval`/`exec` w silniku | 6 reguł demo; analiza AST | `inv::test_s17_full_analysis_runs_with_process_spawning_blocked`, `inv::test_s17_engine_has_no_dynamic_execution_primitives` | PASS |
| S-18 | Deterministyczne raporty | dwa uruchomienia → identyczny JSON i HTML z pominięciem `analyzed_at_utc` | porównanie raportów | `inv::test_s18_two_runs_on_same_evidence_give_identical_json`, `inv::test_s18_two_runs_on_same_evidence_give_identical_html` | PASS |

## Zestawienie XFAIL według Issue

| Issue | Liczba | Luki |
|---|---|---|
| #4 (T-101) | 9 | niepoprawny baseline → traceback (3 warianty); `--database` jako symlink; hardlink; TOCTOU; FIFO w logach; nieczytelny log; `--output` w katalogu logów |
| #5 (T-102) | 2 | brak `INCONCLUSIVE`; nazwa pliku spoza UTF-8 wywraca zapis `report.json` (tylko Linux) |
| #6 (T-201) | 7 | wersja referencji; nowy plik spoza baseline; offset sygnatury; pusty `--files`; `NO_TRUSTED_REFERENCE`; brak/pusty baseline bez luki (2 warianty) |
| #7 (T-301) | 8 | `NEW_SINCE_BASELINE`; meta-refresh; cytat z redakcją; inwentarz adminów; pominięte instrukcje bez luki; admin bez wiersza users; stratne dekodowanie; `b:0` |
| #3 (bez własnego Issue) | 4 | pusty katalog logów bez luki; stratne dekodowanie logu; brak CSP; token z query stringu w `report.json` |

Razem 30 (29 na macOS, bo jeden wariant jest tam pomijany). Stan po naprawie ReDoS (#11); w T-003 było 31.

## Ograniczenia tej macierzy

- Wszystkie dane są syntetyczne; nie mierzono false positive/false negative na reprezentatywnym zbiorze.
- Testy S-15 i S-17 blokują wywołania na poziomie Pythona i sprawdzają importy; nie zastępują izolacji kontenera.
- Budżety czasu (S-08) używają `SIGALRM`, więc działają tylko na systemach POSIX.
- `pytest --cov` zapisuje plik `.coverage` w katalogu roboczym; nie jest on jeszcze w `.gitignore` (zmiana poza zakresem T-003).
