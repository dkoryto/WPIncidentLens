# Macierz testów P1–P6, N1–N8, S-01–S-18 (T-003, stan po M1)

**Stan na 2026-11-11**, gałąź `agent/T-101-case-manager`, commit `4cac876` (PR #27, w chwili pisania niescalony z `main`). Źródło scenariuszy: `docs/WPTrace_Specyfikacja_Senior_PoC_2026-11-09.md`, rozdz. 14.1–14.3. Dokument opisuje jeden, aktualny stan; wcześniejsze wyniki cząstkowe (T-003, #11, T-101, T-102) są w historii gita tego pliku.

Macierz nie jest dowodem bezpieczeństwa ani skuteczności detekcji. `PASS` znaczy tylko: opisane zachowanie zaobserwowano w uruchomionym teście na danych syntetycznych, na macOS.

## Jak czytać

- **PASS** — test uruchomiony i zielony w przebiegu opisanym niżej.
- **XFAIL (#N)** — test uruchomiony, potwierdza znaną lukę; oznaczony `xfail(strict=True)` z numerem Issue w powodzie. Po naprawie test da XPASS i wymusi zdjęcie znacznika.
- **SKIP** — test nie wykonał się na tej platformie; podany powód.
- **NOT COVERED** — brak testu; podany powód.
- Skróty plików (`tests/test_*.py`): `pos` = `test_scenarios_positive`, `neg` = `test_negative`, `sec` = `test_security_inputs`, `inv` = `test_invariants`, `cli` = `test_cli`, `ing` = `test_ingest`, `prop` = `test_ingest_properties`, `mod` = `test_models`, `con` = `test_contract`, `mig` = `test_migrate`, `case` = `test_case`, `rw` = `test_report_writer`.
- Raport ma schemat `poc-1` (ADR 0003). Kolumna „Dowód w raporcie” używa nazw widoku testowego `Run` z `tests/conftest.py` (`source`, `metadata`, `gaps`, `manifest`), który składa ustalenie z jego obserwacją i dowodem; nazwy pól w pliku opisuje ADR 0003.
- Issue (stan z `gh issue list --state all`, 2026-11-11): **otwarte** #4 (T-101), #6 (T-201 pliki), #7 (T-301 SQL), #13 (T-401 logi), #18 (T-006); **zamknięte** #3 (T-003), #5 (T-102), #11, #14 (T-501), #15 (T-601), #17.

## Wyniki uruchomienia (2026-11-11)

Uruchomione przez agenta aktualizującego ten dokument, w świeżym środowisku (`uv venv --python 3.12`, `pip install -e '.[dev]'`):

| Komenda | Środowisko | Wynik |
|---|---|---|
| `python -m ruff check .` | macOS 27.0.1 (Darwin 27.0.0, arm64), ruff 0.8.6 | **All checks passed** (reguły `E9`, `F`) |
| `python -m pytest -q` | jw., Python 3.12.11, pytest 8.4.2, jsonschema 4.26.0 | **1853 passed, 5 skipped, 13 xfailed** (19,75 s) |
| `python -m pytest -q --cov=wptrace --cov-report=term-missing` | jw., pytest-cov 6.3.0, coverage 7.17.2 | **1853 passed, 5 skipped, 13 xfailed; pokrycie 99%** (tabela niżej) |
| `python -m pytest -v` | jw. | ten sam wynik; trzeci przebieg, w tym oba testy wyścigu |
| `python -m wptrace --files fixtures/site --database fixtures/database.sql --logs fixtures/logs --baseline fixtures/baseline.json --output <tmp> --case-id DEMO-001` | jw. | kod 0; `SUSPICIOUS`, `scope_complete: true`, 6 ustaleń, 2 luki; powstały `report.json`, `report.html`, `case.json`, wszystkie z trybem `0600` |
| `python -m wptrace --files fixtures/site --output <tmp>` | jw. | kod 3; `SUSPICIOUS`, `scope_complete: false` |
| `python -m wptrace --help` | jw. | kod 0 |

Zebrano 1871 przypadków z 362 funkcji testowych (`pytest --collect-only -q`): 1066 w `prop`, 184 w `mod`, 119 w `con`, 116 w `ing`, 108 w `sec`, 91 w `case`, 61 w `mig`, 41 w `neg`, 38 w `inv`, 22 w `rw`, 19 w `pos`, 6 w `cli`.

Pominięcia na macOS (5), wszystkie z powodu systemu plików APFS:

| Test | Powód |
|---|---|
| `sec::test_s05_non_utf8_filename_does_not_break_the_report` | APFS odrzuca nazwy spoza UTF-8 |
| `ing::test_non_utf8_filename_is_read_and_reported_under_an_encodable_name` | jw. |
| `ing::test_raw_byte_name_and_its_spelled_out_twin_are_two_entries` | jw. |
| `prop::test_distinct_files_never_share_a_ledger_path` | jw. |
| `con::test_report_names_the_flagged_file_whose_mtime_cannot_be_written_as_a_date` | system plików nie zachowuje `mtime` spoza zakresu lat 1–9999 |

**Linux nie był uruchamiany w ramach tej aktualizacji.** Jedyny znany wynik z Linuksa pochodzi z opisu PR #27 (pomiar agenta prowadzącego, nieodtworzony tutaj): kontener `python:3.12-slim`, `--network none`, uid 1000, kopia repozytorium — „1856 passed, 2 skipped, 13 xfailed; ruff czysty”. Wyniku CI (`ubuntu-24.04`) dla PR #27 nie sprawdzano.

### Pokrycie kodu

```
Name                  Stmts   Miss  Cover   Missing
---------------------------------------------------
wptrace/__init__.py       1      0   100%
wptrace/__main__.py       2      0   100%
wptrace/case.py          86      0   100%
wptrace/cli.py          470     11    98%   334-335, 345-346, 355, 359, 368, 377, 440-441, 674
wptrace/ingest.py       380      7    98%   170-172, 334-335, 413, 520
wptrace/migrate.py      136      1    99%   211
wptrace/models.py       459      0   100%
wptrace/report.py        82      0   100%
---------------------------------------------------
TOTAL                  1616     19    99%
```

Pokrycie liniowe mierzy wykonanie, nie poprawność: 13 przypadków XFAIL wykonuje kod, który zachowuje się źle. Niepokryte na macOS: treść niedostępna po zmianie pliku w trakcie odczytu (`cli.py` 334–335, 440–441), limit 100 000 wierszy `INSERT` (345–346), wiersze bez listy kolumn o zbyt małej liczbie pól (355, 359, 368, 377), błąd `fstat` tuż po otwarciu (`ingest.py` 170–172), limit wpisów osiągnięty w pętli przejścia (334–335), luka o nazwie spoza UTF-8 (413 — testy pominięte na APFS), wpis zmieniony na inny typ przy ponownej weryfikacji (520). Nie ustawiono progu `fail-under`.

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
| P5 | Cron zmieniony wobec baseline | anomalia trwałości | — | — | NOT COVERED: PoC nie ma wejścia na bazową migawkę DB ani analizy opcji `cron` (#7) |
| P6 | Sygnatura sztucznego webshella | trafienie sygnatury | `SUSPICIOUS_PHP_EVAL_DECODE`, confidence `medium`, „heurystyka, nie dowód malware” | `pos::test_p6_synthetic_webshell_marker_is_a_heuristic_finding`, `cli::test_poc_end_to_end` | PASS |
| P6 | — | YARA finding z `rule_id` i offsetem | `metadata.offset` | `pos::test_p6_signature_finding_carries_match_offset` | XFAIL (#6) |

Reguły PoC spoza P1–P6 (test pozytywny i negatywny): `REQUEST_TO_COMMAND_EXEC` — `pos::test_content_rules_fire_only_on_request_driven_exec_in_code_files` (PASS); `BASELINE_FILE_MISSING` — `pos::test_baseline_file_missing_only_for_files_absent_from_evidence` (PASS).

## Scenariusze negatywne N1–N8

| ID | Wymaganie | Oczekiwany status / zachowanie | Dowód w raporcie | Test | Stan |
|---|---|---|---|---|---|
| N1 | Czysty WordPress, poprawny manifest | bez alertów | `findings == []`, `NO_INDICATORS_IN_ANALYZED_SCOPE` (komplet źródeł) | `neg::test_n1_clean_site_with_matching_manifest_has_no_findings`, `con::test_complete_scope_without_findings_is_no_indicators_in_analyzed_scope` | PASS |
| N2 | Legalny kod analytics w pliku motywu | brak ustaleń | `findings == []` | `neg::test_n2_analytics_snippet_in_theme_file_raises_nothing` | PASS |
| N2 | Legalny kod analytics w opcji DB | brak wysokiego alarmu | jedno `SUSPICIOUS_DB_MARKUP` medium/low — **znany false positive** (każdy `<script>` w opcji) | `neg::test_n2_analytics_snippet_in_option_is_only_a_low_confidence_review_item` | PASS |
| N3 | Legalny admin bez baseline | brak alertu, nota o braku listy | `findings == []`, gap „brak wiarygodnej listy porównawczej” | `neg::test_n3_admin_without_trusted_list_is_a_gap_not_an_alert` | PASS |
| N3 | — | „tylko inventory” | konto w inwentarzu raportu | `neg::test_n3_admin_without_trusted_list_appears_in_inventory` | XFAIL (#7) |
| N3 | Admin z zaufanej listy (flaga lub baseline) | brak alertu | `findings == []` | `neg::test_trusted_admin_is_not_flagged[cli-flag, baseline-list]` | PASS |
| N4 | Legalna aktualizacja wtyczki | „needs review”, nie exploit | `BASELINE_FILE_CHANGED` medium, „zmiana nie przesądza o ataku” | `neg::test_n4_updated_plugin_is_a_medium_review_item_not_an_exploit` | PASS |
| N5 | Legalny PHP w nietypowym katalogu | heurystyka, nie silny dowód | `EXECUTABLE_IN_UPLOADS` confidence `medium`, „wymaga analizy kontekstu” (severity pozostaje `high`) | `neg::test_n5_harmless_php_in_uploads_is_heuristic_not_strong_evidence` | PASS |
| N6 | Brak bazy i/lub logów | luka pokrycia, nigdy „clean” | gap „Brak zrzutu bazy danych” / „Brak logów HTTP”, disclaimer w HTML | `neg::test_n6_missing_source_is_reported_as_coverage_gap[no-database, no-logs, neither]`, `cli::test_no_indicators_not_a_clean_bill` | PASS |
| N6 | — | `INCONCLUSIVE`, pokrycie `NOT_PROVIDED`, kod wyjścia 3 | `assessment`, `coverage.database`, `coverage.logs` | `neg::test_n6_missing_database_and_logs_is_inconclusive`, `con::test_incomplete_scope_without_findings_is_inconclusive[no-database, no-logs]` | PASS |
| N7 | Błędna strefa czasu w logu | brak zdarzenia na osi czasu, jawna nota | brak wpisu HTTP w `timeline`, gap „Nie można znormalizować czasu logu” | `neg::test_n7_unusable_log_timezone_yields_gap_instead_of_timeline_event[no-zone, impossible-zone, garbage]` | PASS |
| N7 | Poprawna strefa | UTC + adnotacja o niezweryfikowanym zegarze | `time_utc`, `timestamp_basis` | `neg::test_n7_log_event_time_is_marked_as_unverified_clock` | PASS |
| N7 | Brak fałszywej **ścisłej** korelacji czasowej | — | — | — | NOT COVERED: korelacja PoC łączy plik z logiem wyłącznie po ścieżce i nie używa czasu (#13) |
| N8 | Wtyczka premium bez sum kontrolnych | `NO_TRUSTED_REFERENCE` | status w raporcie | `neg::test_n8_premium_plugin_without_checksums_has_no_trusted_reference` | XFAIL (#6) |

### Luki pokrycia i wiarygodność baseline (poza numeracją N)

| Wymaganie | Oczekiwane zachowanie | Test | Stan |
|---|---|---|---|
| Brak lub pusty baseline | powód w `coverage.baseline`; zakres pozostaje pełny | `neg::test_missing_trusted_baseline_is_reported_as_coverage_gap[not-provided, empty-manifest]`, `con::test_missing_baseline_is_reported_but_does_not_make_the_scope_incomplete` | PASS |
| Niepoprawny plik baseline (zły JSON, zły typ, nie-UTF-8, głębokie zagnieżdżenie) | odmowa, kod 2, nic nie zapisane | `neg::test_malformed_baseline_is_rejected_as_usage_error` (9 wariantów) | PASS |
| Baseline nieczytelny lub z wieloma dowiązaniami twardymi | odmowa, kod 2 (nie cicha rezygnacja z porównania) | `sec::test_unreadable_baseline_is_refused_not_silently_dropped`, `neg::test_hardlinked_baseline_is_refused_with_a_hint` | PASS |
| Baseline lub `--known-admin` z tekstem nie do zapisania w UTF-8 | odmowa, kod 2, przed analizą | `case::test_baseline_text_that_cannot_be_encoded_is_refused_before_analysis` (3 warianty), `case::test_known_admin_that_cannot_be_encoded_is_refused_before_analysis` (2 warianty) | PASS |
| Baseline jako dowód | wpis `baseline/<nazwa>` w `evidence` | `neg::test_baseline_is_listed_in_evidence_manifest`, `con::test_provided_baseline_is_analyzed_and_counted` | PASS |
| Plik z baseline obecny, ale nieprzeczytany (hardlink, nieczytelny katalog, limit) | luka, nie `BASELINE_FILE_MISSING` | `sec::test_file_present_but_not_read_is_a_gap_not_a_missing_file_finding[hardlinked, in-unreadable-directory, beyond-file-limit]` | PASS |
| Plik PHP w uploads, którego nie przeczytano | ustalenie po ścieżce z pewnością `low`; poza uploads — brak ustalenia | `sec::test_unread_php_in_uploads_is_still_reported_by_path` (2 warianty), `sec::test_unread_file_outside_uploads_gives_no_finding` | PASS |
| Pusty katalog logów lub `--files` | luka pokrycia, pokrycie `FAILED`, kod wyjścia 4 | `neg::test_empty_source_directory_is_reported_as_coverage_gap[logs, site]`, `con::test_incomplete_scope_without_findings_is_inconclusive[empty-log-directory, log-without-lines, empty-site-directory]` | PASS |
| Obcy SQL (PostgreSQL COPY, identyfikatory w `"`, śmieci binarne, pusty plik) | gap „Brak obsługiwanych instrukcji INSERT”, zero ustaleń | `neg::test_foreign_sql_is_reported_as_unparsed_not_clean` (4 warianty) | PASS |
| `INSERT`/`REPLACE` w nieobsługiwanej składni, instrukcja niedomknięta, komentarz wykonywalny, `DELIMITER`, ukośnik wsteczny poza łańcuchem, wiersz o złej liczbie pól | luka i pokrycie bazy `PARTIAL` albo `FAILED` | `neg::test_unsupported_statement_next_to_supported_one_adds_a_gap`, `con::test_sql_that_the_parser_skipped_lowers_database_coverage` (16 przypadków), `con::test_dump_without_wordpress_tables_is_not_an_analyzed_database` | PASS |
| Obsługiwane `INSERT` w różnych zapisach | pokrycie bazy pozostaje `ANALYZED` | `con::test_supported_inserts_keep_database_coverage_complete` (8 przypadków) | PASS |
| Instrukcje SQL inne niż `INSERT`/`REPLACE` (`UPDATE`, `CREATE TRIGGER`…) | luka obniżająca pokrycie | — | NOT COVERED: kod daje tylko stałą notę (`wptrace/cli.py:411`); jednorazowa sonda opisana w `docs/M1_GATE.md` §3 dała pokrycie `ANALYZED` (#7) |
| Rola administratora bez wiersza `*_users` | ustalenie albo luka | `neg::test_admin_capability_without_user_row_is_not_silently_dropped` | PASS (luka + `PARTIAL`) |
| Log w obcym formacie / częściowo nieparsowalny | luka z licznikiem | `neg::test_unsupported_log_lines_are_counted_as_coverage_gap[json-lines, partly-parsed]` | PASS |

## Testy odporności S-01–S-18

| ID | Wymaganie | Oczekiwany status / zachowanie | Dowód | Test | Stan |
|---|---|---|---|---|---|
| S-01 | Symlink (plik, katalog) w `--files` poza root | pominięty, luka, treść nieczytana | gap „Łącze symboliczne pominięte”, brak SHA celu | `sec::test_s01_site_symlink_outside_root_is_skipped_with_gap[file-link, dir-link]`, `cli::test_symlinks_never_followed`, `ing::test_symlink_inside_tree_is_skipped_without_following` | PASS |
| S-01 | Symlink w katalogu logów | pominięty, luka | gap „Pominięto link w logach” | `sec::test_s01_log_symlink_outside_root_is_skipped_with_gap` | PASS |
| S-01 | Symlink podany wprost jako `--files`, `--database`, `--logs` (katalog i plik), `--baseline` | odmowa, kod 2, komunikat bez celu dowiązania (ADR 0002 B5) | `SystemExit(2)`, brak katalogu wyników | `sec::test_s01_database_symlink_outside_root_is_not_read`, `sec::test_s01_symlink_given_as_any_source_is_refused[files, logs-directory, logs-file, baseline]`, `ing::test_symlink_given_as_source_root_is_refused` (4 warianty) | PASS |
| S-01 | Hardlink do pliku spoza root | domyślnie nieczytany, luka `SKIPPED_HARDLINK`; z `--allow-hardlinks` czytany i policzony w luce | gap z nazwą pliku; brak SHA celu | `sec::test_s01_hardlink_to_file_outside_root_is_flagged`, `sec::test_s01_hardlinked_file_is_not_hashed_or_analyzed_by_default`, `sec::test_s01_allow_hardlinks_flag_reads_the_file_and_reports_how_many`, `ing::test_hardlinked_file_*` (2 funkcje) | PASS |
| S-01 | Klucze baseline z `../` i ścieżką bezwzględną | tylko porównywane, nigdy otwierane | brak SHA pliku spoza dowodów | `sec::test_s01_traversal_keys_in_baseline_are_compared_but_never_opened`, `ing::test_symlink_to_parent_directory_does_not_escape_or_loop` | PASS |
| S-01 | Losowe drzewa z dowiązaniami symbolicznymi i twardymi do „kanarka” poza korzeniem (25 ziaren × 4 konfiguracje sesji) | nic spoza korzenia nie jest czytane, poza jawnie dozwolonym i oznaczonym hardlinkiem | brak skrótu i treści kanarka w rekordach i rejestrze | `prop::test_nothing_outside_the_root_is_read_except_an_allowed_marked_hardlink` (100 przypadków) | PASS |
| S-02 | Podmiana pliku lub katalogu na symlink między enumeracją a otwarciem — hak deterministyczny | cel nieczytany, luka | gap „Łącze symboliczne pominięte”, brak SHA celu | `sec::test_s02_file_swapped_for_symlink_after_check_is_not_read`, `ing::test_entry_swapped_for_symlink_after_enumeration_is_not_followed[file, directory]` | PASS |
| S-02 | Ta sama podmiana wykonywana w pętli przez **osobny proces** podczas czytania (marker `race`) | pod podmienianą ścieżką tylko oryginał albo jawna odmowa; nic spoza korzenia | etykiety `original` i `blocked` zaobserwowane, zero naruszeń | `prop::test_file_swapped_for_a_symlink_by_another_process_is_never_followed`, `prop::test_directory_swapped_for_a_symlink_by_another_process_is_never_entered` | PASS — próbkowanie ok. 1,5 s na wariant, nie dowód braku okna |
| S-02 | Zmiana pliku w trakcie odczytu | status `CHANGED`, luka `SOURCE_CHANGED_DURING_ANALYSIS`; skrót opisuje bajty przekazane do analizy | gap, `sha256` = skrót `content` | `ing::test_file_modified_while_being_read_is_marked_changed`, `ing::test_hash_of_a_changed_file_still_describes_the_bytes_handed_to_analysis`, `ing::test_file_growing_on_every_read_does_not_stall_the_reader` | PASS (hak) |
| S-02 | Zmiana po odczycie (treść przy tym samym rozmiarze i mtime, nowy i-węzeł, symlink, usunięcie, obcięcie, sam mtime, podmiana lub usunięcie korzenia) | luka `SOURCE_CHANGED_DURING_ANALYSIS` przy ponownej weryfikacji, dla każdego źródła; wpis niesie własną lukę | gap z nazwą wpisu | `ing::test_change_between_read_and_reverification_is_reported` (6 wariantów), `ing::test_source_root_*` (2 funkcje), `sec::test_s02_evidence_changed_after_reading_is_reported_for_every_source[files, database, logs, baseline]`, `prop::test_entry_marked_changed_by_reverification_carries_its_own_gap` | PASS |
| S-02 | `--no-reverify` | weryfikacja pominięta i odnotowana jako luka | gap z nazwą flagi | `sec::test_s02_no_reverify_flag_skips_the_check_and_says_so`, `ing::test_disabled_reverification_is_itself_reported_and_detects_nothing` | PASS |
| S-03 | FIFO w `--files` | pominięte, luka, bez zawieszenia | gap „Plik specjalny pominięty” | `sec::test_s03_fifo_in_site_is_skipped_with_gap`, `ing::test_fifo_is_skipped_without_blocking` | PASS |
| S-03 | FIFO w katalogu logów | luka | gap z nazwą pliku | `sec::test_s03_fifo_in_logs_is_skipped_with_gap` | PASS |
| S-03 | FIFO podane wprost jako `--database`, `--logs`, `--baseline` | odmowa, kod 2, bez zawieszenia | `SystemExit(2)` w budżecie czasu | `sec::test_s03_fifo_given_as_source_is_refused_without_blocking` (3 warianty), `ing::test_fifo_given_as_source_root_is_refused_without_blocking` | PASS |
| S-03 | Socket (gniazdo uniksowe w drzewie; lokalne, bez sieci) | pominięte, status `SKIPPED_SPECIAL`, bez łączenia | `reason == "SOCKET"` | `ing::test_unix_socket_is_skipped_without_connecting` | PASS |
| S-03 | Plik urządzenia w drzewie | pominięty z luką | — | — | NOT COVERED: wymaga uprawnień roota; kod otwiera wpis przed `fstat` (`wptrace/ingest.py:8-11`) |
| S-03 | Nieczytelny plik lub katalog w dowolnym źródle | luka z nazwą błędu (`EACCES`), bez awarii i bez ścieżki hosta | gap „Odczyt nieudany (EACCES): …” | `sec::test_unreadable_log_file_becomes_a_gap_not_a_crash`, `sec::test_unreadable_entry_becomes_a_gap_named_by_errno[site-file, site-directory, database-file, logs-directory]`, `ing::test_unreadable_entry_is_an_error_record_named_by_errno[file, directory]`, `ing::test_io_error_becomes_an_error_record_without_leaking_descriptors` (3 warianty) | PASS |
| S-04 | Nazwa pliku 255 znaków | ścieżka nieobcięta w raporcie | `source` ustalenia | `sec::test_s04_maximum_length_filename_is_reported_untruncated` | PASS |
| S-04 | Ścieżka dłuższa niż `PATH_MAX` | przy domyślnym limicie 4096 B: luka i odcięcie; przy podniesionym limicie: odczyt względem deskryptorów | `MAX_PATH_BYTES` | `ing::test_tree_nested_beyond_path_max_is_cut_off_at_the_default_path_limit`, `ing::test_tree_nested_beyond_path_max_is_readable_when_the_limit_allows` | PASS |
| S-05 | Ścieżka Unicode | zachowana w raporcie | `source` ustalenia | `sec::test_s05_unicode_path_is_preserved_in_report` | PASS |
| S-05 | Nazwa pliku spoza UTF-8 | raport powstaje; nazwa w postaci `\xNN` i luka o postaci zastępczej; dwie różne nazwy bajtowe nigdy nie dają tej samej postaci | `report.json`, `rel` kodowalne w UTF-8 | `sec::test_s05_non_utf8_filename_does_not_break_the_report`, `ing::test_non_utf8_filename_is_read_and_reported_under_an_encodable_name`, `ing::test_raw_byte_name_and_its_spelled_out_twin_are_two_entries`, `prop::test_distinct_files_never_share_a_ledger_path` | **SKIP na macOS** (4 testy; nieuruchomione w tej aktualizacji) |
| S-05 | Odwzorowanie nazw na postać zapisywalną (bez systemu plików) | różnowartościowe, odwracalne, nazwa z dosłownym `\xNN` z podwojonymi ukośnikami | wynik `_printable` | `ing::test_two_different_byte_names_never_share_a_printable_form`, `ing::test_printable_form_is_encodable_and_gives_back_the_original_bytes`, `ing::test_printable_name_changes_only_names_that_could_be_mistaken_for_a_substitute_form` (10 wariantów), `ing::test_valid_name_spelling_out_an_escape_is_reported_with_doubled_backslashes` | PASS |
| S-06 | Limit liczby plików (domyślnie 200 000, `--max-files`), wspólny dla wszystkich źródeł | przerwanie przejścia z luką; kolejne źródła pominięte z luką | gap „Limit N plików; analiza katalogu niepełna” | `sec::test_s06_file_count_limit_stops_scan_with_gap` (stała `MAX_FILES` obniżona przez monkeypatch do 3), `sec::test_s06_default_file_count_limit_follows_adr_0002`, `sec::test_s06_file_count_limit_is_shared_by_all_sources`, `ing::test_file_count_limit_*` (2 funkcje) | PASS |
| S-06 | Limit wszystkich wpisów (1 000 000, `--max-entries`): katalogi, dowiązania, pliki specjalne | lista katalogu obcinana budżetem; luka | `MAX_ENTRIES` | `ing::test_entries_other_than_regular_files_are_bounded_by_the_entry_limit` (2 warianty), `ing::test_directory_listing_never_returns_more_than_the_requested_names`, `ing::test_entry_limit_spans_all_sources_of_a_session`, `ing::test_names_listed_in_parent_directories_count_against_the_entry_budget` | PASS |
| S-06 | Limity długości ścieżki (4096 B), głębokości (64) i czasu (30 min, `--max-seconds`, zegar monotoniczny) | wpis pominięty lub analiza częściowa, nazwana luka | `MAX_PATH_BYTES`, `MAX_DEPTH`, `MAX_SECONDS` | `ing::test_relative_path_above_byte_limit_is_skipped`, `ing::test_directory_below_depth_limit_is_not_entered`, `ing::test_time_budget_exhausted_*` (2 funkcje), `ing::test_every_exceeded_limit_produces_a_gap_naming_its_value` (5 wariantów), `sec::test_s07_time_limit_flag_yields_partial_analysis_with_gap`, `case::test_new_limit_flag_bounds_the_walk_and_is_recorded` (2 warianty) | PASS — zegar podstawiony, nie czekano 30 min |
| S-06 | Limit niedodatni lub nieskończony | odmowa, kod 2 | komunikat z nazwą limitu | `sec::test_non_positive_limit_is_rejected_as_usage_error` (4 flagi), `case::test_limit_that_is_not_a_positive_finite_number_is_refused` (4 warianty), `ing::test_limits_reject_non_positive_values` (8 wariantów) | PASS |
| S-06 | Limity na losowych drzewach (25 ziaren × 4 konfiguracje) | żaden limit nie jest przekroczony | liczniki rejestru | `prop::test_limits_are_never_exceeded` (100 przypadków) | PASS |
| S-06 | Milion małych plików | budżet czasu/pamięci | — | — | NOT COVERED: nie tworzono miliona plików; zmierzono tylko mechanizm limitu |
| S-06 | Limit czasu wewnątrz parserów SQL i logów oraz w trakcie odczytu jednego pliku | przerwanie z luką | — | — | NOT COVERED: kod sprawdza zegar tylko między wpisami (`wptrace/ingest.py:327`, `:474`) |
| S-07 | Plik > limitu (plik rzadki, progi 4/20/30 MiB + 1 B) | treść pominięta z luką; hash i rozmiar w manifeście | gap „Analiza treści pominięta” / „Eksport SQL większy niż” / „Log za duży” | `sec::test_s07_oversized_site_file_is_hashed_but_not_content_scanned`, `sec::test_s07_oversized_sql_dump_is_skipped_with_gap`, `sec::test_s07_oversized_log_is_skipped_with_gap` | PASS |
| S-07 | 10 GB sparse file | pominięty przed skrótem (limit 2 GiB na plik, `--max-file-bytes`), luka, reszta analizowana | gap „Plik większy niż limit … pominięty bez obliczania skrótu” w 5 s | `sec::test_s07_ten_gigabyte_sparse_file_is_skipped_without_hashing`, `sec::test_s07_size_limit_flags_skip_the_file_and_continue_with_the_rest[max-file-bytes, max-total-bytes]`, `ing::test_file_above_size_limit_is_skipped_before_hashing`, `ing::test_total_volume_limit_skips_what_does_not_fit_and_continues` | PASS |
| S-07 | Limit treści plików (4 MiB) a SQL i logi | SQL (20 MiB) i logi (30 MiB) zachowują własne progi | reguły DB i logów działają powyżej progu plików | `sec::test_s07_file_scan_limit_does_not_apply_to_sql_and_logs[sql-dump, access-log]` | PASS |
| S-08 | Wejście wymuszające katastrofalny backtracking (SQL) | parser kończy w budżecie czasu | brak przekroczenia budżetu | `sec::test_s08_crafted_insert_does_not_stall_the_sql_parser`, `sec::test_s08_unterminated_insert_headers_do_not_stall_the_sql_parser` (4 warianty), `sec::test_s08_statement_scanner_is_linear_on_crafted_sql` (5 wariantów), `sec::test_sql_row_splitting_scales_linearly` | PASS |
| S-08 | Spreparowany wiersz logu | wzorzec kończy w budżecie czasu | jw. | `sec::test_s08_crafted_log_line_does_not_stall_the_log_pattern` (5 wariantów) | PASS |
| S-08 | Powtarzalna treść PHP dla reguł plikowych | koniec w budżecie | zero ustaleń w budżecie | `sec::test_s08_repetitive_php_does_not_stall_the_file_rules` | PASS |
| S-08 | Fuzzing parserów SQL i logów | brak awarii i zawieszeń na losowym wejściu | — | — | NOT COVERED: testy S-08 to ręcznie dobrane wejścia (M6) |
| S-08 | Timeout YARA | — | — | — | NOT COVERED: brak YARA w PoC (#6) |
| S-09 | INSERT wielowierszowy, `\'`, `''`, sekwencje ucieczki, `NULL`, instrukcja w łańcuchu | sparsowane jako dane | wynik `iter_insert_rows` | `sec::test_s09_escaped_and_multiline_inserts_are_parsed_as_data` (6 wariantów), `sec::test_sql_row_groups_are_split_outside_quotes` (8 wariantów), `cli::test_sql_rows_and_prefix` | PASS |
| S-09 | Urwany INSERT | brak wierszy | wynik `iter_insert_rows` | `sec::test_s09_truncated_insert_yields_no_rows[open-string, no-terminator]` | PASS |
| S-10 | Uszkodzone UTF-8 w pliku PHP / SQL / logu | wskaźnik nadal wykryty, raport poprawny | odpowiednia reguła w `findings` | `sec::test_s10_invalid_utf8_does_not_hide_indicators[php-file, sql-dump, access-log]` | PASS |
| S-10 | Stratne dekodowanie SQL | luka pokrycia | gap o kodowaniu | `sec::test_s10_lossy_decoding_is_reported_as_coverage_gap[sql-dump]` | XFAIL (#7) |
| S-10 | Stratne dekodowanie logu | luka pokrycia | gap o kodowaniu | `sec::test_s10_lossy_decoding_is_reported_as_coverage_gap[access-log]` | XFAIL (#3 — zamknięte) |
| S-11 | Zserializowany obiekt PHP w opcji | traktowany jako tekst, nie trafia do raportu | zero ustaleń, brak nazwy klasy w wyjściu | `sec::test_s11_serialized_php_object_is_inert_text` | PASS |
| S-11 | `administrator` z `b:0` | nie jest adminem | zero ustaleń | `sec::test_s11_revoked_administrator_capability_is_not_an_admin` | XFAIL (#7) |
| S-12 | HTML z `onerror` w ścieżce pliku, nazwie opcji, nazwie pliku logu, polu czasu logu, nazwie symlinka | escapowany w `report.html` | brak surowego znacznika, obecna postać `&lt;img…` | `sec::test_s12_markup_from_evidence_is_escaped_in_html_report[finding-file-path, finding-option-name, finding-log-file-name, gap-log-timestamp, gap-symlink-name]`, `con::test_html_report_escapes_every_new_field` | PASS |
| S-12 | Znaczniki w `--case-id` | odmowa w CLI (kod 2); raport złożony z pominięciem CLI nadal escapowany | komunikat z nazwą flagi; `&lt;` w HTML | `sec::test_s12_markup_in_case_id_is_refused_by_the_command_line`, `sec::test_s12_markup_in_case_id_of_a_composed_report_is_escaped_in_html_report`, `cli::test_report_escapes_html` | PASS |
| S-12 | CSP w raporcie HTML | deklaracja polityki | `Content-Security-Policy` | `sec::test_s12_html_report_declares_content_security_policy` | XFAIL (#3 — zamknięte) |
| S-13 | Kanarek w `wp-config.php` i w kolumnie `user_pass` | nie wypływa do JSON/HTML/stdout | brak łańcucha w wyjściu | `sec::test_s13_canary_secret_never_reaches_any_output[wp-config-password, user-pass-column]` | PASS |
| S-13 | Kanarek w query stringu logu | nie wypływa | jw. | `sec::test_s13_canary_secret_never_reaches_any_output[log-query-token]` | XFAIL (#3 — zamknięte) |
| S-14 | Sfałszowany `X-Forwarded-For` dopisany do wiersza logu | adres klienta = pole połączenia; wartość nagłówka nie trafia do raportu | `metadata.client_ip` | `sec::test_s14_forged_forwarded_for_is_not_used_as_client_address` | PASS |
| S-14 | Konfiguracja zaufanych proxy | — | — | — | NOT COVERED: PoC nie ma takiej konfiguracji (#13) |
| S-15 | Brak sieci | pełna analiza z zablokowanymi gniazdami; brak importów sieciowych | 6 reguł demo; analiza AST importów | `inv::test_s15_full_analysis_runs_with_sockets_blocked`, `inv::test_s15_engine_imports_no_network_modules` | PASS |
| S-15 | Izolacja sieci na poziomie OS/kontenera | — | — | — | NOT COVERED: pomiar `network_mode: none` należy do M6 |
| S-16 | Brak zapisu w dowodach | drzewo identyczne przed i po (ścieżki, tryby, rozmiary, mtime, treść, cele linków; **bez atime**) | skrót drzewa | `inv::test_s16_analysis_leaves_evidence_tree_unchanged`, `inv::test_s16_analysis_with_every_flag_leaves_evidence_tree_unchanged`, `ing::test_reading_and_reverifying_leaves_the_evidence_tree_unchanged` | PASS |
| S-16 | Brak zapisu w dowodach na losowych drzewach (25 ziaren × 4 konfiguracje) | stan drzewa i otoczenia poza korzeniem identyczny przed i po (typ, tryb, rozmiar, mtime, liczba dowiązań, cel dowiązania, skrót treści; bez atime) | migawka | `prop::test_sources_are_left_exactly_as_they_were` (100 przypadków) | PASS |
| S-16 | `--output` wewnątrz dowolnego źródła, równe źródłu albo zawierające źródło (także przez symlink i inną wielkość liter) | odrzucone, kod 2, nic nie zapisane | `SystemExit(2)`, drzewo bez zmian | `cli::test_output_cannot_be_inside_evidence`, `inv::test_s16_output_inside_logs_directory_is_refused`, `inv::test_s16_output_overlapping_any_source_is_refused_before_anything_is_written` (4 warianty), `ing::test_output_overlapping_a_source_is_refused` (6 wariantów), `ing::test_output_inside_source_spelled_in_another_letter_case_is_refused` | PASS |
| S-16 | Brak wycieku deskryptorów | liczba otwartych fd bez zmian (także po przerwaniu, limitach i błędach) | `/dev/fd` przed i po | `ing::test_no_file_descriptor_is_leaked` (8 wariantów), `inv::test_full_analysis_leaks_no_file_descriptor`, `prop::test_no_descriptor_stays_open_after_a_full_read` (100), `prop::test_no_descriptor_stays_open_when_the_reader_is_abandoned_midway` (100), `rw::test_writer_leaks_no_file_descriptor_after_a_failed_write` | PASS |
| B8 | Ścieżki hosta w raporcie | żadna luka ani ustalenie nie zawiera ścieżki bezwzględnej; błędy jako nazwa (`EACCES`) | brak `tmp_path` w JSON i HTML | `sec::test_report_never_contains_an_absolute_host_path`, `ing::test_no_message_contains_an_absolute_host_path`, `prop::test_every_unread_entry_carries_a_gap_and_nothing_names_a_host_path` (100), `prop::test_report_and_html_name_no_host_path_and_no_content_from_outside` (18), `case::test_case_json_contains_no_host_path` | PASS — redakcji query stringów i pseudonimizacji nie ma |
| D4 | Dowody otwiera wyłącznie `wptrace/ingest.py`, wyniki pisze wyłącznie `wptrace/report.py` | strażnik AST: poza `ingest.py` dozwolone tylko `makedirs` ×1, `open` ×2 i `unlink` ×1 w `report.py`; moduł `os` importują tylko `ingest.py` i `report.py`; strażnik obejmuje podpakiety; `ingest.py` importuje tylko dozwolone moduły stdlib i nie zawiera wywołań ani flag zapisu | lista wyjątków w teście | `inv::test_d4_only_ingest_touches_the_filesystem`, `inv::test_d4_only_ingest_and_reporter_import_the_os_module`, `inv::test_d4_guard_covers_modules_in_subpackages`, `inv::test_d4_guard_recognises_file_access` (20 wariantów), `ing::test_ingest_imports_only_allowlisted_standard_modules`, `ing::test_ingest_contains_no_writing_call_or_flag`, `case::test_case_manager_imports_nothing_that_identifies_the_host_or_opens_files` | PASS — strażnik działa po nazwach wywołań: potykacz, nie piaskownica |
| B3 | Platforma bez `dir_fd`/`O_NOFOLLOW` | jawna odmowa pracy | `IngestRefusal(UNSUPPORTED_PLATFORM)` | `ing::test_platform_without_descriptor_relative_open_is_refused` | PASS — symulacja przez monkeypatch; Windows nie był uruchamiany |
| S-17 | Brak uruchomienia PHP ani innych procesów | pełna analiza z zablokowanym `subprocess`/`os.system`/`fork`/`exec`; brak `eval`/`exec` w silniku | 6 reguł demo; analiza AST | `inv::test_s17_full_analysis_runs_with_process_spawning_blocked`, `inv::test_s17_engine_has_no_dynamic_execution_primitives` | PASS |
| S-18 | Deterministyczne raporty | dwa uruchomienia → identyczny JSON i HTML z pominięciem `analyzed_at_utc`; kolejność odczytu bajtowo posortowana; ten sam rejestr na losowych drzewach | porównanie raportów | `inv::test_s18_two_runs_on_same_evidence_give_identical_json`, `inv::test_s18_two_runs_on_same_evidence_give_identical_html`, `ing::test_entries_are_visited_in_bytewise_sorted_preorder`, `ing::test_two_sessions_report_identical_records_in_identical_order`, `prop::test_two_sessions_over_the_same_tree_give_the_same_ledger` (100), `con::test_reports_from_processes_with_different_hash_seeds_are_identical` | PASS |
| D7 | Narzędzie pisze wyłącznie `poc-1` | klucze raportu i wpisów `evidence` według ADR 0003 | lista kluczy | `inv::test_report_has_the_poc_1_shape`, `mod::test_report_dictionary_has_the_poc_1_top_level_fields` | PASS |

## Własności SecureIngest na losowych drzewach (`prop`, bramka M1)

Generator `random.Random(seed)`: 25 ziaren × 4 konfiguracje sesji (`default`, `hardlinks`, `tight-a`, `tight-b`), najwyżej 48 wpisów w drzewie; oczekiwania z niezależnego wyliczenia drzewa (`os.walk` bez podążania, `lstat`, własny skrót). Własności end-to-end przez CLI: 6 ziaren × 3 warianty flag.

| Własność | Test | Przypadki | Stan |
|---|---|---|---|
| Każdy wpis drzewa ma wpis w rejestrze albo nazwaną przyczynę braku | `prop::test_every_tree_entry_is_accounted_for_in_the_ledger` | 100 | PASS |
| Nic spoza korzenia nie jest czytane | `prop::test_nothing_outside_the_root_is_read_except_an_allowed_marked_hardlink` | 100 | PASS |
| Rekord `READ` opisuje dokładnie bajty z dysku | `prop::test_read_records_describe_exactly_the_bytes_on_disk` | 100 | PASS |
| Każdy wpis o statusie innym niż `READ` niesie lukę; żaden tekst nie zawiera ścieżki hosta | `prop::test_every_unread_entry_carries_a_gap_and_nothing_names_a_host_path` | 100 | PASS |
| Limity nie są przekraczane | `prop::test_limits_are_never_exceeded` | 100 | PASS |
| Źródła pozostają niezmienione | `prop::test_sources_are_left_exactly_as_they_were` | 100 | PASS |
| Dwie sesje dają ten sam rejestr | `prop::test_two_sessions_over_the_same_tree_give_the_same_ledger` | 100 | PASS |
| Brak otwartych deskryptorów po pełnym i po porzuconym odczycie | `prop::test_no_descriptor_stays_open_after_a_full_read`, `prop::test_no_descriptor_stays_open_when_the_reader_is_abandoned_midway` | 100 + 100 | PASS |
| Ponowna weryfikacja nietkniętego drzewa nie zgłasza zmiany | `prop::test_reverification_of_an_untouched_tree_reports_no_change` | 100 | PASS |
| Raport nad drzewem z czymkolwiek pominiętym nigdy nie ma pełnego zakresu ani kodu 0 | `prop::test_report_over_a_tree_with_anything_skipped_is_never_complete` | 18 | PASS |
| Raport i HTML bez ścieżki hosta i bez treści spoza korzenia | `prop::test_report_and_html_name_no_host_path_and_no_content_from_outside` | 18 | PASS |
| Generator tworzy każdy rodzaj wpisu i jest odtwarzalny z ziarna | `prop::test_generator_produces_every_kind_of_entry_across_the_seeds`, `prop::test_generator_is_reproducible_from_its_seed` | 1 + 25 | PASS |

Ograniczenie opisane w samym pliku testów: katalog przejrzany bez przeszkód nie zostawia wpisu, więc z rejestru nie da się odróżnić „pusty katalog odwiedzony” od „pusty katalog pominięty”. Opis PR #27 podaje dodatkowo 20 powtórzeń zestawu i kontrolę mutacyjną (17 wstrzykniętych wad w `ingest.py`, wszystkie wykryte) — to pomiar agenta prowadzącego, nieodtworzony w tej aktualizacji.

## CaseManager, `case.json` i zapis wyników (T-101)

| Wymaganie | Oczekiwane zachowanie | Test | Stan |
|---|---|---|---|
| `--case-id`, `--operator-id` | tylko `A-Z a-z 0-9 . _ -`, 1–64 znaki, pierwszy znak inny niż kropka i łącznik; inna wartość = kod 2 przed analizą, bez powtarzania odrzuconej wartości | `case::test_invalid_identifier_is_refused_before_analysis` (32 warianty), `case::test_refusal_does_not_echo_the_rejected_identifier` (2), `case::test_valid_case_id_is_recorded_in_report_and_case` (6), `case::test_valid_operator_id_is_recorded_in_case` (6), `case::test_case_id_keeps_its_default` | PASS |
| Operator | wyłącznie z flagi; nigdy ze środowiska, nazwy użytkownika ani hosta | `case::test_operator_id_is_null_unless_given`, `case::test_operator_is_never_taken_from_the_environment`, `case::test_case_manager_imports_nothing_that_identifies_the_host_or_opens_files` | PASS |
| Walidacja przed odczytem | zbudowanie kontekstu nie czyta treści dowodów i nie tworzy katalogu wyników; kontekst zamrożony | `case::test_building_the_context_reads_no_evidence_content_and_creates_no_output`, `case::test_case_context_is_frozen`, `case::test_context_carries_validated_limits_flags_and_trusted_admins` | PASS |
| `--output` | ścieżka niepoprawna, zwykły plik albo symlink = kod 2; plik pozostaje nietknięty | `case::test_output_path_that_is_not_a_valid_path_is_refused` (2), `case::test_output_path_that_is_a_regular_file_is_refused_and_left_intact`, `rw::test_output_directory_given_as_symlink_is_refused_before_anything_is_written`, `rw::test_output_directory_swapped_for_symlink_during_analysis_is_refused`, `rw::test_writer_refuses_a_directory_that_is_not_a_real_directory` (2), `rw::test_trailing_slash_does_not_make_the_writer_follow_a_symlinked_directory` | PASS |
| `case.json` (`case-poc-1`) | kształt i schemat; tylko ostatni składnik ścieżki źródła; bez ścieżek hosta; SHA-256 zapisanego `report.json`; ocena i kod wyjścia; czasy UTC; limity i flagi | `case::test_case_json_has_the_case_poc_1_shape`, `case::test_case_json_conforms_to_the_published_schema`, `case::test_case_schema_rejects_a_document_outside_the_contract` (10), `case::test_case_schema_rejects_a_name_for_a_source_that_was_not_provided`, `case::test_case_json_contains_no_host_path`, `case::test_case_json_names_only_the_last_component_of_each_source`, `case::test_case_json_marks_sources_that_were_not_provided`, `case::test_source_given_without_a_name_is_described_with_null`, `case::test_case_json_digest_matches_the_written_report`, `case::test_case_json_repeats_tool_assessment_and_exit_code_of_the_run`, `case::test_case_json_times_are_utc_and_ordered`, `case::test_case_json_records_default_limits`, `case::test_case_json_records_flags` (2), `case::test_two_runs_give_identical_case_json_apart_from_time_dependent_fields` | PASS |
| Pliki wyniku | w katalogu tylko `report.json`, `report.html`, `case.json`; tryb `0600` | `rw::test_run_leaves_only_the_result_files_in_the_output_directory`, `rw::test_new_result_file_is_readable_by_the_owner_only` (3), `rw::test_report_json_keeps_its_serialisation` | PASS |
| Symlink o nazwie pliku wyniku | zastąpiony zwykłym plikiem; cel nietknięty; wiszące dowiązanie nie tworzy celu | `rw::test_symlink_named_like_a_result_is_replaced_and_its_target_left_untouched` (3), `rw::test_dangling_symlink_named_like_a_result_does_not_create_its_target`, `rw::test_write_html_replaces_a_symlink_without_touching_its_target` | PASS |
| Błąd w trakcie zapisu | brak plików częściowych i tymczasowych; poprzednie wyniki nietknięte | `rw::test_failed_write_leaves_no_partial_or_temporary_file` (2), `rw::test_failed_write_keeps_the_previous_results_intact` (2) | PASS — błąd wstrzykiwany w teście; zamiana trzech plików nie jest jedną operacją |
| Wartość nie do zakodowania w UTF-8 | zapis w postaci `\uXXXX` zamiast utraty raportu | `rw::test_value_that_cannot_be_encoded_is_escaped_instead_of_losing_the_json_report`, `rw::test_value_that_cannot_be_encoded_is_escaped_instead_of_losing_the_html_report` | PASS |

## Kontrakty `poc-1` (T-102, ADR 0003)

| Wymaganie | Oczekiwane zachowanie | Test | Stan |
|---|---|---|---|
| Walidacja raportu | wisząca referencja, powtórzony identyfikator, nieznane wyliczenie, zły typ, brakujące i nieznane pole, identyfikator niezgodny z treścią → `ModelError` z nazwą pola | `mod::test_dangling_reference_is_rejected` (5), `mod::test_duplicate_identifier_is_rejected` (3), `mod::test_broken_report_is_rejected_with_a_message_naming_the_field` (37), `mod::test_report_built_from_wrong_kinds_of_parts_is_rejected` (7) | PASS |
| Liczniki pokrycia a dowody; tekst zapisywalny w UTF-8 (T-006) | raport z licznikami bez pokrycia w `evidence` odrzucany; samotny surogat odrzucany z nazwą pola | `mod::test_coverage_counters_contradicting_the_evidence_list_are_rejected` (6), `mod::test_hand_edited_report_claiming_an_analyzed_database_without_its_evidence_is_rejected`, `mod::test_counters_may_exceed_the_evidence_list_only_where_identical_entries_merge` (3), `mod::test_text_that_cannot_be_written_as_utf8_is_rejected_with_the_field_name` (14), `mod::test_valid_report_is_always_writable_as_utf8_json` | PASS |
| Identyfikatory z treści | zależność od pól tożsamości i tylko od nich; niezależność od kolejności, ścieżki hosta, `mtime` i `PYTHONHASHSEED` | `mod::test_content_id_is_a_pinned_function_of_canonical_json`, `mod::test_*_id_*` (5 funkcji), `mod::test_report_order_does_not_depend_on_the_order_of_its_inputs`, `con::test_identifiers_do_not_depend_on_the_host_path_or_file_times`, `con::test_reports_from_processes_with_different_hash_seeds_are_identical` (dwa osobne procesy) | PASS |
| `severity` i `confidence` | osobne, walidowane skale; każda kombinacja dozwolona | `mod::test_severity_and_confidence_are_separate_scales`, `mod::test_every_severity_combines_with_every_confidence` (12) | PASS |
| Czas | tylko UTC w ISO 8601 z `Z` lub `+00:00`; źródło czasu jawne; czas logu bez strefy → `timestamp_utc: null` | `mod::test_utc_time_is_accepted_with_z_or_zero_offset` (3), `mod::test_time_outside_utc_iso_8601_is_rejected` (6), `mod::test_local_time_is_rejected_wherever_utc_is_required` (2), `con::test_log_observation_carries_line_raw_time_utc_time_and_time_source`, `con::test_log_time_that_cannot_be_normalized_is_kept_raw_with_null_utc`, `con::test_timeline_events_name_their_time_source_and_reference_recorded_items` | PASS |
| Reguła `assessment` | tabela przypadków; raport z oceną sprzeczną z regułą jest odrzucany | `mod::test_assessment_rule` (25), `mod::test_scope_is_complete_only_with_all_critical_sources_analyzed` (7), `mod::test_report_whose_assessment_contradicts_the_rule_is_rejected` (5) | PASS |
| Brak ustaleń przy niepełnym zakresie | `INCONCLUSIVE`, status i liczniki źródła, powód, kod wyjścia 3 lub 4 | `con::test_incomplete_scope_without_findings_is_inconclusive` (15), `con::test_unreadable_database_is_failed_coverage_with_the_error_recorded_on_its_evidence`, `con::test_time_limit_hit_during_reverification_makes_every_provided_source_partial` | PASS |
| Pełny zakres | `NO_INDICATORS_IN_ANALYZED_SCOPE`, kod 0; ograniczenia informacyjne nie obniżają statusu | `con::test_complete_scope_without_findings_is_no_indicators_in_analyzed_scope`, `con::test_limitations_that_do_not_shrink_the_scope_stay_listed_as_reasons`, `con::test_large_file_without_content_rules_does_not_shrink_the_scope`, `con::test_disabled_reverification_is_reported_without_changing_the_assessment` | PASS |
| Dowody pominięte | wpis `evidence` ze statusem odczytu i bez skrótu; wpis `CHANGED` zachowuje skrót i identyfikator | `con::test_skipped_entry_is_an_evidence_record_without_a_hash[hardlink, symlink, size-limit, file-count-limit]`, `con::test_entry_changed_after_reading_keeps_the_hash_of_the_analyzed_bytes`, `con::test_modification_time_before_1970_is_recorded_as_a_negative_number` | PASS |
| Observation a Finding | obserwacja bez oceny; ustalenie wskazuje istniejące obserwacje; korelacja wskazuje obserwację pliku i logu | `con::test_observation_states_the_fact_and_leaves_the_rating_to_the_finding`, `con::test_every_finding_of_the_demo_case_rests_on_recorded_observations_and_evidence`, `con::test_correlation_finding_reuses_the_file_and_log_observations`, `con::test_database_observation_names_table_key_and_row`, `con::test_missing_baseline_file_is_observed_on_the_baseline_evidence` | PASS |
| Ustalenia a zakres i kod wyjścia | syntetyczny incydent z `fixtures/` to `SUSPICIOUS`; ustalenia nie ukrywają niepełnego zakresu i nie ustawiają kodu wyjścia | `con::test_demo_case_is_suspicious_not_strong`, `con::test_findings_do_not_hide_an_incomplete_scope_and_do_not_set_the_exit_code`, `con::test_exit_code_follows_coverage` (7), `con::test_stdout_summary_reports_assessment_scope_and_exit_code` | PASS |
| JSON Schema | plik jest poprawnym schematem draft 2020-12; raport z `fixtures/` przechodzi; zepsute warianty odrzucane; wyliczenia i pola zgodne z modelem | `con::test_published_schema_is_a_valid_draft_2020_12_schema`, `con::test_report_generated_for_the_fixtures_validates_against_the_published_schema`, `con::test_schema_rejects_a_deliberately_broken_report` (23), `con::test_schema_enumerations_match_the_model`, `con::test_schema_fields_match_the_fields_the_model_writes` | PASS |
| HTML na nowym raporcie | assessment, pełność zakresu, waga i pewność, tabela pokrycia; nowe pola escapowane | `con::test_html_report_shows_assessment_and_coverage_of_every_source`, `con::test_html_report_shows_severity_and_confidence_side_by_side`, `con::test_html_report_escapes_every_new_field` | PASS |
| Migracja 0.1.0 → `poc-1` | wynik przechodzi model i schemat; `INDICATORS_FOUND` → `SUSPICIOUS`, `NO_INDICATORS_IN_ANALYZED_SCOPE` → `INCONCLUSIVE`; funkcja czysta i deterministyczna; wejście niespójne odrzucane; wpisy powtórzone scalane z notą albo zgłaszane jako konflikt | `mig::test_migrated_demo_*` (9 funkcji), `mig::test_no_indicators_becomes_inconclusive_because_old_coverage_is_unknown`, `mig::test_migration_is_pure_and_deterministic`, `mig::test_old_source_is_resolved_to_manifest_evidence_and_a_structured_location` (6), `mig::test_input_that_is_not_a_consistent_0_1_0_report_is_refused` (21), `mig::test_identical_old_findings_are_merged_and_the_merge_is_reported`, `mig::test_conflicting_old_findings_are_reported_as_a_conflict_not_as_identical` | PASS |

## Zestawienie XFAIL

13 przypadków w 12 funkcjach, wszystkie `xfail(strict=True)`; wszystkie wykonały się jako XFAIL w przebiegu z 2026-11-11 (macOS). Kolumna „Issue” podaje numer z powodu w znaczniku i jego stan na GitHubie.

| Nr | Test | Powód (ze znacznika) | Issue |
|---|---|---|---|
| 1 | `pos::test_p2_checksum_mismatch_names_reference_version` | finding nie niesie wersji referencji; baseline nie ma kontraktu wersji | #6 — otwarte |
| 2 | `pos::test_p5_mu_plugin_added_since_baseline_is_reported` | plik nieobecny w baseline (nowy mu-plugin) nie daje żadnego ustalenia | #6 — otwarte |
| 3 | `pos::test_p6_signature_finding_carries_match_offset` | brak YARA-X; trafienie sygnatury nie ma offsetu ani wersji reguły | #6 — otwarte |
| 4 | `neg::test_n8_premium_plugin_without_checksums_has_no_trusted_reference` | plik bez wpisu w baseline jest pomijany milcząco; brak `NO_TRUSTED_REFERENCE` | #6 — otwarte |
| 5 | `pos::test_p3_admin_added_since_baseline_is_new_since_baseline` | brak porównania dwóch migawek DB i reguły `NEW_SINCE_BASELINE` | #7 — otwarte |
| 6 | `pos::test_p4_option_with_redirect_markup_is_a_database_finding[meta-refresh]` | redirect meta-refresh nie jest objęty regułą opcji | #7 — otwarte |
| 7 | `pos::test_p4_finding_quotes_option_value_with_secret_redacted` | finding DB nie zawiera cytatu wartości, więc nie ma też redakcji | #7 — otwarte |
| 8 | `neg::test_n3_admin_without_trusted_list_appears_in_inventory` | raport nie zawiera inwentarza kont administratorów | #7 — otwarte |
| 9 | `sec::test_s10_lossy_decoding_is_reported_as_coverage_gap[sql-dump]` | stratne dekodowanie SQL (`errors=replace`) nie jest raportowane jako luka | #7 — otwarte |
| 10 | `sec::test_s11_revoked_administrator_capability_is_not_an_admin` | rola wykrywana podłańcuchem `administrator` bez parsowania serializacji PHP: `b:0` liczy się jak `b:1` | #7 — otwarte |
| 11 | `sec::test_s10_lossy_decoding_is_reported_as_coverage_gap[access-log]` | stratne dekodowanie logu (`errors=replace`) nie jest raportowane jako luka | #3 — **zamknięte** |
| 12 | `sec::test_s12_html_report_declares_content_security_policy` | raport HTML nie deklaruje Content-Security-Policy | #3 — **zamknięte** |
| 13 | `sec::test_s13_canary_secret_never_reaches_any_output[log-query-token]` | query string z logu trafia bez redakcji do `metadata.uri` w `report.json` | #3 — **zamknięte** |

| Issue | Liczba | Stan |
|---|---|---|
| #6 (T-201) | 4 | otwarte |
| #7 (T-301) | 6 | otwarte |
| #3 (T-003) | 3 | zamknięte — znaczniki wskazują Issue, które już nie śledzi tych luk |
| #4, #5 | 0 | wszystkie znaczniki zdjęte |

Trzy luki z wierszy 11–13 nie mają dziś otwartego Issue wskazanego w kodzie. `docs/PROGRESS.md` podaje, że luki bez własnego Issue przeniesiono do #13 (logi) i #14 (reguły, HTML, redakcja); #13 jest otwarte, **#14 jest zamknięte**. Zmiana numerów w znacznikach wymaga edycji testów i nie należała do tej aktualizacji.

## Ograniczenia tej macierzy

- Wszystkie dane są syntetyczne; nie mierzono false positive/false negative na reprezentatywnym zbiorze.
- Wyniki pochodzą z jednej platformy (macOS, APFS). Linuksa, Windows, sieciowych systemów plików, punktów montowania wewnątrz drzewa i plików urządzeń nie testowano w tej aktualizacji.
- Testy S-15 i S-17 blokują wywołania na poziomie Pythona i sprawdzają importy; nie zastępują izolacji kontenera. Kontener nie był uruchamiany.
- Wyścigi: deterministyczne haki (`ing`, `sec`) oraz dwa testy z osobnym procesem (`prop`, marker `race`), które są próbkowaniem przez ok. 1,5 s, nie dowodem braku okna.
- Budżety czasu w testach (`time_limit`) używają `SIGALRM`, więc działają tylko na systemach POSIX. Limit czasu narzędzia sprawdzono podstawionym zegarem.
- Parsery SQL i logów nie były fuzzowane; testy własności na losowych drzewach obejmują wyłącznie SecureIngest.
- Testy kontraktu sprawdzają kształt, referencje i regułę oceny; nie mierzą trafności progu `STRONG_INDICATORS` (żadna reguła PoC go nie osiąga). Migracja była sprawdzana na jednym zachowanym raporcie 0.1.0 i na raportach budowanych w teście.
- `pytest --cov` zapisuje plik `.coverage` w katalogu roboczym (jest w `.gitignore`).
