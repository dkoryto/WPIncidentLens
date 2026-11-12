# WPIncidentLens — mapa wymagań i stanu implementacji (T-002, aktualizacja po M2)

**Data:** 2026-11-12. **Stan kodu:** gałąź `main`, commit `6c4cc87` (po scaleniu PR #30, #31, #33 i #32). **Źródło wymagań:** `docs/WPIncidentLens_Specyfikacja_Senior_PoC_2026-11-09.md` (kolumna „Spec”).

Mapa opisuje **stan obecny**, nie plan. Numery linii sprawdzono w kodzie tego commita: odwołania do wierszy, które M2 tylko przesunął, przeniesiono na podstawie porównania plików z commitem `4cac876` i przyjęto tylko tam, gdzie oba końce zakresu są tymi samymi wierszami; odwołania do kodu przeniesionego z `cli.py` do nowych modułów odczytano w kodzie. Każdy wskazany test istnieje i został uruchomiony w pełnym zestawie (macOS, wynik zbiorczy w `docs/TEST_MATRIX.md`).

Skróty modułów: `cli` = `wpincidentlens/cli.py`, `ing` = `wpincidentlens/ingest.py`, `mod` = `wpincidentlens/models.py`, `mig` = `wpincidentlens/migrate.py`, `case` = `wpincidentlens/case.py`, `rep` = `wpincidentlens/report.py`, `files` = `wpincidentlens/files.py`, `fr` = `wpincidentlens/filerules.py`, `integ` = `wpincidentlens/integrity.py`, `wpd` = `wpincidentlens/wpdetect.py`, `fc` = `wpincidentlens/fileclass.py`, `an` = `wpincidentlens/analysis.py`.

Skróty plików testów (`tests/test_*.py`): `cli` = `test_cli`, `pos` = `test_scenarios_positive`, `neg` = `test_negative`, `sec` = `test_security_inputs`, `inv` = `test_invariants`, `ing` = `test_ingest`, `prop` = `test_ingest_properties`, `mod` = `test_models`, `con` = `test_contract`, `mig` = `test_migrate`, `case` = `test_case`, `rw` = `test_report_writer`, `fr` = `test_filerules`, `integ` = `test_integrity`, `wpd` = `test_wpdetect`, `fc` = `test_fileclass`. W kolumnie „Test” pominięto przedrostek `test_`. „XFAIL (#N)” = test istnieje i potwierdza lukę.

## Statusy

| Status | Znaczenie |
|---|---|
| IMPLEMENTED | istnieje kod **i** test, który sprawdza to zachowanie i przeszedł |
| PARTIAL | kod pokrywa tylko część wymagania (z testem lub bez); kolumna „Uwagi” mówi, czego brakuje |
| MISSING | brak kodu |
| UNVERIFIED | kod lub konfiguracja wyglądają na zgodne (albo własność wynika z braku kodu), ale nie ma testu ani pomiaru |

IMPLEMENTED nie oznacza „bezpieczne” ani „kompletne” — tylko że zachowanie z kolumny „Wymaganie” ma pokrycie testem na danych syntetycznych. Żaden wiersz nie przeszedł przeglądu człowieka.

## Podsumowanie: przed M1 → po M1 → po M2

| Status | Przed M1 (commit `903f337`) | Po M1 (wersja pliku sprzed tej aktualizacji) | Po M2 (ten plik) | Zmiana M1 → M2 |
|---|---|---|---|---|
| IMPLEMENTED | 4 | 33 | 40 | +7 |
| PARTIAL | 45 | 44 | 42 | −2 |
| MISSING | 38 | 16 | 11 | −5 |
| UNVERIFIED | 9 | 3 | 3 | 0 |
| **Razem** | **96** | **96** | **96** | |

Liczby „przed M1” policzono z wierszy tabel w `git show 903f337:docs/REQUIREMENTS_TRACEABILITY.md`; „po M1” — z wersji tego pliku na `main` przed tą aktualizacją; „po M2” — z wierszy tego pliku (skryptem, nie szacunkiem). Wiersze grupujące kilka testów (np. `N1–N8`) liczone są jako jeden.

Zmiany statusu w M2: MISSING → IMPLEMENTED: C03, R-47, R-50; MISSING → PARTIAL: R-46, R-51; PARTIAL → IMPLEMENTED: C04, R-21, R-48, P2. Bez zmiany statusu, z nowym stanem w kolumnie „Uwagi”: C05, C10, R-06, R-33, R-45, R-49, R-52, R-56, P5–P6, N1–N8.

Gdzie M2 nie zmienił stanu: parser i reguły bazy (§6), logi (§7), redakcja, CSP i kontener (§8) — to zakres M3–M6.

## 1. Komponenty C01–C12 (Spec §3.2)

| ID | Komponent | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| C01 | CaseManager | PARTIAL | `case:33-60`, `case:109-141`; `case.json`: `rep:127-136` | `case::invalid_identifier_is_refused_before_analysis`, `case::building_the_context_reads_no_evidence_content_and_creates_no_output`, `case::case_json_conforms_to_the_published_schema` | walidacja wywołania i `case.json` są; brak podkomendy `case init` i pól odroczonych w ADR 0003 §9 (`analyst_notes`, `ruleset_id`, `mode`, `source_authorization_confirmed`) |
| C02 | SecureIngest | IMPLEMENTED | `ing:259-544` | `ing::*` (66 funkcji), `prop::*` (18 funkcji), `sec::s01_*`–`s07_*` | odczyt względem deskryptora, hardlinki, limity, ponowna weryfikacja; nie wykrywa punktów montowania, a plik urządzenia jest otwierany przed `fstat` (`ing:8-11`) |
| C03 | WPDetector | IMPLEMENTED | `wpd:110-190`, ustawienia: `wpd:54-67`; wywołanie: `files:26`, `files:32`, `files:45` | `wpd::standard_files_give_candidates_without_finding_or_assessment_change`, `wpd::version_confidence_follows_the_trusted_reference`, `wpd::missing_files_are_noted_not_guessed`, `wpd::version_that_is_not_one_plain_literal_is_not_reported` (11 wariantów), `wpd::duplicated_assignments_stay_candidates_with_low_confidence`, `wpd::conflicting_locale_sources_are_all_reported_without_a_winner` | wersja, wersja bazy, locale i prefiks jako obserwacje-kandydaci z pewnością; nie powstaje z nich ustalenie. Niejednoznaczność to pewność `low` i nota w pokryciu, nie status `AMBIGUOUS` ze specyfikacji. To nie parser PHP (heredoc, `$GLOBALS`, `include` niemodelowane); `wp-config.php` katalog wyżej nie jest widziany; kandydaci nie są porównywani z bazą ani z wersją manifestu |
| C04 | IntegrityAdapter | IMPLEMENTED | `integ:110-293`, manifest: `integ:40-65`, `cli:432-440`; baseline: `cli:412-429`, `case:166-177`; MD5 w tym samym odczycie: `ing:208-225` | `integ::*` (32 funkcje), `pos::p2_modified_core_file_reports_observed_and_reference_hash`, `pos::p2_checksum_mismatch_names_reference_version`, `pos::baseline_file_missing_only_for_files_absent_from_evidence`, `neg::n8_premium_plugin_without_checksums_has_no_trusted_reference` | baseline SHA-256 i lokalny manifest sum rdzenia (MD5 tylko do porównania); brak referencji to `NOT_CHECKED` per klasa, a dla pliku kodu pokrycie `PARTIAL` (ADR 0005 pkt 6). Brak manifestów wtyczek i motywów; wersja i locale manifestu nie są sprawdzane względem witryny (R-46); brak limitu liczby wpisów baseline (tylko 64 MiB pliku) |
| C05 | FileAnalyzer | PARTIAL | pętla: `files:22-46`; reguły: `fr:119-191`, `fr:198-239` | `fr::rule_fires_only_for_its_indicator` (58 przypadków), `fr::content_finding_points_to_the_byte_offset_of_the_first_match`, `fr::oversized_file_covered_by_content_rules_leaves_a_coverage_gap`, `pos::content_rules_fire_only_on_request_driven_exec_in_code_files`, `neg::n2_analytics_snippet_in_theme_file_raises_nothing`, `neg::n5_harmless_php_in_uploads_is_heuristic_not_strong_evidence` | 13 reguł w wersjonowanej tabeli (`docs/RULES.md`), pętla odczytu oddzielona od reguł. Brak parsera PHP (konkatenacja omija reguły); treść plików niebędących kodem, np. obrazu w uploads, nie jest analizowana; brak limitu czasu reguł na plik (czas liniowy sprawdzony testem na 1 MiB); YARA-X brak (R-52) |
| C06 | SQLDumpAdapter | PARTIAL | `cli:50-233` | `sec::s09_escaped_and_multiline_inserts_are_parsed_as_data`, `neg::foreign_sql_is_reported_as_unparsed_not_clean`, `con::sql_that_the_parser_skipped_lowers_database_coverage` | tylko `INSERT`; cały zrzut w pamięci (`cli:252`); instrukcje inne niż `INSERT`/`REPLACE` są liczone jako luka, nie analizowane (patrz R-56) |
| C07 | JSONLDBAdapter | MISSING | — | — | (#7) |
| C08 | WPDataAnalyzer | PARTIAL | `cli:236-332` | `pos::p3_admin_outside_trusted_list_is_flagged_without_attribution`, `pos::p4_option_with_redirect_markup_is_a_database_finding` | users/usermeta/options; brak posts, cron, serializacji |
| C09 | LogParsers | PARTIAL | `cli:334-388` | `pos::p1_upload_php_and_log_request_are_correlated_with_caveat`, `neg::unsupported_log_lines_are_counted_as_coverage_gap` | tylko access log combined; brak `HttpEvent` |
| C10 | RulesEngine | PARTIAL | reguła oceny: `mod:478-507`; tabela reguł plików: `fr:119-191`; reguły integralności w kodzie: `integ:132-136`, `integ:160-225`; reguły bazy i logów w pętlach: `cli:296-299`, `cli:325-328`, `cli:372-381` | `mod::assessment_rule`, `con::observation_states_the_fact_and_leaves_the_rating_to_the_finding`, `fr::every_rule_has_a_positive_case_and_a_documented_false_positive_note` | reguły plików mają identyfikator i wersję; brak wspólnego silnika: reguły integralności, bazy i logów są nadal w kodzie bez wersji; `RULESET_VERSION` (`fr:20`) nie trafia do raportu ani `case.json`; błąd reguły nie jest zamieniany na lukę (wyjątek przerywa przebieg); osobny silnik to zakres M5 (#14 — zamknięte) |
| C11 | Correlator | PARTIAL | `cli:521-535` | `con::correlation_finding_reuses_the_file_and_log_observations` | wyłącznie równość ścieżki plik ↔ URI |
| C12 | Reporter | PARTIAL | `rep:64-76`, `rep:88-114`, `rep:139-151` | `rw::*` (15 funkcji), `con::html_report_escapes_every_new_field` | zapis atomowy per plik i escapowanie są; brak CSP, redakcji i pozostałych plików wyniku (R-40) |

## 2. Warunki bezwzględne (Spec §0, §20)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-01 | Brak wykonania PHP z wejścia | IMPLEMENTED | treść jako bajty: `fr:224-239`, `wpd:80-90` | `inv::s17_full_analysis_runs_with_process_spawning_blocked`, `inv::s17_engine_has_no_dynamic_execution_primitives` | strażnik działa po nazwach wywołań i importów (AST), nie jest piaskownicą |
| R-02 | Brak wykonania SQL | IMPLEMENTED | parser tekstowy: `cli:150-233` | `inv::d4_only_ingest_touches_the_filesystem` (zakaz importu `sqlite3`, `dbm`), `inv::s17_*`, `sec::s09_escaped_and_multiline_inserts_are_parsed_as_data` | brak sterownika DB i zależności runtime (`pyproject.toml:12`) |
| R-03 | Brak połączeń sieciowych | IMPLEMENTED | — | `inv::s15_full_analysis_runs_with_sockets_blocked`, `inv::s15_engine_imports_no_network_modules` | poziom Pythona; izolacja na poziomie OS niezmierzona (R-84) |
| R-04 | Brak ingerencji w wejście | IMPLEMENTED | flagi tylko do odczytu: `ing:31-33`; kolizja wyjścia: `ing:234-256`, `case:94-106` | `inv::s16_analysis_leaves_evidence_tree_unchanged`, `inv::s16_analysis_with_every_flag_leaves_evidence_tree_unchanged`, `prop::sources_are_left_exactly_as_they_were`, `ing::ingest_contains_no_writing_call_or_flag` | porównanie nie obejmuje `atime`; odczyt może go zmienić (brak `O_NOATIME`) |
| R-05 | Brak deklaracji „clean” | IMPLEMENTED | `cli:19`, `mod:45-49` | `cli::no_indicators_not_a_clean_bill` | |
| R-06 | `INCONCLUSIVE` przy brakach krytycznych | IMPLEMENTED | `mod:478-507`; niezweryfikowany kod: `integ:236-249` | `neg::n6_missing_database_and_logs_is_inconclusive`, `con::incomplete_scope_without_findings_is_inconclusive` (15 przypadków), `mod::assessment_rule`, `con::missing_baseline_is_reported_and_leaves_unverified_code_outside_the_scope`, `integ::file_classes_without_a_reference_are_not_checked_and_never_called_clean` | przy istniejących ustaleniach niepełny zakres pokazuje tylko `scope_complete`; od M2 plik kodu bez referencji obniża pokrycie `files` (ADR 0005 pkt 6, zastępuje wariant z ADR 0003); `--no-reverify` nadal nie obniża oceny |

## 3. Intake i bezpieczeństwo plików (Spec §5.2–§5.4)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-10 | Symlink w drzewie `--files` nie jest otwierany | IMPLEMENTED | `ing:31-33`, `ing:349-354`, `ing:177-187` | `sec::s01_site_symlink_outside_root_is_skipped_with_gap`, `cli::symlinks_never_followed`, `ing::symlink_inside_tree_is_skipped_without_following` | |
| R-11 | Symlink w pozostałych wejściach | IMPLEMENTED | `ing:190-205`, `case:131-136` | `sec::s01_symlink_given_as_any_source_is_refused`, `sec::s01_log_symlink_outside_root_is_skipped_with_gap`, `sec::s01_database_symlink_outside_root_is_not_read` | odmowa dotyczy ostatniego składnika ścieżki; dowiązania w składnikach pośrednich ścieżki operatora są akceptowane |
| R-12 | Pliki specjalne z jawnym `SKIPPED_UNSAFE_TYPE` | IMPLEMENTED | `ing:42`, `ing:200-205`, `ing:365-366` | `sec::s03_fifo_in_site_is_skipped_with_gap`, `sec::s03_fifo_in_logs_is_skipped_with_gap`, `ing::unix_socket_is_skipped_without_connecting` | status nazywa się `SKIPPED_SPECIAL`, nie jak w specyfikacji; plików urządzeń nie testowano |
| R-13 | Hardlinki nieotwierane lub oznaczane | IMPLEMENTED | `ing:399-403`, `ing:311-313` | `ing::hardlinked_file_is_not_read_by_default`, `sec::s01_hardlink_to_file_outside_root_is_flagged`, `sec::s01_allow_hardlinks_flag_reads_the_file_and_reports_how_many` | |
| R-14 | Otwarcie odporne na podmianę (`O_NOFOLLOW`/`openat`), test wyścigu | IMPLEMENTED | `ing:168-174`, `ing:349-354` | `ing::entry_swapped_for_symlink_after_enumeration_is_not_followed`, `prop::file_swapped_for_a_symlink_by_another_process_is_never_followed`, `prop::directory_swapped_for_a_symlink_by_another_process_is_never_entered` | wyścig jest próbkowany (ok. 1,5 s na wariant), nie dowodzi braku okna |
| R-15 | Limity: plik, łączny wolumen, liczba plików, długość ścieżki, czas; konfigurowalne | PARTIAL | `ing:68-83`, `ing:337-358`, `ing:398-407`, `cli:601-609`, `case:83-91` | `ing::every_exceeded_limit_produces_a_gap_naming_its_value`, `prop::limits_are_never_exceeded`, `sec::s07_ten_gigabyte_sparse_file_is_skipped_without_hashing`, `case::limit_that_is_not_a_positive_finite_number_is_refused` | limit czasu sprawdzany tylko między wpisami (`ing:337`, `ing:484`): nie obejmuje parserów ani odczytu jednego pliku; brak limitu pamięci; progi SQL/log/treści stałe (`cli:24-27`) |
| R-16 | Odczyt strumieniowy z ograniczoną pamięcią | PARTIAL | `ing:208-225` | `ing::file_larger_than_one_chunk_is_hashed_whole`, `ing::content_above_scan_limit_is_hashed_but_not_retained` | strumieniowy tylko skrót; treść do progu (4 MiB plik kodu, 20 MiB SQL, 30 MiB log, 64 MiB baseline, 8 MiB manifest sum) w całości w pamięci (`cli:24-28`, `cli:252`, `cli:364`, `cli:405`); zużycia pamięci nie mierzono |
| R-17 | Manifest SHA-256 po bajtach źródłowych | IMPLEMENTED | `ing:208-225`, `ing:410-426`, `an:41-45`, `cli:555` | `ing::regular_file_yields_hash_size_and_content_of_the_same_bytes`, `prop::read_records_describe_exactly_the_bytes_on_disk`, `con::read_evidence_records_hash_size_and_modification_time`, `neg::baseline_is_listed_in_evidence_manifest` | manifestem jest `evidence[]` w `report.json`; osobnego `evidence-manifest.json` nie ma (R-40) |
| R-18 | `mtime`/`ctime` jako deklaracja, nie dowód | PARTIAL | `cli:473`, `cli:484`, `mod:89-93` | `con::timeline_events_name_their_time_source_and_reference_recorded_items`, `neg::n7_log_event_time_is_marked_as_unverified_clock` | źródło czasu jest jawne; brak `ctime` i precyzji |
| R-19 | Ponowny skrót i `SOURCE_CHANGED_DURING_ANALYSIS` | IMPLEMENTED | `ing:27`, `ing:308-316`, `ing:461-544` | `ing::change_between_read_and_reverification_is_reported` (6 wariantów), `sec::s02_evidence_changed_after_reading_is_reported_for_every_source` | zmiana cofnięta przed weryfikacją nie jest wykrywana; `--no-reverify` wyłącza kontrolę (z luką) |
| R-20 | Brak obsługi ZIP/TAR | IMPLEMENTED | — | `inv::d4_only_ingest_touches_the_filesystem` (zakaz importu `zipfile`, `tarfile`, `gzip`, `bz2`, `lzma`) | brak testu z archiwum w drzewie; taki plik jest zwykłym wpisem ze skrótem |
| R-21 | `wp-config.php`: bez wykonania, prefiks ze wzorca, maskowanie sekretów | IMPLEMENTED | `wpd:61-66`, `wpd:144-161`; treść jako bajty: `fr:224-239` | `wpd::secrets_next_to_the_prefix_never_reach_any_output` (3 warianty), `wpd::standard_files_give_candidates_without_finding_or_assessment_change`, `sec::s13_canary_secret_never_reaches_any_output[wp-config-password]` | z pliku do raportu trafia tylko prefiks i locale po sprawdzeniu wzorcem; sekrety nie są maskowane, bo żadna inna treść nie jest kopiowana ani cytowana; `wp-config.php` położony katalog wyżej niż witryna nie jest widziany; prefiks nie jest porównywany ze zrzutem SQL |

## 4. Model danych i wynik (Spec §4, §0)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-30 | `Case` z wymaganymi polami | PARTIAL | `case:33-60`, `rep:127-136` | `case::case_json_has_the_case_poc_1_shape`, `case::case_json_times_are_utc_and_ordered` | pola odroczone: ADR 0003 §9 |
| R-31 | `Evidence` z deterministycznym ID i ścieżką logiczną | IMPLEMENTED | `mod:241-288`, `an:41-45` | `mod::evidence_id_changes_with_each_identity_field`, `con::identifiers_do_not_depend_on_the_host_path_or_file_times`, `con::same_named_logs_in_two_directories_are_two_evidence_entries` | pola okoliczności pozyskania odroczone (ADR 0003 §9) |
| R-32 | `Observation` (fakt oddzielony od interpretacji) | IMPLEMENTED | `mod:314-358` | `con::observation_states_the_fact_and_leaves_the_rating_to_the_finding` | bez `source_span` i `detector_id` (ADR 0003 §9) |
| R-33 | `Finding` z wersją reguły, `observations[]`, alternatywami, rekomendacją | PARTIAL | `mod:361-391` | `con::every_finding_of_the_demo_case_rests_on_recorded_observations_and_evidence` | jest `observations[]`; `Finding` nie ma pola `rule_version` — wersję niosą tylko obserwacje reguł treści plików (atrybut `rule_version`, `fr:237`); brak alternatyw i rekomendacji |
| R-34 | `severity` i `confidence` niezależne, z tabelami regresyjnymi | IMPLEMENTED | `mod:52-64`, `mod:489-507` | `mod::severity_and_confidence_are_separate_scales`, `mod::every_severity_combines_with_every_confidence`, `mod::assessment_rule` (25 przypadków) | wartości reguł plików są w tabeli `fr:119-191`; reguł integralności, bazy i logów — stałymi w kodzie (`integ`, `cli`) |
| R-35 | `Coverage` per źródło ze statusami | IMPLEMENTED | `mod:394-437`, `cli:443-460` | `mod::coverage_status_must_agree_with_its_counters_and_reasons`, `con::incomplete_scope_without_findings_is_inconclusive` | bez liczników wierszy SQL i logu (ADR 0003 §9) |
| R-36 | Cztery stany `assessment` | IMPLEMENTED | `mod:45-49`, `mod:494-507` | `mod::assessment_rule`, `mod::report_whose_assessment_contradicts_the_rule_is_rejected` | `STRONG_INDICATORS` nieosiągalny dla obecnych reguł (`con::demo_case_is_suspicious_not_strong`) |
| R-37 | Inwarianty referencji finding → observation → evidence | IMPLEMENTED | `mod:571-583` | `mod::dangling_reference_is_rejected` (5 wariantów), `mod::duplicate_identifier_is_rejected` | |
| R-38 | Deterministyczny porządek wyników | IMPLEMENTED | `mod:562-569`, `ing:161-165` | `inv::s18_two_runs_on_same_evidence_give_identical_json`, `con::reports_from_processes_with_different_hash_seeds_are_identical`, `mod::report_order_does_not_depend_on_the_order_of_its_inputs` | |
| R-39 | Wersjonowany schemat z JSON Schema i migracją | IMPLEMENTED | `mod:25`, `mig:170-211`, `docs/schema/report-poc-1.schema.json` | `con::report_generated_for_the_fixtures_validates_against_the_published_schema`, `mig::migrated_demo_report_satisfies_the_model_contract_and_the_published_schema` | migracja nie ma wejścia w CLI |
| R-40 | Komplet plików wyniku (`case.json` … `run.log`) | PARTIAL | `rep:25-27`, `rep:139-151` | `rw::run_leaves_only_the_result_files_in_the_output_directory` | `report.json`, `report.html`, `case.json`; brak `evidence-manifest.json`, `observations.jsonl`, `findings.json`, `timeline.json`, `coverage.json`, `run.log` |

## 5. Pliki WordPressa (Spec §6)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-45 | WP-FILE-001 PHP w uploads | IMPLEMENTED | `fr:57-58`, `fr:121-123`, `fr:208-213` | `pos::p1_upload_php_and_log_request_are_correlated_with_caveat`, `neg::n5_harmless_php_in_uploads_is_heuristic_not_strong_evidence`, `sec::unread_php_in_uploads_is_still_reported_by_path`, `sec::unread_file_outside_uploads_gives_no_finding`, `fr::rule_fires_only_for_its_indicator` | sztywny prefiks `wp-content/uploads/` (`fr:24`); rozszerzenia z `fr:22` |
| R-46 | WP-FILE-002 core vs manifest wersji/locale | PARTIAL | `integ:170-182`, `integ:40-65`, `cli:432-440`; flaga: `cli:588-590` | `integ::core_checksum_mismatch_reports_both_digests_and_the_reference`, `integ::manifest_nested_under_a_version_key_supplies_the_reference_version`, `integ::core_file_matching_the_manifest_gives_no_finding_and_md5_stays_out_of_evidence`, `integ::unusable_core_manifest_is_a_usage_error_that_echoes_no_value` (25 wariantów), `pos::p2_checksum_mismatch_names_reference_version` | ustalenie `CORE_CHECKSUM_MISMATCH` niesie oba skróty MD5, SHA-256 pliku i wersję referencji. Brakuje: pola locale manifestu (jest tylko wolny opis `reference`) i sprawdzenia, że manifest odpowiada wersji i locale wykrytym w witrynie — manifest innej wersji daje rozbieżności opisane tylko w wyjaśnieniu; manifest dostarcza operator, narzędzie nie zapisuje jego pochodzenia poza skrótem pliku |
| R-47 | WP-FILE-003 nowy plik w `mu-plugins` | IMPLEMENTED | `integ:165-169`, `integ:208-212`; klasy: `fc:27` | `pos::p5_mu_plugin_added_since_baseline_is_reported`, `integ::new_autoloaded_file_is_a_finding_that_does_not_claim_compromise` (2 warianty), `integ::unread_entry_in_autoloaded_location_is_reported_by_path_with_low_confidence`, `integ::unread_mu_plugins_directory_itself_is_reported_by_path` (2 warianty); negatywny: `integ::file_absent_from_baseline_is_not_a_finding_outside_autoloaded_locations` (6 wariantów) | `NEW_FILE_SINCE_BASELINE` także dla drop-ins; wymaga niepustego `baseline.files`; nowy plik we wtyczce lub motywie to `NOT_CHECKED` i nota `NO_TRUSTED_REFERENCE`, nie ustalenie |
| R-48 | WP-FILE-004 wzorce zaciemnienia | IMPLEMENTED | `fr:133-138`, `fr:155-165`, `fr:224-239` | `pos::p6_synthetic_webshell_marker_is_a_heuristic_finding`, `pos::p6_signature_finding_carries_match_offset`, `fr::rule_fires_only_for_its_indicator`, `fr::content_finding_points_to_the_byte_offset_of_the_first_match` (10 reguł), `fr::matched_content_never_reaches_the_report` | `SUSPICIOUS_PHP_EVAL_DECODE`, `PHP_PREG_REPLACE_EVAL`, `LONG_ENCODED_BLOB` z identyfikatorem, wersją i offsetem; dopasowanie tekstu, nie składni PHP — konkatenacja, komentarz w środku wywołania i serie odstępów powyżej 16 znaków omijają reguły (`docs/RULES.md`, Ograniczenia) |
| R-49 | WP-FILE-005 nietypowy plik wykonawczy w mediach | PARTIAL | `fr:49-62`, `fr:124-131`, `fr:214-220` | `fr::rule_fires_only_for_its_indicator`, `fr::path_rules_report_a_file_that_was_not_read` (2 warianty), `fr::code_hidden_behind_a_double_extension_is_content_scanned`, `fr::code_in_static_core_directory_is_more_confident_than_in_languages` | `DOUBLE_EXTENSION_IN_UPLOADS` i `CODE_IN_UNEXPECTED_LOCATION` działają po nazwie i położeniu; typ treści nie jest badany, więc PHP w pliku o zwykłej nazwie obrazu nie jest wykrywany |
| R-50 | WP-FILE-006 `.htaccess`, `.user.ini`, `auto_prepend_file` | IMPLEMENTED | `fr:177-190`, `fr:69-79` | `fr::rule_fires_only_for_its_indicator` (przypadki `.htaccess`, `.user.ini`, `php.ini`), `fr::s08_hostile_content_does_not_stall_the_file_rules` | `HTACCESS_ENABLES_PHP_IN_UPLOADS` i `PHP_AUTO_PREPEND_CONFIG`; druga trafia też w legalne konfiguracje zapór aplikacyjnych (pewność `low`); obserwacja podaje offset i długość, bez nazwy dyrektywy; inne dyrektywy `.htaccess` (np. przekierowania) nie mają reguły |
| R-51 | Klasyfikacja plików (CORE, PLUGIN, …) | PARTIAL | `fc:7-45` | `fc::standard_layout_paths_get_their_class` (12 wariantów), `fc::paths_outside_the_standard_layout_are_other` (6 wariantów), `integ::file_classes_without_a_reference_are_not_checked_and_never_called_clean` | klasa wyłącznie z położenia w standardowym układzie: CORE, CONFIG, DROPIN, MU_PLUGIN, PLUGIN, THEME, UPLOAD, LANGUAGE, OTHER; brak rozróżnienia pochodzenia ze specyfikacji (`PLUGIN_ORG`/`PLUGIN_PREMIUM`, `THEME_ORG`/`THEME_CUSTOM`); klasa trafia do raportu tylko w notach `NOT_CHECKED` i atrybucie `file_class` |
| R-52 | YARA-X z wersjonowanym pakietem | MISSING | — | — | wyłączone z M2 (ADR 0005 pkt 5); kształt wyniku reguł wbudowanych (identyfikator, wersja, offset, długość) przygotowany pod adapter; osobnego Issue jeszcze nie ma |

## 6. Baza danych (Spec §7)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-55 | Ograniczona gramatyka mysqldump, strumieniowo | PARTIAL | `cli:84-233`, `cli:252` | `sec::s09_escaped_and_multiline_inserts_are_parsed_as_data`, `sec::s08_statement_scanner_is_linear_on_crafted_sql` | tylko `INSERT`; cały plik w pamięci |
| R-56 | Nierozpoznane dane → `SQL_PARSE_GAP` | PARTIAL | `cli:300-317`, `cli:331` | `neg::foreign_sql_is_reported_as_unparsed_not_clean`, `neg::unsupported_statement_next_to_supported_one_adds_a_gap`, `con::sql_that_the_parser_skipped_lowers_database_coverage` (22 przypadki) | luki są tekstami, bez kodu `SQL_PARSE_GAP`; instrukcje inne niż `INSERT`/`REPLACE` (np. `UPDATE`, `CREATE TRIGGER`) są liczone i obniżają pokrycie (`cli:310-314`), ale nie są analizowane (#7) |
| R-57 | Prefiks tabel inny niż `wp_` | PARTIAL | `cli:99`, `cli:263`, `cli:269`, `cli:278`, `cli:287` | `cli::sql_rows_and_prefix`, `cli::poc_end_to_end` (fixture z prefiksem `demo_`) | dopasowanie po sufiksie łapie też tabele wtyczek |
| R-58 | `UNSUPPORTED_MULTISITE` | MISSING | — | — | tylko wzmianka w stałej nocie (`cli:331`) |
| R-59 | Dekoder serializacji PHP data-only | MISSING | `cli:285` | XFAIL (#7): `sec::s11_revoked_administrator_capability_is_not_an_admin` | wyszukiwanie podciągu `administrator` |
| R-60 | WP-DB-001 administrator względem baseline | PARTIAL | `cli:318-328` | `pos::p3_admin_outside_trusted_list_is_flagged_without_attribution`, `neg::trusted_admin_is_not_flagged`, `neg::admin_capability_without_user_row_is_not_silently_dropped`; XFAIL (#7): `pos::p3_admin_added_since_baseline_is_new_since_baseline` | lista loginów, nie porównanie dwóch migawek |
| R-61 | Administrator bez baseline = inwentaryzacja | PARTIAL | `cli:329-330` | `neg::n3_admin_without_trusted_list_is_a_gap_not_an_alert`; XFAIL (#7): `neg::n3_admin_without_trusted_list_appears_in_inventory` | nota zamiast alertu; brak listy kont |
| R-62 | WP-DB-002, 004, 005, 006 | MISSING | — | — | (#7) |
| R-63 | WP-DB-003 JS/redirect w `options` | PARTIAL | `cli:296-299` | `pos::p4_option_with_redirect_markup_is_a_database_finding` (3 warianty), `neg::n2_analytics_snippet_in_option_is_only_a_low_confidence_review_item`; XFAIL (#7): wariant `meta-refresh`, `pos::p4_finding_quotes_option_value_with_secret_redacted` | brak cytatu z redakcją i offsetu |
| R-64 | `user_pass` i zbędne dane nie trafiają do wyniku | IMPLEMENTED | `cli:269-277` | `sec::s13_canary_secret_never_reaches_any_output[user-pass-column]` | |

## 7. Logi i korelacja (Spec §8, §9.3)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-70 | Parser Apache/Nginx combined | PARTIAL | `cli:334`, `cli:364-381` | `pos::p1_upload_php_and_log_request_are_correlated_with_caveat`, `sec::s08_crafted_log_line_does_not_stall_the_log_pattern` | bez bytes, referera, user-agenta |
| R-71 | Niesparsowane wiersze raportowane | IMPLEMENTED | `cli:382-387` | `neg::unsupported_log_lines_are_counted_as_coverage_gap` | |
| R-72 | UTC z zachowaniem czasu surowego i niepewności zegara | PARTIAL | `cli:336-341`, `cli:373-379`, `cli:473` | `con::log_observation_carries_line_raw_time_utc_time_and_time_source`, `con::log_time_that_cannot_be_normalized_is_kept_raw_with_null_utc` | niepewność tylko opisowo |
| R-73 | `X-Forwarded-For` i zaufane proxy | PARTIAL | `cli:334` | `sec::s14_forged_forwarded_for_is_not_used_as_client_address` | adresem klienta jest pole połączenia; brak konfiguracji zaufanych proxy (#13) |
| R-74 | Redakcja `HttpEvent` (tokeny, IP, user-agent) | MISSING | `cli:378` | XFAIL (#14): `sec::s13_canary_secret_never_reaches_any_output[log-query-token]` | URI z query stringiem (do 300 znaków) i IP w `report.json` |
| R-75 | Typy relacji, nigdy `PROVEN_EXPLOIT` | PARTIAL | `cli:531-534` | `con::correlation_finding_reuses_the_file_and_log_observations` | jeden typ; zastrzeżenie w treści |
| R-76 | Agregacja powtórnych zdarzeń | MISSING | `cli:380` | — | jedno ustalenie na wiersz logu, bez limitu liczby |

## 8. Bezpieczeństwo, prywatność, kontener (Spec §10)

| ID | Wymaganie | Status | Kod / konfiguracja | Test | Uwagi |
|---|---|---|---|---|---|
| R-80 | XSS: escape, CSP, brak JS | PARTIAL | `rep:89-114` | `sec::s12_markup_from_evidence_is_escaped_in_html_report` (5 wariantów), `con::html_report_escapes_every_new_field`, `cli::report_escapes_html`; XFAIL (#14): `sec::s12_html_report_declares_content_security_policy` | escape tak; brak CSP; szablon to f-string z ręcznym `esc` |
| R-81 | Redakcja sekretów i danych osobowych | PARTIAL | ścieżki hosta: `ing:437-457`, `mod:262-263`, `case:71-74` | `sec::report_never_contains_an_absolute_host_path`, `prop::report_and_html_name_no_host_path_and_no_content_from_outside`, `case::case_json_contains_no_host_path` | ścieżki hosta nie trafiają do plików wyniku; redakcji query stringów, `--pseudonymize` i ostrzeżenia o danych osobowych (ADR 0002 B8) nie ma; podsumowanie na stdout podaje bezwzględną ścieżkę raportu (`cli:641-642`) |
| R-82 | Odporność na patologie regexów, timeouty | PARTIAL | `cli:50-78`, `cli:84-98`, `cli:334`, `fr:83-114`, `wpd:26-34` | `sec::s08_crafted_insert_does_not_stall_the_sql_parser`, `sec::s08_unterminated_insert_headers_do_not_stall_the_sql_parser`, `sec::s08_repetitive_php_does_not_stall_the_file_rules`, `sec::s08_crafted_log_line_does_not_stall_the_log_pattern`, `fr::s08_hostile_content_does_not_stall_the_file_rules` (26 przypadków, 1 MiB), `wpd::hostile_version_file_is_handled_in_bounded_time_without_a_guess` (7 wariantów) | brak limitu czasu wewnątrz parserów i reguł; brak fuzzingu |
| R-83 | Łańcuch dostaw: piny, hashe, SBOM | PARTIAL | `pyproject.toml:12`, `pyproject.toml:16-17`, `.github/workflows/ci.yml:20`, `:23` | — | brak lock, SBOM, audytu |
| R-84 | Kontener: non-root, ro rootfs, bez sieci, bez capabilities, limity | UNVERIFIED | `docker/Dockerfile:5`, `docker/compose.yaml:7-16` | — | deklaracja; pomiar NOT RUN (M6) |
| R-85 | Dowody montowane tylko do odczytu | UNVERIFIED | `docker/compose.yaml:18-20` | — | deklaracja |
| R-86 | Obraz przypięty do digestu | MISSING | `docker/Dockerfile:2` | — | |
| R-87 | Tekst z dowodów nie jest instrukcją | UNVERIFIED | — | — | brak interpretacji i LLM w kodzie; brak fixture z „instrukcją” |

## 9. CLI (Spec §11)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-90 | Podkomendy `case init`, `analyze`, `report verify`, `version` | MISSING | `cli:579-610` | — | płaskie CLI |
| R-91 | Kody wyjścia 0/2/3/4/5 | PARTIAL | `cli:21`, `cli:568-572`, `cli:620`, `cli:627`, `cli:633`, `cli:640` | `con::exit_code_follows_coverage` (7 przypadków), `con::findings_do_not_hide_an_incomplete_scope_and_do_not_set_the_exit_code`, `neg::malformed_baseline_is_rejected_as_usage_error` | 0/2/3/4 są; brak kodu 5 — nieobsłużony wyjątek (np. `OSError` przy zapisie) kończy proces kodem 1 Pythona |
| R-92 | Zapis atomowy, bez nadpisania bez `--force` | PARTIAL | `rep:53-76` | `rw::failed_write_leaves_no_partial_or_temporary_file`, `rw::failed_write_keeps_the_previous_results_intact`, `rw::symlink_named_like_a_result_is_replaced_and_its_target_left_untouched` | każdy plik zamieniany atomowo; zamiana trzech plików nie jest jedną operacją; istniejące wyniki są zastępowane bez `--force` (flagi nie ma) |
| R-93 | Walidacja ścieżek przed odczytem | IMPLEMENTED | `case:109-141`, `ing:228-231` | `case::building_the_context_reads_no_evidence_content_and_creates_no_output`, `ing::unusable_source_root_is_refused_by_name_of_error` | |
| R-94 | Wyjście poza katalogiem źródeł | IMPLEMENTED | `ing:234-256`, `case:94-106` | `cli::output_cannot_be_inside_evidence`, `inv::s16_output_overlapping_any_source_is_refused_before_anything_is_written` (4 warianty), `ing::output_overlapping_a_source_is_refused` (6 wariantów) | obejmuje wszystkie źródła |

## 10. Matryca testów i jakość (Spec §14, §13.2)

Szczegóły i lista XFAIL: `docs/TEST_MATRIX.md`.

| ID | Wymaganie | Status | Test | Uwagi |
|---|---|---|---|---|
| P1 | PHP w uploads + log, z opisem ograniczeń | IMPLEMENTED | `pos::p1_upload_php_and_log_request_are_correlated_with_caveat` | |
| P2 | Modyfikacja core z manifestem | IMPLEMENTED | `pos::p2_modified_core_file_reports_observed_and_reference_hash`, `pos::p2_checksum_mismatch_names_reference_version`, `integ::core_checksum_mismatch_reports_both_digests_and_the_reference` | baseline SHA-256 i manifest MD5; zgodność manifestu z wersją witryny niesprawdzana (R-46) |
| P3 | Admin dodany w nowszej migawce | PARTIAL | `pos::p3_admin_outside_trusted_list_is_flagged_without_attribution` | lista loginów zamiast migawek; `NEW_SINCE_BASELINE` XFAIL (#7) |
| P4 | Opcja z podejrzanym redirectem | PARTIAL | `pos::p4_option_with_redirect_markup_is_a_database_finding` | meta-refresh i cytat z redakcją XFAIL (#7) |
| P5–P6 | Persistence; sygnatura YARA | PARTIAL | `pos::p5_changed_mu_plugin_is_reported_against_baseline`, `pos::p5_mu_plugin_added_since_baseline_is_reported`, `pos::p6_synthetic_webshell_marker_is_a_heuristic_finding`, `pos::p6_signature_finding_carries_match_offset` | nowy mu-plugin i offset trafienia przechodzą; cron bez testu (#7); sygnatura to reguła wbudowana z wersją i offsetem, nie YARA-X (R-52) |
| N1–N8 | Scenariusze negatywne | PARTIAL | `neg::n1_*`–`neg::n8_*` | N8 przechodzi (nota `NO_TRUSTED_REFERENCE` i `NOT_CHECKED`); N3 (inwentarz) XFAIL (#7); N7 bez testu ścisłej korelacji czasowej (#13) |
| S-01 | Symlink poza root | IMPLEMENTED | `sec::s01_*` (8 funkcji) | wszystkie źródła, hardlink, klucze baseline |
| S-02–S-08 | Wyścig, FIFO, długie nazwy, Unicode, limity, sparse, regex | PARTIAL | `sec::s02_*`–`sec::s08_*`, `prop::*swapped*`, `fr::s08_hostile_content_does_not_stall_the_file_rules` (26 przypadków), `wpd::hostile_version_file_is_handled_in_bounded_time_without_a_guess` (7 wariantów) | bez testu miliona plików i timeoutu YARA (YARA-X brak); nazwa spoza UTF-8 (S-05) SKIP na macOS |
| S-09 | SQL wielowierszowy/escapowany | IMPLEMENTED | `sec::s09_escaped_and_multiline_inserts_are_parsed_as_data`, `sec::s09_truncated_insert_yields_no_rows` | |
| S-10–S-11 | Uszkodzony UTF-8; obiekt PHP serialized | PARTIAL | `sec::s10_invalid_utf8_does_not_hide_indicators`, `sec::s10_lossy_decoding_is_reported_as_coverage_gap` (2 warianty), `sec::s11_serialized_php_object_is_inert_text` | stratne dekodowanie SQL i logu daje lukę; `b:0` XFAIL (#7) |
| S-12 | HTML z `<script>`/`onerror` | PARTIAL | `sec::s12_markup_from_evidence_is_escaped_in_html_report` | CSP XFAIL (#14) |
| S-13–S-15 | Canary; XFF; brak sieci | PARTIAL | `sec::s13_*`, `sec::s14_*`, `inv::s15_*`, `wpd::secrets_next_to_the_prefix_never_reach_any_output` | token w query stringu XFAIL (#14); brak konfiguracji proxy; izolacja OS niezmierzona |
| S-16 | Brak zapisu w evidence | IMPLEMENTED | `inv::s16_*` (4 funkcje), `prop::sources_are_left_exactly_as_they_were` | bez `atime` |
| S-17–S-18 | Brak uruchomienia PHP; determinizm | IMPLEMENTED | `inv::s17_*`, `inv::s18_*` | |
| Q-01 | Fuzzing parserów (Hypothesis) | MISSING | — | parsery SQL i logów bez fuzzingu; testy własności na losowych drzewach (`prop`) obejmują tylko SecureIngest |
| Q-02 | Benchmark wydajności i pamięci | MISSING | — | |
| Q-03 | `ruff`, `mypy`, skan zależności | PARTIAL | — | tylko `ruff` z regułami `E9`, `F` (`pyproject.toml:40`) |

## Rozbieżności dokumentacji zauważone przy mapowaniu

Stan na commit `6c4cc87`. Trzy rozbieżności w `README.md` z poprzedniej wersji tej listy (odsyłacz do `docs/BASELINE.md` po aktualne wyniki, izolacja kontenera opisana jako fakt, zdanie o raporcie HTML) poprawiono razem z tą aktualizacją; poprawki w `wpincidentlens/` i `tests/` nie należały do tego zadania.

- `README.md:88` nadal zaleca `chmod 777` dla katalogu wyników pokazu w kontenerze (R-84).
- ADR 0002 B8 zapowiada redakcję wartości query string, flagę `--pseudonymize` i ostrzeżenie o danych osobowych; w kodzie ich nie ma (R-74, R-81). ADR 0002 D3 zapowiada CSP `default-src 'none'`; `rep:107` jej nie deklaruje.
- ADR 0003 §2 podaje jako pola tożsamości dowodu bez skrótu `read_status` i `read_reason`; kod składa je w jedno pole `unread` (`mod:275-277`). Skutek jest ten sam, zapis inny.
- Znaczniki XFAIL dla CSP i redakcji query stringu wskazują Issue #14, a mitygacje kontenera — #15; oba są na GitHubie **zamknięte** (stan z `gh issue list --state all`, 2026-11-12), choć ich zakres nie jest zrealizowany. Otwarte są #6, #7 i #13.
- `tests/test_ingest_properties.py:584` i `:613` mają komentarze „własności, których kod dziś NIE spełnia” i „sam wpis jej nie niesie”; oba testy pod nimi przechodzą, komentarze są nieaktualne.
- Numeracja ticketów w specyfikacji §13.1 (T-001 „model Case” itd.) różni się od numeracji Issues (T-001 = baseline/CI); w tym repozytorium obowiązuje numeracja Issues.
- ADR 0003 („brak baseline nie czyni zakresu niepełnym”) jest w tej części zastąpiony przez ADR 0005 pkt 6; w ADR 0003 dopisano notę. `docs/M1_GATE.md` opisuje stan z 2026-11-11 (m.in. kod 0 dla demo) i ma dopisaną notę z datą 2026-11-12.
- Pomoc CLI (`cli:581-583`) opisuje kod 3 jako „brak źródła, pominięte lub zmienione wpisy, limit” i nie wymienia pliku kodu bez zaufanej referencji, który od M2 także daje kod 3. Tekst pomocy jest w kodzie, więc nie był zmieniany.
- YARA-X (R-52) wyłączono z M2 decyzją ADR 0005 pkt 5 jako „osobne Issue”, ale takiego Issue nie ma.
- Treść Issue #6 odsyła do `docs/WPTrace_Specyfikacja_Senior_PoC_2026-11-09.md`; plik nazywa się dziś `docs/WPIncidentLens_Specyfikacja_Senior_PoC_2026-11-09.md` (ADR 0004).
