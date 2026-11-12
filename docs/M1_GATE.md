# Raport z bramki M1 — bezpieczny intake i kontrakty danych

| | |
|---|---|
| **Data** | 2026-11-11 |
| **Stan kodu** | gałąź `agent/T-101-case-manager`, commit `4cac876` — PR #27 (otwarty), zawiera też commity PR #26 (otwarty). **Kod M1 nie jest scalony z `main`.** |
| **Autor** | agent kodujący; raport jest oceną agenta, **nie decyzją o przejściu bramki** |
| **Bramka** (`docs/MASTER_AGENT_PROMPT.md`) | „testy bezpieczeństwa wejść przechodzą, źródła pozostają niezmienione, każda nieobsłużona sytuacja tworzy gap” |
| **Zakres M1** | T-101 (#4) CaseManager + SecureIngest; T-102 (#5) kontrakty `poc-1`; poprawki T-005 (#17) i T-006 (#18) |
| **Decyzja** | należy do właściciela repozytorium (§7) |

Powiązane dokumenty: `docs/TEST_MATRIX.md` (wyniki i lista testów), `docs/THREAT_MODEL.md` (Z-01–Z-17), `docs/REQUIREMENTS_TRACEABILITY.md` (mapa wymagań), ADR 0002 i ADR 0003.

> **Nota 2026-11-12 (po M2, commit `6c4cc87`).** Raport opisuje stan z 2026-11-11 i nie był przepisywany; numery linii `wpincidentlens/cli.py` i `ingest.py` oraz liczby testów dotyczą commita `4cac876`. Po scaleniu M2 (PR #30–#33, ADR 0005) nieaktualne są następujące stwierdzenia:
>
> - §1 i tabela kodów wyjścia: pokaz na `fixtures/` nie kończy się już kodem 0 z `scope_complete: true`, tylko kodem 3 z `scope_complete: false` — plik kodu bez zaufanej referencji obniża pokrycie `files` (ADR 0005 pkt 6). Kod 0 wymaga dodatkowo, żeby każdy plik kodu miał wpis w baseline albo w manifeście sum rdzenia.
> - „Brak baseline nie czyni zakresu niepełnym” (wariant z ADR 0003) jest zastąpiony w części przez ADR 0005 pkt 6.
> - Luki nr 3 i 6 („plik nieobecny w baseline”, „`.htaccess` i `.user.ini` bez reguły”): plik spoza referencji jest liczony w `NOT_CHECKED` i dla kodu obniża pokrycie, nowy plik w mu-plugins lub drop-in daje ustalenie `NEW_FILE_SINCE_BASELINE`, a pliki konfiguracji mają reguły `HTACCESS_ENABLES_PHP_IN_UPLOADS` i `PHP_AUTO_PREPEND_CONFIG`. Luki nr 1, 2 i 5 (stratne dekodowanie, instrukcje SQL inne niż `INSERT`/`REPLACE`) zamknęły już poprawki opisane w §0 tego raportu (PR #28).
> - Test `sec::test_s01_traversal_keys_in_baseline_are_compared_but_never_opened` nazywa się teraz `sec::test_s01_traversal_keys_in_baseline_are_refused_before_analysis`: klucz baseline z `../` albo ścieżką bezwzględną jest odrzucany przed analizą (kod 2).
> - Funkcja `scan_files` nie jest już w `cli.py`, tylko w `wpincidentlens/files.py`.
>
> Stan aktualny: `docs/TEST_MATRIX.md`, `docs/THREAT_MODEL.md`, `docs/REQUIREMENTS_TRACEABILITY.md`, `docs/PROGRESS.md`.

> **Nota 2026-11-12 (po M6, `main` `2db956c`).** Po scaleniu M6 (PR #61–#66, #68, #69, ADR 0009) nieaktualne są następujące stwierdzenia tego raportu:
>
> - §4 („Kontener niezmierzony”) i §7 („kontener nie był mierzony”): izolację kontenera mierzy zadanie CI `container` (`.github/workflows/container.yml`, sonda `docker/probe.py`, runner `ubuntu-24.04`) — na `main` `2db956c` 21/21 sprawdzeń PASS (UID/GID 65532, rootfs i dowody tylko do odczytu, `/tmp` `noexec`, capability 0, `NoNewPrivs`, tylko `lo`, limity cgroup). Pomiar odbywa się wyłącznie w CI, nie lokalnie.
> - §5 (ADR 0002 D9 „odłożona do M6”): ADR 0009 pkt 6 rozstrzygnął D9 — izolacja parserów w osobnym procesie **nie teraz**.
> - §5 i §8 (Issue #14 i #15 „zamknięte”): oba zostały ponownie otwarte 2026-11-12; kod M5 i M6 jest scalony, zamknięcie należy do właściciela. Tabela etapów w §8: M6 wykonany w kodzie (PR #61–#66, #68, #69), w tym fuzzing ze strukturą, benchmarki i pomiar kontenera; Linux mierzony tylko w CI.
> - §7 (warunek B10): pomiar kontenera się odbył, ale zakaz pracy na realnym materiale trwa — ADR 0009 pkt 7 przedłuża go do bramki GO/NO-GO (M7) z przeglądem człowieka; bramka M1 nadal nie jest zatwierdzona przez właściciela.

## 1. Co uruchomiono

Świeże środowisko (`uv venv --python 3.12`, `pip install -e '.[dev]'`), macOS 27.0.1 (Darwin 27.0.0, arm64, APFS), Python 3.12.11, pytest 8.4.2, ruff 0.8.6.

| Komenda | Wynik |
|---|---|
| `python -m ruff check .` | All checks passed (reguły `E9`, `F`) |
| `python -m pytest -q` | **1853 passed, 5 skipped, 13 xfailed** |
| `python -m pytest -q --cov=wpincidentlens --cov-report=term-missing` | ten sam wynik; pokrycie liniowe **99%** (`cli.py` 98%, `ingest.py` 98%, `migrate.py` 99%, `case.py`, `models.py`, `report.py` 100%) |
| `python -m pytest -v` | ten sam wynik (trzeci przebieg) |
| `python -m wpincidentlens … --case-id DEMO-001` na `fixtures/` | kod 0, `SUSPICIOUS`, `scope_complete: true`, 6 ustaleń |

Linuksa, Windows i kontenera nie uruchamiano. Wynik z Linuksa znany jest wyłącznie z opisu PR #27 („1856 passed, 2 skipped, 13 xfailed”, kontener `python:3.12-slim`, `--network none`, uid 1000 — pomiar agenta prowadzącego, tutaj nieodtworzony). Wyniku CI dla PR #27 nie sprawdzano.

## 0. Aktualizacja po raporcie (2026-11-11)

Raport poniżej opisuje stan sprzed poprawek wywołanych jego własnym werdyktem dla K3. Po nim agent prowadzący zmienił kod tak, żeby cztery z sześciu rodzajów treści pomijanych bez luki (§2.3) zostawiały ślad:

| Nr z §2.3 | Sytuacja | Stan po poprawce | Test |
|---|---|---|---|
| 1, 2 | Stratne dekodowanie SQL i logu | pokrycie źródła `PARTIAL` z nazwanym powodem | `sec::test_s10_lossy_decoding_is_reported_as_coverage_gap[sql-dump, access-log]` — PASS |
| 3 | Plik obecny w materiale, nieobecny w baseline | nota `NO_TRUSTED_REFERENCE` z liczbą i przykładami w `coverage_gaps`; **nie** obniża pokrycia (pliki spoza baseline to norma, np. uploads) i nadal nie daje ustalenia | `neg::test_n8_premium_plugin_without_checksums_has_no_trusted_reference` — PASS |
| 5 | Instrukcje SQL inne niż `INSERT`/`REPLACE` (`UPDATE`, `DELETE`, `CREATE TRIGGER`, `CALL`…) | pokrycie bazy `PARTIAL`, powód wymienia słowa kluczowe i liczby; definicje tabel i ustawienia sesji z mysqldump nie obniżają pokrycia | `contract::test_sql_that_the_parser_skipped_lowers_database_coverage[update-statement, delete-statement, create-trigger, drop-view, call-procedure, …]` — PASS |

Pozostają bez zmian: rola administratora cofnięta w serializacji (`b:0`, #7) i brak jakiejkolwiek reguły dla `.htaccess` / `.user.ini` (#6). Oba to braki detekcji, nie odczytu.

Wynik po poprawkach (pomiar agenta prowadzącego): macOS — 1864 passed, 5 skipped, 10 xfailed; Linux w kontenerze `python:3.12-slim`, `--network none`, uid 1000 — 1867 passed, 2 skipped, 10 xfailed. Liczby w §1 i §5.1 pochodzą sprzed poprawek.

**Werdykt K3 po poprawkach: SPEŁNIONE Z ZASTRZEŻENIAMI** — każda sytuacja, o której wiadomo, że narzędzie jej nie obsługuje na poziomie odczytu i parserów, zostawia lukę; zastrzeżeniem są dwa braki detekcji powyżej oraz to, że wykrywanie nieanalizowanych instrukcji SQL jest heurystyką nałożoną na parser PoC (ścisły parser: #7).

## 2. Werdykt agenta

| Nr | Kryterium bramki | Werdykt | Jedno zdanie |
|---|---|---|---|
| K1 | Testy bezpieczeństwa wejść przechodzą | **SPEŁNIONE Z ZASTRZEŻENIAMI** | Wszystkie testy odczytu wejść (S-01–S-09, S-16, własności, wyścig) przeszły na macOS; 4 testy nazw spoza UTF-8 nie wykonały się, a 5 przypadków z pliku testów bezpieczeństwa wejść to XFAIL. |
| K2 | Źródła pozostają niezmienione | **SPEŁNIONE Z ZASTRZEŻENIAMI** | Stan drzewa dowodów przed i po analizie jest identyczny w testach, ale porównanie nie obejmuje `atime`, a sprawdzono jedną platformę. |
| K3 | Każda nieobsłużona sytuacja tworzy gap | **NIESPEŁNIONE** w brzmieniu dosłownym; dla samej warstwy odczytu (SecureIngest) — spełnione z zastrzeżeniami | Każdy wpis nieprzeczytany przez SecureIngest niesie lukę (test), lecz parsery i reguły pomijają bez luki co najmniej sześć rodzajów treści: cztery potwierdzają testy XFAIL, dwa — sonda z §3. |

### 2.1. K1 — testy bezpieczeństwa wejść

Dowód — testy, które przeszły w przebiegu z §1 (liczba przypadków w nawiasie):

| Obszar | Testy | Wynik |
|---|---|---|
| Symlink w drzewie i jako źródło | `sec::test_s01_site_symlink_outside_root_is_skipped_with_gap` (2), `sec::test_s01_log_symlink_outside_root_is_skipped_with_gap`, `sec::test_s01_database_symlink_outside_root_is_not_read`, `sec::test_s01_symlink_given_as_any_source_is_refused` (4), `ing::test_symlink_to_parent_directory_does_not_escape_or_loop` | PASS |
| Hardlink | `sec::test_s01_hardlink_to_file_outside_root_is_flagged`, `sec::test_s01_hardlinked_file_is_not_hashed_or_analyzed_by_default`, `sec::test_s01_allow_hardlinks_flag_reads_the_file_and_reports_how_many`, `neg::test_hardlinked_baseline_is_refused_with_a_hint` | PASS |
| Path traversal | `sec::test_s01_traversal_keys_in_baseline_are_compared_but_never_opened`, `prop::test_nothing_outside_the_root_is_read_except_an_allowed_marked_hardlink` (100) | PASS |
| TOCTOU — haki deterministyczne | `sec::test_s02_file_swapped_for_symlink_after_check_is_not_read`, `ing::test_entry_swapped_for_symlink_after_enumeration_is_not_followed` (2), `ing::test_file_modified_while_being_read_is_marked_changed`, `ing::test_change_between_read_and_reverification_is_reported` (6), `sec::test_s02_evidence_changed_after_reading_is_reported_for_every_source` (4) | PASS |
| TOCTOU — osobny proces podmieniający | `prop::test_file_swapped_for_a_symlink_by_another_process_is_never_followed`, `prop::test_directory_swapped_for_a_symlink_by_another_process_is_never_entered` | PASS (3 przebiegi z rzędu) |
| Pliki specjalne | `sec::test_s03_fifo_in_site_is_skipped_with_gap`, `sec::test_s03_fifo_in_logs_is_skipped_with_gap`, `sec::test_s03_fifo_given_as_source_is_refused_without_blocking` (3), `ing::test_unix_socket_is_skipped_without_connecting` | PASS |
| Limity | `ing::test_every_exceeded_limit_produces_a_gap_naming_its_value` (5), `prop::test_limits_are_never_exceeded` (100), `sec::test_s06_file_count_limit_is_shared_by_all_sources`, `sec::test_s07_ten_gigabyte_sparse_file_is_skipped_without_hashing`, `ing::test_names_listed_in_parent_directories_count_against_the_entry_budget` | PASS |
| Patologie wejścia parserów | `sec::test_s08_crafted_insert_does_not_stall_the_sql_parser`, `sec::test_s08_unterminated_insert_headers_do_not_stall_the_sql_parser` (4), `sec::test_s08_statement_scanner_is_linear_on_crafted_sql` (5), `sec::test_s08_crafted_log_line_does_not_stall_the_log_pattern` (5), `sec::test_s09_escaped_and_multiline_inserts_are_parsed_as_data` (6) | PASS |
| Wywołanie i wyjście | `case::test_invalid_identifier_is_refused_before_analysis` (32), `inv::test_s16_output_overlapping_any_source_is_refused_before_anything_is_written` (4), `rw::test_symlink_named_like_a_result_is_replaced_and_its_target_left_untouched` (3), `rw::test_output_directory_swapped_for_symlink_during_analysis_is_refused` | PASS |
| Brak sieci i wykonania | `inv::test_s15_*` (2), `inv::test_s17_*` (2), `inv::test_d4_only_ingest_touches_the_filesystem` | PASS |

Zastrzeżenia:

1. **Nie wszystko się wykonało.** Cztery testy nazw plików spoza UTF-8 (`sec::test_s05_non_utf8_filename_does_not_break_the_report`, dwa w `ing`, jeden w `prop`) są na macOS pomijane, bo APFS nie pozwala utworzyć takiej nazwy. W tym środowisku ścieżka kodu `wpincidentlens/ingest.py:413` nie została wykonana ani razu.
2. **Nie wszystko przechodzi.** W `tests/test_security_inputs.py` jest 5 przypadków XFAIL: stratne dekodowanie SQL i logu bez luki (S-10, ×2), rola administratora rozpoznawana podciągiem (S-11), brak CSP (S-12), token z query stringu w raporcie (S-13). Dotyczą parserów i raportu, nie odczytu plików, ale są testami odporności na wejście.
3. **Jedna platforma.** ADR 0002 B3 deklaruje gwarancje dla Linuksa i macOS „testowane na obu”; w ramach tego raportu uruchomiono tylko macOS.
4. **Wyścig jest próbkowany.** Dwa testy z osobnym procesem czytają drzewo pod ostrzałem przez ok. 1,5 s każdy; pokazują brak naruszeń w zaobserwowanych przeplotach, nie brak okna.

### 2.2. K2 — źródła pozostają niezmienione

| Co sprawdza | Testy | Wynik |
|---|---|---|
| Drzewo dowodów (ścieżki, tryby, rozmiary, `mtime`, treść, cele dowiązań) identyczne przed i po pełnej analizie — także z wiszącym symlinkiem, hardlinkiem, FIFO i `--allow-hardlinks` | `inv::test_s16_analysis_leaves_evidence_tree_unchanged`, `inv::test_s16_analysis_with_every_flag_leaves_evidence_tree_unchanged`, `ing::test_reading_and_reverifying_leaves_the_evidence_tree_unchanged` | PASS |
| To samo na losowych drzewach, razem z otoczeniem poza korzeniem (typ, tryb, rozmiar, `mtime`, liczba dowiązań, cel dowiązania, skrót treści) | `prop::test_sources_are_left_exactly_as_they_were` (100) | PASS |
| `ingest.py` nie zawiera wywołań ani flag zapisu; zapisuje wyłącznie `report.py` | `ing::test_ingest_contains_no_writing_call_or_flag`, `inv::test_d4_only_ingest_touches_the_filesystem`, `inv::test_d4_only_ingest_and_reporter_import_the_os_module` | PASS |
| Katalog wyników nie może leżeć w źródle ani go zawierać; odmowa przed jakimkolwiek zapisem | `inv::test_s16_output_overlapping_any_source_is_refused_before_anything_is_written` (4), `ing::test_output_overlapping_a_source_is_refused` (6), `ing::test_output_inside_source_spelled_in_another_letter_case_is_refused` | PASS |
| Symlink w katalogu wyników nie prowadzi do zapisu pod jego celem | `rw::test_symlink_named_like_a_result_is_replaced_and_its_target_left_untouched` (3), `rw::test_dangling_symlink_named_like_a_result_does_not_create_its_target` | PASS |

Zastrzeżenia:

1. **`atime` jest poza porównaniem.** Oba pomocnicze skróty drzewa pomijają czas dostępu, a `ingest.py` nie otwiera plików z `O_NOATIME` (`wpincidentlens/ingest.py:31-32`). Na systemie plików z aktualizacją `atime` sam odczyt może go zmienić; zapobiega temu dopiero montowanie materiału tylko do odczytu.
2. **Otwarcie pliku urządzenia** następuje, zanim `fstat` pozwoli go odrzucić (`wpincidentlens/ingest.py:8-11`) i może wywołać efekt uboczny sterownika; materiał należy montować `ro,nodev`. Tego przypadku nie testowano.
3. **Zmiany dokonanej przez inny proces** narzędzie nie powstrzyma; wykrywa ją ponowna weryfikacja, o ile nie została cofnięta i o ile operator nie użył `--no-reverify`.
4. Jedna platforma i jeden system plików (APFS).

### 2.3. K3 — każda nieobsłużona sytuacja tworzy gap

Co jest spełnione — warstwa odczytu:

| Co sprawdza | Testy | Wynik |
|---|---|---|
| Każdy wpis rejestru o statusie innym niż `READ` niesie własną lukę | `prop::test_every_unread_entry_carries_a_gap_and_nothing_names_a_host_path` (100), `prop::test_entry_marked_changed_by_reverification_carries_its_own_gap` | PASS |
| Każdy wpis drzewa ma wpis w rejestrze albo nazwaną przyczynę braku | `prop::test_every_tree_entry_is_accounted_for_in_the_ledger` (100) | PASS |
| Każdy przekroczony limit daje lukę z wartością limitu | `ing::test_every_exceeded_limit_produces_a_gap_naming_its_value` (5) | PASS |
| Cokolwiek pominięte → zakres niepełny, kod wyjścia ≠ 0, nigdy „brak wskaźników” | `prop::test_report_over_a_tree_with_anything_skipped_is_never_complete` (18), `con::test_incomplete_scope_without_findings_is_inconclusive` (15), `con::test_skipped_entry_is_an_evidence_record_without_a_hash` (4) | PASS |
| Wyłączona weryfikacja i odczytane hardlinki są odnotowane | `sec::test_s02_no_reverify_flag_skips_the_check_and_says_so`, `ing::test_allowed_hardlinks_are_counted_in_an_informational_gap` | PASS |
| Parser SQL: instrukcja niedomknięta, `INSERT`/`REPLACE` w nieobsługiwanej składni, komentarz wykonywalny, `DELIMITER`, wiersz o złej liczbie pól | `con::test_sql_that_the_parser_skipped_lowers_database_coverage` (16) | PASS |
| Logi: wiersze niesparsowane, obcy format, pusty katalog | `neg::test_unsupported_log_lines_are_counted_as_coverage_gap` (2), `neg::test_empty_source_directory_is_reported_as_coverage_gap` (2) | PASS |

Co nie jest spełnione — sytuacje, które dziś **nie** tworzą luki:

| Nr | Sytuacja | Dowód | Kod | Issue |
|---|---|---|---|---|
| 1 | Bajty niepoprawne w UTF-8 w zrzucie SQL są zastępowane znakiem zastępczym bez luki | XFAIL `sec::test_s10_lossy_decoding_is_reported_as_coverage_gap[sql-dump]` | `wpincidentlens/cli.py:38-40` | #7 |
| 2 | To samo w logu | XFAIL `sec::test_s10_lossy_decoding_is_reported_as_coverage_gap[access-log]` | `wpincidentlens/cli.py:38-40` | #3 (zamknięte) |
| 3 | Plik obecny w materiale, ale nieobecny w baseline, jest pomijany bez śladu | XFAIL `neg::test_n8_premium_plugin_without_checksums_has_no_trusted_reference`, XFAIL `pos::test_p5_mu_plugin_added_since_baseline_is_reported` | `wpincidentlens/cli.py:119` | #6 |
| 4 | Rola administratora cofnięta w serializacji (`b:0`) jest liczona jak nadana | XFAIL `sec::test_s11_revoked_administrator_capability_is_not_an_admin` | `wpincidentlens/cli.py:369` | #7 |
| 5 | Instrukcje SQL inne niż `INSERT`/`REPLACE` (`UPDATE`, `CREATE TRIGGER`…) nie obniżają pokrycia bazy | sonda, §3 (brak trwałego testu) | `wpincidentlens/cli.py:231`, `:411` | #7 |
| 6 | `.htaccess` i `.user.ini` są czytane, ale nie ma dla nich żadnej reguły ani luki | sonda, §3 (brak trwałego testu) | `wpincidentlens/cli.py:35` | #6 |

Dodatkowo, z analizy kodu bez testu: punkt montowania wewnątrz drzewa nie jest rozpoznawany (`wpincidentlens/ingest.py:8-11`); tabele wtyczek o nazwie kończącej się na `_users`, `_usermeta`, `_options` są traktowane jak tabele WordPressa (`wpincidentlens/cli.py:347-371`).

Uzasadnienie werdyktu: kryterium mówi „każda”. W warstwie, którą M1 miał dostarczyć (odczyt i kontrakty), własność ma test na 100 losowych drzewach. W całym narzędziu własność jest fałszywa i wynik `NO_INDICATORS_IN_ANALYZED_SCOPE` z kodem 0 jest osiągalny przy treści, której nikt nie przeanalizował (§3). Roadmapa przypisuje luki parserów do M2–M4; czy to wystarcza do przejścia bramki M1, rozstrzyga właściciel.

## 3. Sonda: treść nieobsługiwana przez parsery a ocena

Jednorazowy skrypt na danych syntetycznych w katalogu tymczasowym poza repozytorium (2026-11-11, commit `4cac876`); nie jest częścią zestawu testów.

| Wejście | Zawartość |
|---|---|
| `--files` | `index.php` (komentarz) oraz `.htaccess` z dyrektywą `AddHandler application/x-httpd-php .jpg` |
| `--database` | trzy obsługiwane `INSERT` (`wp_users`, `wp_usermeta`, `wp_options`), a po nich `UPDATE wp_users SET user_login=…` i `CREATE TRIGGER … ON wp_users` |
| `--logs` | jeden poprawny wiersz combined |

| Wynik | Wartość |
|---|---|
| Kod wyjścia | `0` |
| `assessment` | `NO_INDICATORS_IN_ANALYZED_SCOPE` |
| `scope_complete` | `true` |
| `coverage.files` | `ANALYZED`, bez powodów |
| `coverage.database` | `ANALYZED`; jedyny powód to stała nota „Parser SQL PoC obsługuje wybrane INSERT; nie obsługuje triggerów, procedur, pełnej składni ani multisite” |
| Ustalenia | brak |

Stała nota pojawia się przy każdym zrzucie i nie zależy od tego, czy zrzut zawiera nieobsługiwane instrukcje. Raport nie mówi więc, że w tym konkretnym materiale coś pominięto.

## 4. Co ten wynik dowodzi, a czego nie

| Obszar | Dowodzi | Nie dowodzi |
|---|---|---|
| Symlink, hardlink, traversal | Na syntetycznych i losowych drzewach (macOS) nic spoza korzenia nie zostało przeczytane, poza jawnie dozwolonym i oznaczonym hardlinkiem | Zachowania na Linuksie (nieuruchomiony), z punktami montowania w drzewie, na sieciowych systemach plików; dowiązań w pośrednich składnikach ścieżki operatora (są rozwiązywane) |
| TOCTOU | Podmiana wstrzyknięta hakiem jest zawsze odrzucana; w próbkowanym wyścigu z osobnym procesem nie zaobserwowano naruszenia | Braku okna wyścigu: próbkowanie ok. 1,5 s na wariant; zmiany cofniętej przed ponowną weryfikacją |
| Limity | Limit plików, wpisów, rozmiaru, wolumenu, ścieżki i głębokości nie jest przekraczany; przekroczenie daje lukę | **Limit czasu nie obejmuje parserów** SQL i logów ani odczytu jednego pliku; nie mierzono pamięci ani miliona plików; limit czasu sprawdzono podstawionym zegarem |
| Parsery | Wybrane, ręcznie dobrane wejścia patologiczne kończą się w budżecie czasu | **Parsery nie były fuzzowane**; brak gwarancji dla wejść spoza listy |
| Niezmienność źródeł | Treść, tryby, rozmiary i `mtime` bez zmian w testach | `atime`; efektów ubocznych otwarcia pliku urządzenia |
| Platformy | macOS 27 / APFS / Python 3.12.11 | **Windows nietestowany** (odmowę na platformie bez `dir_fd` sprawdza tylko symulacja); Linux tylko z opisu PR |
| Izolacja | Brak importów sieciowych i wywołań procesów na poziomie Pythona | **Kontener niezmierzony**: brak sieci, ro rootfs, capabilities i limity są tylko zadeklarowane w `docker/compose.yaml` |
| Strażnik D4 | W pakiecie nie ma wywołań plikowych poza `ingest.py` oraz `makedirs`, `open` i `unlink` w `report.py` | Że obejścia nie da się napisać: strażnik działa po nazwach, nie jest piaskownicą |
| Kontrakt raportu | Każdy raport zapisany w testach przechodzi `validate_report` i JSON Schema; ocena wynika z reguły | Trafności oceny: `STRONG_INDICATORS` jest nieosiągalny, a pokrycie nie widzi luk z §2.3 |
| Detekcje | Sześć reguł PoC działa na `fixtures/` | Skuteczności na realnym materiale; skali false positive i false negative |
| Zapis wyników | Plik wyniku jest zamieniany atomowo, ma tryb `0600`, symlink nie jest otwierany | Atomowości zestawu trzech plików; obsługi błędu I/O (kończy się nieobsłużonym wyjątkiem) |
| Przegląd | Kod czytały agenty | **Przeglądu bezpieczeństwa przez człowieka nie było** |

## 5. Otwarte luki

### 5.1. Testy XFAIL (13 przypadków)

Pełna lista z powodami: `docs/TEST_MATRIX.md`, sekcja „Zestawienie XFAIL”.

| Issue | Stan Issue | Liczba | Luki |
|---|---|---|---|
| #6 (T-201) | otwarte | 4 | wersja referencji w ustaleniu; nowy plik spoza baseline; `NO_TRUSTED_REFERENCE`; offset sygnatury |
| #7 (T-301) | otwarte | 6 | `NEW_SINCE_BASELINE`; meta-refresh; cytat z redakcją; inwentarz administratorów; stratne dekodowanie SQL; `b:0` |
| #3 (T-003) | **zamknięte** | 3 | stratne dekodowanie logu; brak CSP; token z query stringu w `report.json` |

### 5.2. Ograniczenia zapisane w ADR

| Źródło | Ograniczenie |
|---|---|
| ADR 0002 B8 | Redakcja wartości query string, danych logowania w URL i flaga `--pseudonymize` są przyjęte, ale **niewdrożone**; brak ostrzeżenia o danych osobowych w raporcie |
| ADR 0002 D3 | CSP `default-src 'none'` przyjęta, **niewdrożona** |
| ADR 0002 D9 | Izolacja parserów w osobnym procesie odłożona do M6 |
| ADR 0003 §4 | Reguła liczników nie wymaga równości: usunięcie jednego z kilku dowodów o tym samym statusie z ręcznie zmienionego raportu nie jest wykrywane |
| ADR 0003 §6 | Żadna obecna reguła nie daje `STRONG_INDICATORS` |
| ADR 0003 §7 | Kod wyjścia 5 niewdrożony; nieobsłużony wyjątek kończy proces kodem 1 |
| ADR 0003 §8 | Migracja 0.1.0 → `poc-1` nie ma wejścia w CLI |
| ADR 0003 §9 | Pola specyfikacji odroczone w `Case`, `Evidence`, `Observation`, `Finding`, `Coverage` |
| ADR 0003, warianty mniej ostrożne | Brak baseline nie czyni zakresu niepełnym; `--no-reverify` nie obniża oceny; brak listy zaufanych administratorów nie obniża pokrycia bazy |

### 5.3. Ryzyka resztkowe z opisów PR #16, #20, #27

Pełna tabela ze stanem w kodzie: `docs/THREAT_MODEL.md` §5, wiersze 11–25. Najważniejsze dla operatora: punkty montowania w drzewie niewykrywane; dowiązania w pośrednich składnikach ścieżek akceptowane; plik urządzenia otwierany przed odrzuceniem; zmiana cofnięta przed ponowną weryfikacją niewykrywana; budżet czasu sprawdzany tylko między wpisami; raport rośnie z liczbą wpisów; zamiana trzech plików wyniku nie jest jedną operacją; błąd I/O przy zapisie nieobsłużony.

### 5.4. Stan śledzenia

| Obserwacja | Skutek |
|---|---|
| PR #26 i PR #27 są otwarte; Issue #4 i #18 (oba oznaczone `[M1]` w tytule) są otwarte | kod oceniany w tym raporcie nie jest w `main` |
| Issue #14 (T-501) i #15 (T-601) są **zamknięte**, choć ich zakres (redakcja, CSP, pomiar kontenera) nie jest wykonany | luki bez otwartego Issue; warunek B10 „pomiar kontenera w #15” wskazuje zamknięte Issue |
| Trzy znaczniki XFAIL wskazują zamknięte Issue #3 | numery w testach do poprawienia przy najbliższej zmianie testów |

## 6. Zmiany zachowania CLI wprowadzone w M1

Wywołanie pozostaje płaskie (`python -m wpincidentlens --files … --output …`); podkomend nie ma.

### 6.1. Kody wyjścia

| Kod | Znaczenie | Kod źródłowy |
|---|---|---|
| `0` | zakres analizy pełny: pliki, baza i logi `ANALYZED`, baseline `ANALYZED` albo niepodany. **Nie znaczy „brak ustaleń”** — ustalenia nie zmieniają kodu | `wpincidentlens/cli.py:605-609` |
| `2` | błąd wywołania (odmowa, §6.2); nic nie zostaje zapisane | `wpincidentlens/cli.py:654`, `:661`, `:668` |
| `3` | analiza częściowa: brak bazy lub logów, wpis pominięty lub zmieniony, przekroczony limit. **Uruchomienie na samych plikach zawsze daje 3** | `wpincidentlens/cli.py:609` |
| `4` | podane źródło nie zostało przeanalizowane (status `FAILED`), np. pusty katalog, obcy format | `wpincidentlens/cli.py:607-608` |
| `1` | nieobsłużony wyjątek Pythona (np. błąd I/O przy zapisie wyników); kod `5` ze specyfikacji nie jest wdrożony | — |

Przed M1 zakończona analiza zawsze dawała kod `0` (wersja dokumentu `docs/THREAT_MODEL.md` z T-002, Z-16). Automatyzacja sprawdzająca „kod ≠ 0 = błąd” wymaga dostosowania.

### 6.2. Odmowy (kod 2)

| Sytuacja | Test |
|---|---|
| `--files`, `--database`, `--logs` lub `--baseline` jest dowiązaniem symbolicznym | `sec::test_s01_symlink_given_as_any_source_is_refused` |
| Źródło jest FIFO lub innym plikiem specjalnym, nie istnieje albo ma zły rodzaj (`--files` nie jest katalogiem; `--database`, `--baseline` nie są zwykłym plikiem) | `sec::test_s03_fifo_given_as_source_is_refused_without_blocking`, `ing::test_unusable_source_root_is_refused_by_name_of_error` |
| `--output` leży w źródle, jest źródłem albo je zawiera | `inv::test_s16_output_overlapping_any_source_is_refused_before_anything_is_written` |
| `--output` jest dowiązaniem symbolicznym, zwykłym plikiem albo niepoprawną ścieżką | `rw::test_output_directory_given_as_symlink_is_refused_before_anything_is_written`, `case::test_output_path_that_is_a_regular_file_is_refused_and_left_intact` |
| `--case-id` lub `--operator-id` poza wzorcem: 1–64 znaki `A-Z a-z 0-9 . _ -`, pierwszy znak inny niż kropka i łącznik | `case::test_invalid_identifier_is_refused_before_analysis` |
| Limit niedodatni lub nieskończony | `case::test_limit_that_is_not_a_positive_finite_number_is_refused` |
| Baseline: niepoprawny JSON lub kształt, większy niż 64 MiB, nieczytelny, z wieloma dowiązaniami twardymi, z tekstem nie do zapisania w UTF-8 | `neg::test_malformed_baseline_is_rejected_as_usage_error`, `sec::test_unreadable_baseline_is_refused_not_silently_dropped`, `neg::test_hardlinked_baseline_is_refused_with_a_hint`, `case::test_baseline_text_that_cannot_be_encoded_is_refused_before_analysis` |
| `--known-admin` z tekstem nie do zapisania w UTF-8 | `case::test_known_admin_that_cannot_be_encoded_is_refused_before_analysis` |

Nie jest odmową: źródło `--files`, `--database` lub `--logs` bez uprawnień do odczytu — analiza trwa, a źródło dostaje lukę i pokrycie `FAILED` (kod 4). Komunikaty odmów nie powtarzają odrzuconej wartości ani celu dowiązania.

### 6.3. Nowe flagi

| Flaga | Domyślnie | Znaczenie |
|---|---|---|
| `--operator-id` | brak (`null`) | pseudonim operatora zapisywany w `case.json`; narzędzie nie czyta nazwy użytkownika ani hosta |
| `--allow-hardlinks` | wyłączona | czytaj pliki z `st_nlink > 1`; raport podaje ich liczbę |
| `--no-reverify` | wyłączona | pomiń ponowną weryfikację po analizie; odnotowane jako luka, **nie obniża oceny** |
| `--max-files` | 200 000 (wcześniej stałe 20 000) | limit liczby plików, łącznie we wszystkich źródłach |
| `--max-entries` | 1 000 000 | limit wszystkich wpisów (pliki, katalogi, dowiązania, pliki specjalne) |
| `--max-file-bytes` | 2 GiB | większy plik jest pomijany bez liczenia skrótu |
| `--max-total-bytes` | 20 GiB | limit łącznego rozmiaru czytanych plików |
| `--max-seconds` | 1800 | limit czasu, sprawdzany między wpisami |
| `--max-depth` | 64 | limit głębokości katalogów |
| `--max-path-bytes` | 4096 | limit długości ścieżki względnej |

Wartości domyślne: `wpincidentlens/ingest.py:68-78`; definicje flag: `wpincidentlens/cli.py:628-643`. Flaga `--pseudonymize` z ADR 0002 nie istnieje.

### 6.4. Inne zmiany zachowania

| Zmiana | Skutek dla operatora |
|---|---|
| Pliki z wieloma dowiązaniami twardymi są domyślnie pomijane | kopia z deduplikacją (np. `rsync --link-dest`) bez `--allow-hardlinks` da niemal puste pokrycie i kod 3 lub 4 |
| Symlinki, FIFO, gniazda w drzewie są pomijane z luką | każdy taki wpis obniża pokrycie źródła do `PARTIAL` (kod 3) |
| Baseline jest dowodem (`evidence`) i jest weryfikowany ponownie | zmiana pliku baseline w trakcie analizy daje `SOURCE_CHANGED_DURING_ANALYSIS` |
| Plik z baseline obecny, ale nieprzeczytany | luka zamiast ustalenia `BASELINE_FILE_MISSING` |
| Pliki wyników mają tryb `0600` | w pokazie Dockera pliki należą do UID 65532 i inny użytkownik hosta ich nie odczyta bez zmiany uprawnień |
| Istniejące `report.json`, `report.html`, `case.json` są zastępowane bez pytania | flagi `--force` nie ma; poprzednie wyniki w tym samym katalogu przepadają |
| Podsumowanie na stdout ma pola `assessment`, `scope_complete`, `findings`, `coverage_gaps`, `exit_code`, `report` | pole `report` zawiera bezwzględną ścieżkę `report.html` (tylko stdout, nie pliki wyniku) |

### 6.5. Nowy schemat raportu i `case.json`

| Plik | Schemat | Najważniejsze różnice |
|---|---|---|
| `report.json` | `poc-1` (`docs/schema/report-poc-1.schema.json`, ADR 0003) | raport 0.1.0 nie jest już zapisywany; `evidence_manifest` → `evidence` (także wpisy pominięte, z `read_status`); `rule` → `rule_id`; nowe `observations`, `coverage` per źródło, `scope_complete`; `counts` usunięte; identyfikatory `ev_`/`obs_`/`fnd_` z treści |
| `assessment` | — | `INDICATORS_FOUND` zastąpione przez `SUSPICIOUS` / `STRONG_INDICATORS`; brak ustaleń przy niepełnym zakresie to `INCONCLUSIVE`; dla `fixtures/` wynik to `SUSPICIOUS` |
| `case.json` (nowy) | `case-poc-1` (`docs/schema/case-poc-1.schema.json`) | identyfikator sprawy, pseudonim operatora, czasy UTC, nazwy (ostatni składnik ścieżki) i obecność źródeł, limity, flagi, SHA-256 zapisanego `report.json`, ocena, kod wyjścia; bez ścieżek hosta |
| Starsze raporty | — | przenosi funkcja `wpincidentlens.migrate.migrate_0_1_0`; nie ma wejścia w CLI |

## 7. Zastrzeżenie o przeglądzie i zakaz pracy na realnym materiale

- **Przegląd wykonywały wyłącznie agenty**: agent prowadzący oraz niezależne przeglądy agentów (według opisów PR #16 i #20; opis PR #27 wymienia tylko lekturę `report.py` i zmian w `ingest.py` przez agenta prowadzącego). **Przegląd bezpieczeństwa przez człowieka się nie odbył.** ADR 0002 i ADR 0003 zostały przyjęte przez agenta z delegacji właściciela i same zaznaczają, że niezależny przegląd AppSec pozostaje wymagany.
- **Zakaz pracy na realnym materiale pozostaje w mocy.** ADR 0002 B10: zakaz obowiązuje do bramki M1 **i** pomiaru kontenera (T-601, #15). Żaden z tych warunków nie jest dziś spełniony: bramka nie została zatwierdzona, kontener nie był mierzony, a Issue #15 jest zamknięte bez wykonania pomiaru.
- Ten raport nie zmienia statusu żadnego Issue ani ADR i nie jest zgodą na cokolwiek.
- **Decyzja o przejściu bramki M1 należy do właściciela repozytorium.** Do rozstrzygnięcia przez właściciela:

| Nr | Pytanie |
|---|---|
| 1 | Czy K3 ma być oceniane dosłownie (wtedy bramka nie przechodzi do czasu M3–M4), czy w zakresie warstwy odczytu M1? |
| 2 | Czy wynik z jednej platformy wystarcza, czy przed decyzją wymagany jest zielony przebieg na Linuksie (CI dla PR #27)? |
| 3 | Czy PR #26 i #27 mają zostać scalone przed decyzją o bramce? |
| 4 | Czy Issue #14 i #15 mają zostać otwarte ponownie, skoro ich zakres nie jest wykonany? |
| 5 | Czy przed M2 ma się odbyć przegląd `wpincidentlens/ingest.py` i `wpincidentlens/report.py` przez człowieka? |

## 8. Co dalej

| Etap | Zadanie | Issue | Stan Issue | Co zamyka z tego raportu |
|---|---|---|---|---|
| M2 | T-201 WPDetector, FileAnalyzer, integralność | #6 | otwarte | §2.3 nr 3 i 6; 4 XFAIL |
| M3 | T-301 ekstraktor SQL/JSONL, serializacja PHP | #7 | otwarte | §2.3 nr 1, 4, 5; 6 XFAIL |
| M4 | T-401 parser logów, UTC, korelacja | #13 | otwarte | §2.3 nr 2; limit zdarzeń logu |
| M5 | T-501 reguły, raport HTML, redakcja | #14 | **zamknięte** | CSP, redakcja query stringu, `--pseudonymize` |
| M6 | T-601 hardening, pomiar kontenera, fuzzing, QA | #15 | **zamknięte** | pomiar kontenera (warunek B10), fuzzing parserów, benchmark, Linux w pomiarze |

Poza kolejnością etapów pozostają: scalenie PR #26 i #27, poprawienie numerów Issue w trzech znacznikach XFAIL oraz rozbieżności dokumentacja–kod wymienione w `docs/REQUIREMENTS_TRACEABILITY.md`.
