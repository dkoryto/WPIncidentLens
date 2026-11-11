# WPIncidentLens — model zagrożeń (T-002, aktualizacja po M1)

**Status:** ACCEPTED 2026-11-11 na podstawie delegacji właściciela — patrz `docs/adr/0002-decyzje-bramki-m0.md`; bez niezależnego przeglądu AppSec. **Data aktualizacji:** 2026-11-11. **Stan kodu:** gałąź `agent/T-101-case-manager`, commit `4cac876` (PR #27, w chwili pisania niescalony z `main`).

Dokument rozdziela **stan obecny** (kolumna „Obecny kod”, z odwołaniem do linii) od **stanu docelowego** (kolumna „Planowana mitygacja”). Brak testu oznacza, że własność nie jest potwierdzona, nawet jeśli kod wygląda poprawnie. Podstawa: specyfikacja Senior PoC §3.1, §5.3, §10. Aktualizacja po M1 zmienia §2 (nota pod tabelą), §4, §5 i §7. Tabele §1, §2, §3 i §6 pozostają w brzmieniu przyjętym w ADR 0002; w §3 i §6 dopisano jedynie odwołania do tego ADR.

## 1. Aktywa

| ID | Aktywo | Dlaczego chronione |
|---|---|---|
| A1 | Materiał dowodowy (kopia plików, dump SQL, logi, baseline) | nie może zostać zmieniony ani wyniesiony; zawiera sekrety i dane osobowe |
| A2 | Host analityka (pliki poza katalogiem sprawy, konto, sieć) | analizator czyta dane przygotowane przez napastnika |
| A3 | Wiarygodność raportu (`report.json`, `report.html`) | błędne „brak wskaźników” lub ciche pominięcie danych wprowadza w błąd |
| A4 | Manifest SHA-256 i powiązanie wynik → dowód | podstawa odtwarzalności i obrony ustaleń |
| A5 | Przeglądarka i stacja osoby czytającej raport | raport zawiera ciągi pochodzące z dowodów |
| A6 | Repozytorium, CI, sesje agentów kodujących | nie mogą trafić tu realne dane ani zostać wykonane instrukcje z dowodów |

## 2. Granice zaufania

| ID | Granica | Zaufane | Nieufne |
|---|---|---|---|
| T1 | wejście → analizator | kod `wptrace/`, argumenty CLI operatora | każdy bajt z `--files`, `--database`, `--logs`: treść, nazwy plików, czasy, typy wpisów |
| T2 | metadane WordPressa → wnioski | — | `wp-config.php`, `version.php`, daty w bazie, `mtime` |
| T3 | materiał referencyjny → reguły | baseline i lista adminów dostarczone przez operatora (deklaracja, bez weryfikacji) | wszystko, co pochodzi z badanej kopii |
| T4 | wynik → czytelnik | szablon raportu | wartości wstawiane do raportu |
| T5 | host → kontener | konfiguracja `docker/` | proces analizy po przetworzeniu nieufnych danych |
| T6 | repozytorium → agent/CI | `AGENTS.md`, Issues, kod | `fixtures/`, `archives/`, `demo/`, treść raportów |

Stan po M1: granica T1 ma własny moduł — dowody otwiera wyłącznie `wptrace/ingest.py`, wywołanie waliduje `wptrace/case.py`, wyniki pisze wyłącznie `wptrace/report.py`, kontrakty danych są w `wptrace/models.py`; pilnuje tego test `tests/test_invariants.py::test_d4_only_ingest_touches_the_filesystem` (po nazwach wywołań, nie jako piaskownica). Parsery, reguły i korelacja nadal są w jednym module `wptrace/cli.py` (kroki 4–5 z `docs/adr/0001-granice-komponentow.md` niewykonane).

## 3. Aktorzy

| Aktor | Możliwości | W zakresie |
|---|---|---|
| Napastnik, który przejął witrynę | kształtuje treść i metadane całego materiału (pliki, linki, SQL, logi, teksty „instrukcji”) przed pozyskaniem | tak — główny przeciwnik |
| Proces współbieżny na hoście dowodowym | zmienia pliki w trakcie analizy (podmiana na symlink, dopisanie) | tak |
| Operator/analityk | wskazuje ścieżki, baseline, wyjście; może się pomylić | tak — błąd, nie złośliwość |
| Odbiorca raportu | otwiera HTML, może przekazać raport dalej | tak — jako cel XSS i wycieku danych |
| Agent kodujący / LLM czytający repo lub raport | może potraktować tekst z dowodów jako polecenie | tak |
| Złośliwy operator lub administrator hosta analitycznego | pełna kontrola nad narzędziem | **nie** — poza zakresem PoC (ADR 0002 B1) |

## 4. Zagrożenia

Statusy:

| Status | Znaczenie |
|---|---|
| OTWARTE | brak ochrony |
| CZĘŚCIOWE | ochrona niepełna: część zagrożenia nie ma kodu albo testu; kolumna „Pozostaje” wymienia co |
| OGRANICZONE (test) | mitygacja zaplanowana na M1 istnieje w kodzie i ma test, który przeszedł (macOS, `docs/TEST_MATRIX.md`); ryzyko resztkowe w kolumnie „Pozostaje” |
| NIEZWERYFIKOWANE | kod lub konfiguracja wyglądają poprawnie, brak testu/pomiaru |

**Żaden wiersz nie ma statusu „zamknięte”.** „OGRANICZONE (test)” opisuje wynik testów na danych syntetycznych, uruchomionych przez agenta na jednej platformie; nie zastępuje przeglądu bezpieczeństwa przez człowieka, który się nie odbył.

Skróty modułów: `cli` = `wptrace/cli.py`, `ing` = `wptrace/ingest.py`, `mod` = `wptrace/models.py`, `case` = `wptrace/case.py`, `rep` = `wptrace/report.py`. Skróty testów jak w `docs/TEST_MATRIX.md` (`sec`, `inv`, `ing`, `prop`, `con`, `mod`, `neg`, `case`, `rw`), bez przedrostka `test_`.

Issue (stan z `gh issue list`, 2026-11-11): otwarte #4 T-101, #6 T-201 (pliki), #7 T-301 (SQL), #13 T-401 (logi), #18 T-006; **zamknięte** #3 T-003, #5 T-102, #14 T-501 (reguły, HTML, redakcja), #15 T-601 (hardening, kontener). Mitygacje przypisane do #14 i #15 nie są wykonane i nie mają dziś otwartego Issue.

| ID | Zagrożenie | Obecny kod | Pozostaje | Planowana mitygacja | Issue | Status |
|---|---|---|---|---|---|---|
| Z-01 | Wykonanie nieufnego PHP | Brak prymitywów wykonania; treść czytana jako bajty i dopasowywana regexem (`cli:135-142`). Testy: `inv::s17_full_analysis_runs_with_process_spawning_blocked`, `inv::s17_engine_has_no_dynamic_execution_primitives`. | Strażnik działa po nazwach (AST) i blokuje wywołania na poziomie Pythona; nie jest izolacją procesu. | Izolacja kontenera zmierzona w M6. | #15 (zamknięte) | OGRANICZONE (test) |
| Z-02 | Wykonanie lub „odtworzenie” nieufnego SQL | Parser tekstowy `INSERT` (`cli:236-319`), brak sterownika DB i zależności runtime (`pyproject.toml:12`). Testy: `inv::d4_only_ingest_touches_the_filesystem` (zakaz importu `sqlite3`, `dbm`), `inv::s17_*`, `sec::s09_escaped_and_multiline_inserts_are_parsed_as_data`. | Lista zakazanych modułów jest zamknięta i sprawdzana po nazwach. | Ograniczona gramatyka, strumieniowo. | #7 | OGRANICZONE (test) |
| Z-03 | Nieufne logi jako wejście parsera | Wzorzec na wiersz bez nawrotów (`cli:414`; `sec::s08_crafted_log_line_does_not_stall_the_log_pattern`), próg 30 MiB na plik (`cli:23`, `cli:436-438`), wiersze niesparsowane liczone w luce (`cli:460-465`; `neg::unsupported_log_lines_are_counted_as_coverage_gap`), URI obcinane do 300 i adres do 64 znaków (`cli:456`; `con::long_option_name_and_client_address_are_truncated_in_the_report`). | Brak limitu długości wiersza i liczby zdarzeń: jedno ustalenie na wiersz (`cli:458`). Stratne dekodowanie bez luki (`cli:38-40`; XFAIL `sec::s10_lossy_decoding_is_reported_as_coverage_gap[access-log]`). Parser bez wersji. Limit czasu nie obejmuje parsowania. | Wersjonowany parser, limity długości wiersza i liczby zdarzeń. | #13 | CZĘŚCIOWE |
| Z-04 | Tekst udający instrukcje (plik, SQL, log, README w dowodach) | Narzędzie nie interpretuje tekstu i nie używa LLM. Ciągi z dowodów trafiają do raportu: ścieżka (`ing:136-150`, `cli:104-105`), nazwa opcji (`cli:378`), URI (`cli:456`), teksty luk (`ing:427-447`). | Brak fixture z „instrukcją” i testu, że raport traktuje ją jako dane; pola pochodzące z dowodów nie są oznaczone w kontrakcie. | Fixture i test; oznaczenie pól pochodzących z dowodów; zakaz LLM-werdyktu. | #14 (zamknięte) | NIEZWERYFIKOWANE |
| Z-05 | Path traversal | Nazwy pochodzą z listowania otwartego deskryptora katalogu (`ing:159-163`) i są otwierane pojedynczo względem tego deskryptora (`ing:339-340`). Klucze baseline są tylko porównywane (`cli:119`, `cli:145-148`; `sec::s01_traversal_keys_in_baseline_are_compared_but_never_opened`). `--output` nie może leżeć w żadnym źródle ani go zawierać (`ing:226-248`, `case:86-98`; `inv::s16_output_overlapping_any_source_is_refused_before_anything_is_written`). `--case-id` bez separatorów (`case:21`; `case::invalid_identifier_is_refused_before_analysis`). | `O_NOFOLLOW` chroni tylko ostatni składnik ścieżki: dowiązania w katalogach nadrzędnych źródeł i `--output` są rozwiązywane (`rep:9-10`). Punkty montowania w drzewie nie są wykrywane (`ing:8-11`). | — | #4 | OGRANICZONE (test) |
| Z-06 | Symlink | Każdy wpis otwierany z `O_NOFOLLOW` (`ing:31-33`); symlink w drzewie = `SKIPPED_SYMLINK` z luką (`ing:175-185`, `ing:341-344`); symlink podany jako źródło = odmowa, kod 2 (`ing:188-203`, `case:118-123`). Testy: `sec::s01_site_symlink_outside_root_is_skipped_with_gap`, `sec::s01_log_symlink_outside_root_is_skipped_with_gap`, `sec::s01_symlink_given_as_any_source_is_refused`, `ing::symlink_to_parent_directory_does_not_escape_or_loop`, `prop::nothing_outside_the_root_is_read_except_an_allowed_marked_hardlink`. | Jak w Z-05: składniki pośrednie ścieżki operatora. | — | #4 | OGRANICZONE (test) |
| Z-07 | Hardlink | Zwykły plik z `st_nlink > 1` domyślnie nieczytany, status `SKIPPED_HARDLINK` i luka (`ing:389-393`); `--allow-hardlinks` czyta, oznacza dowód i dodaje lukę z liczbą (`ing:301-303`). Testy: `ing::hardlinked_file_is_not_read_by_default`, `sec::s01_hardlink_to_file_outside_root_is_flagged`, `sec::s01_hardlinked_file_is_not_hashed_or_analyzed_by_default`, `sec::s01_allow_hardlinks_flag_reads_the_file_and_reports_how_many`. | Z flagą treść może być współdzielona z plikiem spoza materiału i nie da się ustalić, gdzie jest drugie dowiązanie. Dowiązanie utworzone po odczycie nie jest wykrywane (ponowna weryfikacja nie porównuje `st_nlink`, `ing:518-527`). | — | #4 | OGRANICZONE (test) |
| Z-08 | TOCTOU | Typ ustala `fstat` na otwartym deskryptorze (`ing:166-172`); skrót i treść z jednego odczytu (`ing:206-217`); `fstat` po odczycie wykrywa zmianę w trakcie (`ing:400-409`); ponowna weryfikacja po analizie (`ing:451-534`) daje `SOURCE_CHANGED_DURING_ANALYSIS`. Testy: `ing::entry_swapped_for_symlink_after_enumeration_is_not_followed`, `ing::file_modified_while_being_read_is_marked_changed`, `ing::change_between_read_and_reverification_is_reported`, `sec::s02_evidence_changed_after_reading_is_reported_for_every_source`, `prop::file_swapped_for_a_symlink_by_another_process_is_never_followed`, `prop::directory_swapped_for_a_symlink_by_another_process_is_never_entered`. | Wyścig z osobnym procesem jest **próbkowany** (ok. 1,5 s na wariant), nie dowodzi braku okna. Zmiana cofnięta przed ponowną weryfikacją nie jest wykrywana. `--no-reverify` wyłącza kontrolę i nie obniża oceny (ADR 0003). Plik urządzenia jest otwierany, zanim `fstat` pozwoli go odrzucić (`ing:8-11`). Na Linuksie agent aktualizujący ten dokument testów nie uruchamiał. | Montowanie materiału `ro,nodev`; pomiar na Linuksie w CI. | #4, #15 (zamknięte) | OGRANICZONE (test) |
| Z-09 | DoS / limity zasobów | Limity wspólne dla sesji (`ing:68-83`): pliki, wpisy, rozmiar pliku sprawdzany **przed** skrótem (`ing:394-397`), łączny wolumen, długość ścieżki, głębokość, czas; konfigurowalne z CLI (`cli:635-643`); przekroczenie = nazwana luka i pokrycie `PARTIAL`. Lista katalogu ograniczona budżetem wpisów (`ing:159-163`, `ing:374`). ReDoS usunięty: skaner liniowy (`cli:155-183`), wzorce bez nawrotów (`cli:189-203`). Testy: `ing::every_exceeded_limit_produces_a_gap_naming_its_value`, `prop::limits_are_never_exceeded`, `sec::s07_ten_gigabyte_sparse_file_is_skipped_without_hashing`, `sec::s08_*` (5 funkcji), `ing::names_listed_in_parent_directories_count_against_the_entry_budget`. | Limit czasu sprawdzany tylko między wpisami (`ing:327`, `ing:474`): **nie obejmuje parserów** SQL i logów ani odczytu jednego pliku (do 2 GiB). Brak limitu pamięci: zrzut do 20 MiB, log do 30 MiB i baseline do 64 MiB są w całości w pamięci (`cli:22-24`, `cli:336`); rejestr i `evidence[]` rosną z liczbą wpisów (do 1 000 000). Brak limitu liczby ustaleń (`cli:458`). Limit treści 4 MiB nie jest konfigurowalny z CLI (`cli:651`). Nie testowano miliona plików ani zużycia pamięci; brak fuzzingu parserów. | Parsery strumieniowe z budżetem czasu; benchmark i fuzzing w M6. | #7, #13, #15 (zamknięte) | CZĘŚCIOWE |
| Z-10 | Błędy parserów i ciche pominięcia | Luka i obniżone pokrycie dla: niedomkniętego `INSERT` (`cli:389-390`), wiersza o złej liczbie pól (`cli:391-393`), `INSERT`/`REPLACE` w nieobsługiwanej składni, komentarza wykonywalnego i `DELIMITER` (`cli:394-397`), roli administratora bez wiersza użytkownika (`cli:400-404`), zrzutu bez obsługiwanych `INSERT` lub bez tabel WordPressa (`cli:384-388`), niesparsowanych wierszy logu (`cli:460-465`), wpisów niebędących plikami (rejestr `ing`). Błędny baseline = kod 2 (`cli:469-489`, `cli:660-661`). Testy: `con::sql_that_the_parser_skipped_lowers_database_coverage` (16 przypadków), `neg::foreign_sql_is_reported_as_unparsed_not_clean`, `neg::admin_capability_without_user_row_is_not_silently_dropped`, `neg::malformed_baseline_is_rejected_as_usage_error`. | **Nadal bez luki:** stratne dekodowanie UTF-8 (`cli:38-40`; XFAIL ×2); rola wykrywana podciągiem `administrator` (`cli:369`; XFAIL); plik nieobecny w baseline (XFAIL ×2); pliki `.htaccess`/`.user.ini` czytane bez żadnej reguły (`cli:35`). **Instrukcje SQL inne niż `INSERT`/`REPLACE`** (`UPDATE`, `CREATE TRIGGER`…) mają tylko stałą notę (`cli:411`) i nie obniżają pokrycia — sonda z 2026-11-11 dała `NO_INDICATORS_IN_ANALYZED_SCOPE` i kod 0 (`docs/M1_GATE.md` §3). Dopasowanie tabel po sufiksie (`cli:347-371`) łączy tabele wtyczek. Brak fuzzingu. | Każde pominięcie = nazwana luka z licznikiem; dekoder serializacji data-only; fuzzing. | #6, #7, #13 | CZĘŚCIOWE |
| Z-11 | Sieć / eksfiltracja | Brak modułów sieciowych w pakiecie. Testy: `inv::s15_full_analysis_runs_with_sockets_blocked`, `inv::s15_engine_imports_no_network_modules`. | Tylko poziom Pythona. `network_mode: "none"` jest zadeklarowane (`docker/compose.yaml:8`), niezmierzone. Instalacja dev/CI pobiera pakiety z PyPI. | Pomiar w kontenerze; rozdzielenie środowiska dev od silnika. | #15 (zamknięte) | OGRANICZONE (test) — tylko warstwa Pythona |
| Z-12 | Wyciek sekretów i danych osobowych | Teksty luk i ścieżki dowodów są względne do źródła (`ing:427-447`, `mod:262-263`); `case.json` podaje tylko ostatni składnik ścieżki źródła (`case:44-52`, `case:63-66`); odmowy nie powtarzają odrzuconej wartości (`case:25-26`, `ing:48-65`). `user_pass` nie jest kopiowany (`cli:353-361`). Testy: `sec::report_never_contains_an_absolute_host_path`, `prop::report_and_html_name_no_host_path_and_no_content_from_outside`, `case::case_json_contains_no_host_path`, `sec::s13_canary_secret_never_reaches_any_output[wp-config-password, user-pass-column]`. | Query string z logu trafia bez redakcji do `attributes.uri` (`cli:456`; XFAIL `sec::s13_*[log-query-token]`). IP i loginy są w raporcie (decyzja B8), ale zapowiedzianego ostrzeżenia o danych osobowych, redakcji danych logowania w URL i flagi `--pseudonymize` nie ma. Podsumowanie na stdout podaje bezwzględną ścieżkę raportu (`cli:669-670`). | Redakcja w modelu danych, tryb `client-safe`. | #14 (zamknięte) | CZĘŚCIOWE |
| Z-13 | XSS w raporcie HTML | `html.escape(..., quote=True)` dla każdej wstawianej wartości (`rep:89-114`); brak JS w szablonie. Testy: `sec::s12_markup_from_evidence_is_escaped_in_html_report` (5 pól), `con::html_report_escapes_every_new_field`, `sec::s12_markup_in_case_id_of_a_composed_report_is_escaped_in_html_report`. | Brak CSP (`rep:107`; XFAIL `sec::s12_html_report_declares_content_security_policy`), wbrew ADR 0002 D3. Szablon to f-string — każde nowe pole wymaga ręcznego `esc`. | Jedna funkcja renderująca, CSP bez skryptów. | #14 (zamknięte) | CZĘŚCIOWE |
| Z-14 | Kontener / ucieczka na host | Obraz bez pinu digestu (`docker/Dockerfile:2`). Non-root, ro rootfs, brak sieci, `cap_drop`, `no-new-privileges`, limity, `tmpfs` są **zadeklarowane** (`docker/compose.yaml:7-16`), niezmierzone. `results` montowane rw (`docker/compose.yaml:21`), README zaleca `chmod 777` (`README.md:72`). Pliki wyników mają tryb 0600 (`rep:54`; `rw::new_result_file_is_readable_by_the_owner_only`). | Całość: brak pomiaru runtime. Flaga `ro` nie chroni przed zmianą po stronie hosta. | Pomiar runtime, pin digestu, SBOM, uprawnienia wyjścia bez 777; VM dla materiału szczególnie nieufnego. | #15 (zamknięte) | NIEZWERYFIKOWANE |
| Z-15 | Łańcuch dowodowy | `evidence[]` obejmuje każdy wpis wszystkich źródeł, także baseline i wpisy pominięte (`cli:592`, `cli:75-79`); identyfikatory z treści (`mod:213-220`, `mod:275-277`); logi rozróżniane ścieżką względną; ponowna weryfikacja (Z-08); deterministyczny porządek (`mod:562-569`); zapis atomowy per plik (`rep:53-76`); `case.json` podaje SHA-256 zapisanego `report.json` (`rep:144-146`). Testy: `con::skipped_entry_is_an_evidence_record_without_a_hash`, `neg::baseline_is_listed_in_evidence_manifest`, `con::same_named_logs_in_two_directories_are_two_evidence_entries`, `inv::s18_two_runs_on_same_evidence_give_identical_json`, `case::case_json_digest_matches_the_written_report`, `rw::failed_write_keeps_the_previous_results_intact`. | Brak metody i czasu pozyskania; operator to niezweryfikowany pseudonim. Brak podpisu i komendy `report verify`. Zamiana trzech plików wyniku nie jest jedną operacją. Reguła liczników dopuszcza usunięcie jednego z kilku dowodów o tym samym statusie z ręcznie zmienionego raportu (ADR 0003 §4). | Pola pozyskania w `Evidence`, weryfikacja raportu. | #14 (zamknięte) | CZĘŚCIOWE |
| Z-16 | Fałszywa pewność wyniku | Cztery stany, `INCONCLUSIVE` przy niepełnym zakresie bez ustaleń (`mod:478-507`); model odrzuca raport z oceną sprzeczną z regułą (`mod:599-604`); pokrycie per źródło wynika z rejestru odczytu (`cli:492-509`); kody wyjścia 0/3/4 z pokrycia (`cli:605-609`). Testy: `mod::assessment_rule` (25 przypadków), `con::incomplete_scope_without_findings_is_inconclusive` (15 przypadków), `con::exit_code_follows_coverage`, `prop::report_over_a_tree_with_anything_skipped_is_never_complete`. | Pokrycie jest tak dobre, jak luki parserów: przypadki z Z-10 „nadal bez luki” dają pełny zakres i „brak wskaźników” mimo nieprzeanalizowanej treści. Brak baseline i `--no-reverify` nie obniżają oceny; `STRONG_INDICATORS` jest nieosiągalny (ADR 0003, wariant mniej ostrożny). | RulesEngine z matrycą; luki parserów z M3–M4. | #6, #7, #13 | CZĘŚCIOWE |
| Z-17 | Łańcuch dostaw | Brak zależności runtime (`pyproject.toml:12`); `jsonschema` tylko w extras testowych (`pyproject.toml:16-17`); akcje CI przypięte do SHA (`.github/workflows/ci.yml:20`, `:23`). Bez testu. | Zależności dev bez pliku lock, brak SBOM i audytu. | Lock z hashami, `pip-audit`, SBOM; każda nowa zależność z oceną licencji. | #15 (zamknięte) | CZĘŚCIOWE |

Zmiana statusów względem wersji z T-002: Z-01, Z-02, Z-11 NIEZWERYFIKOWANE → OGRANICZONE (test); Z-05, Z-06 CZĘŚCIOWE → OGRANICZONE (test); Z-07, Z-08 OTWARTE → OGRANICZONE (test); Z-09, Z-10, Z-12 OTWARTE → CZĘŚCIOWE; Z-03, Z-13, Z-15, Z-16, Z-17 pozostają CZĘŚCIOWE; Z-04, Z-14 pozostają NIEZWERYFIKOWANE.

## 5. Pozostałe ryzyka

Ryzyka, które pozostaną także po wdrożeniu planowanych mitygacji (lista przyjęta w ADR 0002 B11):

1. **Parser nigdy nie będzie kompletny.** Ograniczona gramatyka SQL i wybrane formaty logów zawsze coś pominą; mitygacją jest jawna luka, nie pełne pokrycie.
2. **Kontener nie jest sandboxem.** Błąd w interpreterze lub jądrze omija izolację; dla materiału wysokiego ryzyka potrzebna jest osobna VM.
3. **Zmiana źródeł po stronie hosta** jest wykrywalna (ponowny skrót), ale nie da się jej zapobiec z poziomu narzędzia.
4. **Polityka hardlinków ma koszt.** Odrzucanie `st_nlink > 1` pominie legalne pliki (np. kopie z deduplikacją); czytanie ich nie pozwala stwierdzić, gdzie jest drugie dowiązanie.
5. **Różnice platform.** Semantyka `O_NOFOLLOW`/`openat` różni się między Linuksem a macOS; gwarancje potwierdzone na jednej platformie nie przenoszą się automatycznie.
6. **Metadane są kontrolowane przez napastnika.** `mtime`, daty w bazie i treść logów mogą być sfałszowane; oś czasu pozostaje orientacyjna.
7. **Raport zawiera dane z dowodów.** Nawet poprawnie escapowany tekst może zmylić człowieka lub model językowy czytający raport.
8. **Redakcja nie jest zupełna.** Wzorce sekretów nie pokryją wszystkich formatów; raport nadal wymaga przeglądu przed przekazaniem.
9. **Heurystyki mają false positive i false negative**, których skali nie da się oszacować na syntetycznych fixtures.
10. **PoC nadal nie nadaje się do pracy na realnym materiale.** ADR 0002 B10 utrzymuje zakaz do bramki M1 **i** pomiaru kontenera (T-601, #15). Bramka M1 nie została zatwierdzona przez właściciela (`docs/M1_GATE.md`), pomiar kontenera się nie odbył, a przegląd bezpieczeństwa przez człowieka nie miał miejsca.

Ryzyka resztkowe zgłoszone w opisach PR-ów etapu M1 (źródło: `gh pr view <nr> --json body`, 2026-11-11). Kolumna „Stan w kodzie” opisuje commit `4cac876`.

| Nr | Ryzyko | Źródło | Stan w kodzie |
|---|---|---|---|
| 11 | Punkty montowania wewnątrz drzewa nie są wykrywane | PR #16 | bez zmian (`ing:8-11`) |
| 12 | Symlinki w pośrednich składnikach ścieżki operatora są akceptowane; `O_NOFOLLOW` chroni tylko ostatni składnik, także dla `--output` | PR #16, PR #27 | bez zmian (`ing:188-203`, `rep:9-10`, `rep:43-50`) |
| 13 | Plik urządzenia lub FIFO jest otwierany, zanim `fstat` pozwoli go odrzucić; materiał należy montować `ro,nodev` | PR #16 | bez zmian (`ing:8-11`, `ing:166-172`); FIFO otwierane z `O_NONBLOCK` (`ing:31-32`) |
| 14 | Zmiana cofnięta przed ponowną weryfikacją nie zostanie wykryta | PR #16 | bez zmian |
| 15 | Wyścigi były w testach symulowane hakami; prawdziwy wyścig to próbkowanie (ok. 1,5 s na wariant), nie dowód braku okna | PR #16, PR #27 | doszły dwa testy z osobnym procesem (`tests/test_ingest_properties.py:780`, `:792`); ograniczenie próbkowania pozostaje |
| 16 | `listdir` wczytuje wszystkie nazwy katalogu naraz; limit plików liczy tylko zwykłe pliki | PR #16 | **ograniczone po PR #16**: lista obcinana budżetem wpisów (`ing:159-163`, `ing:374`), limit `max_entries` liczy każdy wpis (`ing:332-335`); testy `ing::directory_listing_never_returns_more_than_the_requested_names`, `ing::entries_other_than_regular_files_are_bounded_by_the_entry_limit` |
| 17 | Budżet czasu sprawdzany między plikami; ponowna weryfikacja podwaja I/O | PR #16 | bez zmian (`ing:327`, `ing:474`); parsery poza budżetem (Z-09) |
| 18 | Strażnik AST działa po nazwach wywołań i nie jest piaskownicą | PR #16 | bez zmian (`tests/test_invariants.py:142-159`) |
| 19 | Windows, sieciowe systemy plików i pliki urządzeń nie były testowane | PR #16 | bez zmian; na platformie bez `dir_fd`/`O_NOFOLLOW` narzędzie odmawia pracy (`ing:117-121`), sprawdzone tylko symulacją (`ing::platform_without_descriptor_relative_open_is_refused`) |
| 20 | Query string z logu trafia bez redakcji do obserwacji | PR #20 | bez zmian (`cli:456`); XFAIL |
| 21 | `evidence` zawiera każdy wpis rejestru, więc raport rośnie z rozmiarem drzewa | PR #20 | bez zmian (`cli:592`); górną granicą jest `max_entries` |
| 22 | Pola specyfikacji §4, których PoC nie potrafi wypełnić, są odroczone | PR #20 | lista w ADR 0003 §9 |
| 23 | Migrację sprawdzono na jednym zachowanym raporcie 0.1.0 i raportach budowanych w testach | PR #20 | bez zmian (`tests/data/report-0.1.0.json`) |
| 24 | Zamiana trzech plików wyników nie jest jedną operacją; błąd w jej trakcie może zostawić nowy `report.json` obok starego `case.json` | PR #27 | bez zmian (`rep:64-76`); `case.json` zamieniany jako ostatni |
| 25 | Błąd I/O przy zapisie (np. brak miejsca) kończy się nieobsłużonym `OSError`; kod wyjścia 5 nie jest wdrożony | PR #27 | bez zmian (`cli:665-668` obsługuje tylko `OutputRefusal`) |

## 6. Bramka przeglądu człowieka

Pytania, które musiały zostać rozstrzygnięte przed T-101 (#4) i T-102 (#5). **Rozstrzygnięcia: `docs/adr/0002-decyzje-bramki-m0.md`.**

| ID | Pytanie / decyzja | Dotyczy |
|---|---|---|
| B1 | Czy aktywa, granice T1–T6 i lista aktorów są kompletne? Czy złośliwy operator pozostaje poza zakresem? | całość |
| B2 | Hardlinki: odrzucać każdy plik z `st_nlink > 1` (luka), czy czytać i oznaczać? | Z-07, #4 |
| B3 | TOCTOU: odczyt względem deskryptora katalogu z `O_NOFOLLOW`, obowiązkowa prywatna kopia robocza sprawy, czy oba? Na jakich platformach obowiązują gwarancje (tylko Linux)? | Z-06, Z-08, #4 |
| B4 | Czy skrót i analiza mają pochodzić z jednego odczytu, a ponowny skrót po analizie ma być domyślny? | Z-08, Z-15, #4 |
| B5 | Symlink wskazany wprost przez operatora (`--files`, `--database`, `--logs`, `--baseline`): odmowa czy rozwiązanie z odnotowaniem? | Z-06, #4 |
| B6 | Wartości domyślne limitów (rozmiar pliku, łączny wolumen, liczba plików, długość ścieżki, czas) i zachowanie po przekroczeniu: analiza częściowa czy przerwanie? | Z-09, #4 |
| B7 | ReDoS w `cli.py:154`: osobna, wcześniejsza poprawka czy w ramach T-301 (#7)? | Z-09 |
| B8 | Prywatność: czy IP, query string i loginy mają być domyślnie redagowane także w `report.json`? Kto zatwierdza politykę? | Z-12, #5 |
| B9 | Wprowadzenie `INCONCLUSIVE` zmienia schemat i odwraca oczekiwanie testu `test_no_indicators_not_a_clean_bill`. Czy zmiana wchodzi w T-102 z migracją z 0.1.0? | Z-16, #5 |
| B10 | Czy T-101 może ruszyć przed pomiarem runtime kontenera (T-601)? Czy dla realnego materiału wymagana będzie VM? | Z-14 |
| B11 | Akceptacja listy „Pozostałe ryzyka” i zakazu użycia PoC na realnych dowodach do bramki M1. | §5 |

Odwołanie `cli.py:154` w B7 dotyczy kodu sprzed naprawy (#11) i zostało zachowane jako brzmienie pytania.

## 7. Jak zweryfikowano ten dokument

- Numery linii w §4 i §5 sprawdzono względem plików `wptrace/*.py`, `docker/*`, `pyproject.toml` i `README.md` na commicie `4cac876`.
- Każdy test wymieniony w §4 został uruchomiony w ramach pełnego zestawu: `python -m pytest -q` → **1853 passed, 5 skipped, 13 xfailed** (macOS, Darwin 27.0.0 arm64, Python 3.12.11, pytest 8.4.2; trzy kolejne przebiegi z tym samym wynikiem). Szczegóły: `docs/TEST_MATRIX.md`.
- Wpis „sonda” w Z-10 i Z-16 to jednorazowy skrypt na danych syntetycznych w katalogu tymczasowym poza repozytorium (opis w `docs/M1_GATE.md` §3); nie jest trwałym testem.
- Ryzyka 11–25 w §5 przepisano z opisów PR #16, #20 i #27; kolumnę „Stan w kodzie” sprawdzono w kodzie.
- Nie zweryfikowano: zachowania na Linuksie (wyniki z Linuksa istnieją tylko w opisach PR-ów), Windows, runtime kontenera, sieciowych systemów plików, plików urządzeń, zużycia pamięci, wyniku CI dla PR #27. Przeglądu przez człowieka nie było.
