# WPIncidentLens — mapa wymagań i stanu implementacji (T-002)

**Data:** 2026-11-11. **Stan kodu:** gałąź `agent/T-001-baseline-ci`. **Źródło wymagań:** `docs/WPTrace_Specyfikacja_Senior_PoC_2026-11-09.md` (kolumna „Spec”).

Odwołania bez nazwy pliku dotyczą `wptrace/cli.py`; `T:` oznacza `tests/test_cli.py`. Mapa opisuje **stan obecny**, nie plan.

## Statusy

| Status | Znaczenie |
|---|---|
| IMPLEMENTED | istnieje kod **i** test, który sprawdza to zachowanie |
| PARTIAL | kod pokrywa tylko część wymagania (z testem lub bez) |
| MISSING | brak kodu |
| UNVERIFIED | kod lub konfiguracja wyglądają na zgodne (albo własność wynika z braku kodu), ale nie ma testu ani pomiaru |

IMPLEMENTED nie oznacza „bezpieczne” ani „kompletne” — tylko że zachowanie z kolumny „Wymaganie” ma pokrycie testem.

## Podsumowanie

| Status | Liczba wierszy |
|---|---|
| IMPLEMENTED | 4 |
| PARTIAL | 45 |
| MISSING | 38 |
| UNVERIFIED | 9 |
| **Razem** | **96** |

Wiersze grupujące kilka testów (np. `N1–N8`) liczone są jako jeden.

## 1. Komponenty C01–C12 (Spec §3.2)

| ID | Komponent | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| C01 | CaseManager | MISSING | — | — | jedynie dowolny ciąg `--case-id` (`:362`, `:333`); brak `case.json` i `CaseContext` |
| C02 | SecureIngest | PARTIAL | `:39-78` | `T:30-36` | symlink i pliki specjalne tylko w `--files`; brak hardlink, TOCTOU, limitów łącznych |
| C03 | WPDetector | MISSING | — | — | brak wykrywania wersji, locale, prefiksu |
| C04 | IntegrityAdapter | PARTIAL | `:79-82`, `:102-106` | — | tylko własny baseline SHA-256; fixture ma pusty `files`, więc ścieżka nietestowana; brak `NOT_CHECKED` |
| C05 | FileAnalyzer | PARTIAL | `:83-101` | `T:17` | trzy heurystyki; `REQUEST_TO_COMMAND_EXEC` bez testu; brak testów negatywnych |
| C06 | SQLDumpAdapter | PARTIAL | `:110-190` | `T:7-9` | tylko `INSERT`; nieobsłużone instrukcje bez nazwanej luki |
| C07 | JSONLDBAdapter | MISSING | — | — | |
| C08 | WPDataAnalyzer | PARTIAL | `:193-250` | `T:17-18` | users/usermeta/options; brak posts, cron, serializacji |
| C09 | LogParsers | PARTIAL | `:252-285` | `T:18`, `T:21` | tylko access log combined; brak `HttpEvent` |
| C10 | RulesEngine | MISSING | — | — | reguły wpisane w pętle odczytu (`:79-101`, `:236-246`, `:276-280`); brak wersji reguł i warstwy obserwacji |
| C11 | Correlator | PARTIAL | `:302-308` | `T:17-18` | wyłącznie równość ścieżki plik ↔ URI |
| C12 | Reporter | PARTIAL | `:331-337`, `:340-352`, `:379-380` | `T:15-22`, `T:45-52` | brak schematu, CSP i redakcji |

## 2. Warunki bezwzględne (Spec §0, §20)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-01 | Brak wykonania PHP z wejścia | UNVERIFIED | `:4-14`, `:92-99` | — | brak prymitywów wykonania w kodzie; brak testu S-17 |
| R-02 | Brak wykonania SQL | UNVERIFIED | `:110-190` | — | parser tekstowy, brak sterownika DB; brak testu |
| R-03 | Brak połączeń sieciowych | UNVERIFIED | `:4-14` | — | brak modułów sieciowych; brak testu S-15 |
| R-04 | Brak ingerencji w wejście | PARTIAL | `:367-369`, `:378-380` | `T:39-43` | chroniony tylko katalog `--files`; brak porównania skrótów przed/po |
| R-05 | Brak deklaracji „clean” | IMPLEMENTED | `:334-335` | `T:24-28` | |
| R-06 | `INCONCLUSIVE` przy brakach krytycznych | MISSING | `:334` | — | `T:24-28` utrwala zachowanie przeciwne (brak DB i logów → „brak wskaźników”) |

## 3. Intake i bezpieczeństwo plików (Spec §5.2–§5.4)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-10 | Symlink w drzewie `--files` nie jest otwierany | IMPLEMENTED | `:55-61` | `T:30-36` | tylko statyczny link; kontrola po ścieżce, nie po deskryptorze |
| R-11 | Symlink w pozostałych wejściach | PARTIAL | `:259-261` | — | logi pomijają; `--database` (`:195`, `:370`), `--baseline` (`:374`) i `--files` (`:365`) podążają |
| R-12 | Pliki specjalne z jawnym `SKIPPED_UNSAFE_TYPE` | PARTIAL | `:65-67` | — | luka tekstowa w `--files`; w logach ciche pominięcie (`:259-261`) |
| R-13 | Hardlinki nieotwierane lub oznaczane | MISSING | — | — | brak kontroli `st_nlink` |
| R-14 | Otwarcie odporne na podmianę (`O_NOFOLLOW`/`openat`), test wyścigu | MISSING | `:26`, `:92` | — | otwarcia po ścieżce |
| R-15 | Limity: plik, łączny wolumen, liczba plików, długość ścieżki, czas; konfigurowalne | PARTIAL | `:17-20`, `:69-71`, `:86-88`, `:197-199`, `:264-266` | — | stałe; brak limitu łącznego, ścieżki i czasu |
| R-16 | Odczyt strumieniowy z ograniczoną pamięcią | PARTIAL | `:24-29` | — | strumieniowy tylko skrót; treść w całości w pamięci (`:92`, `:200`) |
| R-17 | Manifest SHA-256 po bajtach źródłowych | PARTIAL | `:24-29`, `:77-78`, `:196`, `:263` | `T:20` | test liczy wpisy, nie sprawdza skrótów; baseline poza manifestem |
| R-18 | `mtime`/`ctime` jako deklaracja, nie dowód | PARTIAL | `:309`, `:326-329` | — | opis podstawy czasu; brak `ctime` i precyzji |
| R-19 | Ponowny skrót i `SOURCE_CHANGED_DURING_ANALYSIS` | MISSING | — | — | |
| R-20 | Brak obsługi ZIP/TAR | UNVERIFIED | `:4-14` | — | brak modułów archiwów; archiwum w drzewie jest tylko haszowane |
| R-21 | `wp-config.php`: bez wykonania, prefiks ze wzorca, maskowanie sekretów | MISSING | — | — | plik jest tylko haszowany |

## 4. Model danych i wynik (Spec §4, §0)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-30 | `Case` z wymaganymi polami | MISSING | `:332-333` | — | tylko `case_id`, `tool_version`, czas analizy |
| R-31 | `Evidence` z deterministycznym ID i ścieżką logiczną | PARTIAL | `:77-78`, `:196`, `:263` | `T:20` | brak ID; logi po samej nazwie pliku |
| R-32 | `Observation` (fakt oddzielony od interpretacji) | MISSING | — | — | |
| R-33 | `Finding` z wersją reguły, `observations[]`, alternatywami, rekomendacją | PARTIAL | `:32-36` | `T:16-18` | słownik z regułą, wagą, pewnością, źródłem |
| R-34 | `severity` i `confidence` niezależne, z tabelami regresyjnymi | PARTIAL | `:32-36` | — | dwa pola o wartościach wpisanych na stałe; brak testów |
| R-35 | `Coverage` per źródło ze statusami | PARTIAL | `:336` | `T:28`, `T:36` | lista tekstów, bez struktury |
| R-36 | Cztery stany `assessment` | PARTIAL | `:334` | `T:19`, `T:27` | dwa stany; `INDICATORS_FOUND` nie występuje w specyfikacji |
| R-37 | Inwarianty referencji finding → observation → evidence | MISSING | — | — | |
| R-38 | Deterministyczny porządek wyników | PARTIAL | `:47`, `:330`, `:336-337` | — | znaleziska niesortowane; kolejność z `:104` zależy od `PYTHONHASHSEED` |
| R-39 | Wersjonowany schemat z JSON Schema i migracją | PARTIAL | `:332` | — | tylko pole `schema_version` |
| R-40 | Komplet plików wyniku (`case.json` … `run.log`) | PARTIAL | `:379-380` | `T:15`, `T:22` | `report.json` i `report.html` |

## 5. Pliki WordPressa (Spec §6)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-45 | WP-FILE-001 PHP w uploads | IMPLEMENTED | `:83-85` | `T:17` | tylko test pozytywny; sztywny prefiks `wp-content/uploads/` |
| R-46 | WP-FILE-002 core vs manifest wersji/locale | MISSING | — | — | porównanie z własnym baseline: patrz C04 |
| R-47 | WP-FILE-003 nowy plik w `mu-plugins` | MISSING | — | — | pliki spoza baseline nie są zgłaszane (`:79`) |
| R-48 | WP-FILE-004 wzorce zaciemnienia | PARTIAL | `:96-101` | `T:17` | dwa regexy, bez offsetu; jeden bez testu |
| R-49 | WP-FILE-005 nietypowy plik wykonawczy w mediach | PARTIAL | `:21`, `:83` | — | tylko po rozszerzeniu, wspólnie z R-45 |
| R-50 | WP-FILE-006 `.htaccess`, `.user.ini`, `auto_prepend_file` | MISSING | `:89` | — | pliki są czytane, ale brak reguły |
| R-51 | Klasyfikacja plików (CORE, PLUGIN, …) | MISSING | — | — | |
| R-52 | YARA-X z wersjonowanym pakietem | MISSING | — | — | |

## 6. Baza danych (Spec §7)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-55 | Ograniczona gramatyka mysqldump, strumieniowo | PARTIAL | `:116-190`, `:200` | `T:7-9` | tylko `INSERT`; cały plik w pamięci |
| R-56 | Nierozpoznane dane → `SQL_PARSE_GAP` | MISSING | `:152-153` | — | ciche pominięcie; jedynie stała luka ogólna (`:249`) |
| R-57 | Prefiks tabel inny niż `wp_` | PARTIAL | `:209`, `:218`, `:227` | `T:11-18` | dopasowanie po sufiksie; fixture z prefiksem `demo_`; łapie też inne tabele |
| R-58 | `UNSUPPORTED_MULTISITE` | MISSING | — | — | |
| R-59 | Dekoder serializacji PHP data-only | MISSING | `:225` | — | wyszukiwanie podciągu |
| R-60 | WP-DB-001 administrator względem baseline | PARTIAL | `:241-246` | `T:17` | lista loginów, nie porównanie dwóch migawek; admin bez wiersza użytkownika ginie (`:243`) |
| R-61 | Administrator bez baseline = inwentaryzacja | PARTIAL | `:247-248` | — | luka zamiast alertu; brak listy kont; brak testu N3 |
| R-62 | WP-DB-002, 004, 005, 006 | MISSING | — | — | |
| R-63 | WP-DB-003 JS/redirect w `options` | PARTIAL | `:236-238` | `T:18` | brak redakcji i offsetu; brak testu N2 |
| R-64 | `user_pass` i zbędne dane nie trafiają do wyniku | UNVERIFIED | `:209-217` | — | używane tylko ID i login; brak testu canary |

## 7. Logi i korelacja (Spec §8, §9.3)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-70 | Parser Apache/Nginx combined | PARTIAL | `:252`, `:267-280` | `T:18` | bez bytes, referera, user-agenta |
| R-71 | Niesparsowane wiersze raportowane | UNVERIFIED | `:281-284` | — | |
| R-72 | UTC z zachowaniem czasu surowego i niepewności zegara | PARTIAL | `:280`, `:313-322` | `T:21` | niepewność tylko opisowo; README:37 twierdzi, że czas nie jest normalizowany |
| R-73 | `X-Forwarded-For` i zaufane proxy | MISSING | — | — | |
| R-74 | Redakcja `HttpEvent` (tokeny, IP, user-agent) | MISSING | `:279-280` | — | surowe URI i IP w `report.json` |
| R-75 | Typy relacji, nigdy `PROVEN_EXPLOIT` | PARTIAL | `:302-308` | `T:17-18` | jeden typ; zastrzeżenie w treści |
| R-76 | Agregacja powtórnych zdarzeń | MISSING | `:277` | — | jedno znalezisko na wiersz logu |

## 8. Bezpieczeństwo, prywatność, kontener (Spec §10)

| ID | Wymaganie | Status | Kod / konfiguracja | Test | Uwagi |
|---|---|---|---|---|---|
| R-80 | XSS: escape, CSP, brak JS | PARTIAL | `:341-348` | `T:45-52` | escape tak; test tylko dla `case_id`; brak CSP |
| R-81 | Redakcja sekretów i danych osobowych | MISSING | — | — | ścieżki hosta w lukach (`:49`) |
| R-82 | Odporność na patologie regexów, timeouty | MISSING | `:154`, `:99` | — | wykładniczy czas w `:154` potwierdzony sondą |
| R-83 | Łańcuch dostaw: piny, hashe, SBOM | PARTIAL | `pyproject.toml:12`, `.github/workflows/ci.yml:20`, `:23` | — | brak lock, SBOM, audytu |
| R-84 | Kontener: non-root, ro rootfs, bez sieci, bez capabilities, limity | UNVERIFIED | `docker/Dockerfile:5`, `docker/compose.yaml:7-16` | — | deklaracja; pomiar NOT RUN (`docs/BASELINE.md`) |
| R-85 | Dowody montowane tylko do odczytu | UNVERIFIED | `docker/compose.yaml:18-20` | — | deklaracja |
| R-86 | Obraz przypięty do digestu | MISSING | `docker/Dockerfile:2` | — | |
| R-87 | Tekst z dowodów nie jest instrukcją | UNVERIFIED | — | — | brak interpretacji i LLM w kodzie; brak fixture |

## 9. CLI (Spec §11)

| ID | Wymaganie | Status | Kod | Test | Uwagi |
|---|---|---|---|---|---|
| R-90 | Podkomendy `case init`, `analyze`, `report verify`, `version` | MISSING | `:356-364` | — | płaskie CLI |
| R-91 | Kody wyjścia 0/2/3/4/5 | PARTIAL | `:366-375`, `:383` | `T:14`, `T:42` | 0 i błąd argparse; brak 3/4/5; nieobsłużone wyjątki (`:374`) |
| R-92 | Zapis atomowy, bez nadpisania bez `--force` | MISSING | `:378-380` | — | |
| R-93 | Walidacja ścieżek przed odczytem | PARTIAL | `:365-371` | `T:39-43` | |
| R-94 | Wyjście poza katalogiem `--files` | IMPLEMENTED | `:367-369` | `T:39-43` | nie obejmuje `--database` i `--logs` |

## 10. Matryca testów i jakość (Spec §14, §13.2)

| ID | Wymaganie | Status | Test | Uwagi |
|---|---|---|---|---|
| P1 | PHP w uploads + log, z opisem ograniczeń | PARTIAL | `T:11-22` | treść ograniczeń niesprawdzana |
| P2 | Modyfikacja core z manifestem | MISSING | — | |
| P3 | Admin dodany w nowszej migawce | PARTIAL | `T:17` | lista loginów zamiast migawek |
| P4 | Opcja z podejrzanym redirectem | PARTIAL | `T:18` | bez redakcji |
| P5–P6 | Persistence; sygnatura YARA | MISSING | — | |
| N1–N8 | Scenariusze negatywne | MISSING | — | N3: kod w `:247-248` bez testu; N6: zachowanie sprzeczne (R-06) |
| S-01 | Symlink poza root | PARTIAL | `T:30-36` | tylko `--files` |
| S-02–S-08 | Wyścig, FIFO, długie nazwy, Unicode, limity, sparse, regex | MISSING | — | |
| S-09 | SQL wielowierszowy/escapowany | PARTIAL | `T:7-9` | wiele wierszy tak, escapowanie nie |
| S-10–S-11 | Uszkodzony UTF-8; obiekt PHP serialized | MISSING | — | |
| S-12 | HTML z `<script>`/`onerror` | PARTIAL | `T:45-52` | jedno pole |
| S-13–S-15 | Canary; XFF; brak sieci | MISSING | — | |
| S-16 | Brak zapisu w evidence | PARTIAL | `T:39-43` | odmowa wyjścia; bez porównania skrótów |
| S-17–S-18 | Brak uruchomienia PHP; determinizm | MISSING | — | |
| Q-01 | Fuzzing parserów (Hypothesis) | MISSING | — | |
| Q-02 | Benchmark wydajności i pamięci | MISSING | — | |
| Q-03 | `ruff`, `mypy`, skan zależności | PARTIAL | — | tylko `ruff` z regułami `E9`, `F` (`pyproject.toml:36`) |

## Rozbieżności dokumentacji zauważone przy mapowaniu

- `README.md:37` podaje, że czas logów nie jest normalizowany; kod normalizuje go do UTC (`:313-322`) i sprawdza to `T:21`.
- `README.md:30` i `:41` opisują izolację kontenera i brak „niekontrolowanego kodu” w HTML jako fakty; pierwsze jest niezmierzone (R-84), drugie testowane dla jednego pola (R-80).
- Numeracja ticketów w specyfikacji §13.1 (T-001 „model Case” itd.) różni się od numeracji Issues (T-001 = baseline/CI); w tym repozytorium obowiązuje numeracja Issues.
