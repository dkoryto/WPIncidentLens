# WPIncidentLens — prototyp analizy powłamaniowej WordPressa

**Nie jest to gotowe narzędzie produkcyjne ani dowód braku kompromitacji.**

PoC zapewnia działający **offline** przepływ: statyczna analiza kopii katalogu WordPressa, wybranego podzbioru eksportu SQL i logów HTTP → manifest SHA-256 → `report.json` + `report.html` + widoki (`evidence-manifest.json`, `observations.jsonl`, `findings.json`, `timeline.json`, `coverage.json`, `run.log`) + `case.json`. Zawiera wyłącznie syntetyczne dane testowe.

## Test lokalny

Wymagany Python 3.12. Aktualne wyniki testów: [docs/TEST_MATRIX.md](docs/TEST_MATRIX.md); środowisko i wyniki z pierwszego etapu (T-001): [docs/BASELINE.md](docs/BASELINE.md).

```bash
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes -r requirements/dev.lock
python -m pip install --no-deps -e .
python -m ruff check .
python -m pytest -q
python -m wpincidentlens --files fixtures/site --database fixtures/database.sql --logs fixtures/logs --baseline fixtures/baseline.json --output results --case-id DEMO-001
```

Silnik nie ma zależności runtime (tylko biblioteka standardowa). Narzędzia testowe i deweloperskie instaluje się z `requirements/dev.lock` — wersje przypięte, każda paczka z hashem SHA-256, więc pip odrzuci pakiet o innej zawartości. Po zmianie extras w `pyproject.toml` lock generuje się ponownie (polecenie jest w nagłówku pliku; test `tests/test_supply_chain.py` wykrywa rozjazd):

```bash
uv pip compile pyproject.toml --extra dev --generate-hashes --python-version 3.12 --universal -o requirements/dev.lock
uv pip compile requirements/audit.in --generate-hashes --python-version 3.12 --universal -o requirements/audit.lock
```

CI instaluje z locka (`--require-hashes`), uruchamia `pip-audit` na obu lockach (znana podatność = czerwone CI) i zapisuje SBOM CycloneDX środowiska testowego jako artefakt `sbom-test-env`. Narzędzia audytu (`pip-audit`, `cyclonedx-bom`) mają własny lock `requirements/audit.lock` i osobny venv. Lokalny audyt: `python -m venv /tmp/sca && /tmp/sca/bin/pip install --require-hashes -r requirements/audit.lock && /tmp/sca/bin/pip-audit -r requirements/dev.lock --require-hashes --disable-pip --strict`.

`--database-format {sql,jsonl}` (domyślnie `sql`) mówi, czym jest plik `--database`: zrzutem SQL (`INSERT INTO … VALUES`) albo eksportem JSONL — jeden obiekt `{"table": "wp_users", "row": {"ID": 1, "user_login": "…"}}` na wiersz, wartości tylko łańcuch, liczba lub `null`. Formatu nie zgaduje się po treści; wiersze niezgodne z kontraktem obniżają pokrycie bazy (szczegóły: [docs/RULES.md](docs/RULES.md)).

`--log-format {combined,common,json}` (domyślnie `combined`) mówi, w jakim formacie są wiersze `--logs`: Apache/Nginx `combined` albo `common`, albo jeden obiekt JSON na wiersz (pola `time`, `remote_addr`, `method`, `uri`, `status`, opcjonalnie `bytes` i `forwarded_for`). Formatu nie zgaduje się po treści; wiersze odrzucone obniżają pokrycie logów z liczbą per powód. `--trusted-proxy CIDR` (powtarzalna) wskazuje sieci zaufanych proxy: tylko dla połączeń z nich adres klienta pochodzi z `forwarded_for` (format json). `--log-clock-skew SEKUNDY` to deklarowana niepewność zegara serwera logów (nieujemna); bez niej zegar jest niezweryfikowany. Wszystkie trzy trafiają do `case.json` (szczegóły: [docs/RULES.md](docs/RULES.md), sekcja „Logi HTTP”).

`--pseudonymize` zastępuje adresy IP klientów, loginy i `user_id` kont — w atrybutach obserwacji i w tekstach (cytaty, `uri`, wyjaśnienia, luki) — pseudonimami `ip-`/`user-`/`uid-<16 hex>` (HMAC-SHA256 z kluczem losowanym na jedno uruchomienie, nigdzie niezapisywanym). Ta sama wartość ma ten sam pseudonim w jednym raporcie, więc korelacja działa; między uruchomieniami pseudonimy się różnią. Porównanie z `--known-admin` odbywa się przed pseudonimizacją. Jawne pozostają m.in. czas rejestracji konta, nazwy w ścieżkach i kluczach (np. slug autora w URL) i domeny e-mail w cytatach. Bez flagi narzędzie ostrzega na stderr, gdy raport zawiera takie dane. `case.json` zapisuje wybór w `flags.pseudonymize`. Niezależnie od flagi każdy tekst swobodny raportu przechodzi redakcję sekretów (`wpincidentlens/privacy.py`).

`--baseline PLIK` to zaufany JSON operatora: `{"files": {"ścieżka/względna.php": "<sha256>"}, "known_admins": ["login"]}`, opcjonalnie z `wordpress_version` i `reference`, które trafiają do ustaleń jako opis referencji.

Opcjonalnie `--core-checksums PLIK` wskazuje **lokalny** plik JSON z sumami MD5 rdzenia w kształcie `api.wordpress.org/core/checksums/1.0` (`{"checksums": {"wp-admin/about.php": "<md5>", …}}`; można dopisać `wordpress_version` i `reference`). Narzędzie niczego nie pobiera z sieci. Manifest jest wpisem `evidence` źródła `baseline`; MD5 służy tylko do porównania z manifestem (ustalenia `CORE_CHECKSUM_MISMATCH`, `CORE_FILE_NOT_IN_MANIFEST`, `CORE_FILE_MISSING`), skrótem dowodu pozostaje SHA-256. Manifest innej wersji lub locale daje rozbieżności; niepoprawny manifest to błąd wywołania (kod 2). Klasy plików bez referencji są w pokryciu oznaczane `NOT_CHECKED`.

Plik kodu (PHP i pokrewne, `.htaccess`, `.user.ini`, `php.ini`), którego nie porównano z żadną referencją — baseline ani manifestem — obniża pokrycie `files` do `PARTIAL`: zakres jest niepełny, przebieg bez ustaleń daje `INCONCLUSIVE`, a kod wyjścia to 3 (ADR 0005, pkt 6). Dotyczy to także demo powyżej: `fixtures/baseline.json` nie zawiera skrótów plików, więc żaden plik kodu nie ma referencji i polecenie kończy się kodem 3 z oceną `SUSPICIOUS` (zapis wyniku: [demo/report.json](demo/report.json)). Wpis wymieniony w referencji, którego nie dało się odczytać (dowiązanie, drugi hardlink, brak uprawnień), daje ustalenie `REFERENCE_FILE_UNREADABLE`. Każda reguła integralności zgłasza najwyżej 200 ustaleń na przebieg; nadmiar jest luką z łączną liczbą wykryć. Baseline i manifest z powtórzonym kluczem, ścieżką niewzględną albo skrótem w złej postaci są odrzucane (kod 2).

Otwórz `results/report.html`. Kod wyjścia opisuje pełność analizy, nie wynik: `0` — zakres pełny, `3` — analiza częściowa (np. brak bazy lub logów, plik kodu bez zaufanej referencji, pominięty wpis, limit), `4` — podane źródło nieprzetworzone, `2` — błąd wywołania. Ocenę podaje pole `assessment` w `report.json`.

## Co analizuje PoC (stan po M2)

- **Pliki — reguły ścieżki i treści** (13 reguł, opis i fałszywe alarmy: [docs/RULES.md](docs/RULES.md)): kod PHP i podwójne rozszerzenia w uploads, kod w katalogach zasobów i tłumaczeń, `eval`/`assert` na zdekodowanej treści lub danych żądania, dane żądania przy wykonaniu komendy, w `include` i jako cel zapisu pliku, `preg_replace /e`, długie bloby, `.htaccess` włączający PHP w uploads, `auto_prepend_file`/`auto_append_file`. Każda to heurystyka; żadna nie daje pewności `high`.
- **Pliki — integralność względem referencji**: `BASELINE_FILE_CHANGED`, `BASELINE_FILE_MISSING`, `NEW_FILE_SINCE_BASELINE` (mu-plugins i drop-ins), `CORE_CHECKSUM_MISMATCH`, `CORE_FILE_NOT_IN_MANIFEST`, `CORE_FILE_MISSING`, `REFERENCE_FILE_UNREADABLE`.
- **WPDetector**: wersja WordPressa, wersja bazy, locale i prefiks tabel jako kandydaci z pewnością (`observations`), bez ustalenia i bez wpływu na ocenę.
- **Baza (wybrane `INSERT`)**: administrator spoza zaufanej listy, aktywny znacznik HTML lub schemat JS w opcji.
- **Logi (formaty combined, common, json)**: żądanie do pliku kodu (rozszerzenia jak w regułach plików, także podwójne) w uploads oraz korelacja z plikami, które mają ustalenie (ścieżka i czas).
- **Korelacja plik–żądanie** (ADR 0007, [docs/RULES.md](docs/RULES.md#korelacja-plikżądanie-correlate-t-401)): ta sama ścieżka (`CORRELATED_UPLOAD_REQUEST`, `CORRELATED_FILE_REQUEST`) i bliskość w czasie żądania i `mtime` pliku z ustaleniem (`REQUEST_NEAR_FILE_CHANGE`, okno `--correlation-window SECONDS`, domyślnie 900, poszerzane o zadeklarowaną niepewność zegara). Korelacja nie dowodzi przyczynowości, zapisu ani wykonania pliku; HTTP 200 też nie.

Brak ustalenia w którymkolwiek z tych obszarów nie oznacza, że witryna nie została naruszona.

## Bezpieczny odczyt dowodów (T-101)

Materiał dowodowy otwiera wyłącznie moduł `wpincidentlens/ingest.py`: względem deskryptora katalogu, z `O_NOFOLLOW`, czytając tylko zwykłe pliki i katalogi (Linux i macOS; na platformie bez `dir_fd`/`O_NOFOLLOW` narzędzie odmawia pracy). Skrót SHA-256 i analizowana treść pochodzą z jednego odczytu, a po analizie dowody są weryfikowane ponownie. Zmiany zachowania względem wcześniejszego PoC:

- Ścieżka `--files`, `--database`, `--logs`, `--baseline` lub `--core-checksums` będąca dowiązaniem symbolicznym jest **odrzucana** (kod wyjścia 2) — podaj ścieżkę rzeczywistą. Symlinki wewnątrz drzewa są nadal pomijane z luką.
- Pliki z wieloma dowiązaniami twardymi (`st_nlink > 1`) są domyślnie **pomijane** z luką `SKIPPED_HARDLINK`. Kopie z deduplikacją (np. `rsync --link-dest`) wymagają `--allow-hardlinks`.
- `--output` nie może leżeć w żadnym źródle dowodów ani go zawierać; niepoprawny lub nieczytelny `--baseline` to błąd wywołania (kod 2). Baseline jest wpisem w `evidence`.
- Limity dotyczą wszystkich źródeł łącznie; po przekroczeniu analiza jest częściowa i powstaje nazwana luka w `coverage_gaps`. Komunikaty luk zawierają tylko ścieżki względne do źródła i nazwę błędu (np. `EACCES`).

| Flaga | Domyślnie | Znaczenie |
|---|---|---|
| `--allow-hardlinks` | wyłączona | czytaj pliki z wieloma dowiązaniami twardymi; raport podaje ich liczbę |
| `--no-reverify` | wyłączona | pomiń ponowną weryfikację skrótów po analizie (odnotowane jako luka) |
| `--max-files` | 200000 | limit liczby plików |
| `--max-entries` | 1000000 | limit wszystkich wpisów (pliki, katalogi, dowiązania, pliki specjalne) |
| `--max-file-bytes` | 2147483648 (2 GiB) | większy plik jest pomijany bez liczenia skrótu |
| `--max-total-bytes` | 21474836480 (20 GiB) | limit łącznego rozmiaru czytanych plików |
| `--max-seconds` | 1800 | limit czasu całej analizy, sprawdzany między plikami oraz w trakcie parsowania SQL, JSONL i logów, reguł bazy i treści plików i korelacji; nie przerywa odczytu i skrótu jednego pliku |
| `--max-depth` | 64 | limit głębokości katalogów; głębszy katalog nie jest przeglądany |
| `--max-path-bytes` | 4096 | limit długości ścieżki względnej do źródła; dłuższa ścieżka jest pomijana |

Każdy limit musi być dodatni i skończony, inaczej wywołanie jest odrzucane (kod 2). Stałe limity: treść plików analizowana do 4 MiB, zrzut SQL czytany strumieniowo (limit pliku `--max-file-bytes`, jedna instrukcja do 16 MiB), log czytany strumieniowo (limit pliku `--max-file-bytes`, jeden wiersz do 64 KiB), baseline do 64 MiB, manifest sum rdzenia do 8 MiB i 50 000 wpisów. Bezpieczny odczyt nie zastępuje izolacji: nie wykrywa punktów montowania w drzewie ani zmian cofniętych przed ponowną weryfikacją; materiał montuj tylko do odczytu, z `nodev`.

## Sprawa i zapis wyników (T-101)

Wywołanie waliduje `wpincidentlens/case.py` (CaseManager), zanim zostanie przeczytany jakikolwiek dowód; wyniki zapisuje wyłącznie `wpincidentlens/report.py` (Reporter).

- `--case-id` (domyślnie `WPINCIDENTLENS-DEMO`) i opcjonalny `--operator-id`: 1–64 znaki `A-Z a-z 0-9 . _ -`, pierwszy znak inny niż kropka i łącznik. Inna wartość (separator ścieżki, spacja, znak sterujący, znak spoza ASCII) to błąd wywołania (kod 2).
- `--operator-id` to pseudonim podany przez operatora. Narzędzie nie odczytuje nazwy użytkownika systemu, nazwy hosta ani zmiennych środowiskowych; bez flagi pole ma wartość `null`.
- Wartość `--known-admin` i loginy w baseline, których nie da się zapisać w UTF-8, oraz ścieżki i skróty w baseline w niepoprawnej postaci są odrzucane (kod 2) przed analizą.
- `--output` wskazujący dowiązanie symboliczne albo wpis niebędący katalogiem jest odrzucany (kod 2). Sprawdzany jest ostatni składnik ścieżki, nie katalogi nadrzędne.
- Każdy plik wyników powstaje jako plik tymczasowy w katalogu wyników (uprawnienia `0600`) i jest zamieniany na docelowy dopiero po zapisaniu w całości. Istniejący wpis o nazwie wyniku, także dowiązanie symboliczne, jest zastępowany, a cel dowiązania pozostaje nietknięty. Zamiana dziewięciu plików nie jest jedną operacją: `case.json` jest zamieniany jako ostatni i podaje SHA-256 pozostałych (`outputs`); plik, którego skrót nie zgadza się z `case.json`, jest pozostałością przerwanego zapisu i jest nieaktualny.

Pliki wyniku (R-40; kształty opisuje `wpincidentlens/outputs.py`). `report.json` jest źródłem prawdy, pozostałe są jego widokami:

| Plik | Zawartość |
|---|---|
| `report.json`, `report.html` | pełny raport `poc-1` i jego wersja HTML |
| `evidence-manifest.json` | `evidence` raportu: identyfikatory, ścieżki logiczne, statusy odczytu, SHA-256 |
| `observations.jsonl` | jedna obserwacja na wiersz, w kolejności raportu, wyłącznie ASCII |
| `findings.json`, `timeline.json` | `findings` i `timeline` raportu |
| `coverage.json` | `coverage`, `coverage_gaps`, `scope_complete`, `assessment` |
| `run.log` | wiersze JSON (ASCII) ze stałą listą pól: narzędzie i wersja, sprawa, czas analizy, ocena, kod wyjścia, liczniki i status pokrycia per źródło; bez treści dowodów, nazw plików i tekstów swobodnych |
| `case.json` | opis sprawy i przebiegu (poniżej) |

Każdy widok JSON ma `schema_version` (np. `findings-poc-1`) i `case_id`.

`case.json` (schemat **`case-poc-1`**, [docs/schema/case-poc-1.schema.json](docs/schema/case-poc-1.schema.json)) opisuje sprawę i przebieg. Nie zawiera sekretów, ścieżek hosta, zmiennych środowiskowych ani listy zaufanych administratorów.

| Pole | Zawartość |
|---|---|
| `schema_version`, `case_id`, `operator_id` | wersja schematu, identyfikator sprawy, pseudonim operatora albo `null` |
| `tool`, `tool_version` | jak w `report.json` |
| `created_at_utc`, `analysis_finished_at_utc` | czas walidacji wywołania i czas zakończenia analizy (równy `analyzed_at_utc` raportu); UTC, zegar narzędzia |
| `sources` | dla `files`, `database`, `logs`, `baseline`: `provided` oraz `name` — wyłącznie ostatni składnik podanej ścieżki (`null`, gdy źródła nie podano albo ścieżka nie ma nazwy, np. `.`); `database` podanej bazy ma też `format` (`sql` albo `jsonl`); `core_checksums` w tym samym kształcie tylko wtedy, gdy podano `--core-checksums` |
| `limits` | wszystkie limity odczytu użyte w przebiegu |
| `flags` | `allow_hardlinks`, `reverify`, `pseudonymize` (to ostatnie opcjonalne w schemacie) |
| `report` | nazwa pliku raportu i SHA-256 jego zapisanych bajtów |
| `assessment`, `exit_code` | etykieta triage z raportu i kod wyjścia procesu |
| `ruleset` | `id`, `version` i SHA-256 kanonicznego JSON rejestru reguł (`wpincidentlens/rules.py`); pole opcjonalne w schemacie |
| `outputs` | SHA-256 każdego innego zapisanego pliku wyniku, po nazwie; pole opcjonalne w schemacie (starsze `case.json` go nie mają) |

## Kontener Docker

`docker/Dockerfile` przypina obraz bazowy `python:3.12-slim` digestem indeksu multi-arch (odczyt z 2026-11-12) i kopiuje do obrazu wyłącznie pakiet `wpincidentlens/` (`.dockerignore`); proces działa jako UID/GID 65532. Katalog wyników musi być zapisywalny dla tego UID, ale nie dla wszystkich. Pokaz, wariant A — katalog należy do UID 65532 (pliki wyników będą jego, `0600`; odczyt przez `sudo` albo po zmianie właściciela):

```bash
sudo install -d -m 0700 -o 65532 -g 65532 results
cd docker && docker compose run --build --rm wpincidentlens
```

Wariant B — kontener działa z UID użytkownika hosta, katalog zostaje jego (`0700`):

```bash
install -d -m 0700 results
cd docker && docker compose run --build --rm --user "$(id -u):$(id -g)" wpincidentlens
```

Nie nadawaj katalogowi wyników praw `777`: każdy użytkownik hosta mógłby podmienić lub odczytać wyniki.

`docker/compose.yaml` ustawia: brak sieci, rootfs tylko do odczytu, dowody zamontowane `:ro`, UID 65532, `--cap-drop ALL`, `no-new-privileges`, limity PID (128), pamięci (1 GiB, bez swap) i CPU (1), `/tmp` jako tmpfs `noexec,nosuid`. Te same ograniczenia, jako argumenty `docker run`, są w `docker/run-flags.txt`; zgodność obu plików i oczekiwań sondy sprawdza `tests/test_container_probe.py`. Zadanie CI `container` (`.github/workflows/container.yml`) buduje obraz i **mierzy** izolację sondą `docker/probe.py` uruchomioną w kontenerze z tymi flagami (UID/GID, odmowa zapisu do `/`, `/app` i dowodów, `noexec` na `/tmp`, capability i `NoNewPrivs` z `/proc/self/status`, tylko interfejs `lo` i nieudane połączenie, limity cgroup v2). Następnie uruchamia `command` z compose w kontenerze i to samo polecenie na hoście i wymaga tej samej oceny, ustaleń i kodu wyjścia. Wynik sondy, porównanie i SBOM obrazu (CycloneDX) są artefaktem `container-measurement`. Pomiar dotyczy runnera `ubuntu-24.04` (cgroup v2); na innym hoście uruchom sondę samodzielnie (polecenie w workflow).

## Ograniczenia PoC

- Reguły plików to heurystyki tekstowe bez parsera PHP: łączenie łańcuchów, komentarz w środku wywołania i zmienne pośrednie je omijają (lista ograniczeń: [docs/RULES.md](docs/RULES.md)). Nie ma YARA-X. Częstości fałszywych alarmów nie mierzono na rzeczywistych wtyczkach i motywach.
- Sumy rdzenia są porównywane tylko z manifestem podanym lokalnie przez operatora; narzędzie nie sprawdza, czy manifest odpowiada wersji i locale witryny, i nie ma manifestów wtyczek ani motywów. Kod wtyczek i motywów da się zweryfikować wyłącznie własnym baseline; bez niego zostaje `NOT_CHECKED` i kod wyjścia 3.
- Wersja, locale i prefiks tabel z WPDetector to kandydaci odczytani z plików, które napastnik mógł zmienić; nie są porównywani z bazą ani z wersją manifestu.
- Parsowanie SQL jest celowo ograniczone do wybranych składni `INSERT INTO`; nie interpretuje złożonych dumpów, `BLOB`, triggerów, procedur, multisite ani całej składni MySQL. Brak informacji jest jawnie zgłaszany.
- Dane serializowane PHP są dekodowane tylko jako dane (`wpincidentlens/phpserialize.py`) i tylko tam, gdzie potrzebuje ich reguła (role, cron, aktywne wtyczki); obiekty zostają nieprzezroczystym znacznikiem, a zmian w innych serializowanych opcjach narzędzie nie rozpoznaje.
- Analizuje tylko logi dostępu w formatach `combined`, `common` i `json` (bez logów błędów, `vhost_combined` i IIS). Czas z logu jest zapisywany dosłownie i, gdy ma strefę, także w UTC; zegar serwera nie jest weryfikowany, a **wektor ataku nie jest ustalany**.
- Symlinki, pliki specjalne i (domyślnie) pliki z wieloma dowiązaniami twardymi są pomijane z luką; pliki powyżej 4 MiB są haszowane, ale ich zawartość nie jest skanowana. Brak uczenia maszynowego i nie ma wykonywania PHP.
- Testowe detekcje są heurystykami i mogą mieć false positive / false negative.
- Nie wdraża pełnej chain of custody, sygnowania dowodów ani modeli uprawnień. Nie uruchamiaj na poufnych realnych danych bez przeglądu bezpieczeństwa.
- Raport HTML escapuje każdą wartość w jednym miejscu i deklaruje Content-Security-Policy bez skryptów (`<meta>`, więc bez dyrektyw działających tylko w nagłówku HTTP). Query string i dane logowania z URL są usuwane, a teksty swobodne redagowane, ale wzorce sekretów nie są zupełne, a nazwy plików i ścieżki względne nie są redagowane. Bez `--pseudonymize` adresy IP klientów i loginy (także w postaci e-mail) są w raporcie jawnie i są danymi osobowymi; z flagą część danych nadal zostaje jawna (lista wyżej). Przechowuj raport bezpiecznie i przejrzyj go przed przekazaniem.

## Schemat JSON

`report.json` ma schemat **`poc-1`**: kontrakt w `wpincidentlens/models.py`, opublikowany JSON Schema w [docs/schema/report-poc-1.schema.json](docs/schema/report-poc-1.schema.json), decyzje w [ADR 0003](docs/adr/0003-schemat-poc-1-i-migracja.md). Przykład: [demo/report.json](demo/report.json).

| Pole | Zawartość |
|---|---|
| `evidence` | każdy wpis materiału wejściowego, także pominięty: ścieżka względna do źródła, `read_status` (`READ`, `SKIPPED_SYMLINK`, `SKIPPED_HARDLINK`, `SKIPPED_SPECIAL`, `SKIPPED_LIMIT`, `ERROR`, `CHANGED`), SHA-256 i rozmiar, jeśli bajty przeczytano |
| `observations` | fakty odczytane przez parsery (np. plik PHP w uploads, żądanie HTTP), bez oceny; każda wskazuje dowód i miejsce: ścieżkę, wiersz logu albo tabelę. Obserwacja reguły treści ma atrybuty `rule_version`, `offset`, `length`, `match_count`, nigdy dopasowaną treść. Kandydaci WPDetector (`WP_*_CANDIDATE`) są obserwacjami bez ustalenia |
| `findings` | interpretacje: reguła, `severity` i `confidence` jako niezależne skale, wyjaśnienie oraz lista obserwacji, na których ustalenie się opiera |
| `coverage` | dla `files`, `database`, `logs` i `baseline`: status (`ANALYZED`, `PARTIAL`, `NOT_PROVIDED`, `FAILED`), liczniki wpisów według statusu odczytu i powody |
| `coverage_gaps` | wszystkie ograniczenia analizy jako teksty |
| `timeline` | orientacyjne znaczniki czasu w UTC ze źródłem (`log`, `mtime`); nie dowód kolejności ani przyczynowości |
| `scope_complete` | `true`, gdy pliki, baza i logi mają pokrycie `ANALYZED`. Dla plików wymaga to m.in. porównania każdego pliku kodu z referencją (baseline albo manifest sum rdzenia); bez pełnej referencji jest `false` |

Identyfikatory (`ev_…`, `obs_…`, `fnd_…`) są skrótami treści: ten sam materiał daje te same identyfikatory w każdym uruchomieniu.

`assessment` to etykieta triage, nigdy „clean”:

| Wartość | Kiedy |
|---|---|
| `STRONG_INDICATORS` | istnieje ustalenie o wadze `high` lub `critical` i pewności `high`. Obecne heurystyki PoC nie osiągają tego progu |
| `SUSPICIOUS` | istnieje jakiekolwiek inne ustalenie |
| `NO_INDICATORS_IN_ANALYZED_SCOPE` | brak ustaleń przy pełnym zakresie (`scope_complete`) |
| `INCONCLUSIVE` | brak ustaleń przy niepełnym zakresie: brak bazy lub logów, plik kodu bez zaufanej referencji, pominięte lub zmienione wpisy, przekroczony limit, nieobsługiwany format |

Raporty w starszym schemacie 0.1.0 przenosi czysta funkcja `wpincidentlens.migrate.migrate_0_1_0(report: dict) -> dict`. Stary raport nie niósł pokrycia ani statusów odczytu, więc wynik oznacza je jako `UNKNOWN_LEGACY`, ustalenia opiera na obserwacjach syntetycznych `LEGACY_FINDING`, a ocenę przenosi ostrożnie: `INDICATORS_FOUND` → `SUSPICIOUS`, `NO_INDICATORS_IN_ANALYZED_SCOPE` → `INCONCLUSIVE`. Migracja nie ma wejścia w CLI; narzędzie zapisuje wyłącznie `poc-1`.

## Dokumentacja projektu

Szczegóły architektury, zagrożeń, warunków akceptacji, roadmapy i przeglądu inżynierskiego znajdują się w `docs/WPIncidentLens_Specyfikacja_Techniczna.md`, `docs/WPIncidentLens_Specyfikacja_Senior_PoC_2026-11-09.md`, `docs/WPIncidentLens_Plan_Realizacji_Kamienie_Milowe_2026-11-11.pdf` i plikach DOCX w katalogu `docs/`.


## Zmiana nazwy

Projekt, pakiet Pythona i polecenie nazywają się **WPIncidentLens** (`wpincidentlens`). Prototyp z 9 listopada 2026 nosił nazwę WPTrace; 11 listopada 2026 usunięto ją z kodu, poleceń, raportu i nazw dokumentów (`docs/adr/0004-zmiana-nazwy-na-wpincidentlens.md`). Polecenie `python -m wptrace` już nie istnieje. Dawna nazwa pozostaje tylko tam, gdzie opisuje historię: w `archives/` (oryginalne pakiety), w treści plików DOCX i PDF, w `docs/MIGRATION_2026-11-11.md`, `docs/legacy-release-notes.txt` oraz w zachowanym raporcie 0.1.0 używanym w teście migracji.

## Materiały źródłowe i zakres migracji

Przywrócono zawartość oryginalnych archiwów wydania, specyfikacje Markdown/DOCX, plan PDF oraz przykładowe artefakty demonstracyjne. Archiwa źródłowe zachowano w `archives/` dla integralności i śledzenia pochodzenia. **Do repozytorium nie należy dodawać autentycznych dowodów, logów produkcyjnych, haseł ani kluczy.**

Migracja repozytorium nie oznacza gotowości produkcyjnej.
