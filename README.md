# WPIncidentLens — prototyp analizy powłamaniowej WordPressa

**Nie jest to gotowe narzędzie produkcyjne ani dowód braku kompromitacji.**

PoC zapewnia działający **offline** przepływ: statyczna analiza kopii katalogu WordPressa, wybranego podzbioru eksportu SQL i logów HTTP → manifest SHA-256 → `report.json` + `report.html` + `case.json`. Zawiera wyłącznie syntetyczne dane testowe.

## Test lokalny

Wymagany Python 3.12. Szczegóły środowiska i faktyczne wyniki: [docs/BASELINE.md](docs/BASELINE.md).

```bash
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q
python -m wpincidentlens --files fixtures/site --database fixtures/database.sql --logs fixtures/logs --baseline fixtures/baseline.json --output results --case-id DEMO-001
```

Otwórz `results/report.html`. Kod wyjścia opisuje pełność analizy, nie wynik: `0` — zakres pełny, `3` — analiza częściowa (np. brak bazy lub logów), `4` — podane źródło nieprzetworzone, `2` — błąd wywołania. Ocenę podaje pole `assessment` w `report.json`.

## Bezpieczny odczyt dowodów (T-101)

Materiał dowodowy otwiera wyłącznie moduł `wpincidentlens/ingest.py`: względem deskryptora katalogu, z `O_NOFOLLOW`, czytając tylko zwykłe pliki i katalogi (Linux i macOS; na platformie bez `dir_fd`/`O_NOFOLLOW` narzędzie odmawia pracy). Skrót SHA-256 i analizowana treść pochodzą z jednego odczytu, a po analizie dowody są weryfikowane ponownie. Zmiany zachowania względem wcześniejszego PoC:

- Ścieżka `--files`, `--database`, `--logs` lub `--baseline` będąca dowiązaniem symbolicznym jest **odrzucana** (kod wyjścia 2) — podaj ścieżkę rzeczywistą. Symlinki wewnątrz drzewa są nadal pomijane z luką.
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
| `--max-seconds` | 1800 | limit czasu całej analizy, sprawdzany między plikami |
| `--max-depth` | 64 | limit głębokości katalogów; głębszy katalog nie jest przeglądany |
| `--max-path-bytes` | 4096 | limit długości ścieżki względnej do źródła; dłuższa ścieżka jest pomijana |

Każdy limit musi być dodatni i skończony, inaczej wywołanie jest odrzucane (kod 2). Stałe limity: treść plików analizowana do 4 MiB, SQL do 20 MiB, log do 30 MiB. Bezpieczny odczyt nie zastępuje izolacji: nie wykrywa punktów montowania w drzewie ani zmian cofniętych przed ponowną weryfikacją; materiał montuj tylko do odczytu, z `nodev`.

## Sprawa i zapis wyników (T-101)

Wywołanie waliduje `wpincidentlens/case.py` (CaseManager), zanim zostanie przeczytany jakikolwiek dowód; wyniki zapisuje wyłącznie `wpincidentlens/report.py` (Reporter).

- `--case-id` (domyślnie `WPINCIDENTLENS-DEMO`) i opcjonalny `--operator-id`: 1–64 znaki `A-Z a-z 0-9 . _ -`, pierwszy znak inny niż kropka i łącznik. Inna wartość (separator ścieżki, spacja, znak sterujący, znak spoza ASCII) to błąd wywołania (kod 2).
- `--operator-id` to pseudonim podany przez operatora. Narzędzie nie odczytuje nazwy użytkownika systemu, nazwy hosta ani zmiennych środowiskowych; bez flagi pole ma wartość `null`.
- Wartość `--known-admin` oraz ścieżki, skróty i loginy w baseline, których nie da się zapisać w UTF-8, są odrzucane (kod 2) przed analizą.
- `--output` wskazujący dowiązanie symboliczne albo wpis niebędący katalogiem jest odrzucany (kod 2). Sprawdzany jest ostatni składnik ścieżki, nie katalogi nadrzędne.
- Każdy plik wyników powstaje jako plik tymczasowy w katalogu wyników (uprawnienia `0600`) i jest zamieniany na docelowy dopiero po zapisaniu w całości. Istniejący wpis o nazwie wyniku, także dowiązanie symboliczne, jest zastępowany, a cel dowiązania pozostaje nietknięty. Zamiana trzech plików nie jest jedną operacją: `case.json` jest zamieniany jako ostatni.

`case.json` (schemat **`case-poc-1`**, [docs/schema/case-poc-1.schema.json](docs/schema/case-poc-1.schema.json)) opisuje sprawę i przebieg. Nie zawiera sekretów, ścieżek hosta, zmiennych środowiskowych ani listy zaufanych administratorów.

| Pole | Zawartość |
|---|---|
| `schema_version`, `case_id`, `operator_id` | wersja schematu, identyfikator sprawy, pseudonim operatora albo `null` |
| `tool`, `tool_version` | jak w `report.json` |
| `created_at_utc`, `analysis_finished_at_utc` | czas walidacji wywołania i czas zakończenia analizy (równy `analyzed_at_utc` raportu); UTC, zegar narzędzia |
| `sources` | dla `files`, `database`, `logs`, `baseline`: `provided` oraz `name` — wyłącznie ostatni składnik podanej ścieżki (`null`, gdy źródła nie podano albo ścieżka nie ma nazwy, np. `.`) |
| `limits` | wszystkie limity odczytu użyte w przebiegu |
| `flags` | `allow_hardlinks`, `reverify` |
| `report` | nazwa pliku raportu i SHA-256 jego zapisanych bajtów |
| `assessment`, `exit_code` | etykieta triage z raportu i kod wyjścia procesu |

## Kontener Docker

`docker/Dockerfile` używa `python:3.12-slim` bez pinu **wyłącznie na potrzeby PoC**. Przed wdrożeniem produkcyjnym wymagaj zweryfikowanego obrazu pinowanego po digest oraz SBOM. Aby uruchomić pokaz:

```bash
mkdir -p results && chmod 777 results  # TYLKO jednorazowy lokalny PoC; nigdy na rzeczywistych dowodach!
cd docker && docker compose run --build --rm wpincidentlens
```

Tryb bez sieci, ro rootfs, dowody zamontowane ro, kontener bez capability, non-root. Wymaga poprawnych uprawnień do odczytu dowodów i zapisu wyniku przez UID 65532. Pliki wyników mają uprawnienia `0600` i właściciela UID 65532, więc inny użytkownik hosta odczyta je dopiero po zmianie właściciela lub uprawnień.

## Ograniczenia PoC

- Wykrywa tylko kilka heurystyk PHP, nie zawiera produkcyjnych reguł YARA-X ani weryfikacji oficjalnych checksumów. Integracje przewidziano w pełnej specyfikacji.
- Parsowanie SQL jest celowo ograniczone do wybranych składni `INSERT INTO`; nie interpretuje złożonych dumpów, `BLOB`, triggerów, procedur, multisite ani całej składni MySQL. Brak informacji jest jawnie zgłaszany.
- Brak parsera PHP serialization, więc nie rozpoznaje ukrytych zmian w serializowanych opcjach.
- Nie analizuje logów poza formatem Apache/Nginx combined. Czas z logu jest zapisywany dosłownie i, gdy ma strefę, także w UTC; zegar serwera nie jest weryfikowany, a **wektor ataku nie jest ustalany**.
- Symlinki, pliki specjalne i (domyślnie) pliki z wieloma dowiązaniami twardymi są pomijane z luką; pliki powyżej 4 MiB są haszowane, ale ich zawartość nie jest skanowana. Brak uczenia maszynowego i nie ma wykonywania PHP.
- Testowe detekcje są heurystykami i mogą mieć false positive / false negative.
- Nie wdraża pełnej chain of custody, sygnowania dowodów ani modeli uprawnień. Nie uruchamiaj na poufnych realnych danych bez przeglądu bezpieczeństwa.
- Raport HTML nie wyświetla niekontrolowanego kodu, lecz metadane IP/URL mogą nadal być danymi osobowymi; przechowuj bezpiecznie.

## Schemat JSON

`report.json` ma schemat **`poc-1`**: kontrakt w `wpincidentlens/models.py`, opublikowany JSON Schema w [docs/schema/report-poc-1.schema.json](docs/schema/report-poc-1.schema.json), decyzje w [ADR 0003](docs/adr/0003-schemat-poc-1-i-migracja.md). Przykład: [demo/report.json](demo/report.json).

| Pole | Zawartość |
|---|---|
| `evidence` | każdy wpis materiału wejściowego, także pominięty: ścieżka względna do źródła, `read_status` (`READ`, `SKIPPED_SYMLINK`, `SKIPPED_HARDLINK`, `SKIPPED_SPECIAL`, `SKIPPED_LIMIT`, `ERROR`, `CHANGED`), SHA-256 i rozmiar, jeśli bajty przeczytano |
| `observations` | fakty odczytane przez parsery (np. plik PHP w uploads, żądanie HTTP), bez oceny; każda wskazuje dowód i miejsce: ścieżkę, wiersz logu albo tabelę |
| `findings` | interpretacje: reguła, `severity` i `confidence` jako niezależne skale, wyjaśnienie oraz lista obserwacji, na których ustalenie się opiera |
| `coverage` | dla `files`, `database`, `logs` i `baseline`: status (`ANALYZED`, `PARTIAL`, `NOT_PROVIDED`, `FAILED`), liczniki wpisów według statusu odczytu i powody |
| `coverage_gaps` | wszystkie ograniczenia analizy jako teksty |
| `timeline` | orientacyjne znaczniki czasu w UTC ze źródłem (`log`, `mtime`); nie dowód kolejności ani przyczynowości |
| `scope_complete` | `true`, gdy pliki, baza i logi zostały przeanalizowane w całości |

Identyfikatory (`ev_…`, `obs_…`, `fnd_…`) są skrótami treści: ten sam materiał daje te same identyfikatory w każdym uruchomieniu.

`assessment` to etykieta triage, nigdy „clean”:

| Wartość | Kiedy |
|---|---|
| `STRONG_INDICATORS` | istnieje ustalenie o wadze `high` lub `critical` i pewności `high`. Obecne heurystyki PoC nie osiągają tego progu |
| `SUSPICIOUS` | istnieje jakiekolwiek inne ustalenie |
| `NO_INDICATORS_IN_ANALYZED_SCOPE` | brak ustaleń przy pełnym zakresie (`scope_complete`) |
| `INCONCLUSIVE` | brak ustaleń przy niepełnym zakresie: brak bazy lub logów, pominięte lub zmienione wpisy, przekroczony limit, nieobsługiwany format |

Raporty w starszym schemacie 0.1.0 przenosi czysta funkcja `wpincidentlens.migrate.migrate_0_1_0(report: dict) -> dict`. Stary raport nie niósł pokrycia ani statusów odczytu, więc wynik oznacza je jako `UNKNOWN_LEGACY`, ustalenia opiera na obserwacjach syntetycznych `LEGACY_FINDING`, a ocenę przenosi ostrożnie: `INDICATORS_FOUND` → `SUSPICIOUS`, `NO_INDICATORS_IN_ANALYZED_SCOPE` → `INCONCLUSIVE`. Migracja nie ma wejścia w CLI; narzędzie zapisuje wyłącznie `poc-1`.

## Dokumentacja projektu

Szczegóły architektury, zagrożeń, warunków akceptacji, roadmapy i przeglądu inżynierskiego znajdują się w `docs/WPIncidentLens_Specyfikacja_Techniczna.md`, `docs/WPIncidentLens_Specyfikacja_Senior_PoC_2026-11-09.md`, `docs/WPIncidentLens_Plan_Realizacji_Kamienie_Milowe_2026-11-11.pdf` i plikach DOCX w katalogu `docs/`.


## Zmiana nazwy

Projekt, pakiet Pythona i polecenie nazywają się **WPIncidentLens** (`wpincidentlens`). Prototyp z 9 listopada 2026 nosił nazwę WPTrace; 11 listopada 2026 usunięto ją z kodu, poleceń, raportu i nazw dokumentów (`docs/adr/0004-zmiana-nazwy-na-wpincidentlens.md`). Polecenie `python -m wptrace` już nie istnieje. Dawna nazwa pozostaje tylko tam, gdzie opisuje historię: w `archives/` (oryginalne pakiety), w treści plików DOCX i PDF, w `docs/MIGRATION_2026-11-11.md`, `docs/legacy-release-notes.txt` oraz w zachowanym raporcie 0.1.0 używanym w teście migracji.

## Materiały źródłowe i zakres migracji

Przywrócono zawartość oryginalnych archiwów wydania, specyfikacje Markdown/DOCX, plan PDF oraz przykładowe artefakty demonstracyjne. Archiwa źródłowe zachowano w `archives/` dla integralności i śledzenia pochodzenia. **Do repozytorium nie należy dodawać autentycznych dowodów, logów produkcyjnych, haseł ani kluczy.**

Migracja repozytorium nie oznacza gotowości produkcyjnej.
