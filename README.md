# WPIncidentLens — prototyp analizy powłamaniowej WordPressa

**Nie jest to gotowe narzędzie produkcyjne ani dowód braku kompromitacji.**

PoC zapewnia działający **offline** przepływ: statyczna analiza kopii katalogu WordPressa, wybranego podzbioru eksportu SQL i logów HTTP → manifest SHA-256 → `report.json` + `report.html`. Zawiera wyłącznie syntetyczne dane testowe.

## Test lokalny

Wymagany Python 3.12. Szczegóły środowiska i faktyczne wyniki: [docs/BASELINE.md](docs/BASELINE.md).

```bash
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q
python -m wptrace --files fixtures/site --database fixtures/database.sql --logs fixtures/logs --baseline fixtures/baseline.json --output results --case-id DEMO-001
```

Otwórz `results/report.html`.

## Bezpieczny odczyt dowodów (T-101)

Materiał dowodowy otwiera wyłącznie moduł `wptrace/ingest.py`: względem deskryptora katalogu, z `O_NOFOLLOW`, czytając tylko zwykłe pliki i katalogi (Linux i macOS; na platformie bez `dir_fd`/`O_NOFOLLOW` narzędzie odmawia pracy). Skrót SHA-256 i analizowana treść pochodzą z jednego odczytu, a po analizie dowody są weryfikowane ponownie. Zmiany zachowania względem wcześniejszego PoC:

- Ścieżka `--files`, `--database`, `--logs` lub `--baseline` będąca dowiązaniem symbolicznym jest **odrzucana** (kod wyjścia 2) — podaj ścieżkę rzeczywistą. Symlinki wewnątrz drzewa są nadal pomijane z luką.
- Pliki z wieloma dowiązaniami twardymi (`st_nlink > 1`) są domyślnie **pomijane** z luką `SKIPPED_HARDLINK`. Kopie z deduplikacją (np. `rsync --link-dest`) wymagają `--allow-hardlinks`.
- `--output` nie może leżeć w żadnym źródle dowodów ani go zawierać; niepoprawny lub nieczytelny `--baseline` to błąd wywołania (kod 2). Baseline trafia do `evidence_manifest`.
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

Stałe limity: treść plików analizowana do 4 MiB, SQL do 20 MiB, log do 30 MiB, ścieżka względna do 4096 bajtów, głębokość katalogów 64. Bezpieczny odczyt nie zastępuje izolacji: nie wykrywa punktów montowania w drzewie ani zmian cofniętych przed ponowną weryfikacją; materiał montuj tylko do odczytu, z `nodev`.

## Kontener Docker

`docker/Dockerfile` używa `python:3.12-slim` bez pinu **wyłącznie na potrzeby PoC**. Przed wdrożeniem produkcyjnym wymagaj zweryfikowanego obrazu pinowanego po digest oraz SBOM. Aby uruchomić pokaz:

```bash
mkdir -p results && chmod 777 results  # TYLKO jednorazowy lokalny PoC; nigdy na rzeczywistych dowodach!
cd docker && docker compose run --build --rm wptrace
```

Tryb bez sieci, ro rootfs, dowody zamontowane ro, kontener bez capability, non-root. Wymaga poprawnych uprawnień do odczytu dowodów i zapisu wyniku przez UID 65532.

## Ograniczenia PoC

- Wykrywa tylko kilka heurystyk PHP, nie zawiera produkcyjnych reguł YARA-X ani weryfikacji oficjalnych checksumów. Integracje przewidziano w pełnej specyfikacji.
- Parsowanie SQL jest celowo ograniczone do wybranych składni `INSERT INTO`; nie interpretuje złożonych dumpów, `BLOB`, triggerów, procedur, multisite ani całej składni MySQL. Brak informacji jest jawnie zgłaszany.
- Brak parsera PHP serialization, więc nie rozpoznaje ukrytych zmian w serializowanych opcjach.
- Nie analizuje logów poza formatem Apache/Nginx combined. Czas w logach zachowany dosłownie, **nie jest normalizowany ani ustalany wektor ataku**.
- Symlinki, pliki specjalne i (domyślnie) pliki z wieloma dowiązaniami twardymi są pomijane z luką; pliki powyżej 4 MiB są haszowane, ale ich zawartość nie jest skanowana. Brak uczenia maszynowego i nie ma wykonywania PHP.
- Testowe detekcje są heurystykami i mogą mieć false positive / false negative.
- Nie wdraża pełnej chain of custody, sygnowania dowodów ani modeli uprawnień. Nie uruchamiaj na poufnych realnych danych bez przeglądu bezpieczeństwa.
- Raport HTML nie wyświetla niekontrolowanego kodu, lecz metadane IP/URL mogą nadal być danymi osobowymi; przechowuj bezpiecznie.

## Schemat JSON

`assessment`: `INDICATORS_FOUND` lub `NO_INDICATORS_IN_ANALYZED_SCOPE` (nigdy „clean”); `timeline`: orientacyjne znaczniki czasu z logów i mtime, nie dowód przyczynowości; `findings`: reguła, waga, pewność, źródło i wyjaśnienie; `evidence_manifest`: SHA-256, rozmiar, ścieżka; `coverage_gaps`: wyłączenia i nieobsługiwane dane.

## Dokumentacja projektu

Szczegóły architektury, zagrożeń, warunków akceptacji, roadmapy i przeglądu inżynierskiego znajdują się w `docs/WPTrace_Specyfikacja_Techniczna.md`, `docs/WPTrace_Specyfikacja_Senior_PoC_2026-11-09.md`, `docs/WPTrace_Plan_Realizacji_Kamienie_Milowe_2026-11-11.pdf` i plikach DOCX w katalogu `docs/`.


## Zmiana nazwy

Repozytorium i nazwa projektu to **WPIncidentLens**. W prototypie z 9 listopada 2026 zachowano historyczną nazwę `WPTrace`, moduł Python `wptrace` oraz nazwy plików specyfikacji, aby nie łamać istniejących poleceń i testów. Zmiana nazwy pakietu programistycznego wymaga osobnego zadania.

## Materiały źródłowe i zakres migracji

Przywrócono zawartość oryginalnych archiwów wydania, specyfikacje Markdown/DOCX, plan PDF oraz przykładowe artefakty demonstracyjne. Archiwa źródłowe zachowano w `archives/` dla integralności i śledzenia pochodzenia. **Do repozytorium nie należy dodawać autentycznych dowodów, logów produkcyjnych, haseł ani kluczy.**

Migracja repozytorium nie oznacza gotowości produkcyjnej.
