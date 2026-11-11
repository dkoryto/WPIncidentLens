# WPIncidentLens — prototyp analizy powłamaniowej WordPressa

**Nie jest to gotowe narzędzie produkcyjne ani dowód braku kompromitacji.**

PoC zapewnia działający **offline** przepływ: statyczna analiza kopii katalogu WordPressa, wybranego podzbioru eksportu SQL i logów HTTP → manifest SHA-256 → `report.json` + `report.html`. Zawiera wyłącznie syntetyczne dane testowe.

## Test lokalny

```bash
python -m pytest -q
python -m wptrace --files fixtures/site --database fixtures/database.sql --logs fixtures/logs --baseline fixtures/baseline.json --output results --case-id DEMO-001
```

Otwórz `results/report.html`.

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
- Symlinki są pomijane; pliki duże są haszowane, ale ich zawartość nie jest skanowana. Brak uczenia maszynowego i nie ma wykonywania PHP.
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
