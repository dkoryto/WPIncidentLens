# WPIncidentLens — instalacja i uruchomienie (M7, T-701)

Dokument opisuje, jak przygotować środowisko PoC i uruchomić analizę na hoście albo w kontenerze. Narzędzie to **ograniczony PoC**, nie produkt: przed bramką GO/NO-GO (M7) nie wolno go używać na realnym materiale (sekcja „Zakaz pracy na realnym materiale”).

## Wymagania

| Element | Wymaganie | Gdzie sprawdzone |
|---|---|---|
| Python | 3.12 (`requires-python = ">=3.12,<3.13"`) | `pyproject.toml` |
| System | Linux albo macOS: odczyt względem deskryptora katalogu (`dir_fd`, `O_NOFOLLOW`, `O_DIRECTORY`). Na platformie bez tych funkcji narzędzie odmawia pracy (`UNSUPPORTED_PLATFORM`) | `wpincidentlens/ingest.py` |
| Zależności runtime | brak — silnik używa wyłącznie biblioteki standardowej (`dependencies = []`) | `pyproject.toml`, `tests/test_supply_chain.py` |
| Zależności deweloperskie | `pytest`, `pytest-cov`, `jsonschema`, `hypothesis`, `ruff` z locka z hashami `requirements/dev.lock` | `pyproject.toml` (extra `dev`) |
| Docker (opcjonalnie) | Docker z Compose v2; pomiar izolacji wykonano na runnerze `ubuntu-24.04` z cgroup v2 | `.github/workflows/container.yml` |
| YARA-X (opcjonalnie) | extra `yara` = `yara-x==1.22.1`, lock `requirements/yara.lock` | ADR 0010 |

## Instalacja deweloperska (lock z hashami)

```bash
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes -r requirements/dev.lock
python -m pip install --no-deps -e .
python -m ruff check .
python -m pytest -q
```

`requirements/dev.lock` ma przypięte wersje i SHA-256 każdej paczki: pip odrzuci paczkę o innej zawartości. Polecenie regenerujące lock jest w nagłówku pliku; rozjazd locka z `pyproject.toml` wykrywa `tests/test_supply_chain.py`. Audyt zależności (`pip-audit`) i SBOM opisuje [README](../README.md#test-lokalny).

## Uruchomienie

Bez instalacji, z katalogu głównego repozytorium (pakiet `wpincidentlens/` jest w bieżącym katalogu):

```bash
python -m wpincidentlens --help
python -m wpincidentlens --files fixtures/site --database fixtures/database.sql --logs fixtures/logs \
  --baseline fixtures/baseline.json --output results --case-id DEMO-001
```

Po `pip install --no-deps -e .` to samo udostępnia polecenie `wpincidentlens` (`[project.scripts]` w `pyproject.toml`). Wymagane są tylko `--files` i `--output`; pozostałe źródła są opcjonalne, ale ich brak obniża zakres analizy (kod wyjścia 3, ocena bez ustaleń `INCONCLUSIVE` — [ANALYST_GUIDE.md](ANALYST_GUIDE.md)). Pełny opis wejść, wyjść i kodów wyjścia: [FORMATS.md](FORMATS.md).

Dokumentacja w tym katalogu używa płaskiej postaci wywołania (`python -m wpincidentlens --files …`), równoważnej `wpincidentlens analyze --files …` (ADR 0011). Pozostałe podkomendy: `wpincidentlens report verify KATALOG` (spójność katalogu wyników; kody wyjścia w [FORMATS.md](FORMATS.md#report-verify)) i `wpincidentlens version [--json]`. Katalog `--output` z wynikami poprzedniej analizy jest odrzucany (kod 2), chyba że podano `--force`.

Warunki na ścieżki (sprawdzane przed odczytem czegokolwiek, błąd = kod 2):

- `--files`, `--database`, `--logs`, `--baseline` i `--core-checksums` nie mogą być dowiązaniami symbolicznymi — podaj ścieżkę rzeczywistą.
- `--output` nie może leżeć w żadnym źródle dowodów ani go zawierać, nie może być dowiązaniem ani wpisem niebędącym katalogiem. Katalog jest tworzony, jeśli go nie ma.
- `--yara-rules` nie może leżeć w źródle dowodów ani go zawierać.

## Katalog wyników i uprawnienia

Każdy plik wyniku powstaje z uprawnieniami `0600` (plik tymczasowy, potem zamiana na nazwę docelową; `wpincidentlens/report.py`). Katalog wyników przygotuj z prawami `0700` dla użytkownika, który uruchamia narzędzie:

```bash
install -d -m 0700 results
```

**Nie nadawaj katalogowi wyników praw `777`** (także „żeby kontener mógł pisać”): każdy użytkownik hosta mógłby odczytać raport z danymi osobowymi albo podmienić pliki wyniku. Dla kontenera użyj jednego z wariantów niżej.

## Kontener Docker

`docker/Dockerfile` przypina obraz bazowy `python:3.12-slim` digestem, kopiuje do obrazu wyłącznie pakiet `wpincidentlens/` (`.dockerignore`) i uruchamia proces jako UID/GID 65532. Obraz **nie zawiera** YARA-X: `--yara-rules` w kontenerze daje lukę pokrycia `files`, nie trafienia.

### Compose (pokaz na danych syntetycznych)

`docker/compose.yaml` montuje `fixtures/` tylko do odczytu i `results/` do zapisu. Wariant A — katalog wyników należy do UID 65532 (pliki wyników będą jego, odczyt przez `sudo` albo po zmianie właściciela):

```bash
sudo install -d -m 0700 -o 65532 -g 65532 results
cd docker && docker compose run --build --rm wpincidentlens
```

Wariant B — kontener działa z UID użytkownika hosta, katalog zostaje jego:

```bash
install -d -m 0700 results
cd docker && docker compose run --build --rm --user "$(id -u):$(id -g)" wpincidentlens
```

### `docker run` z mierzonymi flagami izolacji

Zmierzone ograniczenia (CI, zadanie `container`, sonda `docker/probe.py`) są w `docker/run-flags.txt`, jeden argument na wiersz; `docker/compose.yaml` deklaruje te same, a zgodność obu plików sprawdza `tests/test_container_probe.py`.

| Flaga z `docker/run-flags.txt` | Znaczenie |
|---|---|
| `--network=none` | brak sieci (tylko interfejs `lo`) |
| `--read-only` | rootfs tylko do odczytu |
| `--user=65532:65532` | proces bez uprawnień roota |
| `--cap-drop=ALL` | brak capabilities |
| `--security-opt=no-new-privileges:true` | `NoNewPrivs: 1` |
| `--pids-limit=128` | limit procesów |
| `--memory=1g`, `--memory-swap=1g` | 1 GiB pamięci, bez swap |
| `--cpus=1` | jeden procesor |
| `--tmpfs=/tmp:rw,noexec,nosuid,size=64m` | `/tmp` w pamięci, bez wykonywania |

Przykład z katalogu głównego repozytorium (wartości w pliku nie zawierają spacji, więc rozwinięcie powłoki jest bezpieczne):

```bash
docker build -f docker/Dockerfile -t wpincidentlens:local .
sudo install -d -m 0700 -o 65532 -g 65532 results
docker run --rm $(grep -v '^#' docker/run-flags.txt) \
  -v "$PWD/fixtures/site:/evidence/files:ro" \
  -v "$PWD/fixtures/database.sql:/evidence/database.sql:ro" \
  -v "$PWD/fixtures/logs:/evidence/logs:ro" \
  -v "$PWD/results:/results:rw" \
  wpincidentlens:local --files /evidence/files --database /evidence/database.sql --logs /evidence/logs \
  --known-admin knownadmin --output /results --case-id DEMO-001
```

Kontener działa jako UID 65532 z pliku flag, więc katalog `results` musi należeć do tego UID (jak w wariancie A). Pomiar izolacji dotyczy runnera `ubuntu-24.04`; na innym hoście uruchom sondę samodzielnie (polecenie w `.github/workflows/container.yml`). Limit pamięci 1 GiB wystarcza dla domyślnego `--max-entries` (250 000); wyższy limit wpisów wymaga proporcjonalnie więcej pamięci (`bench/RESULTS.md`).

## Opcjonalny adapter YARA-X

Domyślnie wyłączony; włącza go `--yara-rules PATH` (lokalny pakiet reguł operatora, ADR 0010). Instalacja extra z locka (lock zawiera wyłącznie hashe kół, więc tylko koła):

```bash
python -m pip install --require-hashes --only-binary=:all: -r requirements/yara.lock
```

Bez modułu `yara_x` analiza z `--yara-rules` nie przerywa się: `files` dostaje lukę pokrycia (`PARTIAL`), a przebieg bez ustaleń kończy się `INCONCLUSIVE`. Błąd kompilacji pakietu to błąd wywołania (kod 2). YARA-X działa w osobnym procesie z limitami ([ARCHITECTURE.md](ARCHITECTURE.md#izolacja-procesu-yara-x)); `RLIMIT_DATA` nie działa na macOS — limit pamięci procesu YARA obowiązuje wtedy tylko w kontenerze (raport ma notę).

## Praca offline

Narzędzie nie łączy się z siecią i niczego nie pobiera: manifest sum rdzenia (`--core-checksums`) i pakiet YARA to pliki lokalne podane przez operatora. Brak wywołań sieciowych pilnuje `tests/test_invariants.py` (S-15), a kontener działa z `--network=none`. Nie łącz się z badaną witryną — analizowana jest wyłącznie przygotowana kopia.

## Zakaz pracy na realnym materiale (B10)

Do bramki GO/NO-GO kontrolowanego PoC (M7: niezależny przegląd bezpieczeństwa i akceptacja właściciela) narzędzia używa się **wyłącznie na danych syntetycznych** (ADR 0002 B10, ADR 0009 pkt 7) — także po zielonym pomiarze kontenera. Po bramce: tylko autoryzowane kopie, offline, materiał montowany tylko do odczytu z `nodev`, dla materiału wysokiego ryzyka osobna VM. Realnych dowodów, logów, zrzutów baz, haseł ani kluczy nie dodaje się do repozytorium, Issues, PR ani CI.
