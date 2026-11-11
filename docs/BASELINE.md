# Baseline PoC (T-001)

> **Dokument historyczny.** Opisuje stan z zadania T-001 (commit `1fe3457`: jeden moduł `wpincidentlens/cli.py`, 6 testów, raport 0.1.0) i nie jest aktualizowany. Wyniki, kody wyjścia, kształt raportu i przykładowe komendy poniżej **nie odpowiadają obecnemu kodowi**. Aktualny stan po etapie M1: [`docs/M1_GATE.md`](M1_GATE.md); aktualne wyniki testów: [`docs/TEST_MATRIX.md`](TEST_MATRIX.md).

Stan na 2026-11-11, gałąź `agent/T-001-baseline-ci`, bazowy commit `1fe3457`. Dokument opisuje **faktycznie uruchomione** komendy. Baseline potwierdza tylko powtarzalność obecnego PoC; nie jest dowodem bezpieczeństwa ani gotowości do pracy na realnych danych.

## Środowisko

| Element | Wartość |
|---|---|
| System | macOS (Darwin 27.0.0, arm64) |
| Python | 3.12.11 (venv utworzony przez `uv venv --python 3.12`) |
| pytest | 8.4.2 |
| ruff | 0.8.6 |
| Docker | 29.9.2 |
| Zależności runtime | brak (tylko biblioteka standardowa) |

## Odtworzenie

```bash
python3.12 -m venv .venv && . .venv/bin/activate   # lub: uv venv --python 3.12 .venv
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q
python -m wpincidentlens --help
```

Instalacja pobiera `setuptools`, `pytest` i `ruff` z PyPI. Dotyczy to wyłącznie środowiska deweloperskiego i CI; sam silnik analizy nie używa sieci.

## Wyniki (uruchomione lokalnie 2026-11-11)

| Komenda | Wynik |
|---|---|
| `python -m pytest -q` | **6 passed** w 0.03 s |
| `python -m ruff check .` | brak zgłoszeń (reguły `E9`, `F`) |
| `python -m wpincidentlens --help` | kod 0, interfejs bez zmian |
| `wpincidentlens --help` (entry point) | kod 0 |
| `python -m wpincidentlens --files fixtures/site --database fixtures/database.sql --logs fixtures/logs --baseline fixtures/baseline.json --output <tmp> --case-id DEMO-001` | kod 0; `INDICATORS_FOUND`, 6 findings, 1 coverage gap; powstały `report.json` i `report.html` |
| `cd docker && docker compose run --build --rm wpincidentlens` | kod 0; `INDICATORS_FOUND`, 6 findings, 1 coverage gap; raport zapisany w `results/` |

Stan przed zmianą: w systemie nie było polecenia `python` (tylko `python3`), a `pytest` uruchomiony spoza venv kończył się `ModuleNotFoundError: No module named 'wpincidentlens'`. Usuwa to instalacja edytowalna z `pyproject.toml`.

CI (`.github/workflows/ci.yml`): wynik podany jest w PR; ten plik nie deklaruje wyniku CI.

## Stan Docker

Uruchomiono **tylko** jednorazowy pokaz na syntetycznych fixtures (wiersz w tabeli powyżej). Zbudowany obraz ma `User=65532:65532`; bazowy `python:3.12-slim` rozwiązał się w tej sesji do `sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9`, ale `Dockerfile` nadal **nie pinuje** digestu.

Nie zmierzono (status **NOT RUN**): faktycznego braku sieci w kontenerze, read-only rootfs, zrzuconych capabilities, `no-new-privileges`, limitów CPU/RAM/PID, zachowania na Linuksie ani zapisu do `results/` przy innych uprawnieniach hosta. Ustawienia te są jedynie zadeklarowane w `docker/compose.yaml`. Pomiar należy do M6 (T-601). Docker nie jest uruchamiany w CI.

## Ograniczenia baseline

- 6 testów na syntetycznych fixtures nie dowodzi poprawności detekcji ani bezpieczeństwa odczytu (symlink/hardlink/TOCTOU/limity) — to zakres T-003 i T-101.
- `ruff` sprawdza tylko `E9` i `F`. Reguły stylu (m.in. `E701`/`E702`) i formatowanie są odłożone, żeby nie przepisywać monolitu `wpincidentlens/cli.py` w tym PR.
- Wersja pakietu w `pyproject.toml` to `0.1.0`, bo PEP 440 nie dopuszcza `0.1.0-poc`. `wpincidentlens.__version__` i `tool_version` w raporcie pozostają `0.1.0-poc`; `schema_version` raportu bez zmian (`0.1.0`).
- Wymagany jest Python 3.12 (`requires-python = ">=3.12,<3.13"`); innych wersji nie testowano.
- Brak pliku lock: zależności deweloperskie są ograniczone zakresami wersji, nie hashami. Brak pomiaru pokrycia kodu (planowany w T-003).
- Akcje GitHub są przypięte do SHA commitów; nie ma jeszcze automatu aktualizującego te piny.
