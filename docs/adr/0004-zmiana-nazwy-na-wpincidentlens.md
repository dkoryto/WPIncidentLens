# ADR 0004 — Usunięcie dawnej nazwy WPTrace

| | |
|---|---|
| **Status** | **ACCEPTED** (2026-11-11) |
| **Kto zdecydował** | Właściciel repozytorium (polecenie z 2026-11-11: usunąć pozostałości po starej nazwie po zakończeniu M1); wykonanie: agent kodujący |
| **Zastępuje** | zapis z `AGENTS.md` i `docs/MIGRATION_2026-11-11.md` o zachowaniu `python -m wptrace` do czasu zaakceptowanej migracji |

## Decyzja

Projekt, pakiet Pythona i polecenie mają jedną nazwę: **WPIncidentLens** / `wpincidentlens`. Nie ma aliasu zgodności wstecznej.

| Co | Przed | Po |
|---|---|---|
| Pakiet i katalog | `wptrace/` | `wpincidentlens/` |
| Uruchomienie | `python -m wptrace`, polecenie `wptrace` | `python -m wpincidentlens`, polecenie `wpincidentlens` |
| Nazwa dystrybucji (`pyproject.toml`) | `wptrace` | `wpincidentlens` |
| Pole `tool` w `report.json` i `case.json` | `WPTrace PoC` | `WPIncidentLens PoC` |
| Domyślny `--case-id` | `WPTRACE-DEMO` | `WPINCIDENTLENS-DEMO` |
| Usługa i obraz w `docker/` | `wptrace` | `wpincidentlens` |
| Pliki `docs/WPTrace_*` | `WPTrace_…` | `WPIncidentLens_…` |

`schema_version` raportu (`poc-1`) i `case.json` (`case-poc-1`) się nie zmienia: pole `tool` jest swobodnym tekstem i żaden schemat nie przypina jego wartości.

## Co celowo zachowuje dawną nazwę

- `archives/*.zip` — oryginalne pakiety źródłowe trzymane dla pochodzenia; ich nazwy i zawartość pozostają nietknięte.
- Treść plików DOCX i PDF w `docs/` — zmieniono tylko nazwy plików; treści binarnych nie przepisywano.
- `docs/MIGRATION_2026-11-11.md` i `docs/legacy-release-notes.txt` — zapis historii.
- `tests/data/report-0.1.0.json` oraz raport 0.1.0 budowany w `tests/test_migrate.py` — stary raport ma treść, jaką pisało narzędzie pod dawną nazwą; migracja przenosi pole `tool` bez zmiany.
- Historia Gita, zamknięte Issues i PR-y.

## Konsekwencje

- Skrypty wywołujące `python -m wptrace` lub polecenie `wptrace` przestają działać i wymagają zmiany nazwy.
- Środowisko deweloperskie trzeba zainstalować ponownie (`pip install -e ".[dev]"`).
- Rollback: revert commita ze zmianą nazwy.
