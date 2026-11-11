# Postęp prac

Status `IN REVIEW` oznacza otwarty PR czekający na przegląd człowieka, nie ukończone zadanie. Zadanie jest `DONE` dopiero po spełnieniu DoD i merge wykonanym przez człowieka.

| Zadanie | Issue | Gałąź | Status | Uwagi |
|---|---|---|---|---|
| T-001 baseline, packaging, CI | #1 | `agent/T-001-baseline-ci` | IN REVIEW | lokalnie 6 passed, ruff czysty; wyniki w `docs/BASELINE.md` |
| T-002 threat model, ADR, traceability | #2 | `agent/T-002-threat-model-adr` | IN REVIEW | tylko dokumentacja; ADR 0001 i 0002 ACCEPTED z delegacji właściciela, bez niezależnego przeglądu AppSec |
| T-003 macierz testów i testy negatywne | #3 | — | TODO | zależy od T-001; równolegle z T-002 |
| T-101 CaseManager / SecureIngest | #4 | — | TODO | odblokowane przez ADR 0002 |
| T-102 kontrakty Evidence/Observation/Finding | #5 | — | TODO | odblokowane przez ADR 0002; po T-101 |
| T-201 analiza plików WordPressa | #6 | — | BLOCKED | wymaga M1 |
| T-301 ekstraktor SQL/JSONL | #7 | — | BLOCKED | wymaga M1 |

## Przekazanie

- 2026-11-11 — T-001: dodano `pyproject.toml`, CI i `docs/BASELINE.md`. Kod `wptrace/` i testy bez zmian. Następny krok: przegląd PR T-001, potem T-002 i T-003.
- 2026-11-11 — T-002: dodano `docs/THREAT_MODEL.md`, `docs/REQUIREMENTS_TRACEABILITY.md` i `docs/adr/0001-granice-komponentow.md` (gałąź od T-001, bez zmian w kodzie). Następny krok: decyzje człowieka B1–B11 i D1–D9; do tego czasu T-101/T-102 pozostają zablokowane.
- 2026-11-11 — Bramka M0: właściciel delegował decyzje agentowi; rozstrzygnięcia B1–B11 i D1–D9 w `docs/adr/0002-decyzje-bramki-m0.md`. Następny krok: poprawka ReDoS, potem T-101.
