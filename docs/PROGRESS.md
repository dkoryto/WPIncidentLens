# Postęp prac

Status `IN REVIEW` oznacza otwarty PR czekający na przegląd człowieka, nie ukończone zadanie. Zadanie jest `DONE` dopiero po spełnieniu DoD i merge wykonanym przez człowieka.

| Zadanie | Issue | Gałąź | Status | Uwagi |
|---|---|---|---|---|
| T-001 baseline, packaging, CI | #1 | `agent/T-001-baseline-ci` | IN REVIEW | lokalnie 6 passed, ruff czysty; wyniki w `docs/BASELINE.md` |
| T-002 threat model, ADR, traceability | #2 | — | TODO | zależy od T-001; wymaga przeglądu człowieka |
| T-003 macierz testów i testy negatywne | #3 | — | TODO | zależy od T-001; równolegle z T-002 |
| T-101 CaseManager / SecureIngest | #4 | — | BLOCKED | bramka M0: zatwierdzony threat model i ADR (T-002) |
| T-102 kontrakty Evidence/Observation/Finding | #5 | — | BLOCKED | bramka M0 |
| T-201 analiza plików WordPressa | #6 | — | BLOCKED | wymaga M1 |
| T-301 ekstraktor SQL/JSONL | #7 | — | BLOCKED | wymaga M1 |

## Przekazanie

- 2026-11-11 — T-001: dodano `pyproject.toml`, CI i `docs/BASELINE.md`. Kod `wptrace/` i testy bez zmian. Następny krok: przegląd PR T-001, potem T-002 i T-003.
