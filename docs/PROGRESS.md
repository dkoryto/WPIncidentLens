# Postęp prac

Status `IN REVIEW` oznacza otwarty PR czekający na przegląd człowieka, nie ukończone zadanie. Zadanie jest `DONE` dopiero po spełnieniu DoD i merge wykonanym przez człowieka.

| Zadanie | Issue | Gałąź | Status | Uwagi |
|---|---|---|---|---|
| T-001 baseline, packaging, CI | #1 | `agent/T-001-baseline-ci` | IN REVIEW | lokalnie 6 passed, ruff czysty; wyniki w `docs/BASELINE.md` |
| T-002 threat model, ADR, traceability | #2 | — | TODO | zależy od T-001; wymaga przeglądu człowieka |
| T-003 macierz testów i testy negatywne | #3 | `agent/T-003-test-matrix` | IN REVIEW | lokalnie 79 passed, 1 skipped, 30 xfailed (Linux: 79 passed, 31 xfailed); coverage 93%; `docs/TEST_MATRIX.md` |
| T-004 ReDoS w parserze INSERT | #11 | `agent/T-004-sql-redos` | IN REVIEW | lokalnie 89 passed, 1 skipped, 29 xfailed |
| T-101 CaseManager / SecureIngest | #4 | — | BLOCKED | bramka M0: zatwierdzony threat model i ADR (T-002) |
| T-102 kontrakty Evidence/Observation/Finding | #5 | — | BLOCKED | bramka M0 |
| T-201 analiza plików WordPressa | #6 | — | BLOCKED | wymaga M1 |
| T-301 ekstraktor SQL/JSONL | #7 | — | BLOCKED | wymaga M1 |

## Przekazanie

- 2026-11-11 — T-001: dodano `pyproject.toml`, CI i `docs/BASELINE.md`. Kod `wptrace/` i testy bez zmian. Następny krok: przegląd PR T-001, potem T-002 i T-003.
- 2026-11-11 — T-003: dodano `docs/TEST_MATRIX.md`, 104 testy syntetyczne i `pytest-cov`; kod `wptrace/` bez zmian. 31 luk oznaczonych `xfail(strict)` (#3–#7), w tym ReDoS parsera SQL i TOCTOU. Następny krok: przegląd PR, decyzja o nowych Issue dla luk przypisanych do #3.
- 2026-11-11 — T-004 (#11): regex wiersza w `iter_insert_rows` zastąpiony skanerem liniowym; test S-08 przechodzi bez `xfail`. Gałąź `agent/T-004-sql-redos` (od T-003).
