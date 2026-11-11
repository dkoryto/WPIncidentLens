# Postęp prac

Status `IN REVIEW` oznacza otwarty PR, nie ukończone zadanie. `MERGED` oznacza PR scalony do `main` z zielonym CI. Od 2026-11-11 właściciel upoważnił agenta do samodzielnego merge; niezależny przegląd AppSec nadal się nie odbył i pozostaje wymagany przed bramką GO/NO-GO.

| Zadanie | Issue | Gałąź | Status | Uwagi |
|---|---|---|---|---|
| T-001 baseline, packaging, CI | #1 | `agent/T-001-baseline-ci` | MERGED (#8) | 6 passed, ruff czysty; wyniki w `docs/BASELINE.md` |
| T-002 threat model, ADR, traceability | #2 | `agent/T-002-threat-model-adr` | MERGED (#9) | tylko dokumentacja; ADR 0001 i 0002 ACCEPTED z delegacji właściciela |
| T-003 macierz testów i testy negatywne | #3 | `agent/T-003-test-matrix` | MERGED (#10) | 104 nowe testy; coverage 93%; `docs/TEST_MATRIX.md` |
| T-004 ReDoS w parserze INSERT | #11 | `agent/T-004-sql-redos` | MERGED (#12) | macOS: 89 passed, 1 skipped, 29 xfailed |
| T-101 SecureIngest | #4 | `agent/T-101-secure-ingest` | IN REVIEW | `wptrace/ingest.py` wg ADR 0002 B2–B6, B8, D4; macOS 270 passed, 2 skipped, 20 xfailed po poprawkach z audytu (Linux przed poprawkami: 263 passed, 1 skipped, 20 xfailed; po nich tylko CI); CaseManager i `case.json` poza zakresem tego PR |
| T-102 kontrakty Evidence/Observation/Finding | #5 | — | TODO | po T-101; schemat `poc-1` z `INCONCLUSIVE` i migracją |
| T-201 analiza plików WordPressa | #6 | — | BLOCKED | wymaga M1 |
| T-301 ekstraktor SQL/JSONL | #7 | — | BLOCKED | wymaga M1 |
| T-401 logi, UTC, korelacja | #13 | — | BLOCKED | wymaga M1 |
| T-501 reguły, raport HTML, redakcja | #14 | — | BLOCKED | wymaga T-102 |
| T-601 hardening, pomiar kontenera, QA | #15 | — | BLOCKED | wymaga M1–M5 |

## Przekazanie

- 2026-11-11 — T-001: dodano `pyproject.toml`, CI i `docs/BASELINE.md`. Kod `wptrace/` i testy bez zmian.
- 2026-11-11 — T-002: dodano `docs/THREAT_MODEL.md`, `docs/REQUIREMENTS_TRACEABILITY.md` i `docs/adr/0001-granice-komponentow.md`.
- 2026-11-11 — Bramka M0: właściciel delegował decyzje agentowi; rozstrzygnięcia B1–B11 i D1–D9 w `docs/adr/0002-decyzje-bramki-m0.md`.
- 2026-11-11 — T-003: dodano `docs/TEST_MATRIX.md`, 104 testy syntetyczne i `pytest-cov`. 31 luk oznaczonych `xfail(strict)`; luki bez własnego Issue przeniesiono do #13 i #14.
- 2026-11-11 — T-004 (#11): regex wiersza w `iter_insert_rows` zastąpiony skanerem liniowym; test S-08 przechodzi bez `xfail`.
- 2026-11-11 — PR-y #8, #10, #12 i #9 scalone do `main` przez agenta na polecenie właściciela. Następny krok: przegląd i PR dla T-101, potem T-102.
- 2026-11-11 — T-101 (#4): cały odczyt dowodów w `cli.py` idzie przez `wptrace/ingest.py` (deskryptory, `O_NOFOLLOW`, hardlinki, limity, ponowna weryfikacja, strażnik AST D4); schemat raportu 0.1.0 bez zmian; zdjęto 10 przypadków `xfail`. Następny krok: CaseManager i `case.json`, potem T-102.
