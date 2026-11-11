# Postęp prac

Status `IN REVIEW` oznacza otwarty PR, nie ukończone zadanie. `MERGED` oznacza PR scalony do `main` z zielonym CI. Od 2026-11-11 właściciel upoważnił agenta do samodzielnego merge; niezależny przegląd AppSec nadal się nie odbył i pozostaje wymagany przed bramką GO/NO-GO.

| Zadanie | Issue | Gałąź | Status | Uwagi |
|---|---|---|---|---|
| T-001 baseline, packaging, CI | #1 | `agent/T-001-baseline-ci` | MERGED (#8) | 6 passed, ruff czysty; wyniki w `docs/BASELINE.md` |
| T-002 threat model, ADR, traceability | #2 | `agent/T-002-threat-model-adr` | MERGED (#9) | tylko dokumentacja; ADR 0001 i 0002 ACCEPTED z delegacji właściciela |
| T-003 macierz testów i testy negatywne | #3 | `agent/T-003-test-matrix` | MERGED (#10) | 104 nowe testy; coverage 93%; `docs/TEST_MATRIX.md` |
| T-004 ReDoS w parserze INSERT | #11 | `agent/T-004-sql-redos` | MERGED (#12) | macOS: 89 passed, 1 skipped, 29 xfailed |
| T-101 SecureIngest | #4 | `agent/T-101-secure-ingest` | MERGED (#16) | `wptrace/ingest.py` wg ADR 0002; niezależny audyt agenta: 0 critical/high, poprawki w PR; CaseManager i `case.json` jeszcze do zrobienia (#4 otwarte) |
| T-005 kwadratowy parser INSERT, budżet wpisów | #17 | `agent/T-005-sql-header-linear` | MERGED (#19) | nagłówek INSERT liniowy; nazwy na stosie katalogów w budżecie wpisów |
| T-006 ustalenia przeglądów T-101 i T-102 | #18 | `agent/T-006-review-followups` | IN PROGRESS | pierwszy PR: skaner początków instrukcji SQL i wzorzec logu; reszta listy w #18 |
| T-102 kontrakty Evidence/Observation/Finding | #5 | `agent/T-102-contracts` | MERGED (#20) | raport `poc-1`, `INCONCLUSIVE`, kody wyjścia 0/3/4, migracja z 0.1.0, ADR 0003; niezależny przegląd agenta, wada blokująca poprawiona w PR |
| T-201 analiza plików WordPressa | #6 | — | TODO | odblokowane po T-102 |
| T-301 ekstraktor SQL/JSONL | #7 | — | TODO | odblokowane po T-102 |
| T-401 logi, UTC, korelacja | #13 | — | BLOCKED | wymaga M1 |
| T-501 reguły, raport HTML, redakcja | #14 | — | TODO | odblokowane po T-102 |
| T-601 hardening, pomiar kontenera, QA | #15 | — | BLOCKED | wymaga M1–M5 |

## Przekazanie

- 2026-11-11 — T-001: dodano `pyproject.toml`, CI i `docs/BASELINE.md`. Kod `wptrace/` i testy bez zmian.
- 2026-11-11 — T-002: dodano `docs/THREAT_MODEL.md`, `docs/REQUIREMENTS_TRACEABILITY.md` i `docs/adr/0001-granice-komponentow.md`.
- 2026-11-11 — Bramka M0: właściciel delegował decyzje agentowi; rozstrzygnięcia B1–B11 i D1–D9 w `docs/adr/0002-decyzje-bramki-m0.md`.
- 2026-11-11 — T-003: dodano `docs/TEST_MATRIX.md`, 104 testy syntetyczne i `pytest-cov`. 31 luk oznaczonych `xfail(strict)`; luki bez własnego Issue przeniesiono do #13 i #14.
- 2026-11-11 — T-004 (#11): regex wiersza w `iter_insert_rows` zastąpiony skanerem liniowym; test S-08 przechodzi bez `xfail`.
- 2026-11-11 — PR-y #8, #10, #12 i #9 scalone do `main` przez agenta na polecenie właściciela. Następny krok: przegląd i PR dla T-101, potem T-102.
- 2026-11-11 — T-101 (#4): cały odczyt dowodów w `cli.py` idzie przez `wptrace/ingest.py` (deskryptory, `O_NOFOLLOW`, hardlinki, limity, ponowna weryfikacja, strażnik AST D4); schemat raportu 0.1.0 bez zmian; zdjęto 10 przypadków `xfail`. Następny krok: CaseManager i `case.json`, potem T-102.
- 2026-11-11 — PR #16 (T-101) scalony po niezależnym audycie agenta; ustalenia audytu poza zakresem przeniesione do #17 i #18.
- 2026-11-11 — T-005 (#17): nagłówek INSERT parsowany liniowo; nazwy wylistowane na stosie katalogów liczą się do budżetu wpisów.
- 2026-11-11 — T-102 (#5): raport `poc-1` z obserwacjami, pokryciem per źródło i `INCONCLUSIVE`; uruchomienie bez bazy lub logów kończy się kodem 3. Następny krok: CaseManager (#4), #18, potem T-201 i T-301.
- 2026-11-11 — PR #20 (T-102) scalony. T-006 (#18), pierwszy PR: instrukcje INSERT/REPLACE wykrywane skanerem leksemów zamiast wzorca początku wiersza; wzorzec logu bez nawrotów na ciągu spacji. macOS: 604 passed, 2 skipped, 13 xfailed.
- 2026-11-11 — T-006 (#18), drugi PR: komentarz wykonywalny ze słowem INSERT/REPLACE i dyrektywa DELIMITER obniżają pokrycie bazy.
