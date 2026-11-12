# Postęp prac

Status `IN REVIEW` oznacza otwarty PR, nie ukończone zadanie. `MERGED` oznacza PR scalony do `main` z zielonym CI. `DONE` oznacza, że PR-y z kodem są scalone, a agent ocenił DoD z Issue jako spełnione; nie zastępuje to przeglądu człowieka ani zamknięcia Issue przez właściciela. Od 2026-11-11 właściciel upoważnił agenta do samodzielnego merge; niezależny przegląd AppSec nadal się nie odbył i pozostaje wymagany przed bramką GO/NO-GO.

| Zadanie | Issue | Gałąź | Status | Uwagi |
|---|---|---|---|---|
| T-001 baseline, packaging, CI | #1 | `agent/T-001-baseline-ci` | MERGED (#8) | 6 passed, ruff czysty; wyniki w `docs/BASELINE.md` |
| T-002 threat model, ADR, traceability | #2 | `agent/T-002-threat-model-adr` | MERGED (#9) | tylko dokumentacja; ADR 0001 i 0002 ACCEPTED z delegacji właściciela |
| T-003 macierz testów i testy negatywne | #3 | `agent/T-003-test-matrix` | MERGED (#10) | 104 nowe testy; coverage 93%; `docs/TEST_MATRIX.md` |
| T-004 ReDoS w parserze INSERT | #11 | `agent/T-004-sql-redos` | MERGED (#12) | macOS: 89 passed, 1 skipped, 29 xfailed |
| T-101 SecureIngest, CaseManager, Reporter | #4 | `agent/T-101-secure-ingest`, `agent/T-101-case-manager` | MERGED (#16, #27) | odczyt przez deskryptory, `case.json`, bezpieczny zapis wyników, testy własności i wyścigu |
| T-005 kwadratowy parser INSERT, budżet wpisów | #17 | `agent/T-005-sql-header-linear` | MERGED (#19) | nagłówek INSERT liniowy; nazwy na stosie katalogów w budżecie wpisów |
| T-006 ustalenia przeglądów T-101 i T-102 | #18 | kilka gałęzi `agent/T-006-*` | MERGED (#21–#26) | pozostałe drobne pozycje w #18 |
| T-102 kontrakty Evidence/Observation/Finding | #5 | `agent/T-102-contracts` | MERGED (#20) | raport `poc-1`, `INCONCLUSIVE`, kody wyjścia 0/3/4, migracja z 0.1.0, ADR 0003; niezależny przegląd agenta, wada blokująca poprawiona w PR |
| T-201 analiza plików WordPressa | #6 | `agent/T-201-prep-file-analyzer`, `agent/T-201-wpdetect`, `agent/T-201-filerules`, `agent/T-201-integrity`, `agent/T-201-docs` | DONE — kod MERGED (#30, #31, #33, #32); dokumentacja M2 w PR `agent/T-201-docs` | DoD z Issue spełnione według oceny agenta, wyłącznie na danych syntetycznych: testy FP/FN reguł i integralności, luki dla pominięć (`NOT_CHECKED`, `REFERENCE_FILE_UNREADABLE`, limit 200), brak wykonania PHP, wersja i plik referencji w ustaleniach. Poza zakresem lub otwarte: adapter YARA-X (brak Issue), zgodność manifestu z wersją witryny, pomiar fałszywych alarmów na rzeczywistym kodzie, przegląd człowieka zmian w `ingest.py` i ADR 0005. Issue #6 pozostaje otwarte do decyzji właściciela |
| T-301 ekstraktor SQL/JSONL | #7 | — | IN PROGRESS | podział na moduły (ADR 0006); parser ścisły, reguły bazy i JSONL w osobnych PR |
| T-401 logi, UTC, korelacja | #13 | — | BLOCKED | wymaga M1 |
| T-501 reguły, raport HTML, redakcja | #14 | — | TODO | odblokowane po T-102 |
| T-601 hardening, pomiar kontenera, QA | #15 | — | BLOCKED | wymaga M1–M5 |

## Przekazanie

- 2026-11-11 — T-001: dodano `pyproject.toml`, CI i `docs/BASELINE.md`. Kod `wpincidentlens/` i testy bez zmian.
- 2026-11-11 — T-002: dodano `docs/THREAT_MODEL.md`, `docs/REQUIREMENTS_TRACEABILITY.md` i `docs/adr/0001-granice-komponentow.md`.
- 2026-11-11 — Bramka M0: właściciel delegował decyzje agentowi; rozstrzygnięcia B1–B11 i D1–D9 w `docs/adr/0002-decyzje-bramki-m0.md`.
- 2026-11-11 — T-003: dodano `docs/TEST_MATRIX.md`, 104 testy syntetyczne i `pytest-cov`. 31 luk oznaczonych `xfail(strict)`; luki bez własnego Issue przeniesiono do #13 i #14.
- 2026-11-11 — T-004 (#11): regex wiersza w `iter_insert_rows` zastąpiony skanerem liniowym; test S-08 przechodzi bez `xfail`.
- 2026-11-11 — PR-y #8, #10, #12 i #9 scalone do `main` przez agenta na polecenie właściciela. Następny krok: przegląd i PR dla T-101, potem T-102.
- 2026-11-11 — T-101 (#4): cały odczyt dowodów w `cli.py` idzie przez `wpincidentlens/ingest.py` (deskryptory, `O_NOFOLLOW`, hardlinki, limity, ponowna weryfikacja, strażnik AST D4); schemat raportu 0.1.0 bez zmian; zdjęto 10 przypadków `xfail`. Następny krok: CaseManager i `case.json`, potem T-102.
- 2026-11-11 — PR #16 (T-101) scalony po niezależnym audycie agenta; ustalenia audytu poza zakresem przeniesione do #17 i #18.
- 2026-11-11 — T-005 (#17): nagłówek INSERT parsowany liniowo; nazwy wylistowane na stosie katalogów liczą się do budżetu wpisów.
- 2026-11-11 — T-102 (#5): raport `poc-1` z obserwacjami, pokryciem per źródło i `INCONCLUSIVE`; uruchomienie bez bazy lub logów kończy się kodem 3. Następny krok: CaseManager (#4), #18, potem T-201 i T-301.
- 2026-11-11 — PR #20 (T-102) scalony. T-006 (#18), pierwszy PR: instrukcje INSERT/REPLACE wykrywane skanerem leksemów zamiast wzorca początku wiersza; wzorzec logu bez nawrotów na ciągu spacji. macOS: 604 passed, 2 skipped, 13 xfailed.
- 2026-11-11 — T-006 (#18), drugi PR: komentarz wykonywalny ze słowem INSERT/REPLACE i dyrektywa DELIMITER obniżają pokrycie bazy.
- 2026-11-11 — PR #26 i #27 scalone na polecenie właściciela bez wyniku GitHub Actions (kolejka nie ruszała); zamiast CI lokalny przebieg na Linuksie w kontenerze bez sieci.
- 2026-11-11 — **Bramka M1:** raport w `docs/M1_GATE.md`. Werdykt agenta: K1 i K2 spełnione z zastrzeżeniami; K3 po poprawkach (nieanalizowane instrukcje SQL, stratne dekodowanie, `NO_TRUSTED_REFERENCE`) spełnione z zastrzeżeniami. Decyzja o przejściu bramki należy do właściciela; zakaz pracy na realnym materiale pozostaje. Następny krok: usunięcie starej nazwy `wpincidentlens`, potem M2 (#6) i M3 (#7).
- 2026-11-11 — Usunięto dawną nazwę WPTrace: pakiet i polecenie to `wpincidentlens`, pole `tool` w raporcie to `WPIncidentLens PoC`, pliki `docs/WPTrace_*` przemianowane (ADR 0004). Dawna nazwa zostaje tylko w materiałach historycznych.
- 2026-11-12 — T-201 (#6), krok przygotowawczy: analiza plików wydzielona z `cli.py` do `files.py`, `integrity.py`, `filerules.py`, `analysis.py` (ADR 0005), bez zmiany zachowania. Następny krok: trzy równoległe PR — WPDetector, integralność z referencją, reguły plików.
- 2026-11-12 — **M2 (T-201, #6) scalony:** PR #30 (podział na moduły, klasyfikacja plików), #31 (WPDetector: wersja, locale i prefiks jako kandydaci w `observations`), #33 (13 reguł plików w wersjonowanej tabeli, offset trafienia, `docs/RULES.md`), #32 (integralność: baseline z wersją referencji, lokalny manifest sum rdzenia `--core-checksums`, siedem reguł, `NOT_CHECKED` per klasa; poprawki po przeglądzie bezpieczeństwa agenta, ADR 0005 pkt 6–12). macOS: 2138 passed, 5 skipped, 7 xfailed; CI na `main` (`6c4cc87`) zielone. Zdjęto trzy znaczniki XFAIL (#6); zostało 7 (5 dla #7, 2 dla zamkniętego #14).
- 2026-11-12 — **Zmiana zachowania po M2 (ADR 0005 pkt 6, zastępuje wariant z ADR 0003):** plik kodu, którego nie porównano z żadną referencją, obniża pokrycie `files` do `PARTIAL`. Przebieg bez pełnej referencji (baseline albo manifest sum obejmujący każdy plik kodu) kończy się kodem **3** i `scope_complete: false`, a bez ustaleń — oceną `INCONCLUSIVE`. Dotyczy to także pokazu na `fixtures/` (wcześniej kod 0); `demo/report.json` i `demo/report.html` wygenerowano ponownie. Baseline z kluczem niebędącym ścieżką względną, skrótem w innej postaci albo powtórzonym kluczem jest odrzucany (kod 2).
- 2026-11-12 — Dokumentacja M2 (PR `agent/T-201-docs`): mapa wymagań (IMPLEMENTED 33 → 40, PARTIAL 44 → 42, MISSING 16 → 11, UNVERIFIED 3), macierz testów, model zagrożeń (Z-18–Z-20, ryzyka 26–37), `docs/RULES.md` (reguły integralności, obserwacje WPDetector), README. Pozostają otwarte: adapter YARA-X (brak Issue), sprawdzenie zgodności manifestu z wersją witryny, limit wpisów baseline, pomiar fałszywych alarmów, pomiar kontenera; przeglądu człowieka nadal nie było i zakaz pracy na realnym materiale obowiązuje. **Następny krok: M3 — T-301 (#7), ekstraktor SQL/JSONL.**
- 2026-11-12 — T-301 (#7), krok przygotowawczy: kod bazy wydzielony z `cli.py` do `database.py`, `sqldump.py`, `dbrules.py` (ADR 0006), bez zmiany zachowania. Następny krok: równoległe PR — parser ścisły strumieniowy, reguły bazy z odczytem danych serializowanych PHP; potem adapter JSONL.
