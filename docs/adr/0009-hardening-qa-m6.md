# ADR 0009 — Hardening, pomiar kontenera i QA (M6, T-601)

| | |
|---|---|
| **Status** | **ACCEPTED** (2026-11-12) |
| **Kto zdecydował** | Agent kodujący na podstawie delegacji właściciela; bez niezależnego przeglądu AppSec |
| **Dotyczy** | Issue #15 (T-601), ADR 0002 B10 i D9, R-82–R-86, S-06, S-07, S-15, Q-01 |

## Kontekst

Po M5 kontener jest tylko deklaracją (`docker/compose.yaml`, obraz bazowy bez digestu, R-84–R-86 UNVERIFIED/MISSING); zależności testowe nie mają locka z hashami, nie ma audytu ani SBOM (R-83); fuzz jest wyłącznie mutacyjny (Q-01); limit czasu działa w trakcie pliku tylko w parserze logów — parsery SQL i JSONL, reguły treści plików i wyjątek w regule mogą go obejść albo przerwać analizę (S-06, C10). Lokalny demon Dockera nie jest dostępny; GitHub Actions (`ubuntu-24.04`) ma Dockera.

## Decyzja

1. **Kontener mierzony, nie deklarowany.** Obraz bazowy przypięty digestem (`python:3.12-slim@sha256:…`), w obrazie tylko pakiet. Osobne zadanie CI `container` buduje obraz i uruchamia go z flagami z `compose.yaml` (bez sieci, UID 65532, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, limity PID/RAM/CPU, tmpfs `noexec`, dowody `:ro`). Sonda **w środku kontenera** (skrypt Python ze stdlib, dostarczany jako dowód tylko do odczytu albo `-c`) sprawdza: `uid`/`gid`, zapis do `/` i do katalogu dowodów kończy się błędem, `CapEff`/`CapBnd` = 0 i `NoNewPrivs: 1` z `/proc/self/status`, brak interfejsów poza `lo` i nieudane połączenie gniazdem, limity cgroup (`memory.max`, `pids.max`, `cpu.max`). Następnie demo w kontenerze daje tę samą ocenę i ustalenia co na hoście. Wynik pomiaru jest artefaktem CI; zadanie musi przejść przed scaleniem.
2. **Łańcuch dostaw:** silnik nie ma zależności runtime. Zależności testowe i deweloperskie mają lock z hashami (`requirements/dev.lock`, generowany `uv pip compile --generate-hashes`), CI instaluje `--require-hashes`. CI uruchamia `pip-audit` na locku (podatność = czerwone CI) i tworzy SBOM CycloneDX środowiska testowego oraz obrazu (artefakty). Narzędzia CI przypięte do wersji/SHA.
3. **Fuzzing ze strukturą** (`hypothesis`, zależność wyłącznie testowa): generatory poprawnych i prawie poprawnych zrzutów SQL, wierszy JSONL, wierszy logów, danych serializacji PHP i tekstów do redakcji. Niezmienniki: brak wyjątku spoza kontraktu, deterministyczny wynik, **niezależność od podziału na porcje** (strumień podany w losowych kawałkach = całość naraz), ograniczony czas na wejście, idempotencja `redact`. Profil CI ma stały seed i limit przykładów; profil `nightly` lokalnie z większą liczbą przykładów. Każdy znaleziony błąd dostaje test regresyjny.
4. **Limit czasu wszędzie:** parsery SQL i JSONL oraz reguły treści plików sprawdzają `Session.expired()` co stałą liczbę instrukcji/wierszy/bloków i kończą analizę pliku luką „przeanalizowany do …” (jak logi w M4). Wyjątek w regule (błąd kodu wywołany danymi) staje się luką źródła z identyfikatorem reguły, nie przerwaniem analizy (spec C10); test wstrzykuje wyjątek.
5. **Benchmarki S-06/S-07** jako skrypty `bench/` (poza domyślnym `pytest`, znacznik `bench`), syntetyczne dane generowane w katalogu tymczasowym: milion małych plików, log ≥ 1 GiB, zrzut SQL ≥ 1 GiB; mierzony czas, maksymalny RSS i zachowanie limitów. Wyniki z maszyny i daty zapisane w `docs/TEST_MATRIX.md`; brak twardych progów w CI.
6. **D9 — izolacja parserów w osobnym procesie: nie teraz.** Parsery są czystym Pythonem bez kodu natywnego i bez wykonywania danych; zagrożenia to czas i pamięć, które ograniczają limity aplikacji (pkt 4) i kontenera (pkt 1). Decyzja wraca, jeśli fuzzing (pkt 3) znajdzie awarię niedającą się ograniczyć w procesie albo pojawi się parser natywny (np. YARA-X).
7. **Zakaz pracy na realnym materiale (B10) trwa** do bramki GO/NO-GO (M7) z przeglądem człowieka, nawet po zielonym pomiarze kontenera.

## Konsekwencje

- Gałęzie: `agent/T-601-container`, `agent/T-601-supply-chain`, `agent/T-601-fuzz`, `agent/T-601-deadlines`, `agent/T-601-bench`; potem przegląd bezpieczeństwa i dokumentacja M6.
- `hypothesis` dochodzi do `[project.optional-dependencies] test`/`dev` (lock obejmuje go od razu).
- Rollback: revert commitów; zadanie CI `container` można wyłączyć bez wpływu na silnik.
