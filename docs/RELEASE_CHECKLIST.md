# Lista kontrolna wydania `0.2.0rc1` — kontrolowany PoC (M7, T-701)

| | |
|---|---|
| **Wydanie** | `0.2.0rc1` (PEP 440, wydanie kandydujące; ADR 0011 pkt 8), tag `v0.2.0rc1`, GitHub *pre-release* |
| **Charakter** | **kontrolowany PoC** — nie wydanie produkcyjne, nie narzędzie do postępowań dowodowych, nie produkt SOC (spec §20 pkt 10) |
| **Warunek wstępny** | decyzja właściciela w `docs/GO_NO_GO.md` (§9) — bez niej tagu nie tworzy się |
| **Przygotował** | agent kodujący, 2026-11-17, na `main` `92a1188`; lista nie jest zgodą na wydanie |
| **Issue** | #76 (T-701) |

Wydanie oznacza wyłącznie: zamrożony, opisany i zweryfikowany stan kodu, który właściciel dopuścił do **kontrolowanego** użycia na warunkach z `docs/GO_NO_GO.md`. Nie publikuje się paczki w PyPI ani obrazu w rejestrze; wydanie to tag, notatka i załączniki (SBOM, pomiar kontenera).

Role (spec §18): **agent** — przygotowuje dowody i polecenia, nie podpisuje decyzji; **recenzent bezpieczeństwa** — człowiek niezależny od autora kodu; **właściciel** — repozytorium i decyzja GO/NO-GO. Agent nie może podpisać pozycji przypisanej człowiekowi ani uznać jej za spełnioną.

Wszystkie polecenia uruchamia się z katalogu głównego repozytorium. `SHA` = pełny skrót commita przeznaczonego do tagu, `PY` = interpreter środowiska deweloperskiego (`.venv/bin/python` po instalacji z `docs/INSTALL.md`).

```bash
SHA=$(git rev-parse origin/main)   # albo commit wskazany przez właściciela
PY=.venv/bin/python
```

## 1. Zamrożenie kodu

| Nr | Pozycja | Jak sprawdzić | Kryterium | Podpisuje |
|---|---|---|---|---|
| 1.1 | Commit do tagu jest na `main` i jest tym, który przejrzał recenzent | `git merge-base --is-ancestor "$SHA" origin/main && echo on-main`; `git diff --stat <commit_przeglądu> "$SHA" -- wpincidentlens/ docker/ requirements/ pyproject.toml .github/` | `on-main`; diff pusty albo każda różnica przejrzana i odnotowana w #76 | recenzent |
| 1.2 | Drzewo robocze czyste, brak niezacommitowanych zmian | `git status --porcelain` | brak wyjścia | agent |
| 1.3 | Brak otwartych PR, które miały wejść do wydania | `gh pr list --state open` | lista pusta albo każdy PR jawnie poza wydaniem | właściciel |

## 2. CI na commicie tagu

CI uruchamia się na `push` do `main` i na PR (`.github/workflows/ci.yml`, `container.yml`) — **nie na tagu**. Tag musi więc wskazywać commit z `main`, który ma już zielone przebiegi; nowy commit tylko pod tag oznacza brak dowodu CI.

| Nr | Pozycja | Jak sprawdzić | Kryterium | Podpisuje |
|---|---|---|---|---|
| 2.1 | `ci` i `container` zielone na `SHA` | `gh run list --commit "$SHA" --json databaseId,name,conclusion` | dokładnie jeden najnowszy przebieg `ci` i jeden `container`, oba `success` | agent przygotowuje, recenzent potwierdza |
| 2.2 | Zadania `test`, `yara`, `audit` w `ci` | `gh run view <id_ci> --json jobs --jq '.jobs[] \| "\(.name) \(.conclusion)"'` | trzy zadania `success`; zadanie `yara` bez pominięć (krok kończy się błędem przy pominięciu testu YARA-X) | agent / recenzent |
| 2.3 | Liczby testów z logu CI | `gh run view <id_ci> --log \| grep -E '[0-9]+ passed'` | `test`: 0 failed; `yara`: 0 failed, 0 skipped; liczby wpisane do notatki wydania | agent |
| 2.4 | Pomiar kontenera | `gh run download <id_container> -n container-measurement -D release-artifacts/`; `python -c 'import json;p=json.load(open("release-artifacts/probe.json"));print(p["ok"],p["failed"],len(p["checks"]))'`; `python -c 'import json;print(json.load(open("release-artifacts/demo-compare.json"))["problems"])'` | `True [] 21`; `problems` = `[]` (demo w kontenerze = na hoście) | recenzent |

Stan na 2026-11-17 (`92a1188`, po PR #79): `ci` 44139136002 — `test` 3383 passed, 15 skipped; `yara` 147 passed; `audit` `success`; `container` 44139135639 — sonda 21/21, `problems: []`. To dowód dla `92a1188`; jeśli tag wskaże inny commit, pozycje 2.1–2.4 trzeba powtórzyć.

## 3. Testy i lint lokalnie

| Nr | Pozycja | Jak sprawdzić | Kryterium | Podpisuje |
|---|---|---|---|---|
| 3.1 | Pełny zestaw testów | `PYTHONPATH=$PWD $PY -m pytest -q -rs` | 0 failed; pominięcia tylko z powodów: brak `yara-x` (13) i system plików (APFS: 5; na Linuksie 0–2) | agent |
| 3.2 | Pokrycie | `PYTHONPATH=$PWD $PY -m pytest -q --cov=wpincidentlens --cov-report=term` | wynik wpisany do notatki; spadek poniżej 97% (bez `yara-x`) wymaga wyjaśnienia | agent |
| 3.3 | Lint | `$PY -m ruff check .` | `All checks passed!` | agent |
| 3.4 | Testy spójności dokumentacji i przykładu | `PYTHONPATH=$PWD $PY -m pytest -q tests/test_docs_consistency.py tests/test_sample_case.py` | 14 passed | agent |
| 3.5 | Odnośniki README i dokumentów istnieją | `python3 -c 'import re,pathlib;[print(f,l) for f in ["README.md",*map(str,pathlib.Path("docs").glob("*.md"))] for l in re.findall(r"\]\(([^)#]+)",open(f,encoding="utf-8").read()) if not l.startswith("http") and not (pathlib.Path(f).parent/l).exists()]'` | brak wyjścia poza jednym znanym trafieniem `docs/RULES.md …` (wzorzec `$_POST[…](…)` w tabeli reguł, nie odnośnik) | agent |

## 4. Łańcuch dostaw

| Nr | Pozycja | Jak sprawdzić | Kryterium | Podpisuje |
|---|---|---|---|---|
| 4.1 | `pip-audit` czysty w dniu tagu (advisory pojawiają się bez zmiany kodu) | `python3.12 -m venv /tmp/sca && /tmp/sca/bin/python -m pip install --require-hashes -r requirements/audit.lock`, potem dla `dev.lock`, `yara.lock`, `audit.lock`: `/tmp/sca/bin/pip-audit -r requirements/<lock> --require-hashes --disable-pip --strict` | „No known vulnerabilities found” dla trzech locków; albo zielone zadanie `audit` z 2.2 nie starsze niż 24 h | agent / recenzent |
| 4.2 | Lock z hashami jest jedynym źródłem zależności | `PYTHONPATH=$PWD $PY -m pytest -q tests/test_supply_chain.py` | passed; silnik bez zależności runtime (`dependencies = []`) | agent |
| 4.3 | SBOM środowiska testowego i obrazu dołączone do wydania | `gh run download <id_ci> -n sbom-test-env -D release-artifacts/`; plik obrazu z 2.4 (`sbom-image.cdx.json`); `sha256sum release-artifacts/*.cdx.json` | oba pliki to CycloneDX (`bomFormat`), skróty wpisane do notatki wydania; **artefakt `container-measurement` wygasa po 30 dniach** — pobrać przed wygaśnięciem | agent |
| 4.4 | Digest obrazu bazowego przypięty | `grep -n '^FROM' docker/Dockerfile` | `python:3.12-slim@sha256:…` (dziś `5e2bdb1b…4fa5b`, odczytany 2026-11-12) | agent |
| 4.5 | Digest odświeżony (poprawki bezpieczeństwa obrazu bazowego) | `docker buildx imagetools inspect python:3.12-slim --format '{{json .Manifest.Digest}}'` (wymaga sieci i Dockera, poza materiałem dowodowym) | ten sam digest co w 4.4 **albo** PR zmieniający digest z zielonym zadaniem `container` przed tagiem; decyzję „zostawiamy starszy” odnotowuje recenzent | agent przygotowuje, recenzent podpisuje |
| 4.6 | Akcje GitHub przypięte do SHA | `grep -n 'uses:' .github/workflows/*.yml` | każde `uses:` z 40-znakowym SHA | agent |

Brak skanu podatności obrazu (jest tylko SBOM) i hashy backendu budowania (`setuptools`) to ryzyka 50 i 52 z `docs/THREAT_MODEL.md` — akceptuje je właściciel w decyzji (§9 `docs/GO_NO_GO.md`), nie ta lista.

## 5. Wersja i artefakty pokazu

| Nr | Pozycja | Jak sprawdzić | Kryterium | Podpisuje |
|---|---|---|---|---|
| 5.1 | Jedna wersja wszędzie | `grep -n '__version__' wpincidentlens/__init__.py`; `grep -n '^version' pyproject.toml`; `PYTHONPATH=$PWD $PY -m wpincidentlens version --json`; `python3 -c 'import json;print(json.load(open("demo/report.json"))["tool_version"])'` | wszędzie `0.2.0rc1`; tag = `v` + ta wersja; test `cli::test_tool_version_is_a_pep440_release_candidate_shared_with_the_package_metadata` zielony | agent |
| 5.2 | Zestaw reguł w notatce | `PYTHONPATH=$PWD $PY -m wpincidentlens version --json` | `ruleset.version` i `ruleset.sha256` przepisane do notatki (dziś `2026.11.5`, `5025868649ee…`) | agent |
| 5.3 | `report verify` na przykładzie | `PYTHONPATH=$PWD $PY -m wpincidentlens --files fixtures/site --database fixtures/database.sql --logs fixtures/logs --baseline fixtures/baseline.json --output /tmp/rc-demo --case-id DEMO-001`; `PYTHONPATH=$PWD $PY -m wpincidentlens report verify /tmp/rc-demo` | analiza: kod 3, `SUSPICIOUS`, 6 ustaleń; weryfikacja: kod 0 („ZGODNY”, 9 plików) | agent / recenzent |
| 5.4 | `report verify` wykrywa zmianę | `printf x >> /tmp/rc-demo/report.html; PYTHONPATH=$PWD $PY -m wpincidentlens report verify /tmp/rc-demo` | kod 1, `MODIFIED report.html` | recenzent |
| 5.5 | Brak nadpisania bez `--force` | ponowić polecenie analizy z 5.3 do tego samego katalogu | kod 2, nic nie zapisano; z `--force` — kod 3 i nowy zestaw | recenzent |
| 5.6 | `demo/` aktualne | `python3 -c 'import json;d=json.load(open("demo/report.json"));print(d["tool_version"],d["assessment"],len(d["findings"]))'` | `0.2.0rc1 SUSPICIOUS 6`; `demo/` ma tylko `report.json` i `report.html` (bez `case.json`), więc nie podlega `report verify` — dowodem jest 5.3 | agent |

## 6. Brak realnych danych w repozytorium

Repozytorium jest prywatne, ale zakaz realnych danych (AGENTS.md, ADR 0002 B10) dotyczy całej historii, Issues i PR. Polecenia niżej wykrywają typowe ślady; nie zastępują przeglądu człowieka.

| Nr | Pozycja | Jak sprawdzić | Kryterium | Podpisuje |
|---|---|---|---|---|
| 6.1 | Pliki danych w drzewie | `git ls-files \| grep -Ei '\.(sql\|log\|gz\|zip\|tar\|tgz\|7z\|jsonl\|db\|sqlite\|pem\|key\|p12\|pfx)$\|(^\|/)\.env'` | tylko `fixtures/database.sql`, `fixtures/logs/access.log` (syntetyczne) i dwa archiwa `archives/WPTrace_*.zip` (pakiety specyfikacji z 2026-11-09) | recenzent |
| 6.2 | Zawartość archiwów bez rozpakowania | `unzip -l archives/WPTrace_Final_Pakiet_2026-11-09.zip`; `unzip -l archives/WPTrace_Specyfikacja_PoC_Dla_Seniora_2026-11-09.zip` | tylko dokumenty, kod PoC i fikstury syntetyczne; żadnych zrzutów, logów produkcyjnych, kopii witryn | recenzent |
| 6.3 | Adresy IP | `git grep -hoIP '(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])' -- . ':!*.lock' \| sort -u` | tylko zakresy dokumentacyjne (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), prywatne (`10.0.0.0/8`), `0.0.0.0` i `1.2.3.4` (syntetyczny); stan 2026-11-17: zgodne | recenzent |
| 6.4 | Adresy e-mail | `git grep -hoIE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}' -- . ':!*.lock' \| sort -u` | tylko domeny `example.org`, `example.com`, `*.invalid`; stan 2026-11-17: zgodne | recenzent |
| 6.5 | Kształty sekretów w drzewie i historii | `gitleaks git --redact -v .` (jeśli dostępny) albo `git log -p --all \| grep -nE 'AKIA[0-9A-Z]{16}\|BEGIN [A-Z ]*PRIVATE KEY\|gh[pousr]_[A-Za-z0-9]{36}\|xox[abpr]-\|AIza[0-9A-Za-z_-]{35}'` | brak trafień poza celowymi kanarkami w `tests/` (rozpoznawalne po nazwie `canary`/`synthetic`) — każde trafienie opisane w #76 | recenzent |
| 6.6 | Issues i PR | `gh issue list --state all --limit 200 --json number,title`; przegląd treści PR scalonych w M0–M7 | brak wklejonych fragmentów realnych dowodów, adresów, haseł, tokenów | recenzent |

## 7. Dokumentacja na commicie tagu

| Nr | Pozycja | Jak sprawdzić | Kryterium | Podpisuje |
|---|---|---|---|---|
| 7.1 | Mapa wymagań, macierz testów, model zagrożeń, postęp opisują ten sam stan | `grep -n '92a1188' docs/REQUIREMENTS_TRACEABILITY.md docs/TEST_MATRIX.md docs/THREAT_MODEL.md docs/PROGRESS.md` (albo commit tagu, jeśli inny) | każdy dokument wskazuje commit tagu albo wcześniejszy z jawną informacją, że późniejsze zmiany go nie dotyczą | agent |
| 7.2 | Sumy mapy wymagań przeliczone skryptem | skrypt z §3 `docs/GO_NO_GO.md` | wynik równy kolumnie „Po M7” w `docs/REQUIREMENTS_TRACEABILITY.md` | agent |
| 7.3 | Notatka wydania | plik notatki (poza repozytorium albo w treści wydania) | zawiera: charakter „kontrolowany PoC”, commit, wyniki 2.3, 3.1–3.3, skróty SBOM, wersję zestawu reguł, odwołanie do `docs/GO_NO_GO.md`, listę znanych braków (§6 tamtego dokumentu) i warunki z decyzji właściciela | agent przygotowuje, właściciel zatwierdza |

## 8. Przegląd człowieka i decyzja

| Nr | Pozycja | Jak sprawdzić | Kryterium | Podpisuje |
|---|---|---|---|---|
| 8.1 | Niezależny przegląd bezpieczeństwa przez człowieka | komentarz w #76: kto, kiedy, który commit, zakres według §8 `docs/GO_NO_GO.md`, ustalenia z wagą i rozstrzygnięciem | brak otwartych ustaleń wagi P0 (spec §18: krytyczny błąd wejścia lub fałszywe „clean” = NO-GO); P1 jawnie wymienione | **recenzent bezpieczeństwa (człowiek)** |
| 8.2 | Akceptacja ryzyk resztkowych | lista z §5 `docs/GO_NO_GO.md` z decyzją „akceptuję / warunek / blokuje” przy każdej pozycji | każda pozycja ma decyzję | **właściciel** |
| 8.3 | Decyzja GO / GO z warunkami / NO-GO | wpis właściciela w #76 i zmiana pola „Status” w `docs/GO_NO_GO.md` commitem właściciela (albo na jego wyraźne polecenie) | jedna z opcji §9 `docs/GO_NO_GO.md`, z datą i commitem | **właściciel** |
| 8.4 | Zniesienie zakazu B10 (praca na realnym materiale) | nowy ADR zastępujący w części ADR 0002 B10 i ADR 0009 pkt 7, ze statusem przyjętym **przez właściciela** i warunkami (środowisko, rodzaj materiału, kto analizuje) | ADR istnieje i jest podpisany przez właściciela; agent może przygotować projekt ze statusem `PROPOSED`, nigdy `ACCEPTED` | **wyłącznie właściciel** |

## 9. Utworzenie wydania (po 8.3 = GO albo GO z warunkami)

```bash
git tag -a v0.2.0rc1 "$SHA" -m "WPIncidentLens 0.2.0rc1 — kontrolowany PoC (decyzja: #76)"
git push origin v0.2.0rc1
gh release create v0.2.0rc1 --prerelease --verify-tag --title "WPIncidentLens 0.2.0rc1 (kontrolowany PoC)" \
  --notes-file <notatka> release-artifacts/sbom-test-env.cdx.json release-artifacts/sbom-image.cdx.json \
  release-artifacts/probe.json release-artifacts/demo-compare.json
```

Tag i wydanie tworzy właściciel albo agent na jego wyraźne polecenie zapisane w #76. **Rollback:** `gh release delete v0.2.0rc1 --yes`, `git push --delete origin v0.2.0rc1`, `git tag -d v0.2.0rc1`; decyzja i ADR o B10 pozostają w historii.

## 10. Podpisy

| Rola | Imię i nazwisko / login | Data | Commit | Pozycje | Podpis |
|---|---|---|---|---|---|
| Agent (przygotowanie dowodów) | agent kodujący | 2026-11-17 | `92a1188` | dowody do 2.1–2.4, 3.1–3.4, 4.2, 4.4, 4.6, 5.1–5.3, 5.6, 6.3, 6.4, 7.1, 7.2 zebrane na `92a1188` (`docs/GO_NO_GO.md`) | — (agent nie podpisuje) |
| Recenzent bezpieczeństwa | | | | | |
| Właściciel | | | | | |
