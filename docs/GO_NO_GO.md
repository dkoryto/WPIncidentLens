# Pakiet dowodów do bramki GO/NO-GO kontrolowanego PoC (M7, T-701)

| | |
|---|---|
| **Status** | **PENDING — wymaga przeglądu człowieka i decyzji właściciela** |
| **Data** | 2026-11-17 |
| **Stan kodu** | `main` `92a1188` (po scaleniu PR #79); gałąź dokumentacji `agent/T-701-gate` |
| **Wersja** | `0.2.0rc1`, schematy `poc-1` / `case-poc-1`, zestaw reguł `wpincidentlens-poc` `2026.11.5` |
| **Autor** | agent kodujący. Dokument zbiera dowody i opcje; **nie jest decyzją, rekomendacją wydania ani zgodą na pracę na realnym materiale** |
| **Bramka** (`docs/MASTER_AGENT_PROMPT.md`, M7) | „niezależny przegląd bezpieczeństwa oraz akceptacja właściciela. Brak automatycznego release'u produkcyjnego” |
| **Kryteria** | spec §20 „Finalne kryteria akceptacji całego PoC” (§3.3 niżej) |
| **Lista wydania** | `docs/RELEASE_CHECKLIST.md` |
| **Issue** | #76 |

Do czasu decyzji właściciela obowiązuje zakaz pracy na realnym materiale (ADR 0002 B10, ADR 0009 pkt 7). Zmienić pole „Status” może wyłącznie właściciel (albo agent na jego wyraźne polecenie zapisane w #76), wpisując wybraną opcję z §9, datę i commit.

## Spis

1. Zakres dostarczony w M0–M7
2. Co uruchomiono
3. Dowody: testy, CI, wymagania, kryteria spec §20
4. Model zagrożeń — stan per Z
5. Przeglądy bezpieczeństwa wykonane dotąd
6. Otwarte ryzyka resztkowe (ranking)
7. Znane braki — jawnie
8. Przewodnik dla recenzenta bezpieczeństwa (człowieka)
9. Opcje decyzji właściciela

## 1. Zakres dostarczony w M0–M7

| Etap | Issue | PR (scalone) | ADR | Co dostarczono |
|---|---|---|---|---|
| M0 — audyt i fundament | #1, #2, #3, #11 | #8, #9, #10, #12 | 0001, 0002 | `pyproject.toml`, CI z `contents: read`, baseline; model zagrożeń i mapa wymagań; macierz P1–P6/N1–N8/S-01–S-18 ze 104 testami; naprawa ReDoS w parserze `INSERT` |
| M1 — bezpieczny intake i kontrakty | #4, #5, #17, #18 | #16, #19, #20, #21–#27, #28, #29 | 0003, 0004 | SecureIngest (deskryptory, `O_NOFOLLOW`, hardlinki, limity, ponowna weryfikacja, strażnik D4), CaseManager i `case.json`, schemat `poc-1`, `INCONCLUSIVE`, kody 0/2/3/4, migracja z 0.1.0; raport bramki `docs/M1_GATE.md`; zmiana nazwy na WPIncidentLens |
| M2 — pliki WordPressa | #6, #35, #36 | #30–#34; po M6: #71, #72, #79 | 0005, 0010 | podział na moduły, WPDetector, 13 reguł plików z offsetem, integralność (baseline SHA-256, lokalny manifest sum rdzenia), `NOT_CHECKED` per klasa; po M6: zgodność manifestu z wersją i locale, limity, pomiar fałszywych alarmów (`docs/FP_MEASUREMENT.md`), opcjonalny adapter YARA-X w osobnym procesie, losowe numery żądań do procesu YARA (#79) |
| M3 — baza danych | #7 | #37–#45 | 0006 | ścisły parser strumieniowy mysqldump, adapter JSONL, reguły bazy, odczyt `serialize()` PHP jako danych; trzy rundy utwardzenia parsera po przeglądach |
| M4 — logi i korelacja | #13 | #46–#52 | 0007 | wersjonowany parser `combined@1`/`common@1`/`json@1`, UTC, źródło i niepewność czasu, zaufane proxy, korelacja `SAME_PATH`/`NEAR_IN_TIME`, oś czasu |
| M5 — reguły i raport | #14 (otwarte), #58 | #53–#57, #59, #60; po M6: #73 | 0008 | rejestr 29 reguł z niezależnymi `severity`/`confidence`, raport HTML z jednym miejscem escapowania i CSP, dziewięć plików wyniku ze skrótami w `case.json`, redakcja w jednym miejscu, `--pseudonymize`; kształty sekretów PHP (#73) |
| M6 — hardening i QA | #15 (otwarte), #67 | #61–#66, #68–#70; po M6: #74, #75 | 0009 | lock z hashami, `pip-audit --strict`, SBOM; kontener mierzony w CI (sonda 21 sprawdzeń), digest obrazu; limity czasu w parserach, regułach i korelacji; fuzzing `hypothesis`; benchmarki; budżet pamięci (`--max-entries` 250 000) |
| M7 — demonstrator i bramka | #76 (otwarte) | #77, #78; ta gałąź | 0011 | `docs/INSTALL.md`, `ARCHITECTURE.md`, `FORMATS.md`, `ANALYST_GUIDE.md`, `examples/synthetic-case/`; podkomendy `analyze`, `report verify`, `version`; kod 5; `--force`; wersja `0.2.0rc1`; `docs/RELEASE_CHECKLIST.md`, ten dokument |

Wszystkie ADR (0001–0011) przyjął agent na podstawie delegacji właściciela z 2026-11-11; żaden nie przeszedł niezależnego przeglądu AppSec. Merge PR wykonywał agent z upoważnienia właściciela.

## 2. Co uruchomiono

Środowisko: macOS 27.0.1 (Darwin 27.0.0, arm64, APFS), Python 3.12.11, pytest 9.2.0, ruff 0.8.6, `.venv` projektu **bez `yara-x`**; drzewo `agent/T-701-gate` (= `main` `92a1188` + zmiany wyłącznie w `docs/` i `README.md`).

| Komenda | Wynik |
|---|---|
| `PYTHONPATH=$PWD python -m pytest -q -rs --cov=wpincidentlens --cov-report=term` | **3380 passed, 18 skipped** (186,6 s); zebrano 3398 przypadków z 932 funkcji |
| `python -m ruff check .` | All checks passed |
| polecenie z `examples/synthetic-case/README.md` (wyjście w katalogu tymczasowym) | kod 3, `SUSPICIOUS`, `scope_complete: false`, 6 ustaleń, 6 luk, 9 plików wyniku |
| `python -m wpincidentlens report verify <katalog>` | kod 0, „ZGODNY — sprawa DEMO-001, sprawdzono plików: 9” |
| ponowna analiza do tego samego katalogu bez `--force` | kod 2, nic nie zapisano |
| `report verify` po dopisaniu bajtu do `report.html` | kod 1, `MODIFIED report.html` |
| `python -m wpincidentlens version --json` | `0.2.0rc1`, `poc-1`, `case-poc-1`, `ruleset` `2026.11.5` / `5025868649ee671b01e6f9615da8cab39f3b794fcc299a38b2fc9d74e44dedfd` |
| `pip-audit -r requirements/{dev,yara,audit}.lock --require-hashes --disable-pip --strict` (pip-audit 2.10.1 z `audit.lock`, 2026-11-17) | „No known vulnerabilities found” dla trzech locków |
| `pytest -q tests/test_yarax.py` ×5 (przed PR #79, bez `yara-x`) | 5 × „42 passed, 11 skipped”; migotania lokalnie nie odtworzono — wyścig ujawnił przebieg CI (§5, PR #79) |
| skrypt na `rules.REGISTRY`: reguły z wagą `high`/`critical` i dopuszczalną pewnością `high` | **brak** (29 reguł) — `STRONG_INDICATORS` nieosiągalny |
| `git grep` adresów IP i e-mail w drzewie (`docs/RELEASE_CHECKLIST.md` 6.3–6.4) | tylko zakresy dokumentacyjne/prywatne, `1.2.3.4`, domeny `example.*` i `.invalid` |

Nie uruchamiano lokalnie: Dockera (brak demona), YARA-X (brak pakietu), Linuksa poza CI, Windows, profilu `HYPOTHESIS_PROFILE=nightly`, benchmarków `bench/`.

## 3. Dowody

### 3.1. Testy i CI

| Dowód | Wartość |
|---|---|
| Testy lokalnie (macOS) | 3380 passed, 18 skipped, 0 failed; bez XFAIL (`grep -rn xfail tests` — brak) |
| Pokrycie liniowe | 97% (4946 instrukcji, 172 niepokryte); `verify.py` 95%, `cli.py` 97%, `report.py` 99%, `ingest.py` 98%, `yarax.py` 73% (proces potomny i ścieżki z prawdziwym silnikiem nie wykonują się lokalnie bez `yara-x`) |
| Pliki testów | 38 (`tests/test_*.py`); w M7 nowe: `test_verify.py` (40 funkcji, 85 przypadków), `test_sample_case.py` (2), `test_docs_consistency.py` (4 funkcje, 12 przypadków) |
| Pominięcia lokalnie | 5 — APFS (nazwy spoza UTF-8, `mtime` spoza zakresu); 13 — brak `yara-x` (uruchamia je zadanie CI `yara`) |
| CI `main` `5c570a9` (PR #78) | `ci` 44136797223 `success` — `test` 3382 passed, 15 skipped (Linux), `yara` 146 passed, `audit` `success`; `container` 44136797602 `success` — sonda 21/21 (`ok: true`, `failed: []`), demo w kontenerze = na hoście (`problems: []`), SBOM obrazu CycloneDX 1.7 (2755 komponentów), SBOM środowiska testowego CycloneDX 1.6 (18 komponentów) — odczytane z logu i artefaktów |
| CI `main` `92a1188` (PR #79) | `ci` 44139136002 `success` — `test` 3383 passed, 15 skipped (Linux), `yara` 147 passed bez pominięć, `audit` `success`; `container` 44139135639 `success` — sonda 21/21 (`ok: true`, `failed: []`), demo w kontenerze = na hoście (`problems: []`), SBOM obrazu CycloneDX 1.7 (2755 komponentów) — odczytane z logu i artefaktu `container-measurement` |
| Historia CI | ostatnie 200 przebiegów (`gh run list --limit 200`): 157 `success`, 1 `failure` (gałąź `agent/T-006-backslash-anywhere`, 2026-11-11), 4 `cancelled` (kolejka `concurrency`), 1 bez wyniku; migotanie testu `extra-line` (przebieg 44135848332, gałąź `agent/T-701-cli`) zakończyło się zielonym ponowieniem i doprowadziło do PR #79 |

Szczegóły i lista testów: `docs/TEST_MATRIX.md` („Stan po M7”, sekcja „M7: podkomendy, `report verify`, `--force`, dokumentacja”).

### 3.2. Wymagania (mapa `docs/REQUIREMENTS_TRACEABILITY.md`)

Policzone skryptem, nie szacunkiem — status z wierszy tabel o identyfikatorze `C`, `R-`, `P`, `N`, `S-`, `Q-` (wiersze grupujące, np. `N1–N8`, liczone raz):

```python
import re, collections
c = collections.Counter()
for line in open("docs/REQUIREMENTS_TRACEABILITY.md", encoding="utf-8"):
    if re.match(r"\|\s*(C\d\d|R-\d+|P\d(–P\d)?|N\d(–N\d)?|S-\d\d(–S-\d\d)?|Q-\d\d)\s*\|", line):
        cells = [x.strip() for x in line.strip().strip("|").split("|")]
        c[next(x for x in cells[1:4] if x in ("IMPLEMENTED", "PARTIAL", "MISSING", "UNVERIFIED"))] += 1
print(dict(c), sum(c.values()))
```

| Status | Po poprawkach M6 (`3e6ecb6`) | Po M7 (ta gałąź) | Zmiana |
|---|---|---|---|
| IMPLEMENTED | 64 | **65** | +1 (R-91) |
| PARTIAL | 30 | **30** | 0 (R-90 MISSING → PARTIAL, R-91 PARTIAL → IMPLEMENTED) |
| MISSING | 1 | **0** | −1 (R-90) |
| UNVERIFIED | 1 | **1** | R-87 (tekst z dowodów jako instrukcja — brak testu) |
| **Razem** | 96 | **96** | |

IMPLEMENTED znaczy „kod i zielony test na danych syntetycznych”, nie „bezpieczne” ani „kompletne”. 30 wierszy PARTIAL wymienia braki w kolumnie „Uwagi”.

### 3.3. Kryteria spec §20 (GO dla demonstracji)

Oznaczenia: PASS — jest dowód; PARTIAL — dowód częściowy; NOT_TESTED — brak uruchomienia; FAIL — kryterium niespełnione. Ocena agenta, do weryfikacji przez recenzenta.

| Nr | Kryterium (skrót) | Ocena agenta | Dowód / brak |
|---|---|---|---|
| 1 | Fixture i manifesty wersjonowane, dane syntetyczne | PASS | `fixtures/`, `tests/data/`; `docs/RELEASE_CHECKLIST.md` §6 (IP, e-mail, typy plików) |
| 2 | P1–P6 i N1–N8 zgodne; S-01–S-18 bez blockerów | PARTIAL | N1–N8 IMPLEMENTED; P3, P5–P6, S-02–S-08, S-13–S-15 PARTIAL (`docs/TEST_MATRIX.md`); blockerów (testów czerwonych, XFAIL) brak; S-05 (nazwy spoza UTF-8) uruchamiany tylko w CI na Linuksie |
| 3 | Pliki i dump nie są uruchamiane; wejście niemodyfikowane | PASS | `inv::test_s17_*`, `inv::test_s16_*`, `prop::test_sources_are_left_exactly_as_they_were`; wyjątek S-17: stały proces YARA (ADR 0010 pkt 9); bez `atime` |
| 4 | `network_mode: none` i ograniczenia kontenera zweryfikowane na runtime | PARTIAL | sonda 21/21 w zadaniu CI `container` (`ubuntu-24.04`, cgroup v2); lokalnie i na innych hostach NOT_TESTED; obraz bez YARA-X |
| 5 | JSON i HTML z tym samym zestawem ustaleń; HTML odporny na XSS; kanarki usuwane | PASS | `html::test_every_text_leaf_of_a_full_report_is_escaped`, `sec::test_s12_*`, `priv::test_canary_from_any_source_never_reaches_report_html_or_case`; od M7 `report verify` wylicza HTML z `report.json`; zachowania przeglądarek nie testowano |
| 6 | Błąd parsera SQL i brak logów widoczne w pokryciu; brak „safe/clean” | PASS | `con::test_sql_that_the_parser_skipped_lowers_database_coverage`, `neg::test_n6_missing_database_and_logs_is_inconclusive`, `cli::test_no_indicators_not_a_clean_bill` |
| 7 | Senior zatwierdził zagrożenia P0 jako zamknięte; P1 widoczne | **NOT_TESTED** | przeglądu człowieka nie było (§5); żaden Z nie ma statusu „zamknięte” (§4) |
| 8 | README: izolacja, ograniczenia, powtórzenie skanu, retencja, tylko uprawnione materiały | PARTIAL | `docs/INSTALL.md`, `docs/ANALYST_GUIDE.md`, README; retencja tylko jako zalecenia (katalog `0700`, dane osobowe), bez procedury |
| 9 | Wyniki testów i benchmarków z komendą, środowiskiem, czasem, wersją | PARTIAL | `docs/TEST_MATRIX.md`, `bench/RESULTS.md`; benchmark tylko macOS, sprzed PR #68, bez progów |
| 10 | Zatwierdzenie dotyczy kontrolowanego PoC | do decyzji | §9 |

Spec §18: „krytyczny błąd bezpieczeństwa wejścia lub niewłaściwa deklaracja »clean« = automatyczne NO-GO”. Agent nie zna otwartego błędu tej klasy; to stwierdzenie wymaga potwierdzenia przez recenzenta.

## 4. Model zagrożeń — stan per Z (`docs/THREAT_MODEL.md` §4)

Żaden wiersz nie ma statusu „zamknięte”. „OGRANICZONE (test)” = mitygacja w kodzie z zielonym testem na danych syntetycznych, bez przeglądu człowieka.

| ID | Zagrożenie | Status | Najważniejsze, co pozostaje |
|---|---|---|---|
| Z-01 | Wykonanie nieufnego PHP | OGRANICZONE (test) | strażnik AST po nazwach, nie piaskownica; wyjątek: proces YARA |
| Z-02 | Wykonanie lub odtworzenie SQL | OGRANICZONE (test) | parser tekstowy; ograniczona gramatyka |
| Z-03 | Nieufne logi jako wejście parsera | CZĘŚCIOWE | tylko access log w 3 formatach; brak logów błędów |
| Z-04 | Tekst udający instrukcje | NIEZWERYFIKOWANE | brak fixture z „instrukcją”; ryzyko dla ludzi i modeli czytających raport |
| Z-05 | Path traversal | OGRANICZONE (test) | dowiązania w pośrednich składnikach ścieżki operatora akceptowane |
| Z-06 | Symlink | OGRANICZONE (test) | jw. |
| Z-07 | Hardlink | OGRANICZONE (test) | odrzucanie `st_nlink > 1` pomija kopie z deduplikacją |
| Z-08 | TOCTOU | OGRANICZONE (test) | wyścig próbkowany; zmiana cofnięta przed ponowną weryfikacją niewykrywalna |
| Z-09 | DoS / limity zasobów | CZĘŚCIOWE | pamięć szacowana (`--max-entries`), RSS mierzony tylko na macOS; instrukcja SQL ≤ 16 MiB bez zegara |
| Z-10 | Błędy parserów i ciche pominięcia | CZĘŚCIOWE | parser nigdy kompletny; fuzz tylko profil `ci` w CI |
| Z-11 | Sieć / eksfiltracja | OGRANICZONE (test) | sieć kontenera mierzona tylko w CI |
| Z-12 | Wyciek sekretów i danych osobowych | CZĘŚCIOWE | redakcja heurystyczna; ścieżki i nazwy plików nieredagowane; IP i loginy jawne bez `--pseudonymize` |
| Z-13 | XSS w raporcie HTML | OGRANICZONE (test) | CSP w `<meta>`; przeglądarek nie testowano |
| Z-14 | Kontener / ucieczka na host | OGRANICZONE (test) | kontener nie jest sandboxem; pomiar tylko w CI |
| Z-15 | Łańcuch dowodowy | CZĘŚCIOWE | `report verify` = spójność, nie autentyczność; brak podpisu, pól pozyskania, archiwizacji przy `--force` |
| Z-16 | Fałszywa pewność wyniku | CZĘŚCIOWE | `STRONG_INDICATORS` nieosiągalny; pełny zakres zależy od referencji operatora |
| Z-17 | Łańcuch dostaw | OGRANICZONE (test) | `setuptools` bez hashy; digest obrazu odświeżany ręcznie; obraz bez skanu podatności |
| Z-18 | Zaufana referencja jako wejście | CZĘŚCIOWE | pochodzenie referencji niesprawdzane |
| Z-19 | WPDetector na plikach napastnika | OGRANICZONE (test) | brak parsera PHP |
| Z-20 | Omijanie reguł plików | CZĘŚCIOWE | konkatenacja i zmienne pośrednie omijają reguły bez śladu |
| Z-21 | Kod natywny YARA-X | CZĘŚCIOWE | proces potomny bez seccomp/namespaces; na macOS bez limitu pamięci; obraz bez YARA-X; po PR #79 odpowiedź spóźniona nie zostaje przypisana następnemu plikowi |

Suma: OGRANICZONE (test) 11, CZĘŚCIOWE 9, NIEZWERYFIKOWANE 1, OTWARTE 0.

## 5. Przeglądy bezpieczeństwa wykonane dotąd

**Żadnego przeglądu nie wykonał człowiek.** Wszystkie poniżej to agenty (agent prowadzący, osobne sesje agenta-audytora) albo automatyczne przeglądy commitów. Źródło: opisy PR (`gh pr view <nr> --json body`), `docs/PROGRESS.md`, ADR.

| PR | Zakres | Kto | Główne ustalenia poprawione |
|---|---|---|---|
| #12 (T-004) | parser `INSERT` | agent (z macierzy T-003) | ReDoS we wzorcu wiersza `INSERT` → skaner liniowy |
| #16 → #19, #21–#26 | SecureIngest (T-101) | agent prowadzący + niezależny agent-audytor | kwadratowy nagłówek `INSERT` (400 kB: 74 s → 0,014 s) i budżet wpisów na stosie katalogów (#17 → PR #19); drobne ustalenia #18 (skaner instrukcji, komentarze wykonywalne, `DELIMITER`, ukośnik poza łańcuchem, spójność pokrycia z dowodami) |
| #20 (T-102) | kontrakty `poc-1` | niezależny agent | wada blokująca poprawiona w PR |
| #28 | bramka M1 | agent | K3: stratne dekodowanie, instrukcje SQL spoza `INSERT`, `NO_TRUSTED_REFERENCE` dają lukę |
| #32 (T-201) | integralność | niezależny agent | poprawki w `4b22b99` (ADR 0005 pkt 6–12: plik kodu bez referencji obniża pokrycie, odrzucanie złych kluczy baseline) |
| #42 | parser SQL (M3) | niezależny agent | 3 wysokie: zapis ukryty w `SET STATEMENT`/`CREATE TABLE … SELECT`/`ALTER … RENAME`, instrukcja w komentarzu wykonywalnym, różnice leksera z serwerem; 3 średnie, 2 niskie (L7 zostaje) |
| #44, #45 | parser SQL | automatyczne przeglądy commitów | 4 + 3 obejścia (apostrof w komentarzu DDL, `sql_mode` ze zmiennej, treść po kolumnach `CREATE TABLE`, wielkość liter tabel, `@@x`, przepełnienie rejestru tabel) |
| #49, #50 | logi i korelacja (M4) | niezależny agent | HIGH: czas kwadratowy `_script_path` i limit czasu tylko między plikami; MEDIUM: zalew żądań wypierał regułę uploads; znaki niewidoczne w ścieżce, ucieczki logu, dane logowania w adresie bezwzględnym |
| #53, #54 | projekt ADR 0008 | agent | pseudonim 16 hex zamiast 10, wartość spoza deklaracji nie usuwa ustalenia, kolejność `<head>`, lista pól strukturalnych, `ensure_ascii` w plikach wierszowych |
| #59 | prywatność, HTML, pliki wyniku (M5) | niezależny agent | 1 średnie + 2 średnie/niskie + 3 niskie w `cfef2bc`: `timestamp_raw` tylko w kształcie czasu, loginy zamieniane tylko w tekstach z dowodów, liniowe skanowanie tokenów, IP w polach strukturalnych; reszta → #58 |
| #64, #65 | redakcja | automatyczne przeglądy commitów | nazwa sekretu tuż po `?` i ukośnik wsteczny w zapytaniu odsłaniały wartość |
| #68 | limity czasu (M6) | agent | 2 średnie + 3 niskie + 1 info: JSONL 257 MiB przy `--max-seconds 2` (41,5 s bez luki → 2,05 s z luką), korelacja 120 s → 3,0 s, nazwy plików w lukach neutralizowane |
| #69 | fuzzing (M6) | `hypothesis` + automatyczne przeglądy commitów | 6 błędów: 2 czasu kwadratowego w SQL, 4 w redakcji; komentarz wykonywalny z pozostawionym komentarzem = luka |
| #71 (T-202) | adapter YARA-X | agent | 2 średnie + 3 niskie + 4 info: tysiące reguł i długa nazwa reguły wyłączały YARA do końca analizy, odczyt odporny na zagnieżdżony JSON, rozsynchronizowanie odpowiedzi, walidacja `engine` |
| #74 (#67) | pamięć | agent | brak ustaleń blokujących |
| #78 (T-701) | `report verify`, `--force`, kod 5 | agent | 1 średnie: podmiana `tool_version` na starszą z fałszywym `report.html` dawała „zgodny” (teraz `HASHES_ONLY`/`INVALID_TOOL_VERSION`); 2 niskie: osobne limity pamięci `case.json`/`report.json`, wyjątek przy ponownym wyliczeniu = `INVALID_REPORT`; 1 info |
| #79 (T-202) | protokół procesu YARA | migotanie testu CI `extra-line` (przebieg 44135848332) + analiza agenta | kolejne numery żądań pozwalały niezaufanemu procesowi odpowiedzieć z wyprzedzeniem na **następne** żądanie — następny plik wychodził „bez trafień” bez luki (naruszenie fail-closed); teraz numery losowe (`secrets.randbits(63) + 1`), spóźniona linia = restart i jednorazowe ponowne skanowanie pliku; nota w ADR 0010 |

Niezależny od autora przegląd przez człowieka — wymagany przez AGENTS.md dla zmian security-critical, ADR 0002–0011 i spec §18 — **się nie odbył**. Przeglądy agentów korzystały z tego samego modelu co autor kodu i nie są niezależne w sensie organizacyjnym.

## 6. Otwarte ryzyka resztkowe (ranking)

Konsolidacja z `docs/THREAT_MODEL.md` §5 (numery w nawiasach). Ranking agenta według wpływu na decyzję o kontrolowanym użyciu na autoryzowanym materiale; recenzent może go zmienić.

| Poz. | Ryzyko | Nr w modelu | Dlaczego tak wysoko |
|---|---|---|---|
| 1 | Brak przeglądu bezpieczeństwa przez człowieka; wszystkie ADR i przeglądy wykonał agent | 10, 37; §5 | warunek bramki z MASTER_AGENT_PROMPT i spec §20 pkt 7 |
| 2 | Parsery działają w procesie analizy (D9: izolacja „nie teraz”); kontener nie jest sandboxem — błąd interpretera lub jądra omija izolację | 2, 56 | materiał przygotował napastnik; jedyną barierą jest kontener |
| 3 | Fałszywe negatywy bez śladu: reguły to tekst, nie parser PHP; fałszywe alarmy mierzone tylko na kodzie z wordpress.org; metadane (`mtime`, daty w bazie, logi) kontroluje napastnik | 6, 9, 26, 31, 62 | analityk może uznać brak ustaleń za brak włamania mimo `INCONCLUSIVE` |
| 4 | Redakcja heurystyczna; nazwy plików i ścieżki nieredagowane; IP i loginy jawne bez `--pseudonymize`; z flagą część danych zostaje | 8, 38, 40, 41, 60 | raport wychodzi poza zespół z danymi osobowymi lub sekretem |
| 5 | Pamięć ograniczona szacunkiem (`--max-entries`), RSS mierzony tylko na macOS; OOM w kontenerze 1 GiB zamiast luki | 46, 61, 63 | przerwana analiza na dużej witrynie |
| 6 | Kontener mierzony tylko w CI na `ubuntu-24.04`; obraz bez YARA-X; proces YARA bez limitu pamięci na macOS i bez seccomp | 49, 57, 58 | użycie z `--yara-rules` wychodzi poza zmierzone środowisko |
| 7 | `report verify` sprawdza spójność, nie autentyczność; zestaw wyniku nie jest zamieniany atomowo; `--force` bez archiwum | 42, 65, 68 | łańcuch dowodowy wymaga mitygacji organizacyjnej (skrót `case.json` poza katalogiem) |
| 8 | Zmiana materiału po stronie hosta niezapobiegalna (wykrywalna); punkty montowania, pliki urządzeń, dowiązania w ścieżce operatora | 3, 11, 12, 13, 14 | wymaga montowania `ro,nodev` i dyscypliny operatora |
| 9 | Jedna instrukcja SQL ≤ 16 MiB oraz odczyt i skrót jednego pliku poza zegarem | 17, 47 | limit czasu przekraczalny o sekundy |
| 10 | Łańcuch dostaw: digest obrazu odświeżany ręcznie, brak skanu podatności obrazu, `setuptools` bez hashy, `--strict` może zablokować CI | 50, 51, 52 | znane podatności obrazu bazowego mogą narastać między wydaniami |
| 11 | Platformy: Windows nietestowany, Linux tylko w CI, sieciowe systemy plików nietestowane | 5, 19 | gwarancje SecureIngest potwierdzone na macOS i runnerze CI |
| 12 | Referencja operatora bez weryfikacji pochodzenia; zmieniony `$wp_version` zwija rozbieżności rdzenia do jednego ustalenia | 35, 59 | referencja wykonana po włamaniu potwierdza zmienione pliki |
| 13 | Kod 5 bez śladu stosu; renderowanie musi być deterministyczne dla `report verify`; brak `case init` | 67, 69, 71 | diagnoza i rejestr sprawy poza narzędziem |
| 14 | Termin `hypothesis` (2 s) może migotać na obciążonym runnerze | 55 | fałszywie czerwone CI, nie wada wyniku |

## 7. Znane braki — jawnie

| Brak | Stan | Dowód |
|---|---|---|
| `STRONG_INDICATORS` nieosiągalny | żadna z 29 reguł nie ma wagi `high`/`critical` z dopuszczalną pewnością `high`; najwyższa realna ocena to `SUSPICIOUS` | skrypt na `rules.REGISTRY` (§2); `con::test_demo_case_is_suspicious_not_strong`; ADR 0003 §6 |
| Pamięć (R-16) | RSS mierzony tylko na macOS (`bench/RESULTS.md`); w kontenerze i na Linuksie niezmierzony | R-16 PARTIAL |
| Kontener | mierzony wyłącznie w CI (`ubuntu-24.04`, cgroup v2); lokalnie brak demona | R-84, R-85; przebiegi `container` |
| `case init` | odroczone (nowy schemat i model zagrożeń pliku konfiguracji) | ADR 0011 „Odroczone”; R-90 PARTIAL |
| `report verify` | spójność, nie autentyczność; brak podpisu; starsza wersja, raport przeniesiony i duży `report.json` → `HASHES_ONLY` | ADR 0011 pkt 3; ryzyka 65, 66 |
| Migotanie testu YARA | **naprawione w PR #79** — migotanie `extra-line` w CI było objawem realnej słabości protokołu (§5); według opisu PR pętla 200× testów protokołu z `yara-x`: 0 błędów (pomiar agenta, nieodtworzony tutaj); lokalnie bez `yara-x` 5 przebiegów `test_yarax.py` zielonych | PR #79, ADR 0010 (nota) |
| Migracja 0.1.0 | bez wejścia w CLI | R-39 |
| Tekst z dowodów jako instrukcja | UNVERIFIED | R-87, Z-04 |
| Analiza typów | brak `mypy` | Q-03 PARTIAL |
| Benchmark | tylko macOS, przed PR #68, bez progów w CI | Q-02 PARTIAL |
| Detekcje | brak `posts`/`postmeta`/`siteurl`, porównania cron i wtyczek z baseline (R-62), logów błędów, relacji `SAME_ACCOUNT`/`POSSIBLE_SEQUENTIAL`, multisite i witryny w podkatalogu URL | C08, C09, C11 PARTIAL |
| Retencja | brak procedury retencji wyników w narzędziu; tylko zalecenia | spec §20 pkt 8 |
| Issue | #14 i #15 otwarte (kod scalony, zamknięcie należy do właściciela); #76 otwarte do decyzji | `gh issue list --state all` |

## 8. Przewodnik dla recenzenta bezpieczeństwa (człowieka)

Cel: niezależna ocena granicy T1 (nieufne wejście → analizator), T4 (wynik → czytelnik) i T5 (kontener). Czas orientacyjnie 1–2 dni. Model zagrożeń: `docs/THREAT_MODEL.md`; architektura i granica D4: `docs/ARCHITECTURE.md`. Pracuj na kopii repozytorium i danych syntetycznych; ustalenia zapisuj w #76 z wagą P0/P1/P2, plikiem, linią i reprodukcją (spec §19, Prompt C).

### 8.1. Moduły security-critical (`wc -l`, `main` `92a1188`)

| Moduł | Linie | Na co patrzeć | Pytania kontrolne |
|---|---|---|---|
| `wpincidentlens/ingest.py` | 605 | `Session`, `_Root`, `check_source`, `resolve_output`, `present`; `os.open` z `O_NOFOLLOW`/`dir_fd`, `fstat` po otwarciu, `st_nlink`, liczniki limitów, ponowna weryfikacja, `sink_factory` | Czy istnieje ścieżka otwarcia bez `dir_fd`/`O_NOFOLLOW`? Czy plik urządzenia lub FIFO może zablokować albo wywołać efekt uboczny przed `fstat`? Czy każdy pominięty wpis ma lukę? Czy limit wpisów obejmuje nazwy z `listdir` przed obcięciem? |
| `wpincidentlens/sqldump.py` | 553 | `DumpParser`: lekser (łańcuchy, komentarze `/*! */`, `--`, `#`), lista instrukcji „obojętnych”, `SET` trybu i kodowania, granice porcji, `CLOCK_EVERY_*`, limit 16 MiB instrukcji | Czy da się ukryć zapis do `*_users`/`*_options` w instrukcji uznanej za obojętną? Czy podział na porcje zmienia wynik? Czy jakaś konstrukcja daje czas kwadratowy? |
| `wpincidentlens/jsonldb.py` | 192 | `JsonlParser`: kontrakt wiersza, limity kolumn i długości, zegar | Czy wiersz sprzeczny z kontraktem może zostać przyjęty? Głębokość i rozmiar JSON? |
| `wpincidentlens/logformats.py` | 345 | wzorce `combined@1`/`common@1`/`json@1` (kwantyfikatory zaborcze), `resolve_target`, `client_address` (zaufane proxy) | ReDoS? Czy `X-Forwarded-For` spoza zaufanych sieci może podmienić adres? Czy znaki sterujące docierają do raportu? |
| `wpincidentlens/httplog.py` | 462 | `LogFileParser` (strumień, limit wiersza 64 KiB, `expired()` co 256 wierszy), `redacted_uri`, `_script_path` | Czy query/fragment lub dane logowania w URL mogą przetrwać? Czy zalew żądań wypiera regułę uploads? |
| `wpincidentlens/phpserialize.py` | 175 | parser `serialize()` jako danych: obiekty i referencje → znaczniki, limity głębokości i długości | Czy nazwa klasy albo obiekt może trafić do wyniku? Rekurencja i długości deklarowane vs rzeczywiste? |
| `wpincidentlens/redact.py` | 167 | `redact` (kolejność wzorców sekretów i zapytania, idempotencja), `neutralise` (bidi, zero-width) | Jaki kształt sekretu przechodzi (ryzyko 60)? Czy redakcja jest liniowa? |
| `wpincidentlens/privacy.py` | 334 | `sanitize`, lista pól strukturalnych `_STRUCTURAL`, `Pseudonymizer` (HMAC, klucz na uruchomienie, `PSEUDONYM_HEX = 16`) | Czy nieznany atrybut tekstowy zawsze jest redagowany? Czy klucz HMAC może wypłynąć? Co zostaje jawne z `--pseudonymize`? |
| `wpincidentlens/report.py` | 282 | `render_html` (jedno `html.escape` w `_text`, CSP), `write`/`_publish` (tryb `0600`, `os.replace`, `case.json` ostatni), `existing_results` | Czy wartość z dowodu może trafić do atrybutu lub poza węzeł tekstowy? Czy zapis może pójść za dowiązaniem? Okno między sprawdzeniem a `os.replace`? |
| `wpincidentlens/verify.py` | 344 | `_read` (wyłącznie przez `ingest.Session`), `_case`, `_report`, `_recomputable`, `_recomputed`, `version_key`, `shown` | Czy spreparowany katalog wyników może dać `VERIFIED` bez ponownego wyliczenia? Czy nazwa pliku może wstrzyknąć sekwencję terminala? Czy limity chronią pamięć? |
| `wpincidentlens/yarax.py` | 528 | `worker_argv` (`-I`, puste środowisko, `cwd=/`), `_confine` (`setrlimit`), `_Worker` (numery żądań losowe po PR #79, kolejka, nadzór czasu, restart), walidacja odpowiedzi, `load_pack` | Czy niezaufany proces może przypisać odpowiedź innemu plikowi lub ukryć trafienie bez luki? Czy dopasowane bajty mogą trafić do raportu? Co z pamięcią na macOS? |
| `wpincidentlens/cli.py` | 480 | `main` (podkomendy, kod 5 tylko z nazwą typu), `_analyze` (odmowa bez `--force`, walidacja wejść), `compose_report` | Czy któryś wyjątek wypisuje treść dowodu lub ścieżkę? Czy forma płaska i `analyze` mają identyczną walidację? |

Pozostałe moduły (`files`, `filerules`, `integrity`, `wpdetect`, `database`, `dbrules`, `correlate`, `rules`, `outputs`, `models`, `case`, `migrate`) dostają bajty już przeczytane przez `ingest` (strażnik D4: `inv::test_d4_only_ingest_touches_the_filesystem`), ale decydują o fałszywych negatywach (Z-16, Z-20).

### 8.2. Testy „atakujące” — jak uruchomić

```bash
python3.12 -m venv .venv && .venv/bin/python -m pip install --require-hashes -r requirements/dev.lock && .venv/bin/python -m pip install --no-deps -e .
export PYTHONPATH=$PWD; PY=.venv/bin/python
$PY -m pytest -q -rs tests/test_security_inputs.py tests/test_ingest.py tests/test_invariants.py   # S-01–S-18, D4, brak sieci i procesów
$PY -m pytest -q -rs tests/test_ingest_properties.py                                                # losowe drzewa, wyścig z osobnym procesem (~1,5 s/wariant)
$PY -m pytest -q tests/test_sqldump.py tests/test_sqldump_evasion.py tests/test_jsonldb.py          # parser SQL/JSONL, obejścia z przeglądów
$PY -m pytest -q tests/test_logformats.py tests/test_httplog.py tests/test_phpserialize.py
$PY -m pytest -q tests/test_redact.py tests/test_privacy.py tests/test_report_html.py               # redakcja, kanarki, XSS, CSP
$PY -m pytest -q tests/test_verify.py tests/test_report_writer.py tests/test_outputs.py             # report verify, --force, zapis
$PY -m pytest -q tests/test_deadlines.py tests/test_memory_budget.py                                # limity czasu i pamięci
HYPOTHESIS_PROFILE=nightly $PY -m pytest -q tests/test_fuzz.py                                     # 4000 przykładów na właściwość, ~30 min
$PY -m pip install --require-hashes --only-binary=:all: -r requirements/yara.lock && $PY -m pytest -q -rs tests/test_yarax.py   # z prawdziwym YARA-X
```

Kontener (wymaga Dockera na Linuksie z cgroup v2): kroki zadania `.github/workflows/container.yml` — `docker build --file docker/Dockerfile --tag wpincidentlens:ci .`, sonda `docker/probe.py` z flagami z `python docker/containercheck.py flags` i porównanie demo `python docker/containercheck.py compare …`.

### 8.3. Proponowane sondy ręczne (dane syntetyczne)

1. Drzewo z dowiązaniem do `/etc`, FIFO, hardlinkiem i plikiem 10 GiB rzadkim → każdy wpis ma lukę, nic spoza korzenia nie jest czytane.
2. Zrzut SQL z `INSERT` do `wp_usermeta` ukrytym w nietypowej składni (komentarz wykonywalny, `SET STATEMENT`, zmiana `sql_mode`) → albo poprawny odczyt, albo luka; nigdy `ANALYZED` bez administratora.
3. Log z sekwencjami ESC/RLO w URI i user-agencie, z tokenem w query → brak sekwencji i tokenu w `report.html`, `report.json`, na stdout.
4. Katalog wyników spreparowany do `report verify`: dowiązania, `case.json` z `outputs` wskazującym `../`, `tool_version` obniżona, nazwy z ESC → kod ≠ 0, brak wydruku surowych nazw.
5. Pakiet YARA z regułą dopasowującą się do sekretu w pliku → raport bez dopasowanych bajtów.

### 8.4. Czego recenzent nie dostanie od agenta

Oceny, czy kontener i `setrlimit` wystarczają dla materiału wysokiego ryzyka; oceny prawnej przetwarzania danych osobowych; oceny, czy ryzyka z §6 są akceptowalne. To decyzje człowieka.

## 9. Opcje decyzji właściciela

Agent nie wybiera opcji. Decyzję zapisuje właściciel w #76 i w polu „Status” tego dokumentu; zniesienie B10 wymaga nowego ADR przyjętego przez właściciela (`docs/RELEASE_CHECKLIST.md` 8.4).

### Opcja A — NO-GO

Zakaz B10 trwa; narzędzie zostaje na danych syntetycznych. Właściwa, jeśli przegląd człowieka się nie odbył, znalazł otwarte P0 albo ryzyka 1–3 z §6 są nieakceptowalne. Tag `v0.2.0rc1` może powstać wyłącznie jako znacznik stanu do demonstracji na danych syntetycznych (spec §20 „GO dla demonstracji”) — albo wcale.

### Opcja B — GO z warunkami (kontrolowane użycie na autoryzowanym materiale)

Warunki do przyjęcia, zmiany lub odrzucenia przez właściciela (każdy sprawdzalny):

1. Przegląd człowieka wg §8 wykonany na commicie tagu; brak otwartych P0; każde P1 z decyzją w #76.
2. Analiza wyłącznie w kontenerze z flagami `docker/run-flags.txt` na hoście Linux z cgroup v2 (jak w pomiarze CI) albo w osobnej VM bez sieci; nigdy bezpośrednio na stacji analityka.
3. Materiał: tylko kopie z pisemnym upoważnieniem, montowane `ro,nodev`; bez archiwów do rozpakowania przez narzędzie.
4. Bez `--yara-rules` poza VM (obraz nie zawiera YARA-X, a proces YARA nie jest mierzony w kontenerze).
5. Domyślne limity; podniesienie `--max-entries` tylko po pomiarze RSS na hoście docelowym (ryzyko 61).
6. Katalog wyników `0700` poza materiałem; SHA-256 `case.json` zapisany poza katalogiem wyników w chwili analizy (mitygacja ryzyka 65); `report verify` z kodem 0 przed przekazaniem raportu.
7. Raport przekazywany poza zespół tylko z `--pseudonymize` i po ręcznym przeglądzie redakcji (ryzyka 38, 60).
8. Wynik jest materiałem triage dla analityka, nie dowodem w postępowaniu ani werdyktem; `INCONCLUSIVE` i `SUSPICIOUS` wymagają ręcznej analizy (spec §20 pkt 10).
9. Lista dopuszczonych osób i rodzajów spraw; przegląd decyzji po określonej liczbie spraw albo dacie; każda anomalia narzędzia zgłaszana jako Issue bez danych z dowodów.
10. Nowy ADR (zastępujący w części ADR 0002 B10 i ADR 0009 pkt 7) z tymi warunkami, przyjęty przez właściciela.

### Opcja C — GO dla demonstracji, NO-GO dla realnego materiału

Wydanie `0.2.0rc1` jako kontrolowany PoC do pokazów na `fixtures/` i `examples/synthetic-case/` (spec §20, „GO dla demonstracji”); B10 pozostaje w mocy; realny materiał dopiero po opcji B w osobnej decyzji. Wymaga co najmniej warunku 1 z opcji B dla rzetelności pokazu albo jawnej adnotacji w notatce wydania, że przeglądu człowieka nie było.

W każdej opcji: brak produkcyjnego wydania, brak publikacji w PyPI i rejestrze obrazów, zamknięcie #14, #15 i #76 — decyzja właściciela.

| Decyzja | Opcja | Warunki (numery z opcji B / zmiany) | Data | Commit | Podpis właściciela |
|---|---|---|---|---|---|
| | | | | | |
