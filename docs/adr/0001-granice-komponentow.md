# ADR 0001 — Granice komponentów: CaseManager, SecureIngest, parsery, Rules, Reporter

| | |
|---|---|
| **Status** | **ACCEPTED** 2026-11-11 (opcja B) — decyzje D1–D9 w `docs/adr/0002-decyzje-bramki-m0.md`; bez niezależnego przeglądu AppSec |
| **Data** | 2026-11-11 |
| **Zadanie** | T-002 (#2); blokuje T-101 (#4) i T-102 (#5) |
| **Powiązane** | `docs/THREAT_MODEL.md`, `docs/REQUIREMENTS_TRACEABILITY.md`, specyfikacja Senior PoC §3.2 i §12 |

Numeracja `0001` dotyczy plików w `docs/adr/`. Katalog decyzji ADR-001–ADR-010 ze specyfikacji Senior PoC §16 to osobna lista zasad produktu; ich przeniesienie do plików wymaga decyzji (pytanie D8).

## Kontekst

Cały PoC to jeden moduł `wptrace/cli.py` (386 linii):

| Funkcja | Linie | Co łączy |
|---|---|---|
| `digest_file` | 24-29 | odczyt pliku |
| `finding` | 32-36 | model znaleziska (słownik) |
| `scan_files` | 39-107 | enumeracja, odczyt, skrót, baseline, reguły plików |
| `iter_insert_rows` | 110-190 | parser SQL |
| `scan_database` | 193-250 | odczyt, parser, semantyka WordPressa, reguły DB |
| `scan_logs` | 252-285 | enumeracja, odczyt, parser, reguła HTTP |
| `compose_report` | 288-337 | orkiestracja, korelacja, oś czasu, assessment, kształt raportu |
| `write_html` | 340-352 | render HTML |
| `main` | 355-383 | CLI, walidacja ścieżek, odczyt baseline, zapis wyników |

Skutki dla bezpieczeństwa:

- Materiał dowodowy jest otwierany w pięciu niezależnych miejscach (`:26`, `:92`, `:200`, `:267`, `:374`), każde z inną polityką linków i limitów. Nie ma jednego punktu, w którym da się wymusić i przetestować zasady odczytu (THREAT_MODEL Z-06–Z-09).
- Reguły są wpisane w pętle odczytu (`:79-101`, `:236-246`, `:276-280`), więc nie istnieje warstwa obserwacji, do której znalezisko mogłoby się odwołać.
- Redakcja i escapowanie zależą od miejsca użycia, a nie od modelu danych.

Ograniczenia: `python -m wptrace` i jego argumenty muszą działać bez zmian; testy importują `main`, `iter_insert_rows`, `compose_report` i `write_html` z `wptrace.cli` (`tests/test_cli.py:3`, `:46`); raport ma `schema_version` 0.1.0; silnik nie ma zależności runtime.

## Rozważane opcje

| Opcja | Opis | Zalety | Wady |
|---|---|---|---|
| A | Pozostawić monolit i utwardzać funkcje w miejscu | najmniejszy diff | pięć ścieżek odczytu zostaje; granic nie da się wymusić testem |
| B | Moduły wewnątrz pakietu `wptrace/` z jednokierunkowymi zależnościami, wydzielane po jednym na PR | małe, odwracalne kroki; CLI i testy zachowane; granice sprawdzalne testem importów | okres przejściowy z kodem w dwóch miejscach; reeksporty w `cli.py` |
| C | Od razu docelowe drzewo ze specyfikacji §12 (`src/wptrace/`, `adapters/`, `analyzers/`, Pydantic, Jinja2) | zgodność ze specyfikacją | faktyczny rewrite w jednym PR; nowe zależności przed threat model; sprzeczne z `AGENTS.md` |
| D | Parsery w osobnych procesach roboczych z limitami | najsilniejsza izolacja błędów parsera | złożoność i koszt zbyt wczesne; wymaga stabilnych kontraktów danych |

## Decyzja proponowana

**Opcja B**, z nazwami zbieżnymi z opcją C tam, gdzie nic to nie kosztuje, i bez zamykania drogi do opcji D (parsery jako czyste funkcje dają się później przenieść do procesu roboczego).

### Granice

| Komponent | Spec | Odpowiada za | Wejście → wyjście | Nie wolno |
|---|---|---|---|---|
| CaseManager | C01 | walidację argumentów, `case_id`, ścieżek wejścia/wyjścia, limitów | argumenty CLI → `CaseContext` | czytać treści dowodów |
| SecureIngest | C02 | **jedyne** miejsce otwierające materiał dowodowy: enumeracja, typy wpisów, limity, skrót, manifest | `CaseContext` → `Evidence[]`, strumienie bajtów, `Coverage[]` | interpretować treści; pisać gdziekolwiek |
| Parsery | C03, C05 (odczyt treści), C06, C07, C09 | zamianę bajtów na fakty | strumień + `Evidence` → `Observation[]`, `Coverage[]` | otwierać ścieżek, sięgać do sieci, oceniać wagę |
| Rules | C04, C08, C10, C11 | interpretację faktów, korelację, assessment | `Observation[]` + baseline → `Finding[]`, `Assessment` | wykonywać I/O; czytać surowe bajty |
| Reporter | C12 | **jedyne** miejsce piszące do katalogu wyników; redakcja i escapowanie | model wyniku → JSON/HTML | czytać dowody; zmieniać treść ustaleń |
| Modele | §4 | wspólne kontrakty danych (T-102) | — | zawierać logikę I/O |

Zależności wyłącznie w jedną stronę: `cli → case → ingest → parsers → rules → report`; wszystkie warstwy mogą importować modele, modele nie importują niczego z pakietu. Granice mają być sprawdzane testem (lista dozwolonych importów; `open`/`os`/`pathlib` do odczytu dowodów tylko w ingest).

## Ścieżka migracji

Każdy krok to osobny PR; po każdym `python -m wptrace`, sześć istniejących testów i raport 0.1.0 dla `fixtures/` pozostają bez zmian (poza `analyzed_at_utc`). `wptrace/cli.py` reeksportuje przeniesione nazwy do czasu migracji testów. Rollback każdego kroku = cofnięcie jednego PR.

| Krok | Zakres | Zadanie | Warunek wstępny |
|---|---|---|---|
| 0 | Testy charakteryzujące: zamrożony raport dla `fixtures/`, testy negatywne | T-003 (#3) | — |
| 1 | `wptrace/report.py`: przeniesienie `write_html` i zapisu JSON bez zmiany zachowania | T-102 (#5) | krok 0 |
| 2 | `wptrace/models.py`: typy `Evidence`, `Observation`, `Finding`, `Coverage`; adapter do raportu 0.1.0 | T-102 (#5) | bramka M0 |
| 3 | `wptrace/ingest.py`: enumeracja i skrót dla `--files`, potem ten sam odczyt dla `--database`, `--logs`, `--baseline` | T-101 (#4) | bramka M0 |
| 4 | `wptrace/parsers/`: `iter_insert_rows`, parser logów, odczyt treści plików jako czyste funkcje | T-201 (#6), T-301 (#7), T-401 | krok 3 |
| 5 | `wptrace/rules/`: reguły wyjęte z pętli odczytu, korelacja, assessment | T-201, T-301, T-501 | kroki 2 i 4 |
| 6 | `wptrace/case.py`; `cli.py` zostaje cienką warstwą; ewentualne podkomendy z zachowaniem płaskiego wywołania | T-101 (#4) | krok 3 |

Zmiana schematu raportu (np. `INCONCLUSIVE`, identyfikatory) nie jest częścią przenoszenia kodu — wymaga osobnego PR z wersją, migracją i testem kompatybilności.

## Konsekwencje

| Pozytywne | Negatywne |
|---|---|
| jeden punkt egzekwowania zasad odczytu, testowalny osobno | więcej plików i reeksporty w okresie przejściowym |
| parsery i reguły testowalne bez systemu plików | podział C05 na „odczyt” i „reguły” wymaga dyscypliny w przeglądach |
| redakcja i escapowanie w jednym miejscu | do kroku 3 obecne luki odczytu pozostają otwarte |
| brak nowych zależności wymuszonych przez refaktoryzację | odstępstwo od drzewa `src/` ze specyfikacji §12 do czasu decyzji D1 |

## Ryzyka

| Ryzyko | Ograniczenie |
|---|---|
| Niezamierzona zmiana zachowania przy przenoszeniu kodu | krok 0 przed jakimkolwiek przeniesieniem; PR „tylko przeniesienie” bez zmian logiki |
| Granice istnieją tylko na papierze | test importów w CI od kroku 3 |
| Stary i nowy odczyt działają równolegle | krok 3 kończy się dopiero po usunięciu bezpośrednich otwarć z `cli.py` |
| Kontrakty danych zmieniane w trakcie migracji | modele (krok 2) zatwierdzone przed krokami 4–5 |
| Przedwczesny wybór bibliotek (Pydantic, Jinja2) | decyzja D2/D3 przed T-102; do tego czasu stdlib |

## Bramka przeglądu człowieka

Pytania rozstrzygnięte w `docs/adr/0002-decyzje-bramki-m0.md`:

| ID | Pytanie / decyzja |
|---|---|
| D1 | Czy przyjąć opcję B (moduły w `wptrace/`), czy docelowy układ `src/wptrace/` ze specyfikacji §12 ma obowiązywać od razu? |
| D2 | Modele: Pydantic 2 (specyfikacja §3.3) czy `dataclasses` + JSON Schema (zero zależności runtime)? |
| D3 | Raport: Jinja2 z autoescape czy stdlib z jedną funkcją renderującą? |
| D4 | Czy zasada „dowody otwiera wyłącznie SecureIngest, wyniki pisze wyłącznie Reporter” jest wiążąca i ma być egzekwowana testem w CI? |
| D5 | Czy podział C05 (odczyt w parserach, ocena w Rules) oraz przypisanie C04/C08/C11 do Rules są akceptowalne? |
| D6 | Kolejność kroków 1–6 i to, czy krok 1 (przeniesienie Reportera) może nastąpić przed bramką M0. |
| D7 | Jak długo raport 0.1.0 ma być utrzymywany bajtowo zgodny i kiedy wchodzi schemat `poc-1`? |
| D8 | Numeracja ADR: czy zasady ADR-001–ADR-010 ze specyfikacji §16 stają się plikami `docs/adr/` i jak je pogodzić z `0001`? |
| D9 | Czy izolacja parserów w osobnym procesie (opcja D) ma być wymaganiem przed bramką M6, czy pozostaje opcjonalna? |
