# ADR 0002 — Decyzje bramki M0 (B1–B11, D1–D9)

| | |
|---|---|
| **Status** | **ACCEPTED** (2026-11-11) |
| **Kto zdecydował** | Agent kodujący, na podstawie delegacji właściciela repozytorium udzielonej 2026-11-11 („sam podejmuj decyzje”). |
| **Czego to nie oznacza** | Nie odbył się niezależny przegląd AppSec ani przegląd przez drugą osobę. Pozostaje on wymagany przed bramką GO/NO-GO (M7) i przed jakimkolwiek użyciem na realnym materiale. Właściciel może każdą decyzję zmienić; rollback = nowy ADR. |
| **Rozstrzyga** | pytania z `docs/THREAT_MODEL.md` §6 i `docs/adr/0001-granice-komponentow.md` |
| **Odblokowuje** | T-101 (#4), T-102 (#5) |

Zasada ogólna przyjęta przy wyborach: **fail-closed i jawna luka pokrycia** zamiast cichego odczytu; zero zależności runtime; małe, odwracalne kroki.

## Model zagrożeń

| ID | Decyzja | Uzasadnienie |
|---|---|---|
| B1 | Aktywa, granice T1–T6 i aktorzy przyjęte. Złośliwy operator i administrator hosta analitycznego pozostają **poza zakresem** PoC. | Narzędzie działa z uprawnieniami operatora; nie da się przed nim bronić z poziomu procesu. |
| B2 | Zwykły plik z `st_nlink > 1` jest domyślnie **nieczytany**: wpis w manifeście ze statusem `SKIPPED_HARDLINK` i luka pokrycia. Jawna flaga `--allow-hardlinks` pozwala czytać; każdy taki dowód dostaje znacznik `hardlinked`, a raport lukę informacyjną. | Domyślnie bezpiecznie; flaga jest potrzebna, bo kopie z deduplikacją (np. `rsync --link-dest`) składają się niemal wyłącznie z hardlinków. |
| B3 | Obowiązkowy odczyt **względem deskryptora katalogu**: `os.open(..., dir_fd=, O_NOFOLLOW)`, typ wpisu sprawdzany przez `fstat` na otwartym deskryptorze (tylko zwykłe pliki i katalogi). Prywatna kopia robocza **nie** jest wymagana. Gwarancje deklarujemy dla Linuksa i macOS, testowane na obu; na platformie bez `dir_fd`/`O_NOFOLLOW` narzędzie odmawia pracy. | Operator z założenia dostarcza już kopię; druga kopia podwaja koszt i nie usuwa wyścigu przy kopiowaniu. |
| B4 | Skrót i analiza pochodzą z **jednego odczytu** tego samego deskryptora. Po analizie domyślnie ponowna weryfikacja (`fstat` + ponowny skrót); rozbieżność daje lukę `SOURCE_CHANGED_DURING_ANALYSIS` i wyklucza ocenę „brak wskaźników”. Wyłączenie tylko jawną flagą, odnotowaną w raporcie. | Manifest ma opisywać dokładnie te bajty, które widziały reguły. |
| B5 | Jeśli ścieżka podana przez operatora (`--files`, `--database`, `--logs`, `--baseline`) jest symlinkiem — **odmowa**, kod wyjścia 2, komunikat z prośbą o podanie ścieżki rzeczywistej. | Jedna prosta reguła dla wszystkich źródeł; operator łatwo poprawia wywołanie. |
| B6 | Limity domyślne: 200 000 plików, 2 GiB na plik (skrót), 20 GiB łącznie, treść analizowana do 4 MiB (bez zmian), ścieżka do 4096 bajtów, głębokość 64, czas całej analizy 30 min. SQL 20 MiB i log 30 MiB bez zmian do czasu parserów strumieniowych (T-301, T-401). Rozmiar sprawdzany **przed** skrótem. Po przekroczeniu: analiza **częściowa** trwa dalej, powstaje nazwana luka, a wynik nie może być „brak wskaźników”. Limity są konfigurowalne z CLI. | Częściowy wynik z jawną luką jest dla analityka cenniejszy niż przerwanie; obecny limit 20 000 plików jest za niski dla typowej instalacji z wtyczkami. |
| B7 | ReDoS w `wpincidentlens/cli.py:154` naprawiamy **teraz**, osobnym małym PR z testem regresyjnym z ograniczeniem czasu, przed T-301. | Potwierdzona podatność na wejściu kontrolowanym przez napastnika; poprawka jest tania i nie zależy od architektury. |
| B8 | Domyślnie w `report.json` i `report.html`: wartości parametrów query string zastąpione `[REDACTED]` (nazwy zostają), dane logowania w URL i rozpoznane wzorce sekretów redagowane, bezwzględne ścieżki hosta nigdy nie trafiają do raportu. Adresy IP i loginy **zostają** — są niezbędne do korelacji — z ostrzeżeniem o danych osobowych. Flaga `--pseudonymize` zastępuje IP i loginy stabilnym w obrębie sprawy pseudonimem. Politykę zatwierdził właściciel przez delegację. | Minimalizacja bez utraty wartości analitycznej; raport bez IP jest dla triage bezużyteczny. |
| B9 | `INCONCLUSIVE` wchodzi w **T-102** razem ze schematem `poc-1`, funkcją migracji z 0.1.0 i testem kompatybilności. Test `test_no_indicators_not_a_clean_bill` jest zmieniany w tym samym PR, z opisem w PR. | Zmiana oceny to zmiana kontraktu, nie refaktoryzacja. |
| B10 | T-101 może ruszyć przed pomiarem kontenera (T-601). Zakaz pracy na realnym materiale obowiązuje do bramki M1 **i** pomiaru kontenera. Dla materiału wysokiego ryzyka zalecana osobna VM. | Bezpieczny odczyt nie zależy od kontenera; kontener jest drugą warstwą. |
| B11 | Lista „Pozostałe ryzyka” przyjęta. | — |

## Architektura

| ID | Decyzja | Uzasadnienie |
|---|---|---|
| D1 | **Opcja B**: moduły wewnątrz `wpincidentlens/`. Układ `src/` nie jest planowany; ewentualna zmiana wymaga osobnego ADR. | Zachowuje CLI i testy; `src/` nie daje nic poza zgodnością z rysunkiem w specyfikacji. |
| D2 | Modele jako zamrożone `dataclasses` z jawną walidacją oraz opublikowany JSON Schema. `jsonschema` wyłącznie jako zależność testowa. **Bez Pydantic.** | Zero zależności runtime w silniku przetwarzającym nieufne dane; mniejsza powierzchnia łańcucha dostaw. |
| D3 | Raport HTML w stdlib: jedna funkcja renderująca, każda wartość przez jedno miejsce escapowania, CSP `default-src 'none'` bez skryptów. **Bez Jinja2.** | Szablon jest mały; ryzyko „zapomnianego escape” usuwa konstrukcja funkcji i testy dla każdego pola. |
| D4 | Zasada „dowody otwiera wyłącznie SecureIngest, wyniki pisze wyłącznie Reporter” jest **wiążąca**. Test oparty na AST uruchamiany w CI od chwili powstania `wpincidentlens/ingest.py`; `cli.py` jest na liście wyjątków do zakończenia migracji, a lista może się tylko skracać. | Granica bez testu nie przetrwa. |
| D5 | Podział C05 (odczyt w parserach, ocena w Rules) i przypisanie C04/C08/C11 do Rules przyjęte. | — |
| D6 | Kolejność: krok 0 (T-003) → krok 3 (ingest, T-101) → krok 2 (modele, T-102) → krok 1 (report) → 4 → 5 → 6. Krok 1 jako czyste przeniesienie może nastąpić w dowolnym momencie po kroku 0. | Najpierw zamykamy otwarte luki odczytu (Z-06–Z-09), potem kontrakty. |
| D7 | Raport 0.1.0 pozostaje zgodny (poza polami czasu) do wejścia `poc-1` w T-102. Potem narzędzie pisze tylko `poc-1`; zgodność wstecz zapewnia funkcja migrująca stare raporty i jej test. | Dwa równoległe formaty zapisu podwajają powierzchnię testów bez użytkowników 0.1.0. |
| D8 | Zasady ADR-001–ADR-010 pozostają w specyfikacji jako zasady produktu. Pliki `docs/adr/NNNN-*.md` mają własną, czterocyfrową numerację; odwołania zapisujemy jako „ADR 0001” (plik) i „ADR-001 (spec)”. | Brak kopiowania treści i brak kolizji numerów. |
| D9 | Izolacja parserów w osobnym procesie pozostaje **opcjonalna**; decyzja wraca przy bramce M6 razem z wynikami fuzzingu. | Bez danych z fuzzingu koszt jest nieuzasadniony. |

## Konsekwencje

- T-101 (#4) i T-102 (#5) są odblokowane w zakresie opisanym wyżej.
- Powstają nowe flagi CLI (`--allow-hardlinks`, `--pseudonymize`, limity); istniejące argumenty zachowują znaczenie. Wyjątek: symlink podany wprost przestaje być akceptowany (B5) — zmiana zachowania do opisania w PR T-101.
- Nowe zadania: poprawka ReDoS (B7) oraz Issues dla T-401, T-501, T-601.
