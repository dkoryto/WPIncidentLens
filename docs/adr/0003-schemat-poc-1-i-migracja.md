# ADR 0003 — Schemat raportu `poc-1`, stan `INCONCLUSIVE` i migracja z 0.1.0

| | |
|---|---|
| **Status** | **ACCEPTED** (2026-11-11) |
| **Kto zdecydował** | Agent kodujący, na podstawie delegacji właściciela repozytorium udzielonej 2026-11-11 („sam podejmuj decyzje”), tak jak ADR 0002. |
| **Czego to nie oznacza** | Nie odbył się niezależny przegląd AppSec ani przegląd przez drugą osobę. Pozostaje on wymagany przed bramką GO/NO-GO (M7) i przed jakimkolwiek użyciem na realnym materiale. Właściciel może każdą decyzję zmienić; rollback = nowy ADR. |
| **Wdraża** | ADR 0002: B9, D2, D5, D7; specyfikacja `docs/WPTrace_Specyfikacja_Senior_PoC_2026-11-09.md` §4, §9, §11 |
| **Zadanie** | T-102 (#5) |
| **Kod** | `wptrace/models.py`, `wptrace/migrate.py`, `wptrace/cli.py`, `docs/schema/report-poc-1.schema.json` |

## Kontekst

Raport 0.1.0 miał dwa stany (`INDICATORS_FOUND`, `NO_INDICATORS_IN_ANALYZED_SCOPE`), ustalenia bez oddzielonych faktów i luki pokrycia wyłącznie jako teksty. Brak bazy i logów dawał „brak wskaźników”, a pominięty plik nie istniał w manifeście (zagrożenie Z-16). T-102 wprowadza kontrakty danych, które oddzielają fakt od oceny i zakres zbadany od niezbadanego.

## 1. Kształt raportu

Narzędzie pisze wyłącznie `schema_version: "poc-1"`. Pola najwyższego poziomu, w kolejności zapisu:

| Pole | Znaczenie |
|---|---|
| `schema_version`, `tool`, `tool_version`, `case_id` | identyfikacja raportu |
| `analyzed_at_utc`, `analyzed_at_time_source` | czas zakończenia analizy w UTC; źródło zawsze `tool_clock` |
| `assessment` | etykieta triage (§6) |
| `scope_complete` | czy zakres analizy był pełny (§5); osobne pole, żeby ustalenia nie ukryły niepełnego zakresu |
| `disclaimer` | stałe zastrzeżenie |
| `findings[]` | interpretacje: `id`, `rule_id`, `category`, `severity`, `confidence`, `reason`, `observations[]` |
| `observations[]` | fakty: `id`, `evidence_id`, `kind`, `location`, `attributes`, `timestamp_raw`, `timestamp_utc`, `time_source` |
| `evidence[]` | każdy wpis materiału, także pominięty: `id`, `origin_kind`, `logical_path`, `read_status`, `read_reason`, `sha256`, `size_bytes`, `mtime_ns`, `hardlinked` |
| `coverage{files,database,logs,baseline}` | per źródło: `status`, `entries` (liczniki wpisów według statusu odczytu), `reasons[]` |
| `coverage_gaps[]` | wszystkie ograniczenia analizy: powody z `coverage` oraz uwagi dotyczące całej sesji |
| `timeline[]` | `time_utc`, `time_source`, `timestamp_basis`, `event`, `source`, `confidence`, `evidence_id`, `observation_id` |
| `migrated_from` | tylko w raporcie przeniesionym; wartość `0.1.0` |

Zasady:

- **Observation to fakt z parsera** (D5), np. `PHP_FILE_IN_UPLOADS` albo `HTTP_REQUEST_FOR_PHP_IN_UPLOADS`; nie niesie wagi, pewności ani wyjaśnienia. **Finding to interpretacja** wskazująca co najmniej jedną obserwację. Ustalenie korelacyjne (`CORRELATED_UPLOAD_REQUEST`) wskazuje dwie istniejące obserwacje: pliku i wiersza logu.
- `severity` (`low`, `medium`, `high`, `critical`) i `confidence` (`low`, `medium`, `high`) to dwa osobne wyliczenia.
- `Evidence.read_status` pochodzi z `ingest.ReadStatus`. Wpis pominięty (symlink, hardlink, plik specjalny, limit, błąd) jest dowodem bez skrótu; wpis `CHANGED` zachowuje skrót bajtów, które widziały reguły. To zamyka ograniczenie 0.1.0, w którym pominięcia istniały tylko jako tekst luki.
- `logical_path` ma postać `<źródło>/<ścieżka względna>`; model odrzuca ścieżkę, która nie zaczyna się od nazwy źródła, więc ścieżka hosta nie trafi do `evidence` (B8). Wpis `<źródło>/.` opisuje samo źródło, np. nieudane otwarcie.
- `location` zawiera tylko pola znane parserowi: `path`, `line` (wiersz logu), `table`, `key`, `row` (numer kolejny sparsowanego wiersza `INSERT`).
- Czas jest zapisywany w UTC w ISO 8601 z `Z` albo `+00:00`, zawsze z nazwą źródła: `log`, `mtime`, `tool_clock`. Czas logu, którego nie da się znormalizować, zostaje w `timestamp_raw`, a `timestamp_utc` jest jawnie `null`.
- `counts` z 0.1.0 znika: jest wyliczalne z `findings`.

Zmiany w regułach i parserach ograniczono do wyprodukowania obserwacji. Jedyna zmiana treści: ustalenie `UNRECOGNIZED_ADMIN` podaje rzeczywistą tabelę i klucz wiersza z rolą (np. `wp_usermeta:wp_capabilities`) zamiast stałego tekstu `*_users / *_usermeta`.

## 2. Identyfikatory

`<prefiks>_<32 znaki szesnastkowe>`: pierwsze 128 bitów SHA-256 z kanonicznego JSON pól tożsamości (klucze posortowane, bez odstępów, wyłącznie ASCII).

| Obiekt | Prefiks | Pola tożsamości |
|---|---|---|
| Evidence | `ev_` | `origin_kind`, `logical_path`, `sha256`; dla wpisu bez skrótu dodatkowo `read_status` i `read_reason` |
| Observation | `obs_` | `evidence_id`, `kind`, `location`, `attributes`, `timestamp_raw` |
| Finding | `fnd_` | `rule_id`, posortowane `observations` |

Konsekwencje: identyfikator nie zależy od kolejności przejścia, `PYTHONHASHSEED`, ścieżki hosta, `mtime` ani czasu analizy; dwa uruchomienia na tym samym materiale dają te same identyfikatory. Zmiana `severity` lub `confidence` reguły nie zmienia identyfikatora ustalenia. Dowód ze statusem `READ` i ten sam dowód ze statusem `CHANGED` mają ten sam identyfikator. `validate_report` przelicza każdy identyfikator i odrzuca raport, w którym nie wynika on z treści. Kolizja dwóch różnych tożsamości kończy się błędem walidacji (powtórzony identyfikator), nie cichym scaleniem; wpisy o identycznej tożsamości są jednym obiektem.

## 3. Porządek zapisu

`evidence` według (`logical_path`, `id`); `observations` według `id`; `findings` według (waga malejąco, `rule_id`, `id`); `timeline` według (`time_utc`, `source`, `event`, `evidence_id`, `observation_id`); `coverage_gaps` i `reasons` alfabetycznie; `coverage` w stałej kolejności `files`, `database`, `logs`, `baseline`.

## 4. Walidacja: model i schemat

- `wptrace/models.py`: zamrożone `dataclasses` z jawną walidacją (D2), bez zależności. `validate_report(dict)` sprawdza typy, wyliczenia, nieznane i brakujące pola, unikalność identyfikatorów, istnienie wskazywanych dowodów i obserwacji, zgodność identyfikatorów z treścią, spójność liczników ze statusem pokrycia oraz zgodność `assessment` i `scope_complete` z regułą. Błąd to `ModelError` z nazwą pola.
- **Liczniki a dowody (T-006, #18).** W raporcie bez `migrated_from` liczniki `coverage[źródło].entries` muszą mieć pokrycie w `evidence[]` tego źródła: (1) dowodów o danym `read_status` jest najwyżej tyle, ile wynosi licznik tego statusu; (2) licznik niezerowy ma co najmniej jeden dowód, przy czym `READ` i `CHANGED` są liczone łącznie, bo ten sam plik ma w obu statusach jeden identyfikator (§2). Raport z `coverage.database = ANALYZED` i `READ: 1`, ale bez dowodu bazy, jest więc odrzucany, tak samo jak dowód źródła `NOT_PROVIDED` albo dowód pominięty przy liczniku zerowym. Równości nie wymagamy celowo: liczniki liczą wpisy rejestru odczytu, a `evidence[]` scala wpisy o identycznej tożsamości. Po uczynieniu nazw zastępczych różnowartościowymi (`ingest._printable`) taki przypadek nie powstaje w zwykłym przebiegu — w każdym raporcie pisanym w testach liczniki są równe liczbie dowodów — ale pozostaje możliwy, gdy katalog zmieniany w trakcie listowania zwróci tę samą nazwę dwukrotnie albo gdy jedna sesja odczyta to samo źródło dwa razy; odrzucenie własnego raportu po zakończonej analizie byłoby wtedy gorsze niż słabsza reguła. Skutek uboczny: usunięcie z ręcznie zmienionego raportu jednego z kilku dowodów o tym samym statusie nie jest wykrywane. Raport przeniesiony z 0.1.0 nie podlega regule (stary manifest nie zawierał wpisów pominiętych).
- **Tekst zapisywalny w UTF-8 (T-006, #18).** Każde pole tekstowe, także nazwa i wartość atrybutu obserwacji, jest odrzucane, gdy zawiera samotny surogat (U+D800–U+DFFF): „poprawny” raport musi dać się zapisać jako JSON w UTF-8. Obie reguły zawężają zbiór akceptowanych dokumentów bez zmiany `schema_version`: raport, który je łamie, był wewnętrznie sprzeczny albo niezapisywalny, a narzędzie takiego nie pisało.
- `docs/schema/report-poc-1.schema.json` (draft 2020-12) opisuje kształt. Nie wyraża referencji ani reguły oceny — to ograniczenie JSON Schema, opisane w samym pliku. `jsonschema` jest zależnością wyłącznie testową (`pyproject.toml`, extras `dev` i `test`); test pilnuje, by wyliczenia w pliku i w modelu były identyczne.

## 5. Pokrycie i pełność zakresu

Status źródła wynika z faktów, nie z samej obecności tekstu luki:

| Status | Kiedy |
|---|---|
| `NOT_PROVIDED` | źródła nie podano |
| `FAILED` | źródło podano, ale nie przeczytano z niego żadnych bajtów albo parser nie przeanalizował niczego (zrzut SQL ponad limit, brak obsługiwanych `INSERT`, zrzut bez wierszy tabel `*_users`, `*_usermeta`, `*_options`, log w obcym formacie, log bez wierszy, pusty katalog) |
| `PARTIAL` | którykolwiek wpis ma status inny niż `READ` (pominięty, błąd, `CHANGED`), plik kodu przekracza limit skanowania treści, log przekracza limit lub ma niesparsowane wiersze, przekroczono 100 000 wierszy `INSERT`, rola administratora nie ma odczytanego wiersza użytkownika, parser SQL pominął instrukcję (niedomkniętą, w nieobsługiwanej składni) albo wiersz tabeli użytkowników lub opcji o nieoczekiwanej liczbie pól, źródło podmieniono albo ponowną weryfikację przerwał limit czasu |
| `ANALYZED` | w pozostałych przypadkach; wymaga co najmniej jednego wpisu `READ` i żadnego innego |

Status inny niż `ANALYZED` ma zawsze co najmniej jeden powód. Dotychczasowe teksty `coverage_gaps` zostały zachowane jako powody.

Teksty, które **nie** obniżają statusu (informacja o zakresie): stałe ograniczenie parsera SQL, brak listy zaufanych administratorów, baseline bez skrótów plików, nazwa spoza UTF-8 zapisana w postaci zastępczej, nazwa z dosłowną sekwencją `\xNN` zapisana z podwojonymi ukośnikami wstecznymi, czas logu nie do znormalizowania, duży plik bez reguł treści (np. obraz), liczba plików odczytanych z `--allow-hardlinks`, `--no-reverify`.

`scope_complete` jest prawdą, gdy `files`, `database` i `logs` mają status `ANALYZED`, a `baseline` — `ANALYZED` albo `NOT_PROVIDED`.

## 6. Reguła `assessment`

Jedna czysta funkcja `models.assess(findings, coverage)`, przetestowana tabelą przypadków:

1. istnieje ustalenie o wadze `high` lub `critical` **i** pewności `high` → `STRONG_INDICATORS`, także przy niepełnym zakresie;
2. istnieje jakiekolwiek inne ustalenie → `SUSPICIOUS`;
3. brak ustaleń i `scope_complete` → `NO_INDICATORS_IN_ANALYZED_SCOPE`;
4. brak ustaleń i zakres niepełny → `INCONCLUSIVE`.

To odwzorowanie pseudoreguł §9.2 specyfikacji (reguły 1 i 5 specyfikacji to tutaj punkt 4). Brak bazy **lub** logów, źródło `PARTIAL`/`FAILED`, jakikolwiek wpis `CHANGED` i każdy przekroczony limit wykluczają „brak wskaźników”. Niepełny zakres przy istniejących ustaleniach komunikuje pole `scope_complete` i tabela pokrycia.

**Wybór ostrożniejszy.** Specyfikacja wymaga dla `STRONG_INDICATORS` „jawnej, przetestowanej matrycy” (§6.3) i zabrania wywodzenia go z samej obecności `eval` lub PHP w nietypowym katalogu, ale matrycy nie podaje. Przyjęto próg na pojedynczym ustaleniu (waga co najmniej `high` i pewność `high`); liczba ustaleń ani ich korelacja niczego nie sumują. Wszystkie obecne reguły PoC o wadze `high` mają pewność najwyżej `medium`, więc **dzisiejsze reguły nie dają `STRONG_INDICATORS`** — syntetyczny incydent z `fixtures/` to `SUSPICIOUS`. Stan stanie się osiągalny, gdy RulesEngine zdefiniuje matrycę i reguły o pewności `high`.

## 7. Kody wyjścia

Specyfikacja §11: `0` = analiza w całości (ustalenia możliwe), `2` = błąd wejścia, `3` = analiza częściowa, `4` = nieprzetworzony materiał wymagany, `5` = błąd narzędzia; znalezisko nie zmienia kodu. Specyfikacja nie przypisuje kodu do etykiety `assessment`, tylko do pełności analizy. Wdrożenie:

| Kod | Warunek |
|---|---|
| `0` | `scope_complete` jest prawdą |
| `4` | co najmniej jedno **podane** źródło ma status `FAILED` |
| `3` | każda inna niepełność (źródło `PARTIAL` albo niepodana baza lub logi) |
| `2` | błąd wywołania (bez zmian, zgłasza `argparse`) |

Skutek: `INCONCLUSIVE` nigdy nie kończy się kodem `0`; `SUSPICIOUS` i `STRONG_INDICATORS` dają `0` przy pełnym zakresie i `3`/`4` przy niepełnym. Kod `5` nie jest wdrożony: nieobsłużony wyjątek kończy proces kodem `1` Pythona (otwarte).

## 8. Migracja 0.1.0 → `poc-1`

`wptrace.migrate.migrate_0_1_0(report: dict) -> dict` jest czystą funkcją: nie czyta i nie zapisuje plików, nie zmienia wejścia, a wynik przechodzi `validate_report` i JSON Schema. Czego nie da się odtworzyć, jest oznaczone jawnie.

| 0.1.0 | `poc-1` |
|---|---|
| `schema_version: "0.1.0"` | `schema_version: "poc-1"`, `migrated_from: "0.1.0"` |
| `assessment: INDICATORS_FOUND` | `SUSPICIOUS` (także gdy stare ustalenie miało wagę i pewność `high`) |
| `assessment: NO_INDICATORS_IN_ANALYZED_SCOPE` | `INCONCLUSIVE` — stary raport nie niósł informacji o pokryciu |
| `evidence_manifest[]` (`source`, `sha256`, `size`, `mtime_ns`) | `evidence[]` z tym samym skrótem, `read_status: UNKNOWN_LEGACY` |
| `findings[]` (`rule`, `severity`, `confidence`, `explanation`) | `findings[]` (`rule_id`, `severity`, `confidence`, `reason`), `category` z `source_type` |
| `findings[].source`, `metadata` | jedna obserwacja syntetyczna `LEGACY_FINDING` na ustalenie: `location` odtworzone z `source` (`plik`, `log:wiersz`, `tabela:klucz`), `attributes` = `metadata` + `legacy_rule` + `legacy_source_type` |
| ustalenie o wpisie spoza manifestu (np. nieprzeczytany plik) | dodatkowy dowód bez skrótu, `read_status: UNKNOWN_LEGACY` |
| `coverage_gaps[]` | `coverage_gaps[]` bez zmian + nota o migracji |
| brak | `coverage`: wszystkie źródła `UNKNOWN_LEGACY`, `entries: null` |
| `timeline[]` | te same zdarzenia + `time_source` (`mtime` dla `SUSPICIOUS_FILE_MTIME`, inaczej `log`) + `evidence_id`; zdarzenie bez czasu ze strefą jest pomijane z notą |
| `analyzed_at_utc` | przeliczone na UTC; czas bez strefy → `null` z notą |
| `counts` | pomijane (wyliczalne) |

`UNKNOWN_LEGACY` jest dozwolone wyłącznie w raporcie z polem `migrated_from`; raport pisany przez narzędzie nigdy go nie zawiera (pilnuje tego model i schemat). Wejście niespójne (np. `INDICATORS_FOUND` bez ustaleń, nieznana waga, ścieżka manifestu spoza znanych źródeł) jest odrzucane błędem `MigrationError`, bez zgadywania.

Wpisy powtórzone (T-006, #18): dwa wpisy `evidence_manifest` o tej samej ścieżce i różnym `sha256` (albo rozmiarze lub `mtime_ns`) to `MigrationError` — nie wiadomo, który plik widziały reguły; wpis powtórzony bez różnic jest jednym dowodem. Dwa stare ustalenia o tej samej regule, źródle i metadanych mają w `poc-1` ten sam identyfikator: identyczne są scalane z notą, a różniące się wagą, pewnością lub wyjaśnieniem dają jedno ustalenie z najwyższą wagą i najwyższą pewnością (wybieranymi niezależnie), pierwszym wyjaśnieniem i osobną notą o konflikcie w `coverage_gaps`. Wybrano scalenie zamiast odmowy, bo powtórzony wpis nie czyni reszty starego raportu nieczytelną, a wynik nie zaniża żadnej z ocen; ocena całości i tak jest po migracji najwyżej `SUSPICIOUS`.

Testy kompatybilności: `tests/test_migrate.py` na `tests/data/report-0.1.0.json` (dawny `demo/report.json`, dane syntetyczne) oraz na raportach 0.1.0 budowanych w teście.

Migracja nie ma wejścia w CLI. Wywołanie z kodu: wczytać stary raport bezpiecznym odczytem (`ingest.Session.read_file`), sparsować JSON, przekazać słownik do `migrate_0_1_0`. Wejście CLI wymaga decyzji o miejscu zapisu wyniku i należy do zadania wydzielającego Reporter.

## 9. Pola specyfikacji odroczone

Pominięte, bo PoC nie ma skąd ich wziąć; nie wstawiono atrap.

| Obiekt | Pola odroczone | Powód |
|---|---|---|
| Case (§4.1) | `created_at_utc`, `operator_id`, `analyst_notes`, `ruleset_id`, `ruleset_sha256`, `analysis_started_at_utc`, `mode`, `source_authorization_confirmed` | brak CaseManagera i `case.json` (pozostała część #4) |
| Evidence (§4.2) | `intake_order`, `mtime_precision`, `acquired_at_utc`, `source_confidence`, `acquisition_note` | narzędzie nie zna okoliczności pozyskania; `mtime_ns` jest surową wartością w nanosekundach |
| Observation (§4.3) | `source_span` (offset i długość w bajtach), `raw_value_sha256`, `normalized_value`, `detector_id`, `parse_confidence`, `clock_uncertainty_seconds` | parsery PoC nie śledzą offsetów ani niepewności zegara (#6, #7) |
| Finding (§4.4) | `rule_version`, `title`, `alternative_explanations[]`, `recommendation`, `status` | brak wersjonowanego zestawu reguł (RulesEngine, #14) |
| Coverage (§4.5) | liczba wierszy SQL i logu, liczba nieznanych instrukcji, procent | parsery strumieniowe z licznikami to #7 (SQL) i #13 (logi) |

Poza zakresem T-102 pozostają także: redakcja i pseudonimizacja (B8, #14) — `attributes.uri` nadal zawiera query string z logu; CSP i przebudowa HTML (#14); identyfikatory reguł `WP-FILE-00x` ze specyfikacji.

## 10. Polityka wersjonowania

- `poc-1` jest zamknięty: każda zmiana, po której poprawny dotąd raport przestaje przechodzić `validate_report` albo zmienia znaczenie istniejącego pola, wymaga `poc-2`. Dotyczy to usunięcia lub zmiany typu pola, dodania pola wymaganego, zmiany reguły identyfikatorów, zmiany reguły `assessment` lub `scope_complete`, zmiany znaczenia wartości wyliczenia.
- Każda nowa wersja ma nowy plik `docs/schema/report-<wersja>.schema.json`, funkcję migrującą z wersji poprzedniej w `wptrace/migrate.py`, test kompatybilności na zachowanym raporcie poprzedniej wersji i ADR. Narzędzie zapisuje zawsze tylko najnowszą wersję (D7).
- Model i schemat odrzucają nieznane pola, więc także dodanie pola opcjonalnego wymaga jednoczesnej zmiany modelu, schematu i testów; w fazie PoC nie utrzymujemy zgodności „w przód”.
- Nowy `kind` obserwacji, nowe `rule_id` i nowy tekst powodu nie zmieniają wersji schematu: to wartości, nie kształt.

## Decyzje przyjęte w wariancie mniej ostrożnym

Przyjęte przez agenta prowadzącego z delegacji właściciela (2026-11-11); każdą można odwrócić nowym ADR.

1. **Brak baseline nie czyni zakresu niepełnym.** Zlecenie i specyfikacja §9.1 wymieniają jako źródła krytyczne pliki, bazę i logi. Wariant ostrożniejszy (baseline wymagany do „braku wskaźników”) sprawiłby, że bez zaufanej migawki wynikiem byłoby zawsze `INCONCLUSIVE`. Brak baseline jest raportowany jako powód w `coverage.baseline` i w `coverage_gaps`.
2. **`--no-reverify` nie obniża oceny.** Flaga jest jawnym wyborem operatora, odnotowanym jako luka; zmiana wykryta w trakcie odczytu nadal daje `CHANGED`. Wariant ostrożniejszy: traktować wyłączoną weryfikację jak niepełny zakres.
3. **Kod wyjścia `3` przy niepodanej bazie lub logach.** Przyjęto, że „analiza w całości” oznacza pełny zakres wspierany, nie tylko podany materiał. Automatyzacja uruchamiająca narzędzie na samych plikach dostanie `3`.
4. **`STRONG_INDICATORS` jest dziś nieosiągalny** (§6).
5. **Brak listy zaufanych administratorów nie obniża pokrycia bazy.** Specyfikacja (N3) traktuje administratora bez listy porównawczej jako inwentaryzację; raport odnotowuje to jako powód. Natomiast rola administratora bez odczytanego wiersza w tabeli użytkowników obniża pokrycie bazy do `PARTIAL`, bo loginu nie da się ustalić.
6. **128-bitowe identyfikatory.** Skrócenie SHA-256 zmniejsza raport; kolizja wymaga około 2^64 prób i kończy się błędem walidacji.

## Konsekwencje

- `tests/test_cli.py::test_no_indicators_not_a_clean_bill` oczekuje teraz `INCONCLUSIVE` (B9); pozostałe zmiany asercji dotyczą wyłącznie nazw pól nowego kształtu.
- `wptrace/ingest.py` dostał atrybut `Session.integrity_notes` (źródło i tekst każdej rozbieżności z ponownej weryfikacji). Logika odczytu się nie zmieniła; zmiana pozwala przypisać rozbieżność do źródła bez parsowania tekstu.
- `compose_report` nie przyjmuje już baseline, którego nie wczytano w tej samej sesji (`load_baseline`): dowodem braku pliku jest wpis baseline w rejestrze sesji.
- Lista wyjątków strażnika D4 nie wydłużyła się: `models.py` i `migrate.py` nie dotykają systemu plików.
- Rollback: przywrócenie zapisu 0.1.0 wymaga cofnięcia zmian w `wptrace/cli.py` i testach; raporty `poc-1` nie mają migracji wstecz.
