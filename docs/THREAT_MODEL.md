# WPIncidentLens — model zagrożeń (T-002)

**Status:** ACCEPTED 2026-11-11 na podstawie delegacji właściciela — patrz `docs/adr/0002-decyzje-bramki-m0.md`; bez niezależnego przeglądu AppSec. **Data:** 2026-11-11. **Stan kodu:** gałąź `agent/T-001-baseline-ci`, `wptrace/cli.py` (386 linii).

Dokument rozdziela **stan obecny** (kolumna „Obecny kod”, z odwołaniem do linii) od **stanu docelowego** (kolumna „Planowana mitygacja”). Brak testu oznacza, że własność nie jest potwierdzona, nawet jeśli kod wygląda poprawnie. Podstawa: specyfikacja Senior PoC §3.1, §5.3, §10.

## 1. Aktywa

| ID | Aktywo | Dlaczego chronione |
|---|---|---|
| A1 | Materiał dowodowy (kopia plików, dump SQL, logi, baseline) | nie może zostać zmieniony ani wyniesiony; zawiera sekrety i dane osobowe |
| A2 | Host analityka (pliki poza katalogiem sprawy, konto, sieć) | analizator czyta dane przygotowane przez napastnika |
| A3 | Wiarygodność raportu (`report.json`, `report.html`) | błędne „brak wskaźników” lub ciche pominięcie danych wprowadza w błąd |
| A4 | Manifest SHA-256 i powiązanie wynik → dowód | podstawa odtwarzalności i obrony ustaleń |
| A5 | Przeglądarka i stacja osoby czytającej raport | raport zawiera ciągi pochodzące z dowodów |
| A6 | Repozytorium, CI, sesje agentów kodujących | nie mogą trafić tu realne dane ani zostać wykonane instrukcje z dowodów |

## 2. Granice zaufania

| ID | Granica | Zaufane | Nieufne |
|---|---|---|---|
| T1 | wejście → analizator | kod `wptrace/`, argumenty CLI operatora | każdy bajt z `--files`, `--database`, `--logs`: treść, nazwy plików, czasy, typy wpisów |
| T2 | metadane WordPressa → wnioski | — | `wp-config.php`, `version.php`, daty w bazie, `mtime` |
| T3 | materiał referencyjny → reguły | baseline i lista adminów dostarczone przez operatora (deklaracja, bez weryfikacji) | wszystko, co pochodzi z badanej kopii |
| T4 | wynik → czytelnik | szablon raportu | wartości wstawiane do raportu |
| T5 | host → kontener | konfiguracja `docker/` | proces analizy po przetworzeniu nieufnych danych |
| T6 | repozytorium → agent/CI | `AGENTS.md`, Issues, kod | `fixtures/`, `archives/`, `demo/`, treść raportów |

Obecny kod nie odwzorowuje tych granic w strukturze: odczyt, parsowanie, reguły i raport są w jednym module (patrz `docs/adr/0001-granice-komponentow.md`).

## 3. Aktorzy

| Aktor | Możliwości | W zakresie |
|---|---|---|
| Napastnik, który przejął witrynę | kształtuje treść i metadane całego materiału (pliki, linki, SQL, logi, teksty „instrukcji”) przed pozyskaniem | tak — główny przeciwnik |
| Proces współbieżny na hoście dowodowym | zmienia pliki w trakcie analizy (podmiana na symlink, dopisanie) | tak |
| Operator/analityk | wskazuje ścieżki, baseline, wyjście; może się pomylić | tak — błąd, nie złośliwość |
| Odbiorca raportu | otwiera HTML, może przekazać raport dalej | tak — jako cel XSS i wycieku danych |
| Agent kodujący / LLM czytający repo lub raport | może potraktować tekst z dowodów jako polecenie | tak |
| Złośliwy operator lub administrator hosta analitycznego | pełna kontrola nad narzędziem | **nie** — poza zakresem PoC (do potwierdzenia, pytanie B1) |

## 4. Zagrożenia

Status: **OTWARTE** — brak ochrony; **CZĘŚCIOWE** — ochrona niepełna; **NIEZWERYFIKOWANE** — kod lub konfiguracja wyglądają poprawnie, brak testu/pomiaru. Żaden wiersz nie ma statusu „zamknięte”.

Issue: #3 T-003 (testy), #4 T-101 (SecureIngest), #5 T-102 (kontrakty), #6 T-201 (pliki), #7 T-301 (SQL). T-401 (logi), T-501 (raport), T-601 (hardening) nie mają jeszcze numerów Issue.

| ID | Zagrożenie | Obecny kod (`wptrace/cli.py`) | Planowana mitygacja | Issue | Status |
|---|---|---|---|---|---|
| Z-01 | Wykonanie nieufnego PHP | Brak `subprocess`/`exec`/importu danych; importy to wyłącznie stdlib (`:4-14`). Treść czytana jako bajty i dopasowywana regexem (`:92-99`). Brak testu S-17. | Test strażniczy: zakaz modułów wykonujących kod w pakiecie; odczyt tylko przez SecureIngest. | #3, #4, #6 | NIEZWERYFIKOWANE |
| Z-02 | Wykonanie lub „odtworzenie” nieufnego SQL | Parser tekstowy `INSERT` (`:110-190`), brak sterownika DB. Test obejmuje tylko prosty przypadek (`tests/test_cli.py:7-9`). | Ograniczona gramatyka, strumieniowo, test „DDL nie jest wykonywany”. | #7 | NIEZWERYFIKOWANE |
| Z-03 | Nieufne logi jako wejście parsera | Regex na wiersz (`:252`, `:267-270`); wartości z logu trafiają do raportu (`:277-280`). | Wersjonowany parser, limity długości wiersza i liczby zdarzeń. | T-401 | CZĘŚCIOWE |
| Z-04 | Tekst udający instrukcje (plik, SQL, log, README w dowodach) | Narzędzie nie interpretuje tekstu i nie używa LLM. Ciągi z dowodów trafiają jednak do raportu: ścieżka (`:53`), nazwa opcji (`:238`), URI (`:279`), komunikaty luk. Brak fixture i testu. | Fixture z „instrukcją” i test, że raport traktuje ją jako dane; oznaczenie pól pochodzących z dowodów w kontrakcie; zakaz LLM-werdyktu. | #3, #5 | NIEZWERYFIKOWANE |
| Z-05 | Path traversal | Ścieżki względne powstają z `os.scandir` pod `root` (`:47-53`). Klucze baseline są tylko porównywane, nigdy otwierane (`:79`, `:104`). Kontrola `--output` dotyczy wyłącznie `--files` (`:367-369`) — wyjście może trafić do katalogu logów lub obok dumpu. | Jedna walidacja ścieżek w CaseManager dla wszystkich źródeł; ścieżki logiczne względne do sprawy. | #4 | CZĘŚCIOWE |
| Z-06 | Symlink | Drzewo `--files`: `lstat` i pominięcie z luką (`:55-61`), test `tests/test_cli.py:30-36`. Poza tym: `--files` jest rozwiązywane z podążaniem (`:365`), `--database` podąża (`:195`, `:200`, `:370`; potwierdzone sondą), `--baseline` podąża (`:374`), w logach pominięcie przez `is_symlink` (`:259-261`) bez testu, a `--logs` będące symlinkiem do katalogu jest przeglądane (`:256`). | Spójna polityka dla wszystkich wejść, otwarcie z `O_NOFOLLOW`, testy S-01. | #4 | CZĘŚCIOWE |
| Z-07 | Hardlink | Brak kontroli `st_nlink`. Sonda: plik z dowiązaniem twardym do pliku spoza `--files` został odczytany, wygenerował znalezisko i **nie** powstała luka pokrycia. | Decyzja polityki (pytanie B2), jawny status i test. | #4 | OTWARTE |
| Z-08 | TOCTOU | Sprawdzenie i użycie po ścieżce, nie po deskryptorze: `lstat` (`:55`) → otwarcie do skrótu (`:26` przez `:73`) → drugie otwarcie do analizy (`:92`). Katalog zaakceptowany w `:62-63` jest listowany później (`:47`). Skrót i analizowana treść mogą pochodzić z różnych wersji pliku. Logi: `:259`, `:262`, `:263`, `:267`. Brak ponownego skrótu po analizie. | Otwarcie względem deskryptora katalogu, jeden odczyt dla skrótu i analizy, ponowna weryfikacja i `SOURCE_CHANGED_DURING_ANALYSIS`, test S-02. | #4 | OTWARTE |
| Z-09 | DoS / limity zasobów | Stałe limity (`:17-20`): liczba plików tylko dla `--files` (`:69-71`), treść > 4 MB pomijana z luką (`:86-88`), SQL > 20 MB (`:197-199`), log > 30 MB (`:264-266`), 100 000 wierszy (`:206-208`). Braki: skrót liczony przed sprawdzeniem rozmiaru i bez limitu (`:73`, `:196`, `:263`); brak limitu łącznego wolumenu, długości ścieżki, liczby plików logów (`:256`), czasu i liczby znalezisk (`:277`). **ReDoS potwierdzony** w `:154`: wejście poniżej 100 B, czas ×4 na każde dodatkowe 4 znaki (0,009 s → 0,55 s dla 16 → 22 par). Regex `:99` niezmierzony. | Konfigurowalne limity i budżet czasu w SecureIngest; parser SQL bez regexów z zagnieżdżonymi kwantyfikatorami; przekroczenie = status `PARTIAL`, nie cisza; testy S-06–S-08. | #4, #7 | OTWARTE |
| Z-10 | Błędy parserów i ciche pominięcia | Niedomknięty lub niezbalansowany `INSERT` jest pomijany bez luki (`:152-153`); istnieje tylko stała, ogólna luka (`:249`). Błędne UTF-8 zastępowane bez luki (`:200`, `:267`). Dopasowanie tabel po sufiksie (`:209`, `:218`, `:227`) łączy tabele wtyczek i multisite. Rola wykrywana podciągiem `administrator` (`:225`). Administrator bez wiersza w `*_users` nie daje ani znaleziska, ani luki (`:242-243`; potwierdzone sondą). Wpisy niebędące plikami w logach pomijane bez luki (`:259-261`; potwierdzone dla FIFO). Błędny baseline kończy się nieobsłużonym wyjątkiem (`:374-375`). | Każde pominięcie = nazwana luka z licznikiem; dekoder serializacji data-only; fuzzing; obsługa błędów wejścia kodem wyjścia 2. | #5, #7, T-401 | OTWARTE |
| Z-11 | Sieć / eksfiltracja | Brak modułów sieciowych w kodzie (`:4-14`). Brak testu S-15. `network_mode: "none"` tylko zadeklarowane (`docker/compose.yaml:8`). Instalacja dev/CI pobiera pakiety z PyPI. | Test braku importów sieciowych; pomiar w kontenerze; rozdzielenie środowiska dev od silnika. | #3, T-601 | NIEZWERYFIKOWANE |
| Z-12 | Wyciek sekretów i danych osobowych | Brak jakiejkolwiek redakcji. Do `report.json` trafiają: IP klienta i URI z query stringiem (`:279-280`), login (`:246`), nazwa opcji (`:238`). Komunikat wyjątku w luce ujawnia **bezwzględną ścieżkę hosta** (`:49`, `:57`, `:75`, `:94`; potwierdzone sondą). `user_pass` nie jest kopiowany (`:209-217`), ale brak testu canary. HTML nie pokazuje `metadata`, JSON tak. | Redakcja w modelu danych (nie w szablonie), tryb `client-safe`, test canary S-13, komunikaty luk bez ścieżek hosta. | #5, T-501 | OTWARTE |
| Z-13 | XSS w raporcie HTML | `html.escape(..., quote=True)` dla każdej wstawianej wartości (`:341-348`); brak JS w szablonie. Test sprawdza tylko `case_id` (`tests/test_cli.py:45-52`), nie znaleziska, luki ani oś czasu. Brak CSP. Szablon to f-string — każde nowe pole wymaga ręcznego `esc`. | Autoescape lub jedna funkcja renderująca, CSP bez skryptów, testy S-12 dla każdego pola. | T-501 | CZĘŚCIOWE |
| Z-14 | Kontener / ucieczka na host | Obraz bez pinu digestu (`docker/Dockerfile:2`). Non-root, ro rootfs, brak sieci, `cap_drop`, `no-new-privileges`, limity, `tmpfs` są **zadeklarowane** (`docker/compose.yaml:7-16`), niezmierzone (`docs/BASELINE.md`). `results` montowane rw (`:21`), README zaleca `chmod 777` (`README.md:26`). Flaga `ro` nie chroni przed zmianą po stronie hosta. | Pomiar runtime, pin digestu, SBOM, uprawnienia wyjścia bez 777; VM dla materiału szczególnie nieufnego. | T-601 | NIEZWERYFIKOWANE |
| Z-15 | Łańcuch dowodowy | Manifest SHA-256 (`:77-78`, `:196`, `:263`, `:337`); test sprawdza tylko liczbę wpisów (`tests/test_cli.py:20`). Braki: baseline nie jest w manifeście (`:374`); brak operatora, metody i czasu pozyskania; brak ponownego skrótu; logi identyfikowane samą nazwą pliku, więc kolizje (`:263`); plik z błędem skrótu znika z manifestu (`:74-76`); raport nadpisywany nieatomowo (`:378-380`); kolejność `BASELINE_FILE_MISSING` niedeterministyczna (`:104`; potwierdzone dwoma przebiegami). | Kontrakt `Evidence` z deterministycznym ID i `read_status`, manifest wszystkich wejść, zapis atomowy, sortowanie, test S-18. | #4, #5 | CZĘŚCIOWE |
| Z-16 | Fałszywa pewność wyniku | Dwa stany: `INDICATORS_FOUND` / `NO_INDICATORS_IN_ANALYZED_SCOPE` (`:334`), bez `INCONCLUSIVE`. Brak bazy i logów nadal daje „brak wskaźników” — istniejący test to utrwala (`tests/test_cli.py:24-28`). Kod wyjścia zawsze 0 (`:383`). | Cztery stany z regułą pierwszeństwa, pokrycie per źródło, kody wyjścia 3/4. | #5 | CZĘŚCIOWE — od T-102 raport `poc-1` ma `INCONCLUSIVE`, pokrycie per źródło i kody 0/3/4 (ADR 0003); kolumna „Obecny kod” opisuje stan sprzed T-102 |
| Z-17 | Łańcuch dostaw | Brak zależności runtime (`pyproject.toml:12`); akcje CI przypięte do SHA (`.github/workflows/ci.yml:20`, `:23`). Zależności dev bez pliku lock, brak SBOM i audytu. | Lock z hashami, `pip-audit`, SBOM; każda nowa zależność z oceną licencji. | T-601 | CZĘŚCIOWE |

## 5. Pozostałe ryzyka

Ryzyka, które pozostaną także po wdrożeniu planowanych mitygacji:

1. **Parser nigdy nie będzie kompletny.** Ograniczona gramatyka SQL i wybrane formaty logów zawsze coś pominą; mitygacją jest jawna luka, nie pełne pokrycie.
2. **Kontener nie jest sandboxem.** Błąd w interpreterze lub jądrze omija izolację; dla materiału wysokiego ryzyka potrzebna jest osobna VM.
3. **Zmiana źródeł po stronie hosta** jest wykrywalna (ponowny skrót), ale nie da się jej zapobiec z poziomu narzędzia.
4. **Polityka hardlinków ma koszt.** Odrzucanie `st_nlink > 1` pominie legalne pliki (np. kopie z deduplikacją); czytanie ich nie pozwala stwierdzić, gdzie jest drugie dowiązanie.
5. **Różnice platform.** Semantyka `O_NOFOLLOW`/`openat` różni się między Linuksem a macOS; gwarancje potwierdzone na jednej platformie nie przenoszą się automatycznie.
6. **Metadane są kontrolowane przez napastnika.** `mtime`, daty w bazie i treść logów mogą być sfałszowane; oś czasu pozostaje orientacyjna.
7. **Raport zawiera dane z dowodów.** Nawet poprawnie escapowany tekst może zmylić człowieka lub model językowy czytający raport.
8. **Redakcja nie jest zupełna.** Wzorce sekretów nie pokryją wszystkich formatów; raport nadal wymaga przeglądu przed przekazaniem.
9. **Heurystyki mają false positive i false negative**, których skali nie da się oszacować na syntetycznych fixtures.
10. **Do czasu bramki M1 PoC nie nadaje się do pracy na realnym materiale** — Z-07, Z-08, Z-09 i Z-12 są otwarte.

## 6. Bramka przeglądu człowieka

Pytania, które musiały zostać rozstrzygnięte przed T-101 (#4) i T-102 (#5). **Rozstrzygnięcia: `docs/adr/0002-decyzje-bramki-m0.md`.**

| ID | Pytanie / decyzja | Dotyczy |
|---|---|---|
| B1 | Czy aktywa, granice T1–T6 i lista aktorów są kompletne? Czy złośliwy operator pozostaje poza zakresem? | całość |
| B2 | Hardlinki: odrzucać każdy plik z `st_nlink > 1` (luka), czy czytać i oznaczać? | Z-07, #4 |
| B3 | TOCTOU: odczyt względem deskryptora katalogu z `O_NOFOLLOW`, obowiązkowa prywatna kopia robocza sprawy, czy oba? Na jakich platformach obowiązują gwarancje (tylko Linux)? | Z-06, Z-08, #4 |
| B4 | Czy skrót i analiza mają pochodzić z jednego odczytu, a ponowny skrót po analizie ma być domyślny? | Z-08, Z-15, #4 |
| B5 | Symlink wskazany wprost przez operatora (`--files`, `--database`, `--logs`, `--baseline`): odmowa czy rozwiązanie z odnotowaniem? | Z-06, #4 |
| B6 | Wartości domyślne limitów (rozmiar pliku, łączny wolumen, liczba plików, długość ścieżki, czas) i zachowanie po przekroczeniu: analiza częściowa czy przerwanie? | Z-09, #4 |
| B7 | ReDoS w `cli.py:154`: osobna, wcześniejsza poprawka czy w ramach T-301 (#7)? | Z-09 |
| B8 | Prywatność: czy IP, query string i loginy mają być domyślnie redagowane także w `report.json`? Kto zatwierdza politykę? | Z-12, #5 |
| B9 | Wprowadzenie `INCONCLUSIVE` zmienia schemat i odwraca oczekiwanie testu `test_no_indicators_not_a_clean_bill`. Czy zmiana wchodzi w T-102 z migracją z 0.1.0? | Z-16, #5 |
| B10 | Czy T-101 może ruszyć przed pomiarem runtime kontenera (T-601)? Czy dla realnego materiału wymagana będzie VM? | Z-14 |
| B11 | Akceptacja listy „Pozostałe ryzyka” i zakazu użycia PoC na realnych dowodach do bramki M1. | §5 |

## 7. Jak zweryfikowano ten dokument

- Numery linii sprawdzono względem `wptrace/cli.py` na gałęzi `agent/T-001-baseline-ci`.
- Istniejące testy uruchomiono lokalnie: `PYTHONPATH=. python3 -m pytest -q` → 6 passed (Python 3.12.4, pytest 9.0.3 — poza zakresem wersji z `pyproject.toml`, bez instalacji edytowalnej).
- Wpisy oznaczone „potwierdzone sondą” sprawdzono jednorazowym skryptem na syntetycznych danych w katalogu tymczasowym poza repozytorium (hardlink, symlink `--database`, FIFO w logach, administrator bez wiersza użytkownika, ścieżka hosta w luce, czas regexu `:154`, kolejność znalezisk przy dwóch wartościach `PYTHONHASHSEED`). Skrypt nie jest częścią repozytorium; trwałe testy należą do T-003.
- Nie zweryfikowano: zachowania na Linuksie, runtime kontenera, wyścigów TOCTOU (wynikają z analizy kodu, nie z testu), kosztu regexu `:99`, treści Issues na GitHubie (brak połączeń sieciowych w tej sesji).
