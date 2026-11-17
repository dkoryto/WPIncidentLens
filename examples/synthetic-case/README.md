# Przykładowa sprawa: syntetyczny incydent (M7, T-701)

Pokaz pełnego przebiegu na **wyłącznie syntetycznych** danych z katalogu `fixtures/`. Nie ma tu realnych dowodów, kont, haseł ani logów: adresy to TEST-NET (`192.0.2.0/24`), domeny `example.invalid`, a „złośliwy” kod to obojętny tekst, którego nic nie wykonuje. Ten katalog nie zawiera własnych danych — opisuje polecenie i oczekiwany wynik. Zgodność opisu z narzędziem sprawdza `tests/test_sample_case.py`: uruchamia polecenie z tego pliku i porównuje ocenę, kod wyjścia i zbiór reguł z tabelami niżej.

## Materiał

| Ścieżka | Źródło | Zawartość |
|---|---|---|
| `fixtures/site/index.php` | `--files` | zaślepka punktu wejścia WordPressa |
| `fixtures/site/wp-config.php` | `--files` | sam `$table_prefix = 'demo_';`, bez danych dostępowych |
| `fixtures/site/wp-content/uploads/2026/11/cache-view.php` | `--files` | plik PHP w uploads z tekstem wzorca `eval(base64_decode(…))` w komentarzu |
| `fixtures/database.sql` | `--database` | `INSERT` do `demo_users`, `demo_usermeta` (dwóch administratorów: `knownadmin`, `mysteryadmin`) i `demo_options` (opcja `custom_footer` ze znacznikiem `<script>`) |
| `fixtures/logs/access.log` | `--logs` | dwa wiersze `combined`: `POST` do pliku PHP w uploads i zwykłe `GET` |
| `fixtures/baseline.json` | `--baseline` | `known_admins: ["knownadmin"]` i pusta mapa `files` — brak skrótów plików |

## Polecenie

Z katalogu głównego repozytorium:

```bash
python -m wpincidentlens --files fixtures/site --database fixtures/database.sql --logs fixtures/logs --baseline fixtures/baseline.json --output results/synthetic-case --case-id DEMO-001
```

## Oczekiwany wynik

| Pole | Wartość |
|---|---|
| `assessment` | `SUSPICIOUS` |
| `scope_complete` | `false` |
| `exit_code` | `3` |

Ocena `SUSPICIOUS`, bo są ustalenia, a żadne nie ma jednocześnie wagi `high` i pewności `high` (`STRONG_INDICATORS` jest dziś nieosiągalny). Kod 3, bo zakres jest niepełny: baseline nie zawiera skrótów plików, więc trzy pliki kodu mają status `NOT_CHECKED` (klasy `CORE`, `CONFIG`, `UPLOAD`) i pokrycie `files` to `PARTIAL`. Baza, logi i baseline mają `ANALYZED`.

### Ustalenia

| Reguła | Waga | Pewność | Co wskazuje |
|---|---|---|---|
| `CORRELATED_UPLOAD_REQUEST` | high | medium | ten sam plik PHP w uploads jest w kopii i w logu (`SAME_PATH`) |
| `EXECUTABLE_IN_UPLOADS` | high | medium | `cache-view.php` w `wp-content/uploads/` |
| `HTTP_EXECUTABLE_IN_UPLOADS` | high | medium | `POST` do tego pliku w `access.log:1` |
| `NEW_SINCE_BASELINE` | high | medium | administrator `mysteryadmin` spoza `known_admins` |
| `SUSPICIOUS_PHP_EVAL_DECODE` | high | medium | tekst `eval(base64_decode(…))` w pliku z uploads |
| `SUSPICIOUS_DB_MARKUP` | medium | low | `<script>` w opcji `custom_footer` |

Obserwacje bez ustalenia: kandydat prefiksu tabel `WP_TABLE_PREFIX_CANDIDATE` (`demo_`) z `wp-config.php` i dwa wpisy inwentarza `ADMINISTRATOR_ACCOUNT`. Oś czasu ma dwa zdarzenia: żądanie z logu (`2026-11-09T01:14:01+00:00`, zegar serwera niezweryfikowany) i `mtime` pliku z uploads — ten drugi zależy od chwili wykonania kopii repozytorium, więc różni się między maszynami.

## Na co zwrócić uwagę

- Zakres jest niepełny mimo podania wszystkich źródeł: tak wygląda typowy wynik bez baseline ze skrótami plików albo manifestu sum rdzenia ([ANALYST_GUIDE.md](../../docs/ANALYST_GUIDE.md), rozdział 6).
- Raport zawiera adresy IP i loginy (narzędzie ostrzega na stderr); z `--pseudonymize` zostają zastąpione pseudonimami, a ocena, kod wyjścia i zbiór reguł się nie zmieniają.
- To samo polecenie w kontenerze uruchamia `docker/compose.yaml` z dodatkowym `--known-admin knownadmin` ([INSTALL.md](../../docs/INSTALL.md#kontener-docker)); CI porównuje wynik kontenera z hostem.
- Zapisany wcześniej raport tego scenariusza: [demo/report.json](../../demo/report.json) i [demo/report.html](../../demo/report.html).
