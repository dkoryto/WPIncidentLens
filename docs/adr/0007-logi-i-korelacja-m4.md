# ADR 0007 — Logi HTTP, czas UTC i korelacja (M4, T-401)

| | |
|---|---|
| **Status** | **ACCEPTED** (2026-11-12) |
| **Kto zdecydował** | Agent kodujący na podstawie delegacji właściciela; bez niezależnego przeglądu AppSec |
| **Dotyczy** | Issue #13 (T-401) |

## Kontekst

Parser logów PoC to jedno wyrażenie dla Apache/Nginx combined w `cli.py`: wczytuje cały plik (limit 30 MiB), rozpoznaje wyłącznie `.php|.phtml|.phar` w uploads i nie zna zaufanych proxy. Korelacja łączy plik z logiem tylko po ścieżce i tylko w uploads. Pusty katalog logów nie daje luki.

## Decyzja

Kod logów i osi czasu jest poza `cli.py`, w modułach bez dostępu do systemu plików poza SecureIngest (strażnik D4 bez zmian):

| Moduł | Odpowiedzialność |
|---|---|
| `httplog.py` | odczyt logów przez SecureIngest (strumieniowo, `sink`), wybór formatu, limity, pokrycie per plik, reguła HTTP |
| `logformats.py` | czyste parsery wiersza: wersjonowana tabela formatów, wynik `HttpRecord` |
| `correlate.py` | oś czasu i ustalenia korelacyjne między źródłami |

1. **Formaty jawne, wybierane flagą** `--log-format {combined,common,json}` (domyślnie `combined`); bez zgadywania po treści (jak `--database-format`, ADR 0006 pkt 9). Każdy format ma identyfikator i wersję (`combined@1`), zapisywane w atrybucie `log_format` obserwacji. `json` ma udokumentowany kontrakt jednego obiektu na wiersz (pola w `docs/RULES.md`).
2. **Odczyt strumieniowy.** Porcje z odczytu liczącego SHA-256 trafiają do parsera wierszy; znika limit 30 MiB (obowiązuje `--max-file-bytes`). Wiersz dłuższy niż 64 KiB jest nieparsowany i liczony.
3. **Pokrycie per plik:** liczba wierszy, sparsowanych i odrzuconych z powodem; wiersze ze stratnym dekodowaniem liczone osobno. Pusty katalog logów albo brak plików to `FAILED` z luką. Plik bez żadnego sparsowanego wiersza obniża pokrycie.
4. **Rozszerzenia kodu wspólne z regułami plików** (`filerules.CODE_SUFFIXES`, także podwójne rozszerzenia w uploads). Ścieżka żądania jest normalizowana (dekodowanie `%XX` raz, bez query, bez `..`); surowy URI w raporcie przechodzi przez `redact` (tokeny w query).
5. **Adres klienta** to adres połączenia. `X-Forwarded-For` jest brany pod uwagę wyłącznie, gdy format go niesie (`json`: pole `forwarded_for`) **i** adres połączenia należy do `--trusted-proxy CIDR` (powtarzalna). Wtedy klientem jest ostatni od prawej adres spoza zaufanych. Atrybut `client_ip_basis`: `connection` albo `forwarded_for_via_trusted_proxy`.
6. **Czas.** Obserwacja ma `timestamp_raw`, `timestamp_utc` (albo `null` z luką, gdy brak strefy) i `time_source=log`. Atrybuty `timestamp_precision` (`second` dla combined/common) i `clock_uncertainty_seconds` z `--log-clock-skew SECONDS` deklarowanego przez operatora; bez flagi atrybut ma wartość `null` i oś czasu mówi „zegar niezweryfikowany”.
7. **Interfejs dla korelacji.** `httplog.scan_logs(root, session, config) -> LogScan(detections, cover, requests)`. `requests` to obserwacje rodzaju `HTTP_REQUEST` wyłącznie dla żądań do ścieżek z rozszerzeniem kodu (limit 50 000, przekroczenie = luka). Atrybuty: `path` (znormalizowana ścieżka względna bez wiodącego `/`), `uri` (po redakcji), `method`, `status`, `bytes` (int lub null), `client_ip`, `client_ip_basis`, `log_format`, `timestamp_precision`, `clock_uncertainty_seconds`.
8. **Korelacja nie twierdzi przyczynowości.** Relacje (spec §8.3) są identyfikatorami reguł, więc schemat `poc-1` się nie zmienia:
   - `CORRELATED_UPLOAD_REQUEST` (bez zmian, `SAME_PATH` dla pliku wykonywalnego w uploads),
   - `CORRELATED_FILE_REQUEST` (`SAME_PATH` dla każdego innego pliku kodu z ustaleniem plikowym),
   - `REQUEST_NEAR_FILE_CHANGE` (`NEAR_IN_TIME`: żądanie w oknie `--correlation-window` sekund, domyślnie 900, od `mtime` pliku z ustaleniem). Pewność `low`; tylko gdy oba czasy są znane. Okno poszerza się o zadeklarowaną niepewność zegara. `mtime` jest zmienialny, więc reguła nigdy nie podnosi pewności innego ustalenia.
   Nigdy `PROVEN_EXPLOIT`; status HTTP 200 nie jest dowodem wykonania.
9. **Poza M4:** czas rejestracji konta z bazy na osi czasu wymaga nowej wartości `TimeSource`, czyli zmiany schematu (osobna decyzja z migracją).

## Konsekwencje

- Krok przygotowawczy (`agent/T-401-prep-logs`): kod logów przeniesiony do `httplog.py`, oś czasu i korelacja do `correlate.py`, bez zmiany zachowania (2503 passed przed i po). `cli.scan_logs`, `cli.LOG_PATTERN`, `cli.MAX_LOG_BYTES`, `cli._timeline` zostają jako importy dla testów.
- Korelacja (`agent/T-401-correlate`): `correlate.correlate(detections, requests, evidence, window_seconds)` zwraca ustalenia, wskazane obserwacje żądań (trafiają do `observations` raportu i na oś czasu jako `HTTP_REQUEST`) i noty o limitach. `CORRELATED_FILE_REQUEST` i `REQUEST_NEAR_FILE_CHANGE` mają wagę `medium` i pewność `low`: relacja wskazuje trop do zbadania, sama nie jest szkodliwym faktem i nie dorównuje `CORRELATED_UPLOAD_REQUEST` (`high`/`medium`), bo żądania do plików wtyczek i motywów są zwykłym ruchem. Jedno ustalenie na parę (plik, reguła) z najwyżej 20 żądaniami, najwyżej 200 ustaleń na regułę (nadmiar to luka `logs`). `cli._log_scan` przyjmuje wynik `scan_logs` jako krotkę `(detections, cover)` albo obiekt z polami `detections`, `cover`, `requests`; flaga `--correlation-window` nie jest zapisywana w `case.json` (zmiana schematu `case-poc-1`), okno podaje wyjaśnienie ustalenia.
- Parser logów (`agent/T-401-logparser`): `logformats.py` (czyste parsery `combined@1`, `common@1`, `json@1` z kwantyfikatorami zaborczymi, normalizacja ścieżki, adres klienta) i `httplog.py` (`scan_logs(root, session, config) -> LogScan`). `ingest.Session.read` dostał `sink_factory(rel)`: każdy zwykły plik źródła-katalogu dostaje własny `sink`, wołany po sprawdzeniu limitów; limit 30 MiB zniknął, a `cli.LOG_PATTERN` i `cli.MAX_LOG_BYTES` nie są już eksportowane (testy S-08 wołają `logformats.parse`). Opcje trafiają do `case.json` jako opcjonalne pola `sources.logs.{format, trusted_proxies, clock_skew_seconds}` (zgodnie wstecz). Doprecyzowania: segmenty `..` są rozwiązywane jak przez serwer, a ścieżka wychodząca ponad katalog główny nie jest przypisywana do pliku (nota); czas `json@1` bez przesunięcia strefy daje `timestamp_utc: null` jak w combined; reguła `HTTP_EXECUTABLE_IN_UPLOADS` obejmuje każdą metodę, a podwójne rozszerzenie ma pewność `low`; ten sam wiersz daje obserwację reguły (`HTTP_REQUEST_FOR_PHP_IN_UPLOADS`) i obserwację żądania (`HTTP_REQUEST`) o tych samych atrybutach — rodzaj reguły zostaje dla zgodności kontraktu, a łączenie ich na osi czasu należy do `correlate`.
- Zmiana w odczycie logów przez `sink` korzysta z mechanizmu z ADR 0006; nowe parsery nieufnych danych wymagają przeglądu bezpieczeństwa przed scaleniem.
- Rollback: revert commitów.
