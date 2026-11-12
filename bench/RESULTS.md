# Benchmarki S-06/S-07 — wyniki pomiaru

ADR 0009 pkt 5, Issue #15 (T-601). Pomiar, nie test: CI nie ma progów. Dane wyłącznie syntetyczne (`bench/generate.py`:
adresy TEST-NET, domeny `example.invalid`, bez haseł i danych osób), generowane w katalogu tymczasowym poza repozytorium
i usuwane po przebiegu.

## Maszyna i stan

| | |
|---|---|
| Data | 2026-11-12 |
| Commit silnika | `e739098` (`main` po PR #61; przed zmianami T-601 „deadlines”, ADR 0009 pkt 4) |
| CPU | Apple M1 Max (10 rdzeni; narzędzie jest jednowątkowe) |
| RAM | 32 GiB |
| OS | macOS 27.0.1 (26A434), APFS na SSD |
| Python | 3.12.11 |

Metoda: przebiegi sekwencyjne, każdy w osobnym podprocesie; dane powstały tuż przed pomiarem (są w page cache).
Przebieg `files-default-limits` nakładał się częściowo z równoległym `pytest` w innym procesie, więc jego czas ścienny
może być zawyżony. Maksymalny RSS pochodzi z `os.wait4` (ten sam licznik co `getrusage(RUSAGE_CHILDREN)`, ale osobno
dla każdego podprocesu); CPU user/sys to różnica `RUSAGE_CHILDREN` przed i po przebiegu.

## Odtworzenie

```sh
# szybki tryb (1%: 10 000 plików, log i zrzut po ~10 MiB), ok. 15 s
PYTHONPATH=$PWD python bench/run.py --data /tmp/wpil-bench --scale 0.01 --generate
# pełny (1 000 000 plików, log 1 GiB, zrzut SQL 1 GiB): ok. 6 GB dysku, ok. 15 min na tej maszynie
PYTHONPATH=$PWD python bench/run.py --data /tmp/wpil-bench --scale 1 --generate --json bench.json --markdown bench.md
```

`--only files|log|sql` ogranicza scenariusze, `--tight-seconds` zmienia ciasny limit (domyślnie 2 s), `--keep` zostawia
dane. `--data` w repozytorium jest odrzucane.

Scenariusze: `files-default-limits` — domyślne limity (`--max-files` 200 000); `files-raised-limits` — `--max-files`
i `--max-entries` powyżej rozmiaru drzewa; `*-tight-time` — to samo z `--max-seconds 2`; `log` i `sql` — minimalna
witryna (`--files`) oraz log albo zrzut.

## Dane (scale 1.0)

| Źródło | Rozmiar | Zawartość | Generowanie |
|---|---|---|---:|
| Drzewo plików | 1 000 000 plików (dane łącznie ~5,8 GB na dysku) | rdzeń 15%, wtyczki 45%, motywy 10%, uploads 30% (obrazy, co 50 000. plik PHP), 250 plików na katalog | 133,9 s |
| Log dostępu (combined) | 1 073 741 947 B, 6 985 776 wierszy | żądania zwykłe; co 20 000. wiersz POST do PHP w uploads; co 200 000. wiersz 80 KiB (> limit wiersza 64 KiB) | 29,5 s |
| Zrzut SQL (mysqldump) | 1 074 420 893 B | `wp_users` 735 500, `wp_usermeta` 1 471 000, `wp_options` 2 942 000 wierszy; INSERT po 500 wierszy; 3 administratorów; co 100 000. opcja z `<script>` | 3,4 s |

## Wyniki (scale 1.0)

| Scenariusz | Wall [s] | User [s] | Sys [s] | Max RSS [MiB] | Kod | Ocena | Pokrycie | Luki limitów |
|---|---:|---:|---:|---:|---:|---|---|---|
| files-default-limits | 67.24 | 20.54 | 25.41 | 971.5 | 3 | INCONCLUSIVE | files=PARTIAL | Limit 200000 plików; analiza katalogu niepełna (pierwszy pominięty wpis: wp-content/plugins/pkg0019/dir00799/f199998.php) |
| files-raised-limits | 322.51 | 97.11 | 129.05 | 3460.6 | 3 | SUSPICIOUS | files=PARTIAL | — |
| files-tight-time | 2.37 | 1.1 | 0.76 | 83.0 | 3 | INCONCLUSIVE | files=PARTIAL | Limit czasu analizy 2 s przekroczony; nieodczytana pozostała część: źródło files<br>Ponowna weryfikacja przerwana limitem czasu 2 s: sprawdzono 0/12256 dowodów |
| log | 100.79 | 99.54 | 0.66 | 32.6 | 3 | SUSPICIOUS | files=PARTIAL, logs=PARTIAL | Nie sparsowano 35/6985776 wierszy logów (0.0%, format combined@1): dłuższy niż 65536 B ×35 |
| log-tight-time | 2.77 | 2.62 | 0.12 | 29.6 | 3 | SUSPICIOUS | files=PARTIAL, logs=PARTIAL | Limit czasu analizy 2 s przekroczony w trakcie pliku logu: access.log przeanalizowany do wiersza 138239<br>Nie sparsowano 1/138239 wierszy logów<br>Ponowna weryfikacja przerwana limitem czasu 2 s: sprawdzono 0/5 dowodów |
| sql | 100.17 | 99.17 | 0.7 | 305.0 | 3 | SUSPICIOUS | files=PARTIAL, database=PARTIAL | Reguły objęły 430677 z 5148500 wierszy tabel użytkowników i opcji (limit 1000000 wierszy i 268435456 B treści) |
| sql-tight-time | 99.26 | 98.45 | 0.51 | 303.0 | 3 | SUSPICIOUS | files=PARTIAL, database=PARTIAL | Ponowna weryfikacja przerwana limitem czasu 2 s: sprawdzono 0/5 dowodów<br>Reguły objęły 430677 z 5148500 wierszy (limit jak wyżej) |

Kod 3 we wszystkich przebiegach to „analiza częściowa” (m.in. integralność plików bez zaufanej referencji,
`NOT_CHECKED`). `files=PARTIAL` wynika z tego samego. Ustalenia: files-default 0, files-raised 6, files-tight 0, log 350,
log-tight 7, sql 3, sql-tight 3. Rozmiar `report.json`: files-default 76 MiB, files-raised 382 MiB, pozostałe < 1 MiB.

Kontrola liniowości SQL (osobny przebieg, scale 0.25, zrzut 256 MiB): `sql` 28,96 s, RSS 301,5 MiB; `sql-tight-time`
28,76 s. Szybki tryb (scale 0.01): wszystkie przebiegi 1–2 s, RSS 27–75 MiB.

## Wnioski

- **Skalowanie liniowe.** Pliki: 200 000 → 67 s, 1 000 000 → 323 s (×4,8); log 1 GiB → 101 s (~10,6 MiB/s);
  SQL 256 MiB → 29 s, 1 GiB → 100 s. Nie zaobserwowano zachowania superliniowego.
- **Limit liczby plików działa:** przy domyślnych limitach przejście kończy się po 200 000 plików z nazwaną luką, ocena
  `INCONCLUSIVE` (przejście nie dotarło do `uploads`, więc brak ustaleń — brak alertów nie oznacza „czysto”).
- **Limit czasu w drzewie plików i w logu działa:** limit 2 s → 2,4 s i 2,8 s czasu ściennego (start interpretera,
  zapis raportu), z lukami „przekroczony” i „przeanalizowany do wiersza 138239”.
- **Log: pamięć stała** (~30 MiB przy 1 GiB); 35 wierszy ponad 64 KiB odrzuconych i policzonych w luce.
- **SQL: pamięć ograniczona** (~300 MiB przy 256 MiB i 1 GiB) limitem reguł bazy (1 000 000 wierszy, 256 MiB treści);
  reguły objęły 430 677 z 5 148 500 wierszy, co jest jawną luką i daje `database=PARTIAL`.

## Anomalie (zgłoszone, nienaprawiane w tej gałęzi)

1. **`--max-seconds` nie ogranicza parsowania zrzutu SQL.** `sql-tight-time` z limitem 2 s trwa 99 s (tyle co bez
   limitu). Jedyna luka czasowa dotyczy ponownej weryfikacji skrótów; raport nie mówi, że analiza bazy przekroczyła limit
   czasu ~50-krotnie. Zgodne z wierszem S-06 „NOT COVERED” w `docs/TEST_MATRIX.md` i ADR 0009 pkt 4 (gałąź
   `agent/T-601-deadlines`). Reprodukcja:
   `python bench/generate.py --out DIR --scale 0.25 --scenario sql`, potem
   `python -m wpincidentlens --files DIR/site --database DIR/dump.sql --max-seconds 2 --output OUT` → ~29 s, brak luki
   „Limit czasu analizy … przekroczony” dla bazy.
2. **Pamięć rośnie liniowo z liczbą plików: ~3,5 KiB RSS na plik** (200 000 plików → 971 MiB, 1 000 000 → 3,46 GiB),
   `report.json` ~400 B na plik (76 MiB / 382 MiB). Przy domyślnym `--max-files` 200 000 RSS na macOS jest tuż pod
   `mem_limit: 1g` z `docker/compose.yaml`; drzewo bliskie domyślnemu limitowi może w kontenerze zakończyć się OOM
   zamiast luką limitu (niezmierzone w kontenerze — brak lokalnego Dockera; RSS na Linuksie może się różnić). Reprodukcja:
   `python bench/run.py --data DIR --scale 0.2 --generate --only files` (200 000 plików), odczyt `max_rss_mib`
   w `files-raised-limits`.
3. **Po wyczerpaniu limitu reguł bazy parser czyta zrzut do końca.** Limit treści reguł wyczerpał się po ~8% wierszy,
   a czas przebiegu nadal rośnie liniowo z rozmiarem całego pliku (29 s dla 256 MiB, 100 s dla 1 GiB). Konto
   administratora dopisane na końcu dużego zrzutu nie zostanie ocenione (luka jest jawna). Obserwacja wydajnościowa,
   nie błąd poprawności; nie sprawdzano, które dalsze elementy (np. nazwy tabel, prefiksy) korzystają z dalszego
   parsowania.
