# ADR 0006 — Analiza bazy: parser ścisły, dane serializowane PHP, JSONL (M3, T-301)

| | |
|---|---|
| **Status** | **ACCEPTED** (2026-11-12) |
| **Kto zdecydował** | Agent kodujący na podstawie delegacji właściciela; bez niezależnego przeglądu AppSec |
| **Dotyczy** | Issue #7 (T-301) |

## Kontekst

Parser PoC wczytuje cały zrzut do pamięci (limit 20 MiB), rozpoznaje podzbiór `INSERT`, a pominięte instrukcje wykrywa osobną heurystyką, która w kolejnych przeglądach rozjeżdżała się z zachowaniem prawdziwego serwera. Rola administratora jest wykrywana podłańcuchem `administrator` w wartości meta.

## Decyzja

Kod bazy jest poza `cli.py`, w modułach bez dostępu do systemu plików (strażnik D4 bez zmian):

| Moduł | Odpowiedzialność |
|---|---|
| `database.py` | odczyt źródła przez SecureIngest, wybór formatu, limity, pokrycie |
| `sqldump.py` | parser zrzutu SQL |
| `jsonldb.py` | adapter eksportu JSONL |
| `dbrules.py` | reguły na wierszach: użytkownicy, role, opcje, cron |
| `phpserialize.py` | bezpieczny odczyt danych serializowanych PHP |

1. **Parser ścisły zamiast detektora.** Każdy bajt zrzutu należy do rozpoznanej instrukcji albo powstaje luka w pokryciu. Instrukcje obojętne (ustawienia sesji, definicje tabel, blokady) są rozpoznawane i pomijane jawnie; wszystko inne (UPDATE, DELETE, wyzwalacze, procedury, `DELIMITER`, polecenia klienta, komentarze wykonywalne z zapisem) obniża pokrycie. SQL nie jest nigdy wykonywany.
2. **Parser strumieniowy na bajtach.** Dostaje kolejne porcje (`feed`) i oddaje wiersze; SecureIngest podaje mu porcje w tym samym, jedynym odczycie, w którym liczy SHA-256. Zrzut nie jest trzymany w pamięci w całości. Limit rozmiaru zrzutu to ogólny limit pliku; osobne limity mają długość instrukcji, komórki i liczba wierszy. Przekroczenie = luka, nie przerwanie analizy.
3. **Jedna postać wiersza** dla obu formatów: tabela, lista kolumn, komórki (`str | None`), numer wiersza. Reguły nie wiedzą, z jakiego formatu wiersz pochodzi.
4. **Prefiks tabel wynika ze zrzutu**, nie z założenia `wp_`. Tabele rdzenia rozpoznaje się po parze `<prefiks>users` i `<prefiks>usermeta`. Kilka prefiksów lub układ multisite = luka w pokryciu.
5. **Dane serializowane PHP to dane.** Parser odczytuje typy proste i tablice z limitem głębokości i rozmiaru. Obiekty (`O:`, `C:`) nie są nigdy odtwarzane: zostają nieprzezroczystym znacznikiem. Błąd składni = luka, bez powrotu do dopasowania podłańcuchem. Administratorem jest konto, którego tablica uprawnień ma klucz `administrator` z wartością prawdziwą.
6. **Inwentarz zamiast alertu.** Konta administratorów i zadania cron trafiają do `observations` bez ustalenia. Schemat `poc-1` się nie zmienia. Samo istnienie administratora nie jest alertem.
7. **`NEW_SINCE_BASELINE`.** Administrator nieobecny na liście `known_admins` z baseline to ustalenie „nowy względem migawki”. Nieobecny tylko na liście z `--known-admin` pozostaje `UNRECOGNIZED_ADMIN`. Bez żadnej listy nie ma ustalenia.
8. **Cytat wartości z redakcją.** Ustalenie o wartości opcji niesie krótki, ograniczony wycinek z usuniętymi sekretami i parametrami zapytania. Funkcja redakcji jest wspólna i będzie użyta także w T-501 (#14).
9. **JSONL** ma ścisły kontrakt: jeden obiekt na wiersz, jawna tabela i kolumny, tylko wartości proste. Wiersz niezgodny = luka. Format wybiera operator flagą; nie ma zgadywania po treści.

## Konsekwencje

- `cli.iter_insert_rows` i pomocnicze funkcje parsera są w `sqldump.py`; `cli.scan_database` to `database.scan_database`.
- Krok przygotowawczy (podział na moduły) nie zmienia zachowania: 2138 passed, 5 skipped, 7 xfailed przed i po.
- Zmiana w `ingest.py` (podawanie porcji do parsera) jest krytyczna dla bezpieczeństwa i wymaga osobnego przeglądu.
- Rollback: revert commitów.
