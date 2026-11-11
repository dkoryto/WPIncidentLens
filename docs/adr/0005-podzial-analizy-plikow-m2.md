# ADR 0005 — Podział analizy plików na moduły (M2, T-201)

| | |
|---|---|
| **Status** | **ACCEPTED** (2026-11-12) |
| **Kto zdecydował** | Agent kodujący na podstawie delegacji właściciela („sam podejmuj decyzje”); bez niezależnego przeglądu AppSec |
| **Dotyczy** | Issue #6 (T-201) |

## Kontekst

Cała analiza plików była jedną funkcją `scan_files` w `cli.py`. M2 dodaje trzy niezależne obszary (wykrywanie WordPressa, integralność względem referencji, reguły plików), które mają powstawać równolegle.

## Decyzja

Jedno przejście drzewa przez SecureIngest zostaje w `wpincidentlens/files.py`. Logika jest w modułach, które nie dotykają systemu plików (strażnik D4 z ADR 0002 obowiązuje bez zmian):

| Moduł | Odpowiedzialność |
|---|---|
| `analysis.py` | wspólne typy: `Detection`, `SourceCoverage`, budowa obserwacji |
| `files.py` | pętla po wpisach, limit skanu treści, wynik `FileScan` |
| `integrity.py` | porównanie z zaufaną referencją: baseline SHA-256, lokalny manifest sum WordPress.org (MD5) |
| `filerules.py` | reguły ścieżki i treści, każda z identyfikatorem i wersją |
| `wpdetect.py` | WPDetector: wersja, locale, prefiks tabel jako kandydaci |

Rozstrzygnięcia dla M2:

1. **WPDetector nie zmienia schematu raportu.** Kandydaci trafiają do `observations` (przez `FileScan.observations`) z poziomem zaufania w atrybutach. Nie powstaje z nich ustalenie i nie wpływają na `assessment`. Schemat zostaje `poc-1`.
2. **MD5 nie jest skrótem dowodowym.** Skrótem dowodu pozostaje SHA-256 z SecureIngest. MD5 służy wyłącznie do porównania z publicznym manifestem WordPress.org dostarczonym jako plik lokalny; narzędzie niczego nie pobiera z sieci.
3. **Brak referencji to `NOT_CHECKED`**, zapisany w pokryciu z podziałem na klasy plików (core, plugin, theme, mu-plugin, drop-in), nigdy „czysto”.
4. **Nowy plik w miejscu ładowanym automatycznie** (mu-plugins, drop-ins) względem baseline jest ustaleniem; w pozostałych miejscach zostaje notą `NO_TRUSTED_REFERENCE`.
5. **YARA-X nie wchodzi do M2.** Reguły wbudowane dostają identyfikator, wersję i offset trafienia, żeby późniejszy adapter miał ten sam kształt wyniku. Adapter to osobne Issue.

## Konsekwencje

- `cli.scan_files` przestaje istnieć; wywołuje się `files.scan_files(root, baseline, session)`.
- Refaktor nie zmienia zachowania: wynik testów przed i po jest ten sam (1864 passed, 5 skipped, 10 xfailed).
- Rollback: revert commita.
