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
| `fileclass.py` | klasa pliku po ścieżce (core, drop-in, mu-plugin, plugin, theme, upload…) |
| `filerules.py` | reguły ścieżki i treści, każda z identyfikatorem i wersją |
| `wpdetect.py` | WPDetector: wersja, locale, prefiks tabel jako kandydaci |

Rozstrzygnięcia dla M2:

1. **WPDetector nie zmienia schematu raportu.** Kandydaci trafiają do `observations` (przez `FileScan.observations`) z poziomem zaufania w atrybutach. Nie powstaje z nich ustalenie i nie wpływają na `assessment`. Schemat zostaje `poc-1`.
2. **MD5 nie jest skrótem dowodowym.** Skrótem dowodu pozostaje SHA-256 z SecureIngest. MD5 służy wyłącznie do porównania z publicznym manifestem WordPress.org dostarczonym jako plik lokalny; narzędzie niczego nie pobiera z sieci.
3. **Brak referencji to `NOT_CHECKED`**, zapisany w pokryciu z podziałem na klasy plików (core, plugin, theme, mu-plugin, drop-in), nigdy „czysto”.
4. **Nowy plik w miejscu ładowanym automatycznie** (mu-plugins, drop-ins) względem baseline jest ustaleniem; w pozostałych miejscach zostaje notą `NO_TRUSTED_REFERENCE`.
5. **YARA-X nie wchodzi do M2.** Reguły wbudowane dostają identyfikator, wersję i offset trafienia, żeby późniejszy adapter miał ten sam kształt wyniku. Adapter to osobne Issue.

Rozstrzygnięcia po przeglądzie bezpieczeństwa IntegrityAdapter (PR #32, 2026-11-12):

6. **Niezweryfikowany kod nie daje pełnego zakresu.** Jeżeli choć jeden plik kodu w drzewie witryny (`filerules.wants_content`: PHP i pokrewne, `.htaccess`, `.user.ini`, `php.ini`; przeczytany albo nie; dowolna klasa, także `OTHER`, `CONFIG` i uploads) nie został porównany z żadną referencją (baseline SHA-256 albo manifest sum rdzenia MD5), pokrycie `files` ma status `PARTIAL` z powodami `NOT_CHECKED` per klasa. Wtedy `scope_complete` jest fałszem, przebieg bez ustaleń daje `INCONCLUSIVE`, a kod wyjścia to 3. Reguła jest jednakowa bez względu na to, czy podano jakąkolwiek referencję, więc podanie referencji nigdy nie pogarsza wyniku względem jej braku. **To zastępuje wcześniejszy wariant z ADR 0003** („brak baseline nie obniża pokrycia”): samo źródło `baseline` nadal może mieć status `NOT_PROVIDED`, ale brak referencji dla kodu obniża pokrycie `files`. Pliki niebędące kodem (obrazy, CSS, JS) bez referencji zostają notą `NOT_CHECKED`, która statusu nie obniża.
7. **Wpis nieprzeczytany nie ucisza kontroli integralności.** Wpis, którego SecureIngest nie przeczytał (dowiązanie symboliczne, dodatkowe dowiązanie twarde, brak uprawnień, plik specjalny, limit), a który referencja wymienia jako plik albo jako katalog swoich plików, daje ustalenie `REFERENCE_FILE_UNREADABLE` (waga `medium`, pewność `low`) z nazwanym statusem odczytu. Wyjątek: katalog pominięty przez limit operatora (głębokość, liczba wpisów) zostaje samą luką pokrycia. Wpisy nieprzeczytane liczą się w sumach `NOT_CHECKED`.
8. **`CORE_FILE_NOT_IN_MANIFEST` obejmuje katalog główny, `wp-admin` i `wp-includes`.** Przy podanym manifeście ustaleniem jest każdy plik kodu (`filerules.wants_content`) spoza manifestu w tych miejscach, także nieprzeczytany (pewność `low`). Wyjątki, których manifest dystrybucji nigdy nie zawiera: `wp-config.php`, `.htaccess`, `.user.ini` i `php.ini` w katalogu głównym — trafiają do `NOT_CHECKED` (klasa `CONFIG`). Kod w innych katalogach poza `wp-content` to `NOT_CHECKED` (klasa `OTHER`).
9. **Nieprzeczytany katalog `wp-content/mu-plugins`** (dowiązanie, limit głębokości, brak uprawnień, plik specjalny), pod którym niepusty baseline niczego nie wymienia, daje `NEW_FILE_SINCE_BASELINE` po samej ścieżce (pewność `low`).
10. **Limit 200 ustaleń na regułę integralności w jednym przebiegu.** Ponad limit nie powstają kolejne ustalenia, tylko luka obniżająca pokrycie `files` z nazwą reguły i łączną liczbą wykryć: limit, który ukrywa ustalenia, sam jest widoczny.
11. **Ścisła walidacja referencji przed analizą (kod wyjścia 2).** Powtórzony klucz w JSON baseline albo manifestu; klucze `baseline.files` niebędące ścieżkami względnymi (te same reguły co klucze manifestu) i wartości inne niż 64 małe cyfry szesnastkowe; w wariancie zagnieżdżonym manifestu jedyny klucz musi wyglądać jak numer wersji (`\d+(\.\d+){1,2}([-+][0-9A-Za-z.]+)?`).
12. **Nazwy plików w nocie `NO_TRUSTED_REFERENCE`** są cytowane jak łańcuchy JSON, żeby nazwa z przecinkami lub znakami sterującymi nie zmieniała sensu zdania.

## Konsekwencje

- `cli.scan_files` przestaje istnieć; wywołuje się `files.scan_files(root, baseline, session)`.
- Refaktor nie zmienia zachowania: wynik testów przed i po jest ten sam (1864 passed, 5 skipped, 10 xfailed).
- Rollback: revert commita.
- Po pkt 6 scenariusz demonstracyjny (`fixtures/`) kończy się kodem 3 i `scope_complete: false`: plik PHP w uploads nie ma zaufanej referencji, a `fixtures/baseline.json` nie zawiera skrótów plików. Ocena `SUSPICIOUS` wynika z ustaleń i się nie zmienia.
- Analiza bez żadnej referencji nie może już dać `NO_INDICATORS_IN_ANALYZED_SCOPE`, jeśli w drzewie jest plik kodu.
