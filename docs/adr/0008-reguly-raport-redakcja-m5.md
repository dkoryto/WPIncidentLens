# ADR 0008 — Rejestr reguł, raport HTML, redakcja i pliki wyniku (M5, T-501)

| | |
|---|---|
| **Status** | **ACCEPTED** (2026-11-12) |
| **Kto zdecydował** | Agent kodujący na podstawie delegacji właściciela; bez niezależnego przeglądu AppSec |
| **Dotyczy** | Issue #14 (T-501), ADR 0002 B8 i D3, specyfikacja §9 i C10, R-40, R-74, R-80, R-81 |

## Kontekst

Po M4 ocena (`models.assess`) ma cztery stany i niezależne `severity`/`confidence`, ale:

- reguły są rozproszone: tabela w `filerules.RULES` (z `RULESET_VERSION`), reszta to wywołania `Detection(...)` i `models.Finding(...)` w `integrity`, `dbrules`, `httplog`, `correlate`; nie ma jednego spisu, identyfikatora ani skrótu zestawu reguł, a reguła spoza spisu przechodzi niezauważona;
- raport HTML to jeden f-string z ręcznym `esc` przy każdym polu i bez CSP (XFAIL `s12_html_report_declares_content_security_policy`);
- redakcja działa tylko tam, gdzie moduł o niej pamięta (`redact` w bazie i plikach, `httplog.redacted_uri`); adres IP i login trafiają do raportu jawnie, bez flagi `--pseudonymize` i bez ostrzeżenia (B8);
- wynik to trzy pliki (`report.json`, `report.html`, `case.json`), specyfikacja wymaga ośmiu (R-40).

## Decyzja

1. **Schemat raportu `poc-1` się nie zmienia.** Nowe informacje trafiają do `case.json` jako pola **opcjonalne** (jak `sources.logs.*` w M4): stary `case.json` przechodzi walidację nowego schematu, nowe pola są zawsze zapisywane przez narzędzie.
2. **Rejestr reguł** `wpincidentlens/rules.py`: jeden słownik `Rule` dla każdej reguły z każdego modułu (identyfikator, wersja, kategoria, `severity`, dopuszczalne wartości `confidence`, opis, znane fałszywe alarmy). `RULESET_ID = "wpincidentlens-poc"`, `RULESET_VERSION` i `ruleset_sha256()` — SHA-256 kanonicznego JSON rejestru. `filerules.RULES` staje się częścią rejestru (bez zmiany zachowania). Zamiana wykrycia na ustalenie przechodzi przez jedną funkcję rejestru: reguła spoza rejestru albo `severity`/`confidence` spoza deklaracji to **luka pokrycia źródła, nie cisza i nie awaria** (spec C10); test kontraktu wymaga, by każde `rule_id` emitowane w kodzie było w rejestrze. Dwie osobne tabele regresyjne `severity` i `confidence` (spec §9.2). `case.json` dostaje `ruleset: {id, version, sha256}`. `docs/RULES.md` jest sprawdzany testem względem rejestru (każda reguła opisana, żadna zbędna).
3. **Raport HTML (D3):** jedna funkcja renderująca; każda wartość z raportu przechodzi przez jedno miejsce escapowania (pomocnik budujący komórki i elementy; w szablonie nie ma interpolacji surowej wartości). CSP w `<meta http-equiv>`: `default-src 'none'; style-src 'sha256-…'; base-uri 'none'; form-action 'none'` — skrót liczony z jedynego bloku `<style>`, bez skryptów, bez zewnętrznych zasobów i bez atrybutów `style`. Test XSS obejmuje **każdy** liść tekstowy raportu (przejście po pełnym raporcie z syntetycznej analizy wszystkich źródeł, podstawienie znacznika w każde pole). Znacznik XFAIL CSP zostaje zdjęty.
4. **Redakcja (B8) w jednym miejscu:** teksty swobodne trafiające do raportu (atrybuty tekstowe obserwacji poza polami strukturalnymi, `reason`, zdarzenia osi czasu, luki) przechodzą przez `redact.redact` **przy budowie modelu**, przed wyliczeniem identyfikatorów treściowych, więc `id` pozostają spójne, a raport przechodzi walidację. Pola strukturalne (identyfikatory, skróty, enumy, czasy, ścieżka względna, `location`) nie są redagowane. Redakcja jest idempotentna. Query string w `uri` z logu nadal jest usuwany w całości (ostrzej niż B8, decyzja M4).
5. **Pseudonimizacja (B8):** flaga `--pseudonymize` zastępuje adres IP klienta i login konta pseudonimem `ip-<10 hex>` / `user-<10 hex>` z HMAC-SHA256 z kluczem losowanym (`secrets`) na jedno uruchomienie i **nigdzie nie zapisywanym**. Ta sama wartość w jednym uruchomieniu daje ten sam pseudonim (korelacja wewnątrz raportu działa), między uruchomieniami pseudonimy się różnią — stąd test odtwarzalności S-18 dotyczy trybu domyślnego. Skrót bez klucza (np. z `case_id`) odrzucony: przestrzeń IPv4 da się przeliczyć w całości. Bez flagi raport HTML i wyjście CLI ostrzegają, że raport zawiera dane osobowe (IP, loginy). `case.json` dostaje `flags.pseudonymize`.
6. **Pliki wyniku (R-40):** obok `report.json`, `report.html`, `case.json` powstają widoki tego samego raportu: `evidence-manifest.json`, `observations.jsonl`, `findings.json`, `timeline.json`, `coverage.json` (pokrycie, luki, `scope_complete`) i `run.log` (wersja narzędzia, sprawa, czasy, liczniki per źródło, kod wyjścia; bez treści dowodów i bez ścieżek hosta). Wszystkie wyliczane z raportu, zapisywane tą samą ścieżką `report._publish`; `report.json` pozostaje źródłem prawdy. `case.json` dostaje opcjonalne `outputs: {plik: sha256}`.
7. **Poza M5:** agregacja powtórzonych zdarzeń HTTP i suppressions (spec §9.3, R-76), podpis raportu i `report verify`, tryb `client-safe` (spec §11).

## Konsekwencje

- Cztery niezależne gałęzie: `agent/T-501-rules`, `agent/T-501-html`, `agent/T-501-privacy`, `agent/T-501-outputs`; potem przegląd bezpieczeństwa redakcji i HTML oraz dokumentacja M5.
- `--pseudonymize` ustala odtwarzalność tylko w obrębie uruchomienia; operator potrzebujący porównania dwóch przebiegów uruchamia bez flagi.
- Rollback: revert commitów; stare `case.json` pozostają poprawne.
