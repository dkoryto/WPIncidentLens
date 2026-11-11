# WPIncidentLens — START HERE (handoff do senior developera)

**Pakiet dokumentacyjny; nie zawiera nowo tworzonej aplikacji ani uruchomionego serwisu.**

## Co przeczytać
1. `WPIncidentLens_Specyfikacja_Senior_PoC_2026-11-09.docx` — dokument główny, 22 strony, gotowy do przeglądu i redakcji.
2. `WPIncidentLens_Specyfikacja_Senior_PoC_2026-11-09.md` — wersja źródłowa Markdown dla repozytorium, PR i agentów kodujących.
3. W dokumencie głównym rozdziały 0, 1, 3, 4, 10, 13, 14 i 19 — kontrakt projektu, bezpieczeństwo, kamienie milowe, testy i prompty.

## Zatwierdź przed jakimkolwiek generowaniem kodu
- Granice PoC: offline, katalog WordPress + baza + logi, single-site, bez AI i GUI.
- Import danych: regularne pliki, limity, niezmienność źródeł, SHA-256.
- Baza: bez wykonywania SQL, tylko zakres parsera jawnie przetestowany; kontrolowany JSONL dla deterministycznego testowania.
- Status `INCONCLUSIVE`, `NO_INDICATORS_IN_ANALYZED_SCOPE` i `STRONG_INDICATORS` z jasną semantyką.
- Bezpieczeństwo: niezaufane parsery, brak sieci, kontener bez uprawnień, XSS/secret redaction.
- Schematy JSON, fixture plan, bramki GO/NO-GO i odpowiedzialność seniora za review.

## Najbardziej ryzykowne założenia
1. Parser dumpów SQL w sposób cichy pomija część danych.
2. Heurystyka zostaje przedstawiona jako dowód włamania.
3. Nieufny materiał powoduje odczyt pliku spoza katalogu lub wykonanie kodu.
4. Raport ujawnia tokeny lub dane użytkowników albo wykonuje JS z dowodów.
5. Ktoś uruchamia prototyp na produkcyjnym serwerze i myli go z narzędziem DFIR w pełni zwalidowanym.

## Co oznacza finalny PoC
PoC pokazuje demonstrację na kontrolowanych danych syntetycznych, z testami pozytywnymi, negatywnymi i adversarialnymi. **Nie jest to potwierdzona gotowość produkcyjna ani prawdziwe śledztwo cyfrowe**.

**Data specyfikacji:** 9 listopada 2026. **Nowy kod podczas tej rundy:** nie tworzono.
