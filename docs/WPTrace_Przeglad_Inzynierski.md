# WPTrace — przegląd inżynierski / decyzja techniczna

**Data:** 9.11.2026 · **Werdykt:** GO dla kontrolowanego PoC; NO-GO dla produkcji i automatycznej oceny „strona bezpieczna”.

## Co zostało wykonane

Dostarczono dokumentację obejmującą architekturę, wymagania, model danych, threat model, reguły detekcji, przetwarzanie plików/SQL/logów, bezpieczeństwo, testy, roadmapę i kryteria akceptacji. Dodatkowo działa minimalny CLI Python, analizujący wyłącznie próbki syntetyczne. Testy lokalne: **6 PASS**; w fikcyjnym scenariuszu wykryto **6 sygnałów**, utworzono raport HTML, JSON, manifest SHA-256 oraz orientacyjną oś czasu. Nie wykonano testu Dockera (brak uruchomienia Docker Engine w tym środowisku).

## Ocena gotowości

| Obszar | Aktualny stan | Decyzja |
|---|---|---|
| Przepływ ingest → reguły → raport | Działa na danych syntetycznych | GO — demo |
| Połączenie danych plik–log | Działa dla prostego przypadku | GO — demo |
| Analiza rzeczywistych dumpów SQL | Obsługuje wybrane INSERT, liczne ograniczenia | BLOKER P0 |
| Analiza realnego WordPressa | Brak YARA-X, official checksum, multisite, PHP serialization | BLOKER P1 |
| Prawidłowe utrwalanie dowodów | Manifest jest, brak pełnego chain of custody i ochrony TOCTOU | BLOKER P0 |
| Bezpieczeństwo kontenera | Compose z izolacją, ale nieprzetestowany runtime i nieprzypięty digest PoC | BLOKER P1 |
| Ocena skuteczności | Brak reprezentatywnego zbioru oznaczonych próbek | BLOKER P1 |

## Niezbędne rozszerzenia przed pełną aplikacją

1. **P0 — bezpieczny import:** deskryptory plików i ochrona przed podmianą ścieżki; limity przestrzeni/czasu; potwierdzenie niezmienności źródeł; poprawny mechanizm obsługi plików większych niż limit.
2. **P0 — parser danych:** streamingowy, testowany na eksportach MySQL/MariaDB z wieloma zestawami znaków, prefiksami i wtyczkami; każda nieobsłużona instrukcja zwiększa jawny `coverage_gap`.
3. **P0 — evidentiary model:** jednoznaczny identyfikator dowodu, numer linii/offset, wersja parsera i reguł, rozdzielenie surowego faktu od interpretacji.
4. **P0 — semantyka oceny:** brak alertów nie może oznaczać „nie zhakowana”; wysoki wskaźnik niepewności przy niepełnym materiale.
5. **P1 — moduły WordPress:** oficjalne checksumy z poprawną wersją i locale, premium/mu-plugins, dynamiczne prefiksy, multisite, PHP serialized usermeta/options.
6. **P1 — sygnatury:** YARA-X z przetestowanymi i audytowanymi licencyjnie regułami, analiza FP/FN i aktualizacje podpisanych paczek.
7. **P1 — logi i chronologia:** Nginx/Apache JSON/custom, rotacje, różne strefy czasu, zegary, korelacja z WAF/serwerem; nie przypisywać automatycznie przyczyny.
8. **P1 — bezpieczeństwo i prywatność:** hardened Docker z pinem obrazu, SBOM, fuzzing parserów, CSP/escaping, redakcja danych osobowych, retencja i kontrola dostępu.

## Testy wymagane do wydania 1.0

- Minimum pięć scenariuszy pozytywnych i pięć negatywnych, w tym legalne skrypty analityczne, konta adminów i aktualizacje.
- Testy parserów na zrzutach różnych wersji MySQL/MariaDB i formatach hostingowych.
- Symlinki, race/TOCTOU, podmiana plików podczas skanowania, bardzo duże wejścia, uszkodzony Unicode, XSS w raportach, niepoprawny SQL.
- Reprodukowalność raportów dla tej samej wersji reguł; niezmienność dowodów; brak komunikacji sieciowej w trybie offline.
- Pilotaż na danych zanonimizowanych, po uzyskaniu zgody właścicieli i ręcznej weryfikacji ustaleń.

## Rekomendacja architekta

Nie zaczynać od GUI i AI. Najpierw dokończyć **offline evidence engine** z wiarygodnym modelem pochodzenia danych i jakościową analizą WordPress-specific. Rozwijać modułowo, mierzyć prawdziwe false-positive/false-negative, nie obiecywać usuwania malware i nie korzystać z niezweryfikowanych dumpów przez uruchamianie ich na produkcyjnym DB.

**Ostateczna decyzja:** PoC jest wystarczająco realny, by kontynuować rozwój. Produkcyjna aplikacja wymaga istotnych rozszerzeń P0/P1; obecne sześć testów i syntetyczny incydent dowodzą przepływu, nie skuteczności śledczej.
