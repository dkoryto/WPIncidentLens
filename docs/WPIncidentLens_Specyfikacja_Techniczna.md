# WPIncidentLens

**Specyfikacja techniczna, projekt architektury, plan wdrożenia i niezależny przegląd inżynierski**  
**Wersja:** 0.9 — dokument projektowy  |  **Data:** 9 listopada 2026  |  **Status:** gotowy do realizacji ograniczonego PoC; **niegotowy do wdrożenia produkcyjnego**

> **Misja.** WPIncidentLens pomaga administratorowi WordPressa ustalić, czy dostępne dane zawierają oznaki kompromitacji, jakie zmiany można wykazać i jak wiarygodne są poszczególne hipotezy. Narzędzie nie „certyfikuje czystości” witryny, nie zastępuje pełnego DFIR i domyślnie niczego nie naprawia.

## 1. Streszczenie wykonawcze i decyzja architektoniczna

Projekt ma uzasadnioną niszę: **offline-first, WordPress-specific incident triage** z łącznym analizowaniem plików, eksportu bazy, logów i metadanych. Sam skaner PHP nie stanowi przewagi. Przewagą może być spójna historia incydentu, reprodukowalne dowody i precyzyjne komunikowanie niewiedzy.

**Decyzja:** rozpocząć **PoC zakresu S0**. Nie sprzedawać go jako forensycznej certyfikacji ani wykrywacza wszystkich włamań. Wersję 1.0 dopuścić dopiero po spełnieniu bramek bezpieczeństwa, poprawności parserów i jakości wyników opisanych w rozdziale 13.

| Obszar | PoC S0 | Produkcja S1+ |
|---|---|---|
| Statyczne pliki | działające heurystyki i SHA-256 | oficjalne checksumy, YARA-X, polityka wyjątków, skalowanie |
| Baza danych | wybrane rekordy `INSERT` z SQL | zweryfikowany parser dumpów / kontrolowany ekstraktor; multisite; PHP serialization |
| Logi | Apache/Nginx combined | wiele formatów, rotacje, kompresja, timezone, korelacja sesji |
| Oś czasu | prosta lista mtime i wpisów logów | normalizacja UTC, niepewność czasu, relacje przyczynowe wyraźnie oddzielone |
| Raport | JSON + HTML | schemat wersjonowany, audyt, eksport PDF/STIX opcjonalnie |
| Bezpieczeństwo | kontener offline, bez wykonania PHP | hardening, supply chain, testy adversarial, polityka retencji |

## 2. Problem, użytkownicy, scenariusze

### 2.1 Problem

Po ataku na WordPressa administrator dostaje niekompletne i nierównej jakości materiały: kopię plików, częściowy zrzut MySQL, logi HTTP, czasem backup sprzed incydentu. Wykrycie jednego pliku malware nie odpowiada na pytania o początek zdarzenia, zmiany w bazie, utrzymanie dostępu, zakres i czas. Zwykłe skanery sygnatur nie łączą wiarygodnie tych dowodów.

### 2.2 Persona i use cases

- **UC-01 Reakcja na zgłoszenie:** agencja otrzymuje wiadomość o przekierowaniach sklepu WooCommerce; bez uruchamiania strony pobiera kopię i wykonuje ocenę przesiewową.
- **UC-02 Weryfikacja po oczyszczeniu:** administrator porównuje kopię przed i po odtworzeniu z zaufanego źródła; zapisuje nierozstrzygnięte odchylenia.
- **UC-03 Obsługa wielu witryn:** firma hostingowa generuje powtarzalny, ograniczony do odczytu raport dla klienta (dopiero w S1+).
- **UC-04 Analiza retrospektywna:** analityk koreluje historyczne logi, podejrzane pliki i aktywność kont; nie wnioskuje o przyczynowości tylko z bliskości czasowej.

### 2.3 Nie-cele v1

Nie: aktywny pentest, eksploitacja podatności, skanowanie internetu bez upoważnienia, dezynfekcja na produkcji, samodzielne przywracanie kopii, analiza pamięci RAM, odzyskiwanie usuniętych śladów z systemu plików, gwarancja wykrycia każdego włamania, ustalanie sprawcy, automatyczne orzeczenia prawne.

## 3. Wymagania funkcjonalne — kryteria akceptacji

| ID | Funkcja | Wymaganie i test akceptacyjny | Etap |
|---|---|---|---|
| FR-01 | Bezpieczny import | Katalog, SQL i logi wskazywane jawnie; symlinki i pliki specjalne nie są wykonywane ani automatycznie śledzone; każda odmowa jest raportowana. | S0 |
| FR-02 | Manifest dowodowy | SHA-256 i rozmiar każdego skutecznie odczytanego pliku; identyfikator sprawy, data UTC, wersja analizatora. | S0 |
| FR-03 | Sygnały PHP | Heurystyki plików wykonywalnych w `uploads` i podejrzanych wzorców; z rozróżnieniem „podejrzane” vs „potwierdzone”. | S0 |
| FR-04 | Analiza administratorów | Identyfikacja ról z `*_users` i `*_usermeta`; alarm o **nowym** adminie wyłącznie względem jawnej, zaufanej listy/migawki. | S0 |
| FR-05 | Opcje WP | Sygnały potencjalnej iniekcji HTML/JS w opcjach; nie drukować haszy haseł ani pełnych danych osobowych. | S0 |
| FR-06 | Logi | Parsowanie wejścia HTTP z polem `timestamp`, IP, metoda, URL, status; wejście niepasujące do formatu jako luka pokrycia. | S0 |
| FR-07 | Korelacja | Wskazanie, że żądanie HTTP dotyczy tego samego podejrzanego pliku; korelacja nie oznacza wykonania kodu. | S0 |
| FR-08 | Raporty | `report.json` oraz bezpiecznie escapowany HTML, identyczna lista ustaleń i ograniczeń. | S0 |
| FR-09 | Integralność WP | Opcjonalne manifesty bazowe oraz porównanie core/pluginów wg wersji i locale; kategoria nieobsługiwanej wtyczki. | S1 |
| FR-10 | YARA-X | Oddzielne paczki wersjonowanych reguł, testy FP, podpisana lub haszowana wersja paczki. | S1 |
| FR-11 | Parsowanie SQL | Pełne, kontrolowane przetwarzanie obsługiwanych form dumpów, prefiksy i serializowane wartości; błędy nie mogą oznaczać „czysto”. | S1 |
| FR-12 | Monitoring | Różnice pomiędzy migawkami i powiadomienia; bez ingerencji w forensyczne dane źródłowe. | S2 |

### 3.1 Reguła biznesowa, której nie wolno złamać

Brak alertów daje **`NO_INDICATORS_IN_ANALYZED_SCOPE`**, nigdy „NOT_COMPROMISED” ani „SAFE”. Brak logów, nieobsługiwany dump, niedostępny checksum lub przekroczone limity skutkują jawnym polem `coverage_gaps` i potencjalnie statusem `INCONCLUSIVE` w S1.

## 4. Architektura logiczna

```text
ŹRÓDŁO (kopia offline / backup / spakowany zbiór)
    │
    ├── Katalog WordPressa ─────┐
    ├── Zrzut bazy MySQL ───────┤  tylko odczyt; brak wykonania PHP/SQL
    └── Logi serwera ──────────┘
                │
    [Ingest & Evidence Manifest]
          SHA-256 + case ID + coverage
                │
      [Normalized Evidence Model]
          plik / rekord DB / log
                │
     ┌──────────┼────────────┐
     │ File     │ Database   │ HTTP Log
     │ Analyzers│ Analyzers  │ Parsers
     └──────────┼────────────┘
                │
         [Rules + Findings]
                │
     [Correlation & Timeline]
                │
   [Assessment + Coverage + Report]
                │
        JSON / HTML / PDF później
```

**Zasada architektoniczna:** odseparować *surowe dowody* od *zinterpretowanych znalezisk*. Każdy wynik ma odsyłać do niezmiennego `evidence_id` oraz identyfikatora reguły. Silnik korelacji operuje na ustandaryzowanych zdarzeniach, a nie na przypadkowych ciągach z logu.

### 4.1 Moduły i interfejsy

1. **Ingest:** walidacja ścieżek, manifest SHA-256, zliczenie odrzuconych danych, limity rozmiarów.
2. **CoreChecksums:** dopasowanie `version` + `locale` do oficjalnych sum WordPressa; wersja manifestu i URL pochodzenia; weryfikacja nie modyfikuje wejścia.
3. **PluginChecksums:** oficjalne repozytorium WordPress.org; wtyczki premium lub lokalne oznaczane `NO_TRUSTED_REFERENCE`, a nie podejrzane automatycznie.
4. **YaraAdapter:** skanowanie kopii statycznych, limity czasu i pamięci, reguły walidowane przy starcie, osobne kategorie malware/heurystyka.
5. **DatabaseExtractors:** `*_users`, `*_usermeta`, `*_options`, `*_posts`, `*_postmeta`, tabele dodatkowe; serializacja PHP jako dane, bez `unserialize` w PHP.
6. **LogParsers:** daty strefowe, proxy i rotacje, normalizacja UTC, zachowanie surowego timestampu.
7. **Correlator:** łączenie po znanej ścieżce / identyfikatorze / rekordzie; brak nieudowodnionych relacji przyczynowych.
8. **Reporter:** wyniki, źródła, ograniczenia, rekomendacje, tryb anonimizacji.

### 4.2 Kontrakt CLI — docelowy

```bash
wpincidentlens analyze \
  --case-id CASE-2026-0042 \
  --files /evidence/wordpress \
  --database /evidence/database.sql \
  --logs /evidence/logs \
  --baseline /evidence/trusted-baseline.json \
  --output /results/CASE-2026-0042 \
  --offline
```

**Exit codes, wersja docelowa:** `0` — analiza kompletna (niezależnie od alertów); `2` — niepoprawna konfiguracja; `3` — analiza częściowa; `4` — nieprzetworzony materiał krytyczny; `5` — błąd wewnętrzny. Nie używać kodu wyjścia jako oceny kompromitacji.

## 5. Model danych i dowodowość

### 5.1 Główne encje

| Encja | Minimalne pola | Uwagi |
|---|---|---|
| Case | `case_id`, `created_at_utc`, `analyst`, `tool_version`, `rulepack_digest` | Identyfikacja analizy |
| Evidence | `evidence_id`, `source_path`, `sha256`, `size`, `acquired_at`, `acquisition_method` | Manifest nie jest sam w sobie pełnym chain of custody |
| Observation | `observation_id`, `evidence_id`, `offset/line`, `observed_time`, `time_basis`, `parser_version` | Surowy wyciąg danych |
| Finding | `rule_id`, `severity`, `confidence`, `observations[]`, `reason`, `mitigation` | Rozdzielić wagę od pewności |
| TimelineEvent | `timestamp_utc`, `precision`, `clock_source`, `supporting_observations[]` | Umożliwić brak daty |
| Coverage | `source`, `parsed_records`, `skipped_records`, `reason`, `coverage_status` | Klucz do uczciwego podsumowania |

### 5.2 Przykład wyniku JSON

```json
{
  "schema_version": "1.0",
  "case_id": "CASE-2026-0042",
  "assessment": "SUSPICIOUS",
  "findings": [
    {
      "rule_id": "WP-FILE-001",
      "severity": "high",
      "confidence": "medium",
      "title": "PHP w katalogu uploads",
      "observations": ["obs-file-382", "obs-http-101"],
      "interpretation": "Podejrzany artefakt i żądanie do niego; wykonanie niepotwierdzone"
    }
  ],
  "coverage": {"files": "analyzed", "database": "partial", "logs": "partial"},
  "coverage_gaps": ["Brak rotowanych logów sprzed 7 dni"]
}
```

Ten kontrakt opisuje **docelowy model S1**. W dołączonym PoC schemat ma numer `0.1.0` i uproszczone pola; nie należy mylić ich kompatybilności.

### 5.3 Dowody i łańcuch przechowywania

- Manifest źródeł obliczyć w chwili przyjęcia i ponownie porównać przed raportem; źródło, operator, miejsce, czas UTC i metoda pozyskania w `case.json`.
- Nie polegać wyłącznie na `mtime` pliku: można je zmienić. `mtime`, `ctime`, `birthtime` (jeśli dostępny), log HTTP oraz czas backupu to osobne obserwacje.
- Nie kopiować plików po uprzednim uruchomieniu przejętego WordPressa; zakładać, że dane mogą być zmanipulowane.
- Dla danych poufnych: szyfrowanie nośnika, oddzielne ACL, retencja, kontrola dostępu i redakcja raportów. Unikać wysyłania plików do publicznych API.
- Własny manifest SHA-256 jest **dodatkowy** względem oficjalnego mechanizmu WordPress MD5 (porównanie integralności wersji); tych funkcji nie wolno utożsamiać.

## 6. Detekcje: reguły, pewność, klasyfikacja

### 6.1 Minimalny katalog reguł

| Reguła | Źródło | Sygnał | Typowe FP / uwaga |
|---|---|---|---|
| WP-FILE-001 | filesystem | PHP w `wp-content/uploads` | Legalne, choć ryzykowne implementacje; nie przesądza |
| WP-FILE-002 | filesystem | Niezgodność z podpisaną/zaufaną migawką | Aktualizacja lub edycja administracyjna |
| WP-FILE-003 | YARA | Sygnatura webshella / obfuskacji | W zależności od jakości reguły i kontekstu |
| WP-DB-001 | DB | Nowe uprzywilejowane konto względem znanej listy | Autoryzowane dodanie przez właściciela |
| WP-DB-002 | DB | Zmiana `active_plugins`, `siteurl`, `home`, `cron` względem baseline | Zwykła migracja / aktualizacja |
| WP-DB-003 | DB | Nieznany skrypt w HTML przechowywanym w opcjach/treściach | Analityka, reklamy, tag managers |
| WP-HTTP-001 | log | Żądanie do pliku PHP z `uploads` | Żądanie nie dowodzi uruchomienia |
| WP-CORR-001 | wiele | Ten sam ślad w pliku i żądaniu HTTP | Korelacja, brak dowodu wektora ataku |

### 6.2 Mechanizm oceny

Stosować **dwuwymiarową** ocenę: `severity` (potencjalny skutek) oraz `confidence` (pewność ustalenia). Nie wyliczać pseudo-procentów z arbitralnych wag. `Compromised` tylko przy zweryfikowanym, mocnym dowodzie; w praktyce raportować: `NO_INDICATORS_IN_ANALYZED_SCOPE`, `SUSPICIOUS`, `STRONG_INDICATORS`, `INCONCLUSIVE`. Skala i zasady awansu statusu muszą mieć testy regresyjne.

**Szczególne przypadki:** sam `eval(` nie oznacza malware; sam nowy admin nie oznacza włamania; brak SHA względem niepewnej wersji core nie oznacza podmiany; wynik HTTP 200 nie potwierdza wykonania PHP; log z jednego serwera może być niekompletny albo modyfikowany.

## 7. Parser WordPressa: rzeczy trudniejsze niż wyglądają

### 7.1 Pliki i wersje

Core: wersja, locale i metadane aktualizacji muszą pochodzić ze źródeł możliwych do weryfikacji; nie ufać bezwarunkowo `wp-includes/version.php` w przejętej kopii. Core checksumy WordPress.org używają MD5; w praktyce służą do porównania z oficjalną dystrybucją, **nie** do dowodowego haszowania. Dla wtyczek WordPress.org dostępność sum nie jest uniwersalna. Premium, motywy własne, `mu-plugins`, `drop-ins`, pliki z generatorów i wyjątki muszą mieć osobną politykę.

Zmiany zalegalizowane przez aktualizację są nadal zmianami i powinny być widoczne w raporcie, ale odpowiednio oznaczone. Nie pobierać żadnych binariów i nie uruchamiać ich w sandboxie analitycznym.

### 7.2 Baza danych

Kluczowe pułapki: zmienne prefiksy (`$table_prefix`, nie zawsze `wp_`), wiele blogów w multisite, `wp_usermeta` z serializowanymi rolami, różne zestawy kolumn, nietypowe zestawy znaków, `INSERT` wielowierszowe, `REPLACE`, `INSERT ... ON DUPLICATE`, komentarze `/*!...*/`, `BLOB`, escapowanie MySQL, tabele WooCommerce i wtyczek.

**Wybrany kierunek produkcyjny:** przygotować bezpieczny, streamingowy ekstraktor o ściśle określonej gramatyce i testach kompatybilności z eksportami `mysqldump`, `mariadb-dump` i narzędziami hostingowymi. Nie wykonywać surowego SQL na głównym hoście. Opcjonalne odtworzenie w odrębnym silnie odizolowanym kontenerze tylko po audycie zagrożeń (triggerów, funkcji, `LOAD DATA`, parsera i ograniczeń zasobów). Dekoder serializacji PHP w Pythonie musi pracować tylko na strukturach danych, nigdy na obiektach wykonujących kod.

**Klasyfikacja, gdy nie ma baseline:** istniejące konta administratorów są inwentaryzacją, nie incydentem. Wykrycie „nowego konta” jest możliwe dopiero przy dostępnej wiarygodnej migawce lub audycie utworzenia.

### 7.3 Logi

Apache combined, Nginx custom, JSON, błędy PHP, WAF, reverse proxy i hosting mogą mieć różne formaty. Strefę logu przechować w oryginale i sprowadzać do UTC, odnotowując zegar oraz niepewność synchronizacji. W przypadku wielu reverse proxy nie wolno automatycznie ufać `X-Forwarded-For`; ustalać zaufane hop-y i źródła.

## 8. Bezpieczeństwo samego analizatora

WPIncidentLens przetwarza **niezaufane materiały po ataku**, zatem sam jest celem ataku. Model zagrożeń:

| Zagrożenie | Kontrola wymagana |
|---|---|
| Ucieczka poza katalog wejściowy | `openat2`/bezpieczne deskryptory; nie śledzić symlinków; zabezpieczyć race/TOCTOU |
| Zip bomb i pliki ogromne | Limit pliku, limit całego przypadku, limit rozpakowania, limity czasu i pamięci |
| Eksploit parsera SQL/YARA | Pinowanie i aktualizacje bibliotek, fuzzing, oddzielne procesy/parser workers |
| Złośliwy HTML w dowodach | Escape i CSP w raportach, brak renderowania zawartości jako HTML |
| Eksfiltracja przez komponent | Domyślnie brak sieci; integracje zewnętrzne oddzielić od silnika dowodowego |
| Wycieki haseł i PII | Redakcja, lokalne przechowywanie, niewypisywanie `user_pass` i sekretów |
| Podmiana reguł | Wersjonowanie paczek YARA i manifest SHA-256, podpisy w późniejszym etapie |
| Nadmierne uprawnienia | Non-root, read-only rootfs, wszystkie capabilities wyłączone, `no-new-privileges`, bez Dockera socket |
| Atak na UI raportu | Escape wejścia, zakaz inline JS, odpowiednia CSP, bez osadzania surowych fragmentów |

**PoC i środowisko produkcyjne to dwa różne profile bezpieczeństwa.** Projekt PoC zawiera Compose z izolacją podczas uruchomienia, ale bez weryfikacji obrazu, SBOM i zewnętrznego audytu nie wolno deklarować odporności produkcyjnej. Materiały mogą zawierać dane osobowe — przypisać odpowiedzialność, podstawę prawną i retencję zgodnie z polityką organizacji.

## 9. Wdrożenie i operacje

### 9.1 Topologia PoC

```text
HOST ANALITYKA
  WPIncidentLens (Python 3.12, CLI, kontener bez sieci)
    /evidence/files   (ro)
    /evidence/db.sql  (ro)
    /evidence/logs    (ro)
    /results           (rw, lokalne ACL)
```

Docker: `network_mode: none`, `read_only: true`, `cap_drop: ALL`, `no-new-privileges`, `user: 65532`, `tmpfs /tmp`, limity CPU/RAM/PID. W środowisku produkcyjnym pinować obraz po digest, skanować SBOM, weryfikować podpis/pochodzenie; żadnych sekretów w obrazie. Wdrożenie jest **analizą kopii**, nie pluginem aktywowanym w WordPressie.

### 9.2 Uruchomienie dołączonego PoC

```bash
cd WPIncidentLens_PoC
python -m pytest -q
python -m wpincidentlens \
  --files fixtures/site \
  --database fixtures/database.sql \
  --logs fixtures/logs \
  --baseline fixtures/baseline.json \
  --case-id DEMO-001 \
  --output results
```

Utworzone pliki: `results/report.json` i `results/report.html`. Dane laboratoryjne zostały celowo sfabrykowane; wynik jest demonstracją przepływu, nie miarą skuteczności na produkcji. W próbce powstaje sześć ustaleń, orientacyjna oś czasu oraz jedna jawna luka pokrycia parsera SQL. Dołączony Docker Compose powinien działać po skonfigurowaniu uprawnień wyjścia i weryfikacji obrazu w środowisku z Docker Engine. W bieżącym środowisku przetestowano wykonanie Pythona, nie runtime kontenera.

### 9.3 Uruchomienie produkcyjne — przed uruchomieniem

- Legalna autoryzacja do analizy konkretnej witryny, identyfikator sprawy, polityka retencji.
- Pozyskanie spójnego snapshotu katalogu i eksportu bazy z odpowiednią informacją o czasie; kopie logów rotowanych.
- Offline, z dedykowanym kontem analityka i separacją wyników poszczególnych klientów.
- Przegląd danych przed eksportem raportu dla klienta; wykluczenie danych osobowych niepotrzebnych do ustaleń.
- Weryfikacja raportu przez człowieka przed formalnym przekazaniem jako materiału powłamaniowego.

## 10. Konkurencja i własny wyróżnik

WP-CLI zapewnia oficjalną weryfikację checksumów core i wtyczek. PHP Malware Finder dostarcza reguły YARA wykrywające podejrzane wzorce PHP. YARA-X zapewnia Python API i limit czasu skanowania. Plaso jest rozwiniętym silnikiem timeline, którego **nie należy** bez potrzeby włączać jako ciężkiej zależności do pierwszego kontenera.

**Własna wartość WPIncidentLens:** model WordPressa, import niezaufanego materiału z jawnym pokryciem, powiązanie dowodów z plików/DB/logów, ergonomia raportów. Nie deklarować nowej kategorii produktu bez porównania z istniejącymi skanerami i usługami DFIR.

Ważne prawne/techniczne: zgodność reguł napisanych pod klasyczną YARA z YARA-X trzeba **zweryfikować testem kompilacji**. Reguły PHP Malware Finder są na licencji LGPL-3.0; decyzję o vendoringu, dystrybucji i atrybucji podjąć po audycie licencji. Nie kopiować cudzych reguł do repo bez przeanalizowania licencji.

## 11. Plan implementacji — repo i backlog

### 11.1 Repozytorium docelowe

```text
wpincidentlens/
  wpincidentlens/
    cli.py                  # kontrakty CLI
    ingest/                # dowody + ograniczenia
    file_analysis/         # manifest, core/plugin baseline, yara
    db_analysis/           # dump parser, WP semantic extractors
    log_analysis/          # log formats and time normalization
    correlation/           # facts and evidence links
    reports/               # JSON schema, HTML, PDF later
    models/                # typed evidence/events/findings
  rules/                   # curated, versioned rule packs
  schemas/                 # JSON Schema + migrations
  tests/
    unit/ integration/ fixtures/ negative/ fuzz/
  docs/                    # models, evidence policy, threat model
  docker/
  .github/workflows/
```

### 11.2 Etapy realizacji

| Etap | Zadania | Weryfikacja zakończenia |
|---|---|---|
| S0 — PoC przepływu | Python CLI, import kopii, proste heurystyki, raport, syntetyczne próbki, brak sieci | Demo end-to-end i testy regresji |
| S0.5 — parsery i model | Refaktoryzacja do modułów, schema JSON, offsety, wiarygodna oś czasu, parser SQL bez wykonywania | Testy na >= 5 wariantach dumpów i 4 formatach logów |
| S1 — detekcje | YARA-X z przetestowanymi regułami, checksumy core/plugin, baseline, analiza PHP serialization, rozszerzone reguły DB | Zbiór prawdziwych, zanonimizowanych prób ze znaną etykietą; mierzone FP/FN |
| S1 — hardening | Fuzzing, supply chain, SBOM, limitowanie zasobów, testy atakujące parsery, przegląd prywatności | Brak otwartych błędów P0/P1 z bezpieczeństwa |
| S1 — wydanie | Dokumentacja instalacji, migracje schematów, eksport raportów, release notes | Checklist i pilot z 3–5 administratorami |
| S2 — rozbudowa | GUI, monitoring, integracje Wazuh/hostingi, tryb wielokliencki, opcjonalne AI | Osobna decyzja i nowe zagrożenia modelu |

### 11.3 Propozycja priorytetów problemów

P0: bezpieczne czytanie plików + ochrona przed TOCTOU; poprawne traktowanie nieobsługiwanych danych; parser dumpów; wyciek sekretów; schemat wyniku i kompletność manifestu; zakaz fałszywego „czysto”.

P1: YARA-X i testy reguł; checksumy z dopasowaniem wersji; logi i czas UTC; bazowe scenariusze i baseline; korelacja z odnośnikami do dowodów; regresje i fuzzing.

P2: ergonomiczne GUI, wygodny eksport PDF, integracje, dashboard trendów i automatyczne powiadomienia.

## 12. Plan testów: jakość, bezpieczeństwo i wydajność

### 12.1 Testy funkcjonalne

| ID | Próbka | Oczekiwany wynik |
|---|---|---|
| T-01 | Zdrowa instancja lab z kompletną kopią | Brak alarmów; status **nie oznacza** „na pewno czysto” |
| T-02 | PHP z `eval(base64_decode())` w `uploads` | Heurystyczne alerty, odnośnik do dowodu |
| T-03 | Legalna wtyczka PHP poza `uploads` | Bez automatycznego uznania za malware |
| T-04 | Nieznany admin + zaufana lista kont | Alert odchylenia, nie potwierdzenie włamania |
| T-05 | Konto admin bez baseline | Inwentaryzacja, nie alert o kompromitacji |
| T-06 | SQL z własnym prefiksem tabel | Prawidłowy odczyt relacji ról do kont |
| T-07 | SQL z wielowierszowym INSERT, escapowaniem, binarką | Albo prawidłowa analiza, albo jawne `UNSUPPORTED` |
| T-08 | Podejrzany POST do PHP w uploads | Log + korelacja, brak twierdzenia o wykonaniu kodu |
| T-09 | Logi w dwóch strefach czasowych | Wspólne UTC i zachowanie oryginalnego czasu |
| T-10 | Przekierowanie symlinkiem poza materiał | Brak odczytu spoza dozwolonego katalogu |
| T-11 | Plik > limit / niespójne wejście | Jasna luka pokrycia, analiza nie może zwrócić „czysto” |
| T-12 | HTML w nazwie pliku lub polu DB | Brak XSS w raporcie |
| T-13 | Brak bazy i logów | Jawna niekompletność; poprawnie ograniczona ocena |
| T-14 | Normalna aktualizacja WordPressa | Zmiany oznaczone, ale bez przypisania im automatycznie ataku |

### 12.2 Testy bezpieczeństwa i wydajności

- Fuzzing parsera SQL, dekodera serializacji PHP, logów i wejściowych struktur JSON; limit czasu per parser i całkowity.
- Testy archiwów z traversal/zip bomb (jeśli import ZIP zostanie dodany; nie w PoC).
- Testy odmowy dostępu do sieci, plików hosta i socketu Docker.
- Testy wierności manifestu SHA-256 przed/po skanowaniu; sprawdzić, czy skaner nie zmienił żadnego bajtu źródeł.
- Zbiór negatywnych przypadków: legalne wtyczki, motywy premium, skrypty analityczne, importy WP i aktywne mu-plugins.
- Cele **proponowane, niezmierzone**: dla kopii 5 GB i SQL 1 GB czas do 15 min na 4 vCPU/8 GB RAM po zdefiniowaniu profilu testowego; ograniczenia pamięci 1 GB dla podstawowego worker-a; brak połączeń wychodzących przy `--offline`.

### 12.3 Mierniki gotowości

Wymagane: 100% pokrycie jawnych błędów importu (żadnego cichego „OK”); zero nieautoryzowanych modyfikacji danych; odtwarzalność wyników przy tych samych wejściach i wersji reguł; przegląd wszystkich alertów klasy HIGH przez analityka. Precyzja/czułość reguł dopiero po stworzeniu oznaczonego zbioru testowego, **bez wymyślania procentów**.

## 13. Niezależny przegląd inżynierski

### 13.1 Czy wcześniejsza koncepcja nadawała się do implementacji?

**Tak — jako zarys architektury i POC. Nie — jako kompletna specyfikacja produktu.** Oryginalny pomysł „Docker + Python + YARA-X + checksumy + analiza bazy + raport” poprawnie definiował kierunek, ale nie rozwiązywał najtrudniejszych problemów: niezaufanego importu danych, zmienności dumpów, bezpiecznego dekodowania serializacji PHP, dowodowości, opisu braków danych, wersjonowania reguł i miarodajności ocen.

### 13.2 Wyniki przeglądu — ryzyka i decyzje

| Priorytet | Problem projektu | Konsekwencja | Wymagana zmiana |
|---|---|---|---|
| P0 | „Skan plików i SQL” bez modelu zaufania | Fałszywe wnioski po ataku, możliwość skażenia materiału | Warstwa ingest, immutable evidence, manifest i provenance |
| P0 | Zbyt prosty parser SQL | Pominięcie zapisów lub błędne przypisanie ról/treści | Parser z deklarowaną gramatyką, testy wariantów, kompletność |
| P0 | Brak dowodowego odniesienia każdej tezy | Raport nieprzydatny do obrony ustaleń | `observation_id`, `evidence_id`, source offset/line |
| P0 | Brak rozróżnienia „nie wykryto” vs „nie zbadano” | Fałszywe poczucie bezpieczeństwa | Coverage matrix i `INCONCLUSIVE` |
| P0 | Niezaufany kod/log jako dane wejściowe | RCE/DoS/XSS we własnym silniku | Bezpieczny IO, sandbox, fuzzing, limity, raport escaping |
| P1 | Niejasny status checksum MD5 | Mylenie porównania z oficjalną wersją z integralnością dowodową | Użyć SHA-256 w manifestach, MD5 wyłącznie do core/plugin reference |
| P1 | Reguły PHP Malware Finder i YARA-X | Błędy kompatybilności, licencje | Testy kompilacji i audyt licencji reguł |
| P1 | Mtime i żądania HTTP jako „wektor ataku” | Niepoprawna rekonstrukcja | Niepewność czasów, oddzielenie korelacji od przyczynowości |
| P1 | Brak testów dla premium/multisite/WooCommerce | Słabe pokrycie typowego WordPressa | Matryca wsparcia, dobre próbki, wersje pluginów |
| P2 | LLM jako sędzia kompromitacji | Halucynacje i prompt injection ze śladów | LLM tylko do omówienia już ustalonych dowodów, po redakcji |

### 13.3 Przegląd faktycznie uruchomionego PoC S0

**Zrealizowane i przetestowane lokalnie:** CLI w Pythonie 3.12; statyczny odczyt plików, dumpu `INSERT` i logów combined; manifest SHA-256; kilka heurystyk; korelacja plik–żądanie; HTML i JSON; 6 testów automatycznych. Syntetyczny przypadek demonstracyjny wykazuje 6 sygnałów. Testy nie używają kodu malware i nie uruchamiają PHP.

**Niezrealizowane (celowo):** YARA-X, oficjalne checksumy WordPressa, pełny parser SQL, obsługa multisite, serializacji PHP, autentykacja kontenerowej kompilacji, chain of custody, eksport PDF, korelacja rzeczywistych sesji, hardening produkcyjny, pełna matryca testów, performance. **Nie jest to gotowy produkt do analiz prawnych ani odpłatnej usługi DFIR.**

**Uwaga o Dockerze:** definicja Compose została przygotowana; w tej sesji nie uruchamiano Docker Engine. Fakt działania Python CLI nie stanowi testu uruchomienia kontenera. Trzeba jeszcze sprawdzić prawa montowań, pin digest i zależności na rzeczywistym Linux/macOS/Windows.

### 13.4 Werdykt GO/NO-GO

| Cel | Decyzja | Uzasadnienie |
|---|---|---|
| Demonstracja na danych syntetycznych | **GO** | Przetwarzanie end-to-end i testy są wykonane |
| Udostępnienie repo jako eksperymentalnego open source | **GO z oznaczeniem PoC** | Wskazać ograniczenia i brak gwarancji bezpieczeństwa |
| Analiza realnej witryny na potrzeby wskazówek administratora | **Warunkowo, po przeglądzie danych** | Możliwe pominięcia i false positive/false negative |
| Publiczna usługa analizy dla klientów | **NO-GO** | Brak kompletności, audytu bezpieczeństwa i procesu ochrony danych |
| Wnioskowanie „strona nie jest zhakowana” | **NO-GO** | Nie da się dowieść braku kompromitacji ze skończonego zbioru sygnałów |

## 14. Plan pierwszego pilota i kryteria „gotowe”

1. Przygotować pięć **syntetycznych** scenariuszy: czysty WP, plik PHP w uploads, nadużycie roli, wstrzyknięta zawartość opcji, tylko logi bez pliku.
2. Dodać trzy testy fałszywych alarmów: legalna analityka JS, wtyczka premium, aktualizacja core.
3. Przygotować dwa formaty dumpu i dwa formaty logów z jawnie odnotowanymi brakami.
4. Zmienić PoC z funkcji demonstracyjnej na schemat `Observation -> Finding`, przeprowadzić review IO i testy fuzz.
5. Zmierzyć wyniki, uruchomić w Dockerze i potwierdzić niezmienność danych wejściowych.
6. Poprosić 3 administratorów WordPressa o ocenę przydatności raportów na anonimowych danych laboratoryjnych.

**Definition of Done PoC:** jedna komenda, reprodukowalny wynik, testy automatyczne i dokumentacja ograniczeń. **Definition of Done S1:** udokumentowany model dowodowy, kompletne pokrycie wspieranych formatów, utwardzony pipeline, testy negatywne i pilotaż z ręczną walidacją.

## 15. Źródła i decyzje wynikające z dokumentacji

1. **WordPress: weryfikacja core checksum** — [developer.wordpress.org/cli/commands/core/verify-checksums](https://developer.wordpress.org/cli/commands/core/verify-checksums/); porównanie z oryginalną wersją, odpowiedni locale, brak wykonania WordPressa przez tę komendę.
2. **WordPress: checksumy wtyczek** — [developer.wordpress.org/cli/commands/plugin/verify-checksums](https://developer.wordpress.org/cli/commands/plugin/verify-checksums/); dostępność zależna od wtyczki z WordPress.org.
3. **WordPress: get_core_checksums** — [developer.wordpress.org/reference/functions/get_core_checksums](https://developer.wordpress.org/reference/functions/get_core_checksums/); źródło API WordPress.org.
4. **WordPress: prefix DB** — [developer.wordpress.org/advanced-administration/wordpress/wp-config](https://developer.wordpress.org/advanced-administration/wordpress/wp-config/); `$table_prefix` jest konfigurowalny.
5. **YARA-X Python API** — [virustotal.github.io/yara-x/docs/api/python](https://virustotal.github.io/yara-x/docs/api/python/); kompilacja, skanowanie, timeout.
6. **PHP Malware Finder** — [github.com/nbs-system/php-malware-finder](https://github.com/nbs-system/php-malware-finder); reguły YARA, wskazana LGPL-3.0 i ograniczenia heurystyk.
7. **Plaso** — [plaso.readthedocs.io](https://plaso.readthedocs.io/en/latest/); rozbudowana analiza osi czasu jako inspiracja i ewentualna późniejsza integracja.
8. **NIST SP 800-86** — [csrc.nist.gov/pubs/sp/800/86/final](https://csrc.nist.gov/pubs/sp/800/86/final); metody nabywania i oceny integralności dowodów.
9. **NIST SP 800-61 Rev. 3** — [csrc.nist.gov/pubs/sp/800/61/r3/final](https://csrc.nist.gov/pubs/sp/800/61/r3/final); współczesny proces reagowania na incydenty.

---

**Ostateczny wniosek inżynierski:** WPIncidentLens ma wystarczająco konkretny problem, architekturę i małe jądro, by realizować ograniczony PoC. Przed wersją produkcyjną najważniejsze są bezpieczna i pełna ekstrakcja danych, jakość dowodów oraz jawne ograniczenia analizy — nie panel WWW ani AI.
