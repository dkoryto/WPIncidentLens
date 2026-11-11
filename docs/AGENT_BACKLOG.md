# WPIncidentLens — backlog do vibe codingu (2026-11-11)

## Punkt startowy

Pierwsze zadanie: [T-001: baseline, packaging i CI](https://github.com/dkoryto/WPIncidentLens/issues/1). Następnie T-002 oraz T-003. Każde zadanie realizować w osobnym PR bez auto-merge. Pełny prompt startowy znajduje się w [MASTER_AGENT_PROMPT.md](MASTER_AGENT_PROMPT.md).

| Kolejność | Issue | Etap | Priorytet | Zależności / bramka |
|---|---|---|---|---|
| 1 | [T-001](https://github.com/dkoryto/WPIncidentLens/issues/1) | M0 | P0 | brak; **zacząć teraz** |
| 2 | [T-002](https://github.com/dkoryto/WPIncidentLens/issues/2) | M0 | P0 | przegląd człowieka przed SecureIngest |
| 3 | [T-003](https://github.com/dkoryto/WPIncidentLens/issues/3) | M0 | P0 | bazowe testy |
| 4 | [T-101](https://github.com/dkoryto/WPIncidentLens/issues/4) | M1 | P0 | zatwierdzony T-002 |
| 5 | [T-102](https://github.com/dkoryto/WPIncidentLens/issues/5) | M1 | P0 | kontrakty i ADR |
| 6 | [T-201](https://github.com/dkoryto/WPIncidentLens/issues/6) | M2 | P0 | M1 |
| 7 | [T-301](https://github.com/dkoryto/WPIncidentLens/issues/7) | M3 | P0 | M1 |

Kolejne zaplanowane zadania: T-401 (logi, UTC, korelacja), T-501 (reguły i raporty), T-601 (QA/hardening), T-701 (release candidate + GO/NO-GO), T-801 (projekt lokalnego GUI dopiero po M7). Harmonogram to szacunek; każda bramka wymaga faktycznych dowodów testowych.

## Techniczne przypomnienia

- Istniejący raport `schema_version=0.1.0` nie spełnia docelowego modelu `poc-1`; wprowadzać zmianę z migracją i testami.
- `wpincidentlens/cli.py` jest monolitem; refaktoryzacja stopniowa, nie rewrite „w jednym PR”.
- Logi i SQL są celowo obsługiwane częściowo. Każde pominięcie musi być raportowane jako coverage gap.
- 6 historycznie zaliczonych testów i syntetyczne fixtures nie dowodzą gotowości bezpieczeństwa.
- Bez realnych dowodów, sekretów, automatycznych zmian produkcyjnych, sieci w runtime i niezweryfikowanego stwierdzenia „clean”.
