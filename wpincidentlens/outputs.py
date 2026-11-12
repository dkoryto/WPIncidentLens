"""Widoki wyniku (R-40, ADR 0008 pkt 6): pliki wyliczane z jednego słownika raportu ``poc-1``.

``report.json`` pozostaje źródłem prawdy; każdy widok to dosłowna kopia jego części, bez nowych faktów.
Moduł nie dotyka plików: zwraca nazwy i bajty, a zapisuje je ``report.write`` jednym ``_publish``.

Kształty (każdy widok JSON ma ``schema_version`` i ``case_id`` raportu, więc da się go odczytać bez ``report.json``):

- ``evidence-manifest.json`` — ``{"schema_version": "evidence-manifest-poc-1", "case_id", "evidence": [...]}``;
  ``evidence`` jak w raporcie: identyfikator, ścieżka logiczna, status odczytu, SHA-256, rozmiar.
- ``observations.jsonl`` — jedna obserwacja raportu na wiersz, w kolejności raportu, bez nagłówka (każdy wiersz to
  dokładnie element ``observations``); wersję i sprawę podają pozostałe widoki i ``case.json`` (``outputs``).
  Zapis wyłącznie w ASCII (``ensure_ascii``): U+2028, U+2029 i U+0085 z dowodów, które ``str.splitlines`` uznaje za
  koniec wiersza, trafiają do pliku jako ``\\uXXXX`` i nie mogą rozciąć wiersza na sfałszowane rekordy.
- ``findings.json`` — ``{"schema_version": "findings-poc-1", "case_id", "findings": [...]}``.
- ``timeline.json`` — ``{"schema_version": "timeline-poc-1", "case_id", "timeline": [...]}``.
- ``coverage.json`` — ``{"schema_version": "coverage-poc-1", "case_id", "assessment", "scope_complete", "coverage", "coverage_gaps"}``.
- ``run.log`` — wiersze JSON w ASCII o stałej liście kluczy (``RUN_KEYS``, ``COVERAGE_KEYS``): najpierw
  ``{"event": "run", ...}`` (narzędzie i wersja, sprawa, czas analizy, ocena, zakres, kod wyjścia, liczniki ustaleń,
  obserwacji, dowodów i luk), potem ``{"event": "coverage", "source", "status", "entries"}`` dla każdego źródła.
  Wartości pochodzą wyłącznie z pól strukturalnych (enumy, liczby, identyfikator sprawy, czas): bez treści dowodów,
  nazw plików, tekstu wyjątków i tekstów swobodnych (``reasons`` pokrycia i luki są tylko w ``coverage.json``).

Spójność: ``case.json`` jest zamieniany jako ostatni i podaje SHA-256 każdego z tych plików (``outputs``). Widok,
którego skrót nie zgadza się z ``case.json``, jest nieaktualny (pozostałość przerwanego lub wcześniejszego zapisu)
i nie należy go używać.
"""
from __future__ import annotations

import json

EVIDENCE_MANIFEST = "evidence-manifest.json"
OBSERVATIONS = "observations.jsonl"
FINDINGS = "findings.json"
TIMELINE = "timeline.json"
COVERAGE = "coverage.json"
RUN_LOG = "run.log"
VIEWS = (EVIDENCE_MANIFEST, OBSERVATIONS, FINDINGS, TIMELINE, COVERAGE, RUN_LOG)


def encode(text: str) -> bytes:
    """UTF-8; znak, którego nie da się zakodować (samotny surogat), dostaje postać ``\\uXXXX`` zamiast gubić cały plik."""
    return text.encode("utf-8", "backslashreplace")


def to_json(document: dict) -> bytes:
    return encode(json.dumps(document, indent=2, ensure_ascii=False))


def _view(kind: str, report: dict, **parts) -> bytes:
    return to_json({"schema_version": f"{kind}-poc-1", "case_id": report["case_id"], **parts})


RUN_KEYS = ("event", "tool", "tool_version", "case_id", "analyzed_at_utc", "assessment", "scope_complete", "exit_code",
            "findings", "observations", "evidence", "coverage_gaps")
COVERAGE_KEYS = ("event", "source", "status", "entries")


def _line(record: dict) -> str:
    return json.dumps(record, ensure_ascii=True) + "\n"


def run_log(report: dict, exit_code: int) -> str:
    """Dziennik przebiegu; ``report`` przeniesiony z 0.1.0 nie ma liczników wpisów (``entries`` = ``null``)."""
    run = {"event": "run", "tool": report["tool"], "tool_version": report["tool_version"], "case_id": report["case_id"],
           "analyzed_at_utc": report["analyzed_at_utc"], "assessment": report["assessment"],
           "scope_complete": report["scope_complete"], "exit_code": exit_code,
           **{name: len(report[name]) for name in ("findings", "observations", "evidence", "coverage_gaps")}}
    records = [run] + [{"event": "coverage", "source": source, "status": entry["status"], "entries": entry["entries"]}
                       for source, entry in report["coverage"].items()]
    return "".join(_line(record) for record in records)


def render(report: dict, exit_code: int) -> dict[str, bytes]:
    """Wszystkie widoki raportu jako ``{nazwa pliku: bajty}``, w kolejności ``VIEWS``."""
    observations = "".join(_line(item) for item in report["observations"])
    return {
        EVIDENCE_MANIFEST: _view("evidence-manifest", report, evidence=report["evidence"]),
        OBSERVATIONS: encode(observations),
        FINDINGS: _view("findings", report, findings=report["findings"]),
        TIMELINE: _view("timeline", report, timeline=report["timeline"]),
        COVERAGE: _view("coverage", report, assessment=report["assessment"], scope_complete=report["scope_complete"],
                        coverage=report["coverage"], coverage_gaps=report["coverage_gaps"]),
        RUN_LOG: encode(run_log(report, exit_code)),
    }
