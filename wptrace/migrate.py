"""Migracja raportu 0.1.0 do ``poc-1`` (ADR 0002 D7, ADR 0003).

``migrate_0_1_0`` jest czystą funkcją: nie czyta i nie zapisuje plików, nie zmienia słownika wejściowego.
Stary raport nie niósł obserwacji, statusów odczytu ani pokrycia per źródło. Tych informacji nie zgadujemy:
ustalenia dostają obserwacje syntetyczne ``LEGACY_FINDING``, dowody i pokrycie znacznik ``UNKNOWN_LEGACY``,
a ocena jest przenoszona ostrożnie (nigdy na „brak wskaźników”).
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from . import models

LEGACY_VERSION = "0.1.0"
LEGACY_KIND = "LEGACY_FINDING"
MIGRATION_NOTE = ("Raport przeniesiony ze schematu 0.1.0: pokrycie źródeł i statusy odczytu dowodów są nieznane (UNKNOWN_LEGACY), "
                  "a obserwacje LEGACY_FINDING odtworzono z ustaleń starego raportu")
# Stary raport nie mówił, czy zakres był pełny, więc „brak wskaźników” nie może przetrwać migracji.
_ASSESSMENT = {"INDICATORS_FOUND": models.Assessment.SUSPICIOUS, "NO_INDICATORS_IN_ANALYZED_SCOPE": models.Assessment.INCONCLUSIVE}
_REQUIRED = ("schema_version", "tool", "tool_version", "case_id", "analyzed_at_utc", "assessment", "disclaimer",
             "findings", "coverage_gaps", "evidence_manifest")
_ORIGIN_OF_CATEGORY = {models.Category.FILE: models.OriginKind.FILE, models.Category.CORRELATION: models.OriginKind.FILE,
                       models.Category.HTTP_LOG: models.OriginKind.LOG, models.Category.DATABASE: models.OriginKind.SQL_DUMP}


class MigrationError(ValueError):
    """Wejście nie jest raportem 0.1.0, który da się przenieść bez zgadywania."""


def _object(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MigrationError(f"{where}: oczekiwano obiektu, jest {type(value).__name__}")
    return value


def _list(value: Any, where: str) -> list:
    if not isinstance(value, list):
        raise MigrationError(f"{where}: oczekiwano listy, jest {type(value).__name__}")
    return value


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise MigrationError(f"{where}: oczekiwano tekstu, jest {type(value).__name__}")
    return value


def _utc(value: Any) -> str | None:
    """Czas starego raportu jako UTC; ``None``, gdy nie jest jednoznacznym czasem ze strefą."""
    try:
        return models.utc_iso(datetime.fromisoformat(value))
    except (TypeError, ValueError, OverflowError):  # ModelError (czas bez strefy) jest podklasą ValueError
        return None


def _scalar(value: Any) -> str | int | bool | None:
    """Wartość metadanych jako atrybut obserwacji; struktury zagnieżdżone zostają zapisane jako tekst JSON."""
    if isinstance(value, (str, int, bool, type(None))):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)


class _Evidence:
    """Dowody z manifestu oraz dowody dopisane dla odwołań, których manifest nie zawierał."""

    def __init__(self, manifest: list) -> None:
        self.by_path: dict[str, models.Evidence] = {}
        for index, entry in enumerate(manifest):
            entry = _object(entry, f"evidence_manifest[{index}]")
            path = _text(entry.get("source"), f"evidence_manifest[{index}].source")
            origin = models.ORIGIN_OF_SOURCE.get(path.split("/", 1)[0])
            if origin is None or "/" not in path:
                raise MigrationError(f"evidence_manifest[{index}].source: nieznane źródło w ścieżce {path[:80]!r}")
            try:
                self.by_path[path] = models.Evidence(origin, path, models.UNKNOWN_LEGACY, sha256=entry.get("sha256"),
                                                     size_bytes=entry.get("size"), mtime_ns=entry.get("mtime_ns"))
            except models.ModelError as invalid:
                raise MigrationError(f"evidence_manifest[{index}]: {invalid}") from None

    def entry_for(self, origin: models.OriginKind, name: str) -> models.Evidence:
        """Dowód o ścieżce ``<źródło>/<name>``; gdy manifest go nie zawiera, powstaje wpis bez skrótu."""
        path = f"{models.SOURCE_OF_ORIGIN[origin]}/{name}"
        return self.by_path.setdefault(path, models.Evidence(origin, path, models.UNKNOWN_LEGACY))

    def database(self) -> models.Evidence:
        dumps = [item for item in self.by_path.values() if item.origin_kind is models.OriginKind.SQL_DUMP and item.sha256 is not None]
        return dumps[0] if len(dumps) == 1 else self.entry_for(models.OriginKind.SQL_DUMP, models.UNKNOWN_LEGACY)


def _place(category: models.Category, source: str, evidence: _Evidence) -> tuple[models.Evidence, models.Location]:
    """Dowód i miejsce odtworzone z pola ``source`` starego ustalenia (``plik``, ``log:wiersz``, ``tabela:klucz``)."""
    if category is models.Category.DATABASE:
        table, _, key = source.partition(":")
        return evidence.database(), models.Location(table=table, key=key or None)
    if category is models.Category.HTTP_LOG:
        name, _, line = source.rpartition(":")
        if name and len(line) <= 18 and line.isascii() and line.isdigit():
            return evidence.entry_for(models.OriginKind.LOG, name), models.Location(path=name, line=int(line))
    return evidence.entry_for(_ORIGIN_OF_CATEGORY[category], source), models.Location(path=source)


def _finding(entry: Any, where: str, evidence: _Evidence) -> tuple[models.Observation, models.Finding]:
    entry = _object(entry, where)
    try:
        category = models.Category(entry.get("source_type"))
    except ValueError:
        raise MigrationError(f"{where}.source_type: nieznana wartość {str(entry.get('source_type'))[:80]!r}") from None
    source = _text(entry.get("source"), f"{where}.source")
    metadata = _object(entry.get("metadata", {}), f"{where}.metadata")
    record, location = _place(category, source, evidence)
    facts = {str(name): _scalar(value) for name, value in metadata.items()}
    try:
        observation = models.Observation(record.id, LEGACY_KIND, location,
                                         {**facts, "legacy_rule": entry.get("rule"), "legacy_source_type": str(category)})
        return observation, models.Finding(entry.get("rule"), category, entry.get("severity"), entry.get("confidence"),
                                           entry.get("explanation"), (observation.id,))
    except models.ModelError as invalid:
        raise MigrationError(f"{where}: {invalid}") from None


def _timeline(events: list, evidence: _Evidence, notes: list[str]) -> list[models.TimelineEvent]:
    timeline = []
    for index, event in enumerate(events):
        event = _object(event, f"timeline[{index}]")
        source = _text(event.get("source"), f"timeline[{index}].source")
        moment = _utc(event.get("time_utc"))
        if moment is None:
            notes.append(f"Migracja z 0.1.0: pominięto zdarzenie osi czasu bez jednoznacznego czasu UTC ({source[:120]})")
            continue
        if event.get("event") == "SUSPICIOUS_FILE_MTIME":
            time_source, record = models.TimeSource.MTIME, evidence.entry_for(models.OriginKind.FILE, source.removeprefix("files/"))
        else:
            time_source, (record, _) = models.TimeSource.LOG, _place(models.Category.HTTP_LOG, source, evidence)
        timeline.append(models.TimelineEvent(moment, time_source, event.get("timestamp_basis"), event.get("event"), source,
                                             event.get("confidence"), record.id))
    return timeline


def _legacy_report(report: Any) -> Mapping[str, Any]:
    """Sprawdza, że wejście deklaruje schemat 0.1.0, ma jego pola i jedną z dwóch ocen tego schematu."""
    report = _object(report, "raport")
    if report.get("schema_version") != LEGACY_VERSION:
        raise MigrationError(f"schema_version: oczekiwano {LEGACY_VERSION!r}, jest {str(report.get('schema_version'))[:80]!r}")
    if missing := [name for name in _REQUIRED if name not in report]:
        raise MigrationError(f"raport: brak pól: {', '.join(missing)}")
    if not isinstance(report["assessment"], str) or report["assessment"] not in _ASSESSMENT:
        raise MigrationError(f"assessment: nieznana wartość {str(report['assessment'])[:80]!r}")
    return report


def migrate_0_1_0(report: dict) -> dict:
    """Stary raport 0.1.0 (słownik) → nowy słownik ``poc-1`` spełniający cały kontrakt ``models.validate_report``.

    Zgłasza ``MigrationError``, gdy wejście nie jest spójnym raportem 0.1.0.
    """
    report = _legacy_report(report)
    try:
        evidence = _Evidence(_list(report["evidence_manifest"], "evidence_manifest"))
        notes = [MIGRATION_NOTE]
        observations, findings = {}, {}
        legacy_findings = _list(report["findings"], "findings")
        for index, entry in enumerate(legacy_findings):
            observation, finding = _finding(entry, f"findings[{index}]", evidence)
            observations[observation.id] = observation
            findings[finding.id] = finding
        if len(findings) != len(legacy_findings):
            notes.append(f"Migracja z 0.1.0: scalono {len(legacy_findings) - len(findings)} powtórzonych, identycznych ustaleń")
        timeline = _timeline(_list(report.get("timeline", []), "timeline"), evidence, notes)
        analyzed_at = _utc(report["analyzed_at_utc"])
        if analyzed_at is None:
            notes.append("Migracja z 0.1.0: czas analizy nie był jednoznacznym czasem UTC i został pominięty")
        gaps = dict.fromkeys([*(_text(gap, "coverage_gaps") for gap in _list(report["coverage_gaps"], "coverage_gaps")), *notes])
        return models.Report(
            case_id=report["case_id"], tool=report["tool"], tool_version=report["tool_version"], analyzed_at_utc=analyzed_at,
            assessment=_ASSESSMENT[report["assessment"]], disclaimer=report["disclaimer"],
            evidence=tuple(evidence.by_path.values()), observations=tuple(observations.values()), findings=tuple(findings.values()),
            coverage={source: models.Coverage(source, models.CoverageStatus.UNKNOWN_LEGACY, None) for source in models.SOURCES},
            coverage_gaps=tuple(gaps), timeline=tuple(timeline), migrated_from=LEGACY_VERSION).to_dict()
    except models.ModelError as invalid:
        raise MigrationError(f"raport 0.1.0 nie daje się przenieść: {invalid}") from None
    except RecursionError:
        raise MigrationError("raport 0.1.0 jest zbyt głęboko zagnieżdżony") from None
