"""Oś czasu i korelacja ustaleń z różnych źródeł (ADR 0007). Bez dostępu do plików."""
from __future__ import annotations

from datetime import datetime, timezone

from . import models
from .analysis import Detection


def timeline(detections: list[Detection], evidence: dict[str, models.Evidence]) -> tuple[list[models.TimelineEvent], list[str]]:
    """Prosta oś czasu PoC oraz opisy plików, których mtime nie da się zapisać jako daty.

    Czas z logu zależy od zegara serwera, a mtime pliku jest zmienialny: żaden nie dowodzi czasu ataku.
    """
    events, undated = [], []
    for found in detections:
        fact = found.observation
        if found.rule == "HTTP_EXECUTABLE_IN_UPLOADS" and fact.timestamp_utc is not None:
            events.append(models.TimelineEvent(
                fact.timestamp_utc, models.TimeSource.LOG, "HTTP access log; synchronizacja zegara niezweryfikowana", found.rule,
                models.describe_location(fact.location.to_dict()), "medium", fact.evidence_id, fact.id))
    flagged = {found.observation.evidence_id for found in detections if found.category == "file"}
    for item in evidence.values():
        if item.id in flagged and item.origin_kind is models.OriginKind.FILE and item.mtime_ns is not None:
            try:
                moment = models.utc_iso(datetime.fromtimestamp(item.mtime_ns / 1e9, tz=timezone.utc))
            except (ValueError, OverflowError, OSError):  # system plików może deklarować datę spoza zakresu datetime
                undated.append(f"Nie można zapisać mtime jako czasu UTC: {item.logical_path}")
                continue
            events.append(models.TimelineEvent(
                moment, models.TimeSource.MTIME, "Filesystem mtime: zmienialny; nie oznacza czasu ataku", "SUSPICIOUS_FILE_MTIME",
                item.logical_path, "low", item.id))
    return events, undated


def findings_of(detections: list[Detection]) -> list[models.Finding]:
    """Jedno ustalenie na wykrycie oraz korelacja: żądanie HTTP do pliku, który jest też w obrazie witryny."""
    findings = [models.Finding(found.rule, found.category, found.severity, found.confidence, found.explanation, (found.observation.id,))
                for found in detections]
    uploads = {found.observation.location.path: found.observation for found in detections if found.rule == "EXECUTABLE_IN_UPLOADS"}
    for found in detections:
        if found.rule != "HTTP_EXECUTABLE_IN_UPLOADS":
            continue
        path = str(found.observation.attributes["uri"]).split("?")[0].lstrip("/")
        if path in uploads:
            findings.append(models.Finding(
                "CORRELATED_UPLOAD_REQUEST", "correlation", "high", "medium",
                "Ten sam podejrzany plik występuje w obrazie witryny i w logu HTTP; to korelacja, nie dowód wykonania kodu.",
                (uploads[path].id, found.observation.id)))
    return findings
