"""FileAnalyzer: jedno przejście drzewa witryny przez SecureIngest; reguły i porównania są w osobnych modułach.

Szwy (ADR 0005): ``integrity`` — porównanie z referencją, ``filerules`` — reguły ścieżki i treści,
``FileScan.observations`` — fakty bez ustalenia (np. kandydaci WPDetector).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import filerules, ingest, integrity, models, wpdetect
from .analysis import Detection, SourceCoverage


@dataclass
class FileScan:
    detections: list[Detection] = field(default_factory=list)
    cover: SourceCoverage = field(default_factory=SourceCoverage)
    observations: list[models.Observation] = field(default_factory=list)  # fakty, z których nie powstaje ustalenie


def scan_files(root: Path, baseline: dict | None, session: ingest.Session) -> FileScan:
    """Statusy pominiętych wpisów obniżają pokrycie na podstawie rejestru sesji; tutaj trafiają tylko ich opisy."""
    scan = FileScan()
    comparison = integrity.BaselineComparison(baseline)
    detector = wpdetect.WPDetector(baseline)
    scan_limit = session.limits.max_scan_bytes
    for item in session.read(root, "files", expect="dir", wanted=filerules.wants_content):
        scan.cover.note(*item.gaps)
        scan.detections.extend(comparison.check(item))
        scan.detections.extend(filerules.path_rules(item))
        detector.feed(item)
        if item.sha256 is None:
            continue
        if item.size > scan_limit:
            text = f"Analiza treści pominięta, plik > {scan_limit} B: {item.rel}"
            if filerules.wants_content(item.rel):
                scan.cover.degrade(text)
            else:  # reguły treści dotyczą tylko plików kodu; taki plik nie byłby skanowany także poniżej limitu
                scan.cover.note(text)
            continue
        if item.content is not None:
            scan.detections.extend(filerules.content_rules(item))
    scan.detections.extend(comparison.finish(session, scan.cover))
    scan.observations.extend(detector.finish(scan.cover))
    return scan
