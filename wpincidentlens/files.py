"""FileAnalyzer: jedno przejście drzewa witryny przez SecureIngest; reguły i porównania są w osobnych modułach.

Szwy (ADR 0005): ``integrity`` — porównanie z referencją, ``filerules`` — reguły ścieżki i treści,
``FileScan.observations`` — fakty bez ustalenia (np. kandydaci WPDetector).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import filerules, ingest, integrity, models, redact, rules, wpdetect
from .analysis import Detection, SourceCoverage


@dataclass
class FileScan:
    detections: list[Detection] = field(default_factory=list)
    cover: SourceCoverage = field(default_factory=SourceCoverage)
    observations: list[models.Observation] = field(default_factory=list)  # fakty, z których nie powstaje ustalenie


def scan_files(root: Path, baseline: dict | None, session: ingest.Session, core: integrity.CoreChecksums | None = None) -> FileScan:
    """Statusy pominiętych wpisów obniżają pokrycie na podstawie rejestru sesji; tutaj trafiają tylko ich opisy.

    Wyjątek w regule (``rules.guarded``) jest luką tego źródła, a nie przerwaniem analizy; limit czasu sesji przerywa
    reguły treści dużego pliku (luka „przeanalizowany do reguły …”), a dalsze wpisy pomija SecureIngest.
    """
    scan = FileScan()
    comparison = integrity.ReferenceComparison(baseline, core)
    detector = wpdetect.WPDetector(baseline)
    scan_limit = session.limits.max_scan_bytes

    where: str | None = None  # wpis, którego dotyczy bieżąca ocena reguły (pierwsze miejsce w luce po wyjątku)

    def guard(rule: str, call, *args, default=None):
        return rules.guarded(scan.cover, rule, call, *args, default=default, where=where)

    for item in session.read(root, "files", expect="dir", wanted=filerules.wants_content, md5=core is not None):
        where = f"files/{item.rel}"
        scan.cover.note(*item.gaps)
        checked = guard("integrity", comparison.check, item)
        if checked is None:  # wpis nie trafił do porównania: jego „brak” względem referencji byłby fałszywym ustaleniem
            comparison.complete = False
        scan.detections.extend(checked or [])
        scan.detections.extend(guard("filerules.path_rules", filerules.path_rules, item, default=[]))
        guard("wpdetect", detector.feed, item)
        if item.sha256 is None:
            continue
        if item.size > scan_limit:
            text = f"Analiza treści pominięta, plik > {scan_limit} B: {redact.neutralise(item.rel)}"
            if filerules.wants_content(item.rel):
                scan.cover.degrade(text)
            else:  # reguły treści dotyczą tylko plików kodu; taki plik nie byłby skanowany także poniżej limitu
                scan.cover.note(text)
            continue
        if item.content is not None:
            found = filerules.content_rules(item, session.expired, guard)
            scan.detections.extend(found)
            if found.skipped:
                scan.cover.degrade(
                    f"Limit czasu analizy {session.limits.max_seconds:g} s przekroczony w trakcie reguł treści: plik {redact.neutralise(item.rel)} "
                    f"przeanalizowany do reguły {found.applied} z {found.applied + len(found.skipped)}; "
                    f"niezastosowane: {', '.join(found.skipped)}")
    where = None
    scan.detections.extend(guard("integrity", comparison.finish, session, scan.cover, default=[]))
    scan.observations.extend(guard("wpdetect", detector.finish, scan.cover, default=[]))
    return scan
