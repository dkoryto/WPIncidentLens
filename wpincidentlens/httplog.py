"""Analiza logów HTTP: odczyt przez SecureIngest, parser wiersza Apache/Nginx combined i reguła PoC (ADR 0007)."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path, PurePosixPath

from . import ingest, models
from .analysis import Detection, SourceCoverage, decoded, is_lossy
from .analysis import evidence_of as _evidence

MAX_LOG_BYTES = 30 * 1024 * 1024
LOG_PATTERN = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(GET|POST|PUT|PATCH|DELETE|HEAD)[ \t]+(\S+)[ \t]+[^\"\s][^\"]*"\s+(\d{3})\b')

def _log_time_utc(stamp: str) -> str | None:
    """Czas z logu combined jako UTC; ``None``, gdy zapisu nie da się jednoznacznie znormalizować (np. brak strefy)."""
    try:
        return models.utc_iso(datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z"))
    except (ValueError, OverflowError):
        return None


def scan_logs(root: Path, session: ingest.Session) -> tuple[list[Detection], SourceCoverage]:
    findings, cover = [], SourceCoverage()
    hashed, observed, skipped, matched = 0, 0, 0, 0
    for item in session.read(root, "logs", keep_limit=MAX_LOG_BYTES):
        name = PurePosixPath(item.rel).name
        if item.status is ingest.ReadStatus.SKIPPED_SYMLINK and item.rel != ingest.ROOT:
            cover.note(f"Pominięto link w logach: {name}")
        else:
            cover.note(*item.gaps)
        if item.sha256 is None:
            continue
        hashed += 1
        if item.size > MAX_LOG_BYTES:
            cover.degrade(f"Log za duży do parsowania w PoC: {name}")
            continue
        if item.content is None:
            cover.degrade(f"Treść logu niedostępna po odczycie (plik zmienił się w trakcie): {name}")
            continue
        if is_lossy(item.content):
            cover.degrade(f"Log nie jest poprawnym UTF-8: zdekodowano ze znakami zastępczymi: {name}")
        for ln, line in enumerate(decoded(item.content), start=1):
            observed += 1
            m = LOG_PATTERN.match(line)
            if not m:
                skipped += 1
                continue
            matched += 1
            ip, timestamp, method, uri, status = m.groups()
            if method in {"POST", "GET"} and re.search(r"/wp-content/uploads/[^?\s]+\.(?:php|phtml|phar)(?:\?|$)", uri, re.I):
                moment = _log_time_utc(timestamp)
                if moment is None:
                    cover.note("Nie można znormalizować czasu logu: " + timestamp[:64])
                request = models.Observation(
                    _evidence(item).id, "HTTP_REQUEST_FOR_PHP_IN_UPLOADS", models.Location(path=item.rel, line=ln),
                    {"uri": uri[:300], "method": method, "status": int(status), "client_ip": ip[:64]},
                    timestamp_raw=timestamp[:64], timestamp_utc=moment, time_source=models.TimeSource.LOG)
                findings.append(Detection("HTTP_EXECUTABLE_IN_UPLOADS", "high", "medium", "http_log",
                    "Żądanie HTTP do pliku PHP w uploads; brak dowodu wykonania kodu.", request))
    if observed and not matched:
        cover.fail("Logi nie odpowiadają obsługiwanemu formatowi Apache/Nginx combined")
    elif observed and skipped:
        cover.degrade(f"Nie sparsowano {skipped}/{observed} wierszy logów")
    elif hashed and not observed and not cover.partial:
        cover.fail("Logi nie zawierają żadnego wiersza do analizy")
    return findings, cover
