"""WPIncidentLens proof of concept. Only read static inputs; never execute WordPress code."""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import case, files, ingest, integrity, models, report
from . import database as database_scan
from .analysis import Detection, SourceCoverage, decoded, is_lossy
from .sqldump import _iter_row_groups, _write_statement_starts, iter_insert_rows  # noqa: F401  (testy wołają je przez cli)
from .analysis import evidence_of as _evidence

VERSION = "0.1.0-poc"
DISCLAIMER = "Brak alertów nie dowodzi braku włamania. PoC, nie certyfikacja śledcza."
# Kody wyjścia (specyfikacja §11, ADR 0003): 2 zgłasza argparse przy błędzie wywołania; ustalenia nie zmieniają kodu.
EXIT_COMPLETE, EXIT_PARTIAL, EXIT_UNPROCESSED = 0, 3, 4
# Materiał dowodowy otwiera wyłącznie wpincidentlens.ingest (ADR 0002 D4); ten moduł dostaje już przeczytane bajty.
MAX_FILES = ingest.Limits().max_files
MAX_SCAN_BYTES = ingest.Limits().max_scan_bytes
MAX_SQL_BYTES = database_scan.MAX_SQL_BYTES
MAX_LOG_BYTES = 30 * 1024 * 1024
MAX_BASELINE_BYTES = 64 * 1024 * 1024
MAX_CORE_CHECKSUMS_BYTES = 8 * 1024 * 1024


def _session() -> ingest.Session:
    """Sesja odczytu z limitami domyślnymi; stałe MAX_* są czytane w chwili wywołania."""
    return ingest.Session(ingest.Limits(max_files=MAX_FILES, max_scan_bytes=MAX_SCAN_BYTES))


LOG_PATTERN = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(GET|POST|PUT|PATCH|DELETE|HEAD)[ \t]+(\S+)[ \t]+[^\"\s][^\"]*"\s+(\d{3})\b')

def _log_time_utc(stamp: str) -> str | None:
    """Czas z logu combined jako UTC; ``None``, gdy zapisu nie da się jednoznacznie znormalizować (np. brak strefy)."""
    try:
        return models.utc_iso(datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z"))
    except (ValueError, OverflowError):
        return None


def scan_logs(root: Path, session: ingest.Session | None = None) -> tuple[list[Detection], SourceCoverage]:
    findings, cover = [], SourceCoverage()
    hashed, observed, skipped, matched = 0, 0, 0, 0
    for item in (session or _session()).read(root, "logs", keep_limit=MAX_LOG_BYTES):
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


class _DuplicateKey(ValueError):
    pass


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    data = dict(pairs)
    if len(data) != len(pairs):  # json bierze po cichu ostatnią wartość: dwa wpisy tej samej ścieżki ukryłyby jeden skrót
        raise _DuplicateKey
    return data


def _reference_json(content: bytes) -> object:
    """JSON zaufanej referencji (baseline, manifest sum); powtórzony klucz obiektu jest błędem, nie cichym nadpisaniem."""
    try:
        return json.loads(content.decode("utf-8"), object_pairs_hook=_unique_keys)
    except _DuplicateKey:
        raise ValueError("powtórzony klucz w obiekcie JSON") from None
    except (ValueError, RecursionError):
        raise ValueError("niepoprawny JSON (wymagany UTF-8)") from None


def load_baseline(path: Path, session: ingest.Session) -> dict:
    """Czyta zaufany baseline tym samym bezpiecznym odczytem co dowody; wpis dowodu i jego luki zostają w rejestrze sesji.

    Baseline, którego nie da się odczytać albo który ma zły kształt, to błąd wejścia (``ValueError``), nie luka:
    operator jawnie zażądał porównania, więc ciche pominięcie byłoby mylące.
    """
    item = session.read_file(path, "baseline", keep_limit=MAX_BASELINE_BYTES)
    if item.content is None:
        raise ValueError(item.gaps[0] if item.sha256 is None else f"plik większy niż {MAX_BASELINE_BYTES} B")
    data = _reference_json(item.content)
    if not isinstance(data, dict):
        raise ValueError("baseline musi być obiektem JSON")
    files, admins = data.get("files", {}), data.get("known_admins", [])
    if not (isinstance(files, dict) and all(isinstance(value, str) for value in files.values())):
        raise ValueError("baseline.files musi być obiektem {ścieżka: sha256}")
    if not (isinstance(admins, list) and all(isinstance(value, str) for value in admins)):
        raise ValueError("baseline.known_admins musi być listą nazw")
    return data


def load_core_checksums(path: Path, session: ingest.Session) -> integrity.CoreChecksums:
    """Czyta lokalny manifest sum rdzenia WordPress.org tak samo jak baseline; narzędzie niczego nie pobiera z sieci.

    Manifest jest dowodem źródła ``baseline``. Nieczytelny albo o złym kształcie to błąd wejścia (``ValueError``).
    """
    item = session.read_file(path, "baseline", keep_limit=MAX_CORE_CHECKSUMS_BYTES)
    if item.content is None:
        raise ValueError(item.gaps[0] if item.sha256 is None else f"plik większy niż {MAX_CORE_CHECKSUMS_BYTES} B")
    return integrity.parse_core_checksums(_reference_json(item.content), replace(item, content=None))


def _coverage(source: str, cover: SourceCoverage, ledger: list[ingest.Evidence]) -> models.Coverage:
    """Status źródła z ustaleń skanera i z rejestru: każdy wpis o statusie innym niż READ wyklucza ``ANALYZED``."""
    records = [record for record in ledger if record.source == source]
    counted = Counter(str(record.status) for record in records)
    entries = {str(status): counted[str(status)] for status in ingest.ReadStatus}
    hashed = sum(record.sha256 is not None for record in records)
    reasons = set(cover.reasons)
    if not cover.provided:
        status = models.CoverageStatus.NOT_PROVIDED
    elif cover.failed or not hashed:
        status = models.CoverageStatus.FAILED
    elif cover.partial or len(records) != entries[str(ingest.ReadStatus.READ)]:
        status = models.CoverageStatus.PARTIAL
    else:
        status = models.CoverageStatus.ANALYZED
    if status in (models.CoverageStatus.FAILED, models.CoverageStatus.PARTIAL) and not reasons:
        reasons.add(f"Źródło {source}: nie odczytano żadnego pliku" if not hashed else f"Źródło {source}: część wpisów nie została odczytana")
    return models.Coverage(source, status, entries, tuple(reasons))


def _timeline(detections: list[Detection], evidence: dict[str, models.Evidence]) -> tuple[list[models.TimelineEvent], list[str]]:
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


def _scan_sources(root: Path, database: Path | None, logs: Path | None, baseline: dict | None, known_admins: set[str],
                  session: ingest.Session, core: integrity.CoreChecksums | None = None,
                  ) -> tuple[list[Detection], dict[str, SourceCoverage], list[models.Observation]]:
    """Uruchamia skanery podanych źródeł; źródło niepodane dostaje powód zamiast skanu. Trzeci wynik: fakty bez ustalenia."""
    cover = {source: SourceCoverage(provided=False) for source in models.SOURCES}
    scan = files.scan_files(root, baseline, session, core)
    detections, cover["files"], facts = scan.detections, scan.cover, list(scan.observations)
    if database:
        found, cover["database"], database_facts = database_scan.scan_database(database, known_admins, session)
        detections.extend(found)
        facts.extend(database_facts)
    else:
        cover["database"].note("Brak zrzutu bazy danych")
    if logs:
        found, cover["logs"] = scan_logs(logs, session)
        detections.extend(found)
    else:
        cover["logs"].note("Brak logów HTTP")
    if baseline is None and core is None:
        cover["baseline"].note("Brak zaufanej migawki bazowej (baseline): porównanie plików z referencją niewykonane")
    else:  # manifest sum rdzenia jest częścią źródła ``baseline`` (zaufane referencje)
        cover["baseline"] = SourceCoverage()
        cover["baseline"].note(*(gap for record in session.ledger if record.source == "baseline" for gap in record.gaps))
        if baseline is None:
            cover["baseline"].note("Brak zaufanej migawki bazowej (baseline): referencją jest wyłącznie manifest sum rdzenia")
        elif not baseline.get("files"):
            cover["baseline"].note("Baseline nie zawiera skrótów plików (files): porównanie plików z referencją niewykonane")
        if core is not None:
            cover["baseline"].note("Manifest sum rdzenia (MD5) obejmuje tylko pliki dystrybucji WordPressa; zgodność z nim "
                                   "nie mówi nic o wtyczkach, motywach, uploads ani konfiguracji")
    return detections, cover, facts


def _findings(detections: list[Detection]) -> list[models.Finding]:
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


def compose_report(root: Path, database: Path | None, logs: Path | None,
                   baseline: dict | None, known_admins: set[str], case_id: str, *,
                   session: ingest.Session | None = None, core: integrity.CoreChecksums | None = None) -> dict:
    """Zwraca raport ``poc-1`` jako słownik gotowy do zapisu.

    ``baseline`` musi pochodzić z ``load_baseline``, a ``core`` z ``load_core_checksums`` tej samej sesji.
    """
    session = session or _session()
    if baseline is not None and integrity.baseline_record(session, core) is None:
        raise ValueError("baseline musi być wczytany przez load_baseline w tej samej sesji odczytu")
    if core is not None and core.record not in session.ledger:
        raise ValueError("manifest sum musi być wczytany przez load_core_checksums w tej samej sesji odczytu")
    detections, cover, facts = _scan_sources(root, database, logs, baseline, known_admins, session, core)
    session_gaps = session.finish()  # od tej chwili rejestr sesji ma ostateczne statusy (także CHANGED z ponownej weryfikacji)
    for source, text in session.integrity_notes:
        for name in [source] if source else [name for name in models.SOURCES if cover[name].provided]:
            cover[name].degrade(text)
    evidence = {item.id: item for item in map(_evidence, session.ledger)}
    timeline, undated = _timeline(detections, evidence)
    cover["files"].note(*undated)
    coverage = {source: _coverage(source, cover[source], session.ledger) for source in models.SOURCES}
    findings = {item.id: item for item in _findings(detections)}
    gaps = {reason for entry in coverage.values() for reason in entry.reasons} | set(session_gaps)
    return models.Report(
        case_id=case_id, tool="WPIncidentLens PoC", tool_version=VERSION, analyzed_at_utc=models.utc_iso(datetime.now(timezone.utc)),
        assessment=models.assess(findings.values(), coverage), disclaimer=DISCLAIMER,
        evidence=tuple(evidence.values()), observations=tuple({item.id: item for item in [*(found.observation for found in detections), *facts]}.values()),
        findings=tuple(findings.values()), coverage=coverage, coverage_gaps=tuple(gaps), timeline=tuple(timeline)).to_dict()


def exit_code(report: dict) -> int:
    """Kod wyjścia z pokrycia, nigdy z ustaleń: 0 pełny zakres, 4 podane źródło nieprzetworzone, 3 każda inna niepełność."""
    if any(entry["status"] == models.CoverageStatus.FAILED for entry in report["coverage"].values()):
        return EXIT_UNPROCESSED
    return EXIT_COMPLETE if report["scope_complete"] else EXIT_PARTIAL


write_html = report.write_html  # reeksport: Reporter jest w wpincidentlens/report.py (ADR 0001, krok migracji 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="WPIncidentLens PoC — statyczna analiza kopii WordPressa, bazy SQL i logów",
        epilog="Kody wyjścia: 0 — zakres analizy pełny (ustalenia możliwe); 2 — błąd wywołania; 3 — analiza częściowa "
               "(brak źródła, pominięte lub zmienione wpisy, limit); 4 — podane źródło nieprzetworzone. "
               "Kod nie jest oceną kompromitacji: ocenę podaje pole assessment w report.json.")
    parser.add_argument("--files", type=Path, required=True)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--logs", type=Path)
    parser.add_argument("--baseline", type=Path, help="Zaufany JSON: {files: {ścieżka: sha256}, known_admins: [...]} ")
    parser.add_argument("--core-checksums", type=Path,
                        help="Lokalny plik JSON z sumami MD5 rdzenia w kształcie api.wordpress.org core/checksums/1.0: "
                             "{checksums: {ścieżka: md5}}; narzędzie niczego nie pobiera z sieci")
    parser.add_argument("--known-admin", action="append", default=[])
    parser.add_argument("--case-id", default="WPINCIDENTLENS-DEMO",
                        help="Identyfikator sprawy: 1–64 znaki A-Z a-z 0-9 . _ -, pierwszy znak inny niż kropka i łącznik (%(default)s)")
    parser.add_argument("--operator-id", help="Pseudonim operatora zapisywany w case.json (te same znaki co --case-id); domyślnie brak")
    parser.add_argument("--output", type=Path, required=True)
    defaults = ingest.Limits()
    parser.add_argument("--allow-hardlinks", action="store_true",
                        help="Czytaj pliki z wieloma dowiązaniami twardymi (domyślnie pomijane z luką pokrycia)")
    parser.add_argument("--no-reverify", action="store_true",
                        help="Pomiń ponowną weryfikację skrótów po analizie (odnotowane w raporcie jako luka)")
    parser.add_argument("--max-files", type=int, default=MAX_FILES, help="Limit liczby plików, łącznie we wszystkich źródłach (%(default)s)")
    parser.add_argument("--max-entries", type=int, default=defaults.max_entries,
                        help="Limit liczby wszystkich wpisów: plików, katalogów, dowiązań i plików specjalnych (%(default)s)")
    parser.add_argument("--max-file-bytes", type=int, default=defaults.max_file_bytes, help="Limit rozmiaru jednego pliku (%(default)s)")
    parser.add_argument("--max-total-bytes", type=int, default=defaults.max_total_bytes, help="Limit łącznego rozmiaru czytanych plików (%(default)s)")
    parser.add_argument("--max-seconds", type=float, default=defaults.max_seconds, help="Limit czasu całej analizy w sekundach (%(default)s)")
    parser.add_argument("--max-depth", type=int, default=defaults.max_depth, help="Limit głębokości katalogów (%(default)s)")
    parser.add_argument("--max-path-bytes", type=int, default=defaults.max_path_bytes,
                        help="Limit długości ścieżki względnej do źródła w bajtach (%(default)s)")
    args = parser.parse_args(argv)
    try:
        context = case.build(
            files=args.files, database=args.database, logs=args.logs, baseline=args.baseline, output=args.output,
            case_id=args.case_id, operator_id=args.operator_id, known_admins=args.known_admin,
            allow_hardlinks=args.allow_hardlinks, reverify=not args.no_reverify, core_checksums=args.core_checksums,
            limits={"max_files": args.max_files, "max_entries": args.max_entries, "max_file_bytes": args.max_file_bytes,
                    "max_total_bytes": args.max_total_bytes, "max_scan_bytes": MAX_SCAN_BYTES, "max_seconds": args.max_seconds,
                    "max_depth": args.max_depth, "max_path_bytes": args.max_path_bytes})
    except case.CaseError as invalid:
        parser.error(str(invalid))
    session = ingest.Session(context.limits, allow_hardlinks=context.allow_hardlinks, reverify=context.reverify)
    baseline = None
    if context.baseline:
        try:
            baseline = case.check_baseline(load_baseline(context.baseline, session))
        except ValueError as invalid:
            parser.error(f"--baseline: {invalid}")
    core = None
    if context.core_checksums:
        try:
            core = load_core_checksums(context.core_checksums, session)
        except ValueError as invalid:
            parser.error(f"--core-checksums: {invalid}")
    admins = set(context.known_admins) | set((baseline or {}).get("known_admins", []))
    output = compose_report(context.files, context.database, context.logs, baseline, admins, context.case_id, session=session, core=core)
    code = exit_code(output)
    try:
        report.write(context.output, output, context.describe(), code)
    except report.OutputRefusal as refusal:
        parser.error(f"--output: {refusal}")
    print(json.dumps({"assessment": output["assessment"], "scope_complete": output["scope_complete"], "findings":len(output["findings"]),
                      "coverage_gaps":len(output["coverage_gaps"]), "exit_code": code, "report":str(context.output / "report.html")}, ensure_ascii=False))
    return code

if __name__ == "__main__":
    raise SystemExit(main())
