"""WPTrace proof of concept. Only read static inputs; never execute WordPress code."""
from __future__ import annotations

import argparse
import html
import io
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import ingest, models

VERSION = "0.1.0-poc"
DISCLAIMER = "Brak alertów nie dowodzi braku włamania. PoC, nie certyfikacja śledcza."
# Kody wyjścia (specyfikacja §11, ADR 0003): 2 zgłasza argparse przy błędzie wywołania; ustalenia nie zmieniają kodu.
EXIT_COMPLETE, EXIT_PARTIAL, EXIT_UNPROCESSED = 0, 3, 4
# Materiał dowodowy otwiera wyłącznie wptrace.ingest (ADR 0002 D4); ten moduł dostaje już przeczytane bajty.
MAX_FILES = ingest.Limits().max_files
MAX_SCAN_BYTES = ingest.Limits().max_scan_bytes
MAX_SQL_BYTES = 20 * 1024 * 1024
MAX_LOG_BYTES = 30 * 1024 * 1024
MAX_BASELINE_BYTES = 64 * 1024 * 1024
CODE_SUFFIXES = {".php", ".phtml", ".phar", ".inc"}


def _session() -> ingest.Session:
    """Sesja odczytu z limitami domyślnymi; stałe MAX_* są czytane w chwili wywołania."""
    return ingest.Session(ingest.Limits(max_files=MAX_FILES, max_scan_bytes=MAX_SCAN_BYTES))


def _has_content_rules(rel: str) -> bool:
    path = PurePosixPath(rel)
    return path.suffix.lower() in CODE_SUFFIXES or path.name in (".htaccess", ".user.ini")


def _text(content: bytes) -> io.TextIOWrapper:
    """Dekoduje jak dotychczasowe otwarcie w trybie tekstowym: UTF-8 ze znakami zastępczymi, uniwersalne końce wierszy."""
    return io.TextIOWrapper(io.BytesIO(content), encoding="utf-8", errors="replace")


@dataclass(frozen=True)
class Detection:
    """Wykrycie parsera: fakt (``observation``) i ocena, jaką nadaje mu reguła PoC. Z niego powstaje ``Finding``."""
    rule: str
    severity: str
    confidence: str
    category: str
    explanation: str
    observation: models.Observation


@dataclass
class SourceCoverage:
    """Roboczy zapis pokrycia jednego źródła. Status końcowy wynika z niego i z rejestru sesji (``_coverage``)."""
    provided: bool = True
    failed: bool = False   # źródło podano, ale nic z niego nie przeanalizowano
    partial: bool = False  # część materiału pominięta przez limit albo nieobsługiwany format
    reasons: list[str] = field(default_factory=list)

    def note(self, *texts: str) -> None:
        """Informacja o zakresie (np. stałe ograniczenie parsera); sama nie obniża statusu."""
        self.reasons.extend(texts)

    def degrade(self, text: str) -> None:
        self.partial = True
        self.reasons.append(text)

    def fail(self, text: str) -> None:
        self.failed = True
        self.reasons.append(text)


def _evidence(record: ingest.Evidence) -> models.Evidence:
    """Wpis rejestru SecureIngest jako dowód raportu; ścieżka logiczna jest względna do źródła."""
    return models.Evidence(models.ORIGIN_OF_SOURCE[record.source], f"{record.source}/{record.rel}", str(record.status),
                           sha256=record.sha256, size_bytes=record.size, mtime_ns=record.mtime_ns,
                           read_reason=record.reason or None, hardlinked=record.hardlinked)


def _observe(evidence: ingest.Evidence, kind: str, location: models.Location, **facts: str | int | None) -> models.Observation:
    """Fakt bez czasu własnego, stwierdzony w podanym wpisie materiału."""
    return models.Observation(_evidence(evidence).id, kind, location, facts)


def _baseline_record(session: ingest.Session) -> ingest.Evidence | None:
    return next((record for record in session.ledger if record.source == "baseline" and record.sha256 is not None), None)


def _is_code_in_uploads(rel: str) -> bool:
    return rel.startswith("wp-content/uploads/") and PurePosixPath(rel).suffix.lower() in CODE_SUFFIXES


def scan_files(root: Path, baseline: dict | None,
               session: ingest.Session | None = None) -> tuple[list[Detection], SourceCoverage]:
    """Statusy pominiętych wpisów obniżają pokrycie na podstawie rejestru sesji; tutaj trafiają tylko ich opisy."""
    session = session or _session()
    discoveries, cover = [], SourceCoverage()
    ref = (baseline or {}).get("files", {})
    scan_limit = session.limits.max_scan_bytes
    observed, unread, complete = set(), set(), True  # przeczytane; widziane, lecz nieprzeczytane; czy przejście objęło całe drzewo

    def seen_in(item: ingest.Evidence, kind: str, **facts: str) -> models.Observation:
        return _observe(item, kind, models.Location(path=item.rel), **facts)

    for item in session.read(root, "files", expect="dir", wanted=_has_content_rules):
        cover.note(*item.gaps)
        if item.sha256 is None:
            unread.add(item.rel)
            complete = complete and item.rel != ingest.ROOT and item.reason not in ("MAX_FILES", "MAX_ENTRIES")
            if _is_code_in_uploads(item.rel):
                # Reguła zależy tylko od ścieżki: pominięcie odczytu (hardlink, symlink, błąd) nie może jej wyłączyć.
                discoveries.append(Detection("EXECUTABLE_IN_UPLOADS", "high", "low", "file",
                    "Plik wykonywalny PHP w uploads; treść nieodczytana, wymaga ręcznej analizy.", seen_in(item, "PHP_FILE_IN_UPLOADS")))
            continue
        rel = item.rel
        observed.add(rel)
        if rel in ref and ref[rel] != item.sha256:
            discoveries.append(Detection("BASELINE_FILE_CHANGED", "medium", "high", "file",
                "Plik zmieniony względem zaufanej migawki (zmiana nie przesądza o ataku).",
                seen_in(item, "FILE_DIFFERS_FROM_BASELINE", baseline_sha256=ref[rel])))
        if _is_code_in_uploads(rel):
            discoveries.append(Detection("EXECUTABLE_IN_UPLOADS", "high", "medium", "file",
                "Plik wykonywalny PHP w uploads; wymaga analizy kontekstu.", seen_in(item, "PHP_FILE_IN_UPLOADS")))
        if item.size > scan_limit:
            text = f"Analiza treści pominięta, plik > {scan_limit} B: {rel}"
            if _has_content_rules(rel):
                cover.degrade(text)
            else:  # reguły treści dotyczą tylko plików kodu; taki plik nie byłby skanowany także poniżej limitu
                cover.note(text)
            continue
        if item.content is None:
            continue
        raw = item.content.lower()
        if re.search(rb"eval\s*\(\s*base64_decode\s*\(", raw):
            discoveries.append(Detection("SUSPICIOUS_PHP_EVAL_DECODE", "high", "medium", "file",
                "Wykryto łańcuch eval(base64_decode(...)); to heurystyka, nie dowód malware.", seen_in(item, "EVAL_BASE64_DECODE_PATTERN")))
        if re.search(rb"\$_(?:post|get|request)\s*\[.{0,120}\].{0,150}(?:shell_exec|system|passthru)\s*\(", raw, re.DOTALL):
            discoveries.append(Detection("REQUEST_TO_COMMAND_EXEC", "high", "medium", "file",
                "Potencjalne powiązanie danych żądania z wykonaniem komendy; wymaga ręcznej weryfikacji.",
                seen_in(item, "REQUEST_INPUT_NEAR_COMMAND_EXEC_PATTERN")))
    if baseline and ref and complete:  # po przerwanym przejściu nie wiadomo, czego w materiale brakuje
        reference = _baseline_record(session)  # dowodem braku pliku jest baseline, który ten plik wymienia
        for rel in sorted(ref.keys() - observed):
            parts = rel.split("/")
            if any("/".join(parts[:depth]) in unread for depth in range(1, len(parts) + 1)):
                continue  # plik (lub jego katalog) istnieje, tylko nie został przeczytany — luka, nie „brak pliku”
            discoveries.append(Detection("BASELINE_FILE_MISSING", "low", "high", "file",
                "Plik obecny w migawce bazowej nie występuje w materiale wejściowym.",
                _observe(reference, "BASELINE_ENTRY_NOT_IN_FILES", models.Location(path=rel))))
    return discoveries, cover


def _iter_row_groups(values: str):
    """Yield innermost top-level "(...)" groups of a VALUES list in one linear pass.

    Replaces a backtracking regex that took exponential time on crafted input.
    Parentheses inside quoted strings are ignored; a group containing a nested
    parenthesis outside a string is not a plain row and only its innermost part
    is yielded, as before.
    """
    start, quoted, escaped, i = None, False, False, 0
    while i < len(values):
        ch = values[i]
        if quoted:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "'":
                if i + 1 < len(values) and values[i+1] == "'":
                    i += 1
                else:
                    quoted = False
        elif ch == "'":
            quoted = True
        elif ch == "(":
            start = i
        elif ch == ")" and start is not None:
            yield values[start:i+1]
            start = None
        i += 1


def iter_insert_rows(sql: str):
    """Narrow PoC subset of mysqldump INSERT syntax; does NOT execute SQL.

    Supports quoted identifiers, optional column list, multi-row VALUES, MySQL
    backslash quotes, numeric and NULL literals. Unsupported INSERTs are ignored.
    """
    pat = re.compile(r"INSERT\s+INTO\s+`?([A-Za-z0-9_]+)`?\s*(\([^;]*?\))?\s+VALUES\s*", re.I)
    pos = 0
    while (m := pat.search(sql, pos)) is not None:
        table = m.group(1)
        cols = re.findall(r"`([A-Za-z0-9_]+)`", m.group(2) or "")
        i, values, quoted, escaped, nesting = m.end(), "", False, False, 0
        while i < len(sql):
            ch = sql[i]
            if quoted:
                values += ch
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == "'":
                    if i + 1 < len(sql) and sql[i+1] == "'":
                        i += 1
                        values += sql[i]
                    else:
                        quoted = False
            else:
                if ch == "'":
                    quoted = True
                    values += ch
                elif ch == "(":
                    nesting += 1
                    values += ch
                elif ch == ")":
                    nesting -= 1
                    values += ch
                elif ch == ";" and nesting == 0:
                    break
                else:
                    values += ch
            i += 1
        pos = i + 1
        if i >= len(sql) or quoted or nesting != 0:
            continue
        for group in _iter_row_groups(values):
            inside = group[1:-1]
            items, buf, in_str, escape, j = [], [], False, False, 0
            while j < len(inside):
                ch = inside[j]
                if in_str:
                    buf.append(ch)
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == "'":
                        if j + 1 < len(inside) and inside[j+1] == "'":
                            j += 1
                            buf.append(inside[j])
                        else:
                            in_str = False
                elif ch == "'":
                    in_str = True
                    buf.append(ch)
                elif ch == ",":
                    items.append("".join(buf).strip()); buf = []
                else:
                    buf.append(ch)
                j += 1
            items.append("".join(buf).strip())
            cooked = []
            for item in items:
                if item.startswith("'") and item.endswith("'"):
                    v = item[1:-1].replace("''", "'")
                    v = re.sub(r"\\([\\'\"nrt0])", lambda m: {"n":"\n", "r":"\r", "t":"\t", "0":"\0"}.get(m[1], m[1]), v)
                    cooked.append(v)
                elif item.upper() == "NULL":
                    cooked.append(None)
                else:
                    cooked.append(item)
            yield table, cols, cooked


def scan_database(path: Path, known_admins: set[str],
                  session: ingest.Session | None = None) -> tuple[list[Detection], SourceCoverage]:
    """Zrzut, którego nie udało się bezpiecznie odczytać, nie ma skrótu w rejestrze sesji — pokrycie wychodzi wtedy ``FAILED``."""
    cover, findings = SourceCoverage(), []
    item = (session or _session()).read_file(path, "database", keep_limit=MAX_SQL_BYTES)
    cover.note(*item.gaps)
    if item.sha256 is None:
        return findings, cover
    if item.size > MAX_SQL_BYTES:
        cover.fail(f"Eksport SQL większy niż {MAX_SQL_BYTES} B: analiza DB pominięta w PoC")
        return findings, cover
    if item.content is None:
        cover.fail("Treść eksportu SQL niedostępna po odczycie (plik zmienił się w trakcie): analiza DB pominięta")
        return findings, cover
    sql = _text(item.content).read()
    users, admins, count = {}, {}, 0  # admins: identyfikator użytkownika → miejsce pierwszego wiersza z rolą
    tables = set()
    for table, cols, cells in iter_insert_rows(sql):
        tables.add(table)
        count += 1
        if count > 100000:
            cover.degrade("Przekroczono 100000 wierszy INSERT, analiza częściowa")
            break
        if table.endswith("_users"):
            if cols:
                row = dict(zip(cols, cells))
            elif len(cells) >= 2:
                row = {"ID": cells[0], "user_login": cells[1]}
            else:
                continue
            if row.get("ID") is not None:
                users[str(row["ID"])] = str(row.get("user_login") or "")
        elif table.endswith("_usermeta"):
            if cols:
                row = dict(zip(cols, cells))
            elif len(cells) >= 4:
                row = {"user_id": cells[1], "meta_key": cells[2], "meta_value": cells[3]}
            else:
                continue
            if str(row.get("meta_key") or "").endswith("_capabilities") and "administrator" in str(row.get("meta_value") or ""):
                admins.setdefault(str(row.get("user_id")), models.Location(table=table, key=str(row.get("meta_key")), row=count))
        elif table.endswith("_options"):
            if cols:
                row = dict(zip(cols, cells))
            elif len(cells) >= 3:
                row = {"option_name": cells[1], "option_value": cells[2]}
            else:
                continue
            key = str(row.get("option_name") or "")
            value = str(row.get("option_value") or "")
            if re.search(r"<script\b|<iframe\b|javascript\s*:", value, flags=re.I):
                findings.append(Detection("SUSPICIOUS_DB_MARKUP", "medium", "low", "database",
                    "Wartość opcji zawiera aktywny znacznik HTML lub schemat JS; wymaga weryfikacji.",
                    _observe(item, "OPTION_VALUE_WITH_ACTIVE_MARKUP", models.Location(table=table, key=key, row=count))))
    if not tables:
        cover.fail("Brak obsługiwanych instrukcji INSERT; parser PoC nie interpretuje tego formatu SQL")
    for user_id in sorted(admins):
        login = users.get(user_id, "")
        if known_admins and login and login not in known_admins:
            findings.append(Detection("UNRECOGNIZED_ADMIN", "high", "medium", "database",
                "Administrator nie figuruje na dostarczonej, zaufanej liście; nie dowodzi to włamania.",
                _observe(item, "ADMINISTRATOR_ROLE_ROW", admins[user_id], username=login, user_id=user_id)))
    if admins and not known_admins:
        cover.note("Wykryto role administratorów, ale brak wiarygodnej listy porównawczej; sam fakt istnienia admina nie jest alertem")
    cover.note("Parser SQL PoC obsługuje wybrane INSERT; nie obsługuje triggerów, procedur, pełnej składni ani multisite")
    return findings, cover

LOG_PATTERN = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(GET|POST|PUT|PATCH|DELETE|HEAD)\s+([^ ]+)\s+[^\"]+"\s+(\d{3})\b')

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
        for ln, line in enumerate(_text(item.content), start=1):
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
                    {"uri": uri[:300], "method": method, "status": int(status), "client_ip": ip},
                    timestamp_raw=timestamp, timestamp_utc=moment, time_source=models.TimeSource.LOG)
                findings.append(Detection("HTTP_EXECUTABLE_IN_UPLOADS", "high", "medium", "http_log",
                    "Żądanie HTTP do pliku PHP w uploads; brak dowodu wykonania kodu.", request))
    if observed and not matched:
        cover.fail("Logi nie odpowiadają obsługiwanemu formatowi Apache/Nginx combined")
    elif observed and skipped:
        cover.degrade(f"Nie sparsowano {skipped}/{observed} wierszy logów")
    elif hashed and not observed and not cover.partial:
        cover.fail("Logi nie zawierają żadnego wiersza do analizy")
    return findings, cover


def load_baseline(path: Path, session: ingest.Session) -> dict:
    """Czyta zaufany baseline tym samym bezpiecznym odczytem co dowody; wpis dowodu i jego luki zostają w rejestrze sesji.

    Baseline, którego nie da się odczytać albo który ma zły kształt, to błąd wejścia (``ValueError``), nie luka:
    operator jawnie zażądał porównania, więc ciche pominięcie byłoby mylące.
    """
    item = session.read_file(path, "baseline", keep_limit=MAX_BASELINE_BYTES)
    if item.content is None:
        raise ValueError(item.gaps[0] if item.sha256 is None else f"plik większy niż {MAX_BASELINE_BYTES} B")
    try:
        data = json.loads(item.content.decode("utf-8"))
    except (ValueError, RecursionError):
        raise ValueError("niepoprawny JSON (wymagany UTF-8)") from None
    if not isinstance(data, dict):
        raise ValueError("baseline musi być obiektem JSON")
    files, admins = data.get("files", {}), data.get("known_admins", [])
    if not (isinstance(files, dict) and all(isinstance(value, str) for value in files.values())):
        raise ValueError("baseline.files musi być obiektem {ścieżka: sha256}")
    if not (isinstance(admins, list) and all(isinstance(value, str) for value in admins)):
        raise ValueError("baseline.known_admins musi być listą nazw")
    return data


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
                  session: ingest.Session) -> tuple[list[Detection], dict[str, SourceCoverage]]:
    """Uruchamia skanery podanych źródeł; źródło niepodane dostaje powód zamiast skanu."""
    cover = {source: SourceCoverage(provided=False) for source in models.SOURCES}
    detections, cover["files"] = scan_files(root, baseline, session)
    if database:
        found, cover["database"] = scan_database(database, known_admins, session)
        detections.extend(found)
    else:
        cover["database"].note("Brak zrzutu bazy danych")
    if logs:
        found, cover["logs"] = scan_logs(logs, session)
        detections.extend(found)
    else:
        cover["logs"].note("Brak logów HTTP")
    if baseline is None:
        cover["baseline"].note("Brak zaufanej migawki bazowej (baseline): porównanie plików z referencją niewykonane")
    else:
        cover["baseline"] = SourceCoverage()
        cover["baseline"].note(*(gap for record in session.ledger if record.source == "baseline" for gap in record.gaps))
        if not baseline.get("files"):
            cover["baseline"].note("Baseline nie zawiera skrótów plików (files): porównanie plików z referencją niewykonane")
    return detections, cover


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
                   session: ingest.Session | None = None) -> dict:
    """Zwraca raport ``poc-1`` jako słownik gotowy do zapisu. ``baseline`` musi pochodzić z ``load_baseline`` tej samej sesji."""
    session = session or _session()
    if baseline is not None and _baseline_record(session) is None:
        raise ValueError("baseline musi być wczytany przez load_baseline w tej samej sesji odczytu")
    detections, cover = _scan_sources(root, database, logs, baseline, known_admins, session)
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
        case_id=case_id, tool="WPTrace PoC", tool_version=VERSION, analyzed_at_utc=models.utc_iso(datetime.now(timezone.utc)),
        assessment=models.assess(findings.values(), coverage), disclaimer=DISCLAIMER,
        evidence=tuple(evidence.values()), observations=tuple({found.observation.id: found.observation for found in detections}.values()),
        findings=tuple(findings.values()), coverage=coverage, coverage_gaps=tuple(gaps), timeline=tuple(timeline)).to_dict()


def exit_code(report: dict) -> int:
    """Kod wyjścia z pokrycia, nigdy z ustaleń: 0 pełny zakres, 4 podane źródło nieprzetworzone, 3 każda inna niepełność."""
    if any(entry["status"] == models.CoverageStatus.FAILED for entry in report["coverage"].values()):
        return EXIT_UNPROCESSED
    return EXIT_COMPLETE if report["scope_complete"] else EXIT_PARTIAL


def write_html(report: dict, path: Path) -> None:
    esc = lambda s: html.escape(str(s), quote=True)
    places = {item["id"]: models.describe_location(item["location"]) for item in report.get("observations", [])}
    where = lambda item: "; ".join(dict.fromkeys(places.get(reference, reference) for reference in item["observations"]))
    rows = "".join(f"<tr><td>{esc(i['severity'])}</td><td>{esc(i['confidence'])}</td><td>{esc(i['rule_id'])}</td><td>{esc(where(i))}</td><td>{esc(i['reason'])}</td></tr>" for i in report["findings"])
    gaps = "".join(f"<li>{esc(g)}</li>" for g in report["coverage_gaps"])
    timeline_rows = "".join(f"<tr><td>{esc(i['time_utc'])}</td><td>{esc(i['event'])}</td><td>{esc(i['source'])}</td><td>{esc(i['timestamp_basis'])}</td></tr>" for i in report.get("timeline", []))

    def counted(entries: dict | None) -> tuple:
        """Liczba wpisów odczytanych i pozostałych (pominiętych, błędnych, zmienionych); raport przeniesiony z 0.1.0 ich nie zna."""
        if entries is None:
            return "brak danych", "brak danych"
        read = str(ingest.ReadStatus.READ)
        return entries[read], sum(count for status, count in entries.items() if status != read)

    coverage_rows = "".join(
        f"<tr><td>{esc(source)}</td><td>{esc(entry['status'])}</td>" + "".join(f"<td>{esc(count)}</td>" for count in counted(entry["entries"])) + "</tr>"
        for source, entry in report.get("coverage", {}).items())
    scope = {True: "pełny", False: "niepełny"}.get(report.get("scope_complete"), "nieokreślony")
    doc = f"""<!doctype html><html lang=\"pl\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>WPTrace · {esc(report['case_id'])}</title>
<style>body{{font:16px/1.5 system-ui,sans-serif;margin:3em auto;max-width:1100px;padding:0 1em;color:#192938}}h1{{font-size:2em}}h2{{margin-top:2em}}table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #cbd5e1;padding:.65em;text-align:left;vertical-align:top}}th{{background:#edf2f7}}small{{color:#48596c}}code{{word-break:break-all}}</style>
<h1>WPTrace — raport analityczny</h1><p>Sprawa: <b>{esc(report['case_id'])}</b> · {esc(report['analyzed_at_utc'])}</p>
<p>Stan: <strong>{esc(report['assessment'])}</strong>. Zakres analizy: <strong>{esc(scope)}</strong>. {esc(report['disclaimer'])}</p>
<h2>Ustalenia ({len(report['findings'])})</h2><table><thead><tr><th>Waga</th><th>Pewność</th><th>Reguła</th><th>Źródło</th><th>Wyjaśnienie</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Pokrycie źródeł</h2><table><thead><tr><th>Źródło</th><th>Status</th><th>Wpisy odczytane</th><th>Wpisy pominięte lub zmienione</th></tr></thead><tbody>{coverage_rows}</tbody></table>
<h2>Oś czasu (orientacyjna)</h2><table><thead><tr><th>UTC</th><th>Zdarzenie</th><th>Źródło</th><th>Podstawa czasu</th></tr></thead><tbody>{timeline_rows}</tbody></table>
<h2>Ograniczenia danych</h2><ul>{gaps}</ul><p><small>Pełny manifest SHA-256 i metadane są w report.json. Dane wejściowe nie są modyfikowane.</small></p></html>"""
    path.write_text(doc, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="WPTrace PoC — statyczna analiza kopii WordPressa, bazy SQL i logów",
        epilog="Kody wyjścia: 0 — zakres analizy pełny (ustalenia możliwe); 2 — błąd wywołania; 3 — analiza częściowa "
               "(brak źródła, pominięte lub zmienione wpisy, limit); 4 — podane źródło nieprzetworzone. "
               "Kod nie jest oceną kompromitacji: ocenę podaje pole assessment w report.json.")
    parser.add_argument("--files", type=Path, required=True)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--logs", type=Path)
    parser.add_argument("--baseline", type=Path, help="Zaufany JSON: {files: {ścieżka: sha256}, known_admins: [...]} ")
    parser.add_argument("--known-admin", action="append", default=[])
    parser.add_argument("--case-id", default="WPTRACE-DEMO")
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
    args = parser.parse_args(argv)
    given = [(flag, path, expect) for flag, path, expect in (
        ("--files", args.files, "dir"), ("--database", args.database, "file"),
        ("--logs", args.logs, "any"), ("--baseline", args.baseline, "file")) if path is not None]
    for flag, path, expect in given:
        try:
            ingest.check_source(path, expect)
        except ingest.IngestRefusal as refusal:
            if refusal.reason not in ("EACCES", "EPERM"):  # brak uprawnień to luka pokrycia w raporcie, nie błąd wywołania
                parser.error(f"{flag}: {refusal}")
    try:
        out = ingest.resolve_output(args.output, [path for _, path, _ in given])
    except ingest.IngestRefusal as refusal:
        parser.error(f"--output: {refusal}")
    try:
        limits = ingest.Limits(max_files=args.max_files, max_entries=args.max_entries, max_file_bytes=args.max_file_bytes, max_total_bytes=args.max_total_bytes,
                               max_scan_bytes=MAX_SCAN_BYTES, max_seconds=args.max_seconds)
    except ValueError as invalid:
        parser.error(str(invalid))
    session = ingest.Session(limits, allow_hardlinks=args.allow_hardlinks, reverify=not args.no_reverify)
    baseline = None
    if args.baseline:
        try:
            baseline = load_baseline(args.baseline, session)
        except ValueError as invalid:
            parser.error(f"--baseline: {invalid}")
    admins = set(args.known_admin) | set((baseline or {}).get("known_admins", []))
    output = compose_report(args.files, args.database, args.logs, baseline, admins, args.case_id, session=session)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    write_html(output, out / "report.html")
    code = exit_code(output)
    print(json.dumps({"assessment": output["assessment"], "scope_complete": output["scope_complete"], "findings":len(output["findings"]),
                      "coverage_gaps":len(output["coverage_gaps"]), "exit_code": code, "report":str(out / "report.html")}, ensure_ascii=False))
    return code

if __name__ == "__main__":
    raise SystemExit(main())
