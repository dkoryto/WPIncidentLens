"""WPTrace proof of concept. Only read static inputs; never execute WordPress code."""
from __future__ import annotations

import argparse
import html
import io
import json
import re
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from . import ingest

VERSION = "0.1.0-poc"
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


def finding(rule: str, severity: str, confidence: str, kind: str,
            path: str, explanation: str, **metadata: Any) -> dict:
    return {"rule": rule, "severity": severity, "confidence": confidence,
            "source_type": kind, "source": path, "explanation": explanation,
            "metadata": metadata}


def _is_code_in_uploads(rel: str) -> bool:
    return rel.startswith("wp-content/uploads/") and PurePosixPath(rel).suffix.lower() in CODE_SUFFIXES


def scan_files(root: Path, baseline: dict | None,
               session: ingest.Session | None = None) -> tuple[list[dict], list[dict], list[str]]:
    session = session or _session()
    discoveries, manifest, gaps = [], [], []
    ref = (baseline or {}).get("files", {})
    scan_limit = session.limits.max_scan_bytes
    unread, complete = set(), True  # wpisy widziane, lecz nieprzeczytane; czy przejście objęło całe drzewo
    for item in session.read(root, "files", expect="dir", wanted=_has_content_rules):
        gaps.extend(item.gaps)
        if item.sha256 is None:
            unread.add(item.rel)
            complete = complete and item.rel != ingest.ROOT and item.reason not in ("MAX_FILES", "MAX_ENTRIES")
            if _is_code_in_uploads(item.rel):
                # Reguła zależy tylko od ścieżki: pominięcie odczytu (hardlink, symlink, błąd) nie może jej wyłączyć.
                discoveries.append(finding("EXECUTABLE_IN_UPLOADS", "high", "low",
                    "file", item.rel, "Plik wykonywalny PHP w uploads; treść nieodczytana, wymaga ręcznej analizy.",
                    read_status=str(item.status)))
            continue
        rel, sha = item.rel, item.sha256
        manifest.append({"source": f"files/{rel}", "sha256": sha,
                         "size": item.size, "mtime_ns": item.mtime_ns})
        if rel in ref and ref[rel] != sha:
            discoveries.append(finding("BASELINE_FILE_CHANGED", "medium", "high",
                "file", rel, "Plik zmieniony względem zaufanej migawki (zmiana nie przesądza o ataku).",
                sha256=sha, baseline_sha256=ref[rel]))
        if _is_code_in_uploads(rel):
            discoveries.append(finding("EXECUTABLE_IN_UPLOADS", "high", "medium",
                "file", rel, "Plik wykonywalny PHP w uploads; wymaga analizy kontekstu.", sha256=sha))
        if item.size > scan_limit:
            gaps.append(f"Analiza treści pominięta, plik > {scan_limit} B: {rel}")
            continue
        if item.content is None:
            continue
        raw = item.content.lower()
        if re.search(rb"eval\s*\(\s*base64_decode\s*\(", raw):
            discoveries.append(finding("SUSPICIOUS_PHP_EVAL_DECODE", "high", "medium",
                "file", rel, "Wykryto łańcuch eval(base64_decode(...)); to heurystyka, nie dowód malware.", sha256=sha))
        if re.search(rb"\$_(?:post|get|request)\s*\[.{0,120}\].{0,150}(?:shell_exec|system|passthru)\s*\(", raw, re.DOTALL):
            discoveries.append(finding("REQUEST_TO_COMMAND_EXEC", "high", "medium",
                "file", rel, "Potencjalne powiązanie danych żądania z wykonaniem komendy; wymaga ręcznej weryfikacji.", sha256=sha))
    if baseline and ref and complete:  # po przerwanym przejściu nie wiadomo, czego w materiale brakuje
        observed = {x["source"][6:] for x in manifest}
        for rel in ref.keys() - observed:
            parts = rel.split("/")
            if any("/".join(parts[:depth]) in unread for depth in range(1, len(parts) + 1)):
                continue  # plik (lub jego katalog) istnieje, tylko nie został przeczytany — luka, nie „brak pliku”
            discoveries.append(finding("BASELINE_FILE_MISSING", "low", "high",
                "file", rel, "Plik obecny w migawce bazowej nie występuje w materiale wejściowym."))
    return discoveries, manifest, gaps


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
                  session: ingest.Session | None = None) -> tuple[list[dict], dict | None, list[str]]:
    """Wpis manifestu jest ``None``, gdy zrzutu nie udało się bezpiecznie odczytać (przyczyna trafia do luk)."""
    gaps, findings = [], []
    item = (session or _session()).read_file(path, "database", keep_limit=MAX_SQL_BYTES)
    gaps.extend(item.gaps)
    if item.sha256 is None:
        return findings, None, gaps
    entry = {"source": f"database/{item.rel}", "sha256": item.sha256, "size": item.size}
    if item.size > MAX_SQL_BYTES:
        gaps.append(f"Eksport SQL większy niż {MAX_SQL_BYTES} B: analiza DB pominięta w PoC")
        return findings, entry, gaps
    if item.content is None:
        gaps.append("Treść eksportu SQL niedostępna po odczycie (plik zmienił się w trakcie): analiza DB pominięta")
        return findings, entry, gaps
    sql = _text(item.content).read()
    users, admins, count = {}, set(), 0
    tables = set()
    for table, cols, cells in iter_insert_rows(sql):
        tables.add(table)
        count += 1
        if count > 100000:
            gaps.append("Przekroczono 100000 wierszy INSERT, analiza częściowa")
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
                admins.add(str(row.get("user_id")))
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
                findings.append(finding("SUSPICIOUS_DB_MARKUP", "medium", "low", "database",
                    f"{table}:{key}", "Wartość opcji zawiera aktywny znacznik HTML lub schemat JS; wymaga weryfikacji."))
    if not tables:
        gaps.append("Brak obsługiwanych instrukcji INSERT; parser PoC nie interpretuje tego formatu SQL")
    for user_id in sorted(admins):
        login = users.get(user_id, "")
        if known_admins and login and login not in known_admins:
            findings.append(finding("UNRECOGNIZED_ADMIN", "high", "medium", "database",
                "*_users / *_usermeta", "Administrator nie figuruje na dostarczonej, zaufanej liście; nie dowodzi to włamania.",
                username=login, user_id=user_id))
    if admins and not known_admins:
        gaps.append("Wykryto role administratorów, ale brak wiarygodnej listy porównawczej; sam fakt istnienia admina nie jest alertem")
    gaps.append("Parser SQL PoC obsługuje wybrane INSERT; nie obsługuje triggerów, procedur, pełnej składni ani multisite")
    return findings, entry, gaps

LOG_PATTERN = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(GET|POST|PUT|PATCH|DELETE|HEAD)\s+([^ ]+)\s+[^\"]+"\s+(\d{3})\b')

def scan_logs(root: Path, session: ingest.Session | None = None) -> tuple[list[dict], list[dict], list[str]]:
    findings, manifest, gaps = [], [], []
    observed, skipped, matched = 0, 0, 0
    for item in (session or _session()).read(root, "logs", keep_limit=MAX_LOG_BYTES):
        name = PurePosixPath(item.rel).name
        if item.status is ingest.ReadStatus.SKIPPED_SYMLINK and item.rel != ingest.ROOT:
            gaps.append(f"Pominięto link w logach: {name}")
        else:
            gaps.extend(item.gaps)
        if item.sha256 is None:
            continue
        manifest.append({"source": f"logs/{name}", "sha256": item.sha256, "size": item.size})
        if item.size > MAX_LOG_BYTES:
            gaps.append(f"Log za duży do parsowania w PoC: {name}")
            continue
        if item.content is None:
            gaps.append(f"Treść logu niedostępna po odczycie (plik zmienił się w trakcie): {name}")
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
                findings.append(finding("HTTP_EXECUTABLE_IN_UPLOADS", "high", "medium", "http_log",
                    f"{name}:{ln}", "Żądanie HTTP do pliku PHP w uploads; brak dowodu wykonania kodu.",
                    uri=uri[:300], method=method, status=int(status),
                    observed_time=timestamp, client_ip=ip))
    if observed and not matched:
        gaps.append("Logi nie odpowiadają obsługiwanemu formatowi Apache/Nginx combined")
    elif observed and skipped:
        gaps.append(f"Nie sparsowano {skipped}/{observed} wierszy logów")
    return findings, manifest, gaps


def load_baseline(path: Path, session: ingest.Session) -> tuple[dict, dict, list[str]]:
    """Czyta zaufany baseline tym samym bezpiecznym odczytem co dowody: (baseline, wpis manifestu, luki).

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
    return data, {"source": f"baseline/{item.rel}", "sha256": item.sha256, "size": item.size}, list(item.gaps)


def compose_report(root: Path, database: Path | None, logs: Path | None,
                   baseline: dict | None, known_admins: set[str], case_id: str, *,
                   session: ingest.Session | None = None,
                   prior_inputs: Sequence[dict] = (), prior_gaps: Sequence[str] = ()) -> dict:
    """``prior_inputs``/``prior_gaps``: manifest i luki wejść przeczytanych wcześniej w tej samej sesji (baseline)."""
    session = session or _session()
    file_findings, inputs, gaps = scan_files(root, baseline, session)
    inputs.extend(prior_inputs); gaps.extend(prior_gaps)
    items = list(file_findings)
    if database:
        f, man, g = scan_database(database, known_admins, session)
        items.extend(f); gaps.extend(g)
        if man: inputs.append(man)
    else:
        gaps.append("Brak zrzutu bazy danych")
    if logs:
        f, man, g = scan_logs(logs, session)
        items.extend(f); inputs.extend(man); gaps.extend(g)
    else:
        gaps.append("Brak logów HTTP")
    upload_files = {x["source"] for x in items if x["rule"] == "EXECUTABLE_IN_UPLOADS"}
    for log_item in [x for x in items if x["rule"] == "HTTP_EXECUTABLE_IN_UPLOADS"]:
        uri = log_item["metadata"].get("uri", "").split("?")[0].lstrip("/")
        if uri in upload_files:
            items.append(finding("CORRELATED_UPLOAD_REQUEST", "high", "medium", "correlation",
                uri, "Ten sam podejrzany plik występuje w obrazie witryny i w logu HTTP; to korelacja, nie dowód wykonania kodu.",
                file_source=uri, log_source=log_item["source"]))
    # Simple PoC timeline. File mtime is mutable and NOT evidence of attack time.
    timeline = []
    for item in items:
        if item["rule"] == "HTTP_EXECUTABLE_IN_UPLOADS":
            stamp = item["metadata"].get("observed_time", "")
            try:
                moment = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                gaps.append("Nie można znormalizować czasu logu: " + stamp[:64])
                continue
            timeline.append({"time_utc": moment.astimezone(timezone.utc).isoformat(),
                "source": item["source"], "event": item["rule"],
                "timestamp_basis": "HTTP access log; synchronizacja zegara niezweryfikowana",
                "confidence": "medium"})
    relevant_paths = {x["source"] for x in items if x["source_type"] == "file"}
    for entry in inputs:
        if entry["source"].startswith("files/") and "mtime_ns" in entry and entry["source"][6:] in relevant_paths:
            timeline.append({"time_utc": datetime.fromtimestamp(entry["mtime_ns"] / 1e9, tz=timezone.utc).isoformat(),
                "source": entry["source"], "event": "SUSPICIOUS_FILE_MTIME",
                "timestamp_basis": "Filesystem mtime: zmienialny; nie oznacza czasu ataku",
                "confidence": "low"})
    timeline.sort(key=lambda event: (event["time_utc"], event["source"]))
    gaps.extend(session.finish())
    counts = dict(Counter(x["severity"] for x in items))
    return {"schema_version": "0.1.0", "tool": "WPTrace PoC", "tool_version": VERSION,
        "case_id": case_id, "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
        "assessment": "INDICATORS_FOUND" if items else "NO_INDICATORS_IN_ANALYZED_SCOPE",
        "disclaimer": "Brak alertów nie dowodzi braku włamania. PoC, nie certyfikacja śledcza.",
        "findings": items, "counts": counts, "timeline": timeline, "coverage_gaps": sorted(set(gaps)),
        "evidence_manifest": sorted(inputs, key=lambda x: x["source"])}


def write_html(report: dict, path: Path) -> None:
    esc = lambda s: html.escape(str(s), quote=True)
    rows = "".join(f"<tr><td>{esc(i['severity'])}</td><td>{esc(i['rule'])}</td><td>{esc(i['source'])}</td><td>{esc(i['explanation'])}</td></tr>" for i in report["findings"])
    gaps = "".join(f"<li>{esc(g)}</li>" for g in report["coverage_gaps"])
    timeline_rows = "".join(f"<tr><td>{esc(i['time_utc'])}</td><td>{esc(i['event'])}</td><td>{esc(i['source'])}</td><td>{esc(i['timestamp_basis'])}</td></tr>" for i in report.get("timeline", []))
    doc = f"""<!doctype html><html lang=\"pl\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>WPTrace · {esc(report['case_id'])}</title>
<style>body{{font:16px/1.5 system-ui,sans-serif;margin:3em auto;max-width:1100px;padding:0 1em;color:#192938}}h1{{font-size:2em}}h2{{margin-top:2em}}table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #cbd5e1;padding:.65em;text-align:left;vertical-align:top}}th{{background:#edf2f7}}small{{color:#48596c}}code{{word-break:break-all}}</style>
<h1>WPTrace — raport analityczny</h1><p>Sprawa: <b>{esc(report['case_id'])}</b> · {esc(report['analyzed_at_utc'])}</p>
<p>Stan: <strong>{esc(report['assessment'])}</strong>. {esc(report['disclaimer'])}</p>
<h2>Ustalenia ({len(report['findings'])})</h2><table><thead><tr><th>Waga</th><th>Reguła</th><th>Źródło</th><th>Wyjaśnienie</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Oś czasu (orientacyjna)</h2><table><thead><tr><th>UTC</th><th>Zdarzenie</th><th>Źródło</th><th>Podstawa czasu</th></tr></thead><tbody>{timeline_rows}</tbody></table>
<h2>Ograniczenia danych</h2><ul>{gaps}</ul><p><small>Pełny manifest SHA-256 i metadane są w report.json. Dane wejściowe nie są modyfikowane.</small></p></html>"""
    path.write_text(doc, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="WPTrace PoC — statyczna analiza kopii WordPressa, bazy SQL i logów")
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
    baseline, prior_inputs, prior_gaps = None, [], []
    if args.baseline:
        try:
            baseline, entry, prior_gaps = load_baseline(args.baseline, session)
        except ValueError as invalid:
            parser.error(f"--baseline: {invalid}")
        prior_inputs = [entry]
    admins = set(args.known_admin) | set((baseline or {}).get("known_admins", []))
    output = compose_report(args.files, args.database, args.logs, baseline, admins, args.case_id,
                            session=session, prior_inputs=prior_inputs, prior_gaps=prior_gaps)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    write_html(output, out / "report.html")
    print(json.dumps({"assessment": output["assessment"], "findings":len(output["findings"]),
                      "coverage_gaps":len(output["coverage_gaps"]), "report":str(out / "report.html")}, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
