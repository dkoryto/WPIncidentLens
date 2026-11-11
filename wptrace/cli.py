"""WPTrace proof of concept. Only read static inputs; never execute WordPress code."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import stat
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.1.0-poc"
MAX_FILES = 20000
MAX_SCAN_BYTES = 4 * 1024 * 1024
MAX_SQL_BYTES = 20 * 1024 * 1024
MAX_LOG_BYTES = 30 * 1024 * 1024
CODE_SUFFIXES = {".php", ".phtml", ".phar", ".inc"}


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def finding(rule: str, severity: str, confidence: str, kind: str,
            path: str, explanation: str, **metadata: Any) -> dict:
    return {"rule": rule, "severity": severity, "confidence": confidence,
            "source_type": kind, "source": path, "explanation": explanation,
            "metadata": metadata}


def scan_files(root: Path, baseline: dict | None) -> tuple[list[dict], list[dict], list[str]]:
    discoveries, manifest, gaps = [], [], []
    visited = 0
    stack = [root]
    ref = (baseline or {}).get("files", {})
    while stack:
        current = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda x: x.name)
        except OSError as exc:
            gaps.append(f"Nie można odczytać katalogu {current.relative_to(root)}: {exc}")
            continue
        for entry in entries:
            path = Path(entry.path)
            rel = path.relative_to(root).as_posix()
            try:
                info = path.lstat()
            except OSError as exc:
                gaps.append(f"Nie można sprawdzić {rel}: {exc}")
                continue
            if stat.S_ISLNK(info.st_mode):
                gaps.append(f"Łącze symboliczne pominięte (bez podążania): {rel}")
                continue
            if stat.S_ISDIR(info.st_mode):
                stack.append(path)
                continue
            if not stat.S_ISREG(info.st_mode):
                gaps.append(f"Plik specjalny pominięty: {rel}")
                continue
            visited += 1
            if visited > MAX_FILES:
                gaps.append(f"Limit {MAX_FILES} plików; analiza katalogu niepełna")
                return discoveries, manifest, gaps
            try:
                sha = digest_file(path)
            except OSError as exc:
                gaps.append(f"Nie można obliczyć SHA-256 {rel}: {exc}")
                continue
            manifest.append({"source": f"files/{rel}", "sha256": sha,
                             "size": info.st_size, "mtime_ns": info.st_mtime_ns})
            if rel in ref and ref[rel] != sha:
                discoveries.append(finding("BASELINE_FILE_CHANGED", "medium", "high",
                    "file", rel, "Plik zmieniony względem zaufanej migawki (zmiana nie przesądza o ataku).",
                    sha256=sha, baseline_sha256=ref[rel]))
            if rel.startswith("wp-content/uploads/") and path.suffix.lower() in CODE_SUFFIXES:
                discoveries.append(finding("EXECUTABLE_IN_UPLOADS", "high", "medium",
                    "file", rel, "Plik wykonywalny PHP w uploads; wymaga analizy kontekstu.", sha256=sha))
            if info.st_size > MAX_SCAN_BYTES:
                gaps.append(f"Analiza treści pominięta, plik > {MAX_SCAN_BYTES} B: {rel}")
                continue
            if path.suffix.lower() not in CODE_SUFFIXES and path.name not in (".htaccess", ".user.ini"):
                continue
            try:
                raw = path.read_bytes().lower()
            except OSError as exc:
                gaps.append(f"Odczyt treści nieudany {rel}: {exc}")
                continue
            if re.search(rb"eval\s*\(\s*base64_decode\s*\(", raw):
                discoveries.append(finding("SUSPICIOUS_PHP_EVAL_DECODE", "high", "medium",
                    "file", rel, "Wykryto łańcuch eval(base64_decode(...)); to heurystyka, nie dowód malware.", sha256=sha))
            if re.search(rb"\$_(?:post|get|request)\s*\[.{0,120}\].{0,150}(?:shell_exec|system|passthru)\s*\(", raw, re.DOTALL):
                discoveries.append(finding("REQUEST_TO_COMMAND_EXEC", "high", "medium",
                    "file", rel, "Potencjalne powiązanie danych żądania z wykonaniem komendy; wymaga ręcznej weryfikacji.", sha256=sha))
    if baseline and ref:
        observed = {x["source"][6:] for x in manifest}
        for rel in ref.keys() - observed:
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


def scan_database(path: Path, known_admins: set[str]) -> tuple[list[dict], dict, list[str]]:
    gaps, findings = [], []
    size = path.stat().st_size
    entry = {"source": f"database/{path.name}", "sha256": digest_file(path), "size": size}
    if size > MAX_SQL_BYTES:
        gaps.append(f"Eksport SQL większy niż {MAX_SQL_BYTES} B: analiza DB pominięta w PoC")
        return findings, entry, gaps
    sql = path.read_text(encoding="utf-8", errors="replace")
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

def scan_logs(root: Path) -> tuple[list[dict], list[dict], list[str]]:
    findings, manifest, gaps = [], [], []
    files = [root] if root.is_file() else sorted(root.rglob("*"))
    observed, skipped, matched = 0, 0, 0
    for path in files:
        if path.is_symlink() or not path.is_file():
            if path.is_symlink(): gaps.append(f"Pominięto link w logach: {path.name}")
            continue
        size = path.stat().st_size
        manifest.append({"source": f"logs/{path.name}", "sha256": digest_file(path), "size": size})
        if size > MAX_LOG_BYTES:
            gaps.append(f"Log za duży do parsowania w PoC: {path.name}")
            continue
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for ln, line in enumerate(stream, start=1):
                observed += 1
                m = LOG_PATTERN.match(line)
                if not m:
                    skipped += 1
                    continue
                matched += 1
                ip, timestamp, method, uri, status = m.groups()
                if method in {"POST", "GET"} and re.search(r"/wp-content/uploads/[^?\s]+\.(?:php|phtml|phar)(?:\?|$)", uri, re.I):
                    findings.append(finding("HTTP_EXECUTABLE_IN_UPLOADS", "high", "medium", "http_log",
                        f"{path.name}:{ln}", "Żądanie HTTP do pliku PHP w uploads; brak dowodu wykonania kodu.",
                        uri=uri[:300], method=method, status=int(status),
                        observed_time=timestamp, client_ip=ip))
    if observed and not matched:
        gaps.append("Logi nie odpowiadają obsługiwanemu formatowi Apache/Nginx combined")
    elif observed and skipped:
        gaps.append(f"Nie sparsowano {skipped}/{observed} wierszy logów")
    return findings, manifest, gaps


def compose_report(root: Path, database: Path | None, logs: Path | None,
                   baseline: dict | None, known_admins: set[str], case_id: str) -> dict:
    file_findings, inputs, gaps = scan_files(root, baseline)
    items = list(file_findings)
    if database:
        f, man, g = scan_database(database, known_admins)
        items.extend(f); inputs.append(man); gaps.extend(g)
    else:
        gaps.append("Brak zrzutu bazy danych")
    if logs:
        f, man, g = scan_logs(logs)
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
    args = parser.parse_args(argv)
    root = args.files.resolve(strict=True)
    if not root.is_dir(): parser.error("--files musi wskazywać katalog")
    out = args.output.resolve()
    if out == root or root in out.parents:
        parser.error("--output nie może znajdować się w analizowanym katalogu")
    if args.database and not args.database.is_file(): parser.error("--database: brak pliku")
    if args.logs and not args.logs.exists(): parser.error("--logs: brak wskazanej ścieżki")
    baseline = None
    if args.baseline:
        baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        if not isinstance(baseline.get("files", {}), dict): parser.error("baseline.files musi być obiektem")
    admins = set(args.known_admin) | set((baseline or {}).get("known_admins", []))
    output = compose_report(root, args.database, args.logs, baseline, admins, args.case_id)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    write_html(output, out / "report.html")
    print(json.dumps({"assessment": output["assessment"], "findings":len(output["findings"]),
                      "coverage_gaps":len(output["coverage_gaps"]), "report":str(out / "report.html")}, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
