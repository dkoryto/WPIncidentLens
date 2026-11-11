"""WPIncidentLens proof of concept. Only read static inputs; never execute WordPress code."""
from __future__ import annotations

import argparse
import io
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import case, files, ingest, integrity, models, report
from .analysis import Detection, SourceCoverage
from .analysis import evidence_of as _evidence
from .analysis import observe as _observe

VERSION = "0.1.0-poc"
DISCLAIMER = "Brak alertów nie dowodzi braku włamania. PoC, nie certyfikacja śledcza."
# Kody wyjścia (specyfikacja §11, ADR 0003): 2 zgłasza argparse przy błędzie wywołania; ustalenia nie zmieniają kodu.
EXIT_COMPLETE, EXIT_PARTIAL, EXIT_UNPROCESSED = 0, 3, 4
# Materiał dowodowy otwiera wyłącznie wpincidentlens.ingest (ADR 0002 D4); ten moduł dostaje już przeczytane bajty.
MAX_FILES = ingest.Limits().max_files
MAX_SCAN_BYTES = ingest.Limits().max_scan_bytes
MAX_SQL_BYTES = 20 * 1024 * 1024
MAX_LOG_BYTES = 30 * 1024 * 1024
MAX_BASELINE_BYTES = 64 * 1024 * 1024


def _session() -> ingest.Session:
    """Sesja odczytu z limitami domyślnymi; stałe MAX_* są czytane w chwili wywołania."""
    return ingest.Session(ingest.Limits(max_files=MAX_FILES, max_scan_bytes=MAX_SCAN_BYTES))


def _text(content: bytes) -> io.TextIOWrapper:
    """Dekoduje jak dotychczasowe otwarcie w trybie tekstowym: UTF-8 ze znakami zastępczymi, uniwersalne końce wierszy."""
    return io.TextIOWrapper(io.BytesIO(content), encoding="utf-8", errors="replace")


def _is_lossy(content: bytes) -> bool:
    """Czy dekodowanie UTF-8 musiało podstawić znaki zastępcze (część treści mogła zmienić znaczenie)."""
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


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


# Lista kolumn nie zawiera nawiasów: [^;()]* kończy się na pierwszym nawiasie, więc nagłówek bez
# zamknięcia nie jest skanowany do końca pliku przy każdym wystąpieniu (czas kwadratowy, #17).
# Biały znak przed VALUES dopasowuje dokładnie jeden kwantyfikator, więc długi ciąg spacji nie daje nawrotów.
_INSERT_HEAD = re.compile(r"INSERT\s+INTO\s+`?([A-Za-z0-9_]+)(?![A-Za-z0-9_])`?\s*(?:(\([^;()]*\))\s*)?VALUES\s*", re.I)
# Leksemy zrzutu SQL potrzebne do znalezienia początków instrukcji. Każda alternatywa zawsze się dopasowuje
# (niedomknięty łańcuch lub komentarz sięga końca tekstu), a kwantyfikatory zaborcze wykluczają nawroty.
_SQL_TOKEN = re.compile(r"""
      '(?:[^'\\]|\\.|'')*+(?:'|\Z)
    | "(?:[^"\\]|\\.|"")*+(?:"|\Z)
    | `[^`]*+(?:`|\Z)
    | (?P<comment> --(?=\s|\Z)[^\n]*+ | \#[^\n]*+ | /\*.*?(?:\*/|\Z) )
    | (?P<end> ; )
    | (?P<space> \s++ )
    | (?P<word> [A-Za-z_]++ )
    | .
""", re.X | re.S)
# Bez \b z lewej: w "/*!50001INSERT" numer wersji przylega do słowa kluczowego i granicy słowa tam nie ma.
_WRITE_KEYWORD = re.compile(r"(?<![A-Za-z_])(?:INSERT|REPLACE)(?![A-Za-z0-9_])", re.I)
_CORE_TABLE_CELLS = {"_users": 2, "_usermeta": 4, "_options": 3}


# Instrukcje, które zrzut może zawierać, a których pominięcie nie ukrywa danych: ustawienia sesji i definicje tabel.
_INERT_STATEMENTS = frozenset({"SET", "USE", "LOCK", "UNLOCK", "START", "COMMIT", "BEGIN"})
_INERT_OBJECTS = frozenset({"TABLE", "DATABASE", "SCHEMA"})  # po CREATE / DROP / ALTER


def _write_statement_starts(sql: str, unanalysed: Counter | None = None):
    """Pozycje instrukcji INSERT/REPLACE: słowo kluczowe jako pierwszy leksem instrukcji, poza łańcuchami i komentarzami.

    Zgłasza też miejsca, których podział na instrukcje nie obejmuje wiarygodnie: komentarz wykonywalny ze słowem
    INSERT/REPLACE i dyrektywę DELIMITER. Wywołujący liczy je jako składnię nieobsługiwaną.

    Używa podziału na instrukcje po średniku, więc instrukcja w tym samym wierszu co poprzednia albo po
    komentarzu też jest widziana; słowo INSERT w treści wartości nie jest liczone.

    Każda inna instrukcja, która nie jest obojętnym ustawieniem ani definicją tabeli (np. UPDATE, DELETE,
    CREATE TRIGGER, CALL), jest liczona w ``unanalysed`` pod swoim początkowym słowem kluczowym: parser jej nie
    interpretuje, więc nie może zniknąć bez śladu.
    """
    at_start, definer = True, None  # definer: CREATE / DROP / ALTER czekające na nazwę rodzaju obiektu
    for token in _SQL_TOKEN.finditer(sql):
        if token["comment"]:
            # Komentarz wykonywalny (/*!NNNNN ... */, /*M! ... */) serwer traktuje jak kod.
            if token["comment"].startswith(("/*!", "/*M!")) and _WRITE_KEYWORD.search(token["comment"]):
                yield token.start()
            continue
        if token["space"]:
            continue
        if token["end"]:
            at_start, definer = True, None
            continue
        word = (token["word"] or "").upper()
        if unanalysed is not None:
            if definer:
                if word not in _INERT_OBJECTS:
                    unanalysed[f"{definer} {word}"[:40] if word else definer] += 1
                definer = None
            elif at_start and word in ("CREATE", "DROP", "ALTER"):
                definer = word
            elif at_start and word not in _INERT_STATEMENTS and word not in ("INSERT", "REPLACE", "DELIMITER"):
                unanalysed[word[:40] or "(nie słowo kluczowe)"] += 1
        # DELIMITER zmienia znak końca instrukcji: dalszego podziału po średniku nie można uznać za wiarygodny.
        # Ukośnik wsteczny poza łańcuchem i komentarzem to polecenie klienta (\d, \g, \G): może zakończyć
        # instrukcję albo zmienić jej terminator w dowolnym miejscu, a poprawny zrzut go tam nie zawiera.
        if token.group() == "\\" or (at_start and (token["word"] or "").upper() in ("INSERT", "REPLACE", "DELIMITER")):
            yield token.start()
        at_start = False


def iter_insert_rows(sql: str, dropped: list[str] | None = None):
    """Narrow PoC subset of mysqldump INSERT syntax; does NOT execute SQL.

    Supports quoted identifiers, optional column list, multi-row VALUES, MySQL
    backslash quotes, numeric and NULL literals. Unsupported INSERTs are ignored;
    a statement that is not terminated (truncated dump) is skipped and its table
    name is appended to ``dropped`` so the caller can report the gap.
    """
    pos = 0
    while (m := _INSERT_HEAD.search(sql, pos)) is not None:
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
            if dropped is not None:
                dropped.append(table)
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
    if _is_lossy(item.content):
        cover.degrade("Eksport SQL nie jest poprawnym UTF-8: zdekodowano ze znakami zastępczymi, wartości mogą być zniekształcone")
    sql = _text(item.content).read()
    users, admins, count = {}, {}, 0  # admins: identyfikator użytkownika → miejsce pierwszego wiersza z rolą
    tables = set()
    dropped: list[str] = []
    malformed, core_seen = 0, False
    for table, cols, cells in iter_insert_rows(sql, dropped):
        tables.add(table)
        count += 1
        if count > 100000:
            cover.degrade("Przekroczono 100000 wierszy INSERT, analiza częściowa")
            break
        if needed := next((cells_needed for suffix, cells_needed in _CORE_TABLE_CELLS.items() if table.endswith(suffix)), 0):
            core_seen = True
            # Wiersz z wyrażeniem zamiast literału (np. CONCAT(...)) rozpada się na mniej pól, niż ma tabela.
            if (len(cells) != len(cols)) if cols else (len(cells) < needed):
                malformed += 1
                continue
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
                admins.setdefault(str(row.get("user_id")), models.Location(table=table, key=str(row.get("meta_key"))[:200], row=count))
        elif table.endswith("_options"):
            if cols:
                row = dict(zip(cols, cells))
            elif len(cells) >= 3:
                row = {"option_name": cells[1], "option_value": cells[2]}
            else:
                continue
            key = str(row.get("option_name") or "")[:200]
            value = str(row.get("option_value") or "")
            if re.search(r"<script\b|<iframe\b|javascript\s*:", value, flags=re.I):
                findings.append(Detection("SUSPICIOUS_DB_MARKUP", "medium", "low", "database",
                    "Wartość opcji zawiera aktywny znacznik HTML lub schemat JS; wymaga weryfikacji.",
                    _observe(item, "OPTION_VALUE_WITH_ACTIVE_MARKUP", models.Location(table=table, key=key, row=count))))
    if not tables:
        cover.fail("Brak obsługiwanych instrukcji INSERT; parser PoC nie interpretuje tego formatu SQL")
    elif not core_seen:
        cover.fail("Zrzut nie zawiera odczytanych wierszy tabel *_users, *_usermeta ani *_options; "
                   "analiza DB nie objęła danych WordPressa")
    if dropped:
        cover.degrade(f"Pominięto {len(dropped)} niedomkniętych instrukcji INSERT (zrzut ucięty lub uszkodzony)")
    if malformed:
        cover.degrade(f"Pominięto {malformed} wierszy tabel użytkowników lub opcji o nieoczekiwanej liczbie pól "
                      "(np. wyrażenie SQL zamiast literału)")
    unanalysed: Counter = Counter()
    unsupported = sum(1 for start in _write_statement_starts(sql, unanalysed) if _INSERT_HEAD.match(sql, start) is None)
    if unanalysed:
        listed = ", ".join(f"{keyword} ×{number}" for keyword, number in sorted(unanalysed.items(), key=lambda pair: (-pair[1], pair[0]))[:8])
        cover.degrade(f"Zrzut zawiera {sum(unanalysed.values())} instrukcji, których parser PoC nie analizuje: {listed}")
    if unsupported:
        cover.degrade(f"Pominięto {unsupported} instrukcji INSERT/REPLACE w nieobsługiwanej składni "
                      "(np. REPLACE INTO, INSERT IGNORE, nazwa z bazą, INSERT ... SET, komentarz wykonywalny, DELIMITER)")
    for user_id in sorted(admins):
        login = users.get(user_id, "")
        if not login:
            # Roli nie da się porównać z zaufaną listą: bez luki administrator zniknąłby z raportu bez śladu.
            cover.degrade(f"Rola administratora dla user_id {str(user_id)[:40]} bez odczytanego wiersza w tabeli użytkowników; "
                          "nie można ustalić loginu ani porównać go z zaufaną listą")
            continue
        if known_admins and login not in known_admins:
            findings.append(Detection("UNRECOGNIZED_ADMIN", "high", "medium", "database",
                "Administrator nie figuruje na dostarczonej, zaufanej liście; nie dowodzi to włamania.",
                _observe(item, "ADMINISTRATOR_ROLE_ROW", admins[user_id], username=login, user_id=user_id)))
    if admins and not known_admins:
        cover.note("Wykryto role administratorów, ale brak wiarygodnej listy porównawczej; sam fakt istnienia admina nie jest alertem")
    cover.note("Parser SQL PoC obsługuje wybrane INSERT; nie obsługuje triggerów, procedur, pełnej składni ani multisite")
    return findings, cover

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
        if _is_lossy(item.content):
            cover.degrade(f"Log nie jest poprawnym UTF-8: zdekodowano ze znakami zastępczymi: {name}")
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
                  session: ingest.Session) -> tuple[list[Detection], dict[str, SourceCoverage], list[models.Observation]]:
    """Uruchamia skanery podanych źródeł; źródło niepodane dostaje powód zamiast skanu. Trzeci wynik: fakty bez ustalenia."""
    cover = {source: SourceCoverage(provided=False) for source in models.SOURCES}
    scan = files.scan_files(root, baseline, session)
    detections, cover["files"] = scan.detections, scan.cover
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
    return detections, cover, scan.observations


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
    if baseline is not None and integrity.baseline_record(session) is None:
        raise ValueError("baseline musi być wczytany przez load_baseline w tej samej sesji odczytu")
    detections, cover, facts = _scan_sources(root, database, logs, baseline, known_admins, session)
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
            allow_hardlinks=args.allow_hardlinks, reverify=not args.no_reverify,
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
    admins = set(context.known_admins) | set((baseline or {}).get("known_admins", []))
    output = compose_report(context.files, context.database, context.logs, baseline, admins, context.case_id, session=session)
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
