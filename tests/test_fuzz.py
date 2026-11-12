"""Fuzzing ze strukturą (ADR 0009 pkt 3): generatory poprawnych i prawie poprawnych wejść parserów.

Uzupełnia mutacyjne fuzzy w ``test_sqldump.py``, ``test_jsonldb.py`` i ``test_httplog.py``: tam mutowany jest jeden
stały plik, tutaj ``hypothesis`` buduje wejście z gramatyki (zrzut mysqldump, wiersze JSONL, wiersze logów, dane
``serialize()``, tekst do redakcji) i zna oczekiwany wynik dla wejścia poprawnego. Niezmienniki:

- brak wyjątku spoza kontraktu (parser SQL/JSONL/logów: żadnego; ``phpserialize``: tylko ``SerializedError``);
- wynik deterministyczny i **niezależny od podziału strumienia na porcje** (losowe granice, także w środku ucieczki
  i znaku wielobajtowego UTF-8);
- ograniczony czas jednego przykładu (``deadline`` profilu w ``conftest.py``), także dla wejść z długimi powtórzeniami;
- ``redact`` idempotentny, bez znaków sterujących w wyniku i bez nieograniczonego wydłużania tekstu.

Profil ``ci`` jest stały (derandomize); ``HYPOTHESIS_PROFILE=nightly`` przeszukuje losowo i dłużej. Dane wyłącznie
syntetyczne; nic nie jest wykonywane.
"""
from __future__ import annotations

import ipaddress
import json
import re
import unicodedata

import pytest
from hypothesis import assume, example, given
from hypothesis import strategies as st

from wpincidentlens import jsonldb, logformats, phpserialize, privacy, redact, sqldump
from wpincidentlens.httplog import LogConfig, LogFileParser

# --- wspólne ------------------------------------------------------------------------------------

# Tekst bez surogatów (nie da się go zakodować w UTF-8), ale z każdą inną kategorią: sterujące, formatujące, wielobajtowe.
TEXT = st.text(st.characters(exclude_categories=("Cs",)), max_size=40)
TRICKY_TEXT = st.text(st.sampled_from(list("a;'\"`\\-#/*!()\n\r\t\0 ,xż€𝄞\x1a%_?=&@:<>[]")) | st.characters(exclude_categories=("Cs",)),
                      max_size=40)


@st.composite
def splits(draw, data: bytes) -> list[bytes]:
    """``data`` w porcjach o losowych granicach (od jednej porcji do kilkudziesięciu, także puste i jednobajtowe)."""
    cuts = sorted(draw(st.lists(st.integers(0, len(data)), max_size=40)))
    edges = [0, *cuts, len(data)]
    return [data[start:end] for start, end in zip(edges, edges[1:])]


@st.composite
def mutated(draw, data: bytes, alphabet: list[bytes]) -> bytes:
    """Prawie poprawne wejście: kilka wycięć, wstawek z alfabetu gramatyki, podmian bajtu i powtórzeń fragmentu."""
    buffer = bytearray(data)
    for _ in range(draw(st.integers(1, 6))):
        at = draw(st.integers(0, len(buffer)))
        action = draw(st.integers(0, 3))
        if action == 0:
            del buffer[at:at + draw(st.integers(1, 20))]
        elif action == 1:
            buffer[at:at] = draw(st.sampled_from(alphabet))
        elif action == 2 and at < len(buffer):
            buffer[at] = draw(st.integers(0, 255))
        else:
            buffer[at:at] = buffer[at:at + draw(st.integers(1, 30))] * draw(st.integers(1, 3))
    return bytes(buffer)


@st.composite
def repeated(draw, alphabet: list[bytes]) -> bytes:
    """Długie powtórzenie krótkiego wzorca (do ~60 KiB): wykrywa czas nieliniowy wyrażeń regularnych."""
    unit = b"".join(draw(st.lists(st.sampled_from(alphabet), min_size=1, max_size=6)))
    return unit * draw(st.integers(200, max(200, 60_000 // max(1, len(unit)))))


# --- zrzut SQL ----------------------------------------------------------------------------------

_NOT_ESCAPABLE = set("0bnrtZ%_")  # ``\x`` dla tych znaków znaczy coś innego niż sam znak


@st.composite
def mysql_string(draw) -> tuple[str, str]:
    """Łańcuch MySQL w apostrofach i jego wartość; ucieczki wybierane losowo (jak mysqldump i jak człowiek)."""
    value = draw(TRICKY_TEXT)
    out = []
    for char in value:
        style = draw(st.integers(0, 2))
        if char == "\\":
            out.append("\\\\")
        elif char == "'":
            out.append("''" if style else "\\'")
        elif char == "\n" and style == 2:
            out.append("\\\n")  # ukośnik i surowy LF: nieznana ucieczka, czyli sam LF
        elif char in "\0\n\r\x1a" and style:
            out.append({"\0": "\\0", "\n": "\\n", "\r": "\\r", "\x1a": "\\Z"}[char])
        elif style == 2 and char not in _NOT_ESCAPABLE:
            out.append("\\" + char)  # nieznana ucieczka: ``\q`` to ``q``, ``\ż`` to ``ż``
        else:
            out.append(char)
    return "'" + "".join(out) + "'", value


@st.composite
def sql_literal(draw) -> tuple[str, str | None]:
    kind = draw(st.sampled_from(["str", "str", "null", "int", "float", "hex", "xhex", "binary"]))
    if kind == "str":
        return draw(mysql_string())
    if kind == "null":
        return draw(st.sampled_from(["NULL", "null"])), None
    if kind == "int":
        text = draw(st.sampled_from(["", "-", "+"])) + str(draw(st.integers(0, 10**22)))
        return text, text
    if kind == "float":
        text = repr(draw(st.floats(allow_nan=False, allow_infinity=False)))
        return text, text
    raw = draw(st.binary(max_size=12) | TEXT.map(lambda text: text.encode("utf-8")))
    if kind == "hex":
        return "0x" + raw.hex(), raw.decode("utf-8", "replace")
    if kind == "xhex":
        return draw(st.sampled_from("xX")) + "'" + raw.hex().upper() + "'", raw.decode("utf-8", "replace")
    literal, value = draw(mysql_string())
    return "_binary " + literal, value


SPACE = st.sampled_from(["", " ", "\n", "  \t"])
TABLE = st.sampled_from(["wp_users", "wp_usermeta", "wp_options", "Wp_Options", "wp_posts", "t$1", "a_b"])
COLUMN = st.from_regex(r"[A-Za-z_][A-Za-z0-9_$]{0,9}", fullmatch=True)
COLUMN_TYPE = st.sampled_from(["bigint(20) unsigned NOT NULL AUTO_INCREMENT", "varchar(191) NOT NULL DEFAULT ''", "longtext",
                               "datetime NOT NULL DEFAULT '0000-00-00 00:00:00'", "int NOT NULL DEFAULT '0'",
                               "varchar(20) DEFAULT 'a;b''c' COMMENT 'x)y'", "decimal(10,2) DEFAULT NULL"])
# Instrukcje i komentarze, które poprawny zrzut zawiera i które nie zostawiają śladu w licznikach.
NOISE = st.sampled_from([
    "-- MySQL dump 10.13 ; it's\n", "# hash ; \"comment\n", "/* block ; ' \" */", "--\n",
    "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;", "/*!40101 SET NAMES utf8mb4 */;",
    "SET NAMES utf8mb4;", "/*!40103 SET TIME_ZONE='+00:00' */;",
    "/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;",
    "/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;",
    "/*!50503 SET character_set_client = utf8mb4 */;",
    "DROP TABLE IF EXISTS `wp_options`;", "LOCK TABLES `wp_options` WRITE;", "UNLOCK TABLES;",
    "/*!40000 ALTER TABLE `wp_options` DISABLE KEYS */;", "START TRANSACTION;", "COMMIT;", "USE `wordpress`;",
])


@st.composite
def create_table(draw) -> tuple[str, str, list[str]]:
    table = draw(TABLE)
    columns = draw(st.lists(COLUMN, min_size=1, max_size=5))
    parts = [f"  `{name}` {draw(COLUMN_TYPE)}" for name in columns]
    parts.append(f"  PRIMARY KEY (`{columns[0]}`)")
    if draw(st.booleans()):
        parts.append(f"  KEY `idx` (`{columns[-1]}`(10))")
    options = draw(st.sampled_from([" ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci", " ENGINE=MyISAM",
                                    "", " ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COMMENT='a;b'"]))
    head = draw(st.sampled_from(["CREATE TABLE", "create table", "CREATE TABLE IF NOT EXISTS"]))
    return f"{head} `{table}` (\n" + ",\n".join(parts) + f"\n){options};", table, columns


@st.composite
def insert(draw) -> tuple[str, str, list[str] | None, list[list[str | None]]]:
    table = draw(TABLE)
    named = draw(st.booleans())
    columns = draw(st.lists(COLUMN, min_size=1, max_size=4)) if named else None
    rows = draw(st.lists(st.lists(sql_literal(), min_size=1, max_size=4), min_size=1, max_size=4))
    space = draw(SPACE)
    rendered = [f"({space}" + f"{space},{space}".join(literal for literal, _ in row) + f"{space})" for row in rows]
    name = f"`{table}`" if not table[:1].isupper() or draw(st.booleans()) else table
    head = draw(st.sampled_from(["INSERT INTO", "insert into", "INSERT  INTO"]))
    column_list = "" if columns is None else " (" + ", ".join(f"`{column}`" for column in columns) + ")"
    values = draw(st.sampled_from(["VALUES", "values", "VALUES\n"]))
    text = f"{head} {name}{column_list} {values} " + ("," + draw(SPACE)).join(rendered) + ";"
    return text, table, columns, [[value for _, value in row] for row in rows]


@st.composite
def dump(draw) -> tuple[bytes, list]:
    """Poprawny zrzut i oczekiwane wiersze ``(tabela, kolumny, komórki, numer)`` wyliczone z modelu, nie z parsera."""
    ddl: dict[str, list[str]] = {}
    statements, expected = [], []
    for _ in range(draw(st.integers(0, 8))):
        kind = draw(st.sampled_from(["noise", "create", "insert", "insert"]))
        if kind == "noise":
            statements.append(draw(NOISE))
        elif kind == "create":
            text, table, columns = draw(create_table())
            ddl[table.lower()] = columns
            statements.append(text)
        else:
            text, table, columns, rows = draw(insert())
            for cells in rows:
                expected.append((table, list(columns if columns is not None else ddl.get(table.lower(), [])), cells, len(expected) + 1))
            statements.append(text)
    separator = draw(st.sampled_from(["\n", " ", "\n\n", "\r\n"]))
    return (separator.join(statements) + draw(st.sampled_from(["", "\n", "\n-- Dump completed"]))).encode("utf-8"), expected


def sql_state(chunks) -> tuple:
    rows, parser = sqldump.parse(chunks)
    return (rows, sorted(parser.tables), dict(parser.unanalysed), parser.unsupported, parser.expression_rows, parser.truncated,
            parser.lossy_cells, parser.rows, parser.oversized_at, parser.mode_change_at, parser.mode_change, parser.ddl,
            sorted(parser.ddl_names), parser.names_overflow)


SQL_ALPHABET = [b"'", b'"', b"`", b"\\", b"\\\n", b"'\\\n", b";", b"(", b")", b"--", b"-- ", b"#", b"/*", b"*/", b"/*!40101 ", b"*/;", b"\n", b",",
                b"\xff", b"\xc5", b"\xe2\x82", b"0x", b"X'", b"''", b"\\'", b"SET NAMES sjis;", b"SET sql_mode='ANSI_QUOTES';",
                b"DELIMITER ;;\n", b"INSERT INTO `t` VALUES ", b"VALUES", b"NULL", b"CONCAT(", b"_binary ", b"REPLACE ",
                b"/*M!999999\\- enable the sandbox mode */", b"ON DUPLICATE KEY UPDATE a=1", b"SELECT ", b"CREATE TABLE `x` ("]


@given(dump().flatmap(lambda case: st.tuples(st.just(case), splits(case[0]))))
# Granice porcji w środku ucieczki ``\\`` / ``\'`` i w środku znaku „ż”.
@example(((b"INSERT INTO `t` VALUES ('\\\\\\'\xc5\xbc');", [("t", [], ["\\'ż"], 1)]),
          [b"INSERT INTO `t` VALUES ('\\", b"\\\\'\xc5", b"\xbc');"]))
def test_valid_dump_gives_exactly_the_modelled_rows_in_any_chunking(case):
    (data, expected), chunks = case
    state = sql_state(chunks)
    rows, tables, unanalysed, unsupported, expressions, truncated, lossy, count, oversized, mode_at, *_ = state

    assert rows == expected
    assert (unanalysed, unsupported, expressions, truncated, oversized, mode_at) == ({}, 0, 0, [], None, None)
    assert count == len(expected) and tables == sorted({table for table, *_ in expected})
    assert state == sql_state([data])


@given(dump().flatmap(lambda case: mutated(case[0], SQL_ALPHABET)).flatmap(lambda data: st.tuples(st.just(data), splits(data))))
def test_near_valid_dump_never_crashes_and_does_not_depend_on_chunking(case):
    data, chunks = case
    whole = sql_state([data])

    assert sql_state(chunks) == whole == sql_state([data])
    rows, *_, count, _oversized, _mode_at, _mode, _ddl, _names, _overflow = whole
    numbers = [number for *_, number in rows]
    assert numbers == sorted(set(numbers)) and len(rows) <= count
    assert all(isinstance(table, str) and all(isinstance(column, str) for column in columns)
               and all(cell is None or isinstance(cell, str) for cell in cells) for table, columns, cells, _ in rows)


@given(repeated(SQL_ALPHABET + [b"INSERT INTO `t` VALUES (1,'a')", b"(", b"'a',", b"/*!", b"SET @a=1,"]))
def test_dump_of_long_repetitions_is_parsed_in_bounded_time(data):
    assert sql_state([data[:7], data[7:]]) == sql_state([data])


# --- JSONL --------------------------------------------------------------------------------------

JSON_NAME = st.from_regex(r"[A-Za-z0-9_$]{1,12}", fullmatch=True)
JSON_SCALAR = st.one_of(st.none(), TEXT, st.integers(-10**30, 10**30), st.floats(allow_nan=False, allow_infinity=False))


@st.composite
def jsonl_file(draw) -> tuple[bytes, list, int]:
    """Plik JSONL z wierszami poprawnymi i odrzucanymi; oczekiwane wiersze i liczba wierszy niepustych z modelu."""
    lines, expected, counted = [], [], 0
    for number in range(1, draw(st.integers(0, 8)) + 1):
        kind = draw(st.sampled_from(["row", "row", "blank", "bad"]))
        if kind == "row":
            table = draw(JSON_NAME)
            row = draw(st.dictionaries(JSON_NAME, JSON_SCALAR, min_size=1, max_size=5))
            text = json.dumps({"row": row, "table": table} if draw(st.booleans()) else {"table": table, "row": row},
                              ensure_ascii=draw(st.booleans()), separators=draw(st.sampled_from([(",", ":"), (", ", ": ")])))
            cells = [None if value is None else value if isinstance(value, str) else json.dumps(value) for value in row.values()]
            expected.append((table, list(row), cells, number))
            counted += 1
        elif kind == "blank":
            text = draw(st.sampled_from(["", " ", "\t \r"]))
        else:
            text = draw(st.sampled_from([
                '{"table":"t","row":{"a":1,"a":2}}', '{"table":"t","row":{"a":true}}', '{"table":"t","row":{"a":NaN}}',
                '{"table":"t","row":{"a":"\\udc00"}}', '{"table":"t-x","row":{"a":1}}', '{"table":"t","row":{}}',
                '{"table":1,"row":{"a":1}}', '["t",{"a":1}]', "INSERT INTO `t` VALUES (1);", '{"table":"t","row":{"a":[1]}}',
                '{"table":"t","row":{"a":1}', "\x0b{}"]))
            counted += 1
        lines.append(text.encode("utf-8") + draw(st.sampled_from([b"", b"\r"])))
    tail = draw(st.sampled_from([b"\n", b""])) if lines else b""
    return b"\n".join(lines) + tail, expected, counted


def jsonl_state(chunks, max_line: int = jsonldb.MAX_LINE_BYTES) -> tuple:
    parser = jsonldb.JsonlParser(max_line=max_line)
    rows = [row for chunk in chunks for row in parser.feed(chunk)]
    rows += parser.close()
    return rows, parser.rows, dict(parser.rejected), parser.first_rejected, sorted(parser.tables), parser._line


def counted_lines(data: bytes, max_line: int = jsonldb.MAX_LINE_BYTES) -> int:
    """Wiersze pliku, które parser musi policzyć (przyjęte albo odrzucone) — wyliczone niezależnie od parsera:
    każdy za długi i każdy niepusty po usunięciu spacji, tabulacji i ``\\r``."""
    lines = data.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    return sum(1 for line in lines if len(line) > max_line or line.strip(b" \t\r"))


@given(jsonl_file().flatmap(lambda case: st.tuples(st.just(case), splits(case[0]))))
def test_valid_jsonl_rows_come_back_exactly_in_any_chunking(case):
    (data, expected, counted), chunks = case
    rows, accepted, rejected, _first, _tables, _line = state = jsonl_state(chunks)

    assert rows == expected and accepted == len(expected)
    assert accepted + sum(rejected.values()) == counted
    assert state == jsonl_state([data])


JSONL_ALPHABET = [b"{", b"}", b"[", b"]", b'"', b":", b",", b"\\", b"\\u", b"\\ud800", b"\n", b"\r", b" ", b"\xff", b"\xc3",
                  b"true", b"null", b"1e999", b"-0", b'"table"', b'"row"', b"NaN", b"\x0b"]


@given(jsonl_file().flatmap(lambda case: mutated(case[0], JSONL_ALPHABET)).flatmap(
    lambda data: st.tuples(st.just(data), splits(data), st.integers(8, 120))))
def test_near_valid_jsonl_counts_every_line_and_does_not_depend_on_chunking(case):
    data, chunks, max_line = case
    whole = jsonl_state([data], max_line)
    rows, accepted, rejected, *_ = whole

    assert jsonl_state(chunks, max_line) == whole
    assert accepted + sum(rejected.values()) == counted_lines(data, max_line)
    assert set(rejected) <= set(jsonldb.REASONS)
    assert len(rows) == accepted
    assert all(cell is None or isinstance(cell.encode("utf-8"), bytes) for row in rows for cell in row[2])


# --- logi HTTP ----------------------------------------------------------------------------------

IPV4 = st.ip_addresses(v=4).map(str)
IPV6 = st.ip_addresses(v=6).map(str)
HOSTNAME = st.from_regex(r"[A-Za-z0-9][A-Za-z0-9.-]{0,30}", fullmatch=True)
METHOD = st.sampled_from(["GET", "POST", "HEAD", "PUT", "PROPFIND", "get", "M-SEARCH"])
CLF_TIME = st.builds(lambda day, month, year, h, m, s, sign, zone: f"{day:02d}/{month}/{year:04d}:{h:02d}:{m:02d}:{s:02d} {sign}{zone:04d}",
                     st.integers(1, 28), st.sampled_from(["Jan", "Feb", "Mar", "Nov", "Dec"]), st.integers(1, 9999), st.integers(0, 23),
                     st.integers(0, 59), st.integers(0, 59), st.sampled_from("+-"), st.sampled_from([0, 100, 530, 1200, 1400]))
PATH_BYTES = st.binary(max_size=30).map(lambda raw: b"/" + raw.replace(b"%", b"").replace(b"?", b"").replace(b"#", b""))


def apache_escape(raw: bytes) -> str:
    """Bajty celu tak, jak zapisuje je Apache (``ap_escape_logitem``): ``\\"``, ``\\\\``, ``\\xNN`` poza ASCII drukowalnym."""
    out = []
    for byte in raw:
        if byte in b'"\\':
            out.append("\\" + chr(byte))
        elif 0x21 <= byte < 0x7F:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


def percent_encode(raw: bytes) -> str:
    return "".join(chr(byte) if 0x21 <= byte < 0x7F and byte not in b'"\\' else f"%{byte:02X}" for byte in raw)


@st.composite
def access_line(draw) -> tuple[str, dict]:
    """Wiersz ``combined``/``common`` w poprawnej postaci i oczekiwane pola rekordu."""
    client = draw(IPV4 | IPV6 | HOSTNAME.filter(lambda name: logformats.ip_or_none(name) is None))
    method = draw(METHOD)
    target = apache_escape(draw(PATH_BYTES)) + draw(st.sampled_from(["", "?a=1&b=\\x22", "#frag", "?q=%2F"]))
    if draw(st.booleans()):
        target = draw(st.sampled_from(["http://", "https://user:pw@"])) + "example.test" + target
    status, size = draw(st.integers(100, 599)), draw(st.none() | st.integers(0, 10**17))
    when = draw(CLF_TIME)
    request = f"{method} {target}" + draw(st.sampled_from([" HTTP/1.1", " HTTP/2.0", " HTTP/2", ""]))
    line = f'{client} - {draw(st.sampled_from(["-", "user"]))} [{when}] "{request}" {status} {"-" if size is None else size}'
    fmt = draw(st.sampled_from(["combined", "common"]))
    if fmt == "combined":
        agent = apache_escape(draw(TEXT).encode("utf-8"))
        line += f' "{apache_escape(draw(TEXT).encode("utf-8"))}" "{agent}"'
    line += draw(st.sampled_from(["", ' "198.51.100.7, 10.0.0.1"', " 0.123 extra"]))  # XFF i inne pola dopisane
    canonical = str(ipaddress.ip_address(client)) if logformats.ip_or_none(client) else client
    return line, {"fmt": fmt, "client": canonical, "method": method, "target": target, "status": status, "bytes": size,
                  "timestamp_raw": when}


@given(access_line())
def test_valid_access_line_parses_to_the_modelled_fields(case):
    line, expected = case
    record = logformats.parse(expected.pop("fmt"), line)

    assert isinstance(record, logformats.HttpRecord), record
    assert {name: getattr(record, name) for name in expected} == expected
    assert record.timestamp_utc is None or record.timestamp_utc.endswith("+00:00")


@given(PATH_BYTES.filter(lambda raw: b"\0" not in raw))
def test_log_escapes_and_percent_encoding_of_the_same_bytes_resolve_to_the_same_path(raw):
    assert logformats.resolve_target(apache_escape(raw), escaped=True) == logformats.resolve_target(percent_encode(raw))


@st.composite
def json_log_line(draw) -> tuple[str, dict]:
    document = {"time": draw(st.sampled_from(["2026-11-09T02:14:01Z", "2026-11-09T02:14:01.123+01:00", "2026-11-09T02:14:01",
                                              "2026-11-09 02:14:01.123456-05:30"])),
                "remote_addr": draw(IPV4 | IPV6), "method": draw(METHOD),
                "uri": "/" + draw(st.text(st.characters(categories=("L", "N", "P", "S")), max_size=20)),
                "status": draw(st.integers(100, 599))}
    if draw(st.booleans()):
        document["bytes"] = draw(st.none() | st.integers(0, 10**17))
    if draw(st.booleans()):
        document["forwarded_for"] = draw(st.none() | st.sampled_from(["198.51.100.7", "198.51.100.7, 10.0.0.1", "not an ip"]))
    if draw(st.booleans()):
        document["extra"] = draw(JSON_SCALAR)
    return json.dumps(document, ensure_ascii=draw(st.booleans())), document


@given(json_log_line())
def test_valid_json_log_line_parses_to_the_modelled_fields(case):
    line, document = case
    record = logformats.parse("json", line)

    assert isinstance(record, logformats.HttpRecord), record
    assert (record.client, record.method, record.target, record.status, record.bytes, record.forwarded_for) == (
        str(ipaddress.ip_address(document["remote_addr"])), document["method"], document["uri"], document["status"],
        document.get("bytes"), document.get("forwarded_for") or None)


@given(st.sampled_from(sorted(logformats.FORMATS)), st.text(max_size=200) | access_line().map(lambda case: case[0]))
def test_any_line_gives_a_record_or_a_documented_reason(fmt, line):
    record = logformats.parse(fmt, line)

    assert isinstance(record, logformats.HttpRecord) or record in logformats.REASONS
    if isinstance(record, logformats.HttpRecord):
        resolved = logformats.resolve_target(record.target, record.escaped)
        assert resolved.path is None or not resolved.path.startswith("/") and "\0" not in resolved.path
        assert all(segment not in ("..", ".") for segment in (resolved.path or "").split("/"))


def log_state(chunks, fmt: str, max_line: int) -> tuple:
    parser = LogFileParser(LogConfig(fmt=fmt), max_line=max_line)
    for chunk in chunks:
        parser.feed(chunk)
    parser.close()
    return (parser.lines, parser.parsed, dict(parser.rejected), parser.first_rejected, parser.lossy, parser.first_lossy,
            parser.untimed, parser.unresolved, parser.unresolved_code, parser.lossy_paths, parser.hits_seen,
            [(item.line, item.path, item.uri, item.client_ip, item.timestamp_raw) for item in parser.held])


LOG_ALPHABET = [b'"', b"\\", b"\\x", b"\\x2f", b"\\\"", b" ", b"\n", b"\r\n", b"[", b"]", b"\xff", b"\xe2\x80\xae", b"/../",
                b"%2F", b"%00", b".php", b"/wp-content/uploads/", b"?", b"#", b"-"]


@given(st.lists(access_line(), max_size=6).map(lambda cases: ("\n".join(line for line, _ in cases)).encode("utf-8"))
       .flatmap(lambda data: mutated(data, LOG_ALPHABET) if data else st.just(data))
       .flatmap(lambda data: st.tuples(st.just(data), splits(data), st.sampled_from(["combined", "common", "json"]), st.integers(40, 600))))
def test_log_file_counts_every_line_and_does_not_depend_on_chunking(case):
    data, chunks, fmt, max_line = case
    whole = log_state([data], fmt, max_line)

    assert log_state(chunks, fmt, max_line) == whole
    lines, parsed, rejected, *_ = whole
    assert lines == parsed + sum(rejected.values())
    assert set(rejected) <= set(logformats.REASONS)


@given(st.sampled_from(sorted(logformats.FORMATS)), repeated(LOG_ALPHABET + [b'1.2.3.4 - - [', b'"GET /', b"\\x41"]))
def test_long_repetitive_log_line_is_parsed_in_bounded_time(fmt, data):
    line = data.decode("utf-8", "replace")[:logformats.MAX_LINE_BYTES]
    record = logformats.parse(fmt, line)
    if isinstance(record, logformats.HttpRecord):
        logformats.resolve_target(record.target, record.escaped)


# --- serialize() PHP ----------------------------------------------------------------------------

PHP_KEY = st.integers(-2**63, 2**63 - 1) | st.text(max_size=8) | st.sampled_from(["0", "-1", "01", "1.5", " 1", "-0", "9223372036854775808"])
PHP_SCALAR = st.one_of(st.none(), st.booleans(), st.integers(-2**63, 2**63 - 1), st.floats(allow_nan=False, allow_infinity=False),
                       st.text(max_size=20))


def php_key(key: int | str) -> int | str:
    """Klucz tablicy PHP: łańcuch z dziesiętnym zapisem liczby całkowitej w zakresie int64 staje się liczbą."""
    if isinstance(key, str) and re.fullmatch(r"0|-?[1-9][0-9]*", key) and -2**63 <= int(key) < 2**63:
        return int(key)
    return key


def php(value, lengths: list[tuple[int, int]] | None = None) -> str:
    """Zapis ``serialize()`` wartości modelu; ``("object", pary)`` to obiekt ``stdClass``. ``lengths`` dostaje
    położenia (początek, koniec) zapisów długości łańcuchów w wyniku — pola, nie treść łańcucha."""
    parts: list[str] = []
    size = 0

    def put(text: str) -> None:
        nonlocal size
        parts.append(text)
        size += len(text)

    def walk(item) -> None:
        if item is None:
            put("N;")
        elif isinstance(item, bool):
            put(f"b:{int(item)};")
        elif isinstance(item, int):
            put(f"i:{item};")
        elif isinstance(item, float):
            put(f"d:{item!r};")
        elif isinstance(item, str):
            digits = str(len(item.encode("utf-8", "surrogatepass")))
            if lengths is not None:
                lengths.append((size + 2, size + 2 + len(digits)))
            put(f's:{digits}:"{item}";')
        else:
            pairs = item[1] if isinstance(item, tuple) else item
            put(f'O:8:"stdClass":{len(pairs)}:{{' if isinstance(item, tuple) else f"a:{len(pairs)}:{{")
            for key, element in pairs:
                walk(key)
                walk(element)
            put("}")

    walk(value)
    return "".join(parts)


def expected_php(value):
    if isinstance(value, tuple):
        return phpserialize.Opaque("object")
    if isinstance(value, list):
        result = {}
        for key, item in value:
            result[php_key(key)] = expected_php(item)  # powtórzony klucz: wygrywa ostatni, pozycja pierwszego
        return result
    return value


PHP_VALUE = st.recursive(PHP_SCALAR, lambda inner: st.lists(st.tuples(PHP_KEY, inner), max_size=4)
                         | st.lists(st.tuples(st.text(max_size=5), inner), max_size=3).map(lambda pairs: ("object", pairs)),
                         max_leaves=25)


@given(PHP_VALUE)
def test_serialized_value_round_trips(value):
    assert phpserialize.parse(php(value)) == expected_php(value)


@given(PHP_VALUE, st.data())
def test_string_length_off_by_one_is_rejected(value, data):
    """Za łańcuchem zawsze stoi ``";``: długość o 1 za duża trafia w ``;``, o 1 za mała — w ``"`` zamiast ``;``."""
    lengths: list[tuple[int, int]] = []
    text = php(value, lengths)
    assume(lengths)
    start, end = data.draw(st.sampled_from(lengths))
    length = int(text[start:end]) + data.draw(st.sampled_from([-1, 1]))
    assume(length >= 0)
    with pytest.raises(phpserialize.SerializedError):
        phpserialize.parse(text[:start] + str(length) + text[end:])


@given(st.integers(0, 3 * phpserialize.MAX_DEPTH), st.sampled_from(["a:1:{i:0;", 'O:1:"A":1:{s:1:"k";']))
def test_nesting_is_bounded_without_recursion(depth, opener):
    text = opener * depth + "N;" + "}" * depth
    if depth <= phpserialize.MAX_DEPTH:
        phpserialize.parse(text)
    else:
        with pytest.raises(phpserialize.SerializedError, match="zagnieżdżenie"):
            phpserialize.parse(text)


PHP_ALPHABET = [b"a:", b"s:", b"i:", b"d:", b"b:", b"O:", b"C:", b"E:", b"R:", b"r:", b"N;", b"{", b"}", b";", b":", b'"', b"1",
                b"99999999999", b"-", b".", b"e", b"INF", b"\xc5\xbc", b"\xed\xa0\x80"]


@given(PHP_VALUE.map(lambda value: php(value).encode("utf-8", "surrogatepass")).flatmap(lambda data: mutated(data, PHP_ALPHABET))
       | repeated(PHP_ALPHABET) | st.text(max_size=200).map(lambda text: text.encode("utf-8", "surrogatepass")))
def test_any_input_gives_a_value_or_serialized_error(data):
    text = data.decode("utf-8", "surrogateescape")
    try:
        first = phpserialize.parse(text)
    except phpserialize.SerializedError:
        return
    assert phpserialize.parse(text) == first


# --- redakcja -----------------------------------------------------------------------------------

REDACT_PIECE_LIST = [
    "http://", "https://user:pa55@", "://", "?", "&", "=", ":", "key", "token", "password", "Auth", "sig", "session_id", "@",
    "example.com", "a.b", "'", '"', "<", ">", "\\", " ", "\n", "\t", "[usunięto]", "…", "‮", "​", "\ud800", "\x00",
    "0123456789abcdef", "deadBEEF", "Zq9" * 9, "x" * 30, "/wp-content/uploads/a.php", "user_id: 7", "192.0.2.1", "::1",
]
REDACT_PIECES = st.sampled_from(REDACT_PIECE_LIST)
REDACT_TEXT = st.lists(REDACT_PIECES | st.text(max_size=6), max_size=30).map("".join) | st.text(max_size=120)
_UNSAFE = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


@given(REDACT_TEXT)
def test_redact_is_idempotent_safe_and_bounded(text):
    clean = redact.redact(text)

    assert redact.redact(clean) == clean
    assert not any(unicodedata.category(char) in _UNSAFE for char in clean)
    assert len(clean) <= 6 * len(text) + len(redact.MARK)
    assert redact.neutralise(clean) == clean


@given(REDACT_TEXT, st.sampled_from(["password=", "token: ", "api_key='", "Session=\"", "Authorization: Bearer ", "auth: Basic "]),
       st.from_regex(r"[A-Za-z0-9]{12,20}", fullmatch=True), REDACT_TEXT)
def test_value_after_a_secret_name_never_survives_redaction(before, name, secret, after):
    secret = "Zq" + secret
    assume(secret not in before + after)
    assert secret not in redact.redact(before + name + secret + after)


SECRET_NAMES = st.sampled_from(["key", "token", "password", "pass", "secret", "auth", "api_key", "Session", "X-Auth-Token"])
SECRET_SEPARATORS = st.sampled_from(["=", ":", " = ", ": ", "=  ", "\"=", "':"])


@st.composite
def secret_quoted(draw, value: str) -> str:
    """Wartość w losowej postaci: goła, w cudzysłowie (także ze spacjami w środku), z niedomkniętym cudzysłowem, po schemacie."""
    words = draw(st.lists(st.from_regex(r"[A-Za-z0-9]{1,6}", fullmatch=True), max_size=2))
    inner = " ".join([*words, value])
    return draw(st.sampled_from([value, f'"{inner}"', f"'{inner}'", f'"{value}', f"'{value}", f"Bearer {value}"]))


@given(REDACT_TEXT, st.lists(st.tuples(SECRET_NAMES, SECRET_SEPARATORS), min_size=1, max_size=4),
       st.from_regex(r"[A-Za-z0-9]{12,20}", fullmatch=True), st.data(), REDACT_TEXT)
def test_value_at_the_end_of_a_chain_of_secret_names_never_survives(before, chain, secret, data, after):
    """Łańcuch ``nazwa SEP nazwa SEP … wartość`` (``key=token: "a b X"``): wartość na końcu nigdy nie zostaje jawna."""
    secret = "Zq" + secret
    assume(secret not in before + after)
    prefix = "".join(name + sep for name, sep in chain)
    text = before + " " + prefix + data.draw(secret_quoted(secret)) + " " + after
    assert secret not in redact.redact(text)


@given(REDACT_TEXT, st.integers(2, 300), st.sampled_from([None, re.compile("eval"), re.compile("a"), re.compile(r"\?")]))
def test_excerpt_respects_its_limit(text, limit, pattern):
    assert len(redact.excerpt(text, pattern, limit=limit)) <= max(limit, len(redact.ELLIPSIS) * 2)


@given(st.text(max_size=200))
def test_neutralise_keeps_length_and_is_idempotent(text):
    clean = redact.neutralise(text)
    assert len(clean) == len(text) and redact.neutralise(clean) == clean


@given(repeated([piece.encode("utf-8", "surrogatepass") for piece in REDACT_PIECE_LIST]))
def test_redact_of_long_repetitions_is_bounded_in_time(data):
    redact.redact(data.decode("utf-8", "surrogatepass")[:20_000])


# --- pseudonimizacja (privacy) ------------------------------------------------------------------

BOUNDARY = st.sampled_from([" ", ", ", "(", ")", "\n", "\"", "'", "<", ">", "=", "/", "[", "]"])


def pseudonymising_text() -> privacy._Text:
    text = object.__new__(privacy._Text)
    text.pseudonymizer = privacy.Pseudonymizer()
    text.logins = text.hosts = privacy._Words({})
    return text


@given(st.lists(st.tuples(st.text(max_size=8).filter(lambda part: not re.search(r"[0-9A-Fa-f:.]", part)), BOUNDARY, IPV4 | IPV6, BOUNDARY),
                max_size=4))
def test_every_address_literal_is_pseudonymised(parts):
    text = "".join(prefix + left + address + right for prefix, left, address, right in parts)
    converter = pseudonymising_text()

    out = converter.tool(text)
    assert not privacy.has_address(out)
    assert converter.tool(text) == out


@given(st.text(max_size=300) | REDACT_TEXT)
def test_address_scan_never_fails_and_is_deterministic(text):
    converter = pseudonymising_text()
    assert privacy.has_address(text) == privacy.has_address(text)
    assert converter.evidence(text) == converter.evidence(text)
