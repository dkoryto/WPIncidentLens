"""Limit czasu w trakcie pliku i wyjątki reguł (ADR 0009 pkt 4, spec C10, S-06).

Parsery SQL i JSONL oraz reguły treści plików kończą analizę pliku luką „przeanalizowany do …”, a odczyt i skrót
SHA-256 idą do końca (jak logi w M4). Wyjątek w regule staje się luką źródła z identyfikatorem reguły i typem wyjątku,
bez treści wyjątku. Zegar sesji jest sztuczny; dane wyłącznie syntetyczne.
"""
from __future__ import annotations

import itertools
import json
import re
import time
from dataclasses import replace
from datetime import datetime, timezone

import pytest
from conftest import ADMIN_CAPS, EVAL_MARKER, access_line, admin_sql, option_sql, time_limit, trusted, write

from wpincidentlens import (cli, correlate, database, dbrules, files, filerules, httplog, ingest, integrity, jsonldb, models,
                            rules, sqldump)
from wpincidentlens.analysis import Detection, SourceCoverage

SECRET = "SYNTHETIC-SECRET-/srv/host/path"  # treść wyjątku: nie może trafić do raportu


class Clock:
    """Zegar sesji ustawiany przez test: ``now`` przesunięte poza limit oznacza, że czas minął."""
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def counting_session(max_seconds: float) -> ingest.Session:
    """Zegar przesuwa się o 1 s przy każdym odczycie: limit mija po ustalonej liczbie sprawdzeń."""
    return ingest.Session(ingest.Limits(max_seconds=max_seconds), clock=itertools.count().__next__)


def expires_after(calls: int):
    """``expired`` dla testów parsera: fałsz przy pierwszych ``calls`` sprawdzeniach, potem prawda."""
    counter = itertools.count(1)
    return lambda: next(counter) > calls


def raise_secret(*_args, **_kwargs):
    raise ValueError(SECRET)


def time_gaps(cover) -> list[str]:
    return [reason for reason in cover.reasons if "Limit czasu analizy" in reason]


def rule_gaps(texts) -> list[str]:
    return [text for text in texts if text.startswith(rules.RULE_ERROR_GAP + " ")]


# --- parser SQL ---------------------------------------------------------------------------------

DUMP = "".join(option_sql(f"synthetic_{n}", "x") for n in range(40))


def test_sql_parser_stops_at_the_deadline_and_counts_analysed_statements(monkeypatch):
    monkeypatch.setattr(sqldump, "CLOCK_EVERY_STATEMENTS", 4)
    parser = sqldump.DumpParser(expired=expires_after(3))  # porcja, instrukcja 4, instrukcja 8; przy 12 czas minął

    rows = parser.feed(DUMP.encode()) + parser.close()

    assert parser.stopped_at == parser.statements == 12
    assert [number for *_, number in rows] == list(range(1, 13))
    assert parser.truncated == [] and parser.oversized_at is None  # urwana reszta nie jest „niedomkniętą instrukcją”
    assert parser.feed(DUMP.encode()) == []


def test_sql_parser_checks_the_clock_at_every_chunk():
    parser = sqldump.DumpParser(expired=expires_after(1))
    first = parser.feed(DUMP[:200].encode())

    assert first and parser.stopped_at is None
    assert parser.feed(DUMP[200:].encode()) == [] and parser.close() == []
    assert parser.stopped_at == len(first)


def test_sql_parser_with_time_left_gives_the_same_result_as_without_a_clock():
    timed = sqldump.DumpParser(expired=lambda: False)
    rows = timed.feed(DUMP.encode()) + timed.close()

    assert timed.stopped_at is None
    assert rows == sqldump.parse([DUMP.encode()])[0]


# --- parser JSONL -------------------------------------------------------------------------------

def jsonl_line(table: str, **row) -> str:
    return json.dumps({"table": table, "row": row}) + "\n"


JSONL = "".join(jsonl_line("wp_options", option_name=f"synthetic_{n}", option_value="x") for n in range(40))


def test_jsonl_parser_stops_at_the_deadline_and_names_the_last_line(monkeypatch):
    monkeypatch.setattr(jsonldb, "CLOCK_EVERY_LINES", 5)
    parser = jsonldb.JsonlParser(expired=expires_after(2))  # porcja, wiersz 5; przy 10 czas minął

    rows = parser.feed(JSONL.encode()) + parser.close()

    assert parser.stopped_at == 10
    assert [number for *_, number in rows] == list(range(1, 11))
    assert parser.feed(JSONL.encode()) == [] and parser.rejected == {}


def test_jsonl_parser_with_time_left_parses_every_line():
    parser = jsonldb.JsonlParser(expired=lambda: False)
    rows = parser.feed(JSONL.encode()) + parser.close()

    assert parser.stopped_at is None and len(rows) == 40


# --- skan bazy: luka, PARTIAL, pełny skrót ----------------------------------------------------------

def admin_jsonl(login: str) -> str:
    return (jsonl_line("wp_users", ID=1, user_login=login, user_registered="2026-01-01 00:00:00")
            + jsonl_line("wp_usermeta", umeta_id=1, user_id=1, meta_key="wp_capabilities", meta_value=ADMIN_CAPS))


@pytest.mark.parametrize("fmt, content, unit, every", [
    ("sql", admin_sql("early") + DUMP, "instrukcji", (sqldump, "CLOCK_EVERY_STATEMENTS")),
    ("jsonl", admin_jsonl("early") + JSONL, "wiersza", (jsonldb, "CLOCK_EVERY_LINES")),
])
def test_time_limit_inside_a_dump_is_a_gap_naming_the_place_and_the_hash_covers_the_whole_file(
        evidence, monkeypatch, fmt, content, unit, every):
    monkeypatch.setattr(*every, 2)
    dump = write(evidence / f"db.{fmt}", content)
    session = counting_session(8)

    found, cover, _ = database.scan_database(dump, {"trusted"}, session, fmt=fmt)

    [gap] = [reason for reason in time_gaps(cover) if "przeanalizowany do" in reason]
    reached = int(re.search(rf"db\.{fmt} przeanalizowany do {unit} (\d+)", gap)[1])
    assert 2 <= reached < content.count("\n")
    assert found == []  # czas już minął: reguły bazy nie są stosowane do wierszy sprzed przerwania (luka niżej)
    assert any("reguły bazy zastosowano do 0 z" in reason for reason in time_gaps(cover))
    [record] = [item for item in session.ledger if item.source == "database"]
    assert (record.status, record.size) == (ingest.ReadStatus.READ, dump.stat().st_size)
    assert cli._coverage("database", cover, session.ledger).status == models.CoverageStatus.PARTIAL


@pytest.mark.parametrize("fmt", ["sql", "jsonl"])
def test_time_limit_before_any_row_is_partial_not_a_format_failure(evidence, monkeypatch, fmt):
    dump = write(evidence / f"db.{fmt}", (DUMP if fmt == "sql" else JSONL))
    clock = Clock()
    session = ingest.Session(ingest.Limits(max_seconds=10), clock=clock)
    real = ingest._hash_fd

    def late(*args, **kwargs):  # czas mija po otwarciu pliku, przed pierwszą porcją
        clock.now = 11.0
        return real(*args, **kwargs)

    monkeypatch.setattr(ingest, "_hash_fd", late)
    found, cover, _ = database.scan_database(dump, set(), session, fmt=fmt)

    assert found == [] and not cover.failed
    assert any("przeanalizowany do" in gap and gap.endswith("(skrót SHA-256 obejmuje cały plik)") for gap in time_gaps(cover))
    assert cli._coverage("database", cover, session.ledger).status == models.CoverageStatus.PARTIAL


@pytest.mark.parametrize("fmt, content", [("sql", admin_sql("early") + DUMP), ("jsonl", admin_jsonl("early") + JSONL)])
def test_dump_analysed_within_the_time_limit_has_no_time_gap(evidence, fmt, content):
    dump = write(evidence / f"db.{fmt}", content)

    found, cover, _ = database.scan_database(dump, {"trusted"}, ingest.Session(), fmt=fmt)

    assert time_gaps(cover) == [] and not cover.partial
    assert [item.rule for item in found] == ["UNRECOGNIZED_ADMIN"]


# --- reguły treści plików -------------------------------------------------------------------------

BIG = EVAL_MARKER + "// synthetic padding\n" * 4000  # > CLOCK_CONTENT_BYTES


def first_rule_spends_the_time(monkeypatch, clock: Clock) -> str:
    """Pierwsza reguła treści zużywa resztę czasu: kolejne nie mogą już ruszyć."""
    rule = next(rule for rule in filerules.RULES.values() if rule.find is not None)
    real = rule.find

    def slow(raw):
        clock.now = 1e9
        return real(raw)

    monkeypatch.setitem(filerules.RULES, rule.id, replace(rule, find=slow))
    return rule.id


def test_time_limit_between_content_rule_passes_is_a_gap_and_later_files_are_not_analysed(site, monkeypatch):
    write(site / "a-big.php", BIG)  # przed index.php w porządku przejścia
    clock = Clock()
    first = first_rule_spends_the_time(monkeypatch, clock)
    session = ingest.Session(ingest.Limits(max_seconds=10), clock=clock)

    scan = files.scan_files(site, None, session)

    [gap] = [reason for reason in time_gaps(scan.cover) if "reguł treści" in reason]
    applicable = [rule.id for rule in filerules.RULES.values() if rule.find is not None and rule.applies("a-big.php")]
    assert f"plik a-big.php przeanalizowany do reguły 1 z {len(applicable)}" in gap
    assert [item.rule for item in scan.detections] == [first]  # wynik reguły sprzed limitu zostaje
    assert [(item.rel, item.status, item.reason) for item in session.ledger] == [
        ("a-big.php", ingest.ReadStatus.READ, ""), (ingest.ROOT, ingest.ReadStatus.SKIPPED_LIMIT, "MAX_SECONDS")]
    assert any("nieodczytana pozostała część" in reason for reason in scan.cover.reasons)
    assert cli._coverage("files", scan.cover, session.ledger).status == models.CoverageStatus.PARTIAL


def test_small_files_do_not_consult_the_clock_between_rule_passes():
    item = ingest.Evidence("files", "a.php", ingest.ReadStatus.READ, sha256="0" * 64, size=len(EVAL_MARKER),
                           content=EVAL_MARKER.encode())

    found = filerules.content_rules(item, expired=raise_secret)  # wywołanie zegara byłoby tu błędem

    assert found.skipped == () and [hit.rule for hit in found] == ["SUSPICIOUS_PHP_EVAL_DECODE"]


def test_content_rules_with_time_left_apply_every_rule():
    content = BIG.encode()
    item = ingest.Evidence("files", "a-big.php", ingest.ReadStatus.READ, sha256="0" * 64, size=len(content), content=content)

    found = filerules.content_rules(item, expired=lambda: False)

    assert found.skipped == () and found.applied == len([rule for rule in filerules.RULES.values()
                                                         if rule.find is not None and rule.applies("a-big.php")])
    assert found == filerules.content_rules(item)


# --- ocena: limit czasu nigdy nie daje NO_INDICATORS ---------------------------------------------------

def compose(site, evidence, tmp_path, session, *, database_path):
    baseline = cli.load_baseline(write(tmp_path / "baseline.json", json.dumps(trusted(site))), session)
    logs = write(evidence / "logs" / "access.log", access_line("/about/")).parent
    report = cli.compose_report(site, database_path, logs, baseline, {"siteadmin"}, "T601-SYNTH", session=session)
    models.validate_report(report)
    return report


def test_run_cut_by_the_time_limit_without_findings_is_inconclusive(site, evidence, tmp_path, monkeypatch):
    dump = write(evidence / "db.sql", admin_sql("siteadmin") + DUMP)
    clock = Clock()
    real_scan, real_feed = database.scan_database, sqldump.DumpParser.feed

    def feed(parser, chunk):  # czas mija w trakcie zrzutu…
        clock.now = 1e9
        return real_feed(parser, chunk)

    def scan(*args, **kwargs):  # …i wraca po nim: jedynym skutkiem limitu jest przerwany zrzut
        result = real_scan(*args, **kwargs)
        clock.now = 0.0
        return result

    monkeypatch.setattr(sqldump.DumpParser, "feed", feed)
    monkeypatch.setattr(cli.database_scan, "scan_database", scan)
    report = compose(site, evidence, tmp_path, ingest.Session(ingest.Limits(max_seconds=10), clock=clock), database_path=dump)

    assert report["findings"] == []
    assert report["coverage"]["database"]["status"] == "PARTIAL"
    assert report["assessment"] == models.Assessment.INCONCLUSIVE


def test_same_run_with_time_left_has_no_indicators_in_analysed_scope(site, evidence, tmp_path):
    dump = write(evidence / "db.sql", admin_sql("siteadmin") + DUMP)

    report = compose(site, evidence, tmp_path, ingest.Session(), database_path=dump)

    assert report["assessment"] == models.Assessment.NO_INDICATORS_IN_ANALYZED_SCOPE


# --- wyjątek w regule: luka, nie przerwanie ---------------------------------------------------------

def assert_rule_gap(run, rule: str, source: str, count: int, first: str | None) -> None:
    """Jedna luka: reguła, typ wyjątku, liczba wystąpień i pierwsze miejsce w dowodzie — nigdy treść wyjątku."""
    place = f" (pierwsze: {first})" if first else ""
    assert rule_gaps(run.gaps) == [f"{rules.RULE_ERROR_GAP} {rule}: wyjątek ValueError ×{count}{place}; wynik tej reguły "
                                   "dla części materiału jest nieznany, pozostałe reguły i pliki analizowano dalej"]
    assert run.coverage(source)["status"] == "PARTIAL"
    assert "SYNTHETIC-SECRET" not in run.everything and "/srv/host" not in run.everything


def test_exception_in_a_content_rule_is_a_gap_and_other_rules_and_files_continue(site, analyze, monkeypatch):
    rule = filerules.RULES["LONG_ENCODED_BLOB"]
    monkeypatch.setitem(filerules.RULES, rule.id, replace(rule, find=raise_secret))
    write(site / "a.php", EVAL_MARKER)
    write(site / "b.php", EVAL_MARKER)

    run = analyze(site, baseline=trusted(site))

    assert sorted(item["source"] for item in run.findings if item["rule"] == "SUSPICIOUS_PHP_EVAL_DECODE") == ["a.php", "b.php"]
    assert_rule_gap(run, "LONG_ENCODED_BLOB", "files", 3, "files/a.php")  # a.php, b.php, index.php


@pytest.mark.parametrize("target, name, label, count, first", [
    (filerules, "path_rules", "filerules.path_rules", 2, "files/a.php"),
    (integrity.ReferenceComparison, "check", "integrity", 2, "files/a.php"),
    (integrity.ReferenceComparison, "finish", "integrity", 1, None),
], ids=["path-rules", "integrity-check", "integrity-finish"])
def test_exception_in_a_file_rule_site_is_a_gap_naming_it(site, analyze, monkeypatch, target, name, label, count, first):
    monkeypatch.setattr(target, name, raise_secret)
    write(site / "a.php", EVAL_MARKER)

    run = analyze(site, baseline=trusted(site))

    assert run.rules == {"SUSPICIOUS_PHP_EVAL_DECODE"}  # bez BASELINE_FILE_MISSING dla plików, których check nie objął
    assert_rule_gap(run, label, "files", count, first)


def test_exception_in_database_row_rules_skips_that_row_only(site, evidence, analyze, monkeypatch):
    real = dbrules.RowAnalysis.feed

    def feed(self, table, *args):
        if table.endswith("options"):
            raise_secret()
        return real(self, table, *args)

    monkeypatch.setattr(dbrules.RowAnalysis, "feed", feed)
    dump = write(evidence / "db.sql", option_sql("blogname", "synthetic") + admin_sql("intruder"))

    run = analyze(site, database=dump, baseline=trusted(site), known_admins=("siteadmin",))

    assert run.rules == {"UNRECOGNIZED_ADMIN"}
    assert_rule_gap(run, "dbrules", "database", 1, "database/db.sql:1")


def test_exception_in_the_http_rule_keeps_reading_the_log(site, evidence, analyze, monkeypatch):
    monkeypatch.setattr(httplog, "_in_uploads", raise_secret)
    logs = write(evidence / "logs" / "access.log", access_line("/wp-content/uploads/x.php") + access_line("/about/")).parent

    run = analyze(site, logs=logs, baseline=trusted(site))

    assert run.findings == []
    assert_rule_gap(run, "HTTP_EXECUTABLE_IN_UPLOADS", "logs", 1, "logs/access.log:1")
    assert run.evidence("logs/access.log")["read_status"] == "READ"


@pytest.mark.parametrize("name", ["correlate", "_focus"])
def test_exception_in_correlation_is_a_logs_gap(site, evidence, analyze, monkeypatch, name):
    monkeypatch.setattr(cli, name, raise_secret)
    logs = write(evidence / "logs" / "access.log", access_line("/about/")).parent

    run = analyze(site, logs=logs, baseline=trusted(site))

    assert_rule_gap(run, "correlate", "logs", 1, None)


def test_rule_exception_without_findings_is_inconclusive_not_no_indicators(complete_case, analyze, monkeypatch):
    monkeypatch.setattr(dbrules.RowAnalysis, "finish", raise_secret)

    run = analyze(complete_case["site"], **{key: value for key, value in complete_case.items() if key != "site"})

    assert run.findings == [] and run.report["assessment"] == models.Assessment.INCONCLUSIVE
    assert_rule_gap(run, "dbrules", "database", 1, None)


def test_same_error_repeated_in_many_files_is_one_gap(site, analyze, monkeypatch):
    monkeypatch.setattr(filerules, "path_rules", raise_secret)
    for n in range(5):
        write(site / f"f{n}.php")

    run = analyze(site, baseline=trusted(site))

    assert len(rule_gaps(run.gaps)) == 1


@pytest.mark.parametrize("error", [
    ingest.IngestRefusal(ingest.ReadStatus.ERROR, "OUTPUT_OVERLAPS_EVIDENCE"),
    PermissionError(13, SECRET),
    rules.UnknownRule("reguła spoza rejestru"),
], ids=["ingest-refusal", "os-error", "unknown-rule"])
def test_ingest_refusals_io_errors_and_unregistered_rules_are_not_swallowed(error):
    cover = SourceCoverage()

    def fail():
        raise error

    with pytest.raises(type(error)):
        rules.guarded(cover, "integrity", fail)
    assert cover.reasons == [] and not cover.partial


def test_rule_error_gap_neutralises_the_place_and_counts_repeats():
    cover = SourceCoverage()

    for _ in range(3):
        rules.guarded(cover, "dbrules", raise_secret, where="database/a‮b.sql:7")

    [gap] = cover.reasons
    assert "×3 (pierwsze: database/a" in gap and "‮" not in gap and "SYNTHETIC-SECRET" not in gap


# --- przegląd bezpieczeństwa M6: reguły bazy, pojedyncza instrukcja INSERT, korelacja ----------------------

def test_time_limit_while_database_rules_run_is_a_gap_naming_rows_done(evidence, monkeypatch):
    monkeypatch.setattr(database, "CLOCK_EVERY_ROWS", 1)
    dump = write(evidence / "db.sql", admin_sql("early") + DUMP)
    clock = Clock()
    real = dbrules.RowAnalysis.feed

    def slow(self, *args):  # pierwszy wiersz zużywa resztę czasu
        clock.now = 1e9
        return real(self, *args)

    monkeypatch.setattr(dbrules.RowAnalysis, "feed", slow)
    session = ingest.Session(ingest.Limits(max_seconds=10), clock=clock)

    found, cover, _ = database.scan_database(dump, {"trusted"}, session)

    [gap] = time_gaps(cover)
    assert "reguły bazy zastosowano do 1 z " in gap and "przeanalizowany do" not in gap
    assert found == []  # wiersz z rolą (usermeta) nie został oceniony
    assert cli._coverage("database", cover, session.ledger).status == models.CoverageStatus.PARTIAL


INSERT_10 = b"INSERT INTO wp_options VALUES " + b",".join(b"(%d,'a','b','c')" % n for n in range(10)) + b";"


def test_time_limit_inside_one_long_insert_stops_without_its_rows(monkeypatch):
    monkeypatch.setattr(sqldump, "CLOCK_EVERY_TUPLES", 2)
    parser = sqldump.DumpParser(expired=expires_after(1))  # porcja: jest czas; druga krotka: czas minął

    rows = parser.feed(INSERT_10 + DUMP.encode()) + parser.close()

    assert rows == [] and parser.stopped_at == 0 and parser.unsupported == 0


def test_long_insert_with_time_left_gives_every_row(monkeypatch):
    monkeypatch.setattr(sqldump, "CLOCK_EVERY_TUPLES", 2)
    parser = sqldump.DumpParser(expired=lambda: False)

    assert len(parser.feed(INSERT_10) + parser.close()) == 10 and parser.stopped_at is None


T0_NS = 1_794_190_441 * 10**9


def correlation_input(files: int, requests: int):
    """``files`` plików z ustaleniem i ``requests`` żądań do innych plików kodu, wszystkie w oknie czasu każdego pliku."""
    log = models.Evidence("log", "logs/access.log", "READ", sha256="b" * 64, size_bytes=1)
    detections, evidence = [], {log.id: log}
    for n in range(files):
        path = f"wp-content/plugins/demo/f{n}.php"
        record = models.Evidence("file", f"files/{path}", "READ", sha256="a" * 64, size_bytes=1, mtime_ns=T0_NS)
        fact = models.Observation(record.id, "SYNTHETIC_FILE_FACT", models.Location(path=path), {})
        detections.append(Detection("BASELINE_FILE_CHANGED", "medium", "high", "file", "ustalenie syntetyczne", fact))
        evidence[record.id] = record
    when = models.utc_iso(datetime.fromtimestamp(T0_NS // 10**9, tz=timezone.utc))
    hits = [models.Observation(log.id, "HTTP_REQUEST", models.Location(path="access.log", line=n + 1),
                               {"path": f"wp-content/themes/t/a{n}.php", "clock_uncertainty_seconds": None},
                               timestamp_raw="x", timestamp_utc=when, time_source=models.TimeSource.LOG)
            for n in range(requests)]
    return detections, hits, evidence


def test_correlation_cost_does_not_grow_with_requests_in_the_window():
    detections, hits, evidence = correlation_input(1000, 50_000)

    with time_limit(20):
        started = time.perf_counter()
        result = correlate.correlate(detections, hits, evidence, 900)
        elapsed = time.perf_counter() - started

    assert elapsed < 5, elapsed  # przed poprawką ~120 s: każdy plik sortował całe okno 50 000 żądań
    near = [finding for finding in result.findings if finding.rule_id == "REQUEST_NEAR_FILE_CHANGE"]
    assert len(near) == correlate.MAX_FINDINGS_PER_RULE
    assert all(len(finding.observations) == 1 + correlate.MAX_REQUESTS_PER_FINDING for finding in near)
    assert any("wykryć było 1000" in note for note in result.notes)
    assert "żądań: 50000" in near[0].reason


def test_time_limit_during_correlation_is_a_note_naming_files_done():
    detections, hits, evidence = correlation_input(5, 3)

    result = correlate.correlate(detections, hits, evidence, 900, expired=expires_after(2))

    assert len(result.findings) == 2
    assert any("sprawdzono 2 z 5 plików" in note for note in result.notes)


def test_correlation_with_time_left_covers_every_file():
    detections, hits, evidence = correlation_input(5, 3)

    result = correlate.correlate(detections, hits, evidence, 900, expired=lambda: False)

    assert len(result.findings) == 5 and not any("Limit czasu" in note for note in result.notes)


def test_invalid_correlation_window_is_a_call_error_not_a_gap(site):
    with pytest.raises(ValueError, match="okno korelacji"):
        cli.compose_report(site, None, None, None, set(), "T601-SYNTH", correlation_window=0)

