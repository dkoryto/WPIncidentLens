"""Odporność na nieufne wejście: S-01–S-14 (rozdz. 14.3). Mapa: docs/TEST_MATRIX.md."""
import html
import itertools
import json
import os
import re
import unicodedata

import pytest
from conftest import (
    CANARY,
    EVAL_MARKER,
    UPLOAD_PHP,
    XSS,
    access_line,
    admin_sql,
    option_sql,
    sha256,
    sparse,
    tamper_before_reverification,
    time_limit,
    write,
)

from wpincidentlens import cli, ingest, sqldump

UNKNOWN_ADMIN = admin_sql("siteadmin", "ghostadmin")
CHANGED = "SOURCE_CHANGED_DURING_ANALYSIS"


# --- S-01: dowiązania poza katalog dowodów -------------------------------------------------------

@pytest.mark.parametrize("target_is_dir", [False, True], ids=["file-link", "dir-link"])
def test_s01_site_symlink_outside_root_is_skipped_with_gap(site, tmp_path, analyze, target_is_dir):
    outside = write(tmp_path / "outside" / "secret.php", EVAL_MARKER)
    (site / "link.php").symlink_to(outside.parent if target_is_dir else outside)

    run = analyze(site)

    assert run.findings == []
    assert sha256(outside) not in run.json_text
    assert run.has_gap("Łącze symboliczne pominięte (bez podążania): link.php")


def test_s01_log_symlink_outside_root_is_skipped_with_gap(site, evidence, tmp_path, analyze):
    outside = write(tmp_path / "outside.log", access_line("/" + UPLOAD_PHP))
    logs = evidence / "logs"
    logs.mkdir()
    (logs / "access.log").symlink_to(outside)

    run = analyze(site, logs=logs)

    assert run.findings == []
    assert run.has_gap("Pominięto link w logach: access.log")


def test_s01_database_symlink_outside_root_is_not_read(site, evidence, tmp_path, refuse):
    """ADR 0002 B5: symlink podany wprost przez operatora to odmowa (kod 2), a nie cichy odczyt celu."""
    outside = write(tmp_path / "outside.sql", UNKNOWN_ADMIN)
    (evidence / "db.sql").symlink_to(outside)

    message = refuse("--files", str(site), "--database", str(evidence / "db.sql"), "--known-admin", "siteadmin")

    assert "--database" in message and "dowiązaniem symbolicznym" in message
    assert "outside.sql" not in message


@pytest.mark.parametrize("flag, target", [("--files", "real-site"), ("--logs", "real-logs"), ("--logs", "real-logs/access.log"),
                                          ("--baseline", "real-baseline.json")],
                         ids=["files", "logs-directory", "logs-file", "baseline"])
def test_s01_symlink_given_as_any_source_is_refused(site, tmp_path, refuse, flag, target):
    write(tmp_path / "real-site" / "index.php")
    write(tmp_path / "real-logs" / "access.log", access_line("/"))
    write(tmp_path / "real-baseline.json", "{}")
    link = tmp_path / "link"
    link.symlink_to(tmp_path / target)
    argv = ["--files", str(link)] if flag == "--files" else ["--files", str(site), flag, str(link)]

    message = refuse(*argv)

    assert flag in message and "dowiązaniem symbolicznym" in message
    assert target not in message


def test_s01_hardlink_to_file_outside_root_is_flagged(site, tmp_path, analyze):
    outside = write(tmp_path / "outside.php")
    os.link(outside, site / "shared.php")

    assert analyze(site).has_gap("shared.php")


@pytest.mark.parametrize("plant", [
    lambda path, outside: os.link(outside, path),
    lambda path, outside: path.symlink_to(outside),
], ids=["hardlink", "symlink"])
def test_unread_php_in_uploads_is_still_reported_by_path(site, tmp_path, analyze, plant):
    uploads = site / "wp-content" / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    plant(uploads / "t.php", write(tmp_path / "outside.php", EVAL_MARKER))

    finding = analyze(site).finding("EXECUTABLE_IN_UPLOADS")

    assert (finding["source"], finding["confidence"]) == ("wp-content/uploads/t.php", "low")
    assert "sha256" not in finding["metadata"]


def test_unread_file_outside_uploads_gives_no_finding(site, tmp_path, analyze):
    os.link(write(tmp_path / "outside.php", EVAL_MARKER), site / "shared.php")

    assert analyze(site).findings == []


def test_s01_hardlinked_file_is_not_hashed_or_analyzed_by_default(site, tmp_path, analyze):
    outside = write(tmp_path / "outside.php", EVAL_MARKER)
    os.link(outside, site / "shared.php")

    run = analyze(site)

    assert run.findings == []
    assert sha256(outside) not in run.json_text
    assert run.has_gap("SKIPPED_HARDLINK")


def test_s01_allow_hardlinks_flag_reads_the_file_and_reports_how_many(site, tmp_path, analyze):
    outside = write(tmp_path / "outside.php", EVAL_MARKER)
    os.link(outside, site / "shared.php")

    run = analyze(site, flags=("--allow-hardlinks",))

    assert run.finding("SUSPICIOUS_PHP_EVAL_DECODE")["source"] == "shared.php"
    assert run.has_gap("Odczytano 1 plików z wieloma dowiązaniami twardymi")


def _hardlinked(site, tmp_path):
    os.link(write(tmp_path / "outside.php"), site / "wp-includes" / "version.php")
    return ()


def _in_unreadable_directory(site, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ignoruje bity uprawnień; scenariusza nie da się odtworzyć")
    write(site / "wp-includes" / "version.php")
    (site / "wp-includes").chmod(0o000)
    return ()


def _beyond_file_limit(site, tmp_path):
    write(site / "wp-includes" / "earlier.php")
    write(site / "wp-includes" / "version.php")
    return ("--max-files", "2")  # baseline i index.php wyczerpują limit; przejście kończy się na earlier.php


@pytest.mark.parametrize("build, expected", [(_hardlinked, {"REFERENCE_FILE_UNREADABLE"}),
                                             (_in_unreadable_directory, {"REFERENCE_FILE_UNREADABLE"}), (_beyond_file_limit, set())],
                         ids=["hardlinked", "in-unreadable-directory", "beyond-file-limit"])
def test_file_present_but_not_read_is_a_gap_not_a_missing_file_finding(site, tmp_path, analyze, build, expected):
    (site / "wp-includes").mkdir()
    flags = build(site, tmp_path)
    try:
        run = analyze(site, baseline={"files": {"wp-includes/version.php": "0" * 64}}, flags=flags)
    finally:
        (site / "wp-includes").chmod(0o700)

    assert run.rules == expected  # wpis z referencji, którego nie dało się odczytać, jest nazwany; limit operatora to sama luka
    assert run.has_gap("wp-includes")


@pytest.mark.parametrize("key", ["../outside.php", "{outside}"], ids=["parent-traversal", "absolute-path"])
def test_s01_traversal_keys_in_baseline_are_refused_before_analysis(site, tmp_path, refuse, key):
    outside = write(tmp_path / "outside.php", EVAL_MARKER)
    baseline = write(tmp_path / "baseline.json", json.dumps({"files": {key.format(outside=outside): "0" * 64}}))

    message = refuse("--files", str(site), "--baseline", str(baseline))

    assert "--baseline" in message and "outside.php" not in message


# --- S-02: podmiana w trakcie skanowania (TOCTOU) ------------------------------------------------

def test_s02_file_swapped_for_symlink_after_check_is_not_read(site, tmp_path, analyze, monkeypatch):
    """Podmiana między enumeracją katalogu a otwarciem wpisu (hak w ingest; dawny hak ``cli.digest_file`` już nie istnieje)."""
    outside = write(tmp_path / "outside.php", EVAL_MARKER)
    victim = write(site / "theme.php")
    real_listing = ingest._sorted_names

    def swap_after_listing(dir_fd, limit):
        names = real_listing(dir_fd, limit)
        if victim.name in names and not victim.is_symlink():
            victim.unlink()
            victim.symlink_to(outside)
        return names

    monkeypatch.setattr(ingest, "_sorted_names", swap_after_listing)

    run = analyze(site)

    assert "SUSPICIOUS_PHP_EVAL_DECODE" not in run.rules
    assert sha256(outside) not in run.json_text
    assert run.has_gap("Łącze symboliczne pominięte (bez podążania): theme.php")


@pytest.mark.parametrize("tampered, named", [("site/index.php", "index.php"), ("db.sql", "database/db.sql"),
                                             ("logs/access.log", "logs/access.log"), ("baseline.json", "baseline/baseline.json")],
                         ids=["files", "database", "logs", "baseline"])
def test_s02_evidence_changed_after_reading_is_reported_for_every_source(evidence, analyze, monkeypatch, tampered, named):
    write(evidence / "site" / "index.php")
    write(evidence / "db.sql", admin_sql("siteadmin"))
    write(evidence / "logs" / "access.log", access_line("/"))
    write(evidence / "baseline.json", "{}")
    tamper_before_reverification(monkeypatch, lambda: write(evidence / tampered, "tampered after analysis"))

    run = analyze(evidence / "site", database=evidence / "db.sql", logs=evidence / "logs", baseline=evidence / "baseline.json")

    changed = [gap for gap in run.gaps if CHANGED in gap]
    assert len(changed) == 1 and named in changed[0]


def test_s02_no_reverify_flag_skips_the_check_and_says_so(site, analyze, monkeypatch):
    tamper_before_reverification(monkeypatch, lambda: write(site / "index.php", "tampered after analysis"))

    run = analyze(site, flags=("--no-reverify",))

    assert run.has_gap("--no-reverify")
    assert not run.has_gap(CHANGED)


# --- S-03: pliki specjalne i nieczytelne ---------------------------------------------------------

def test_s03_fifo_in_site_is_skipped_with_gap(site, analyze):
    os.mkfifo(site / "pipe.php")

    with time_limit(5):
        run = analyze(site)

    assert run.has_gap("Plik specjalny pominięty: pipe.php")


def test_s03_fifo_in_logs_is_skipped_with_gap(site, evidence, analyze):
    logs = write(evidence / "logs" / "access.log", access_line("/")).parent
    os.mkfifo(logs / "pipe.log")

    with time_limit(5):
        run = analyze(site, logs=logs)

    assert run.has_gap("pipe.log")


@pytest.mark.parametrize("flag", ["--database", "--logs", "--baseline"])
def test_s03_fifo_given_as_source_is_refused_without_blocking(site, evidence, refuse, flag):
    os.mkfifo(evidence / "pipe")

    with time_limit(5):
        message = refuse("--files", str(site), flag, str(evidence / "pipe"))

    assert flag in message


def test_unreadable_log_file_becomes_a_gap_not_a_crash(site, evidence, analyze):
    if os.geteuid() == 0:
        pytest.skip("root ignoruje bity uprawnień; scenariusza nie da się odtworzyć")
    locked = write(evidence / "logs" / "access.log", access_line("/"))
    locked.chmod(0o000)
    try:
        run = analyze(site, logs=locked.parent)
    finally:
        locked.chmod(0o600)

    assert run.has_gap("access.log")


@pytest.mark.parametrize("locked_rel, expected_gap", [
    ("site/wp-content/locked.php", "Odczyt nieudany (EACCES): wp-content/locked.php"),
    ("site/wp-content", "Odczyt nieudany (EACCES): wp-content"),
    ("db.sql", "Odczyt nieudany (EACCES): źródło database"),
    ("logs", "Odczyt nieudany (EACCES): źródło logs"),
], ids=["site-file", "site-directory", "database-file", "logs-directory"])
def test_unreadable_entry_becomes_a_gap_named_by_errno(evidence, analyze, locked_rel, expected_gap):
    if os.geteuid() == 0:
        pytest.skip("root ignoruje bity uprawnień; scenariusza nie da się odtworzyć")
    write(evidence / "site" / "index.php")
    write(evidence / "site" / "wp-content" / "locked.php", EVAL_MARKER)
    write(evidence / "db.sql", UNKNOWN_ADMIN)
    write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP))
    locked = evidence / locked_rel
    mode = locked.stat().st_mode
    locked.chmod(0o000)
    try:
        run = analyze(evidence / "site", database=evidence / "db.sql", logs=evidence / "logs", known_admins=("siteadmin",))
    finally:
        locked.chmod(mode)

    assert expected_gap in run.gaps


def test_unreadable_baseline_is_refused_not_silently_dropped(site, tmp_path, refuse):
    if os.geteuid() == 0:
        pytest.skip("root ignoruje bity uprawnień; scenariusza nie da się odtworzyć")
    locked = write(tmp_path / "baseline.json", "{}")
    locked.chmod(0o000)

    message = refuse("--files", str(site), "--baseline", str(locked))

    assert "--baseline" in message and "EACCES" in message
    assert str(tmp_path) not in message.split("error:")[1]


# --- S-04 / S-05: nazwy plików -------------------------------------------------------------------

def test_s04_maximum_length_filename_is_reported_untruncated(site, analyze):
    name = "a" * 251 + ".php"
    write(site / "wp-content" / "uploads" / name)

    assert analyze(site).finding("EXECUTABLE_IN_UPLOADS")["source"] == f"wp-content/uploads/{name}"


def test_s05_unicode_path_is_preserved_in_report(site, analyze):
    rel = "wp-content/uploads/zażółć-ファイル/gęślą.php"
    write(site / rel)

    source = analyze(site).finding("EXECUTABLE_IN_UPLOADS")["source"]

    assert unicodedata.normalize("NFC", source) == rel


def test_s05_non_utf8_filename_does_not_break_the_report(site, analyze):
    uploads = site / "wp-content" / "uploads"
    uploads.mkdir(parents=True)
    try:
        os.close(os.open(os.fsencode(uploads) + b"/\xff.php", os.O_CREAT | os.O_WRONLY))
    except OSError:
        pytest.skip("system plików odrzuca nazwy spoza UTF-8 (np. APFS)")

    assert "EXECUTABLE_IN_UPLOADS" in analyze(site).rules


# --- S-06 / S-07: limity zasobów -----------------------------------------------------------------

def test_s06_file_count_limit_stops_scan_with_gap(site, analyze, monkeypatch):
    monkeypatch.setattr(cli, "MAX_FILES", 3)
    for number in range(5):
        write(site / f"file-{number}.php")

    run = analyze(site)

    assert run.has_gap("Limit 3 plików; analiza katalogu niepełna")
    assert len(run.manifest) == 3


def test_s06_default_file_count_limit_follows_adr_0002():
    assert cli.MAX_FILES == 200_000


def test_s06_file_count_limit_is_shared_by_all_sources(site, evidence, analyze):
    write(site / "second.php")
    database = write(evidence / "db.sql", UNKNOWN_ADMIN)

    run = analyze(site, database=database, known_admins=("siteadmin",), flags=("--max-files", "2"))

    assert run.findings == []
    assert run.has_gap("Limit 2 plików; analiza katalogu niepełna (pierwszy pominięty wpis: database/db.sql)")
    assert [entry["source"] for entry in run.manifest] == ["files/index.php", "files/second.php"]


@pytest.mark.parametrize("flags, expected_gap", [
    (("--max-file-bytes", "200"), "Plik większy niż limit 200 B pominięty bez obliczania skrótu: m-big.php"),
    (("--max-total-bytes", "200"), "Limit łącznego rozmiaru 200 B wyczerpany; plik pominięty: m-big.php"),
], ids=["max-file-bytes", "max-total-bytes"])
def test_s07_size_limit_flags_skip_the_file_and_continue_with_the_rest(evidence, analyze, flags, expected_gap):
    root = evidence / "tree"
    sparse(root / "m-big.php", 201, EVAL_MARKER)
    write(root / "z-last.php", EVAL_MARKER)

    run = analyze(root, flags=flags)

    assert run.has_gap(expected_gap)
    assert run.finding("SUSPICIOUS_PHP_EVAL_DECODE")["source"] == "z-last.php"
    assert [entry["source"] for entry in run.manifest] == ["files/z-last.php"]


def test_s07_ten_gigabyte_sparse_file_is_skipped_without_hashing(site, analyze):
    sparse(site / "huge.bin", 10 * 1024**3)

    with time_limit(5):
        run = analyze(site)

    assert run.has_gap(f"Plik większy niż limit {2 * 1024**3} B pominięty bez obliczania skrótu: huge.bin")
    assert [entry["source"] for entry in run.manifest] == ["files/index.php"]


def test_s07_time_limit_flag_yields_partial_analysis_with_gap(site, analyze, monkeypatch):
    ticks = itertools.count(0, 10)
    monkeypatch.setattr(ingest.time, "monotonic", lambda: next(ticks))  # każde sprawdzenie zegara to +10 s

    run = analyze(site, flags=("--max-seconds", "5"))

    assert run.has_gap("Limit czasu analizy 5 s przekroczony")
    assert run.manifest == []


@pytest.mark.parametrize("flag", ["--max-files", "--max-file-bytes", "--max-total-bytes", "--max-seconds"])
def test_non_positive_limit_is_rejected_as_usage_error(site, refuse, flag):
    assert "musi być dodatni" in refuse("--files", str(site), flag, "0")


def test_s07_oversized_site_file_is_hashed_but_not_content_scanned(site, analyze):
    sparse(site / "big.php", cli.MAX_SCAN_BYTES + 1, EVAL_MARKER)

    run = analyze(site)

    assert run.findings == []
    assert run.has_gap(f"Analiza treści pominięta, plik > {cli.MAX_SCAN_BYTES} B: big.php")
    assert ("files/big.php", cli.MAX_SCAN_BYTES + 1) in {(entry["source"], entry["size"]) for entry in run.manifest}


@pytest.mark.parametrize("build, rule", [
    (lambda evidence: {"database": write(evidence / "db.sql", UNKNOWN_ADMIN), "known_admins": ("siteadmin",)}, "UNRECOGNIZED_ADMIN"),
    (lambda evidence: {"logs": write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP)).parent}, "HTTP_EXECUTABLE_IN_UPLOADS"),
], ids=["sql-dump", "access-log"])
def test_s07_file_scan_limit_does_not_apply_to_sql_and_logs(site, evidence, analyze, monkeypatch, build, rule):
    monkeypatch.setattr(cli, "MAX_SCAN_BYTES", 10)

    assert rule in analyze(site, **build(evidence)).rules


def test_s07_sql_dump_over_the_file_size_limit_is_skipped_with_gap(site, evidence, analyze):
    database = write(evidence / "db.sql", UNKNOWN_ADMIN)

    run = analyze(site, database=database, known_admins=("siteadmin",), flags=("--max-file-bytes", str(len(UNKNOWN_ADMIN) - 1)))

    assert "UNRECOGNIZED_ADMIN" not in run.rules
    assert run.has_gap("Plik większy niż limit") and run.coverage("database")["status"] == "FAILED"


def test_s07_sql_dump_larger_than_the_old_in_memory_limit_is_streamed(site, evidence, analyze):
    """Dawny limit 20 MiB zniknął (ADR 0006 pkt 2); bajty zerowe bez średnika przekraczają limit jednej instrukcji."""
    database = sparse(evidence / "db.sql", 21 * 1024 * 1024, UNKNOWN_ADMIN)

    run = analyze(site, database=database, known_admins=("siteadmin",))

    assert "UNRECOGNIZED_ADMIN" in run.rules
    assert run.has_gap("Instrukcja SQL dłuższa niż") and run.coverage("database")["status"] == "PARTIAL"


def test_s07_oversized_log_is_skipped_with_gap(site, evidence, analyze):
    log = sparse(evidence / "logs" / "access.log", cli.MAX_LOG_BYTES + 1, access_line("/" + UPLOAD_PHP))

    run = analyze(site, logs=log.parent)

    assert run.findings == []
    assert run.has_gap("Log za duży do parsowania w PoC: access.log")


# --- S-08: złośliwe wejście dla wyrażeń regularnych ----------------------------------------------

def test_s08_crafted_insert_does_not_stall_the_sql_parser():
    crafted = "INSERT INTO `wp_options` VALUES ('" + "\\\\" * 40 + "'());"

    with time_limit(2):
        list(cli.iter_insert_rows(crafted))


@pytest.mark.parametrize("values, expected", [
    ("(1,'a'),(2,'b')", [["1", "a"], ["2", "b"]]),
    ("(1,'x) , (y'),(2,'it''s')", [["1", "x) , (y"], ["2", "it's"]]),
    ("(1,'back\\\\'),(2,'q\\'(')", [["1", "back\\"], ["2", "q'("]]),
    ("(1,NOW()),(2,'b')", [["2", "b"]]),
], ids=["two-rows", "parentheses-in-string", "escaped-quote-and-backslash", "expression-row-skipped"])
def test_sql_rows_are_split_outside_quotes(values, expected):
    rows, _ = sqldump.parse([f"INSERT INTO `t` VALUES {values};".encode()])

    assert [cells for _, _, cells, _ in rows] == expected


@pytest.mark.parametrize("values", [
    "('\\',1)'''", "1,2)", "(1,2", "", "(1,'a') ON DUPLICATE KEY UPDATE a=1", "(1,'a') (2,'b')",
], ids=["string-after-row", "no-opening-parenthesis", "no-closing-parenthesis", "no-rows",
        "on-duplicate-key-update", "missing-comma"])
def test_insert_outside_the_grammar_yields_no_rows_and_is_counted(values):
    rows, parser = sqldump.parse([f"INSERT INTO `t` VALUES {values};".encode()])

    assert rows == [] and parser.unsupported == 1


@pytest.mark.parametrize("crafted", [
    "INSERT INTO a(" * 40_000,
    "INSERT INTO a (`x`" * 40_000,
    "INSERT INTO a" + " " * 400_000 + "x",
    ("INSERT INTO a(`x`) " + " " * 50) * 8_000,
], ids=["unclosed-column-list", "unclosed-with-column", "long-whitespace", "no-values-keyword"])
def test_s08_unterminated_insert_headers_do_not_stall_the_sql_parser(crafted):
    with time_limit(3):
        assert list(cli.iter_insert_rows(crafted)) == []


def test_sql_column_list_is_still_recognised():
    rows = list(cli.iter_insert_rows("INSERT INTO `wp_users` (`ID`, `user_login`) VALUES (1,'a');"))

    assert rows == [("wp_users", ["ID", "user_login"], ["1", "a"])]


def test_sql_row_splitting_scales_linearly():
    many_rows = "INSERT INTO `wp_options` VALUES " + ",".join(f"({n},'v{n}')" for n in range(20000)) + ";"

    with time_limit(5):
        assert len(list(cli.iter_insert_rows(many_rows))) == 20000


def test_s08_repetitive_php_does_not_stall_the_file_rules(site, analyze):
    write(site / "repeat.php", ("$_GET[" + "]" * 120) * 500)

    with time_limit(5):
        assert analyze(site).findings == []


# --- S-09: SQL wielowierszowy i escapowany -------------------------------------------------------

@pytest.mark.parametrize("sql, expected", [
    ("INSERT INTO `wp_options`\n  (`option_id`, `option_name`)\nVALUES\n  (1, 'a'),\n  (2, 'b');",
     [("wp_options", ["option_id", "option_name"], ["1", "a"]), ("wp_options", ["option_id", "option_name"], ["2", "b"])]),
    ("INSERT INTO `wp_options` VALUES (1,'it\\'s; (still) one, value');", [("wp_options", [], ["1", "it's; (still) one, value"])]),
    ("INSERT INTO `wp_options` VALUES (1,'it''s');", [("wp_options", [], ["1", "it's"])]),
    ("INSERT INTO `wp_options` VALUES (1,'line\\nbreak','tail\\\\');", [("wp_options", [], ["1", "line\nbreak", "tail\\"])]),
    ("INSERT INTO `wp_options` VALUES (1,NULL,'NULL');", [("wp_options", [], ["1", None, "NULL"])]),
    ("INSERT INTO `wp_options` VALUES (1,'INSERT INTO `wp_users` VALUES (9,\\'ghost\\');');",
     [("wp_options", [], ["1", "INSERT INTO `wp_users` VALUES (9,'ghost');"])]),
], ids=["multiline-multirow", "backslash-quote", "doubled-quote", "escape-sequences", "null-literal", "statement-inside-string"])
def test_s09_escaped_and_multiline_inserts_are_parsed_as_data(sql, expected):
    assert list(cli.iter_insert_rows(sql)) == expected


@pytest.mark.parametrize("sql", ["INSERT INTO `wp_users` VALUES (1,'unterminated", "INSERT INTO `wp_users` VALUES (1,'a'"],
                         ids=["open-string", "no-terminator"])
def test_s09_truncated_insert_yields_no_rows(sql):
    assert list(cli.iter_insert_rows(sql)) == []


# --- S-10: uszkodzone UTF-8 ----------------------------------------------------------------------

def _broken_php(site, evidence):
    write(site / "broken.php", b"<?php \xff\xfe\xc3 // synthetic: eval(base64_decode('synthetic'));")
    return {}


def _broken_sql(site, evidence):
    return {"database": write(evidence / "db.sql", admin_sql("siteadmin", "ghostX").encode().replace(b"X", b"\xff")),
            "known_admins": ("siteadmin",)}


def _broken_log(site, evidence):
    line = access_line("/wp-content/uploads/a-BYTE.php").encode().replace(b"BYTE", b"\xff\xfe")
    return {"logs": write(evidence / "logs" / "access.log", line).parent}


@pytest.mark.parametrize("build, rule", [
    (_broken_php, "SUSPICIOUS_PHP_EVAL_DECODE"), (_broken_sql, "UNRECOGNIZED_ADMIN"), (_broken_log, "HTTP_EXECUTABLE_IN_UPLOADS"),
], ids=["php-file", "sql-dump", "access-log"])
def test_s10_invalid_utf8_does_not_hide_indicators(site, evidence, analyze, build, rule):
    run = analyze(site, **build(site, evidence))

    assert rule in run.rules


@pytest.mark.parametrize("build", [_broken_sql, _broken_log], ids=["sql-dump", "access-log"])
def test_s10_lossy_decoding_is_reported_as_coverage_gap(site, evidence, analyze, build):
    run = analyze(site, **build(site, evidence))

    assert any(re.search(r"utf-?8|kodowani", gap, re.I) for gap in run.gaps)


# --- S-11: zserializowane wartości PHP -----------------------------------------------------------

def test_s11_serialized_php_object_is_inert_text(site, evidence, analyze):
    database = write(evidence / "db.sql", option_sql("widget_cache", 'O:13:"SyntheticEvil":1:{s:3:"cmd";s:6:"noop()";}'))

    run = analyze(site, database=database)

    assert run.findings == []
    assert "SyntheticEvil" not in run.everything


def test_s11_administrator_role_key_with_false_value_is_still_an_admin(site, evidence, analyze):
    """WordPress wyznacza role po kluczach tablicy uprawnień, więc ``b:0`` pod kluczem roli nie ukrywa administratora."""
    database = write(evidence / "db.sql", admin_sql("editor", caps='a:2:{s:6:"editor";b:1;s:13:"administrator";b:0;}'))

    run = analyze(site, database=database, known_admins=("siteadmin",))

    assert run.finding("UNRECOGNIZED_ADMIN")["metadata"] == {
        "username": "editor", "user_id": "1", "registered": "2026-01-01 00:00:00", "role_value": "false"}


@pytest.mark.parametrize("caps", [
    'a:1:{s:6:"editor";s:13:"administrator";}', 'a:1:{s:17:"not_administrator";b:1;}', 'a:1:{i:0;s:13:"administrator";}',
], ids=["word-as-value", "word-inside-another-key", "word-in-a-list"])
def test_s11_word_administrator_outside_the_role_key_is_not_an_admin(site, evidence, analyze, caps):
    database = write(evidence / "db.sql", admin_sql("editor", caps=caps))

    run = analyze(site, database=database, known_admins=("siteadmin",))

    assert run.findings == []
    assert run.coverage("database")["status"] == "ANALYZED"


# --- S-12: aktywny HTML w wartościach trafiających do raportu ------------------------------------

def _xss_file_path(site, evidence):
    write(site / "wp-content" / "uploads" / f"{XSS}.php")
    return {}


def _xss_option_name(site, evidence):
    return {"database": write(evidence / "db.sql", option_sql(XSS, "<script>synthetic()</script>"))}


def _xss_log_file_name(site, evidence):
    return {"logs": write(evidence / "logs" / f"{XSS}.log", access_line("/" + UPLOAD_PHP)).parent}


def _xss_log_timestamp(site, evidence):
    return {"logs": write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP, when=XSS)).parent}


def _xss_symlink_name(site, evidence):
    (site / f"{XSS}.php").symlink_to(site / "index.php")
    return {}


@pytest.mark.parametrize("build", [_xss_file_path, _xss_option_name, _xss_log_file_name, _xss_log_timestamp, _xss_symlink_name],
                         ids=["finding-file-path", "finding-option-name", "finding-log-file-name", "gap-log-timestamp", "gap-symlink-name"])
def test_s12_markup_from_evidence_is_escaped_in_html_report(site, evidence, analyze, build):
    run = analyze(site, **build(site, evidence))

    assert html.escape(XSS, quote=True) in run.html
    assert XSS not in run.html
    assert not re.search(r"<(script|img|svg|iframe)\b", run.html, re.I)


def test_s12_markup_in_case_id_is_refused_by_the_command_line(site, refuse):
    assert "--case-id" in refuse("--files", str(site), "--case-id", XSS)


def test_s12_markup_in_case_id_of_a_composed_report_is_escaped_in_html_report(site, tmp_path):
    """CaseManager odrzuca taki identyfikator w CLI; raport złożony z pominięciem CLI nadal musi być escapowany."""
    cli.write_html(cli.compose_report(site, None, None, None, set(), XSS), tmp_path / "report.html")
    page = (tmp_path / "report.html").read_text(encoding="utf-8")

    assert html.escape(XSS, quote=True) in page
    assert XSS not in page


@pytest.mark.xfail(strict=True, reason="raport HTML nie deklaruje Content-Security-Policy (#14)")
def test_s12_html_report_declares_content_security_policy(site, analyze):
    assert "Content-Security-Policy" in analyze(site).html


# --- S-13: sekrety-kanarki -----------------------------------------------------------------------

def _canary_wp_config(site, evidence):
    write(site / "wp-config.php", f"<?php define('DB_PASSWORD', '{CANARY}'); // synthetic\n")
    return {}


def _canary_password_hash(site, evidence):
    return {"database": write(evidence / "db.sql", admin_sql("siteadmin", "ghostadmin", password=CANARY)), "known_admins": ("siteadmin",)}


def _canary_log_query(site, evidence):
    return {"logs": write(evidence / "logs" / "access.log", access_line(f"/{UPLOAD_PHP}?token={CANARY}")).parent}


@pytest.mark.parametrize("build", [
    _canary_wp_config, _canary_password_hash,
    pytest.param(_canary_log_query, marks=pytest.mark.xfail(strict=True, reason="query string z logu trafia bez redakcji do metadata.uri w report.json (#14)")),
], ids=["wp-config-password", "user-pass-column", "log-query-token"])
def test_s13_canary_secret_never_reaches_any_output(site, evidence, analyze, build):
    run = analyze(site, **build(site, evidence))

    assert CANARY not in run.everything


# --- S-14: sfałszowany X-Forwarded-For -----------------------------------------------------------

def test_s14_forged_forwarded_for_is_not_used_as_client_address(site, evidence, analyze):
    line = access_line("/" + UPLOAD_PHP, ip="192.0.2.10", extra=' "203.0.113.77"')
    logs = write(evidence / "logs" / "access.log", line).parent

    run = analyze(site, logs=logs)

    assert run.finding("HTTP_EXECUTABLE_IN_UPLOADS")["metadata"]["client_ip"] == "192.0.2.10"
    assert "203.0.113.77" not in run.everything


# --- B8: ścieżki hosta nie trafiają do raportu ---------------------------------------------------

def test_report_never_contains_an_absolute_host_path(evidence, tmp_path, analyze, monkeypatch):
    if os.geteuid() == 0:
        pytest.skip("root ignoruje bity uprawnień; scenariusza nie da się odtworzyć")
    outside = write(tmp_path / "outside.php", EVAL_MARKER)
    site = write(evidence / "site" / "index.php").parent
    (site / "link.php").symlink_to(outside)
    os.link(outside, site / "shared.php")
    os.mkfifo(site / "pipe.php")
    write(site / UPLOAD_PHP, EVAL_MARKER)
    locked = write(evidence / "db.sql", UNKNOWN_ADMIN)
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP)).parent
    (logs / "link.log").symlink_to(outside)
    locked.chmod(0o000)
    tamper_before_reverification(monkeypatch, lambda: write(site / "index.php", "tampered after analysis"))
    try:
        run = analyze(site, database=locked, logs=logs, baseline={"files": {"index.php": "0" * 64}})
    finally:
        locked.chmod(0o600)

    # EACCES, FIFO, hardlink, symlink ×2, zmiana po odczycie, plik bez wpisu w baseline, nota WPDetector, NOT_CHECKED ×2
    assert len(run.gaps) == 10 and run.findings
    assert str(tmp_path) not in run.json_text + run.html
    assert not re.search(r"/(private|var|tmp|home|Users)/", run.json_text + run.html)


@pytest.mark.parametrize("line", [
    '192.0.2.10 - - [x] "GET ' + "\t" * 20_000,
    '192.0.2.10 - - [x] "GET ' + "/a " * 20_000,
    "192.0.2.10 " + "- " * 20_000,
    '192.0.2.10 - - [x] "GET /a' + " " * 20_000,
    '192.0.2.10 - - [x] "GET /a ' + "x " * 20_000,
], ids=["tabs-after-method", "many-tokens", "many-dashes", "spaces-after-uri", "no-closing-quote"])
def test_s08_crafted_log_line_does_not_stall_the_log_pattern(line):
    with time_limit(2):
        assert cli.LOG_PATTERN.match(line) is None



@pytest.mark.parametrize("crafted", [
    "'" + "\\'" * 100_000,
    "/*" * 100_000,
    "`" * 100_001,
    "INSERT " * 50_000,
    "-- x\n" * 50_000,
], ids=["unterminated-string", "unterminated-comments", "odd-backticks", "keywords-without-terminator", "comment-lines"])
def test_s08_statement_scanner_is_linear_on_crafted_sql(crafted):
    with time_limit(3):
        sqldump.parse([crafted.encode()])
