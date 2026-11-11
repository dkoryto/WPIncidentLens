"""Odporność na nieufne wejście: S-01–S-14 (rozdz. 14.3). Mapa: docs/TEST_MATRIX.md."""
import html
import os
import re
import unicodedata

import pytest
from conftest import CANARY, EVAL_MARKER, UPLOAD_PHP, XSS, access_line, admin_sql, option_sql, sha256, time_limit, write

from wptrace import cli

UNKNOWN_ADMIN = admin_sql("siteadmin", "ghostadmin")


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


@pytest.mark.xfail(strict=True, reason="--database będące symlinkiem poza katalog dowodów jest czytane i analizowane (#4)")
def test_s01_database_symlink_outside_root_is_not_read(site, evidence, tmp_path, analyze):
    outside = write(tmp_path / "outside.sql", UNKNOWN_ADMIN)
    (evidence / "db.sql").symlink_to(outside)

    run = analyze(site, database=evidence / "db.sql", known_admins=("siteadmin",))

    assert sha256(outside) not in run.json_text


@pytest.mark.xfail(strict=True, reason="plik z wieloma dowiązaniami twardymi (st_nlink > 1) jest czytany bez żadnej adnotacji (#4)")
def test_s01_hardlink_to_file_outside_root_is_flagged(site, tmp_path, analyze):
    outside = write(tmp_path / "outside.php")
    os.link(outside, site / "shared.php")

    assert analyze(site).has_gap("shared.php")


# --- S-02: podmiana w trakcie skanowania (TOCTOU) ------------------------------------------------

@pytest.mark.xfail(strict=True, reason="TOCTOU: po lstat() plik jest otwierany ponownie po ścieżce i podąża za podmienionym symlinkiem (#4)")
def test_s02_file_swapped_for_symlink_after_check_is_not_read(site, tmp_path, analyze, monkeypatch):
    outside = write(tmp_path / "outside.php", EVAL_MARKER)
    victim = write(site / "theme.php")
    real_digest = cli.digest_file

    def swap_after_hashing(path):
        value = real_digest(path)
        if path.name == victim.name and not victim.is_symlink():
            victim.unlink()
            victim.symlink_to(outside)
        return value

    monkeypatch.setattr(cli, "digest_file", swap_after_hashing)

    assert "SUSPICIOUS_PHP_EVAL_DECODE" not in analyze(site).rules


# --- S-03: pliki specjalne i nieczytelne ---------------------------------------------------------

def test_s03_fifo_in_site_is_skipped_with_gap(site, analyze):
    os.mkfifo(site / "pipe.php")

    with time_limit(5):
        run = analyze(site)

    assert run.has_gap("Plik specjalny pominięty: pipe.php")


@pytest.mark.xfail(strict=True, reason="FIFO w katalogu logów jest pomijane bez luki pokrycia (#4)")
def test_s03_fifo_in_logs_is_skipped_with_gap(site, evidence, analyze):
    logs = write(evidence / "logs" / "access.log", access_line("/")).parent
    os.mkfifo(logs / "pipe.log")

    with time_limit(5):
        run = analyze(site, logs=logs)

    assert run.has_gap("pipe.log")


@pytest.mark.xfail(strict=True, reason="nieczytelny plik logu przerywa analizę nieobsłużonym PermissionError (#4)")
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


@pytest.mark.xfail(strict=True, reason="nazwa pliku spoza UTF-8 (Linux) wywraca zapis report.json: UnicodeEncodeError na surogatach (#5)")
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
    assert len(run.report["evidence_manifest"]) == 3


def _sparse(path, size, head):
    """Plik rzadki: nagłówek z treścią-wskaźnikiem i dziura do ``size`` bajtów (bez zapisu danych)."""
    write(path, head)
    os.truncate(path, size)
    return path


def test_s07_oversized_site_file_is_hashed_but_not_content_scanned(site, analyze):
    _sparse(site / "big.php", cli.MAX_SCAN_BYTES + 1, EVAL_MARKER)

    run = analyze(site)

    assert run.findings == []
    assert run.has_gap(f"Analiza treści pominięta, plik > {cli.MAX_SCAN_BYTES} B: big.php")
    assert ("files/big.php", cli.MAX_SCAN_BYTES + 1) in {(entry["source"], entry["size"]) for entry in run.report["evidence_manifest"]}


def test_s07_oversized_sql_dump_is_skipped_with_gap(site, evidence, analyze):
    database = _sparse(evidence / "db.sql", cli.MAX_SQL_BYTES + 1, UNKNOWN_ADMIN)

    run = analyze(site, database=database, known_admins=("siteadmin",))

    assert run.findings == []
    assert run.has_gap(f"Eksport SQL większy niż {cli.MAX_SQL_BYTES} B")


def test_s07_oversized_log_is_skipped_with_gap(site, evidence, analyze):
    log = _sparse(evidence / "logs" / "access.log", cli.MAX_LOG_BYTES + 1, access_line("/" + UPLOAD_PHP))

    run = analyze(site, logs=log.parent)

    assert run.findings == []
    assert run.has_gap("Log za duży do parsowania w PoC: access.log")


# --- S-08: złośliwe wejście dla wyrażeń regularnych ----------------------------------------------

@pytest.mark.xfail(strict=True, reason="ReDoS: wykładniczy backtracking wzorca wiersza w iter_insert_rows; brak limitu czasu (#7)")
def test_s08_crafted_insert_does_not_stall_the_sql_parser():
    crafted = "INSERT INTO `wp_options` VALUES ('" + "\\\\" * 40 + "'());"

    with time_limit(2):
        list(cli.iter_insert_rows(crafted))


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


@pytest.mark.parametrize("build", [
    pytest.param(_broken_sql, marks=pytest.mark.xfail(strict=True, reason="stratne dekodowanie SQL (errors=replace) nie jest raportowane jako luka (#7)")),
    pytest.param(_broken_log, marks=pytest.mark.xfail(strict=True, reason="stratne dekodowanie logu (errors=replace) nie jest raportowane jako luka (#3)")),
], ids=["sql-dump", "access-log"])
def test_s10_lossy_decoding_is_reported_as_coverage_gap(site, evidence, analyze, build):
    run = analyze(site, **build(site, evidence))

    assert any(re.search(r"utf-?8|kodowani", gap, re.I) for gap in run.gaps)


# --- S-11: zserializowane wartości PHP -----------------------------------------------------------

def test_s11_serialized_php_object_is_inert_text(site, evidence, analyze):
    database = write(evidence / "db.sql", option_sql("widget_cache", 'O:13:"SyntheticEvil":1:{s:3:"cmd";s:6:"noop()";}'))

    run = analyze(site, database=database)

    assert run.findings == []
    assert "SyntheticEvil" not in run.everything


@pytest.mark.xfail(strict=True, reason="rola wykrywana podłańcuchem 'administrator' bez parsowania serializacji PHP: b:0 liczy się jak b:1 (#7)")
def test_s11_revoked_administrator_capability_is_not_an_admin(site, evidence, analyze):
    database = write(evidence / "db.sql", admin_sql("editor", caps='a:2:{s:6:"editor";b:1;s:13:"administrator";b:0;}'))

    assert analyze(site, database=database, known_admins=("siteadmin",)).findings == []


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


def _xss_case_id(site, evidence):
    return {"case_id": XSS}


@pytest.mark.parametrize("build", [_xss_file_path, _xss_option_name, _xss_log_file_name, _xss_log_timestamp, _xss_symlink_name, _xss_case_id],
                         ids=["finding-file-path", "finding-option-name", "finding-log-file-name", "gap-log-timestamp", "gap-symlink-name", "case-id"])
def test_s12_markup_from_evidence_is_escaped_in_html_report(site, evidence, analyze, build):
    run = analyze(site, **build(site, evidence))

    assert html.escape(XSS, quote=True) in run.html
    assert XSS not in run.html
    assert not re.search(r"<(script|img|svg|iframe)\b", run.html, re.I)


@pytest.mark.xfail(strict=True, reason="raport HTML nie deklaruje Content-Security-Policy (#3)")
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
    pytest.param(_canary_log_query, marks=pytest.mark.xfail(strict=True, reason="query string z logu trafia bez redakcji do metadata.uri w report.json (#3)")),
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
