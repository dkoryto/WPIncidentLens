"""Raport ``poc-1`` pisany przez ``wpincidentlens`` (T-102, ADR 0003): pokrycie per źródło, ``INCONCLUSIVE``, kody wyjścia, JSON Schema.

Każdy raport zwrócony przez ``analyze`` przeszedł już ``validate_report`` i JSON Schema (``conftest.analyze``).
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
from conftest import (
    EVAL_MARKER,
    FIXTURES,
    SCHEMA_PATH,
    UPLOAD_PHP,
    XSS,
    access_line,
    admin_sql,
    analyze_demo,
    option_sql,
    remove_at,
    replace_at,
    schema_errors,
    sparse,
    strip_time,
    tamper_before_reverification,
    write,
)

from wpincidentlens import cli, models
from wpincidentlens.ingest import ReadStatus, Session

REPOSITORY = Path(__file__).parents[1]
needs_permission_bits = pytest.mark.skipif(os.geteuid() == 0, reason="root ignoruje bity uprawnień")


def entries(run, source: str) -> dict:
    """Niezerowe liczniki wpisów źródła według statusu odczytu."""
    return {status: count for status, count in run.coverage(source)["entries"].items() if count}


# --- pełny zakres -------------------------------------------------------------------------------

def test_complete_scope_without_findings_is_no_indicators_in_analyzed_scope(complete_case, analyze):
    run = analyze(**complete_case)

    assert (run.report["assessment"], run.report["scope_complete"], run.exit_code) == ("NO_INDICATORS_IN_ANALYZED_SCOPE", True, 0)
    assert {source: run.coverage(source)["status"] for source in models.SOURCES} == {
        "files": "ANALYZED", "database": "ANALYZED", "logs": "ANALYZED", "baseline": "NOT_PROVIDED"}


def test_counters_of_a_fully_read_source_hold_only_read_entries(complete_case, analyze):
    write(complete_case["site"] / "wp-includes" / "version.php")

    run = analyze(**complete_case)

    assert entries(run, "files") == {"READ": 2}
    assert entries(run, "baseline") == {}


def test_limitations_that_do_not_shrink_the_scope_stay_listed_as_reasons(complete_case, analyze):
    """Stałe ograniczenie parsera SQL to informacja o zakresie: jest powodem w pokryciu, ale nie obniża statusu."""
    database = analyze(**complete_case).coverage("database")

    assert database["status"] == "ANALYZED"
    assert any("Parser SQL PoC obsługuje wybrane INSERT" in reason for reason in database["reasons"])


def test_large_file_without_content_rules_does_not_shrink_the_scope(complete_case, analyze):
    sparse(complete_case["site"] / "wp-content" / "uploads" / "photo.jpg", cli.MAX_SCAN_BYTES + 1)

    run = analyze(**complete_case)

    assert run.coverage("files")["status"] == "ANALYZED"
    assert run.has_gap("Analiza treści pominięta") and run.report["assessment"] == "NO_INDICATORS_IN_ANALYZED_SCOPE"


def test_disabled_reverification_is_reported_without_changing_the_assessment(complete_case, analyze):
    """Decyzja ADR 0003: ``--no-reverify`` to jawny wybór operatora odnotowany jako luka; sam odczyt pozostaje pełny."""
    run = analyze(**complete_case, flags=("--no-reverify",))

    assert run.has_gap("--no-reverify")
    assert (run.report["assessment"], run.exit_code) == ("NO_INDICATORS_IN_ANALYZED_SCOPE", 0)


# --- niepełny zakres: brak ustaleń nigdy nie daje „brak wskaźników” -------------------------------

def _without_database(case, tmp_path, monkeypatch):
    del case["database"]


def _without_logs(case, tmp_path, monkeypatch):
    del case["logs"]


def _skipped_hardlink(case, tmp_path, monkeypatch):
    os.link(write(tmp_path / "outside.txt", "synthetic"), case["site"] / "shared.txt")


def _skipped_symlink(case, tmp_path, monkeypatch):
    (case["site"] / "link.txt").symlink_to(tmp_path / "missing.txt")


def _file_above_size_limit(case, tmp_path, monkeypatch):
    sparse(case["site"] / "big.bin", 5000)
    case["flags"] = ("--max-file-bytes", "4096")


def _code_file_above_scan_limit(case, tmp_path, monkeypatch):
    sparse(case["site"] / "big.php", cli.MAX_SCAN_BYTES + 1)


def _file_changed_after_reading(case, tmp_path, monkeypatch):
    tamper_before_reverification(monkeypatch, lambda: write(case["site"] / "index.php", "tampered after analysis"))


def _database_changed_after_reading(case, tmp_path, monkeypatch):
    tamper_before_reverification(monkeypatch, lambda: write(case["database"], "-- tampered after analysis\n"))


def _partly_parsed_log(case, tmp_path, monkeypatch):
    write(case["logs"] / "access.log", access_line("/about/") + "unparseable line\n")


def _file_limit_reached_before_logs(case, tmp_path, monkeypatch):
    case["flags"] = ("--max-files", "2")


def _foreign_sql(case, tmp_path, monkeypatch):
    write(case["database"], "COPY wp_users (id, user_login) FROM stdin;\n")


def _foreign_log_format(case, tmp_path, monkeypatch):
    write(case["logs"] / "access.log", '{"request":"GET / HTTP/1.1","status":200}\n')


def _log_without_lines(case, tmp_path, monkeypatch):
    write(case["logs"] / "access.log", "")


def _empty_log_directory(case, tmp_path, monkeypatch):
    (case["logs"] / "access.log").unlink()


def _empty_site_directory(case, tmp_path, monkeypatch):
    (case["site"] / "index.php").unlink()


INCOMPLETE_SCOPES = {
    # scenariusz: (przygotowanie, źródło, status, niezerowe liczniki wpisów, kod wyjścia)
    "no-database": (_without_database, "database", "NOT_PROVIDED", {}, 3),
    "no-logs": (_without_logs, "logs", "NOT_PROVIDED", {}, 3),
    "skipped-hardlink": (_skipped_hardlink, "files", "PARTIAL", {"READ": 1, "SKIPPED_HARDLINK": 1}, 3),
    "skipped-symlink": (_skipped_symlink, "files", "PARTIAL", {"READ": 1, "SKIPPED_SYMLINK": 1}, 3),
    "file-above-size-limit": (_file_above_size_limit, "files", "PARTIAL", {"READ": 1, "SKIPPED_LIMIT": 1}, 3),
    "code-file-above-scan-limit": (_code_file_above_scan_limit, "files", "PARTIAL", {"READ": 2}, 3),
    "file-changed-after-reading": (_file_changed_after_reading, "files", "PARTIAL", {"CHANGED": 1}, 3),
    "database-changed-after-reading": (_database_changed_after_reading, "database", "PARTIAL", {"CHANGED": 1}, 3),
    "partly-parsed-log": (_partly_parsed_log, "logs", "PARTIAL", {"READ": 1}, 3),
    "file-limit-reached-before-logs": (_file_limit_reached_before_logs, "logs", "FAILED", {"SKIPPED_LIMIT": 1}, 4),
    "foreign-sql": (_foreign_sql, "database", "FAILED", {"READ": 1}, 4),
    "foreign-log-format": (_foreign_log_format, "logs", "FAILED", {"READ": 1}, 4),
    "log-without-lines": (_log_without_lines, "logs", "FAILED", {"READ": 1}, 4),
    "empty-log-directory": (_empty_log_directory, "logs", "FAILED", {}, 4),
    "empty-site-directory": (_empty_site_directory, "files", "FAILED", {}, 4),
}


@pytest.mark.parametrize("prepare, source, status, counted, code", INCOMPLETE_SCOPES.values(), ids=INCOMPLETE_SCOPES.keys())
def test_incomplete_scope_without_findings_is_inconclusive(complete_case, analyze, tmp_path, monkeypatch, prepare, source, status, counted, code):
    prepare(complete_case, tmp_path, monkeypatch)

    run = analyze(**complete_case)

    assert run.findings == []
    assert (run.report["assessment"], run.report["scope_complete"]) == ("INCONCLUSIVE", False)
    assert (run.coverage(source)["status"], entries(run, source)) == (status, counted)
    assert run.coverage(source)["reasons"] and set(run.coverage(source)["reasons"]) <= set(run.gaps)
    assert run.exit_code == code


@needs_permission_bits
def test_unreadable_database_is_failed_coverage_with_the_error_recorded_on_its_evidence(complete_case, analyze):
    complete_case["database"].chmod(0o000)
    try:
        run = analyze(**complete_case)
    finally:
        complete_case["database"].chmod(0o600)

    assert (run.coverage("database")["status"], entries(run, "database"), run.exit_code) == ("FAILED", {"ERROR": 1}, 4)
    assert (run.evidence("database/.")["read_status"], run.evidence("database/.")["read_reason"]) == ("ERROR", "EACCES")
    assert run.report["assessment"] == "INCONCLUSIVE"


def test_missing_baseline_is_reported_but_does_not_make_the_scope_incomplete(complete_case, analyze):
    baseline = analyze(**complete_case).coverage("baseline")

    assert baseline["status"] == "NOT_PROVIDED"
    assert baseline["reasons"] == ["Brak zaufanej migawki bazowej (baseline): porównanie plików z referencją niewykonane"]


def test_provided_baseline_is_analyzed_and_counted(complete_case, analyze):
    run = analyze(**complete_case, baseline={"files": {"index.php": "0" * 64}, "known_admins": ["siteadmin"]})

    assert (run.coverage("baseline")["status"], entries(run, "baseline"), run.coverage("baseline")["reasons"]) == ("ANALYZED", {"READ": 1}, [])


def test_time_limit_hit_during_reverification_makes_every_provided_source_partial(complete_case, analyze, monkeypatch):
    real_finish = Session.finish

    def finish_after_deadline(session):
        session._clock = lambda: float("inf")  # hak: budżet czasu kończy się po analizie, przed ponowną weryfikacją
        return real_finish(session)

    monkeypatch.setattr(Session, "finish", finish_after_deadline)

    run = analyze(**complete_case)

    assert run.has_gap("Ponowna weryfikacja przerwana limitem czasu")
    assert {source: run.coverage(source)["status"] for source in models.SOURCES} == {
        "files": "PARTIAL", "database": "PARTIAL", "logs": "PARTIAL", "baseline": "NOT_PROVIDED"}
    assert (run.report["assessment"], run.exit_code) == ("INCONCLUSIVE", 3)


# --- dowody: status odczytu także dla wpisów pominiętych ------------------------------------------

@pytest.mark.parametrize("prepare, path, status, reason", [
    (_skipped_hardlink, "files/shared.txt", "SKIPPED_HARDLINK", "NLINK"),
    (_skipped_symlink, "files/link.txt", "SKIPPED_SYMLINK", "SYMLINK"),
    (_file_above_size_limit, "files/big.bin", "SKIPPED_LIMIT", "MAX_FILE_BYTES"),
    (_file_limit_reached_before_logs, "logs/access.log", "SKIPPED_LIMIT", "MAX_FILES"),
], ids=["hardlink", "symlink", "size-limit", "file-count-limit"])
def test_skipped_entry_is_an_evidence_record_without_a_hash(complete_case, analyze, tmp_path, monkeypatch, prepare, path, status, reason):
    prepare(complete_case, tmp_path, monkeypatch)

    skipped = analyze(**complete_case).evidence(path)

    assert (skipped["read_status"], skipped["read_reason"]) == (status, reason)
    assert (skipped["sha256"], skipped["size_bytes"], skipped["mtime_ns"]) == (None, None, None)


def test_entry_changed_after_reading_keeps_the_hash_of_the_analyzed_bytes(complete_case, analyze, tmp_path, monkeypatch):
    analyzed = models.Evidence.from_dict(analyze(**complete_case).evidence("files/index.php"))
    _file_changed_after_reading(complete_case, tmp_path, monkeypatch)

    changed = analyze(**complete_case).evidence("files/index.php")

    assert (changed["read_status"], changed["read_reason"]) == ("CHANGED", "REVERIFY_SIZE")
    assert (changed["sha256"], changed["id"]) == (analyzed.sha256, analyzed.id)


def test_read_evidence_records_hash_size_and_modification_time(complete_case, analyze):
    index = complete_case["site"] / "index.php"

    record = analyze(**complete_case).evidence("files/index.php")

    assert (record["read_status"], record["origin_kind"], record["hardlinked"]) == ("READ", "file", False)
    assert (record["size_bytes"], record["mtime_ns"]) == (index.stat().st_size, index.stat().st_mtime_ns)


def test_modification_time_before_1970_is_recorded_as_a_negative_number(complete_case, analyze):
    os.utime(complete_case["site"] / "index.php", ns=(-86_400_000_000_000, -86_400_000_000_000))

    assert analyze(**complete_case).evidence("files/index.php")["mtime_ns"] == -86_400_000_000_000


def test_every_read_status_of_ingest_is_a_valid_evidence_status():
    assert set(models.READ_STATUSES) == {str(status) for status in ReadStatus} | {models.UNKNOWN_LEGACY}


# --- obserwacje i ustalenia ---------------------------------------------------------------------

def test_every_finding_of_the_demo_case_rests_on_recorded_observations_and_evidence(demo_case, analyze):
    report = analyze_demo(analyze, demo_case).report
    observations = {item["id"]: item for item in report["observations"]}
    evidence = {item["id"] for item in report["evidence"]}

    assert report["findings"] and all(finding["observations"] for finding in report["findings"])
    assert {reference for finding in report["findings"] for reference in finding["observations"]} <= set(observations)  # kandydaci WPDetector nie mają ustalenia
    assert {item["evidence_id"] for item in observations.values()} <= evidence


def test_correlation_finding_reuses_the_file_and_log_observations(site, evidence, analyze):
    write(site / UPLOAD_PHP)
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP)).parent

    report = analyze(site, logs=logs).report
    by_rule = {finding["rule_id"]: finding["observations"] for finding in report["findings"]}
    kinds = {item["id"]: item["kind"] for item in report["observations"]}

    assert sorted(by_rule["CORRELATED_UPLOAD_REQUEST"]) == sorted(by_rule["EXECUTABLE_IN_UPLOADS"] + by_rule["HTTP_EXECUTABLE_IN_UPLOADS"])
    assert sorted(kinds[reference] for reference in by_rule["CORRELATED_UPLOAD_REQUEST"]) == [
        "HTTP_REQUEST_FOR_PHP_IN_UPLOADS", "PHP_FILE_IN_UPLOADS"]


def test_observation_states_the_fact_and_leaves_the_rating_to_the_finding(site, analyze):
    write(site / UPLOAD_PHP)

    report = analyze(site).report

    assert [(item["kind"], item["location"], item["attributes"]) for item in report["observations"]] == [
        ("PHP_FILE_IN_UPLOADS", {"path": UPLOAD_PHP}, {})]
    assert not {"severity", "confidence", "reason", "rule_id"} & set(report["observations"][0])


def test_observation_of_an_unread_file_points_to_its_skipped_evidence(site, tmp_path, analyze):
    os.link(write(tmp_path / "outside.php", EVAL_MARKER), write(site / UPLOAD_PHP).with_name("linked.php"))

    report = analyze(site).report
    skipped = next(item for item in report["evidence"] if item["read_status"] == "SKIPPED_HARDLINK")

    assert skipped["id"] in {item["evidence_id"] for item in report["observations"]}


def test_log_observation_carries_line_raw_time_utc_time_and_time_source(site, evidence, analyze):
    logs = write(evidence / "logs" / "access.log", access_line("/") + access_line("/" + UPLOAD_PHP)).parent

    request = analyze(site, logs=logs).report["observations"][0]

    assert request["location"] == {"path": "access.log", "line": 2}
    assert (request["timestamp_raw"], request["timestamp_utc"], request["time_source"]) == (
        "09/Nov/2026:02:14:01 +0100", "2026-11-09T01:14:01+00:00", "log")


def test_log_time_that_cannot_be_normalized_is_kept_raw_with_null_utc(site, evidence, analyze):
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP, when="09/Nov/2026:02:14:01")).parent

    request = analyze(site, logs=logs).report["observations"][0]

    assert (request["timestamp_raw"], request["timestamp_utc"], request["time_source"]) == ("09/Nov/2026:02:14:01", None, "log")


def test_database_observation_names_table_key_and_row(site, evidence, analyze):
    database = write(evidence / "db.sql", option_sql("blogname", "Synthetic") + option_sql("custom_footer", "<script>synthetic()</script>"))

    report = analyze(site, database=database).report

    assert [item["location"] for item in report["observations"]] == [{"table": "wp_options", "key": "custom_footer", "row": 2}]


def test_repeated_rows_with_the_same_key_stay_separate_observations(site, evidence, analyze):
    database = write(evidence / "db.sql", option_sql("custom_footer", "<script>one()</script>") * 2)

    report = analyze(site, database=database).report

    assert sorted(item["location"]["row"] for item in report["observations"]) == [1, 2]
    assert len(report["findings"]) == 2


def test_missing_baseline_file_is_observed_on_the_baseline_evidence(site, tmp_path, analyze):
    baseline = write(tmp_path / "trusted.json", json.dumps({"files": {"wp-includes/removed.php": "0" * 64}}))

    run = analyze(site, baseline=baseline)
    fact = run.report["observations"][0]

    assert (fact["kind"], fact["location"]) == ("BASELINE_ENTRY_NOT_IN_FILES", {"path": "wp-includes/removed.php"})
    assert fact["evidence_id"] == run.evidence("baseline/trusted.json")["id"]


def test_timeline_events_name_their_time_source_and_reference_recorded_items(demo_case, analyze):
    report = analyze_demo(analyze, demo_case).report
    observations = {item["id"] for item in report["observations"]}

    assert {event["event"]: event["time_source"] for event in report["timeline"]} == {
        "HTTP_EXECUTABLE_IN_UPLOADS": "log", "SUSPICIOUS_FILE_MTIME": "mtime"}
    assert {event["observation_id"] for event in report["timeline"] if event["time_source"] == "log"} <= observations
    assert report["analyzed_at_time_source"] == "tool_clock" and report["analyzed_at_utc"].endswith("+00:00")


def test_compose_report_refuses_a_baseline_that_was_not_read_in_its_session(site):
    with pytest.raises(ValueError, match="load_baseline"):
        cli.compose_report(site, None, None, {"files": {"index.php": "0" * 64}}, set(), "SYNTH")


# --- ocena i kody wyjścia przy ustaleniach --------------------------------------------------------

def test_demo_case_is_suspicious_not_strong(demo_case, analyze):
    """Reguły PoC to heurystyki o pewności najwyżej ``medium`` przy wadze ``high``: żadna nie jest silnym wskaźnikiem."""
    run = analyze_demo(analyze, demo_case)

    assert (run.report["assessment"], run.report["scope_complete"], run.exit_code) == ("SUSPICIOUS", True, 0)
    assert not any(models.is_strong(models.Finding.from_dict(finding)) for finding in run.report["findings"])


def test_findings_do_not_hide_an_incomplete_scope_and_do_not_set_the_exit_code(site, analyze):
    write(site / UPLOAD_PHP, EVAL_MARKER)

    run = analyze(site)

    assert (run.report["assessment"], run.report["scope_complete"], run.exit_code) == ("SUSPICIOUS", False, 3)
    assert "Zakres analizy: <strong>niepełny</strong>" in run.html


@pytest.mark.parametrize("statuses, complete, expected", [
    ({}, True, 0),
    ({"baseline": "NOT_PROVIDED"}, True, 0),
    ({"database": "NOT_PROVIDED"}, False, 3),
    ({"files": "PARTIAL"}, False, 3),
    ({"baseline": "PARTIAL"}, False, 3),
    ({"logs": "FAILED"}, False, 4),
    ({"files": "PARTIAL", "database": "FAILED"}, False, 4),
], ids=["complete", "complete-without-baseline", "source-not-provided", "source-partial", "baseline-partial", "source-failed",
        "failed-outranks-partial"])
def test_exit_code_follows_coverage(statuses, complete, expected):
    coverage = {source: {"status": statuses.get(source, "ANALYZED")} for source in models.SOURCES}

    assert cli.exit_code({"coverage": coverage, "scope_complete": complete}) == expected


def test_stdout_summary_reports_assessment_scope_and_exit_code(complete_case, analyze):
    del complete_case["logs"]

    run = analyze(**complete_case)
    summary = json.loads(run.stdout)

    assert (summary["assessment"], summary["scope_complete"], summary["exit_code"]) == ("INCONCLUSIVE", False, 3)


# --- HTML ---------------------------------------------------------------------------------------

def test_html_report_shows_assessment_and_coverage_of_every_source(complete_case, analyze):
    del complete_case["database"]

    html_report = analyze(**complete_case).html

    assert "Stan: <strong>INCONCLUSIVE</strong>" in html_report
    for row in ("<td>files</td><td>ANALYZED</td><td>1</td><td>0</td>", "<td>database</td><td>NOT_PROVIDED</td><td>0</td><td>0</td>",
                "<td>logs</td><td>ANALYZED</td>", "<td>baseline</td><td>NOT_PROVIDED</td>"):
        assert row in html_report


def test_html_report_shows_severity_and_confidence_side_by_side(site, analyze):
    write(site / UPLOAD_PHP)

    assert f"<tr><td>high</td><td>medium</td><td>EXECUTABLE_IN_UPLOADS</td><td>{UPLOAD_PHP}</td>" in analyze(site).html


def test_html_report_escapes_every_new_field(tmp_path):
    """Pola dodane w poc-1 (pokrycie, pewność, miejsce obserwacji) przechodzą przez to samo escapowanie co reszta."""
    marked = {"case_id": XSS, "analyzed_at_utc": XSS, "assessment": XSS, "disclaimer": XSS, "scope_complete": XSS, "coverage_gaps": [XSS],
              "findings": [{"severity": XSS, "confidence": XSS, "rule_id": XSS, "reason": XSS, "observations": ["obs_1", XSS]}],
              "observations": [{"id": "obs_1", "location": {"table": XSS, "key": XSS}}],
              "coverage": {XSS: {"status": XSS, "entries": {"READ": XSS, XSS: 1}}, "legacy": {"status": XSS, "entries": None}},
              "timeline": [{"time_utc": XSS, "event": XSS, "source": XSS, "timestamp_basis": XSS}]}

    cli.write_html(marked, tmp_path / "report.html")

    assert "<img" not in (tmp_path / "report.html").read_text(encoding="utf-8")


# --- deterministyczność identyfikatorów ---------------------------------------------------------

def _identifiers(report: dict) -> dict:
    return {name: [item["id"] for item in report[name]] for name in ("evidence", "observations", "findings")}


def test_identifiers_do_not_depend_on_the_host_path_or_file_times(evidence, tmp_path, analyze):
    first = analyze_demo(analyze, Path(shutil.copytree(FIXTURES, evidence / "copy-a")))
    second_copy = Path(shutil.copytree(FIXTURES, tmp_path / "elsewhere" / "copy-b"))
    os.utime(second_copy / "site" / "index.php", ns=(1_600_000_000_000_000_000, 1_600_000_000_000_000_000))

    second = analyze_demo(analyze, second_copy)

    assert _identifiers(first.report) == _identifiers(second.report)


def _report_from_fresh_process(case: Path, out: Path, hash_seed: str) -> dict:
    """Osobny proces Pythona z zadanym ``PYTHONHASHSEED``; uruchamiane jest wyłącznie narzędzie, nigdy materiał."""
    command = [sys.executable, "-m", "wpincidentlens", "--files", str(case / "site"), "--database", str(case / "database.sql"),
               "--logs", str(case / "logs"), "--baseline", str(case / "baseline.json"), "--output", str(out)]
    done = subprocess.run(command, cwd=REPOSITORY, env={**os.environ, "PYTHONHASHSEED": hash_seed}, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return json.loads((out / "report.json").read_text(encoding="utf-8"))


def test_reports_from_processes_with_different_hash_seeds_are_identical(demo_case, tmp_path):
    first = _report_from_fresh_process(demo_case, tmp_path / "seed-1", "1")
    second = _report_from_fresh_process(demo_case, tmp_path / "seed-2", "4242")

    assert strip_time(first) == strip_time(second)
    assert first["findings"] and _identifiers(first) == _identifiers(second)


# --- JSON Schema --------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_published_schema_is_a_valid_draft_2020_12_schema(schema):
    jsonschema.Draft202012Validator.check_schema(schema)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_report_generated_for_the_fixtures_validates_against_the_published_schema(demo_case, analyze):
    report = analyze_demo(analyze, demo_case).report

    assert (len(report["findings"]), len(report["observations"]), len(report["evidence"])) == (6, 6, 6)
    assert schema_errors(report) == []


def _set(*path_and_value):
    *path, value = path_and_value
    return lambda report: replace_at(report, tuple(path), value)


def _drop(*path):
    return lambda report: remove_at(report, path)


SCHEMA_VIOLATIONS = {
    "missing-assessment": _drop("assessment"),
    "missing-coverage-source": _drop("coverage", "logs"),
    "missing-evidence-read-status": _drop("evidence", 0, "read_status"),
    "unknown-top-level-field": _set("verdict", "clean"),
    "unknown-assessment": _set("assessment", "INDICATORS_FOUND"),
    "old-schema-version": _set("schema_version", "0.1.0"),
    "uppercase-severity": _set("findings", 0, "severity", "HIGH"),
    "critical-confidence": _set("findings", 0, "confidence", "critical"),
    "finding-without-observations": _set("findings", 0, "observations", []),
    "malformed-evidence-id": _set("evidence", 0, "id", "ev-1"),
    "host-path-in-evidence": _set("evidence", 0, "logical_path", "/srv/www/index.php"),
    "read-evidence-without-hash": _set("evidence", 0, "sha256", None),
    "unknown-read-status": _set("evidence", 0, "read_status", "SKIPPED"),
    "legacy-read-status-in-native-report": _set("evidence", 0, "read_status", "UNKNOWN_LEGACY"),
    "legacy-coverage-in-native-report": _set("coverage", "files", {"status": "UNKNOWN_LEGACY", "entries": None, "reasons": []}),
    "partial-coverage-without-reason": _set("coverage", "files", "reasons", []),
    "coverage-without-counters": _set("coverage", "files", "entries", None),
    "negative-counter": _set("coverage", "files", "entries", "READ", -1),
    "local-time": _set("analyzed_at_utc", "2026-11-11T11:00:00+01:00"),
    "time-without-zone": _set("timeline", 0, "time_utc", "2026-11-09T01:14:01"),
    "tool-clock-on-timeline": _set("timeline", 0, "time_source", "tool_clock"),
    "nested-observation-attribute": _set("observations", 0, "attributes", {"nested": {"a": 1}}),
    "scope-flag-as-text": _set("scope_complete", "yes"),
}


@pytest.mark.parametrize("violate", SCHEMA_VIOLATIONS.values(), ids=SCHEMA_VIOLATIONS.keys())
def test_schema_rejects_a_deliberately_broken_report(site, evidence, tmp_path, analyze, violate):
    """Raport wyjściowy ma ustalenie, oś czasu i źródło ``PARTIAL``, żeby każdy wariant psuł istniejące pole."""
    os.link(write(tmp_path / "outside.txt", "synthetic"), site / "shared.txt")
    write(site / UPLOAD_PHP)
    report = analyze(site, logs=write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP)).parent).report

    violate(report)

    assert schema_errors(report) != []


def test_schema_enumerations_match_the_model(schema):
    """Schemat jest pisany ręcznie; ten test wykrywa rozjazd wyliczeń między plikiem a ``wpincidentlens.models``."""
    defs, properties = schema["$defs"], schema["properties"]

    assert properties["assessment"]["enum"] == list(models.Assessment)
    assert defs["severity"]["enum"] == list(models.Severity)
    assert defs["confidence"]["enum"] == list(models.Confidence)
    assert defs["evidence"]["properties"]["read_status"]["enum"] == list(models.READ_STATUSES)
    assert defs["evidence"]["properties"]["origin_kind"]["enum"] == list(models.OriginKind)
    assert defs["finding"]["properties"]["category"]["enum"] == list(models.Category)
    assert defs["coverage"]["properties"]["status"]["enum"] == list(models.CoverageStatus)
    assert defs["coverage"]["properties"]["entries"]["oneOf"][1]["required"] == [str(status) for status in ReadStatus]
    assert defs["observation"]["properties"]["time_source"]["enum"] == [*models.TimeSource, None]
    assert properties["coverage"]["required"] == list(models.SOURCES)
    assert properties["schema_version"]["const"] == models.SCHEMA_VERSION
    assert properties["migrated_from"]["const"] in models.MIGRATED_FROM


def test_schema_fields_match_the_fields_the_model_writes(schema, demo_case, analyze):
    report = analyze_demo(analyze, demo_case).report
    defs = schema["$defs"]

    assert set(schema["required"]) == set(report)
    for name, definition in (("evidence", "evidence"), ("observations", "observation"), ("findings", "finding"), ("timeline", "timeline_event")):
        assert set(defs[definition]["required"]) == set(defs[definition]["properties"]) == set(report[name][0]), name


# --- zrzut SQL, którego część parser pominął, nie ma pełnego pokrycia ----------------------------

MARKUP = "<script src=//example.invalid/x.js></script>"
SKIPPED_SQL = {
    "update-statement": ("UPDATE `wp_users` SET user_pass='x' WHERE ID=1;\n", "PARTIAL", "nie analizuje: UPDATE ×1"),
    "delete-statement": ("delete from `wp_options` where option_id=1;\n", "PARTIAL", "nie analizuje: DELETE ×1"),
    "create-trigger": ("CREATE TRIGGER t BEFORE INSERT ON `wp_users` FOR EACH ROW SET NEW.user_pass='x';\n", "PARTIAL", "CREATE TRIGGER ×1"),
    "drop-view": ("DROP VIEW IF EXISTS v;\n", "PARTIAL", "DROP VIEW ×1"),
    "call-procedure": ("CALL synthetic();\n", "PARTIAL", "CALL ×1"),
    "statement-not-starting-with-a-keyword": ("(SELECT 1);\n", "PARTIAL", "nie analizuje"),
    "executable-comment": (f"/*!50001 REPLACE INTO `wp_options` VALUES (2,'c','{MARKUP}') */;\n", "PARTIAL", "nieobsługiwanej składni"),
    "mariadb-executable-comment": (f"/*M!100100 replace into `wp_options` VALUES (2,'c','{MARKUP}') */;\n", "PARTIAL", "nieobsługiwanej składni"),
    "executable-comment-without-space-after-version": (f"/*!50001REPLACE INTO `wp_options` VALUES (2,'c','{MARKUP}') */;\n",
                                                       "PARTIAL", "nieobsługiwanej składni"),
    "client-delimiter-command": (f"\\d ;;\nREPLACE INTO `wp_options` VALUES (2,'c','{MARKUP}') ;;\n", "PARTIAL", "nieobsługiwanej składni"),
    "client-terminator-inside-a-statement": (f"SELECT 1 \\g REPLACE INTO `wp_options` VALUES (2,'c','{MARKUP}');\n", "PARTIAL", "nieobsługiwanej składni"),
    "delimiter-directive": (f"DELIMITER ;;\nREPLACE INTO `wp_options` VALUES (2,'c','{MARKUP}') ;;\nDELIMITER ;\n", "PARTIAL", "nieobsługiwanej składni"),
    "second-statement-on-the-same-line": (f"INSERT INTO `wp_options` VALUES (1,'a','b'); REPLACE INTO `wp_options` VALUES (2,'c','{MARKUP}');\n",
                                          "PARTIAL", "nieobsługiwanej składni"),
    "statement-after-a-comment": (f"/* note */ REPLACE INTO `wp_options` VALUES (2,'c','{MARKUP}');\n", "PARTIAL", "nieobsługiwanej składni"),
    "statement-after-a-line-comment": (f"-- note\n\tReplace INTO `wp_options` VALUES (2,'c','{MARKUP}');\n", "PARTIAL", "nieobsługiwanej składni"),
    "truncated-statement": (f"INSERT INTO `wp_options` VALUES (1,'siteurl','{MARKUP}'),(2,'x','tru", "PARTIAL", "niedomkniętych instrukcji"),
    "replace-into": (f"REPLACE INTO `wp_options` VALUES (1,'a','{MARKUP}');\n", "PARTIAL", "nieobsługiwanej składni"),
    "insert-ignore": (f"INSERT IGNORE INTO `wp_options` VALUES (1,'a','{MARKUP}');\n", "PARTIAL", "nieobsługiwanej składni"),
    "database-qualified-name": (f"INSERT INTO wp.wp_options VALUES (1,'a','{MARKUP}');\n", "PARTIAL", "nieobsługiwanej składni"),
    "insert-set": (f"INSERT INTO `wp_options` SET option_name='a', option_value='{MARKUP}';\n", "PARTIAL", "nieobsługiwanej składni"),
    "expression-instead-of-literal": ("INSERT INTO `wp_options` VALUES (4,'d',CONCAT('<script>','x'));\n", "PARTIAL", "nieoczekiwanej liczbie pól"),
    "column-list-longer-than-row": ("INSERT INTO `wp_options` (`option_id`,`option_name`,`option_value`) VALUES (4,CONCAT('a','b'));\n",
                                    "PARTIAL", "nieoczekiwanej liczbie pól"),
}


@pytest.mark.parametrize("extra, status, reason", SKIPPED_SQL.values(), ids=SKIPPED_SQL.keys())
def test_sql_that_the_parser_skipped_lowers_database_coverage(complete_case, evidence, analyze, extra, status, reason):
    database = write(evidence / "skipped.sql", admin_sql("siteadmin") + extra)

    run = analyze(**{**complete_case, "database": database})

    assert run.coverage("database")["status"] == status
    assert run.has_gap(reason)
    assert (run.report["assessment"], run.report["scope_complete"], run.exit_code) == ("INCONCLUSIVE", False, 3)


def test_dump_without_wordpress_tables_is_not_an_analyzed_database(complete_case, evidence, analyze):
    database = write(evidence / "foreign.sql", "INSERT INTO `foo` VALUES (1,'x');\n")

    run = analyze(**{**complete_case, "database": database})

    assert run.coverage("database")["status"] == "FAILED"
    assert (run.report["assessment"], run.exit_code) == ("INCONCLUSIVE", 4)


@pytest.mark.parametrize("prose", [
    "INSERT INTO `wp_options` VALUES (5,'note','please insert the key\\ninto the lock');\n",
    "INSERT INTO `wp_options` VALUES (5,'note','x'), (6,'other','y');\n",
    "insert into `wp_options` values (5,'note','x');\n",
    "INSERT INTO `wp_options` VALUES (5,'note','a; REPLACE INTO x VALUES (1)');\n",
    "-- REPLACE INTO `wp_options` VALUES (1,'a','b');\nINSERT INTO `wp_options` VALUES (5,'note','x');\n",
    "/* INSERT IGNORE INTO t VALUES (1); */ INSERT INTO `wp_options` VALUES (5,'note','x');\n",
    "/*!40000 ALTER TABLE `wp_options` DISABLE KEYS */;\nINSERT INTO `wp_options` VALUES (5,'note','x');\n/*!40101 SET NAMES utf8 */;\n",
    "INSERT INTO `wp_options` VALUES (5,'note','C:\\\\path\\\\file and it\\'s fine');\n",
    "DROP TABLE IF EXISTS `wp_options`;\nCREATE TABLE `wp_options` (`option_id` bigint, `option_name` varchar(191));\n"
    "LOCK TABLES `wp_options` WRITE;\nALTER TABLE `wp_options` DISABLE KEYS;\nSET NAMES utf8;\nUNLOCK TABLES;\nCOMMIT;\n",
], ids=["keyword-inside-a-value", "multi-row", "lower-case", "statement-text-inside-a-value", "statement-in-a-line-comment",
        "statement-in-a-block-comment", "mysqldump-version-comments", "backslashes-inside-a-value", "mysqldump-table-definition"])
def test_supported_inserts_keep_database_coverage_complete(complete_case, evidence, analyze, prose):
    database = write(evidence / "plain.sql", admin_sql("siteadmin") + prose)

    run = analyze(**{**complete_case, "database": database})

    assert (run.coverage("database")["status"], run.report["scope_complete"]) == ("ANALYZED", True)


def test_long_option_name_and_client_address_are_truncated_in_the_report(complete_case, evidence, analyze):
    database = write(evidence / "long.sql", admin_sql("siteadmin") + option_sql("k" * 5000, MARKUP))
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP, ip="1" * 5000)).parent

    run = analyze(**{**complete_case, "database": database, "logs": logs})

    assert max(len(str(value)) for observation in run.report["observations"]
               for value in [*observation["location"].values(), *observation["attributes"].values()]) <= 300


# --- pliki logów o tej samej nazwie w różnych katalogach ------------------------------------------

@pytest.fixture
def twin_logs(evidence):
    """Dwa pliki ``access.log`` o identycznej treści (jedno żądanie do PHP w uploads) w katalogach ``a`` i ``b``."""
    for directory in ("a", "b"):
        write(evidence / "rotated" / directory / "access.log", access_line("/" + UPLOAD_PHP))
    return evidence / "rotated"


def test_same_named_logs_in_two_directories_are_two_evidence_entries(complete_case, twin_logs, analyze):
    run = analyze(**{**complete_case, "logs": twin_logs})
    first, second = run.evidence("logs/a/access.log"), run.evidence("logs/b/access.log")

    assert first["id"] != second["id"] and first["sha256"] == second["sha256"]
    assert entries(run, "logs") == {"READ": 2}


def test_requests_in_same_named_logs_are_attributed_to_their_own_file(complete_case, twin_logs, analyze):
    run = analyze(**{**complete_case, "logs": twin_logs})

    assert sorted(item["source"] for item in run.findings if item["rule"] == "HTTP_EXECUTABLE_IN_UPLOADS") == [
        "a/access.log:1", "b/access.log:1"]


# --- mtime, którego nie da się zapisać jako daty --------------------------------------------------

YEAR_10000_SECONDS = 253_402_300_800


def _flagged_upload(mtime_ns: int) -> tuple[cli.Detection, models.Evidence]:
    record = models.Evidence("file", f"files/{UPLOAD_PHP}", "READ", sha256="a" * 64, size_bytes=1, mtime_ns=mtime_ns)
    fact = models.Observation(record.id, "PHP_FILE_IN_UPLOADS", models.Location(path=UPLOAD_PHP))
    return cli.Detection("EXECUTABLE_IN_UPLOADS", "high", "medium", "file", "ustalenie syntetyczne", fact), record


@pytest.mark.parametrize("mtime_ns", [YEAR_10000_SECONDS * 10**9, 10**30, -10**30, -(10**20)],
                         ids=["year-10000", "far-future", "far-past", "before-year-1"])
def test_flagged_file_with_mtime_outside_the_datetime_range_gets_a_note_instead_of_a_timeline_event(mtime_ns):
    found, record = _flagged_upload(mtime_ns)

    assert cli._timeline([found], {record.id: record}) == ([], [f"Nie można zapisać mtime jako czasu UTC: files/{UPLOAD_PHP}"])


def test_flagged_file_with_an_ordinary_mtime_is_dated_without_a_note():
    found, record = _flagged_upload(1_762_650_841 * 10**9)

    events, undated = cli._timeline([found], {record.id: record})

    assert ([(event.time_utc, event.event) for event in events], undated) == (
        [("2025-11-09T01:14:01+00:00", "SUSPICIOUS_FILE_MTIME")], [])


def test_report_names_the_flagged_file_whose_mtime_cannot_be_written_as_a_date(complete_case, site, analyze):
    upload = write(site / UPLOAD_PHP)
    try:
        os.utime(upload, ns=(0, YEAR_10000_SECONDS * 10**9))
    except (OSError, OverflowError):
        pytest.skip("system plików nie przyjmuje mtime spoza zakresu lat 1–9999")
    if upload.stat().st_mtime_ns != YEAR_10000_SECONDS * 10**9:
        pytest.skip("system plików nie zachowuje mtime spoza zakresu lat 1–9999")

    run = analyze(**complete_case)

    assert f"Nie można zapisać mtime jako czasu UTC: files/{UPLOAD_PHP}" in run.gaps
    assert not any(event["event"] == "SUSPICIOUS_FILE_MTIME" for event in run.report["timeline"])
