"""Migracja raportu 0.1.0 do ``poc-1`` (ADR 0002 D7, ADR 0003).

``tests/data/report-0.1.0.json`` to dawny ``demo/report.json``: raport 0.1.0 wygenerowany z syntetycznych ``fixtures/``.
Pozostałe raporty 0.1.0 są budowane w testach.
"""
import copy
import json

import pytest
from conftest import LEGACY_REPORT_PATH, schema_errors

from wptrace import cli
from wptrace.migrate import LEGACY_KIND, MIGRATION_NOTE, MigrationError, migrate_0_1_0
from wptrace.models import SOURCES, describe_location, validate_report

SHA = "c" * 64
UPLOAD = "wp-content/uploads/2026/11/cache-view.php"


def legacy_finding(rule: str = "EXECUTABLE_IN_UPLOADS", source_type: str = "file", source: str = UPLOAD, **metadata) -> dict:
    return {"rule": rule, "severity": "high", "confidence": "medium", "source_type": source_type, "source": source,
            "explanation": "ustalenie syntetyczne", "metadata": metadata}


def legacy_report(findings: list | None = None, **changes) -> dict:
    """Raport 0.1.0 w kształcie, jaki pisało narzędzie przed T-102; domyślnie bez ustaleń."""
    findings = findings or []
    report = {"schema_version": "0.1.0", "tool": "WPTrace PoC", "tool_version": "0.1.0-poc", "case_id": "LEGACY-SYNTH",
              "analyzed_at_utc": "2026-11-10T08:00:00+00:00",
              "assessment": "INDICATORS_FOUND" if findings else "NO_INDICATORS_IN_ANALYZED_SCOPE",
              "disclaimer": "Brak alertów nie dowodzi braku włamania. PoC, nie certyfikacja śledcza.",
              "findings": findings, "counts": {"high": len(findings)} if findings else {}, "timeline": [],
              "coverage_gaps": ["Brak logów HTTP"],
              "evidence_manifest": [
                  {"source": "database/db.sql", "sha256": SHA, "size": 120},
                  {"source": f"files/{UPLOAD}", "sha256": SHA, "size": 40, "mtime_ns": 1_762_692_528_168_411_000},
                  {"source": "logs/access.log", "sha256": SHA, "size": 90}]}
    return {**report, **changes}


@pytest.fixture(scope="module")
def demo_legacy() -> dict:
    return json.loads(LEGACY_REPORT_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def demo_migrated(demo_legacy) -> dict:
    return migrate_0_1_0(demo_legacy)


# --- raport demonstracyjny 0.1.0 ----------------------------------------------------------------

def test_stored_demo_report_is_a_0_1_0_report(demo_legacy):
    assert (demo_legacy["schema_version"], demo_legacy["assessment"]) == ("0.1.0", "INDICATORS_FOUND")


def test_migrated_demo_report_satisfies_the_model_contract_and_the_published_schema(demo_migrated):
    validate_report(demo_migrated)

    assert schema_errors(demo_migrated) == []
    assert (demo_migrated["schema_version"], demo_migrated["migrated_from"]) == ("poc-1", "0.1.0")


def test_migrated_demo_report_keeps_every_finding_with_its_rating_and_explanation(demo_legacy, demo_migrated):
    def rated(findings, rule, reason):
        return sorted((item[rule], item["severity"], item["confidence"], item[reason]) for item in findings)

    assert rated(demo_migrated["findings"], "rule_id", "reason") == rated(demo_legacy["findings"], "rule", "explanation")


def test_migrated_demo_findings_rest_on_synthetic_observations_that_keep_the_old_source(demo_legacy, demo_migrated):
    observations = {item["id"]: item for item in demo_migrated["observations"]}
    places = sorted((finding["rule_id"], describe_location(observations[finding["observations"][0]]["location"]))
                    for finding in demo_migrated["findings"])

    assert {item["kind"] for item in observations.values()} == {LEGACY_KIND}
    assert len(observations) == len(demo_legacy["findings"]) == 6
    assert places == sorted((item["rule"], item["source"]) for item in demo_legacy["findings"])


def test_migrated_demo_observation_keeps_the_old_metadata_as_attributes(demo_legacy, demo_migrated):
    old = next(item for item in demo_legacy["findings"] if item["rule"] == "HTTP_EXECUTABLE_IN_UPLOADS")
    request = next(item for item in demo_migrated["observations"] if item["attributes"]["legacy_rule"] == "HTTP_EXECUTABLE_IN_UPLOADS")

    assert request["location"] == {"path": "access.log", "line": 1}
    assert sorted(old["metadata"]) == ["client_ip", "method", "observed_time", "status", "uri"]
    assert request["attributes"] == {**old["metadata"], "legacy_rule": "HTTP_EXECUTABLE_IN_UPLOADS", "legacy_source_type": "http_log"}


def test_migrated_demo_evidence_keeps_hashes_and_marks_the_read_status_unknown(demo_legacy, demo_migrated):
    migrated = {(item["logical_path"], item["sha256"], item["size_bytes"], item["mtime_ns"]) for item in demo_migrated["evidence"]}

    assert migrated == {(entry["source"], entry["sha256"], entry["size"], entry.get("mtime_ns")) for entry in demo_legacy["evidence_manifest"]}
    assert {item["read_status"] for item in demo_migrated["evidence"]} == {"UNKNOWN_LEGACY"}


def test_migrated_demo_assessment_is_downgraded_to_suspicious(demo_migrated):
    assert (demo_migrated["assessment"], demo_migrated["scope_complete"]) == ("SUSPICIOUS", False)


def test_migrated_demo_coverage_is_unknown_for_every_source(demo_legacy, demo_migrated):
    assert demo_migrated["coverage"] == {source: {"status": "UNKNOWN_LEGACY", "entries": None, "reasons": []} for source in SOURCES}
    assert set(demo_legacy["coverage_gaps"]) | {MIGRATION_NOTE} == set(demo_migrated["coverage_gaps"])


def test_migrated_demo_timeline_keeps_times_and_gains_time_sources(demo_legacy, demo_migrated):
    evidence = {item["id"]: item["logical_path"] for item in demo_migrated["evidence"]}

    assert [(event["time_utc"], event["event"], event["source"], event["timestamp_basis"]) for event in demo_migrated["timeline"]] == [
        (event["time_utc"], event["event"], event["source"], event["timestamp_basis"]) for event in demo_legacy["timeline"]]
    assert [(event["time_source"], evidence[event["evidence_id"]]) for event in demo_migrated["timeline"]] == [
        ("log", "logs/access.log"), ("mtime", f"files/{UPLOAD}")]


def test_migrated_demo_report_renders_to_html(demo_migrated, tmp_path):
    cli.write_html(demo_migrated, tmp_path / "report.html")

    rendered = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "<td>files</td><td>UNKNOWN_LEGACY</td><td>brak danych</td>" in rendered
    assert "<td>demo_options:custom_footer</td>" in rendered


# --- raporty 0.1.0 budowane w teście -------------------------------------------------------------

def test_no_indicators_becomes_inconclusive_because_old_coverage_is_unknown():
    migrated = migrate_0_1_0(legacy_report())

    assert (migrated["assessment"], migrated["findings"], migrated["observations"]) == ("INCONCLUSIVE", [], [])
    assert schema_errors(migrated) == []


def test_indicators_found_becomes_suspicious_even_for_a_high_confidence_finding():
    strongest = {**legacy_finding(), "severity": "high", "confidence": "high"}

    assert migrate_0_1_0(legacy_report([strongest]))["assessment"] == "SUSPICIOUS"


def test_migration_is_pure_and_deterministic():
    legacy = legacy_report([legacy_finding(sha256=SHA)])
    before = copy.deepcopy(legacy)

    first, second = migrate_0_1_0(legacy), migrate_0_1_0(copy.deepcopy(legacy))

    assert legacy == before
    assert first == second


def test_finding_about_an_entry_missing_from_the_manifest_gets_evidence_without_a_hash():
    """Stary raport zgłaszał np. nieprzeczytany plik w uploads, ale nie umieszczał go w manifeście."""
    migrated = migrate_0_1_0(legacy_report([legacy_finding(source="wp-content/uploads/linked.php", read_status="SKIPPED_HARDLINK")]))
    unresolved = next(item for item in migrated["evidence"] if item["logical_path"] == "files/wp-content/uploads/linked.php")

    assert (unresolved["read_status"], unresolved["sha256"], unresolved["size_bytes"]) == ("UNKNOWN_LEGACY", None, None)
    assert migrated["observations"][0]["evidence_id"] == unresolved["id"]
    assert schema_errors(migrated) == []


@pytest.mark.parametrize("finding, logical_path, location", [
    (legacy_finding(), f"files/{UPLOAD}", {"path": UPLOAD}),
    (legacy_finding("CORRELATED_UPLOAD_REQUEST", "correlation"), f"files/{UPLOAD}", {"path": UPLOAD}),
    (legacy_finding("HTTP_EXECUTABLE_IN_UPLOADS", "http_log", "access.log:7"), "logs/access.log", {"path": "access.log", "line": 7}),
    (legacy_finding("SUSPICIOUS_DB_MARKUP", "database", "wp_options:custom_footer"), "database/db.sql", {"table": "wp_options", "key": "custom_footer"}),
    (legacy_finding("UNRECOGNIZED_ADMIN", "database", "*_users / *_usermeta"), "database/db.sql", {"table": "*_users / *_usermeta"}),
    (legacy_finding("SUSPICIOUS_DB_MARKUP", "database", "wp_options:a:b"), "database/db.sql", {"table": "wp_options", "key": "a:b"}),
], ids=["file", "correlation", "log-line", "table-key", "table-pattern", "key-with-colon"])
def test_old_source_is_resolved_to_manifest_evidence_and_a_structured_location(finding, logical_path, location):
    migrated = migrate_0_1_0(legacy_report([finding]))
    evidence = {item["id"]: item for item in migrated["evidence"]}
    fact = migrated["observations"][0]

    assert (evidence[fact["evidence_id"]]["logical_path"], evidence[fact["evidence_id"]]["sha256"]) == (logical_path, SHA)
    assert fact["location"] == location
    assert describe_location(fact["location"]) == finding["source"]


def test_two_old_findings_on_one_file_stay_two_findings_with_their_own_observations():
    migrated = migrate_0_1_0(legacy_report([legacy_finding(), legacy_finding("SUSPICIOUS_PHP_EVAL_DECODE")]))

    assert len(migrated["findings"]) == len(migrated["observations"]) == 2
    assert len({item["evidence_id"] for item in migrated["observations"]}) == 1


def test_identical_old_findings_are_merged_and_the_merge_is_reported():
    migrated = migrate_0_1_0(legacy_report([legacy_finding(), legacy_finding()]))

    assert len(migrated["findings"]) == 1
    assert "Migracja z 0.1.0: scalono 1 powtórzonych, identycznych ustaleń" in migrated["coverage_gaps"]


CONFLICT_NOTE = ("Migracja z 0.1.0: {} ustaleń o tej samej regule, źródle i metadanych co wcześniejsze różniło się wagą, pewnością "
                 "lub wyjaśnieniem; zachowano najwyższą wagę, najwyższą pewność i pierwsze wyjaśnienie")
LOW_BUT_SURE = {**legacy_finding(), "severity": "low", "confidence": "high", "explanation": "pierwsze"}
HIGH_BUT_UNSURE = {**legacy_finding(), "severity": "high", "confidence": "low", "explanation": "drugie"}


@pytest.mark.parametrize("findings", [[LOW_BUT_SURE, HIGH_BUT_UNSURE], [HIGH_BUT_UNSURE, LOW_BUT_SURE]], ids=["weaker-first", "stronger-first"])
def test_old_findings_differing_only_in_rating_keep_the_higher_severity_and_the_higher_confidence(findings):
    migrated = migrate_0_1_0(legacy_report(findings))

    assert [(item["severity"], item["confidence"]) for item in migrated["findings"]] == [("high", "high")]


def test_conflicting_old_findings_are_reported_as_a_conflict_not_as_identical():
    migrated = migrate_0_1_0(legacy_report([LOW_BUT_SURE, HIGH_BUT_UNSURE]))

    assert CONFLICT_NOTE.format(1) in migrated["coverage_gaps"]
    assert not any("identycznych" in gap for gap in migrated["coverage_gaps"])
    assert schema_errors(migrated) == []


def test_conflicting_old_findings_keep_the_first_explanation():
    migrated = migrate_0_1_0(legacy_report([LOW_BUT_SURE, HIGH_BUT_UNSURE]))

    assert [item["reason"] for item in migrated["findings"]] == ["pierwsze"]


def test_old_findings_differing_only_in_explanation_are_a_conflict_too():
    migrated = migrate_0_1_0(legacy_report([legacy_finding(), {**legacy_finding(), "explanation": "inne wyjaśnienie"}]))

    assert [item["reason"] for item in migrated["findings"]] == ["ustalenie syntetyczne"]
    assert CONFLICT_NOTE.format(1) in migrated["coverage_gaps"]


def test_identical_and_conflicting_repeats_are_counted_separately():
    migrated = migrate_0_1_0(legacy_report([LOW_BUT_SURE, LOW_BUT_SURE, HIGH_BUT_UNSURE]))

    assert {CONFLICT_NOTE.format(1), "Migracja z 0.1.0: scalono 1 powtórzonych, identycznych ustaleń"} <= set(migrated["coverage_gaps"])


def test_manifest_entry_repeated_without_any_difference_is_one_evidence():
    entry = {"source": "files/index.php", "sha256": SHA, "size": 1, "mtime_ns": 5}

    migrated = migrate_0_1_0(legacy_report(evidence_manifest=[entry, dict(entry)]))

    assert [item["logical_path"] for item in migrated["evidence"]] == ["files/index.php"]


def test_nested_metadata_is_kept_as_json_text():
    migrated = migrate_0_1_0(legacy_report([legacy_finding(details={"b": [1, 2], "a": None})]))

    assert migrated["observations"][0]["attributes"]["details"] == '{"a": null, "b": [1, 2]}'


@pytest.mark.parametrize("stamp", ["2026-11-10T09:00:00+01:00", "2026-11-10T08:00:00Z"], ids=["local-offset", "zulu"])
def test_zoned_time_is_normalized_to_utc(stamp):
    assert migrate_0_1_0(legacy_report(analyzed_at_utc=stamp))["analyzed_at_utc"] == "2026-11-10T08:00:00+00:00"


@pytest.mark.parametrize("stamp", ["2026-11-10T08:00:00", "yesterday", None], ids=["no-zone", "not-a-date", "null"])
def test_ambiguous_analysis_time_becomes_null_with_a_note(stamp):
    migrated = migrate_0_1_0(legacy_report(analyzed_at_utc=stamp))

    assert migrated["analyzed_at_utc"] is None
    assert "Migracja z 0.1.0: czas analizy nie był jednoznacznym czasem UTC i został pominięty" in migrated["coverage_gaps"]
    assert schema_errors(migrated) == []


def test_timeline_event_without_a_zoned_time_is_dropped_with_a_note():
    event = {"time_utc": "2026-11-09T01:14:01", "source": "access.log:1", "event": "HTTP_EXECUTABLE_IN_UPLOADS",
             "timestamp_basis": "HTTP access log", "confidence": "medium"}

    migrated = migrate_0_1_0(legacy_report(timeline=[event]))

    assert migrated["timeline"] == []
    assert any("pominięto zdarzenie osi czasu" in gap and "access.log:1" in gap for gap in migrated["coverage_gaps"])


def test_report_without_a_timeline_field_is_still_migrated():
    legacy = legacy_report()
    del legacy["timeline"]

    assert migrate_0_1_0(legacy)["timeline"] == []


# --- wejście, którego nie da się przenieść bez zgadywania ------------------------------------------

def _without(field: str) -> dict:
    report = legacy_report()
    del report[field]
    return report


REFUSED = {
    "not-an-object": ([], "raport: oczekiwano obiektu, jest list"),
    "already-poc-1": (legacy_report(schema_version="poc-1"), "schema_version: oczekiwano '0.1.0', jest 'poc-1'"),
    "no-schema-version": (_without("schema_version"), "schema_version: oczekiwano '0.1.0', jest 'None'"),
    "missing-manifest": (_without("evidence_manifest"), "raport: brak pól: evidence_manifest"),
    "missing-findings": (_without("findings"), "raport: brak pól: findings"),
    "unknown-assessment": (legacy_report(assessment="CLEAN"), "assessment: nieznana wartość 'CLEAN'"),
    "indicators-found-without-findings": (legacy_report(assessment="INDICATORS_FOUND"), "assessment: jest SUSPICIOUS, a z ustaleń i pokrycia wynika INCONCLUSIVE"),
    "no-indicators-with-findings": (legacy_report([legacy_finding()], assessment="NO_INDICATORS_IN_ANALYZED_SCOPE"),
                                    "assessment: jest INCONCLUSIVE, a z ustaleń i pokrycia wynika SUSPICIOUS"),
    "findings-not-a-list": (legacy_report(findings={"rule": "X"}, assessment="INDICATORS_FOUND"), "findings: oczekiwano listy, jest dict"),
    "finding-not-an-object": (legacy_report(["EXECUTABLE_IN_UPLOADS"]), r"findings\[0\]: oczekiwano obiektu, jest str"),
    "unknown-severity": (legacy_report([{**legacy_finding(), "severity": "severe"}]), r"findings\[0\]: finding.severity: nieznana wartość 'severe'"),
    "unknown-source-type": (legacy_report([legacy_finding(source_type="memory")]), r"findings\[0\].source_type: nieznana wartość 'memory'"),
    "finding-without-rule": (legacy_report([{**legacy_finding(), "rule": None}]), r"findings\[0\]: .*oczekiwano tekstu, jest NoneType"),
    "finding-without-source": (legacy_report([{**legacy_finding(), "source": None}]), r"findings\[0\].source: oczekiwano tekstu"),
    "manifest-path-outside-known-sources": (legacy_report(evidence_manifest=[{"source": "/srv/www/index.php", "sha256": SHA, "size": 1}]),
                                            r"evidence_manifest\[0\].source: nieznane źródło w ścieżce '/srv/www/index.php'"),
    "manifest-with-malformed-hash": (legacy_report(evidence_manifest=[{"source": "files/index.php", "sha256": "abc", "size": 1}]),
                                     r"evidence_manifest\[0\]: evidence.sha256"),
    "manifest-path-with-two-hashes": (legacy_report(evidence_manifest=[{"source": "files/index.php", "sha256": SHA, "size": 1},
                                                                       {"source": "files/index.php", "sha256": "d" * 64, "size": 1}]),
                                      r"evidence_manifest\[1\].source: ścieżka 'files/index.php' powtórzona z innym skrótem sha256"),
    "manifest-path-with-two-sizes": (legacy_report(evidence_manifest=[{"source": "files/index.php", "sha256": SHA, "size": 1},
                                                                      {"source": "files/index.php", "sha256": SHA, "size": 2}]),
                                     r"evidence_manifest\[1\].source: ścieżka 'files/index.php' powtórzona z innym rozmiarem lub mtime"),
    "text-not-writable-as-utf8": (legacy_report(case_id="a\ud800"), "case_id: tekst nie daje się zapisać w UTF-8"),
    "gap-not-text": (legacy_report(coverage_gaps=[{"gap": 1}]), "coverage_gaps: oczekiwano tekstu, jest dict"),
    "case-id-not-text": (legacy_report(case_id=7), "case_id: oczekiwano tekstu, jest int"),
}


@pytest.mark.parametrize("report, message", REFUSED.values(), ids=REFUSED.keys())
def test_input_that_is_not_a_consistent_0_1_0_report_is_refused(report, message):
    with pytest.raises(MigrationError, match=message):
        migrate_0_1_0(report)


@pytest.mark.parametrize("report", [
    legacy_report(analyzed_at_utc="0001-01-01T00:00:00+05:00"),
    legacy_report(assessment=["x"]),
    legacy_report([legacy_finding(source_type="http_log", source="access.log:" + "9" * 5000)]),
], ids=["time-out-of-range", "assessment-not-text", "huge-line-number"])
def test_malformed_legacy_values_end_in_a_migration_error_or_a_valid_report(report):
    try:
        validate_report(migrate_0_1_0(report))
    except MigrationError:
        pass
