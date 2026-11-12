"""Korelacja plik–żądanie HTTP i oś czasu (ADR 0007 pkt 6 i 8, T-401). Mapa: docs/TEST_MATRIX.md (N7).

Testy jednostkowe budują obiekty ``Detection`` i ``Observation`` wprost, więc nie zależą od parsera logów;
obserwacje ``HTTP_REQUEST`` mają kształt z ADR 0007 pkt 7. Wszystkie dane są syntetyczne.
"""
from __future__ import annotations

import os
import random
import re
from collections import namedtuple
from datetime import datetime, timezone

import pytest
from conftest import UPLOAD_PHP, access_line, write

from wpincidentlens import cli, correlate, httplog, models
from wpincidentlens.analysis import Detection, evidence_of

T0 = "2026-11-09T01:14:01+00:00"
T0_NS = int(datetime.fromisoformat(T0).timestamp()) * 10**9
LOG = models.Evidence("log", "logs/access.log", "READ", sha256="b" * 64, size_bytes=1)
PLUGIN_PHP = "wp-content/plugins/demo/endpoint.php"
DOUBLE_EXT = "wp-content/uploads/2026/11/photo.php.jpg"
UPLOADS_HTACCESS = "wp-content/uploads/.htaccess"
CORRELATION_RULES = {"CORRELATED_UPLOAD_REQUEST", "CORRELATED_FILE_REQUEST", "REQUEST_NEAR_FILE_CHANGE"}
CLAIMS = re.compile(r"proven|exploit|potwierdz|udowodni|spowodował|jest przyczyną|na pewno", re.I)


def flagged(path: str, rule: str = "BASELINE_FILE_CHANGED", *, mtime_ns: int | None = T0_NS,
            origin: str = "file") -> tuple[Detection, models.Evidence]:
    source = "files" if origin == "file" else "baseline"
    record = models.Evidence(origin, f"{source}/{path if origin == 'file' else 'trusted.json'}", "READ",
                             sha256="a" * 64, size_bytes=1, mtime_ns=mtime_ns)
    fact = models.Observation(record.id, "SYNTHETIC_FILE_FACT", models.Location(path=path), {"rule": rule})
    return Detection(rule, "medium", "high", "file", "ustalenie syntetyczne", fact), record


def request(path: str, *, at: str | None = T0, uncertainty: int | None = None, line: int = 1,
            kind: str = "HTTP_REQUEST", status: int = 200) -> models.Observation:
    timed = {"timestamp_raw": "09/Nov/2026:02:14:01 +0100", "timestamp_utc": at, "time_source": models.TimeSource.LOG}
    return models.Observation(LOG.id, kind, models.Location(path="access.log", line=line), {
        "path": path, "uri": "/" + path, "method": "GET", "status": status, "bytes": 75, "client_ip": "192.0.2.10",
        "client_ip_basis": "connection", "log_format": "combined@1", "timestamp_precision": "second",
        "clock_uncertainty_seconds": uncertainty}, **timed)


def shifted(seconds: int) -> str:
    return models.utc_iso(datetime.fromtimestamp(T0_NS // 10**9 + seconds, tz=timezone.utc))


def run(*flags: tuple[Detection, models.Evidence], requests=(), window: int = correlate.DEFAULT_WINDOW_SECONDS,
        extra: list[Detection] = ()) -> correlate.Correlation:
    evidence = {record.id: record for _, record in flags} | {LOG.id: LOG}
    return correlate.correlate([found for found, _ in flags] + list(extra), list(requests), evidence, window)


def by_rule(result: correlate.Correlation, rule: str) -> list[models.Finding]:
    return [finding for finding in result.findings if finding.rule_id == rule]


# --- SAME_PATH ----------------------------------------------------------------------------------

@pytest.mark.parametrize("path, rule", [(PLUGIN_PHP, "BASELINE_FILE_CHANGED"), (DOUBLE_EXT, "DOUBLE_EXTENSION_IN_UPLOADS"),
                                        ("wp-content/uploads/2026/11/x.php5", "EXECUTABLE_IN_UPLOADS")],
                         ids=["plugin-php", "double-extension", "php5-in-uploads"])
def test_request_to_a_flagged_code_file_is_a_same_path_correlation(path, rule):
    file = flagged(path, rule, mtime_ns=None)
    hit = request(path)

    [finding] = by_rule(run(file, requests=[hit]), "CORRELATED_FILE_REQUEST")

    assert set(finding.observations) == {file[0].observation.id, hit.id}
    assert (finding.category, finding.severity, finding.confidence) == ("correlation", "medium", "low")


def test_request_to_a_flagged_non_code_file_is_not_correlated_by_path():
    result = run(flagged(UPLOADS_HTACCESS, "HTACCESS_ENABLES_PHP_IN_UPLOADS", mtime_ns=None), requests=[request(UPLOADS_HTACCESS)])

    assert result.findings == ()


def test_request_without_a_file_finding_is_not_correlated():
    result = run(requests=[request(PLUGIN_PHP), request(UPLOAD_PHP, line=2)])

    assert (result.findings, result.requests) == ((), ())


def test_finding_resting_on_a_reference_entry_is_not_a_file_in_the_copy():
    missing = flagged(PLUGIN_PHP, "BASELINE_FILE_MISSING", origin="baseline")

    assert run(missing, requests=[request(PLUGIN_PHP)]).findings == ()


def test_request_to_another_path_is_not_a_same_path_correlation():
    result = run(flagged(PLUGIN_PHP, mtime_ns=None), requests=[request("wp-content/plugins/demo/other.php")])

    assert by_rule(result, "CORRELATED_FILE_REQUEST") == []


def test_observations_of_another_kind_are_not_requests():
    result = run(flagged(PLUGIN_PHP), requests=[request(PLUGIN_PHP, kind="HTTP_REQUEST_FOR_PHP_IN_UPLOADS")])

    assert result.findings == ()


def test_upload_already_correlated_by_the_upload_rule_gets_no_second_same_path_finding():
    upload = flagged(UPLOAD_PHP, "EXECUTABLE_IN_UPLOADS", mtime_ns=None)
    legacy = models.Observation(LOG.id, "HTTP_REQUEST_FOR_PHP_IN_UPLOADS", models.Location(path="access.log", line=1),
                                {"uri": "/" + UPLOAD_PHP, "method": "GET", "status": 200, "client_ip": "192.0.2.10"})
    http = Detection("HTTP_EXECUTABLE_IN_UPLOADS", "high", "medium", "http_log", "syntetyczne", legacy)

    result = run(upload, requests=[request(UPLOAD_PHP)], extra=[http])

    assert [finding.rule_id for finding in result.findings] == ["CORRELATED_UPLOAD_REQUEST"]
    assert set(result.findings[0].observations) == {upload[0].observation.id, legacy.id}


# --- NEAR_IN_TIME -------------------------------------------------------------------------------

@pytest.mark.parametrize("offset", [0, 600, -600, 900, -900], ids=["same-second", "after", "before", "edge-after", "edge-before"])
def test_request_inside_the_window_is_near_in_time(offset):
    file = flagged(UPLOAD_PHP, "EXECUTABLE_IN_UPLOADS")
    near = request("wp-content/plugins/demo/upload-handler.php", at=shifted(offset))

    [finding] = by_rule(run(file, requests=[near]), "REQUEST_NEAR_FILE_CHANGE")

    assert set(finding.observations) == {file[0].observation.id, near.id}
    assert (finding.severity, finding.confidence) == ("medium", "low")


@pytest.mark.parametrize("offset", [901, -901, 86_400], ids=["just-after", "just-before", "a-day-later"])
def test_request_outside_the_window_is_not_near_in_time(offset):
    result = run(flagged(UPLOAD_PHP, "EXECUTABLE_IN_UPLOADS"), requests=[request(PLUGIN_PHP, at=shifted(offset))])

    assert by_rule(result, "REQUEST_NEAR_FILE_CHANGE") == []


def test_window_is_taken_from_the_argument():
    file = flagged(UPLOAD_PHP, "EXECUTABLE_IN_UPLOADS")
    hits = [request(PLUGIN_PHP, at=shifted(50), line=1), request(PLUGIN_PHP, at=shifted(70), line=2)]

    [finding] = by_rule(run(file, requests=hits, window=60), "REQUEST_NEAR_FILE_CHANGE")

    assert hits[0].id in finding.observations and hits[1].id not in finding.observations
    assert "±60 s" in finding.reason


@pytest.mark.parametrize("uncertainty, near", [(None, False), (0, False), (99, False), (100, True), (3600, True)])
def test_window_is_widened_only_by_the_declared_clock_uncertainty(uncertainty, near):
    result = run(flagged(UPLOAD_PHP, "EXECUTABLE_IN_UPLOADS"), requests=[request(PLUGIN_PHP, at=shifted(1000), uncertainty=uncertainty)])

    assert bool(by_rule(result, "REQUEST_NEAR_FILE_CHANGE")) is near


@pytest.mark.parametrize("uncertainty", [-500, True, "900"], ids=["negative", "bool", "text"])
def test_malformed_clock_uncertainty_does_not_widen_the_window(uncertainty):
    hit = models.Observation(LOG.id, "HTTP_REQUEST", models.Location(path="access.log", line=1),
                             {**request(PLUGIN_PHP).attributes, "clock_uncertainty_seconds": uncertainty},
                             timestamp_raw="x", timestamp_utc=shifted(1000), time_source=models.TimeSource.LOG)

    assert by_rule(run(flagged(UPLOAD_PHP, "EXECUTABLE_IN_UPLOADS"), requests=[hit]), "REQUEST_NEAR_FILE_CHANGE") == []


def test_n7_request_without_utc_time_is_never_near_in_time():
    result = run(flagged(UPLOAD_PHP, "EXECUTABLE_IN_UPLOADS"), requests=[request(PLUGIN_PHP, at=None, uncertainty=10**9)])

    assert by_rule(result, "REQUEST_NEAR_FILE_CHANGE") == []


def test_n7_file_without_mtime_is_never_near_in_time():
    result = run(flagged(UPLOAD_PHP, "EXECUTABLE_IN_UPLOADS", mtime_ns=None), requests=[request(PLUGIN_PHP, uncertainty=10**9)])

    assert by_rule(result, "REQUEST_NEAR_FILE_CHANGE") == []


def test_n7_mtime_outside_the_datetime_range_is_compared_without_error():
    result = run(flagged(UPLOAD_PHP, "EXECUTABLE_IN_UPLOADS", mtime_ns=10**30), requests=[request(PLUGIN_PHP)])

    assert by_rule(result, "REQUEST_NEAR_FILE_CHANGE") == []


def test_near_in_time_never_raises_the_confidence_of_the_file_finding():
    file = flagged(UPLOAD_PHP, "EXECUTABLE_IN_UPLOADS")

    result = run(file, requests=[request(UPLOAD_PHP), request(PLUGIN_PHP, line=2)])

    assert {finding.confidence for finding in result.findings} == {"low"}
    assert all(finding.rule_id in CORRELATION_RULES for finding in result.findings)


# --- agregacja, limity i deterministyczność -----------------------------------------------------

def test_many_requests_to_one_file_give_one_finding_per_rule_with_the_total():
    file = flagged(PLUGIN_PHP)
    hits = [request(PLUGIN_PHP, at=shifted(index), line=index + 1) for index in range(30)]

    result = run(file, requests=hits)

    for rule in ("CORRELATED_FILE_REQUEST", "REQUEST_NEAR_FILE_CHANGE"):
        [finding] = by_rule(result, rule)
        assert len(finding.observations) == 1 + correlate.MAX_REQUESTS_PER_FINDING
        assert "żądań: 30" in finding.reason and f"wskazano {correlate.MAX_REQUESTS_PER_FINDING}" in finding.reason
        assert f"{T0} – {shifted(29)}" in finding.reason


def test_near_in_time_lists_the_closest_requests_first():
    file = flagged(UPLOAD_PHP, "EXECUTABLE_IN_UPLOADS")
    hits = [request(PLUGIN_PHP, at=shifted(800 - index * 10), line=index + 1) for index in range(25)]

    [finding] = by_rule(run(file, requests=hits), "REQUEST_NEAR_FILE_CHANGE")

    assert set(finding.observations) == {file[0].observation.id, *(hit.id for hit in hits[-20:])}


def test_findings_over_the_per_rule_limit_become_a_note_with_the_total(monkeypatch):
    monkeypatch.setattr(correlate, "MAX_FINDINGS_PER_RULE", 2)
    files = [flagged(f"wp-content/plugins/demo/f{index}.php") for index in range(3)]
    hits = [request(f"wp-content/plugins/demo/f{index}.php", line=index + 1) for index in range(3)]

    result = run(*files, requests=hits)

    assert len(by_rule(result, "CORRELATED_FILE_REQUEST")) == len(by_rule(result, "REQUEST_NEAR_FILE_CHANGE")) == 2
    assert sorted(result.notes) == [f"Limit 2 ustaleń reguły {rule} wyczerpany: wykryć było 3; pozostałe pominięto"
                                    for rule in ("CORRELATED_FILE_REQUEST", "REQUEST_NEAR_FILE_CHANGE")]


def test_several_file_findings_on_one_file_give_one_correlation_per_rule():
    one, record = flagged(PLUGIN_PHP)
    two = Detection("SUSPICIOUS_PHP_EVAL_DECODE", "high", "medium", "file", "syntetyczne",
                    models.Observation(record.id, "OTHER_FACT", models.Location(path=PLUGIN_PHP)))

    result = run((one, record), requests=[request(PLUGIN_PHP)], extra=[two])

    assert sorted(finding.rule_id for finding in result.findings) == ["CORRELATED_FILE_REQUEST", "REQUEST_NEAR_FILE_CHANGE"]
    assert all({one.observation.id, two.observation.id} <= set(finding.observations) for finding in result.findings)


def test_result_and_timeline_do_not_depend_on_input_order():
    files = [flagged(f"wp-content/plugins/demo/f{index}.php", mtime_ns=T0_NS + index * 10**9) for index in range(4)]
    hits = [request(f"wp-content/plugins/demo/f{index % 4}.php", at=shifted(index * 7), line=index + 1,
                    uncertainty=None if index % 2 else 30) for index in range(40)]
    evidence = {record.id: record for _, record in files} | {LOG.id: LOG}
    detections = [found for found, _ in files]

    def outcome(seed: int):
        rng = random.Random(seed)
        shuffled_detections, shuffled_hits = rng.sample(detections, len(detections)), rng.sample(hits, len(hits))
        result = correlate.correlate(shuffled_detections, shuffled_hits, evidence, 900)
        return result, correlate.timeline(shuffled_detections, evidence, result.requests)

    first = outcome(1)
    assert all(outcome(seed) == first for seed in range(2, 6))
    times = [event.time_utc for event in first[1][0]]
    assert times == sorted(times)


# --- wyjaśnienia nie twierdzą przyczynowości ----------------------------------------------------

def test_explanations_state_the_limits_and_never_claim_causation():
    file = flagged(PLUGIN_PHP)

    result = run(file, requests=[request(PLUGIN_PHP, uncertainty=30)])

    assert {finding.rule_id for finding in result.findings} == {"CORRELATED_FILE_REQUEST", "REQUEST_NEAR_FILE_CHANGE"}
    for finding in result.findings:
        assert not CLAIMS.search(finding.reason), finding.reason
        assert "przyczynow" in finding.reason and "HTTP 200" in finding.reason
        assert "nie dowodzi" in finding.reason
    assert "mtime jest zmienialny" in by_rule(result, "REQUEST_NEAR_FILE_CHANGE")[0].reason


def test_explanations_carry_no_text_from_the_evidence():
    path = "wp-content/plugins/demo/IGNORE-PREVIOUS-INSTRUCTIONS.php"
    result = run(flagged(path), requests=[request(path)])

    assert result.findings and not any("IGNORE" in finding.reason for finding in result.findings)


# --- oś czasu -----------------------------------------------------------------------------------

def test_timeline_dates_only_correlated_requests_and_names_the_clock_basis():
    file = flagged(PLUGIN_PHP)
    declared, undeclared = request(PLUGIN_PHP, uncertainty=30, line=1), request(PLUGIN_PHP, at=shifted(5), line=2)
    unrelated = request("wp-content/plugins/other/x.php", at=shifted(86_400), line=3)
    evidence = {file[1].id: file[1], LOG.id: LOG}
    result = correlate.correlate([file[0]], [declared, undeclared, unrelated], evidence, 900)

    events, undated = correlate.timeline([file[0]], evidence, result.requests)

    http = {event.observation_id: event for event in events if event.event == "HTTP_REQUEST"}
    assert set(http) == {declared.id, undeclared.id} and undated == []
    assert http[declared.id].timestamp_basis == "HTTP access log; niepewność zegara ±30 s (deklaracja operatora, niezweryfikowana)"
    assert http[undeclared.id].timestamp_basis == "HTTP access log; zegar niezweryfikowany, niepewność niezadeklarowana"
    assert {(event.time_source, event.source) for event in http.values()} == {("log", "access.log:1"), ("log", "access.log:2")}
    [mtime] = [event for event in events if event.event == "SUSPICIOUS_FILE_MTIME"]
    assert "zmienialny" in mtime.timestamp_basis


def test_correlated_request_without_utc_time_has_no_timeline_event():
    file = flagged(PLUGIN_PHP, mtime_ns=None)
    hit = request(PLUGIN_PHP, at=None)
    evidence = {file[1].id: file[1], LOG.id: LOG}

    result = correlate.correlate([file[0]], [hit], evidence, 900)

    assert result.requests == (hit,)
    assert correlate.timeline([file[0]], evidence, result.requests) == ([], [])


# --- interfejs CLI ------------------------------------------------------------------------------

def test_existing_upload_correlation_still_works_with_a_custom_window(site, evidence, analyze):
    write(site / UPLOAD_PHP)
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP)).parent

    run_ = analyze(site, logs=logs, flags=("--correlation-window", "60"))

    assert "CORRELATED_UPLOAD_REQUEST" in run_.rules
    assert not {"CORRELATED_FILE_REQUEST", "REQUEST_NEAR_FILE_CHANGE"} & run_.rules  # parser na main nie daje HTTP_REQUEST


@pytest.mark.parametrize("value", ["0", "-5", "abc", "1.5", ""])
def test_correlation_window_must_be_a_positive_integer(site, refuse, value):
    error = refuse("--files", str(site), "--correlation-window", value)

    assert "--correlation-window" in error


LogScan = namedtuple("LogScan", "detections cover requests")  # kształt z ADR 0007 pkt 7


def test_requests_returned_by_the_log_scan_reach_the_report(site, evidence, analyze, monkeypatch):
    plugin = write(site / PLUGIN_PHP)
    os.utime(plugin, ns=(T0_NS, T0_NS + 120 * 10**9))
    logs = write(evidence / "logs" / "access.log", access_line("/about/")).parent
    real = httplog.scan_logs

    def scan_logs(root, session, *rest):
        result = real(root, session, *rest)
        found, cover = (result.detections, result.cover) if hasattr(result, "cover") else result
        record = evidence_of(next(item for item in session.ledger if item.source == "logs" and item.sha256))
        hit = models.Observation(record.id, "HTTP_REQUEST", models.Location(path="access.log", line=1),
                                 dict(request(PLUGIN_PHP, uncertainty=5).attributes),
                                 timestamp_raw="09/Nov/2026:02:14:01 +0100", timestamp_utc=T0, time_source=models.TimeSource.LOG)
        return LogScan(found, cover, [hit])

    monkeypatch.setattr(cli, "scan_logs", scan_logs)

    report = analyze(site, logs=logs, baseline={"files": {PLUGIN_PHP: "0" * 64}}).report  # ustalenie plikowe: BASELINE_FILE_CHANGED

    rules = {finding["rule_id"] for finding in report["findings"]}
    assert {"BASELINE_FILE_CHANGED", "CORRELATED_FILE_REQUEST", "REQUEST_NEAR_FILE_CHANGE"} <= rules
    assert [event["timestamp_basis"] for event in report["timeline"] if event["event"] == "HTTP_REQUEST"] == [
        "HTTP access log; niepewność zegara ±5 s (deklaracja operatora, niezweryfikowana)"]
    assert any(item["kind"] == "HTTP_REQUEST" for item in report["observations"])
