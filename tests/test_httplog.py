"""Analiza logów HTTP (ADR 0007 pkt 2–7): strumieniowy podział na wiersze, pokrycie per plik, reguła, opcje operatora."""
import ipaddress
import json
import random

import pytest
from conftest import CANARY, UPLOAD_PHP, access_line, time_limit, write

from wpincidentlens import httplog, ingest
from wpincidentlens.httplog import LogConfig, LogFileParser

RULE = "HTTP_EXECUTABLE_IN_UPLOADS"

# Każdy wynik podziału: wiersz sparsowany (z żądaniem do kodu i bez), każdy powód odrzucenia, pusty, \r\n, spoza UTF-8,
# za długi, ostatni bez znaku końca wiersza.
MIXED = (
    access_line("/" + UPLOAD_PHP).encode()
    + access_line("/about/").replace("\n", "\r\n").encode()
    + b"   \t\n"
    + b"garbage line\n"
    + access_line("/a b").encode()
    + access_line("/", ip="bad_host!").encode()
    + access_line("/", status=999).encode()
    + access_line("/wp-content/uploads/BYTE.php").encode().replace(b"BYTE", b"\xff\xfe")
    + b"x" * 200 + b"\n"
    + access_line("/../../etc/passwd").encode()
    + access_line("/wp-content/plugins/demo/demo.php", when="09/Nov/2026:02:14:01").rstrip("\n").encode()
)


def summary(chunks, max_line=150, **config):
    parser = LogFileParser(LogConfig(**config), max_line=max_line)
    for chunk in chunks:
        parser.feed(chunk)
    parser.close()
    held = [(item.line, item.path, item.client_ip, item.basis) for item in parser.held]
    return (parser.lines, parser.parsed, dict(parser.rejected), parser.first_rejected, parser.lossy, parser.first_lossy,
            parser.untimed, parser.unresolved, held)


def test_mixed_file_is_counted_line_by_line():
    lines, parsed, rejected, first, lossy, first_lossy, untimed, unresolved, held = summary([MIXED])

    assert (lines, parsed) == (10, 5)
    assert rejected == {"layout": 1, "request_line": 1, "bad_client": 1, "bad_number": 1, "too_long": 1}
    assert first == {"layout": 4, "request_line": 5, "bad_client": 6, "bad_number": 7, "too_long": 9}
    assert (lossy, first_lossy, untimed, unresolved) == (1, 8, 1, 1)
    assert held == [(1, UPLOAD_PHP, "192.0.2.10", "connection"), (8, "wp-content/uploads/��.php", "192.0.2.10", "connection"),
                    (11, "wp-content/plugins/demo/demo.php", "192.0.2.10", "connection")]


def test_result_does_not_depend_on_where_the_chunks_are_split():
    whole = summary([MIXED])

    for cut in range(len(MIXED) + 1):
        assert summary([MIXED[:cut], MIXED[cut:]]) == whole, cut


def test_byte_by_byte_feeding_gives_the_same_result():
    assert summary([MIXED[i:i + 1] for i in range(len(MIXED))]) == summary([MIXED])


def test_line_over_the_limit_is_skipped_to_the_next_newline_with_a_bounded_buffer():
    parser = LogFileParser(max_line=100)
    parser.feed(access_line("/").encode() + b"x" * 50)
    for _ in range(100):
        parser.feed(b"y" * 50)
        assert len(parser._buf) <= 100
    parser.feed(b"\n" + access_line("/").encode() + b"z" * 150)
    parser.close()

    assert (parser.lines, parser.parsed, dict(parser.rejected), parser.first_rejected) == (4, 2, {"too_long": 2}, {"too_long": 2})


def test_line_exactly_at_the_limit_is_accepted():
    line = access_line("/").encode()

    assert summary([line], max_line=len(line) - 1)[:2] == (1, 1)
    assert summary([line], max_line=len(line) - 2)[2] == {"too_long": 1}


def test_default_line_limit_is_64_kib():
    assert httplog.MAX_LINE_BYTES == 64 * 1024


def test_seeded_mutation_fuzz_never_crashes_and_keeps_counters_consistent():
    """S-08: deterministyczne mutacje poprawnego pliku (bajty, wycięcia, powtórzenia); ziarno stałe."""
    rng = random.Random(4013)
    with time_limit(20):
        for _ in range(1500):
            data = bytearray(MIXED)
            for _ in range(rng.randint(1, 8)):
                at = rng.randrange(len(data))
                operation = rng.randrange(3)
                if operation == 0:
                    data[at] = rng.randrange(256)
                elif operation == 1:
                    del data[at:at + rng.randint(1, 40)]
                else:
                    data[at:at] = data[at:at + rng.randint(1, 40)] * rng.randint(1, 4)
            for fmt in httplog.FORMATS:
                lines, parsed, rejected, *_ = summary([bytes(data)], max_line=400, fmt=fmt)
                assert lines == parsed + sum(rejected.values())


def test_requests_over_the_budget_are_counted_not_held():
    parser = LogFileParser(budget=httplog._Budget(left=2))
    parser.feed(access_line("/" + UPLOAD_PHP).encode() * 5)
    parser.close()

    assert (len(parser.held), parser.budget.dropped) == (2, 3)


def test_clock_uncertainty_is_whole_seconds_rounded_up():
    assert [LogConfig(clock_skew=value).uncertainty for value in (None, 0, 2.0, 2.1)] == [None, 0, 2, 3]


def test_unknown_format_is_refused():
    with pytest.raises(ValueError):
        LogConfig(fmt="w3c")


# --- scan_logs: interfejs dla korelacji (pkt 7) ---------------------------------------------------

def test_scan_logs_returns_http_request_observations_only_for_code_paths(evidence):
    logs = write(evidence / "logs" / "access.log", access_line("/") + access_line("/style.css") + access_line("/index.php?p=1")
                 + access_line("/" + UPLOAD_PHP, method="POST", status=404))

    scan = httplog.scan_logs(logs.parent, ingest.Session(), LogConfig(clock_skew=1.5))

    assert [(item.kind, item.location.line, item.attributes["path"]) for item in scan.requests] == [
        ("HTTP_REQUEST", 3, "index.php"), ("HTTP_REQUEST", 4, UPLOAD_PHP)]
    assert dict(scan.requests[0].attributes) == {
        "path": "index.php", "uri": "/index.php?[usunięto]", "method": "GET", "status": 200, "bytes": 75,
        "client_ip": "192.0.2.10", "client_ip_basis": "connection", "log_format": "combined@1", "timestamp_precision": "second",
        "clock_uncertainty_seconds": 2}
    assert [found.rule for found in scan.detections] == [RULE]
    assert scan.detections[0].observation.attributes == scan.requests[1].attributes
    assert scan.cover.reasons == [] and not (scan.cover.partial or scan.cover.failed)


def test_log_given_as_a_single_file_is_streamed_too(evidence):
    log = write(evidence / "access.log", access_line("/" + UPLOAD_PHP))

    scan = httplog.scan_logs(log, ingest.Session())

    assert [found.observation.location.path for found in scan.detections] == ["access.log"]


def test_skipped_file_contributes_no_lines(evidence):
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP)).parent
    write(logs / "big.log", access_line("/" + UPLOAD_PHP) * 10)

    scan = httplog.scan_logs(logs, ingest.Session(ingest.Limits(max_file_bytes=200)))

    assert [found.observation.location.path for found in scan.detections] == ["access.log"]
    assert any("big.log" in reason for reason in scan.cover.reasons)


def test_request_observations_do_not_enter_the_report_by_themselves(site, evidence, analyze):
    logs = write(evidence / "logs" / "access.log", access_line("/index.php")).parent

    run = analyze(site, logs=logs)

    assert run.report["observations"] == [] and run.findings == []


# --- reguła HTTP_EXECUTABLE_IN_UPLOADS: wariant pozytywny i negatywny dla każdego przypadku ------------

@pytest.mark.parametrize("target, path, confidence", [
    ("/" + UPLOAD_PHP, UPLOAD_PHP, "medium"),
    ("/wp-content/uploads/2026/11/shell.php5", "wp-content/uploads/2026/11/shell.php5", "medium"),
    ("/wp-content/uploads/2026/11/shell.PHTML", "wp-content/uploads/2026/11/shell.PHTML", "medium"),
    ("/wp-content/uploads/2026/11/shell.php.jpg", "wp-content/uploads/2026/11/shell.php.jpg", "low"),
    ("/wp-content/uploads/2026/11/x/%2e%2e/shell.php", "wp-content/uploads/2026/11/shell.php", "medium"),
    ("/wp-content/uploads/2026/11/shell%2ephp", "wp-content/uploads/2026/11/shell.php", "medium"),
    ("//wp-content//uploads/2026/11/shell.php?cmd=id", "wp-content/uploads/2026/11/shell.php", "medium"),
], ids=["php", "php5", "uppercase-phtml", "double-extension", "encoded-dot-dot", "encoded-dot", "slashes-and-query"])
def test_request_for_code_in_uploads_is_flagged_after_normalisation(site, evidence, analyze, target, path, confidence):
    logs = write(evidence / "logs" / "access.log", access_line(target, method="HEAD")).parent

    finding = analyze(site, logs=logs).finding(RULE)

    assert (finding["metadata"]["path"], finding["confidence"], finding["severity"]) == (path, confidence, "high")
    assert "brak dowodu wykonania kodu" in finding["explanation"]


@pytest.mark.parametrize("target", [
    "/wp-content/plugins/demo/demo.php",
    "/wp-content/uploads/2026/11/photo.jpg",
    "/wp-content/uploads/2026/11/photo.jpg.bak",
    "/index.php?file=wp-content/uploads/2026/11/shell.php",
    "/wp-content/uploads/../../wp-content/uploads/x/%2e%2e/%2e%2e/%2e%2e/%2e%2e/shell.php",
    "/wp-content/uploads%00/shell.php",
    "/wp-content/uploadsX/shell.php",
], ids=["code-outside-uploads", "image-in-uploads", "non-code-double-extension", "code-only-in-query", "dot-dot-above-root",
        "encoded-nul", "similar-directory"])
def test_request_that_is_not_for_code_in_uploads_is_not_flagged(site, evidence, analyze, target):
    logs = write(evidence / "logs" / "access.log", access_line(target)).parent

    assert RULE not in analyze(site, logs=logs).rules


def test_request_with_path_above_root_is_a_note(site, evidence, analyze):
    logs = write(evidence / "logs" / "access.log", access_line("/%2e%2e/%2e%2e/etc/passwd")).parent

    run = analyze(site, logs=logs)

    assert run.has_gap("1 żądań ma ścieżkę, której nie da się przypisać do pliku")
    assert run.coverage("logs")["status"] == "ANALYZED"


def test_token_in_query_is_redacted_in_the_uri_and_absent_from_the_path(site, evidence, analyze):
    logs = write(evidence / "logs" / "access.log", access_line(f"/{UPLOAD_PHP}?token={CANARY}&page=2")).parent

    run = analyze(site, logs=logs)

    assert run.finding(RULE)["metadata"]["uri"] == f"/{UPLOAD_PHP}?[usunięto]"
    assert CANARY not in run.everything


def test_client_ip_from_json_log_through_trusted_proxy(site, evidence, analyze):
    record = {"time": "2026-11-09T01:14:01Z", "remote_addr": "10.0.0.5", "method": "POST", "uri": "/" + UPLOAD_PHP,
              "status": 200, "bytes": None, "forwarded_for": "198.51.100.9, 203.0.113.7, 10.1.1.1"}
    logs = write(evidence / "logs" / "access.json", json.dumps(record) + "\n").parent

    run = analyze(site, logs=logs, flags=("--log-format", "json", "--trusted-proxy", "10.0.0.0/8"))
    facts = run.finding(RULE)["metadata"]

    assert (facts["client_ip"], facts["client_ip_basis"], facts["log_format"], facts["bytes"]) == (
        "203.0.113.7", "forwarded_for_via_trusted_proxy", "json@1", None)
    assert "198.51.100.9" not in run.everything


def test_forwarded_for_from_an_untrusted_connection_is_ignored(site, evidence, analyze):
    record = {"time": "2026-11-09T01:14:01Z", "remote_addr": "192.0.2.10", "method": "GET", "uri": "/" + UPLOAD_PHP,
              "status": 200, "forwarded_for": "203.0.113.77"}
    logs = write(evidence / "logs" / "access.json", json.dumps(record) + "\n").parent

    run = analyze(site, logs=logs, flags=("--log-format", "json", "--trusted-proxy", "10.0.0.0/8"))

    assert (run.finding(RULE)["metadata"]["client_ip"], run.finding(RULE)["metadata"]["client_ip_basis"]) == ("192.0.2.10", "connection")
    assert "203.0.113.77" not in run.everything


def test_malformed_forwarded_for_through_trusted_proxy_is_a_note(site, evidence, analyze):
    record = {"time": "2026-11-09T01:14:01Z", "remote_addr": "10.0.0.5", "method": "GET", "uri": "/" + UPLOAD_PHP,
              "status": 200, "forwarded_for": "203.0.113.7, not-an-ip"}
    logs = write(evidence / "logs" / "access.json", json.dumps(record) + "\n").parent

    run = analyze(site, logs=logs, flags=("--log-format", "json", "--trusted-proxy", "10.0.0.0/8"))

    assert run.finding(RULE)["metadata"]["client_ip"] == "10.0.0.5"
    assert run.has_gap("niepoprawny wpis w forwarded_for")


# --- opcje operatora i case.json ------------------------------------------------------------------

def test_log_options_reach_the_observation_and_case_json(site, evidence, analyze):
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP)).parent

    run = analyze(site, logs=logs, flags=("--log-format", "common", "--trusted-proxy", "10.0.0.1/8", "--trusted-proxy",
                                          "2001:db8::/32", "--trusted-proxy", "10.0.0.0/8", "--log-clock-skew", "30"))

    assert (run.finding(RULE)["metadata"]["log_format"], run.finding(RULE)["metadata"]["clock_uncertainty_seconds"]) == ("common@1", 30)
    assert run.case["sources"]["logs"] == {"provided": True, "name": "logs", "format": "common",
                                           "trusted_proxies": ["10.0.0.0/8", "2001:db8::/32"], "clock_skew_seconds": 30.0}


def test_without_clock_skew_the_uncertainty_is_null(site, evidence, analyze):
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP)).parent

    assert analyze(site, logs=logs).finding(RULE)["metadata"]["clock_uncertainty_seconds"] is None


@pytest.mark.parametrize("flags, message", [
    (("--trusted-proxy", "10.0.0.0/33"), "--trusted-proxy"),
    (("--trusted-proxy", "proxy.example.invalid"), "--trusted-proxy"),
    (("--trusted-proxy", ""), "--trusted-proxy"),
    (("--log-clock-skew", "-1"), "--log-clock-skew"),
    (("--log-clock-skew", "nan"), "--log-clock-skew"),
    (("--log-clock-skew", "inf"), "--log-clock-skew"),
    (("--log-format", "w3c"), "--log-format"),
], ids=["prefix-too-long", "hostname", "empty", "negative-skew", "nan-skew", "infinite-skew", "unknown-format"])
def test_invalid_log_option_is_a_usage_error(site, refuse, flags, message):
    assert message in refuse("--files", str(site), *flags)


def test_too_many_trusted_proxies_is_a_usage_error(site, refuse):
    flags = [part for n in range(65) for part in ("--trusted-proxy", f"10.{n}.0.0/16")]

    assert "--trusted-proxy" in refuse("--files", str(site), *flags)


def test_networks_parse_back_from_the_case_context(site, tmp_path):
    from wpincidentlens import case

    context = case.build(files=site, output=tmp_path / "out", case_id="T401", trusted_proxies=["10.0.0.1/8"])

    assert context.proxy_networks() == (ipaddress.ip_network("10.0.0.0/8"),)


# --- pokrycie -------------------------------------------------------------------------------------

def test_empty_log_directory_is_failed_with_a_gap(site, evidence, analyze):
    (evidence / "logs").mkdir()

    run = analyze(site, logs=evidence / "logs")

    assert run.coverage("logs")["status"] == "FAILED"
    assert run.has_gap("Źródło logów nie zawiera żadnego odczytanego pliku")


def test_log_directory_with_only_a_symlink_is_failed(site, evidence, analyze):
    logs = evidence / "logs"
    logs.mkdir()
    (logs / "access.log").symlink_to(write(evidence / "elsewhere.log", access_line("/" + UPLOAD_PHP)))

    run = analyze(site, logs=logs)

    assert run.coverage("logs")["status"] == "FAILED" and RULE not in run.rules


def test_lines_in_another_format_fail_the_source(site, evidence, analyze):
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP)).parent

    run = analyze(site, logs=logs, flags=("--log-format", "json"))

    assert run.coverage("logs")["status"] == "FAILED"
    assert run.has_gap("Logi nie odpowiadają obsługiwanemu formatowi json@1")


def test_unparsed_share_and_files_are_named_in_the_gap(site, evidence, analyze):
    logs = write(evidence / "logs" / "a.log", access_line("/") * 3 + "garbage\n").parent
    write(logs / "b.log", access_line("/"))
    write(logs / "c.log", "only garbage\n")

    run = analyze(site, logs=logs)

    assert run.coverage("logs")["status"] == "PARTIAL"
    assert run.has_gap("Nie sparsowano 2/6 wierszy logów (33.3%, format combined@1): układ pól inny niż w wybranym formacie ×2 "
                       "(pierwszy: a.log:4); pliki: a.log (1/4), c.log (1/1)")
    assert run.has_gap("1 plików logów bez żadnego wiersza w formacie combined@1: c.log")


def test_lossy_lines_are_counted_and_still_analysed(site, evidence, analyze):
    logs = write(evidence / "logs" / "access.log",
                 access_line("/").encode() + access_line("/wp-content/uploads/a-BYTE.php").encode().replace(b"BYTE", b"\xff")).parent

    run = analyze(site, logs=logs)

    assert RULE in run.rules
    assert run.has_gap("1 wierszy logów nie jest poprawnym UTF-8") and run.has_gap("(pierwszy: access.log:2)")
    assert run.coverage("logs")["status"] == "PARTIAL"


def test_request_limit_is_a_gap(site, evidence, analyze, monkeypatch):
    monkeypatch.setattr(httplog, "MAX_REQUESTS", 2)
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP) * 3).parent

    run = analyze(site, logs=logs)

    assert len([item for item in run.findings if item["rule"] == RULE]) == 2
    assert run.has_gap("Limit 2 żądań do plików kodu przekroczony: pominięto 1")
