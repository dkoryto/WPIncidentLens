"""Analiza logów HTTP (ADR 0007 pkt 2–7): strumieniowy podział na wiersze, pokrycie per plik, reguła, opcje operatora."""
import ipaddress
import itertools
import json
import random
import re
import time

import pytest
from conftest import CANARY, UPLOAD_PHP, access_line, time_limit, write

from wpincidentlens import cli, correlate, httplog, ingest
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


def test_held_request_keeps_only_the_bounded_fields_not_the_whole_target():
    """Pamięć trzymanych żądań: cel 60 KiB zostaje jako ``uri`` po redakcji (≤ 300 znaków), bez pełnego rekordu."""
    parser = LogFileParser(max_line=httplog.MAX_LINE_BYTES)
    parser.feed(access_line("/" + UPLOAD_PHP + "?" + "a" * 60_000).encode())
    parser.close()

    held = parser.held[0]
    assert len(held.uri) <= httplog.MAX_URI_CHARS and held.path == UPLOAD_PHP
    assert not any(isinstance(value, str) and len(value) > httplog.MAX_URI_CHARS for value in vars(held).values())


def test_requests_over_the_character_budget_are_counted_not_held():
    line = access_line("/wp-content/uploads/" + "d" * 300 + ".php").encode()
    parser = LogFileParser(budget=httplog._Budget(chars=700), max_line=1000)
    parser.feed(line * 3)
    parser.close()

    assert (len(parser.held), parser.budget.dropped) == (1, 2)
    assert parser.budget.chars == 700 - httplog._cost(parser.held[0])


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
    ("/wp-content/uploads/2026/11/x.php/foo", "wp-content/uploads/2026/11/x.php", "medium"),
    ("/wp-content/uploads/2026/11/x.php/a.jpg/b", "wp-content/uploads/2026/11/x.php", "medium"),
    ("/wp-content/uploads/2026/11/X.PHP", "wp-content/uploads/2026/11/X.PHP", "medium"),
    ("/WP-CONTENT/UPLOADS/a.php", "WP-CONTENT/UPLOADS/a.php", "medium"),
    ("/Wp-Content/Uploads/x.php.jpg/y", "Wp-Content/Uploads/x.php.jpg", "low"),
], ids=["php", "php5", "uppercase-phtml", "double-extension", "encoded-dot-dot", "encoded-dot", "slashes-and-query",
        "path-info", "path-info-with-image", "uppercase-name", "uppercase-uploads-prefix", "double-extension-with-path-info"])
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
    "/wp-content/uploads/2026/11/photo.jpg/x.txt",
    "/index.php/wp-content/uploads/2026/11/shell.php",
], ids=["code-outside-uploads", "image-in-uploads", "non-code-double-extension", "code-only-in-query", "dot-dot-above-root",
        "encoded-nul", "similar-directory", "path-info-without-code", "uploads-only-in-path-info"])
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


@pytest.mark.parametrize("target", [
    f"/{UPLOAD_PHP}?x=\"&token={CANARY}", f"/{UPLOAD_PHP}?x='{CANARY}", f"/{UPLOAD_PHP}?x=<{CANARY}",
    f"/{UPLOAD_PHP}?x=\\{CANARY}", f"/{UPLOAD_PHP}#{CANARY}", f"/{UPLOAD_PHP}#a?{CANARY}",
], ids=["after-double-quote", "after-apostrophe", "after-less-than", "after-backslash", "fragment", "query-in-fragment"])
def test_secret_after_a_character_that_stops_the_query_pattern_never_reaches_the_report(site, evidence, analyze, target):
    record = {"time": "2026-11-09T01:14:01Z", "remote_addr": "192.0.2.10", "method": "GET", "uri": target, "status": 200}
    logs = write(evidence / "logs" / "access.json", json.dumps(record) + "\n").parent

    run = analyze(site, logs=logs, flags=("--log-format", "json"))

    assert run.finding(RULE)["metadata"]["uri"] == f"/{UPLOAD_PHP}{target[len(UPLOAD_PHP) + 1]}[usunięto]"
    assert CANARY not in run.everything


@pytest.mark.parametrize("target, uri", [
    ("/a.php", "/a.php"), ("/a.php?", "/a.php?[usunięto]"), ("/a.php#", "/a.php#[usunięto]"),
    ("/" + "0123456789abcdef" * 2 + ".php", "/[usunięto].php"), ("/" + "z" * 400 + ".php?x", "/" + "z" * 287 + "…?[usunięto]"),
], ids=["plain", "empty-query", "empty-fragment", "hex-run-in-path", "long-path"])
def test_redacted_uri_cuts_query_and_fragment_before_redaction(target, uri):
    assert httplog.redacted_uri(target) == uri
    assert len(httplog.redacted_uri(target)) <= httplog.MAX_URI_CHARS


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

    facts = run.finding(RULE)["metadata"]
    assert (facts["client_ip"], facts["client_ip_basis"]) == ("10.0.0.5", "connection_forwarded_for_rejected")
    assert run.has_gap("1 żądań przez zaufane proxy ma odrzucone forwarded_for")


def test_overlong_forwarded_for_with_a_forged_address_on_the_right_is_rejected(site, evidence, analyze):
    padding = ", ".join(["198.51.100.1"] * 200)
    record = {"time": "2026-11-09T01:14:01Z", "remote_addr": "10.0.0.5", "method": "GET", "uri": "/" + UPLOAD_PHP,
              "status": 200, "forwarded_for": padding + ", 203.0.113.66"}
    logs = write(evidence / "logs" / "access.json", json.dumps(record) + "\n").parent

    run = analyze(site, logs=logs, flags=("--log-format", "json", "--trusted-proxy", "10.0.0.0/8"))

    facts = run.finding(RULE)["metadata"]
    assert (facts["client_ip"], facts["client_ip_basis"]) == ("10.0.0.5", "connection_forwarded_for_rejected")
    assert "203.0.113.66" not in run.everything and run.has_gap("odrzucone forwarded_for")


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
    (("--trusted-proxy", "0.0.0.0/0"), "szersza niż /8"),
    (("--trusted-proxy", "10.0.0.0/7"), "szersza niż /8"),
    (("--trusted-proxy", "::/0"), "/32 (IPv6)"),
    (("--trusted-proxy", "2001:db8::/31"), "/32 (IPv6)"),
    (("--log-clock-skew", "-1"), "--log-clock-skew"),
    (("--log-clock-skew", "nan"), "--log-clock-skew"),
    (("--log-clock-skew", "inf"), "--log-clock-skew"),
    (("--log-format", "w3c"), "--log-format"),
], ids=["prefix-too-long", "hostname", "empty", "ipv4-everything", "ipv4-wider-than-8", "ipv6-everything", "ipv6-wider-than-32",
        "negative-skew", "nan-skew", "infinite-skew", "unknown-format"])
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
    """Limit puli korelacji dotyczy tylko korelacji: reguła uploads ma własny limit (przegląd M4, pkt 2)."""
    monkeypatch.setattr(httplog, "MAX_REQUESTS", 2)
    write(site / UPLOAD_PHP)  # ustalenie plikowe: żądania do tej ścieżki są materiałem korelacji
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP) * 3).parent

    run = analyze(site, logs=logs)

    assert len([item for item in run.findings if item["rule"] == RULE]) == 3
    assert run.has_gap("Limit 2 żądań do plików kodu albo")
    assert run.has_gap("przekroczony: pominięto 1; nie sprawdzono ich korelacją")


# --- poprawki po przeglądzie bezpieczeństwa M4 ----------------------------------------------------

DEEP = "/" + "a/" * 2040 + "x.php"  # ~4 KiB ścieżki z krótkich segmentów


def test_s08_script_path_is_linear_in_the_number_of_segments():
    """Przegląd M4, pkt 1: dawniej każdy ``/`` budował i sprawdzał cały prefiks (≈ 90 ms na wiersz)."""
    path = DEEP.lstrip("/")
    with time_limit(2):
        started = time.perf_counter()
        for _ in range(200):
            assert httplog._script_path(path) == path
        assert (time.perf_counter() - started) / 200 < 0.005


def test_s08_log_of_deep_paths_is_parsed_in_bounded_time():
    parser = LogFileParser()
    data = access_line(DEEP, status=404).encode() * 500

    with time_limit(5):
        parser.feed(data)
        parser.close()

    assert (parser.parsed, len(parser.held)) == (500, 500)


@pytest.mark.parametrize("path, script", [
    ("a/b.php/c/d.php", "a/b.php"), ("wp-content/uploads/x.php.jpg/y.php", "wp-content/uploads/x.php.jpg"),
    ("wp-content/x.php.jpg/y.php", "wp-content/x.php.jpg/y.php"), ("wp-content/uploads.php.jpg/a", None),
    (".php/a", None), ("a/x.php.", None), ("WP-CONTENT/UPLOADS/A.PHP.GIF", "WP-CONTENT/UPLOADS/A.PHP.GIF"), ("", None),
], ids=["first-code-segment", "double-extension-in-uploads", "double-extension-outside-uploads", "uploads-segment-itself",
        "hidden-name", "trailing-dot", "uppercase", "root"])
def test_script_path_decides_per_segment_like_the_file_rules(path, script):
    assert httplog._script_path(path) == script


def test_file_rule_name_helpers_agree_with_purepath_on_random_names():
    from pathlib import PurePosixPath

    from wpincidentlens import filerules
    rng = random.Random(4011)
    for _ in range(3000):
        name = "".join(rng.choice("aP.hpi3nc") for _ in range(rng.randint(1, 9)))
        if name in (".", ".."):
            continue
        assert filerules.is_code_name(name) == (PurePosixPath(name).suffix.lower() in filerules.CODE_SUFFIXES), name


def _clock_session(max_seconds: float) -> ingest.Session:
    """Zegar sesji przesuwa się o 1 s przy każdym odczycie: limit mija po ustalonej liczbie sprawdzeń."""
    return ingest.Session(ingest.Limits(max_seconds=max_seconds), clock=itertools.count().__next__)


def test_time_limit_stops_parsing_inside_a_file_with_a_gap_naming_the_line(evidence, monkeypatch):
    monkeypatch.setattr(httplog, "CLOCK_EVERY_LINES", 2)
    lines = [access_line("/" + UPLOAD_PHP)] + [access_line("/about/")] * 30 + [access_line("/wp-content/uploads/late.php")]
    log = write(evidence / "logs" / "access.log", "".join(lines))
    session = _clock_session(6)

    scan = httplog.scan_logs(log.parent, session)

    [gap] = [reason for reason in scan.cover.reasons if "Limit czasu analizy" in reason]
    reached = int(re.search(r"access\.log przeanalizowany do wiersza (\d+)", gap)[1])
    assert 1 <= reached < len(lines)
    assert [found.observation.location.line for found in scan.detections] == [1]
    [record] = [item for item in session.ledger if item.source == "logs"]
    assert (record.status, record.size) == (ingest.ReadStatus.READ, log.stat().st_size)  # skrót obejmuje cały plik
    assert cli._coverage("logs", scan.cover, session.ledger).status == "PARTIAL"


def test_without_a_time_limit_hit_the_whole_file_is_parsed(evidence):
    log = write(evidence / "logs" / "access.log", access_line("/about/") * 600 + access_line("/" + UPLOAD_PHP))

    scan = httplog.scan_logs(log.parent, ingest.Session())

    assert [found.observation.location.line for found in scan.detections] == [601]
    assert not any("Limit czasu" in reason for reason in scan.cover.reasons)


def test_flood_of_code_requests_does_not_suppress_the_uploads_rule():
    """Przegląd M4, pkt 2: wyczerpana pula korelacji (404, wp-login.php) nie wyłącza reguły uploads."""
    budget = httplog._Budget(left=3)
    parser = LogFileParser(budget=budget)
    parser.feed(access_line("/wp-login.php", status=404).encode() * 10 + access_line("/" + UPLOAD_PHP).encode())
    parser.close()

    assert budget.dropped == 8
    assert [held.path for held, _ in parser.hits] == [UPLOAD_PHP]


def test_flood_end_to_end_keeps_the_rule_finding(site, evidence, analyze, monkeypatch):
    monkeypatch.setattr(httplog, "MAX_REQUESTS", 2)
    flood = access_line("/xmlrpc.php", method="POST") * 20
    logs = write(evidence / "logs" / "access.log", flood + access_line("/" + UPLOAD_PHP)).parent

    run = analyze(site, logs=logs)

    assert run.finding(RULE)["metadata"]["path"] == UPLOAD_PHP
    assert not run.has_gap("żądań do plików kodu albo")  # bez ustaleń plikowych korelacja nie trzyma żadnego żądania


def test_rule_findings_over_their_limit_become_a_gap_with_the_total(evidence, monkeypatch):
    monkeypatch.setattr(httplog, "MAX_RULE_FINDINGS", 2)
    log = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP) * 5)

    scan = httplog.scan_logs(log.parent, ingest.Session(), focus=correlate.Focus())

    assert len(scan.detections) == 2 and scan.requests == []
    assert any("Limit 2 wykryć reguły HTTP_EXECUTABLE_IN_UPLOADS wyczerpany" in reason and "było 5" in reason
               for reason in scan.cover.reasons)
    assert scan.cover.partial


def test_focus_holds_only_requests_correlation_can_use(evidence):
    near = "09/Nov/2026:02:14:01 +0100"  # 01:14:01 UTC
    log = write(evidence / "logs" / "access.log", "".join([
        access_line("/wp-content/plugins/demo/x.php", when="01/Jan/2026:00:00:00 +0000"),
        access_line("/wp-login.php", when="01/Jan/2026:00:00:00 +0000"),
        access_line("/wp-login.php", when=near),
        access_line("/wp-login.php", when="09/Nov/2026:01:29:02 +0000"),
        access_line("/index.php", when="09/Nov/2026"),
    ]))
    mtime = int(correlate._ns("2026-11-09T01:14:01+00:00"))
    focus = correlate.Focus(frozenset({"wp-content/plugins/demo/x.php"}), ((mtime - 900 * 10**9, mtime + 900 * 10**9),))

    scan = httplog.scan_logs(log.parent, ingest.Session(), focus=focus)

    assert [request.location.line for request in scan.requests] == [1, 3]


@pytest.mark.parametrize("target", ["/wp-content/uploads/x.php%00.jpg", "/wp-content/uploads/a%2Fshell.php",
                                    "/../wp-content/uploads/shell.php", "/wp-content/uploads/x.php/" + "a" * 5000],
                         ids=["encoded-nul", "encoded-slash", "dot-dot-above-root", "too-long"])
def test_unresolved_request_that_looks_like_code_degrades_the_coverage(site, evidence, analyze, target):
    logs = write(evidence / "logs" / "access.log", access_line("/about/") + access_line(target)).parent

    run = analyze(site, logs=logs)

    assert run.coverage("logs")["status"] == "PARTIAL"
    assert run.has_gap("1 żądań wygląda na żądania plików kodu") and run.has_gap("(pierwsze: access.log:2)")


@pytest.mark.parametrize("name", ["a\u00a0b.php", "shell\t.php", "\u202egpj.php", "x\u200b.php"],
                         ids=["nbsp", "tab", "right-to-left-override", "zero-width-space"])
def test_webshell_name_with_invisible_or_control_characters_is_flagged_and_neutralised(site, evidence, analyze, name):
    """Przegląd M4, pkt 3: dawniej ścieżka nie była przypisywana (nota), a pokrycie zostawało ANALYZED."""
    encoded = "".join(f"%{byte:02X}" if byte > 0x7E or byte < 0x21 else chr(byte) for byte in name.encode())
    logs = write(evidence / "logs" / "access.log", access_line("/wp-content/uploads/" + encoded)).parent

    run = analyze(site, logs=logs)

    path = run.finding(RULE)["metadata"]["path"]
    assert path.startswith("wp-content/uploads/") and path.endswith(".php")
    assert not any(char in run.json_text + run.html for char in "\u202e\u200b")
    assert run.coverage("logs")["status"] == "ANALYZED"


def test_log_escaped_file_name_is_correlated_with_the_real_file(site, evidence, analyze):
    """Przegląd M4, pkt 4: Apache zapisuje bajty UTF-8 w ``%r`` jako ``\\xNN``."""
    write(site / "wp-content/uploads/2026/11/sh\u00e9ll.php", "<?php // synthetic")
    logs = write(evidence / "logs" / "access.log", access_line("/wp-content/uploads/2026/11/sh\\xc3\\xa9ll.php")).parent

    run = analyze(site, logs=logs)

    assert run.finding(RULE)["metadata"]["path"] == "wp-content/uploads/2026/11/sh\u00e9ll.php"
    assert "CORRELATED_UPLOAD_REQUEST" in run.rules


def test_path_bytes_outside_utf8_are_a_note(site, evidence, analyze):
    logs = write(evidence / "logs" / "access.log", access_line("/wp-content/uploads/a\\xff.php")).parent

    run = analyze(site, logs=logs)

    assert RULE in run.rules and run.has_gap("1 żądań ma ścieżkę, której bajty po dekodowaniu nie są poprawnym UTF-8")


@pytest.mark.parametrize("target", ['http://u:p\\"w@h.invalid/x.php', "http://u:p'w@h.invalid/x.php", "http://u:p<w@h.invalid/x.php",
                                    "http://u:p>w@h.invalid/x.php", "https://a@b:" + CANARY + "@h.invalid/x.php"],
                         ids=["double-quote", "apostrophe", "less-than", "greater-than", "at-in-password"])
def test_userinfo_is_removed_from_the_uri_structurally(target):
    """Przegląd M4, pkt 5: wzorzec ``redact`` zatrzymuje się na cudzysłowie i ``<``; host po ostatnim ``@`` zostaje."""
    uri = httplog.redacted_uri(target)

    assert uri.endswith("://[usunięto]@h.invalid/x.php")
    assert "p'w" not in uri and "p<w" not in uri and "p>w" not in uri and "w@" not in uri and CANARY not in uri


def test_absolute_form_without_userinfo_keeps_the_host():
    assert httplog.redacted_uri("http://site.invalid/wp-content/uploads/x.php?a=1") == "http://site.invalid/wp-content/uploads/x.php?[usunięto]"


@pytest.mark.parametrize("target", [
    "http://user:pa/ss@host/wp-content/uploads/x.php",
    "http://user:pa/ss/more@host/x.php?t=1",
    "https://us/er:SEKRETNE@host/x.php#frag",
], ids=["slash-in-password", "slashes-and-query", "slash-in-user"])
def test_credentials_with_a_slash_never_reach_the_uri(target):
    uri = httplog.redacted_uri(target)

    assert "pa/ss" not in uri and "SEKRETNE" not in uri and "us/er" not in uri and uri.count("[usunięto]") >= 1
