"""Parsery wiersza logu HTTP (ADR 0007 pkt 1, 4, 5): formaty, powody odrzucenia, czas, ścieżka, adres klienta, S-08."""
import ipaddress
import json

import pytest
from conftest import access_line, time_limit

from wpincidentlens import logformats
from wpincidentlens.logformats import HttpRecord, client_address, parse, request_path

COMBINED = access_line("/wp-content/uploads/a.php?x=1").rstrip("\n")
COMMON = '192.0.2.10 - alice [09/Nov/2026:02:14:01 +0100] "POST /wp-login.php HTTP/1.0" 302 -'


def json_line(**fields) -> str:
    document = {"time": "2026-11-09T02:14:01+01:00", "remote_addr": "192.0.2.10", "method": "GET",
                "uri": "/wp-content/uploads/a.php?x=1", "status": 200, **fields}
    return json.dumps({key: value for key, value in document.items() if value is not ...})


def test_format_table_is_versioned():
    assert logformats.FORMATS == {"combined": "combined@1", "common": "common@1", "json": "json@1"}


def test_combined_line_gives_every_field():
    assert parse("combined", COMBINED) == HttpRecord(
        "192.0.2.10", "09/Nov/2026:02:14:01 +0100", "2026-11-09T01:14:01+00:00", "second", "GET",
        "/wp-content/uploads/a.php?x=1", 200, 75, escaped=True)


def test_common_line_gives_every_field_and_dash_bytes_is_none():
    assert parse("common", COMMON) == HttpRecord(
        "192.0.2.10", "09/Nov/2026:02:14:01 +0100", "2026-11-09T01:14:01+00:00", "second", "POST", "/wp-login.php", 302, None, escaped=True)


def test_json_line_gives_every_field():
    record = parse("json", json_line(bytes=512, forwarded_for="203.0.113.7", user_agent="SyntheticTest"))

    assert record == HttpRecord("192.0.2.10", "2026-11-09T02:14:01+01:00", "2026-11-09T01:14:01+00:00", "second", "GET",
                                "/wp-content/uploads/a.php?x=1", 200, 512, "203.0.113.7")


def test_fields_after_the_format_are_ignored_and_never_kept():
    """Np. czas obsługi albo ``X-Forwarded-For`` dopisany w konfiguracji serwera: formaty tekstowe go nie niosą."""
    record = parse("combined", COMBINED + ' "203.0.113.77" 0.004')

    assert record.forwarded_for is None and "203.0.113.77" not in repr(record)


def test_common_format_reads_the_common_part_of_a_combined_line():
    """Combined to common z dwoma polami więcej; pola po formacie są ignorowane, więc common go przyjmuje."""
    assert parse("common", COMBINED) == parse("combined", COMBINED)


def test_combined_format_requires_referer_and_user_agent():
    assert parse("combined", COMMON) == "layout"


def test_escaped_quote_in_the_request_and_user_agent_is_part_of_the_field():
    line = '192.0.2.10 - - [09/Nov/2026:02:14:01 +0100] "GET /a\\"b.php HTTP/1.1" 200 1 "-" "x \\" y"'

    assert parse("combined", line).target == '/a\\"b.php'


def test_http_09_request_without_protocol_is_accepted():
    assert parse("common", '192.0.2.10 - - [09/Nov/2026:02:14:01 +0100] "GET /a.php" 200 1').target == "/a.php"


def test_hostname_as_client_is_kept_and_ipv6_is_canonical():
    assert parse("common", COMMON.replace("192.0.2.10", "crawler.example.invalid", 1)).client == "crawler.example.invalid"
    assert parse("common", COMMON.replace("192.0.2.10", "2001:DB8:0:0::1", 1)).client == "2001:db8::1"


@pytest.mark.parametrize("fmt, line, reason", [
    ("combined", "", "layout"),
    ("combined", "garbage line", "layout"),
    ("combined", COMBINED.replace(" ", "\t", 1), "layout"),
    ("combined", COMBINED.replace('" 200', " 200", 1), "layout"),
    ("common", COMMON.replace("[", "", 1), "layout"),
    ("common", COMMON.replace('"POST /wp-login.php HTTP/1.0"', '"-"'), "request_line"),
    ("common", COMMON.replace("POST /wp-login.php", "POST /a b"), "request_line"),
    ("common", COMMON.replace("POST", "PO(ST"), "request_line"),
    ("common", COMMON.replace("HTTP/1.0", "SMTP/1.0"), "request_line"),
    ("common", COMMON.replace("/wp-login.php", "/a\x0bb"), "request_line"),
    ("common", COMMON.replace("192.0.2.10", "bad_host!", 1), "bad_client"),
    ("common", COMMON.replace("192.0.2.10", "a" * 256, 1), "bad_client"),
    ("common", COMMON.replace(" 302 ", " 099 "), "bad_number"),
    ("common", COMMON.replace(" 302 ", " 600 "), "bad_number"),
    ("common", COMMON.replace(" 302 ", " 2000 "), "bad_number"),
    ("common", COMMON.replace(" -", " " + "9" * 19), "bad_number"),
    ("json", '{"time": "x"', "not_json"),
    ("json", "﻿" + json_line(), "not_json"),
    ("json", json_line() + " " + json_line(), "not_json"),
    ("json", json_line().replace('"status": 200', '"status": 200, "status": 201'), "duplicate_key"),
    ("json", json_line(time=...), "shape"),
    ("json", json_line(status="200"), "shape"),
    ("json", json_line(status=True), "shape"),
    ("json", json_line(status=200.0), "shape"),
    ("json", json_line(bytes=1.5), "shape"),
    ("json", json_line(bytes=False), "shape"),
    ("json", json_line(forwarded_for=7), "shape"),
    ("json", json.dumps([json_line()]), "shape"),
    ("json", '"text"', "shape"),
    ("json", json_line().replace('"status": 200', '"status": NaN'), "bad_value"),
    ("json", json_line().replace('"status": 200', '"status": 200, "x": Infinity'), "bad_value"),
    ("json", json_line(headers={"a": "b"}), "bad_value"),
    ("json", json_line(tags=["a"]), "bad_value"),
    ("json", json_line(remote_addr="\ud800"), "bad_value"),
    ("json", json_line(method="GE/T"), "request_line"),
    ("json", json_line(method="G" * 33), "request_line"),
    ("json", json_line(uri="/a b"), "request_line"),
    ("json", json_line(uri=""), "request_line"),
    ("json", json_line(remote_addr="10.0.0.1:443"), "bad_client"),
    ("json", json_line(status=99), "bad_number"),
    ("json", json_line(bytes=-1), "bad_number"),
], ids=["empty", "garbage", "tab-separator", "unquoted-request", "no-time-brackets", "dash-request", "space-in-target",
        "method-with-separator", "not-http-protocol", "control-in-target", "bad-hostname", "long-hostname", "status-below-100",
        "status-above-599", "four-digit-status", "huge-bytes", "json-unterminated", "json-bom", "json-two-objects",
        "json-duplicate-key", "json-no-time", "json-status-text", "json-status-bool", "json-status-float", "json-bytes-float",
        "json-bytes-bool", "json-forwarded-number", "json-array", "json-string", "json-nan", "json-infinity",
        "json-nested-object", "json-list-value", "json-lone-surrogate", "json-method-with-separator", "json-method-too-long", "json-space-in-uri",
        "json-empty-uri", "json-address-with-port", "json-status-99", "json-negative-bytes"])
def test_line_outside_the_format_is_rejected_with_its_reason(fmt, line, reason):
    assert reason in logformats.REASONS
    assert parse(fmt, line) == reason


def test_every_rejection_reason_except_line_length_is_reachable_from_a_line():
    """``too_long`` nadaje dzielnik wierszy (``httplog``), nie parser wiersza."""
    assert set(logformats.REASONS) - {"too_long"} == {
        "layout", "request_line", "bad_client", "bad_number", "not_json", "duplicate_key", "shape", "bad_value"}


# --- czas ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("stamp, utc", [
    ("09/Nov/2026:02:14:01 +0100", "2026-11-09T01:14:01+00:00"),
    ("09/Nov/2026:02:14:01 -0530", "2026-11-09T07:44:01+00:00"),
    ("01/Jan/2026:00:30:00 +0100", "2025-12-31T23:30:00+00:00"),
    ("09/Nov/2026:02:14:01", None),
    ("09/Nov/2026:02:14:01 +9999", None),
    ("09/Lis/2026:02:14:01 +0100", None),
    ("31/Feb/2026:02:14:01 +0100", None),
    ("01/Jan/0001:00:00:00 +0100", None),
], ids=["plus-zone", "minus-zone", "across-new-year", "no-zone", "impossible-zone", "non-english-month", "impossible-day",
        "before-year-one-in-utc"])
def test_combined_time_is_normalised_to_utc_or_kept_raw(stamp, utc):
    record = parse("combined", access_line("/", when=stamp).rstrip("\n"))

    assert (record.timestamp_raw, record.timestamp_utc) == (stamp, utc)


@pytest.mark.parametrize("fmt, line", [
    ("combined", access_line("/", when="token=SYNTHETIC-S3cr3t 198.51.100.23").rstrip("\n")),
    ("json", json.dumps({"time": "token=SYNTHETIC-S3cr3t 198.51.100.23", "remote_addr": "192.0.2.10", "method": "GET", "uri": "/",
                         "status": 200})),
], ids=["combined", "json"])
def test_time_field_that_is_not_a_time_is_not_kept_raw(fmt, line):
    record = parse(fmt, line)

    assert (record.timestamp_raw, record.timestamp_utc) == (logformats.UNREADABLE_TIME, None)


@pytest.mark.parametrize("stamp, utc, precision", [
    ("2026-11-09T01:14:01Z", "2026-11-09T01:14:01+00:00", "second"),
    ("2026-11-09T02:14:01.123+01:00", "2026-11-09T01:14:01.123000+00:00", "millisecond"),
    ("2026-11-09T02:14:01.123456+01:00", "2026-11-09T01:14:01.123456+00:00", "microsecond"),
    ("2026-11-09T02:14:01", None, "second"),
    ("2026-11-09 02:14:01+01:00", None, "second"),
    ("2026-13-09T02:14:01+01:00", None, "second"),
], ids=["zulu", "milliseconds", "microseconds", "no-offset", "space-separator", "impossible-month"])
def test_json_time_is_normalised_to_utc_with_its_precision(stamp, utc, precision):
    record = parse("json", json_line(time=stamp))

    assert (record.timestamp_raw, record.timestamp_utc, record.precision) == (stamp, utc, precision)


@pytest.mark.parametrize("stamp", ["yesterday", "x" * 1000, "2026-11-09T02:14:01+01:00" + "0" * 1000])
def test_raw_time_outside_the_time_shape_is_replaced(stamp):
    assert parse("json", json_line(time=stamp)).timestamp_raw == logformats.UNREADABLE_TIME


# --- ścieżka ------------------------------------------------------------------------------------

@pytest.mark.parametrize("target, path", [
    ("/wp-content/uploads/a.php", "wp-content/uploads/a.php"),
    ("/wp-content/uploads/a.php?token=x#frag", "wp-content/uploads/a.php"),
    ("/wp-content/uploads/a.php#x?y", "wp-content/uploads/a.php"),
    ("/wp-content//uploads///a.php", "wp-content/uploads/a.php"),
    ("/wp-content/uploads/x/%2e%2e/shell.php", "wp-content/uploads/shell.php"),
    ("/wp-content/uploads/x/%2E%2E/./shell.php", "wp-content/uploads/shell.php"),
    ("/wp-content/uploads/%2fshell.php", None),
    ("/wp-content/uploads/a%2Fshell.php", None),
    ("/wp-content/uploads/%252e%252e/a.php", "wp-content/uploads/%2e%2e/a.php"),
    ("/wp-content/uploads/za%C5%BC%C3%B3%C5%82%C4%87.php", "wp-content/uploads/zażółć.php"),
    ("/wp-content/uploads/%ff.php", "wp-content/uploads/�.php"),
    ("/WP-Content/Uploads/A.PHP", "WP-Content/Uploads/A.PHP"),
    ("http://site.invalid/wp-content/uploads/a.php?x", "wp-content/uploads/a.php"),
    ("https://site.invalid", ""),
    ("/", ""),
    ("/../../etc/passwd", None),
    ("/a/%2e%2e/%2e%2e/etc/passwd", None),
    ("/a%00.php", None),
    ("/a%0a.php", "a\n.php"),
    ("/wp-content/uploads/a%C2%A0b.php", "wp-content/uploads/a\xa0b.php"),
    ("/wp-content/uploads/shell%09.php", "wp-content/uploads/shell\t.php"),
    ("/wp-content/uploads/%E2%80%AEgpj.php", "wp-content/uploads/\u202egpj.php"),
    ("*", None),
    ("wp-content/uploads/a.php", None),
    ("/" + "a" * 5000, None),
], ids=["plain", "query-and-fragment", "fragment-first", "double-slashes", "encoded-dot-dot", "upper-encoded-dot-dot",
        "encoded-slash", "encoded-slash-upper", "decoded-once-only", "utf8", "invalid-utf8", "case-kept", "absolute-form", "absolute-form-no-path",
        "root", "dot-dot-above-root", "encoded-dot-dot-above-root", "encoded-nul", "encoded-newline", "nbsp", "tab", "right-to-left-override", "asterisk",
        "not-origin-form", "too-long"])
def test_request_path_is_normalised_once(target, path):
    assert request_path(target) == path


# --- poprawki po przeglądzie bezpieczeństwa M4 ----------------------------------------------------

@pytest.mark.parametrize("method", ["GET_X", "M-SEARCH", "get", "PROPFIND", "X!#$%&'*+.^_`|~1"],
                         ids=["underscore", "hyphen", "lowercase", "webdav", "every-token-character"])
def test_any_rfc7230_token_is_a_method_because_the_server_passes_it_to_php(method):
    line = f'192.0.2.10 - - [09/Nov/2026:02:14:01 +0100] "{method} /wp-content/uploads/x.php HTTP/1.1" 200 1'

    assert parse("common", line).method == method
    assert parse("json", json_line(method=method)).method == method


@pytest.mark.parametrize("target, path", [
    ("/wp-content/uploads/sh\\xc3\\xa9ll.php", "wp-content/uploads/sh\u00e9ll.php"),
    ('/wp-content/uploads/a\\"b.php', 'wp-content/uploads/a"b.php'),
    ("/wp-content/uploads/a\\\\b.php", "wp-content/uploads/a\\b.php"),
    ("/wp-content/uploads/a\\x41%42.php", "wp-content/uploads/aAB.php"),
    ("/wp-content/uploads/a\\x25%32%35.php", "wp-content/uploads/a%25.php"),
    ("/wp-content/uploads/a\\q.php", "wp-content/uploads/a\\q.php"),
], ids=["utf8-bytes", "quote", "backslash", "escape-then-percent", "escaped-percent-is-not-decoded-twice", "unknown-escape-kept"])
def test_log_escapes_are_reversed_before_percent_decoding(target, path):
    """Apache i Nginx zapisują w ``%r`` bajty spoza ASCII drukowalnego jako ``\\xNN``; plik na dysku ma prawdziwą nazwę."""
    line = f'192.0.2.10 - - [09/Nov/2026:02:14:01 +0100] "GET {target} HTTP/1.1" 200 1'
    record = parse("common", line)

    assert record.escaped and logformats.resolve_target(record.target, record.escaped).path == path


def test_log_escapes_are_not_reversed_in_json_where_the_decoder_already_did_it():
    record = parse("json", json_line(uri="/wp-content/uploads/sh\\xc3\\xa9ll.php"))

    assert not record.escaped and request_path(record.target, record.escaped) == "wp-content/uploads/sh\\xc3\\xa9ll.php"


@pytest.mark.parametrize("target, escaped", [("/wp-content/uploads/%ff.php", False), ("/wp-content/uploads/\\xff.php", True)],
                         ids=["percent", "log-escape"])
def test_bytes_outside_utf8_in_the_path_are_marked_lossy(target, escaped):
    resolved = logformats.resolve_target(target, escaped)

    assert resolved == ("wp-content/uploads/\ufffd.php", True, "/wp-content/uploads/\ufffd.php")
    assert not logformats.resolve_target("/wp-content/uploads/a.php", escaped).lossy


# --- adres klienta (pkt 5, S-14) ----------------------------------------------------------------

TRUSTED = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("2001:db8:ffff::/48"))


def record(client: str, forwarded: str | None) -> HttpRecord:
    return HttpRecord(client, "", None, "second", "GET", "/", 200, None, forwarded)


@pytest.mark.parametrize("client, forwarded, trusted, expected", [
    ("192.0.2.10", "203.0.113.7", TRUSTED, ("192.0.2.10", "connection", False)),
    ("10.0.0.5", "203.0.113.7", (), ("10.0.0.5", "connection", False)),
    ("10.0.0.5", None, TRUSTED, ("10.0.0.5", "connection", False)),
    ("10.0.0.5", "203.0.113.7", TRUSTED, ("203.0.113.7", "forwarded_for_via_trusted_proxy", False)),
    ("10.0.0.5", "198.51.100.1, 203.0.113.7, 10.1.1.1, 10.2.2.2", TRUSTED, ("203.0.113.7", "forwarded_for_via_trusted_proxy", False)),
    ("10.0.0.5", "10.9.9.9, 10.1.1.1", TRUSTED, ("10.9.9.9", "forwarded_for_via_trusted_proxy", False)),
    ("10.0.0.5", "spoofed, 203.0.113.7", TRUSTED, ("203.0.113.7", "forwarded_for_via_trusted_proxy", False)),
    ("10.0.0.5", "203.0.113.7, unknown", TRUSTED, ("10.0.0.5", logformats.FORWARDED_REJECTED, True)),
    ("10.0.0.5", "203.0.113.7:443", TRUSTED, ("10.0.0.5", logformats.FORWARDED_REJECTED, True)),
    ("10.0.0.5", "203.0.113.7,", TRUSTED, ("10.0.0.5", logformats.FORWARDED_REJECTED, True)),
    ("10.0.0.5", "fe80::1%eth0", TRUSTED, ("10.0.0.5", logformats.FORWARDED_REJECTED, True)),
    ("2001:db8:ffff::1", "2001:db8::7", TRUSTED, ("2001:db8::7", "forwarded_for_via_trusted_proxy", False)),
    ("::ffff:10.0.0.5", "203.0.113.7", TRUSTED, ("203.0.113.7", "forwarded_for_via_trusted_proxy", False)),
    ("proxy.example.invalid", "203.0.113.7", TRUSTED, ("proxy.example.invalid", "connection", False)),
], ids=["spoofed-from-untrusted-connection", "no-trusted-proxies", "no-header", "one-trusted-hop", "chain-of-trusted-proxies",
        "whole-chain-trusted", "spoofed-entry-left-of-client", "malformed-entry-right-of-client", "entry-with-port",
        "empty-entry", "scoped-ipv6", "ipv6-proxy", "ipv4-mapped-proxy", "hostname-is-never-trusted"])
def test_client_address_uses_forwarded_for_only_through_trusted_proxies(client, forwarded, trusted, expected):
    assert client_address(record(client, forwarded), trusted) == expected


def test_forwarded_for_over_the_limit_is_rejected_not_truncated():
    """Prawy koniec dopisuje zaufane proxy: ucięcie z dowolnej strony mogłoby zostawić adres podstawiony przez klienta."""
    padding = ", ".join(["198.51.100.1"] * (logformats.MAX_FORWARDED_CHARS // 14 + 1))
    forged = record("10.0.0.5", padding + ", 203.0.113.66, 10.1.1.1")

    assert len(forged.forwarded_for) > logformats.MAX_FORWARDED_CHARS
    assert client_address(forged, TRUSTED) == ("10.0.0.5", logformats.FORWARDED_REJECTED, True)


def test_json_record_keeps_the_whole_forwarded_for_for_the_length_check():
    forwarded = "198.51.100.1, " * 300 + "203.0.113.66"

    assert parse("json", json_line(forwarded_for=forwarded)).forwarded_for == forwarded


def test_combined_format_never_carries_forwarded_for():
    line = access_line("/", ip="10.0.0.5", extra=' "203.0.113.77"').rstrip("\n")

    assert client_address(parse("combined", line), TRUSTED) == ("10.0.0.5", "connection", False)


# --- S-08: czas dopasowania liniowy względem długości wiersza -------------------------------------

CRAFTED = [
    '192.0.2.10 - - [x] "' + "\\\"" * 30_000,
    '192.0.2.10 - - [x] "' + "\\" * 60_000,
    '192.0.2.10 - - [' + "[" * 60_000,
    '192.0.2.10 - - [x] "GET /a HTTP/1.1" 200 1 "' + '\\"' * 30_000,
    '192.0.2.10 - - [x] "GET /a HTTP/1.1" 200 1 "-" "' + "a\\" * 30_000,
    '192.0.2.10 - - [x] "GET /a HTTP/1.1" 200 1 ' + '"" ' * 20_000,
    '192.0.2.10 - - [x] "GET /a HTTP/1.1" ' + "2" * 60_000,
    " " * 60_000,
    "a " * 30_000,
    "{" * 30_000 + "}" * 30_000,
    '{"a":' * 10_000 + "1" + "}" * 10_000,
    '{"time":"' + "\\u0000" * 10_000 + '"}',
    json_line(uri="/" + "%2e%2e/" * 8000),
]


@pytest.mark.parametrize("fmt", list(logformats.FORMATS))
@pytest.mark.parametrize("line", CRAFTED, ids=[f"crafted-{n}" for n in range(len(CRAFTED))])
def test_s08_crafted_line_is_parsed_in_bounded_time(fmt, line):
    with time_limit(2):
        result = parse(fmt, line)
        if not isinstance(result, str):
            request_path(result.target)


def test_s08_crafted_target_is_normalised_in_bounded_time():
    with time_limit(2):
        assert request_path("/" + "%2e%2e/" * 10_000 + "a") is None
        assert request_path("/" + "a/%2e%2e/" * 800 + "b") == "b"
        request_path("/" + "%" * 60_000)
