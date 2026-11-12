"""Redakcja cytatów (ADR 0006, pkt 8). Wszystkie „sekrety” to syntetyczne znaczniki."""
import re

import pytest
from conftest import CANARY, time_limit

from wpincidentlens import redact
from wpincidentlens.redact import MARK

MATCH = re.compile("<script")


@pytest.mark.parametrize("text, expected", [
    (f"https://redirect.example.net/go.php?id=7&next={CANARY}", f"https://redirect.example.net/go.php?{MARK}"),
    (f"/wp-content/uploads/x.php?{CANARY}", f"/wp-content/uploads/x.php?{MARK}"),
    (f"https://synthetic:{CANARY}@redirect.example.net/a", f"https://{MARK}@redirect.example.net/a"),
    (f"var api_key = \"{CANARY} tail\";", f"var api_key = {MARK};"),
    (f"X-Auth-Token: {CANARY}", f"X-Auth-Token: {MARK}"),
    (f'{{"client_secret":"{CANARY}"}}', f'{{"client_secret":{MARK}}}'),
    (f"PASSWORD={CANARY}&x=1", f"PASSWORD={MARK}&x=1"),
    ("kontakt: jan.synthetic+tag@example.org", f"kontakt: {MARK}@example.org"),
    ("sum d41d8cd98f00b204e9800998ecf8427e end", f"sum {MARK} end"),
    ("blob QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3 end", f"blob {MARK} end"),
], ids=["query", "query-without-names", "userinfo", "quoted-secret", "header", "json-secret", "uppercase-name", "email", "hex-run",
        "base64-run"])
def test_secret_like_parts_are_replaced(text, expected):
    assert redact.redact(text) == expected


@pytest.mark.parametrize("text", [
    '<iframe src="https://redirect.example.net/embed/v1"></iframe>',
    "https://a1b2c3d4e5f6a7b8c9d0e1f2a3b4.example.net/",
    "/wp-content/uploads/2026/11/cache-view.php",
    "Zwykły tekst stopki, rok 2026. Czy to działa? Tak.",
    "user@localhost",
], ids=["markup-and-host", "long-host-label", "path", "prose", "at-without-domain"])
def test_indicators_and_plain_text_stay(text):
    assert redact.redact(text) == text


@pytest.mark.parametrize("text, expected", [
    ("a\x00b\x1bc\x7fd", "a\ufffdb\ufffdc\ufffdd"),
    ("line\none\ttab\r", "line one tab "),
    ("abc\u202edef\u200b\u2066", "abc\ufffddef\ufffd\ufffd"),
    ("lone\ud800surrogate", "lone\ufffdsurrogate"),
    ("zażółć gęślą jaźń — „ok”", "zażółć gęślą jaźń — „ok”"),
], ids=["control", "whitespace", "bidi-and-zero-width", "surrogate", "ordinary-unicode"])
def test_control_and_format_characters_are_neutralised(text, expected):
    assert redact.neutralise(text) == expected


def test_excerpt_is_cut_around_the_match_after_redaction():
    text = "lead " * 100 + f'<script src="https://redirect.example.net/x.js?v={CANARY}"></script>' + " tail" * 100

    quoted = redact.excerpt(text, MATCH)

    assert len(quoted) == redact.EXCERPT_CHARS
    assert quoted.startswith(redact.ELLIPSIS) and quoted.endswith(redact.ELLIPSIS)
    assert "<script" in quoted and "redirect.example.net" in quoted
    assert CANARY not in quoted


def test_short_text_is_quoted_whole():
    assert redact.excerpt("<script>synthetic()</script>", MATCH) == "<script>synthetic()</script>"


def test_secret_cut_by_the_window_edge_is_still_redacted():
    """Okno zaczyna się w środku sekretu stojącego tuż przed trafieniem: redakcja całości idzie przed cięciem."""
    secret = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3" * 3
    quoted = redact.excerpt(f"{'x ' * 200}{secret}<script>synthetic()</script>", MATCH)

    assert "<script" in quoted
    assert secret[-20:] not in quoted


def test_match_inside_a_redacted_part_falls_back_to_the_beginning():
    text = "x " * 150 + "https://redirect.example.net/?next=javascript:1"

    quoted = redact.excerpt(text, re.compile("javascript"))

    assert quoted.startswith("x x ") and len(quoted) == redact.EXCERPT_CHARS
    assert "javascript" not in redact.redact(text)


@pytest.mark.parametrize("build", [
    lambda: "a" * 1_000_000,
    lambda: "key" * 300_000,
    lambda: "://" * 300_000,
    lambda: "@a." * 300_000,
    lambda: "?" * 1_000_000,
    lambda: "a1" * 500_000,
], ids=["word-run", "secret-names", "schemes", "at-signs", "question-marks", "alnum-run"])
def test_redaction_of_hostile_megabyte_is_fast(build):
    text = build()

    with time_limit(5):
        redact.redact(text)


_PIECES = [*"aA0f9Z_-+=:?@/.\"' \t\n&;,<>[]{}", "key", "token", "pass", "auth", "sig", "://", "http://", MARK, "@example.org",
           "\u202e", "\x00", "ą", "d41d8cd98f00b204e9800998ecf8427e", CANARY]


def test_redact_is_idempotent_on_random_compositions():
    """Własność: ``redact(redact(x)) == redact(x)``. Ziarno stałe; składniki to fragmenty, na których działają wzorce."""
    import random
    chance = random.Random(8)
    for _ in range(20000):
        text = "".join(chance.choice(_PIECES) for _ in range(chance.randint(0, 40)))
        once = redact.redact(text)
        assert redact.redact(once) == once, text


@pytest.mark.parametrize("text", ["/x?password: hunter2 tail", "/a/oauth=x?user=hunter2&p=1", "/a/secret=s3cr3t?q=hunter2&z=1",
                                  "/login?pwd = hunter2", "?token:hunter2 x"])
def test_secret_named_in_a_query_never_survives(text):
    """Nazwa sekretu tuż po „?” nie może zostać zjedzona przez redakcję zapytania tak, by wartość została jawna."""
    out = redact.redact(text)

    assert "hunter2" not in out and "s3cr3t" not in out
    assert out.count("?") <= 1 and redact.redact(out) == out
