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
    (f"api_key='{CANARY}", f"api_key={MARK}"),
    (f'Session="{CANARY}', f"Session={MARK}"),
    (f"/x.php?token: {CANARY}", f"/x.php?{MARK} {MARK}"),
    ("Authorization: Bearer syntheticbearertoken", f"Authorization: {MARK}"),
    ("authorization: basic c3ludGhldGljOnN5bg== next", f"authorization: {MARK}"),  # „=” na końcu: następne słowo też
    (f"key= token: {CANARY}", f"key= {MARK}"),
    (f"key=token: {CANARY}", f"key={MARK}"),
    ("secret=tokenAb1Cd2=", f"secret={MARK}"),
    ("password=Passw0rd:x", f"password={MARK}"),
    ("password=Passw0rd: x", f"password={MARK}"),
    ("auth=keyAbc123= y", f"auth={MARK}"),
    (f"keyhttp://api_key='{CANARY}", f"keyhttp:{MARK}"),
    (f"keyhttp://Authorization: Bearer {CANARY}", f"keyhttp:{MARK}"),
    ('key=token: "a b c"', f"key={MARK}"),
    ("secret=y: 'a b'", f"secret={MARK}"),
], ids=["query", "query-without-names", "userinfo", "quoted-secret", "header", "json-secret", "uppercase-name", "email", "hex-run",
        "base64-run", "unterminated-single-quote", "unterminated-double-quote", "secret-name-right-after-query-mark",
        "bearer-token", "basic-credentials", "empty-value-before-next-secret-name", "glued-next-secret-name",
        "value-starting-with-a-secret-name", "value-starting-with-a-secret-name-and-colon",
        "value-ending-with-colon-then-word", "value-ending-with-equals-then-word",
        "value-ending-with-equals-then-quote", "value-ending-with-colon-then-auth-scheme",
        "value-ending-with-colon-then-double-quoted", "value-ending-with-colon-then-single-quoted"])
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
                                  "/login?pwd = hunter2", "?token:hunter2 x",
                                  "password=ab?c\\hunter2", "token=?\\hunter2", "/a?q=\\hunter2"])
def test_secret_named_in_a_query_never_survives(text):
    """Nazwa sekretu tuż po „?” nie może zostać zjedzona przez redakcję zapytania tak, by wartość została jawna."""
    out = redact.redact(text)

    assert "hunter2" not in out and "s3cr3t" not in out
    assert out.count("?") <= 1 and redact.redact(out) == out


_WP_CONFIG_SECRETS = ["DB_PASSWORD", "DB_USER", "AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
                      "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"]


@pytest.mark.parametrize("text", [
    "define('DB_PASSWORD', 'hunter2');",
    'define( "AUTH_KEY" , "hunter2" );',
    "define ( 'LOGGED_IN_KEY' ,'hunter2 with spaces' ) ;",
    "define('NONCE_SALT', \"mixed 'quotes' hunter2\");",
    "define('DB_PASSWORD', 'it\\'s hunter2');",
    "'DB_PASSWORD' => 'hunter2',",
    '"password" => "hunter2"',
    "array('db_user'=>'hunter2')",
    "$password = 'hunter2';",
    "$db_pass='hunter2';",
    "INSERT INTO wp_options VALUES (1,'auth_key','hunter2 x','yes');",
    "secret=<hunter2>",
    "secret=<hunter2",
    'key = "' + "a b " * 60 + 'hunter2"',
    "key = '" + "x" * 300 + " hunter2'",
    "pass: 'hunter2 x",
    "pass: 'x hunter2",
    'password="hunter2',
    'password="a<b hunter2"',
    "password: 'x\\' hunter2",
    'key=" password: "hunter2"',
    'key=" password: "x hunter2" tail',
    "key=\n'DB_PASSWORD'=>            hunter2,",
    'key="\ndefine("DB_PASSWORD",hunter2);',
], ids=["define-single", "define-double-spaced", "define-spaces-in-value", "define-mixed-quotes", "define-escaped-quote",
        "array-arrow", "array-arrow-double", "array-arrow-db-user", "assignment", "assignment-glued", "sql-tuple",
        "angle-brackets", "angle-unclosed", "long-quoted-double", "long-quoted-single", "unclosed-quote-two-words",
        "unclosed-quote-tail", "unclosed-double", "lt-inside-quotes", "escaped-quote-in-unclosed",
        "quote-closing-early-glued", "quote-closing-early-glued-words",
        "value-swallowing-the-next-array-key", "value-swallowing-the-next-define-name"])
def test_php_and_config_secret_shapes_are_redacted(text):
    out = redact.redact(text)

    assert "hunter2" not in out
    assert redact.redact(out) == out


@pytest.mark.parametrize("name", _WP_CONFIG_SECRETS)
def test_every_wp_config_credential_constant_is_redacted(name):
    out = redact.redact(f"define( '{name}', 'synthetic hunter2 value' );")

    assert out == f"define( '{name}', {MARK} );"


@pytest.mark.parametrize("text", [
    "define('DB_HOST', 'localhost');",
    "define('DB_NAME', 'wordpress');",
    "define('WP_DEBUG', false);",
    "$table_prefix = 'wp_';",
    "add_action( 'init', array( $this, 'register' ) );",
    '<a title="the key" href="/x">',
], ids=["db-host", "db-name", "wp-debug", "table-prefix", "hook", "comma-after-name-in-markup-without-quote-separator"])
def test_non_secret_config_and_code_stays(text):
    """``DB_HOST`` to wskaźnik (dokąd łączy się witryna), ``DB_NAME`` nie jest poświadczeniem: zostają."""
    assert redact.redact(text) == text


def test_unclosed_quote_stops_before_markup():
    """Niedomknięty cudzysłów nie zjada reszty dokumentu ze wskaźnikami: kończy się przed znacznikiem HTML."""
    out = redact.redact("token='hunter2 <script src=https://redirect.example.net/x.js></script>")

    assert "hunter2" not in out
    assert "<script src=https://redirect.example.net/x.js>" in out


@pytest.mark.parametrize("unit", ["define(", "'a'=>", "define('DB_PASSWORD', ", "'key'=>", "key='", 'key="<', "'auth',",
                                  "key='x', ", "key='a\\", 'salt: "', "pass=>", 'key="a"b, ', 'key="""', 'key=\\"', 'key="x" key '])
def test_redaction_of_hostile_php_fragments_is_linear(unit):
    """1 MiB powtórzonych fragmentów ``define(`` / ``'a'=>``: czas liniowy, nie kwadratowy.

    Bezwzględny budżet (``time_limit``) łapie zawieszenie; stosunek czasów 1 MiB / 256 KiB łapie wzrost kwadratowy
    (liniowy daje ok. 4, kwadratowy ok. 16) niezależnie od szybkości maszyny.
    """
    import time

    def measure(size: int) -> float:
        text = (unit * (size // len(unit) + 1))[:size]
        times = []
        for _ in range(3):  # najkrótszy z trzech: odporny na chwilowe obciążenie maszyny
            start = time.perf_counter()
            with time_limit(5):
                redact.redact(text)
            times.append(time.perf_counter() - start)
        return min(times)

    small, large = measure(1 << 18), measure(1 << 20)
    assert large < 10 * max(small, 0.05)


@pytest.mark.parametrize("unit", ["define(", "'a'=>"])
def test_redaction_of_megabyte_without_secret_names_is_well_under_a_second(unit):
    text = (unit * ((1 << 20) // len(unit) + 1))[:1 << 20]

    with time_limit(1):
        redact.redact(text)
