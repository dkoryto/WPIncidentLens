"""Odczyt danych serializowanych PHP jako danych (ADR 0006, pkt 5). Wyłącznie krótkie wartości syntetyczne."""
import math

import pytest
from conftest import time_limit

from wpincidentlens import phpserialize
from wpincidentlens.phpserialize import Opaque, SerializedError, parse


@pytest.mark.parametrize("text, expected", [
    ("N;", None),
    ("b:1;", True),
    ("b:0;", False),
    ("i:-42;", -42),
    ("d:0.5;", 0.5),
    ("d:1.0E+3;", 1000.0),
    ("d:-INF;", -math.inf),
    ('s:0:"";', ""),
    ('s:5:"a";"b";', 'a";"b'),
    ('s:10:"zażółć";', "zażółć"),
    ("a:0:{}", {}),
    ('a:2:{i:0;s:1:"a";i:1;s:1:"b";}', {0: "a", 1: "b"}),
    ('a:2:{s:6:"editor";b:1;s:13:"administrator";b:0;}', {"editor": True, "administrator": False}),
    ('a:1:{s:1:"a";a:1:{s:1:"b";a:0:{}}}', {"a": {"b": {}}}),
    ('a:2:{s:1:"7";b:1;s:2:"07";b:1;}', {7: True, "07": True}),
    ('a:2:{s:1:"k";i:1;s:1:"k";i:2;}', {"k": 2}),
], ids=["null", "true", "false", "int", "float", "float-exponent", "float-inf", "empty-string", "string-with-delimiters",
        "multibyte-string", "empty-array", "list", "capabilities", "nested", "integer-like-string-key", "repeated-key-last-wins"])
def test_valid_value_is_read_as_plain_python_data(text, expected):
    assert parse(text) == expected


def test_array_keeps_the_order_of_keys():
    assert list(parse('a:3:{s:1:"z";N;s:1:"a";N;i:5;N;}')) == ["z", "a", 5]


@pytest.mark.parametrize("text", [
    "", "x", "N", "b:2;", "b:1", "i:;", "i:1.5;", "i:1", "d:abc;", 's:3:"ab";', 's:1:"ab";', 's:1:"a"', 's:-1:"";', 'S:1:"a";',
    "a:1:{}", "a:0:{i:0;N;}", "a:1:{i:0;N;", "a:1:{N;N;}", "a:1:{b:1;N;}", "a:1:{d:1.5;N;}", "a:1:{a:0:{}N;}", "a:1:{i:0;}",
    "N;N;", "a:0:{};", "i:1; ", 'O:1:"A":0:{', 'O:1:"A":1:{i:0;}', 'C:1:"A":5:{ab}', "r:;",
], ids=["empty", "unknown-tag", "no-terminator", "bool-out-of-range", "bool-unterminated", "int-empty", "int-fraction",
        "int-unterminated", "float-text", "string-too-short", "string-too-long", "string-unterminated", "string-negative-length",
        "escaped-string-form", "array-count-too-high", "array-count-too-low", "array-unclosed", "null-key", "bool-key", "float-key",
        "array-key", "value-missing", "two-values", "garbage-after-array", "trailing-space", "object-unclosed",
        "object-property-without-value", "custom-length-mismatch", "reference-without-number"])
def test_invalid_value_is_an_error_not_a_guess(text):
    with pytest.raises(SerializedError):
        parse(text)


@pytest.mark.parametrize("text, expected", [
    ('O:13:"SyntheticEvil":1:{s:3:"cmd";s:6:"noop()";}', Opaque("object")),
    ('O:8:"stdClass":0:{}', Opaque("object")),
    ('C:11:"ArrayObject":21:{x:i:0;a:0:{};m:a:0:{}}', Opaque("custom")),
    ('E:15:"Suit:SyntheticA";', Opaque("enum")),
    ('a:2:{i:0;O:1:"A":1:{s:1:"p";a:1:{i:0;O:1:"B":0:{}}}i:1;R:2;}', {0: Opaque("object"), 1: Opaque("reference")}),
    ('a:2:{i:0;N;i:1;r:1;}', {0: None, 1: Opaque("reference")}),
], ids=["object", "empty-object", "custom-serialization", "enum", "nested-objects-and-reference", "value-reference"])
def test_objects_and_references_become_opaque_markers(text, expected):
    assert parse(text) == expected


def test_class_name_is_not_kept_anywhere_in_the_result():
    assert "SyntheticEvil" not in repr(parse('a:1:{i:0;O:13:"SyntheticEvil":1:{s:1:"p";O:13:"SyntheticEvil":0:{}}}'))


def test_string_length_counts_utf8_bytes_not_characters():
    """Długość liczona w znakach (zrzut przekodowany z latin1) nie pasuje do bajtów UTF-8: błąd, bez zgadywania."""
    assert parse('s:2:"ż";') == "ż"
    with pytest.raises(SerializedError):
        parse('s:1:"ż";')
    with pytest.raises(SerializedError):
        parse('a:1:{s:6:"zażółć";b:1;}')


@pytest.mark.parametrize("text, limits", [
    ("a:1:{i:0;" * 5 + "N;" + "}" * 5, {"max_depth": 4}),
    ("a:3:{i:0;N;i:1;N;i:2;N;}", {"max_items": 5}),
    ("a:4000000000:{", {}),
    ('s:20:"' + "x" * 20 + '";', {"max_bytes": 16}),
], ids=["depth", "items", "declared-count", "length"])
def test_limits_are_errors(text, limits):
    with pytest.raises(SerializedError):
        parse(text, **limits)


def test_default_limits_accept_a_cron_sized_value():
    entry = 'a:1:{s:32:"' + "0" * 32 + '";a:3:{s:8:"schedule";s:6:"hourly";s:4:"args";a:0:{}s:8:"interval";i:3600;}}'
    text = "a:300:{" + "".join(f'i:{1_800_000_000 + n};a:1:{{s:9:"hook_{n:04d}";{entry}}}' for n in range(300)) + "}"

    assert len(parse(text)) == 300


@pytest.mark.parametrize("build", [
    lambda: "a:1:{i:0;" * 200_000,
    lambda: 'O:1:"A":1:{s:1:"p";' * 100_000,
    lambda: "a:50000:{" + "i:0;N;" * 100_000,
    lambda: 's:999999:"' + "x" * 900_000,
    lambda: "i:" + "9" * 900_000 + ";",
], ids=["deep-arrays", "deep-objects", "many-items", "long-string-with-wrong-length", "long-number"])
def test_hostile_input_is_rejected_quickly(build):
    text = build()

    with time_limit(2), pytest.raises(SerializedError):
        parse(text)


@pytest.mark.parametrize("value, expected", [
    (True, True), (False, False), (None, False), (0, False), (1, True), ("", False), ("0", False), ("no", True),
    ({}, False), ({0: None}, True), (0.0, False), (Opaque("object"), True),
])
def test_truthiness_follows_php(value, expected):
    assert phpserialize.truthy(value) is expected
