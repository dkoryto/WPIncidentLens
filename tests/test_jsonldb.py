"""Adapter eksportu JSONL (ADR 0006 pkt 9): ścisły kontrakt wiersza, powody odrzucenia, granice porcji, limity."""
import json
import random

import pytest
from conftest import ADMIN_CAPS, admin_sql, case_schema_errors, time_limit, write

from wpincidentlens import case, dbrules, jsonldb


def line(table: str, **row) -> str:
    return json.dumps({"table": table, "row": row}, ensure_ascii=False) + "\n"


def admin_jsonl(*logins: str, caps: str = ADMIN_CAPS, prefix: str = "wp_") -> str:
    """Odpowiednik ``admin_sql``: każdy login dostaje wiersz users i usermeta z rolą."""
    users = "".join(line(f"{prefix}users", ID=n, user_login=login, user_registered="2026-01-01 00:00:00")
                    for n, login in enumerate(logins, start=1))
    meta = "".join(line(f"{prefix}usermeta", umeta_id=n, user_id=n, meta_key=f"{prefix}capabilities", meta_value=caps)
                   for n, _ in enumerate(logins, start=1))
    return users + meta


# Każdy powód odrzucenia i każdy przypadek graniczny akceptacji, w jednym pliku.
MIXED = (
    line("wp_options", option_id=1, option_name="blogname", option_value="zażółć \"q\" \\ ;", autoload=None)
    + '{"table":"wp_users","row":{"ID":12345678901234567890123,"user_login":"a","score":-1.5e-3}}\r\n'
    + "   \t\n"
    + '{"table":"wp_users","row":{"ID":1,"ID":2}}\n'
    + '{"table":"wp_users","row":{"ID":true}}\n'
    + '{"table":"wp_users","row":{"ID":NaN}}\n'
    + '{"table":"wp_users","row":{"ID":[1]}}\n'
    + '{"table":"wp_users","row":{"ID":{"a":1}}}\n'
    + '{"table":"wp_users","row":{"ID":"\\ud800"}}\n'
    + '{"table":"wp-users","row":{"ID":1}}\n'
    + '{"table":"wp_users","row":{"user login":"x"}}\n'
    + '{"table":"wp_users","row":{"ID":1},"extra":1}\n'
    + '{"table":"wp_users","row":{}}\n'
    + '["wp_users",{"ID":1}]\n'
    + "INSERT INTO `wp_users` VALUES (1,'x');\n"
).encode() + b'{"table":"wp_users","row":{"user_login":"\xff"}}\n' + line("wp_postmeta", meta_id=1).encode() + (
    '{"table":"wp_options","row":{"option_name":"last","option_value":"no newline"}}').encode()


def summary(chunks, wanted=dbrules.is_core_table):
    parser = jsonldb.JsonlParser(wanted=wanted)
    rows = [row for chunk in chunks for row in parser.feed(chunk)] + parser.close()
    return rows, parser.rows, parser.tables, dict(parser.rejected), dict(parser.first_rejected)


def test_mixed_file_returns_valid_rows_and_counts_every_rejection_by_reason():
    rows, count, tables, rejected, first = summary([MIXED])

    assert [(table, columns, cells, number) for table, columns, cells, number in rows] == [
        ("wp_options", ["option_id", "option_name", "option_value", "autoload"], ["1", "blogname", 'zażółć "q" \\ ;', None], 1),
        ("wp_users", ["ID", "user_login", "score"], ["12345678901234567890123", "a", "-1.5e-3"], 2),
        ("wp_options", ["option_name", "option_value"], ["last", "no newline"], 18)]
    assert count == 4 and tables == {"wp_options", "wp_users", "wp_postmeta"}  # wp_postmeta: sprawdzony i policzony, nie oddany
    assert rejected == {"duplicate_key": 1, "bad_value": 5, "bad_name": 2, "shape": 3, "not_json": 1, "not_utf8": 1}
    assert first == {"duplicate_key": 4, "bad_value": 5, "bad_name": 10, "shape": 12, "not_json": 15, "not_utf8": 16}


@pytest.mark.parametrize("text, reason", [
    ('{"table":"t","row":{"a":1}', "not_json"), ("{'table':'t'}", "not_json"), ('\ufeff{"table":"t","row":{"a":1}}', "not_json"),
    ('{"table":"t","row":{"a":1}} {"table":"t","row":{"a":2}}', "not_json"), ("[" * 100_000 + "]" * 100_000, "not_json"),
    ('{"table":"t","row":{"a":' + "[" * 100_000 + "]" * 100_000 + "}}", "not_json"),
    ('{"table":"t","row":{"a":{"b":1,"b":2}}}', "duplicate_key"), ('{"table":"t","table":"t","row":{"a":1}}', "duplicate_key"),
    ('{"table":"t","row":{"a":false}}', "bad_value"), ('{"table":"t","row":{"a":null,"b":-Infinity}}', "bad_value"),
    ('{"table":"t","row":{"a":Infinity}}', "bad_value"), ('{"table":"t","row":{"a":"\\udfff"}}', "bad_value"),
    ('{"table":"","row":{"a":1}}', "bad_name"), ('{"table":"' + "t" * 65 + '","row":{"a":1}}', "bad_name"),
    ('{"table":"db.t","row":{"a":1}}', "bad_name"), ('{"table":"t","row":{"ą":1}}', "bad_name"),
    ('{"table":"t\\n","row":{"a":1}}', "bad_name"), ('{"table":1,"row":{"a":1}}', "shape"),
    ('{"table":"t","row":[1]}', "shape"), ('{"row":{"a":1}}', "shape"), ('"text"', "shape"), ("null", "shape"),
], ids=["unterminated", "single-quotes", "bom", "two-objects", "deep-array", "deep-value", "duplicate-nested", "duplicate-top",
        "boolean", "minus-infinity", "infinity", "lone-surrogate", "empty-name", "long-name", "dotted-name", "non-ascii-column",
        "newline-in-name", "table-not-string", "row-not-object", "no-table", "string", "null"])
def test_line_outside_the_contract_is_rejected_with_its_reason(text, reason):
    rows, count, _, rejected, _ = summary([text.encode() + b"\n"])

    assert (rows, count, rejected) == ([], 0, {reason: 1})


def test_numbers_keep_their_json_text_beyond_the_integer_digit_limit():
    digits = "9" * 50_000
    rows, *_ = summary([f'{{"table":"t","row":{{"a":{digits},"b":1E+400,"c":-0.0}}}}\n'.encode()], wanted=None)

    assert rows[0][2] == [digits, "1E+400", "-0.0"]


def test_vertical_tab_line_is_rejected_not_ignored_as_blank():
    assert summary([b"\x0b\n \r\n\n"])[3] == {"not_json": 1}


def test_result_does_not_depend_on_where_the_chunks_are_split():
    whole = summary([MIXED])

    for cut in range(len(MIXED) + 1):
        assert summary([MIXED[:cut], MIXED[cut:]]) == whole, cut


def test_byte_by_byte_feeding_gives_the_same_result():
    assert summary([MIXED[i:i + 1] for i in range(len(MIXED))]) == summary([MIXED])


def test_line_over_the_limit_is_skipped_to_the_next_newline_with_a_bounded_buffer():
    parser = jsonldb.JsonlParser(max_line=64)
    chunk = b"x" * 50
    rows = parser.feed(line("t", a=1).encode() + b'{"table":"t","row":{"a":"')
    for _ in range(100):
        rows += parser.feed(chunk)
        assert len(parser._buf) <= 64
    rows += parser.feed(b'"}}\n' + line("t", a=2).encode() + b"y" * 70)
    rows += parser.close()

    assert [(cells, number) for *_, cells, number in rows] == [(["1"], 1), (["2"], 3)]
    assert parser.rejected == {"too_long": 2} and parser.first_rejected == {"too_long": 2}


def test_line_exactly_at_the_limit_is_accepted():
    text = line("t", a="x" * 30).encode()
    parser = jsonldb.JsonlParser(max_line=len(text) - 1)  # bez znaku końca wiersza

    assert len(parser.feed(text)) == 1 and not parser.rejected


def test_buffer_never_holds_more_than_one_line_and_one_chunk():
    parser = jsonldb.JsonlParser()
    chunk = "".join(line("wp_options", option_id=n, option_name="k", option_value="v" * 40) for n in range(2000)).encode()
    for _ in range(50):
        parser.feed(chunk[:-7])
        parser.feed(chunk[-7:])
        assert len(parser._buf) <= len(chunk)
    assert parser.rows == 100_000


def test_table_names_are_bounded():
    parser = jsonldb.JsonlParser(wanted=lambda table: False)
    parser.feed("".join(line(f"t{n}", a=1) for n in range(jsonldb.MAX_TABLES + 10)).encode())

    assert len(parser.tables) == jsonldb.MAX_TABLES and parser.rows == jsonldb.MAX_TABLES + 10


def test_seeded_mutation_fuzz_never_crashes_and_keeps_counters_consistent():
    """Deterministyczny fuzz: losowe wycięcia, wstawki i podmiany bajtów w poprawnym pliku JSONL."""
    base = (admin_jsonl("siteadmin", "ghost") + line("wp_options", option_name="cron", option_value="a:0:{}")).encode() + MIXED
    alphabet = b'{}[]":,\\ntrue1.eE-+\r\n \xff\x00\xc3'
    generator = random.Random(20261112)
    with time_limit(20):
        for _ in range(1500):
            data = bytearray(base)
            for _ in range(generator.randint(1, 8)):
                at = generator.randrange(len(data) + 1)
                action = generator.randrange(3)
                if action == 0:
                    del data[at:at + generator.randint(1, 20)]
                elif action == 1:
                    data[at:at] = bytes(generator.choice(alphabet) for _ in range(generator.randint(1, 6)))
                elif at < len(data):
                    data[at] = generator.choice(alphabet)
            cut = generator.randrange(len(data) + 1)
            whole = summary([bytes(data)])
            assert whole == summary([bytes(data[:cut]), bytes(data[cut:])])
            rows, count, *_ = whole
            assert all(isinstance(cell, (str, type(None))) for row in rows for cell in row[2])
            assert all(cell is None or cell.encode("utf-8") is not None for row in rows for cell in row[2])
            assert len(rows) <= count


# --- cały przebieg: --database-format jsonl ---------------------------------------------------------

JSONL = ("--database-format", "jsonl")


@pytest.fixture
def scan_jsonl(site, evidence, analyze):
    def run(text: str | bytes, **options):
        return analyze(site, database=write(evidence / "db.jsonl", text), flags=JSONL, **options)
    return run


def test_unknown_administrator_from_jsonl_rows_is_unrecognized(scan_jsonl):
    run = scan_jsonl(admin_jsonl("siteadmin", "newadmin"), known_admins=("siteadmin",))

    assert run.rules == {"UNRECOGNIZED_ADMIN"}
    flagged = run.finding("UNRECOGNIZED_ADMIN")
    assert flagged["metadata"]["username"] == "newadmin" and flagged["source"] == "wp_usermeta:wp_capabilities"
    assert run.coverage("database")["status"] == "ANALYZED"
    assert run.case["sources"]["database"] == {"provided": True, "name": "db.jsonl", "format": "jsonl"}


def test_without_a_trusted_list_an_administrator_is_inventory_not_a_finding(scan_jsonl):
    """Fałszywy alarm, którego unikamy: bez listy porównawczej nie ma ustalenia „nowy administrator”."""
    run = scan_jsonl(admin_jsonl("siteadmin", "newadmin"))

    assert run.findings == []
    assert sorted(item["attributes"]["username"] for item in run.report["observations"]
                  if item["kind"] == "ADMINISTRATOR_ACCOUNT") == ["newadmin", "siteadmin"]


def test_file_with_only_rejected_lines_is_failed_and_inconclusive(scan_jsonl):
    run = scan_jsonl('{"table":"wp_users","row":{"ID":true}}\nnot json\n')

    assert run.coverage("database")["status"] == "FAILED" and run.report["assessment"] == "INCONCLUSIVE"
    assert run.has_gap("Pominięto 2 wierszy JSONL") and run.has_gap("nie zawiera żadnego wiersza zgodnego z kontraktem")


def test_partly_rejected_file_is_partial_with_counts_per_reason(scan_jsonl):
    run = scan_jsonl(admin_jsonl("siteadmin") + "{bad\n" + '{"table":"wp_users","row":{"ID":[1]}}\n' + "{also bad\n",
                     known_admins=("siteadmin",))

    assert run.coverage("database")["status"] == "PARTIAL" and run.rules == set()
    assert run.has_gap("Pominięto 3 wierszy JSONL niezgodnych z kontraktem: niepoprawny JSON ×2 (pierwszy: wiersz 3), "
                       "wartość inna niż łańcuch, liczba lub null ×1 (pierwszy: wiersz 4)")


def test_sql_dump_given_as_jsonl_is_not_parsed_as_sql(scan_jsonl):
    run = scan_jsonl(admin_sql("siteadmin", "newadmin"), known_admins=("siteadmin",))

    assert run.rules == set() and run.coverage("database")["status"] == "FAILED"
    assert run.has_gap("Pominięto 2 wierszy JSONL niezgodnych z kontraktem: niepoprawny JSON ×2")


def test_jsonl_without_wordpress_tables_is_failed(scan_jsonl):
    run = scan_jsonl(line("wp_posts", ID=1, post_title="x"))

    assert run.coverage("database")["status"] == "FAILED"
    assert run.has_gap("nie zawiera odczytanych wierszy tabel *_users, *_usermeta ani *_options")


def test_jsonl_coverage_describes_the_jsonl_contract_not_the_sql_grammar(scan_jsonl):
    reasons = scan_jsonl(admin_jsonl("siteadmin"), known_admins=("siteadmin",)).coverage("database")["reasons"]

    assert any("JSONL" in reason and '"table"' in reason for reason in reasons)
    assert not any("INSERT" in reason for reason in reasons)


def test_default_format_is_sql_and_is_recorded(site, evidence, analyze):
    run = analyze(site, database=write(evidence / "db.sql", admin_sql("siteadmin")), known_admins=("siteadmin",))

    assert run.coverage("database")["status"] == "ANALYZED"
    assert run.case["sources"]["database"] == {"provided": True, "name": "db.sql", "format": "sql"}


def test_unknown_database_format_is_refused(site, refuse):
    assert "--database-format" in refuse("--files", str(site), "--database-format", "csv")


def test_case_build_refuses_an_unknown_database_format(site, tmp_path):
    with pytest.raises(case.CaseError, match="--database-format"):
        case.build(files=site, output=tmp_path / "out", case_id="T301-SYNTH", database_format="csv")


@pytest.mark.parametrize("database, valid", [
    ({"provided": True, "name": "db.sql"}, True), ({"provided": True, "name": "db.jsonl", "format": "jsonl"}, True),
    ({"provided": True, "name": "db.csv", "format": "csv"}, False), ({"provided": False, "name": None, "format": "sql"}, False),
    ({"provided": True, "name": "db.sql", "format": "sql", "path": "x"}, False),
], ids=["without-format-as-before", "jsonl", "unknown-format", "format-without-database", "unknown-field"])
def test_case_schema_pins_the_database_format(site, evidence, analyze, database, valid):
    record = analyze(site, database=write(evidence / "db.sql", admin_sql("siteadmin"))).case
    record["sources"]["database"] = database

    assert (case_schema_errors(record) == []) is valid
