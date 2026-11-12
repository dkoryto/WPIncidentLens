"""Ścisły parser strumieniowy zrzutu SQL (ADR 0006 pkt 1–2): gramatyka, granice porcji, liczniki pominięć, limity."""
import hashlib
import random

import pytest
from conftest import admin_sql, option_sql, time_limit, write

from wpincidentlens import ingest, sqldump

# Wszystkie konstrukcje, które łatwo przeciąć granicą porcji: łańcuchy z ucieczkami, komentarze, polecenie klienta.
TRICKY = (
    "-- header comment; INSERT INTO `x` VALUES (9,'no');\n"
    "/*!40101 SET NAMES utf8mb4 */;\n"
    "# hash comment ; still comment\n"
    "DROP TABLE IF EXISTS `wp_options`;\n"
    "CREATE TABLE `wp_options` (`option_id` bigint, `option_name` varchar(191)) ENGINE=InnoDB;\n"
    "INSERT INTO `wp_options` VALUES (1,'semi; colon','it''s \\'quoted\\' \\\\'),(2,NULL,'-- not a comment');\n"
    "insert into wp_users (`ID`, user_login) values (7,'a/*b*/c'), (8, 0x41);\n"
    "UPDATE `wp_users` SET user_pass='x';\n"
    "/*!50001 REPLACE INTO `wp_options` VALUES (3,'c','d') */;\n"
    "INSERT INTO `wp_options` VALUES (4,CONCAT('a','b'),'c'),(5,'e','f');\n"
    "SELECT 1 \\g\n;\n"
    "INSERT INTO `wp_options` VALUES (6,'cut"
).encode()


def summary(chunks):
    rows, parser = sqldump.parse(chunks)
    return (rows, parser.tables, dict(parser.unanalysed), parser.unsupported, parser.expression_rows,
            parser.truncated, parser.lossy_cells, parser.rows)


def test_tricky_dump_is_classified_statement_by_statement():
    rows, tables, unanalysed, unsupported, expressions, truncated, lossy, count = summary([TRICKY])

    assert [(table, cells) for table, _, cells, _ in rows] == [
        ("wp_options", ["1", "semi; colon", "it's 'quoted' \\"]), ("wp_options", ["2", None, "-- not a comment"]),
        ("wp_users", ["7", "a/*b*/c"]), ("wp_users", ["8", "A"]), ("wp_options", ["5", "e", "f"])]
    assert [number for *_, number in rows] == [1, 2, 3, 4, 5]
    assert unanalysed == {"UPDATE": 1, "SELECT": 1}
    assert (unsupported, expressions, truncated, lossy, count) == (2, 1, ["wp_options"], 0, 6)


def test_result_does_not_depend_on_where_the_chunks_are_split():
    whole = summary([TRICKY])

    for cut in range(len(TRICKY) + 1):
        assert summary([TRICKY[:cut], TRICKY[cut:]]) == whole, cut


def test_byte_by_byte_feeding_gives_the_same_result():
    assert summary([TRICKY[i:i + 1] for i in range(len(TRICKY))]) == summary([TRICKY])


@pytest.mark.parametrize("literal, expected", [
    ("'a\\0b'", "a\0b"), ("'\\Z\\b\\t\\r\\n'", "\x1a\b\t\r\n"), ("'50\\% \\_'", "50\\% \\_"), ("'\\q'", "q"),
    ("0x3C736372697074", "<script"), ("X'4142'", "AB"), ("x''", ""), ("0x123", "\x01#"), ("_binary 'bin'", "bin"),
    ("-12.5e-3", "-12.5e-3"), (".5", ".5"), ("null", None), ("'zażółć'", "zażółć"),
], ids=["nul", "control-escapes", "like-wildcards-keep-backslash", "unknown-escape", "hex", "x-quoted", "empty-x-quoted",
        "odd-hex-digits", "binary-introducer", "number", "leading-dot", "lowercase-null", "utf8"])
def test_literals_are_decoded_as_mysql_does(literal, expected):
    rows, _ = sqldump.parse([f"INSERT INTO `t` VALUES (1,{literal});".encode()])

    assert rows[0][2] == ["1", expected]


@pytest.mark.parametrize("sql", [
    "INSERT INTO `t` VALUES (1,NOW);", "INSERT INTO `t` VALUES (1,'a'||'b');", "INSERT INTO `t` VALUES (1,0x4G);",
    "INSERT INTO `t` VALUES (1,12abc);", "INSERT INTO `t` VALUES (1,@var);",
], ids=["bare-word", "operator", "bad-hex", "number-glued-to-word", "variable"])
def test_non_literal_cell_skips_the_row_not_silently(sql):
    rows, parser = sqldump.parse([sql.encode()])

    assert rows == [] and parser.expression_rows + parser.unsupported == 1


@pytest.mark.parametrize("sql", [
    "INSERT IGNORE INTO `t` VALUES (1);", "INSERT INTO db.t VALUES (1);", "INSERT INTO `db`.`t` VALUES (1);",
    "INSERT INTO `t` SET a=1;", "INSERT INTO `t` (`a`,`b`(3)) VALUES (1,2);", "INSERT INTO `t` (a b) VALUES (1);",
    "INSERT INTO `a-b` VALUES (1);", 'INSERT INTO "t" VALUES (1);', "INSERT INTO `t` SELECT * FROM u;",
    "REPLACE INTO `t` VALUES (1);", "DELIMITER ;;",
], ids=["ignore", "qualified", "qualified-quoted", "set", "nested-parenthesis-in-columns", "columns-without-comma",
        "name-outside-charset", "double-quoted-name", "insert-select", "replace", "delimiter"])
def test_statement_outside_the_grammar_is_counted_as_unsupported(sql):
    rows, parser = sqldump.parse([sql.encode()])

    assert rows == [] and parser.unsupported == 1 and not parser.unanalysed


@pytest.mark.parametrize("sql", [
    "SET NAMES utf8;", "LOCK TABLES `t` WRITE;", "UNLOCK TABLES;", "CREATE DATABASE x;", "ALTER TABLE t DISABLE KEYS;",
    "/*!40000 ALTER TABLE `t` ENABLE KEYS */;", "-- only a comment\n;", "START TRANSACTION;", "USE `db`;", ";;",
])
def test_inert_statements_leave_no_trace(sql):
    assert summary([sql.encode()])[2:6] == ({}, 0, 0, [])


def test_rows_of_unwanted_tables_are_checked_and_numbered_but_not_decoded():
    sql = (admin_sql("siteadmin") + "INSERT INTO `wp_postmeta` VALUES (1,2,'k','v'),(2,2,'k',CONCAT('a'));\n"
           + option_sql("blogname", "x")).encode()

    rows, parser = sqldump.parse([sql], wanted=lambda table: table != "wp_postmeta")

    assert {table for table, *_ in rows} == {"wp_users", "wp_usermeta", "wp_options"}
    assert rows[-1][3] == 5 and parser.rows == 5 and parser.expression_rows == 1
    assert "wp_postmeta" in parser.tables


def test_invalid_utf8_cell_is_decoded_with_replacement_and_counted():
    rows, parser = sqldump.parse([b"INSERT INTO `t` VALUES (1,'a\xffb'),(2,'ok');"])

    assert rows[0][2] == ["1", "a\ufffdb"] and parser.lossy_cells == 1


def test_statement_over_the_limit_stops_the_parser_with_its_offset():
    parser = sqldump.DumpParser(max_statement=64)
    rows = parser.feed(b"INSERT INTO `t` VALUES (1,'a');\n" + b"INSERT INTO `t` VALUES ('" + b"x" * 100)
    rows += parser.feed(b"');\nINSERT INTO `t` VALUES (2,'b');")
    rows += parser.close()

    assert [cells for *_, cells, _ in rows] == [["1", "a"]]
    assert parser.oversized_at == 31  # zaraz po średniku poprzedniej instrukcji


def test_buffer_never_holds_more_than_one_statement_and_one_chunk():
    parser = sqldump.DumpParser()
    statement = b"INSERT INTO `t` VALUES " + b",".join(b"(%d,'v')" % n for n in range(2000)) + b";\n"
    for _ in range(50):
        parser.feed(statement)
        assert len(parser._buf) <= 2 * len(statement)
    assert parser.rows == 100_000


def test_truncated_statement_with_many_unclosed_executable_comments_is_classified_in_linear_time():
    """Regresja (fuzz T-601): ``_unwrap`` szukał ``*/`` od każdego ``/*`` do końca tekstu; 400 KB trwało minuty."""
    with time_limit(5):
        _, parser = sqldump.parse([b"/*!40101 /*!40101 ''" * 20_000])

    assert parser.truncated == ["?"]


@pytest.mark.parametrize("sql", [
    b"/*!40101 SET NAMES utf8mb4 /* */ , sql_mode='ANSI_QUOTES' */;",
    b"/*!40101 DROP TABLE IF EXISTS `t` /* */ UPDATE wp_users SET user_pass='x' /* c */;",
    b"/*!40101 LOCK TABLES `t` WRITE # c */;",
    b"/*!40101 DROP TABLE `t` -- c\n */;",
], ids=["hidden-sql-mode", "hidden-update", "hash-comment-inside", "dash-comment-inside"])
def test_comment_left_open_by_an_executable_comment_makes_the_statement_unsupported_not_inert(sql):
    """Regresja (przegląd T-601): komentarz z wnętrza ``/*!…*/`` (``/*`` niedomknięte, ``#``, ``--``) zostaje po rozwinięciu;
    instrukcji nie wolno wtedy sklasyfikować jako obojętnej: klasyfikator widziałby co innego niż serwer."""
    _, parser = sqldump.parse([sql])

    assert parser.unsupported >= 1 and parser.mode_change_at is None


def test_seeded_mutation_fuzz_never_crashes_and_keeps_counters_consistent():
    """Deterministyczny fuzz: losowe wycięcia, wstawki i podmiany bajtów w poprawnym zrzucie (DoD #7)."""
    base = (admin_sql("siteadmin", "ghost") + option_sql("cron", 'a:1:{i:1;a:0:{}}')).encode() + TRICKY
    alphabet = b"'\"`\\;()-#/*!\n ,0xINSERTVALUES\xff\x00"
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
            whole, split = summary([bytes(data)]), summary([bytes(data[:cut]), bytes(data[cut:])])
            assert whole == split
            rows, *_ , count = whole
            assert all(isinstance(cell, (str, type(None))) for row in rows for cell in row[2])
            assert len(rows) <= count


def test_secure_ingest_feeds_the_sink_with_exactly_the_hashed_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest, "CHUNK_BYTES", 7)
    content = admin_sql("siteadmin").encode() * 3
    dump = write(tmp_path / "db.sql", content)
    seen: list[bytes] = []

    item = ingest.Session().read_file(dump, "database", keep_limit=0, sink=seen.append)

    assert b"".join(seen) == content and max(map(len, seen)) == 7
    assert item.sha256 == hashlib.sha256(content).hexdigest() and item.content is None


def test_secure_ingest_does_not_call_the_sink_for_a_file_it_skips(tmp_path):
    dump = write(tmp_path / "db.sql", "INSERT INTO `t` VALUES (1);")
    seen: list[bytes] = []

    item = ingest.Session(ingest.Limits(max_file_bytes=5)).read_file(dump, "database", sink=seen.append)

    assert seen == [] and item.sha256 is None


def test_rows_waiting_for_the_rules_are_capped_by_size_with_a_gap(site, evidence, analyze, monkeypatch):
    from wpincidentlens import database
    monkeypatch.setattr(database, "MAX_ROW_BYTES", 1600)  # dwa wiersze konta mieszczą się, opcja nie
    dump = write(evidence / "db.sql", admin_sql("siteadmin") + option_sql("blogname", "x" * 500))

    run = analyze(site, database=dump, known_admins=("siteadmin",))

    assert run.has_gap("Reguły objęły 2 z 3 wierszy") and run.coverage("database")["status"] == "PARTIAL"
