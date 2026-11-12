"""Próby ukrycia zapisu przed parserem SQL (przegląd bezpieczeństwa T-301): każda musi obniżyć pokrycie albo zostać odczytana.

Zrzut kontroluje atakujący, który przejął witrynę. Serwer MySQL/MariaDB wykonałby te instrukcje jako zapis
do tabel rdzenia; parser nie może ich uznać za obojętne.
"""
import pytest
from conftest import admin_sql, write

from wpincidentlens import jsonldb, sqldump

CAPS = "a:1:{s:13:\\\"administrator\\\";b:1;}"
META = f"(9,2,'wp_capabilities','{CAPS}')"

# Typowy nagłówek i definicja tabeli z mysqldump 8: nie może zostawić żadnego śladu.
MYSQLDUMP = f"""/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
SET @@SESSION.SQL_LOG_BIN= 0;
SET @@GLOBAL.GTID_PURGED=/*!80000 '+'*/ '00000000-0000-0000-0000-000000000000:1-5';
DROP TABLE IF EXISTS `wp_usermeta`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `wp_usermeta` (
  `umeta_id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint unsigned NOT NULL DEFAULT '0',
  `meta_key` varchar(255) COLLATE utf8mb4_unicode_520_ci DEFAULT NULL,
  `meta_value` longtext COLLATE utf8mb4_unicode_520_ci,
  PRIMARY KEY (`umeta_id`),
  KEY `user_id` (`user_id`),
  KEY `meta_key` (`meta_key`(191))
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
LOCK TABLES `wp_usermeta` WRITE;
/*!40000 ALTER TABLE `wp_usermeta` DISABLE KEYS */;
INSERT INTO `wp_usermeta` VALUES {META};
/*!40000 ALTER TABLE `wp_usermeta` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;
"""


def test_mysqldump_header_and_table_definition_leave_no_trace():
    rows, parser = sqldump.parse([MYSQLDUMP.encode()])

    assert (dict(parser.unanalysed), parser.unsupported, parser.mode_change_at) == ({}, 0, None)
    assert rows[0][1] == ["umeta_id", "user_id", "meta_key", "meta_value"]


@pytest.mark.parametrize("sql, keyword", [
    (f"SET STATEMENT max_statement_time=0 FOR INSERT INTO wp_usermeta VALUES {META};", "SET"),
    ("SET @a = (SELECT 1);", "SET"),
    (f"CREATE TABLE wp_usermeta (umeta_id int, user_id int, meta_key text, meta_value text) SELECT 9, 2, 'wp_capabilities', '{CAPS}';",
     "CREATE TABLE"),
    ("CREATE TABLE wp_usermeta AS SELECT * FROM decoy;", "CREATE TABLE"),
    ("CREATE TABLE wp_usermeta LIKE decoy;", "CREATE TABLE"),
    ("CREATE TABLE wp_usermeta (a int) ENGINE=MERGE UNION=(decoy) INSERT_METHOD=LAST;", "CREATE TABLE"),
    ("CREATE TABLE wp_usermeta (meta_value text GENERATED ALWAYS AS ('x'));", "CREATE TABLE"),
    ("CREATE TEMPORARY TABLE t (a int);", "CREATE TEMPORARY"),
    ("ALTER TABLE wp_usermetx RENAME TO wp_usermeta;", "ALTER TABLE"),
    ("ALTER TABLE wp_usermeta ADD COLUMN x int DEFAULT 1;", "ALTER TABLE"),
    ("/*!UPDATE wp_usermeta SET user_id=2 WHERE umeta_id=1*/;", "UPDATE"),
    ("/*M!100100 DELETE FROM wp_users */;", "DELETE"),
    ("/*!50003 CREATE TRIGGER t BEFORE UPDATE ON wp_users FOR EACH ROW SET NEW.user_pass='x' */;", "CREATE TRIGGER"),
    ("/*!40101 PREPARE s FROM 'x' */;", "PREPARE"),
    (f"BEGIN NOT ATOMIC INSERT INTO wp_usermeta VALUES {META};", "BEGIN"),
    ("LOCK TABLES t WRITE, (SELECT 1);", "LOCK"),
], ids=["set-statement-for", "set-subquery", "create-table-select", "create-table-as", "create-table-like", "merge-engine",
        "generated-column", "temporary-table", "alter-rename", "alter-add-column", "executable-update",
        "mariadb-executable-delete", "executable-trigger", "executable-prepare", "begin-not-atomic", "lock-with-parenthesis"])
def test_hidden_write_is_counted_as_unanalysed(sql, keyword):
    _, parser = sqldump.parse([sql.encode()])

    assert parser.unanalysed[keyword] == 1


def test_executable_comment_with_insert_is_unsupported():
    _, parser = sqldump.parse([f"/*!50001 INSERT INTO wp_usermeta VALUES {META} */;".encode()])

    assert parser.unsupported == 1


def test_double_dash_before_a_control_character_starts_a_comment_as_on_the_server():
    sql = f"SET @x=1 --\x01 '\n;INSERT INTO wp_usermeta VALUES {META};\n--\x01 ';"

    rows, parser = sqldump.parse([sql.encode()])

    assert [table for table, *_ in rows] == ["wp_usermeta"] and not parser.unanalysed


@pytest.mark.parametrize("statement, change", [
    ("SET sql_mode='NO_BACKSLASH_ESCAPES';", "NO_BACKSLASH_ESCAPES"),
    ("SET SESSION sql_mode = 'STRICT_ALL_TABLES,ANSI_QUOTES';", "ANSI_QUOTES"),
    ("SET @@sql_mode='ANSI';", "ANSI"),
    ("/*!40101 SET SQL_MODE='ANSI' */;", "ANSI"),
    ("SET NAMES gbk;", "gbk"),
    ("/*!40101 SET NAMES 'big5' */;", "big5"),
    ("SET CHARACTER SET sjis;", "sjis"),
    ("SET character_set_client = cp932;", "cp932"),
], ids=["no-backslash-escapes", "ansi-quotes", "ansi", "ansi-in-executable-comment", "names-gbk", "names-big5",
        "character-set", "character-set-client"])
def test_session_change_of_string_reading_stops_the_analysis(statement, change):
    hidden = f"INSERT INTO wp_options VALUES (5,'x','no','\\');INSERT INTO wp_usermeta VALUES {META};-- ');"

    rows, parser = sqldump.parse([f"INSERT INTO t VALUES (1);\n{statement}\n{hidden}".encode()])

    assert change in parser.mode_change and parser.mode_change_at == len("INSERT INTO t VALUES (1);")
    assert [table for table, *_ in rows] == ["t"]


def test_insert_value_that_contains_an_executable_comment_marker_is_still_data():
    rows, parser = sqldump.parse([b"INSERT INTO `wp_posts` VALUES (1,'/*! jQuery v3 | (c) */ x');"])

    assert rows[0][2] == ["1", "/*! jQuery v3 | (c) */ x"] and parser.unsupported == 0


def test_unanalysed_keywords_are_capped():
    sql = "".join(f"w{chr(97 + n % 26)}{chr(97 + n // 26 % 26)};" for n in range(500)).encode()

    _, parser = sqldump.parse([sql])

    assert len(parser.unanalysed) == sqldump.MAX_UNANALYSED_KEYS + 1 and parser.unanalysed["(inne)"] == 300


# --- przez CLI: wiązanie kolumn i nazwy tabel -----------------------------------------------------

USERS = "INSERT INTO `wp_users` (`ID`,`user_login`) VALUES (1,'siteadmin'),(2,'ghost');\n"
KNOWN = "INSERT INTO `wp_usermeta` VALUES (1,1,'wp_capabilities','a:1:{s:13:\\\"administrator\\\";b:1;}');\n"


@pytest.mark.parametrize("ghost", [
    "INSERT INTO `wp_usermeta` (umeta_id,user_id,META_KEY,Meta_Value) VALUES " + META + ";\n",
    "CREATE TABLE `wp_usermeta` (`umeta_id` int, `meta_value` text, `meta_key` text, `user_id` int);\n"
    f"INSERT INTO `wp_usermeta` VALUES (9,'{CAPS}','wp_capabilities',2);\n",
], ids=["upper-case-columns", "reordered-table-definition"])
def test_admin_is_found_whatever_the_column_spelling_or_order(site, evidence, analyze, ghost):
    run = analyze(site, database=write(evidence / "db.sql", USERS + KNOWN + ghost), known_admins=("siteadmin",))

    assert run.finding("UNRECOGNIZED_ADMIN")["metadata"]["username"] == "ghost"


def test_row_without_a_column_the_rules_need_is_a_gap(site, evidence, analyze):
    ghost = "INSERT INTO `wp_usermeta` (umeta_id,user_id,meta_key) VALUES (9,2,'wp_capabilities');\n"

    run = analyze(site, database=write(evidence / "db.sql", USERS + KNOWN + ghost), known_admins=("siteadmin",))

    assert run.has_gap("bez kolumny potrzebnej regułom") and run.coverage("database")["status"] == "PARTIAL"


def test_table_that_differs_from_a_core_table_only_in_case_is_a_gap(site, evidence, analyze):
    ghost = f"INSERT INTO `WP_USERMETA` VALUES {META};\n"

    run = analyze(site, database=write(evidence / "db.sql", admin_sql("siteadmin") + ghost), known_admins=("siteadmin",))

    assert run.has_gap("tylko wielkością liter (WP_USERMETA)") and run.coverage("database")["status"] == "PARTIAL"


def test_session_mode_change_is_a_gap_in_the_report(site, evidence, analyze):
    sql = admin_sql("siteadmin") + "SET sql_mode='NO_BACKSLASH_ESCAPES';\n" + f"INSERT INTO `wp_usermeta` VALUES {META};\n"

    run = analyze(site, database=write(evidence / "db.sql", sql), known_admins=("siteadmin",))

    assert run.has_gap("sql_mode NO_BACKSLASH_ESCAPES") and run.report["assessment"] == "INCONCLUSIVE"


def test_jsonl_row_with_too_many_columns_is_rejected():
    row = ", ".join(f'"c{n}": 1' for n in range(jsonldb.MAX_COLUMNS + 1))
    parser = jsonldb.JsonlParser()

    parser.feed(('{"table": "wp_options", "row": {' + row + "}}\n").encode())

    assert parser.rejected == {"shape": 1}
