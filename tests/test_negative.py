"""Scenariusze negatywne N1–N8 (rozdz. 14.2) oraz luki pokrycia: brak alertu nigdy nie znaczy „czysto”."""
import os
import re

import pytest
from conftest import UPLOAD_PHP, access_line, admin_sql, option_sql, sha256, write

from wptrace.cli import main

ANALYTICS = '<script async src="https://www.googletagmanager.com/gtag/js?id=G-SYNTHETIC0"></script>'
FOREIGN_SQL = {
    "postgres-copy": "COPY wp_users (id, user_login) FROM stdin;\n1\tsiteadmin\n\\.\n",
    "double-quoted-identifiers": 'INSERT INTO "wp_users" ("ID","user_login") VALUES (1,\'siteadmin\');\n',
    "binary-garbage": b"\x00\x01\x02SQLite format 3\x00\xff\xfe",
    "empty-file": "",
}


# --- N1–N5: legalny materiał nie może dawać mocnych alarmów -------------------------------------

def test_n1_clean_site_with_matching_manifest_has_no_findings(site, evidence, analyze):
    core = write(site / "wp-includes" / "version.php")
    database = write(evidence / "db.sql", admin_sql("siteadmin") + option_sql("blogname", "Synthetic Site"))
    logs = write(evidence / "logs" / "access.log", access_line("/about/")).parent
    baseline = {"files": {"index.php": sha256(site / "index.php"), "wp-includes/version.php": sha256(core)},
                "known_admins": ["siteadmin"]}

    run = analyze(site, database=database, logs=logs, baseline=baseline)

    assert run.findings == []
    assert run.report["assessment"] == "NO_INDICATORS_IN_ANALYZED_SCOPE"


def test_n2_analytics_snippet_in_theme_file_raises_nothing(site, analyze):
    write(site / "wp-content" / "themes" / "demo" / "header.php", f"<?php // synthetic ?>\n{ANALYTICS}\n")

    assert analyze(site).findings == []


def test_n2_analytics_snippet_in_option_is_only_a_low_confidence_review_item(site, evidence, analyze):
    """Znany false positive: każdy <script> w opcji daje ustalenie, ale nie alarm wysokiej wagi."""
    database = write(evidence / "db.sql", option_sql("header_scripts", ANALYTICS))

    run = analyze(site, database=database)

    assert [(item["rule"], item["severity"], item["confidence"]) for item in run.findings] == [("SUSPICIOUS_DB_MARKUP", "medium", "low")]


def test_n3_admin_without_trusted_list_is_a_gap_not_an_alert(site, evidence, analyze):
    database = write(evidence / "db.sql", admin_sql("siteadmin"))

    run = analyze(site, database=database)

    assert run.findings == []
    assert run.has_gap("brak wiarygodnej listy porównawczej")


@pytest.mark.xfail(strict=True, reason="raport nie zawiera inwentarza kont administratorów (#7)")
def test_n3_admin_without_trusted_list_appears_in_inventory(site, evidence, analyze):
    database = write(evidence / "db.sql", admin_sql("siteadmin"))

    assert "siteadmin" in analyze(site, database=database).json_text


@pytest.mark.parametrize("trusted", [{"known_admins": ("siteadmin",)}, {"baseline": {"files": {}, "known_admins": ["siteadmin"]}}],
                         ids=["cli-flag", "baseline-list"])
def test_trusted_admin_is_not_flagged(site, evidence, analyze, trusted):
    database = write(evidence / "db.sql", admin_sql("siteadmin"))

    assert analyze(site, database=database, **trusted).findings == []


def test_n4_updated_plugin_is_a_medium_review_item_not_an_exploit(site, analyze):
    write(site / "wp-content" / "plugins" / "demo" / "demo.php")

    run = analyze(site, baseline={"files": {"wp-content/plugins/demo/demo.php": "0" * 64}})

    changed = run.finding("BASELINE_FILE_CHANGED")
    assert changed["severity"] == "medium"
    assert "zmiana nie przesądza o ataku" in changed["explanation"]
    assert len(run.findings) == 1


def test_n5_harmless_php_in_uploads_is_heuristic_not_strong_evidence(site, analyze):
    write(site / UPLOAD_PHP)

    run = analyze(site)

    unusual = run.finding("EXECUTABLE_IN_UPLOADS")
    assert unusual["confidence"] == "medium"
    assert "wymaga analizy kontekstu" in unusual["explanation"]
    assert len(run.findings) == 1


# --- N6: brakujące źródła -----------------------------------------------------------------------

@pytest.mark.parametrize("given, expected_gaps", [
    ({"logs"}, ["Brak zrzutu bazy danych"]),
    ({"database"}, ["Brak logów HTTP"]),
    (set(), ["Brak zrzutu bazy danych", "Brak logów HTTP"]),
], ids=["no-database", "no-logs", "neither"])
def test_n6_missing_source_is_reported_as_coverage_gap(site, evidence, analyze, given, expected_gaps):
    sources = {"database": write(evidence / "db.sql", admin_sql("siteadmin")),
               "logs": write(evidence / "logs" / "access.log", access_line("/")).parent}

    run = analyze(site, **{name: path for name, path in sources.items() if name in given})

    assert set(expected_gaps) <= set(run.gaps)
    assert "Brak alertów nie dowodzi braku włamania" in run.html


def test_n6_missing_database_and_logs_is_inconclusive(site, analyze):
    assert analyze(site).report["assessment"] == "INCONCLUSIVE"


@pytest.mark.parametrize("source", ["logs", "site"])
def test_empty_source_directory_is_reported_as_coverage_gap(evidence, analyze, source):
    populated = {"site": write(evidence / "site" / "index.php").parent,
                 "logs": write(evidence / "logs" / "access.log", access_line("/")).parent}
    empty = evidence / "empty"
    empty.mkdir()

    reference = analyze(**populated)
    run = analyze(**{**populated, source: empty})

    assert set(run.gaps) > set(reference.gaps)


# --- N7: czas -----------------------------------------------------------------------------------

@pytest.mark.parametrize("stamp", ["09/Nov/2026:02:14:01", "09/Nov/2026:02:14:01 +9999", "not-a-date"],
                         ids=["no-zone", "impossible-zone", "garbage"])
def test_n7_unusable_log_timezone_yields_gap_instead_of_timeline_event(site, evidence, analyze, stamp):
    write(site / UPLOAD_PHP)
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP, when=stamp)).parent

    run = analyze(site, logs=logs)

    assert [event for event in run.report["timeline"] if event["event"] == "HTTP_EXECUTABLE_IN_UPLOADS"] == []
    assert run.has_gap("Nie można znormalizować czasu logu")


def test_n7_log_event_time_is_marked_as_unverified_clock(site, evidence, analyze):
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP)).parent

    event = analyze(site, logs=logs).report["timeline"][0]

    assert event["time_utc"] == "2026-11-09T01:14:01+00:00"
    assert "synchronizacja zegara niezweryfikowana" in event["timestamp_basis"]


# --- N8 i brak wiarygodnego baseline ------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason="plik bez wpisu w baseline jest pomijany milcząco; brak NO_TRUSTED_REFERENCE (#6)")
def test_n8_premium_plugin_without_checksums_has_no_trusted_reference(site, analyze):
    write(site / "wp-content" / "plugins" / "premium-demo" / "premium.php")

    run = analyze(site, baseline={"files": {"index.php": sha256(site / "index.php")}})

    assert "NO_TRUSTED_REFERENCE" in run.json_text


@pytest.mark.parametrize("baseline", [None, {"files": {}}], ids=["not-provided", "empty-manifest"])
def test_missing_trusted_baseline_is_reported_as_coverage_gap(site, analyze, baseline):
    run = analyze(site, baseline=baseline)

    assert any(re.search(r"baseline|migawk|referenc", gap, re.I) for gap in run.gaps)


@pytest.mark.parametrize("content", [
    "{not json", "[]", '"text"', '{"files": []}', '{"files": {"index.php": 1}}', '{"known_admins": "siteadmin"}',
    '{"known_admins": [["siteadmin"]]}', b"\xff\xfe{}", "[" * 100_000,
], ids=["invalid-json", "list", "string", "files-not-object", "hash-not-string", "admins-not-list", "admin-not-string",
        "not-utf8", "deeply-nested"])
def test_malformed_baseline_is_rejected_as_usage_error(site, tmp_path, content):
    baseline = write(tmp_path / "baseline.json", content)

    with pytest.raises(SystemExit) as refusal:
        main(["--files", str(site), "--baseline", str(baseline), "--output", str(tmp_path / "out")])

    assert refusal.value.code == 2
    assert not (tmp_path / "out").exists()


def test_baseline_is_listed_in_evidence_manifest(site, tmp_path, analyze):
    baseline = write(tmp_path / "trusted.json", '{"files": {}}')

    manifest = analyze(site, baseline=baseline).manifest

    assert {"source": "baseline/trusted.json", "sha256": sha256(baseline), "size": 13} in manifest


def test_hardlinked_baseline_is_refused_with_a_hint(site, tmp_path, refuse):
    baseline = write(tmp_path / "trusted.json", '{"files": {}}')
    os.link(baseline, tmp_path / "second-name.json")

    assert "--allow-hardlinks" in refuse("--files", str(site), "--baseline", str(baseline))


# --- Obcy / nieobsługiwany SQL i logi -----------------------------------------------------------

@pytest.mark.parametrize("dump", FOREIGN_SQL.values(), ids=FOREIGN_SQL.keys())
def test_foreign_sql_is_reported_as_unparsed_not_clean(site, evidence, analyze, dump):
    database = write(evidence / "db.sql", dump)

    run = analyze(site, database=database, known_admins=("siteadmin",))

    assert run.findings == []
    assert run.has_gap("Brak obsługiwanych instrukcji INSERT")


@pytest.mark.xfail(strict=True, reason="pominięte instrukcje (np. REPLACE INTO) nie zwiększają coverage_gaps, gdy inne INSERT-y się sparsowały (#7)")
def test_unsupported_statement_next_to_supported_one_adds_a_gap(site, evidence, analyze):
    supported = option_sql("blogname", "Synthetic Site")
    skipped = "REPLACE INTO `wp_usermeta` VALUES (9,9,'wp_capabilities','a:1:{s:13:\"administrator\";b:1;}');\n"

    only_supported = analyze(site, database=write(evidence / "a.sql", supported))
    with_skipped = analyze(site, database=write(evidence / "b.sql", supported + skipped))

    assert set(with_skipped.gaps) > set(only_supported.gaps)


def test_admin_capability_without_user_row_is_not_silently_dropped(site, evidence, analyze):
    orphan = "INSERT INTO `wp_usermeta` VALUES (1,77,'wp_capabilities','a:1:{s:13:\"administrator\";b:1;}');\n"
    database = write(evidence / "db.sql", orphan)

    run = analyze(site, database=database, known_admins=("siteadmin",))

    assert any("77" in gap for gap in run.gaps)
    assert run.report["coverage"]["database"]["status"] == "PARTIAL"
    assert run.report["assessment"] == "INCONCLUSIVE"


@pytest.mark.parametrize("lines, expected_gap", [
    ('{"time":"2026-11-09T01:14:01Z","request":"GET / HTTP/1.1","status":200}\n', "Logi nie odpowiadają obsługiwanemu formatowi"),
    (access_line("/") + "unparseable line\n", "Nie sparsowano 1/2 wierszy logów"),
], ids=["json-lines", "partly-parsed"])
def test_unsupported_log_lines_are_counted_as_coverage_gap(site, evidence, analyze, lines, expected_gap):
    logs = write(evidence / "logs" / "access.log", lines).parent

    assert analyze(site, logs=logs).has_gap(expected_gap)
