"""Scenariusze pozytywne P1–P6 ze specyfikacji (rozdz. 14.1). Mapa: docs/TEST_MATRIX.md."""
import json

import pytest
from conftest import CANARY, EVAL_MARKER, UPLOAD_PHP, access_line, admin_sql, option_sql, sha256, write

OLD_SHA = "0" * 64


def test_p1_upload_php_and_log_request_are_correlated_with_caveat(site, evidence, analyze):
    write(site / UPLOAD_PHP)
    logs = write(evidence / "logs" / "access.log", access_line("/" + UPLOAD_PHP, method="POST")).parent

    run = analyze(site, logs=logs)

    assert {"EXECUTABLE_IN_UPLOADS", "HTTP_EXECUTABLE_IN_UPLOADS", "CORRELATED_UPLOAD_REQUEST"} <= run.rules
    assert "nie dowód wykonania kodu" in run.finding("CORRELATED_UPLOAD_REQUEST")["explanation"]


def test_p2_modified_core_file_reports_observed_and_reference_hash(site, analyze):
    core = write(site / "wp-includes" / "version.php")

    run = analyze(site, baseline={"files": {"wp-includes/version.php": OLD_SHA}})

    changed = run.finding("BASELINE_FILE_CHANGED")
    assert changed["source"] == "wp-includes/version.php"
    assert changed["metadata"] == {"sha256": sha256(core), "baseline_sha256": OLD_SHA}


@pytest.mark.xfail(strict=True, reason="finding nie niesie wersji referencji; baseline nie ma kontraktu wersji (#6)")
def test_p2_checksum_mismatch_names_reference_version(site, analyze):
    write(site / "wp-includes" / "version.php")

    run = analyze(site, baseline={"wordpress_version": "9.9.9-synthetic", "files": {"wp-includes/version.php": OLD_SHA}})

    assert "9.9.9-synthetic" in json.dumps(run.finding("BASELINE_FILE_CHANGED"))


def test_p3_admin_outside_trusted_list_is_flagged_without_attribution(site, evidence, analyze):
    database = write(evidence / "db.sql", admin_sql("siteadmin", "newadmin"))

    run = analyze(site, database=database, known_admins=("siteadmin",))

    flagged = run.finding("UNRECOGNIZED_ADMIN")
    assert flagged["metadata"]["username"] == "newadmin"
    assert "nie dowodzi to włamania" in flagged["explanation"]
    assert "ATTACKER" not in run.json_text.upper()


@pytest.mark.xfail(strict=True, reason="brak porównania dwóch migawek DB i reguły NEW_SINCE_BASELINE (#7)")
def test_p3_admin_added_since_baseline_is_new_since_baseline(site, evidence, analyze):
    database = write(evidence / "db.sql", admin_sql("siteadmin", "newadmin"))

    run = analyze(site, database=database, baseline={"files": {}, "known_admins": ["siteadmin"]})

    assert "NEW_SINCE_BASELINE" in run.rules


@pytest.mark.parametrize("value", [
    '<script>location.href="https://redirect.example.net/"</script>',
    '<iframe src="https://redirect.example.net/"></iframe>',
    '<a href="javascript:location.replace(1)">x</a>',
    pytest.param('<meta http-equiv="refresh" content="0;url=https://redirect.example.net/">',
                 marks=pytest.mark.xfail(strict=True, reason="redirect meta-refresh nie jest objęty regułą opcji (#7)")),
], ids=["script", "iframe", "javascript-scheme", "meta-refresh"])
def test_p4_option_with_redirect_markup_is_a_database_finding(site, evidence, analyze, value):
    database = write(evidence / "db.sql", option_sql("custom_footer", value))

    run = analyze(site, database=database)

    assert run.finding("SUSPICIOUS_DB_MARKUP")["source"] == "wp_options:custom_footer"


@pytest.mark.xfail(strict=True, reason="finding DB nie zawiera cytatu wartości, więc nie ma też redakcji (#7)")
def test_p4_finding_quotes_option_value_with_secret_redacted(site, evidence, analyze):
    value = f'<script>location.href="https://redirect.example.net/?key={CANARY}"</script>'
    database = write(evidence / "db.sql", option_sql("custom_footer", value))

    run = analyze(site, database=database)

    assert "redirect.example.net" in json.dumps(run.finding("SUSPICIOUS_DB_MARKUP"))
    assert CANARY not in run.everything


def test_p5_changed_mu_plugin_is_reported_against_baseline(site, analyze):
    write(site / "wp-content" / "mu-plugins" / "loader.php")

    run = analyze(site, baseline={"files": {"wp-content/mu-plugins/loader.php": OLD_SHA}})

    assert run.finding("BASELINE_FILE_CHANGED")["source"] == "wp-content/mu-plugins/loader.php"


@pytest.mark.xfail(strict=True, reason="plik nieobecny w baseline (nowy mu-plugin) nie daje żadnego ustalenia (#6)")
def test_p5_mu_plugin_added_since_baseline_is_reported(site, analyze):
    write(site / "wp-content" / "mu-plugins" / "loader.php")

    run = analyze(site, baseline={"files": {"index.php": sha256(site / "index.php")}})

    assert any(item["source"] == "wp-content/mu-plugins/loader.php" for item in run.findings)


def test_p6_synthetic_webshell_marker_is_a_heuristic_finding(site, analyze):
    write(site / "wp-content" / "themes" / "demo" / "footer.php", EVAL_MARKER)

    run = analyze(site)

    signature = run.finding("SUSPICIOUS_PHP_EVAL_DECODE")
    assert (signature["source"], signature["confidence"]) == ("wp-content/themes/demo/footer.php", "medium")
    assert "heurystyka, nie dowód malware" in signature["explanation"]


@pytest.mark.xfail(strict=True, reason="brak YARA-X; trafienie sygnatury nie ma offsetu ani wersji reguły (#6)")
def test_p6_signature_finding_carries_match_offset(site, analyze):
    write(site / "wp-content" / "themes" / "demo" / "footer.php", EVAL_MARKER)

    run = analyze(site)

    assert "offset" in run.finding("SUSPICIOUS_PHP_EVAL_DECODE")["metadata"]


# --- Reguły PoC spoza P1–P6: po jednym teście pozytywnym i negatywnym ---------------------------

@pytest.mark.parametrize("name, content, expected", [
    ("handler.php", "<?php // SYNTHETIC indicator text, never executed: $_POST['x'] -> system(\n", {"REQUEST_TO_COMMAND_EXEC"}),
    ("handler.php", "<?php // SYNTHETIC text, never executed: system( without request input\n", set()),
    ("notes.txt", EVAL_MARKER, set()),
], ids=["request-to-exec", "exec-without-request-input", "marker-in-non-code-file"])
def test_content_rules_fire_only_on_request_driven_exec_in_code_files(site, analyze, name, content, expected):
    write(site / "wp-content" / "themes" / "demo" / name, content)

    assert analyze(site).rules == expected


@pytest.mark.parametrize("listed, expected", [("wp-includes/removed.php", {"BASELINE_FILE_MISSING"}), ("index.php", set())],
                         ids=["absent-from-evidence", "present-and-unchanged"])
def test_baseline_file_missing_only_for_files_absent_from_evidence(site, analyze, listed, expected):
    run = analyze(site, baseline={"files": {listed: sha256(site / "index.php")}})

    assert run.rules == expected
