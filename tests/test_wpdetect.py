"""WPDetector (T-201, ADR 0005 pkt 1): wersja, locale i prefiks tabel jako kandydaci, nigdy jako ustalenie.

Wyłącznie dane syntetyczne; treść plików PHP jest tylko czytana jako bajty.
"""
import pytest
from conftest import CANARY, sha256, time_limit, write

from wpincidentlens.wpdetect import MAX_PARSE_BYTES

VERSION_PHP = "<?php\n$wp_version = '6.4.2';\n$wp_db_version = 56657;\n$wp_local_package = 'pl_PL';\n"
WP_CONFIG = "<?php\ndefine('DB_NAME', 'synthetic');\n$table_prefix = 'wp_';\n"
OLD_SHA = "0" * 64


def candidates(run, kind: str) -> list[tuple[str, str]]:
    """Pary (wartość, pewność) kandydatów danego rodzaju."""
    return sorted((item["attributes"]["value"], item["attributes"]["confidence"])
                  for item in run.report["observations"] if item["kind"] == kind)


def detector_note(run) -> str:
    return "".join(gap for gap in run.gaps if gap.startswith("WPDetector:"))


def test_standard_files_give_candidates_without_finding_or_assessment_change(site, analyze):
    before = analyze(site)
    version = write(site / "wp-includes" / "version.php", VERSION_PHP)
    write(site / "wp-config.php", WP_CONFIG)

    run = analyze(site)

    assert candidates(run, "WP_VERSION_CANDIDATE") == [("6.4.2", "medium")]
    assert candidates(run, "WP_DB_VERSION_CANDIDATE") == [("56657", "medium")]
    assert candidates(run, "WP_LOCALE_CANDIDATE") == [("pl_PL", "medium")]
    assert candidates(run, "WP_TABLE_PREFIX_CANDIDATE") == [("wp_", "medium")]
    fact = next(item for item in run.report["observations"] if item["kind"] == "WP_VERSION_CANDIDATE")
    assert fact["location"] == {"path": "wp-includes/version.php"}
    assert fact["evidence_id"] == run.evidence("files/wp-includes/version.php")["id"]
    assert run.evidence("files/wp-includes/version.php")["sha256"] == sha256(version)
    assert run.report["findings"] == [] and run.report["timeline"] == []
    assert (run.report["assessment"], run.coverage("files")["status"]) == (before.report["assessment"], before.coverage("files")["status"])
    assert detector_note(run) == ""


@pytest.mark.parametrize("reference, confidence, basis", [
    (None, "high", "zgodny z baseline"),
    (OLD_SHA, "low", "różni się od baseline"),
], ids=["matches-baseline", "differs-from-baseline"])
def test_version_confidence_follows_the_trusted_reference(site, analyze, reference, confidence, basis):
    version = write(site / "wp-includes" / "version.php", VERSION_PHP)

    run = analyze(site, baseline={"files": {"wp-includes/version.php": reference or sha256(version)}})

    fact = next(item for item in run.report["observations"] if item["kind"] == "WP_VERSION_CANDIDATE")
    assert (fact["attributes"]["value"], fact["attributes"]["confidence"]) == ("6.4.2", confidence)
    assert basis in fact["attributes"]["basis"]
    assert candidates(run, "WP_LOCALE_CANDIDATE") == [("pl_PL", "low" if reference else "medium")]  # locale z pliku to najwyżej wskazówka


def test_missing_files_are_noted_not_guessed(site, analyze):
    run = analyze(site)

    assert not [item for item in run.report["observations"] if item["kind"].startswith("WP_")]
    note = detector_note(run)
    assert "wersja WordPressa nieustalona: brak pliku wp-includes/version.php" in note
    assert "prefiks tabel nieustalony: brak pliku wp-config.php" in note
    assert "locale nieustalone" in note


@pytest.mark.parametrize("body", [
    "// $wp_version = '6.4.2';\n",
    "# $wp_version = '6.4.2';\n",
    "/* $wp_version = '6.4.2'; */\n",
    "$note = \"$wp_version = '6.4.2';\";\n",
    "$wp_version = '6.4' . '.2';\n",
    "$wp_version = synthetic_version('6.4.2');\n",
    "$wp_version == '6.4.2';\n",
    "$wp_version .= '6.4.2';\n",
    "$wp_version = '6.4.2<b>synthetic</b>';\n",
    "$wp_version = '" + "9" * 33 + "';\n",
    "$wp_version = '6.4.2",
], ids=["line-comment", "hash-comment", "block-comment", "inside-string", "concatenation", "call", "comparison",
        "append", "markup-in-value", "too-long", "unterminated"])
def test_version_that_is_not_one_plain_literal_is_not_reported(site, analyze, body):
    write(site / "wp-includes" / "version.php", "<?php\n" + body)

    run = analyze(site)

    assert candidates(run, "WP_VERSION_CANDIDATE") == []
    assert "wersja WordPressa nieustalona" in detector_note(run)
    assert "synthetic</b>" not in run.json_text and "9" * 33 not in run.json_text  # wartości spoza wzorca nie są cytowane


def test_version_file_that_is_a_symlink_is_not_followed(site, tmp_path, analyze):
    outside = write(tmp_path / "outside-version.php", VERSION_PHP)
    (site / "wp-includes").mkdir()
    (site / "wp-includes" / "version.php").symlink_to(outside)

    run = analyze(site)

    assert candidates(run, "WP_VERSION_CANDIDATE") == [] and candidates(run, "WP_LOCALE_CANDIDATE") == []
    assert "wersja WordPressa nieustalona: plik wp-includes/version.php nieodczytany (SKIPPED_SYMLINK)" in detector_note(run)


def test_duplicated_assignments_stay_candidates_with_low_confidence(site, analyze):
    write(site / "wp-includes" / "version.php", "<?php\n$wp_version = '6.4.2';\n$wp_version = '5.0';\n")

    run = analyze(site)

    assert candidates(run, "WP_VERSION_CANDIDATE") == [("5.0", "low"), ("6.4.2", "low")]
    assert "$wp_version w wp-includes/version.php niejednoznaczne" in detector_note(run)


def test_conflicting_locale_sources_are_all_reported_without_a_winner(site, analyze):
    write(site / "wp-includes" / "version.php", VERSION_PHP)
    write(site / "wp-config.php", WP_CONFIG + 'define( "WPLANG", "de_DE" );\n')
    write(site / "wp-content" / "languages" / "fr_FR.mo", b"synthetic")

    run = analyze(site)

    assert candidates(run, "WP_LOCALE_CANDIDATE") == [("de_DE", "low"), ("fr_FR", "low"), ("pl_PL", "low")]
    assert "locale niejednoznaczne: 3 różnych kandydatów" in detector_note(run)
    assert candidates(run, "WP_VERSION_CANDIDATE") == [("6.4.2", "medium")]  # spór o locale nie obniża pewności wersji


def test_agreeing_locale_sources_are_not_a_conflict(site, analyze):
    write(site / "wp-includes" / "version.php", VERSION_PHP)
    write(site / "wp-config.php", WP_CONFIG + "define('WPLANG', 'pl_PL');\ndefine('WP_DEBUG', '');\n")
    write(site / "wp-content" / "languages" / "pl_PL.mo", b"synthetic")

    run = analyze(site)

    assert candidates(run, "WP_LOCALE_CANDIDATE") == [("pl_PL", "low"), ("pl_PL", "medium"), ("pl_PL", "medium")]
    assert detector_note(run) == ""


def test_lookalikes_outside_the_standard_places_are_ignored(site, analyze):
    write(site / "wp-content" / "plugins" / "synthetic" / "version.php", VERSION_PHP)
    write(site / "wp-content" / "plugins" / "synthetic" / "wp-config.php", WP_CONFIG + "define('WPLANG', 'de_DE');\n")
    write(site / "wp-content" / "uploads" / "pl_PL.mo", b"synthetic")
    write(site / "wp-content" / "languages" / "plugins" / "synthetic-pl_PL.mo", b"synthetic")
    write(site / "wp-content" / "languages" / "not a locale.mo", b"synthetic")
    write(site / "wp-config.php", "<?php\ndefine('WPLANG', '');\n$table_prefix = 'wp_';\n")

    run = analyze(site)

    assert [item["kind"] for item in run.report["observations"]] == ["WP_TABLE_PREFIX_CANDIDATE"]
    assert "wersja WordPressa nieustalona: brak pliku" in detector_note(run)


@pytest.mark.parametrize("prefix_line, expected", [
    ("$table_prefix = 'wp_';", [("wp_", "medium")]),
    (f"$table_prefix = '{CANARY}';", []),  # wartość spoza wzorca prefiksu: nota bez cytatu
    (f"$table_prefix = 'wp_' . '{CANARY}';", []),
], ids=["plain", "secret-as-prefix", "secret-concatenated"])
def test_secrets_next_to_the_prefix_never_reach_any_output(site, analyze, prefix_line, expected):
    write(site / "wp-config.php", f"<?php\ndefine('DB_PASSWORD', '{CANARY}');\ndefine('AUTH_KEY', '{CANARY}');\n"
                                  f"$secret = '{CANARY}'; {prefix_line} $salt = \"{CANARY}\"; // {CANARY}\n")

    run = analyze(site)

    assert candidates(run, "WP_TABLE_PREFIX_CANDIDATE") == expected
    assert ("prefiks tabel nieustalony" in detector_note(run)) == (not expected)
    assert CANARY not in run.everything


@pytest.mark.parametrize("payload", [
    b"'" * (MAX_PARSE_BYTES - 6),
    b"'\\" * (MAX_PARSE_BYTES // 2 - 3),
    b'"\\' * (MAX_PARSE_BYTES // 2 - 4) + b"\\",
    b"/*" * (MAX_PARSE_BYTES // 2 - 3),
    b"$wp_version=" * (MAX_PARSE_BYTES // 12 - 1),
    bytes(range(256)) * (MAX_PARSE_BYTES // 256 - 1),
    b"$wp_version = '6.4.2';" + b" " * MAX_PARSE_BYTES,
], ids=["quotes", "escaped-quotes", "trailing-backslash", "open-comments", "assignments", "binary", "over-limit"])
def test_hostile_version_file_is_handled_in_bounded_time_without_a_guess(site, analyze, payload):
    write(site / "wp-includes" / "version.php", b"<?php " + payload)

    with time_limit(10):
        run = analyze(site)

    assert candidates(run, "WP_VERSION_CANDIDATE") == []
    assert "wersja WordPressa nieustalona" in detector_note(run)
