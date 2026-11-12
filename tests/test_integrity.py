"""IntegrityAdapter (T-201, ADR 0005): baseline SHA-256, lokalny manifest sum rdzenia (MD5) i ``NOT_CHECKED`` per klasa.

Plik kodu bez zaufanej referencji obniża pokrycie ``files`` (ADR 0005, pkt 6): brak ustaleń nie daje wtedy pełnego zakresu.

Wyłącznie dane syntetyczne w ``tmp_path``; manifesty to pliki lokalne, nic nie jest pobierane ani wykonywane.
"""
import hashlib
import json
import os

import pytest
from conftest import sha256, tamper_before_reverification, trusted, write

from wpincidentlens import cli, ingest, integrity
from wpincidentlens.ingest import ReadStatus, Session

OLD_SHA = "0" * 64
OLD_MD5 = "0" * 32
MU_PLUGIN = "wp-content/mu-plugins/loader.php"
CORE_FILE = "wp-includes/version.php"


def md5(path) -> str:
    return hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()


def index_only(site) -> dict:
    """Baseline, który zna wyłącznie ``index.php`` z fikstury ``site``."""
    return {"files": {"index.php": sha256(site / "index.php")}}


def core_manifest(site) -> dict:
    """Manifest zgodny z ``index.php`` z fikstury ``site``."""
    return {"checksums": {"index.php": md5(site / "index.php")}}


# --- wersja i opis referencji w baseline --------------------------------------------------------

def test_missing_baseline_file_carries_the_reference_version_and_label(site, analyze):
    run = analyze(site, baseline={"wordpress_version": "9.9.9-synthetic", "reference": "Migawka syntetyczna 2026-11",
                                  "files": {"wp-includes/removed.php": OLD_SHA}})

    assert run.finding("BASELINE_FILE_MISSING")["metadata"] == {
        "reference_version": "9.9.9-synthetic", "reference": "Migawka syntetyczna 2026-11"}


@pytest.mark.parametrize("fields", [
    {"wordpress_version": ""}, {"wordpress_version": "9 9"}, {"wordpress_version": 7}, {"wordpress_version": "9" * 33},
    {"wordpress_version": "9.9\n"}, {"wordpress_version": "<b>9</b>"},
    {"reference": ""}, {"reference": "wiersz\ndrugi"}, {"reference": "x" * 121}, {"reference": ["lista"]}, {"reference": " odstęp"},
    {"reference": "kierunek‮odwrócony"},
], ids=["version-empty", "version-space", "version-number", "version-too-long", "version-newline", "version-markup",
        "label-empty", "label-newline", "label-too-long", "label-list", "label-padded", "label-bidi-override"])
def test_invalid_reference_description_in_baseline_is_a_usage_error(site, tmp_path, refuse, fields):
    baseline = write(tmp_path / "baseline.json", json.dumps({"files": {}, **fields}))

    assert "--baseline" in refuse("--files", str(site), "--baseline", str(baseline))


# --- nowy plik w miejscu ładowanym automatycznie ------------------------------------------------

@pytest.mark.parametrize("rel, file_class", [(MU_PLUGIN, "MU_PLUGIN"), ("wp-content/object-cache.php", "DROPIN")],
                         ids=["mu-plugin", "drop-in"])
def test_new_autoloaded_file_is_a_finding_that_does_not_claim_compromise(site, analyze, rel, file_class):
    added = write(site / rel)

    run = analyze(site, baseline={"wordpress_version": "9.9.9-synthetic", **index_only(site)})

    new = run.finding("NEW_FILE_SINCE_BASELINE")
    assert (new["source"], new["severity"], new["confidence"], new["source_type"]) == (rel, "medium", "medium", "file")
    assert new["metadata"] == {"sha256": sha256(added), "file_class": file_class, "reference_version": "9.9.9-synthetic"}
    assert "nie dowodzi włamania" in new["explanation"] and "starszy" in new["explanation"]
    assert not run.has_gap("NO_TRUSTED_REFERENCE")  # plik ma własne ustalenie, nie ginie w nocie zbiorczej


@pytest.mark.parametrize("rel, baseline", [
    (MU_PLUGIN, "listed"), (MU_PLUGIN, {"files": {}}), (MU_PLUGIN, {}), (MU_PLUGIN, None),
    ("wp-content/plugins/demo/demo.php", "index-only"), ("wp-content/maintenance-notes.php", "index-only"),
], ids=["listed-and-unchanged", "baseline-with-empty-files", "baseline-without-files", "no-baseline", "plugin-file", "not-a-drop-in"])
def test_file_absent_from_baseline_is_not_a_finding_outside_autoloaded_locations(site, analyze, rel, baseline):
    added = write(site / rel)
    if baseline == "listed":
        baseline = {"files": {**index_only(site)["files"], rel: sha256(added)}}
    elif baseline == "index-only":
        baseline = index_only(site)

    assert analyze(site, baseline=baseline).rules == set()


def test_unread_entry_in_autoloaded_location_is_reported_by_path_with_low_confidence(site, evidence, analyze):
    outside = write(evidence / "outside.php")
    (site / "wp-content" / "mu-plugins").mkdir(parents=True)
    os.symlink(outside, site / MU_PLUGIN)

    new = analyze(site, baseline=index_only(site)).finding("NEW_FILE_SINCE_BASELINE")

    assert (new["source"], new["confidence"]) == (MU_PLUGIN, "low")
    assert new["metadata"] == {"read_status": "SKIPPED_SYMLINK", "file_class": "MU_PLUGIN"}
    assert "treść nieodczytana" in new["explanation"]


@pytest.mark.parametrize("listed, listed_as", [(MU_PLUGIN, "file"), ("wp-content/mu-plugins/loader.php/inner.php", "directory")],
                         ids=["entry-itself", "file-below-entry"])
def test_unread_entry_listed_in_the_baseline_is_unreadable_not_new_or_missing(site, evidence, analyze, listed, listed_as):
    outside = write(evidence / "outside.php")
    (site / "wp-content" / "mu-plugins").mkdir(parents=True)
    os.symlink(outside, site / MU_PLUGIN)

    run = analyze(site, baseline={"wordpress_version": "9.9.9-synthetic", "files": {**index_only(site)["files"], listed: OLD_SHA}})

    unreadable = run.finding("REFERENCE_FILE_UNREADABLE")
    assert (unreadable["source"], unreadable["severity"], unreadable["confidence"]) == (MU_PLUGIN, "medium", "low")
    assert unreadable["metadata"] == {"read_status": "SKIPPED_SYMLINK", "listed_in": "baseline", "listed_as": listed_as,
                                      "reference_version": "9.9.9-synthetic"}
    assert "SKIPPED_SYMLINK" in unreadable["explanation"] and "nie dowodzi zmiany" in unreadable["explanation"]
    assert run.rules == {"REFERENCE_FILE_UNREADABLE"}


@pytest.mark.parametrize("baseline_lists_loader, expected", [(False, "NEW_FILE_SINCE_BASELINE"), (True, "REFERENCE_FILE_UNREADABLE")],
                         ids=["nothing-listed-below", "loader-listed-below"])
def test_unread_mu_plugins_directory_itself_is_reported_by_path(site, evidence, analyze, baseline_lists_loader, expected):
    write(evidence / "elsewhere" / "loader.php")
    (site / "wp-content").mkdir()
    os.symlink(evidence / "elsewhere", site / "wp-content" / "mu-plugins")
    baseline = index_only(site)
    if baseline_lists_loader:
        baseline["files"][MU_PLUGIN] = OLD_SHA

    run = analyze(site, baseline=baseline)

    assert run.rules == {expected}
    assert (run.finding(expected)["source"], run.finding(expected)["confidence"]) == ("wp-content/mu-plugins", "low")


# --- manifest sum rdzenia (MD5) -----------------------------------------------------------------

def test_core_file_matching_the_manifest_gives_no_finding_and_md5_stays_out_of_evidence(site, tmp_path, analyze):
    manifest = write(tmp_path / "core-9.9.9.json", json.dumps(core_manifest(site)))

    run = analyze(site, core_checksums=manifest)

    assert run.rules == set()
    assert run.evidence("baseline/core-9.9.9.json")["sha256"] == sha256(manifest)
    assert md5(site / "index.php") not in run.json_text
    assert not run.has_gap("NOT_CHECKED") and run.coverage("files")["status"] == "ANALYZED"


def test_core_checksum_mismatch_reports_both_digests_and_the_reference(site, tmp_path, analyze):
    core = write(site / CORE_FILE)
    manifest = write(tmp_path / "core-9.9.9.json", json.dumps({
        "wordpress_version": "9.9.9-synthetic", "reference": "pl_PL syntetyczny",
        "checksums": {"index.php": md5(site / "index.php"), CORE_FILE: OLD_MD5}}))

    run = analyze(site, core_checksums=manifest)

    mismatch = run.finding("CORE_CHECKSUM_MISMATCH")
    assert (mismatch["source"], mismatch["severity"], mismatch["confidence"]) == (CORE_FILE, "medium", "high")
    assert mismatch["metadata"] == {
        "sha256": sha256(core), "observed_sha256": sha256(core), "observed_md5": md5(core), "reference_md5": OLD_MD5,
        "reference_version": "9.9.9-synthetic", "reference": "pl_PL syntetyczny", "reference_file": "baseline/core-9.9.9.json"}
    assert "9.9.9-synthetic" in mismatch["explanation"] and "locale" in mismatch["explanation"]
    assert run.rules == {"CORE_CHECKSUM_MISMATCH"}


def test_manifest_nested_under_a_version_key_supplies_the_reference_version(site, analyze):
    write(site / CORE_FILE)

    run = analyze(site, core_checksums={"checksums": {"9.9.9-synthetic": {CORE_FILE: OLD_MD5, "index.php": md5(site / "index.php")}}})

    assert run.finding("CORE_CHECKSUM_MISMATCH")["metadata"]["reference_version"] == "9.9.9-synthetic"


def test_baseline_and_manifest_are_compared_independently(site, analyze):
    write(site / CORE_FILE)

    run = analyze(site, baseline={"files": {CORE_FILE: OLD_SHA}}, core_checksums={"checksums": {"index.php": md5(site / "index.php"), CORE_FILE: OLD_MD5}})

    assert run.rules == {"BASELINE_FILE_CHANGED", "CORE_CHECKSUM_MISMATCH"}
    assert run.finding("BASELINE_FILE_CHANGED")["metadata"].keys() == {"sha256", "baseline_sha256"}


@pytest.mark.parametrize("rel, flagged", [
    ("wp-admin/extra.php", True), ("wp-extra.php", True), ("shell.php", True), ("wp-includes/extra.php5", True),
    ("wp-admin/.htaccess", True), ("wp-includes/.user.ini", True),
    ("wp-config.php", False), (".htaccess", False), (".user.ini", False), ("php.ini", False),
    ("wp-includes/js/extra.js", False), ("wp-content/plugins/demo/demo.php", False), ("tools/shell.php", False),
], ids=["php-in-wp-admin", "wp-prefixed-php-in-root", "other-php-in-root", "php5-in-wp-includes", "htaccess-in-wp-admin",
        "user-ini-in-wp-includes", "root-wp-config", "root-htaccess", "root-user-ini", "root-php-ini", "non-code-core-file",
        "plugin-file", "code-in-other-directory"])
def test_code_in_core_locations_absent_from_the_manifest_is_a_finding_except_expected_root_config(site, analyze, rel, flagged):
    write(site / rel, "# synthetic placeholder\n")

    run = analyze(site, core_checksums=core_manifest(site))

    assert run.rules == ({"CORE_FILE_NOT_IN_MANIFEST"} if flagged else set())
    assert run.has_gap("NO_TRUSTED_REFERENCE: 1 odczytanych plików nie ma wpisu w podanej referencji") is not flagged
    for found in run.findings:
        assert (found["source"], found["severity"], found["confidence"]) == (rel, "medium", "low")
        assert "innej wersji" in found["explanation"]
    if rel != "wp-includes/js/extra.js":  # każdy z pozostałych to plik kodu bez referencji: zakres niepełny także bez ustalenia
        assert run.has_gap("NOT_CHECKED") and run.coverage("files")["status"] == "PARTIAL"


def test_unread_code_in_a_core_location_absent_from_the_manifest_is_reported_by_path(site, evidence, analyze):
    (site / "wp-admin").mkdir()
    os.symlink(write(evidence / "outside.php"), site / "wp-admin" / "extra.php")

    found = analyze(site, core_checksums=core_manifest(site)).finding("CORE_FILE_NOT_IN_MANIFEST")

    assert (found["source"], found["confidence"], found["metadata"]["read_status"]) == ("wp-admin/extra.php", "low", "SKIPPED_SYMLINK")
    assert "Treść nieodczytana" in found["explanation"]


def test_core_file_listed_in_the_manifest_but_absent_is_observed_on_the_manifest(site, tmp_path, analyze):
    manifest = write(tmp_path / "core-9.9.9.json", json.dumps({
        "wordpress_version": "9.9.9-synthetic", "checksums": {"index.php": md5(site / "index.php"), "wp-includes/removed.php": OLD_MD5}}))

    run = analyze(site, core_checksums=manifest)

    missing = run.finding("CORE_FILE_MISSING")
    assert (missing["source"], missing["severity"]) == ("wp-includes/removed.php", "low")
    assert missing["metadata"] == {"reference_md5": OLD_MD5, "reference_version": "9.9.9-synthetic"}
    fact = next(item for item in run.report["observations"] if item["kind"] == "CORE_MANIFEST_ENTRY_NOT_IN_FILES")
    assert fact["evidence_id"] == run.evidence("baseline/core-9.9.9.json")["id"]


@pytest.mark.parametrize("listed, flags, gap", [
    ("wp-content/themes/bundled/style.css", (), "Manifest sum rdzenia wymienia 1 plików w wp-content"),
    ("wp-includes/linked.php", (), "Łącze symboliczne pominięte"),
    ("wp-includes/zz-after-limit.php", ("--max-files", "2"), "Limit 2 plików"),
], ids=["bundled-content-removed", "entry-present-but-unread", "traversal-incomplete"])
def test_manifest_entry_is_not_reported_missing_when_absence_is_expected_or_unknown(site, evidence, analyze, listed, flags, gap):
    write(site / "wp-includes" / "version.php")
    os.symlink(write(evidence / "outside.php"), site / "wp-includes" / "linked.php")

    run = analyze(site, flags=flags, core_checksums={"checksums": {"index.php": md5(site / "index.php"), listed: OLD_MD5}})

    assert "CORE_FILE_MISSING" not in run.rules
    assert run.has_gap(gap)


def test_hardlinked_and_symlinked_core_files_are_not_hashed_but_named_as_unverifiable(site, evidence, analyze):
    linked = write(site / "wp-includes" / "hardlinked.php")
    os.link(linked, evidence / "second-name.php")
    os.symlink(write(evidence / "outside.php"), site / "wp-includes" / "symlinked.php")
    manifest = {"checksums": {"index.php": md5(site / "index.php"), "wp-includes/hardlinked.php": OLD_MD5,
                              "wp-includes/symlinked.php": OLD_MD5}}

    skipped = analyze(site, core_checksums=manifest)
    allowed = analyze(site, core_checksums=manifest, flags=("--allow-hardlinks",))

    assert [skipped.evidence(f"files/wp-includes/{name}.php")["sha256"] for name in ("hardlinked", "symlinked")] == [None, None]
    assert skipped.rules == {"REFERENCE_FILE_UNREADABLE"}  # drugi hardlink nie ucisza kontroli integralności
    assert {(found["source"], found["metadata"]["read_status"], found["metadata"]["listed_in"]) for found in skipped.findings} == {
        ("wp-includes/hardlinked.php", "SKIPPED_HARDLINK", "core_manifest"), ("wp-includes/symlinked.php", "SKIPPED_SYMLINK", "core_manifest")}
    assert allowed.finding("CORE_CHECKSUM_MISMATCH")["source"] == "wp-includes/hardlinked.php"


@pytest.mark.parametrize("content", [
    "{not json", "[]", '{"files": {}}', '{"checksums": false}', '{"checksums": {}}', '{"checksums": {"9.9.9": {}}}',
    json.dumps({"checksums": {"../outside-canary.php": OLD_MD5}}), json.dumps({"checksums": {"/etc/outside-canary": OLD_MD5}}),
    json.dumps({"checksums": {"wp-admin/./outside-canary.php": OLD_MD5}}), json.dumps({"checksums": {"wp-admin//outside-canary.php": OLD_MD5}}),
    json.dumps({"checksums": {"wp-admin\\outside-canary.php": OLD_MD5}}), json.dumps({"checksums": {"wp-admin/outside-canary\x00.php": OLD_MD5}}),
    json.dumps({"checksums": {"x" * 1025: OLD_MD5}}), json.dumps({"checksums": {"": OLD_MD5}}),
    json.dumps({"checksums": {"index.php": 1}}), json.dumps({"checksums": {"index.php": OLD_SHA}}),
    json.dumps({"checksums": {"index.php": "A" * 32}}), json.dumps({"checksums": {"index.php": ["outside-canary"]}}),
    json.dumps({"checksums": {"index.php": OLD_MD5, "wp-admin": {"outside-canary.php": OLD_MD5}}}),
    json.dumps({"checksums": {"9 9 outside-canary": {"index.php": OLD_MD5}}}),
    json.dumps({"wordpress_version": "1.0", "checksums": {"9.9.9": {"index.php": OLD_MD5}}}),
    json.dumps({"reference": "outside-canary\n", "checksums": {"index.php": OLD_MD5}}),
    b'{"checksums": {"index.php": "\xff"}}',
    json.dumps({"checksums": {"outside-canary": {"index.php": OLD_MD5}}}),
    '{"checksums": {"outside-canary.php": "%s", "outside-canary.php": "%s"}}' % (OLD_MD5, "1" * 32),
], ids=["invalid-json", "array", "baseline-shape", "api-not-found", "empty", "empty-nested", "parent-traversal", "absolute-path",
        "dot-segment", "empty-segment", "backslash", "nul-byte", "path-too-long", "empty-path", "number-value", "sha256-value",
        "uppercase-md5", "list-value", "mixed-nesting", "bad-nested-version", "conflicting-versions", "bad-label", "not-utf8",
        "nested-key-not-a-version", "duplicate-key"])
def test_unusable_core_manifest_is_a_usage_error_that_echoes_no_value(site, tmp_path, refuse, content):
    manifest = write(tmp_path / "core.json", content)

    message = refuse("--files", str(site), "--core-checksums", str(manifest))

    assert "--core-checksums" in message
    assert "outside-canary" not in message


def test_core_manifest_over_the_entry_or_size_limit_is_a_usage_error(site, tmp_path, refuse, monkeypatch):
    manifest = write(tmp_path / "core.json", json.dumps({"checksums": {f"wp-admin/{number}.php": OLD_MD5 for number in range(3)}}))
    arguments = ("--files", str(site), "--core-checksums", str(manifest))

    monkeypatch.setattr(integrity, "MAX_CORE_CHECKSUMS", 2)
    assert "od 1 do 2 sum" in refuse(*arguments)
    monkeypatch.setattr(cli, "MAX_CORE_CHECKSUMS_BYTES", 16)
    assert "plik większy niż 16 B" in refuse(*arguments)


def test_core_manifest_path_is_refused_when_symlinked_hardlinked_missing_or_named_like_the_baseline(site, tmp_path, refuse):
    manifest = write(tmp_path / "core.json", json.dumps(core_manifest(site)))
    os.symlink(manifest, tmp_path / "link.json")
    twin = write(tmp_path / "other" / "core.json", "{}")

    assert "dowiązaniem symbolicznym" in refuse("--files", str(site), "--core-checksums", str(tmp_path / "link.json"))
    assert "--core-checksums" in refuse("--files", str(site), "--core-checksums", str(tmp_path / "absent.json"))
    assert "nazwa pliku musi różnić się" in refuse("--files", str(site), "--baseline", str(twin), "--core-checksums", str(manifest))
    os.link(manifest, tmp_path / "second-name.json")
    assert "--allow-hardlinks" in refuse("--files", str(site), "--core-checksums", str(manifest))


# --- MD5 w SecureIngest: ten sam odczyt, tylko na żądanie ---------------------------------------

def test_md5_is_computed_in_the_same_single_read_as_sha256(site, monkeypatch):
    core = write(site / CORE_FILE, "<?php // synthetic core placeholder\n" * 3)
    opened, real_open = [], ingest._open_at
    monkeypatch.setattr(ingest, "_open_at", lambda name, *args: opened.append(name) or real_open(name, *args))

    plain = {record.rel: record for record in Session(reverify=False).read(site, "files")}
    opened_without_md5, opened[:] = list(opened), []
    hashed = {record.rel: record for record in Session(reverify=False).read(site, "files", md5=True)}

    assert opened == opened_without_md5 and opened.count("version.php") == 1
    assert (hashed[CORE_FILE].md5, hashed[CORE_FILE].sha256) == (md5(core), sha256(core))
    assert {record.md5 for record in plain.values()} == {None}


def test_md5_is_absent_for_entries_that_were_not_read(site, evidence):
    os.link(write(site / "hardlinked.php"), evidence / "second-name.php")
    os.symlink(evidence / "second-name.php", site / "symlinked.php")

    records = {record.rel: record for record in Session().read(site, "files", md5=True)}

    assert (records["hardlinked.php"].status, records["symlinked.php"].status) == (ReadStatus.SKIPPED_HARDLINK, ReadStatus.SKIPPED_SYMLINK)
    assert [records[rel].md5 for rel in ("hardlinked.php", "symlinked.php")] == [None, None]
    assert records["index.php"].md5 == md5(site / "index.php")


@pytest.mark.parametrize("tampered, source", [("site/index.php", "files"), ("core.json", "baseline")], ids=["site-file", "manifest"])
def test_change_after_analysis_is_still_detected_when_a_manifest_is_used(site, evidence, analyze, monkeypatch, tampered, source):
    manifest = write(evidence / "core.json", json.dumps(core_manifest(site)))
    tamper_before_reverification(monkeypatch, lambda: write(evidence / tampered, "tampered after analysis"))

    run = analyze(site, core_checksums=manifest)

    assert run.has_gap("SOURCE_CHANGED_DURING_ANALYSIS")
    assert run.coverage(source)["status"] == "PARTIAL"


# --- baseline: ścisła walidacja wpisów ------------------------------------------------------------

@pytest.mark.parametrize("content", [
    json.dumps({"files": {"index.php": "abc"}}), json.dumps({"files": {"index.php": "A" * 64}}),
    json.dumps({"files": {"index.php": OLD_MD5}}), json.dumps({"files": {"./outside-canary.php": OLD_SHA}}),
    json.dumps({"files": {"wp-admin\\outside-canary.php": OLD_SHA}}), json.dumps({"files": {"outside-canary\x00.php": OLD_SHA}}),
    '{"files": {"outside-canary.php": "%s", "outside-canary.php": "%s"}}' % (OLD_SHA, "1" * 64),
    '{"files": {}, "files": {"outside-canary.php": "%s"}}' % OLD_SHA,
], ids=["short-value", "uppercase-sha256", "md5-value", "dot-segment", "backslash", "nul-byte", "duplicate-path", "duplicate-files"])
def test_baseline_with_malformed_or_duplicated_entries_is_a_usage_error(site, tmp_path, refuse, content):
    baseline = write(tmp_path / "baseline.json", content)

    message = refuse("--files", str(site), "--baseline", str(baseline))

    assert "--baseline" in message and "outside-canary" not in message


# --- NOT_CHECKED per klasa: niezweryfikowany kod nie daje pełnego zakresu -----------------------

def not_checked(run) -> list[str]:
    return sorted(gap for gap in run.gaps if gap.startswith("NOT_CHECKED"))


def unverified(name: str, count: str, code: int) -> str:
    return f"NOT_CHECKED: integralność plików klasy {name} (plików: {count}, w tym kodu: {code}) niezweryfikowana — brak zaufanej referencji"


def test_file_classes_without_a_reference_are_not_checked_and_never_called_clean(complete_case, analyze):
    site = complete_case["site"]
    del complete_case["baseline"]
    for rel in ("wp-content/plugins/demo/demo.php", "wp-content/plugins/demo/readme.txt", "wp-content/themes/demo/style.css",
                MU_PLUGIN, "wp-content/object-cache.php", "wp-content/uploads/2026/photo.jpg", "wp-config.php", "tools/run.php"):
        write(site / rel, "synthetic placeholder\n")

    run = analyze(**complete_case)

    assert not_checked(run) == [unverified(*row) for row in (
        ("CONFIG", "1", 1), ("CORE", "1", 1), ("DROPIN", "1", 1), ("MU_PLUGIN", "1", 1), ("OTHER", "1", 1), ("PLUGIN", "2", 1),
        ("THEME", "1", 0))]
    assert set(not_checked(run)) <= set(run.coverage("files")["reasons"])
    assert run.findings == []
    assert (run.coverage("files")["status"], run.report["assessment"], run.report["scope_complete"], run.exit_code) == (
        "PARTIAL", "INCONCLUSIVE", False, 3)
    assert not any(word in run.json_text.lower() for word in ("clean", "czyst"))


def test_unverified_files_that_are_not_code_are_noted_without_shrinking_the_scope(complete_case, analyze):
    for rel in ("wp-content/themes/demo/style.css", "wp-content/uploads/2026/photo.jpg", "wp-includes/js/extra.js"):
        write(complete_case["site"] / rel, "synthetic placeholder\n")

    run = analyze(**complete_case)

    assert not_checked(run) == [unverified("CORE", "1 z 2", 0), unverified("THEME", "1", 0)]
    assert (run.coverage("files")["status"], run.report["assessment"], run.exit_code) == ("ANALYZED", "NO_INDICATORS_IN_ANALYZED_SCOPE", 0)


def test_not_checked_counts_read_and_unread_files_that_no_reference_covers(site, evidence, analyze):
    covered = write(site / "wp-content" / "plugins" / "demo" / "demo.php")
    write(site / "wp-content" / "plugins" / "premium-demo" / "premium.php")
    os.symlink(write(evidence / "outside.php"), site / "wp-content" / "plugins" / "premium-demo" / "linked.php")

    run = analyze(site, baseline={"files": {"wp-content/plugins/demo/demo.php": sha256(covered)}}, core_checksums=core_manifest(site))

    assert not_checked(run) == [unverified("PLUGIN", "2 z 3", 2)]


@pytest.mark.parametrize("with_manifest, rules, assessment", [(True, {"CORE_FILE_NOT_IN_MANIFEST"}, "SUSPICIOUS"), (False, set(), "INCONCLUSIVE")],
                         ids=["baseline-and-manifest", "baseline-only"])
def test_code_added_to_a_tree_that_matches_its_references_never_yields_a_full_scope(complete_case, analyze, with_manifest, rules, assessment):
    site = complete_case["site"]
    core = write(site / CORE_FILE)
    complete_case["baseline"] = trusted(site)
    manifest = {"checksums": {"index.php": md5(site / "index.php"), CORE_FILE: md5(core)}} if with_manifest else None
    for rel in ("shell.php", "wp-content/plugins/demo/added.php", "wp-content/themes/demo/functions.php", ".htaccess"):
        write(site / rel, "# synthetic placeholder\n")

    run = analyze(**complete_case, core_checksums=manifest)

    assert run.rules == rules
    assert (run.report["assessment"], run.report["scope_complete"], run.exit_code) == (assessment, False, 3)
    assert not_checked(run) == [unverified("CONFIG", "1", 1), unverified("OTHER", "1", 1), unverified("PLUGIN", "1", 1),
                                unverified("THEME", "1", 1)]
    assert run.coverage("files")["status"] == "PARTIAL"


def test_supplying_a_reference_never_gives_a_wider_scope_than_the_reference_covers(site, analyze):
    write(site / "wp-content" / "plugins" / "demo" / "demo.php")

    without, with_baseline, with_manifest = analyze(site), analyze(site, baseline=index_only(site)), analyze(site, core_checksums=core_manifest(site))

    assert {run.coverage("files")["status"] for run in (without, with_baseline, with_manifest)} == {"PARTIAL"}
    assert not_checked(without) == [unverified("CORE", "1", 1), unverified("PLUGIN", "1", 1)]
    assert not_checked(with_baseline) == not_checked(with_manifest) == [unverified("PLUGIN", "1", 1)]


def test_findings_over_the_per_rule_limit_become_a_visible_gap_with_the_total(site, analyze, monkeypatch):
    monkeypatch.setattr(integrity, "MAX_FINDINGS_PER_RULE", 2)
    baseline = {"files": {**index_only(site)["files"], **{f"wp-includes/removed-{number}.php": OLD_SHA for number in range(5)}}}

    run = analyze(site, baseline=baseline)

    assert {found["source"] for found in run.findings} == {"wp-includes/removed-0.php", "wp-includes/removed-1.php"}
    assert run.has_gap("Limit 2 ustaleń reguły BASELINE_FILE_MISSING wyczerpany: wykryć było 5")
    assert run.coverage("files")["status"] == "PARTIAL"


def test_file_names_in_the_unreferenced_note_are_quoted_so_they_cannot_reshape_it(site, analyze):
    write(site / "wp-content" / "plugins" / "demo" / "one, two (and 9 more\nNO_TRUSTED_REFERENCE: 0.txt", "synthetic placeholder\n")

    run = analyze(site, baseline=index_only(site))

    note = next(gap for gap in run.gaps if gap.startswith("NO_TRUSTED_REFERENCE"))
    assert note.endswith('("wp-content/plugins/demo/one, two (and 9 more\\nNO_TRUSTED_REFERENCE: 0.txt")')
    assert "\n" not in note


# --- pokrycie źródła baseline i case.json -------------------------------------------------------

def test_manifest_alone_is_reported_under_the_baseline_source_without_new_sources(complete_case, tmp_path, analyze):
    manifest = write(tmp_path / "core-9.9.9.json", json.dumps(core_manifest(complete_case["site"])))
    del complete_case["baseline"]

    run = analyze(**complete_case, core_checksums=manifest)

    assert list(run.report["coverage"]) == ["files", "database", "logs", "baseline"]
    assert (run.coverage("baseline")["status"], run.coverage("baseline")["entries"]["READ"]) == ("ANALYZED", 1)
    assert run.has_gap("referencją jest wyłącznie manifest sum rdzenia")
    assert (run.report["scope_complete"], run.exit_code) == (True, 0)  # manifest obejmuje cały kod tej witryny
    assert run.case["sources"]["baseline"] == {"provided": False, "name": None}
    assert run.case["sources"]["core_checksums"] == {"provided": True, "name": "core-9.9.9.json"}


def test_case_json_has_no_manifest_entry_when_none_was_given(site, analyze):
    assert "core_checksums" not in analyze(site, baseline=index_only(site)).case["sources"]
