"""IntegrityAdapter (T-201, ADR 0005): baseline SHA-256, lokalny manifest sum rdzenia (MD5) i ``NOT_CHECKED`` per klasa.

Wyłącznie dane syntetyczne w ``tmp_path``; manifesty to pliki lokalne, nic nie jest pobierane ani wykonywane.
"""
import hashlib
import json
import os

import pytest
from conftest import sha256, tamper_before_reverification, write

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


@pytest.mark.parametrize("listed", [MU_PLUGIN, "wp-content/mu-plugins/loader.php/inner.php"], ids=["entry-itself", "file-below-entry"])
def test_unread_entry_known_to_the_baseline_is_neither_new_nor_missing(site, evidence, analyze, listed):
    outside = write(evidence / "outside.php")
    (site / "wp-content" / "mu-plugins").mkdir(parents=True)
    os.symlink(outside, site / MU_PLUGIN)

    run = analyze(site, baseline={"files": {**index_only(site)["files"], listed: OLD_SHA}})

    assert run.rules == set()


# --- manifest sum rdzenia (MD5) -----------------------------------------------------------------

def test_core_file_matching_the_manifest_gives_no_finding_and_md5_stays_out_of_evidence(site, tmp_path, analyze):
    manifest = write(tmp_path / "core-9.9.9.json", json.dumps(core_manifest(site)))

    run = analyze(site, core_checksums=manifest)

    assert run.rules == set()
    assert run.evidence("baseline/core-9.9.9.json")["sha256"] == sha256(manifest)
    assert md5(site / "index.php") not in run.json_text
    assert not run.has_gap("NOT_CHECKED")


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


@pytest.mark.parametrize("rel, expected", [
    ("wp-admin/extra.php", {"CORE_FILE_NOT_IN_MANIFEST"}), ("wp-extra.php", {"CORE_FILE_NOT_IN_MANIFEST"}),
    ("wp-includes/js/extra.js", set()), ("wp-content/plugins/demo/demo.php", set()), ("wp-config.php", set()),
], ids=["php-in-wp-admin", "php-in-root", "non-code-core-file", "plugin-file", "config-file"])
def test_only_code_in_core_locations_absent_from_the_manifest_is_a_finding(site, analyze, rel, expected):
    write(site / rel)

    run = analyze(site, core_checksums=core_manifest(site))

    assert run.rules == expected
    assert run.has_gap("NO_TRUSTED_REFERENCE: 1 odczytanych plików nie ma wpisu w podanej referencji") is not expected
    for found in run.findings:
        assert (found["source"], found["severity"], found["confidence"]) == (rel, "medium", "low")
        assert "innej wersji" in found["explanation"]


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


def test_hardlinked_and_symlinked_core_files_are_not_hashed_unless_allowed(site, evidence, analyze):
    linked = write(site / "wp-includes" / "hardlinked.php")
    os.link(linked, evidence / "second-name.php")
    os.symlink(write(evidence / "outside.php"), site / "wp-includes" / "symlinked.php")
    manifest = {"checksums": {"index.php": md5(site / "index.php"), "wp-includes/hardlinked.php": OLD_MD5,
                              "wp-includes/symlinked.php": OLD_MD5}}

    skipped = analyze(site, core_checksums=manifest)
    allowed = analyze(site, core_checksums=manifest, flags=("--allow-hardlinks",))

    assert skipped.rules == set()
    assert [skipped.evidence(f"files/wp-includes/{name}.php")["sha256"] for name in ("hardlinked", "symlinked")] == [None, None]
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
], ids=["invalid-json", "array", "baseline-shape", "api-not-found", "empty", "empty-nested", "parent-traversal", "absolute-path",
        "dot-segment", "empty-segment", "backslash", "nul-byte", "path-too-long", "empty-path", "number-value", "sha256-value",
        "uppercase-md5", "list-value", "mixed-nesting", "bad-nested-version", "conflicting-versions", "bad-label", "not-utf8"])
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


# --- NOT_CHECKED per klasa, pokrycie i case.json ------------------------------------------------

def test_file_classes_without_a_reference_are_not_checked_and_never_called_clean(complete_case, analyze):
    site = complete_case["site"]
    for rel in ("wp-content/plugins/demo/demo.php", "wp-content/plugins/demo/readme.txt", "wp-content/themes/demo/style.css",
                MU_PLUGIN, "wp-content/object-cache.php", "wp-content/uploads/2026/photo.jpg"):
        write(site / rel, "synthetic placeholder\n")

    run = analyze(**complete_case)

    unchecked = sorted(gap for gap in run.gaps if gap.startswith("NOT_CHECKED"))
    assert unchecked == [f"NOT_CHECKED: integralność plików klasy {name} (plików: {count}) niezweryfikowana — brak zaufanej referencji"
                         for name, count in (("CORE", 1), ("DROPIN", 1), ("MU_PLUGIN", 1), ("PLUGIN", 2), ("THEME", 1))]
    assert set(unchecked) <= set(run.coverage("files")["reasons"])
    assert (run.coverage("files")["status"], run.report["scope_complete"]) == ("ANALYZED", True)  # nota nie obniża statusu (ADR 0003)
    assert not any(word in run.json_text.lower() for word in ("clean", "czyst"))


def test_not_checked_counts_only_files_that_no_reference_covers(site, analyze):
    covered = write(site / "wp-content" / "plugins" / "demo" / "demo.php")
    write(site / "wp-content" / "plugins" / "premium-demo" / "premium.php")

    run = analyze(site, baseline={"files": {"wp-content/plugins/demo/demo.php": sha256(covered)}}, core_checksums=core_manifest(site))

    assert [gap for gap in run.gaps if gap.startswith("NOT_CHECKED")] == [
        "NOT_CHECKED: integralność plików klasy PLUGIN (plików: 1 z 2) niezweryfikowana — brak zaufanej referencji"]


def test_manifest_alone_is_reported_under_the_baseline_source_without_new_sources(complete_case, tmp_path, analyze):
    manifest = write(tmp_path / "core-9.9.9.json", json.dumps(core_manifest(complete_case["site"])))

    run = analyze(**complete_case, core_checksums=manifest)

    assert list(run.report["coverage"]) == ["files", "database", "logs", "baseline"]
    assert (run.coverage("baseline")["status"], run.coverage("baseline")["entries"]["READ"]) == ("ANALYZED", 1)
    assert run.has_gap("referencją jest wyłącznie manifest sum rdzenia")
    assert run.report["scope_complete"] is True
    assert run.case["sources"]["baseline"] == {"provided": False, "name": None}
    assert run.case["sources"]["core_checksums"] == {"provided": True, "name": "core-9.9.9.json"}


def test_case_json_has_no_manifest_entry_when_none_was_given(site, analyze):
    assert "core_checksums" not in analyze(site, baseline=index_only(site)).case["sources"]
