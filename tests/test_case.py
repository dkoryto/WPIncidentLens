"""CaseManager (C01) i ``case.json`` (T-101): walidacja wywołania przed odczytem dowodów, kontekst sprawy, zapis opisu sprawy.

Wyłącznie dane syntetyczne w ``tmp_path``.
"""
from __future__ import annotations

import ast
import copy
import dataclasses
import json
import os
from datetime import datetime
from pathlib import Path

import pytest
from conftest import CANARY, XSS, analyze_demo, case_schema_errors, replace_at, sha256, write

from wpincidentlens import case, cli, ingest

VALID_IDENTIFIERS = ["A", "0", "_x", "WPINCIDENTLENS-DEMO", "case_1.2-x", "a" * 64]
INVALID_IDENTIFIERS = {
    "empty": "", "too-long": "a" * 65, "leading-dot": ".hidden", "leading-dash": "-x", "parent-directory": "../x",
    "slash": "a/b", "backslash": "a\\b", "space": "a b", "newline": "a\nb", "trailing-newline": "a\n", "nul": "a\x00b",
    "delete-character": "a\x7f", "non-ascii-letter": "sprawa-ą", "lone-surrogate": "a\ud800", "undecodable-argv-byte": "a\udc80",
    "markup": XSS,
}
IDENTIFIER_FLAGS = ["--case-id", "--operator-id"]
TIME_DEPENDENT = ("created_at_utc", "analysis_finished_at_utc", "report")  # skrót raportu zależy od analyzed_at_utc w report.json


@pytest.fixture
def analysis_forbidden(monkeypatch):
    """Od tej chwili rozpoczęcie analizy jest błędem testu: odmowa musi nastąpić wcześniej."""
    def started(*args, **kwargs):
        raise AssertionError("analiza rozpoczęta mimo niepoprawnego wywołania")
    monkeypatch.setattr(cli, "compose_report", started)


def strings(document) -> list[str]:
    """Wszystkie teksty dokumentu JSON: klucze i wartości."""
    if isinstance(document, dict):
        return [text for key, value in document.items() for text in (key, *strings(value))]
    if isinstance(document, list):
        return [text for value in document for text in strings(value)]
    return [document] if isinstance(document, str) else []


# --- identyfikatory ------------------------------------------------------------------------------

@pytest.mark.parametrize("value", VALID_IDENTIFIERS)
def test_valid_case_id_is_recorded_in_report_and_case(site, analyze, value):
    run = analyze(site, case_id=value)

    assert (run.report["case_id"], run.case["case_id"]) == (value, value)


@pytest.mark.parametrize("value", VALID_IDENTIFIERS)
def test_valid_operator_id_is_recorded_in_case(site, analyze, value):
    assert analyze(site, flags=(f"--operator-id={value}",)).case["operator_id"] == value


@pytest.mark.parametrize("flag", IDENTIFIER_FLAGS)
@pytest.mark.parametrize("value", INVALID_IDENTIFIERS.values(), ids=INVALID_IDENTIFIERS.keys())
def test_invalid_identifier_is_refused_before_analysis(site, refuse, analysis_forbidden, flag, value):
    assert flag in refuse("--files", str(site), f"{flag}={value}")


@pytest.mark.parametrize("flag", IDENTIFIER_FLAGS)
def test_refusal_does_not_echo_the_rejected_identifier(site, refuse, flag):
    assert CANARY not in refuse("--files", str(site), f"{flag}=../{CANARY}")


def test_case_id_keeps_its_default(site, tmp_path):
    cli.main(["--files", str(site), "--output", str(tmp_path / "out")])

    assert json.loads((tmp_path / "out" / "case.json").read_text(encoding="utf-8"))["case_id"] == "WPINCIDENTLENS-DEMO"


def test_operator_id_is_null_unless_given(site, analyze):
    assert analyze(site).case["operator_id"] is None


def test_operator_is_never_taken_from_the_environment(site, analyze, monkeypatch):
    for name in ("USER", "LOGNAME", "USERNAME", "HOSTNAME", "HOME"):
        monkeypatch.setenv(name, CANARY)

    run = analyze(site)

    assert CANARY not in run.everything + json.dumps(run.case)


def test_case_manager_imports_nothing_that_identifies_the_host_or_opens_files():
    tree = ast.parse(Path(case.__file__).read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}

    assert imported <= {"__future__", "collections", "dataclasses", "datetime", "math", "pathlib", "re"}


# --- teksty nie do zapisania w UTF-8 -------------------------------------------------------------

@pytest.mark.parametrize("login", ["ghost\udc80", "ghost\ud800"], ids=["undecodable-argv-byte", "lone-surrogate"])
def test_known_admin_that_cannot_be_encoded_is_refused_before_analysis(site, refuse, analysis_forbidden, login):
    assert "--known-admin" in refuse("--files", str(site), f"--known-admin={login}")


@pytest.mark.parametrize("content", [
    '{"files": {"wp-\\ud800.php": "' + "0" * 64 + '"}}', '{"files": {"index.php": "\\ud800"}}', '{"known_admins": ["ghost\\udfff"]}',
], ids=["file-path", "file-digest", "known-admin"])
def test_baseline_text_that_cannot_be_encoded_is_refused_before_analysis(site, evidence, refuse, analysis_forbidden, content):
    baseline = write(evidence / "baseline.json", content)

    assert "--baseline" in refuse("--files", str(site), "--baseline", str(baseline))


# --- katalog wyników -----------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["out\x00dir", "out\ud800dir"], ids=["nul", "lone-surrogate"])
def test_output_path_that_is_not_a_valid_path_is_refused(site, tmp_path, capsys, name):
    with pytest.raises(SystemExit) as refusal:
        cli.main(["--files", str(site), "--output", str(tmp_path / name)])

    assert refusal.value.code == 2
    assert "--output" in capsys.readouterr().err


def test_output_path_that_is_a_regular_file_is_refused_and_left_intact(site, tmp_path, capsys):
    occupied = write(tmp_path / "out", "synthetic")

    with pytest.raises(SystemExit) as refusal:
        cli.main(["--files", str(site), "--output", str(occupied)])

    assert refusal.value.code == 2
    assert occupied.read_text(encoding="utf-8") == "synthetic"


# --- kontekst sprawy -----------------------------------------------------------------------------

def test_case_context_is_frozen(site, tmp_path):
    context = case.build(files=site, output=tmp_path / "out", case_id="T101-SYNTH")

    with pytest.raises(dataclasses.FrozenInstanceError):
        context.case_id = "OTHER"


def test_building_the_context_reads_no_evidence_content_and_creates_no_output(site, tmp_path, monkeypatch):
    def read(*args, **kwargs):
        raise AssertionError("CaseManager czyta treść")
    monkeypatch.setattr(os, "read", read)

    case.build(files=site, output=tmp_path / "out", case_id="T101-SYNTH")

    assert not (tmp_path / "out").exists()


def test_context_carries_validated_limits_flags_and_trusted_admins(site, tmp_path):
    context = case.build(files=site, output=tmp_path / "out", case_id="T101-SYNTH", known_admins=["siteadmin", "siteadmin"],
                         limits={"max_depth": 3}, allow_hardlinks=True, reverify=False)

    assert (context.limits, context.allow_hardlinks, context.reverify, context.known_admins) == (
        ingest.Limits(max_depth=3), True, False, frozenset({"siteadmin"}))


def test_source_given_without_a_name_is_described_with_null(site, tmp_path, monkeypatch):
    monkeypatch.chdir(site)

    described = case.build(files=Path("."), output=tmp_path / "out", case_id="T101-SYNTH").describe()

    assert described["sources"]["files"] == {"provided": True, "name": None}


# --- case.json -----------------------------------------------------------------------------------

def test_case_json_has_the_case_poc_1_shape(demo_case, analyze):
    record = analyze_demo(analyze, demo_case).case

    assert record["schema_version"] == "case-poc-1"
    assert list(record) == ["schema_version", "case_id", "operator_id", "tool", "tool_version", "created_at_utc", "analysis_finished_at_utc",
                            "sources", "limits", "flags", "report", "assessment", "exit_code"]


def test_case_json_conforms_to_the_published_schema(demo_case, analyze):
    assert case_schema_errors(analyze_demo(analyze, demo_case).case) == []


@pytest.mark.parametrize("path, value", [
    (("sources", "files", "name"), "/srv/evidence/site"), (("sources", "logs", "name"), "evidence/logs"),
    (("case_id",), "../x"), (("operator_id",), "a b"), (("report", "sha256"), "0" * 63), (("report", "file"), "/tmp/report.json"),
    (("limits", "max_depth"), 0), (("exit_code",), 2), (("hostname",), "synthetic-host"), (("sources", "files", "path"), "site"),
], ids=["absolute-source-path", "relative-source-path", "case-id-traversal", "operator-id-space", "short-digest", "report-path",
        "zero-limit", "exit-code-of-refusal", "unknown-field", "unknown-source-field"])
def test_case_schema_rejects_a_document_outside_the_contract(demo_case, analyze, path, value):
    record = copy.deepcopy(analyze_demo(analyze, demo_case).case)
    replace_at(record, path, value)

    assert case_schema_errors(record) != []


def test_case_schema_rejects_a_name_for_a_source_that_was_not_provided(site, analyze):
    record = analyze(site).case
    record["sources"]["database"]["name"] = "db.sql"

    assert case_schema_errors(record) != []


def test_case_json_contains_no_host_path(demo_case, analyze, tmp_path):
    run = analyze_demo(analyze, demo_case)

    assert str(tmp_path) not in (run.out / "case.json").read_text(encoding="utf-8")
    assert [text for text in strings(run.case) if "/" in text or "\\" in text] == []


def test_case_json_names_only_the_last_component_of_each_source(demo_case, analyze):
    assert analyze_demo(analyze, demo_case).case["sources"] == {
        "files": {"provided": True, "name": "site"}, "database": {"provided": True, "name": "database.sql", "format": "sql"},
        "logs": {"provided": True, "name": "logs"}, "baseline": {"provided": True, "name": "baseline.json"}}


def test_case_json_marks_sources_that_were_not_provided(site, analyze):
    sources = analyze(site).case["sources"]

    assert [sources[name] for name in ("database", "logs", "baseline")] == [{"provided": False, "name": None}] * 3


def test_case_json_digest_matches_the_written_report(demo_case, analyze):
    run = analyze_demo(analyze, demo_case)

    assert run.case["report"] == {"file": "report.json", "sha256": sha256(run.out / "report.json")}


def test_case_json_repeats_tool_assessment_and_exit_code_of_the_run(site, analyze):
    run = analyze(site)

    assert (run.case["tool"], run.case["tool_version"], run.case["assessment"], run.case["exit_code"]) == (
        run.report["tool"], run.report["tool_version"], run.report["assessment"], run.exit_code)


def test_case_json_times_are_utc_and_ordered(site, analyze):
    run = analyze(site)
    created, finished = (datetime.fromisoformat(run.case[name]) for name in ("created_at_utc", "analysis_finished_at_utc"))

    assert run.case["analysis_finished_at_utc"] == run.report["analyzed_at_utc"]
    assert created <= finished and created.utcoffset().total_seconds() == 0


def test_case_json_records_default_limits(site, analyze):
    assert analyze(site).case["limits"] == dataclasses.asdict(ingest.Limits())


@pytest.mark.parametrize("flags, expected", [
    ((), {"allow_hardlinks": False, "reverify": True}),
    (("--allow-hardlinks", "--no-reverify"), {"allow_hardlinks": True, "reverify": False}),
], ids=["defaults", "both-set"])
def test_case_json_records_flags(site, analyze, flags, expected):
    assert analyze(site, flags=flags).case["flags"] == expected


def test_two_runs_give_identical_case_json_apart_from_time_dependent_fields(demo_case, analyze):
    first, second = (analyze_demo(analyze, demo_case).case for _ in range(2))

    assert all(first.pop(name) and second.pop(name) for name in TIME_DEPENDENT)
    assert first == second


# --- nowe flagi limitów --------------------------------------------------------------------------

@pytest.mark.parametrize("flag, limit, gap", [
    ("--max-depth", "max_depth", "limitu głębokości 1 nieprzeglądany: a/b"),
    ("--max-path-bytes", "max_path_bytes", "Ścieżka dłuższa niż 1 bajtów pominięta"),
])
def test_new_limit_flag_bounds_the_walk_and_is_recorded(site, analyze, flag, limit, gap):
    write(site / "a" / "b" / "deep.php")

    run = analyze(site, flags=(flag, "1"))

    assert run.has_gap(gap)
    assert run.case["limits"][limit] == 1


@pytest.mark.parametrize("flag, value", [("--max-depth", "0"), ("--max-path-bytes", "-1"), ("--max-seconds", "inf"), ("--max-seconds", "nan")],
                         ids=["zero-depth", "negative-path-bytes", "infinite-seconds", "nan-seconds"])
def test_limit_that_is_not_a_positive_finite_number_is_refused(site, refuse, analysis_forbidden, flag, value):
    assert "limit" in refuse("--files", str(site), flag, value)
