"""Widoki wyniku (R-40, ADR 0008 pkt 6): pliki wyliczane z ``report.json`` i ich skróty w ``case.json``.

Wyłącznie dane syntetyczne w ``tmp_path``; „złośliwe” nazwy i treści to obojętne znaczniki tekstowe.
"""
from __future__ import annotations

import json
import os

import pytest
from conftest import CANARY, EVAL_MARKER, analyze_demo, case_schema_errors, sha256, write

from wpincidentlens import cli, report

JSON_VIEWS = {
    "evidence-manifest.json": ("evidence-manifest-poc-1", ("evidence",)),
    "findings.json": ("findings-poc-1", ("findings",)),
    "timeline.json": ("timeline-poc-1", ("timeline",)),
    "coverage.json": ("coverage-poc-1", ("assessment", "scope_complete", "coverage", "coverage_gaps")),
}
LINE_FILES = ("observations.jsonl", "run.log")
LINE_BREAKS = "  \u0085"
FORGED = '"}\n{"kind": "FORGED"'


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def lines(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def hostile_site(site):
    """Witryna z plikiem w uploads, którego nazwa niesie znacznik i znaki uznawane przez ``splitlines`` za koniec wiersza."""
    write(site / "wp-content" / "uploads" / f"{CANARY}{LINE_BREAKS}{FORGED}.php", EVAL_MARKER)
    return site


# --- widoki równe częściom report.json -----------------------------------------------------------

@pytest.mark.parametrize("name", JSON_VIEWS)
def test_json_view_repeats_its_part_of_the_report(demo_case, analyze, name):
    run = analyze_demo(analyze, demo_case)
    version, parts = JSON_VIEWS[name]

    assert read_json(run.out / name) == {"schema_version": version, "case_id": run.report["case_id"],
                                         **{part: run.report[part] for part in parts}}


def test_observations_jsonl_has_one_report_observation_per_line_in_report_order(demo_case, analyze):
    run = analyze_demo(analyze, demo_case)

    assert run.report["observations"]
    assert lines(run.out / "observations.jsonl") == run.report["observations"]


def test_run_log_holds_only_allowlisted_structural_fields(demo_case, analyze):
    run = analyze_demo(analyze, demo_case)
    first, *coverage = lines(run.out / "run.log")

    assert first == {"event": "run", "tool": run.report["tool"], "tool_version": run.report["tool_version"],
                     "case_id": run.report["case_id"], "analyzed_at_utc": run.report["analyzed_at_utc"],
                     "assessment": run.report["assessment"], "scope_complete": run.report["scope_complete"],
                     "exit_code": run.exit_code, "findings": len(run.report["findings"]),
                     "observations": len(run.report["observations"]), "evidence": len(run.report["evidence"]),
                     "coverage_gaps": len(run.report["coverage_gaps"])}
    assert coverage == [{"event": "coverage", "source": source, "status": entry["status"], "entries": entry["entries"]}
                        for source, entry in run.report["coverage"].items()]


# --- treść z dowodów nie fałszuje wierszy i nie trafia do run.log ---------------------------------

@pytest.mark.parametrize("name", LINE_FILES)
def test_line_files_are_printable_ascii_so_evidence_cannot_split_a_record(hostile_site, analyze, name):
    run = analyze(hostile_site)
    text = (run.out / name).read_text(encoding="utf-8")

    assert CANARY in run.json_text  # nazwa pliku z dowodu dotarła do raportu, więc test coś sprawdza
    assert all(" " <= char <= "~" for line in text.split("\n") for char in line)


def test_hostile_observation_stays_a_single_jsonl_record(hostile_site, analyze):
    run = analyze(hostile_site)

    assert lines(run.out / "observations.jsonl") == run.report["observations"]


def test_run_log_contains_no_evidence_text_path_or_address(hostile_site, analyze, tmp_path):
    run = analyze(hostile_site)
    text = (run.out / "run.log").read_text(encoding="utf-8")

    assert run.report["findings"] and run.report["coverage_gaps"]
    assert [marker for marker in (CANARY, "/", "@", "FORGED", str(tmp_path)) if marker in text] == []


# --- case.json: skróty plików i zgodność wstecz ---------------------------------------------------

def test_case_json_lists_the_digest_of_every_other_result_file(demo_case, analyze):
    run = analyze_demo(analyze, demo_case)

    assert run.case["outputs"] == {name: sha256(run.out / name) for name in sorted(os.listdir(run.out)) if name != "case.json"}
    assert run.case["outputs"]["report.json"] == run.case["report"]["sha256"]


def test_case_json_without_outputs_still_validates(demo_case, analyze):
    """``case.json`` sprzed T-501 nie ma ``outputs``; schemat ``case-poc-1`` musi go nadal przyjmować."""
    record = analyze_demo(analyze, demo_case).case
    del record["outputs"]

    assert case_schema_errors(record) == []


@pytest.mark.parametrize("outputs", [{"../report.json": "0" * 64}, {"report.json": "not-a-digest"}],
                         ids=["unknown-file", "bad-digest"])
def test_case_schema_rejects_malformed_outputs(demo_case, analyze, outputs):
    record = analyze_demo(analyze, demo_case).case
    record["outputs"] = outputs

    assert case_schema_errors(record) != []


def test_interrupted_publish_leaves_views_that_case_json_marks_as_stale(site, tmp_path, monkeypatch):
    """Błąd przy zamianie ``case.json`` (ostatniej) zostawia nowe widoki obok starego ``case.json``: skróty się nie zgadzają."""
    out = tmp_path / "out"
    assert cli.main(["--files", str(site), "--output", str(out), "--case-id", "T501-SYNTH"]) in (0, 3)
    previous_case = (out / "case.json").read_bytes()
    write(site / "added.txt", "synthetic change")
    document = cli.compose_report(site, None, None, None, set(), "T501-SYNTH")
    real_replace = os.replace

    def replace(src, dst, **kwargs):
        if dst == "case.json":
            raise OSError(28, "synthetic write failure")
        return real_replace(src, dst, **kwargs)
    monkeypatch.setattr(os, "replace", replace)

    with pytest.raises(OSError):
        report.write(out, document, json.loads(previous_case), cli.exit_code(document))

    recorded = json.loads(previous_case)["outputs"]
    assert (out / "case.json").read_bytes() == previous_case
    assert sorted(os.listdir(out)) == sorted([*recorded, "case.json"])  # bez plików tymczasowych
    assert [name for name, digest in recorded.items() if sha256(out / name) != digest] != []


# --- odtwarzalność (S-18) -------------------------------------------------------------------------

@pytest.mark.parametrize("name", [*JSON_VIEWS, "observations.jsonl"])
def test_s18_two_runs_on_same_evidence_give_byte_identical_views(demo_case, analyze, name):
    first, second = analyze_demo(analyze, demo_case), analyze_demo(analyze, demo_case)

    assert (first.out / name).read_bytes() == (second.out / name).read_bytes()


def test_s18_two_runs_give_identical_run_log_apart_from_analysis_time(demo_case, analyze):
    first, second = analyze_demo(analyze, demo_case), analyze_demo(analyze, demo_case)
    logs = [(run.out / "run.log").read_text(encoding="utf-8").replace(run.report["analyzed_at_utc"], "") for run in (first, second)]

    assert logs[0] == logs[1]
