"""``wpincidentlens report verify`` (R-90, ADR 0011): spójność katalogu wyników.

Wyłącznie dane syntetyczne w ``tmp_path``. Katalog wyników jest traktowany jak nieufne wejście: każda podmiana
(plik, widok, ``case.json``, dowiązanie, nadmiarowy plik, rozmiar) musi dać kod różny od 0, a wypisany wynik nie może
powtarzać treści plików ani surowych nazw z sekwencjami sterującymi.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from conftest import LEGACY_REPORT_PATH, sha256, sparse, write

from wpincidentlens import cli, report, verify
from wpincidentlens.migrate import migrate_0_1_0

VIEWS = ("report.html", "evidence-manifest.json", "observations.jsonl", "findings.json", "timeline.json", "coverage.json", "run.log")


@pytest.fixture
def results(demo_case: Path, tmp_path: Path) -> Path:
    """Katalog wyników analizy syntetycznego incydentu (pliki, baza, logi, baseline)."""
    out = tmp_path / "results"
    code = cli.main(["--files", str(demo_case / "site"), "--database", str(demo_case / "database.sql"), "--logs", str(demo_case / "logs"),
                     "--baseline", str(demo_case / "baseline.json"), "--output", str(out), "--case-id", "T701-SYNTH"])
    assert code in (cli.EXIT_COMPLETE, cli.EXIT_PARTIAL)
    return out


def check(directory: Path, capsys, *flags: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = cli.main(["report", "verify", str(directory), "--json", *flags])
    return code, json.loads(capsys.readouterr().out)


def problems(outcome: dict) -> set[tuple[str, str]]:
    return {(item["file"], item["problem"]) for item in outcome["problems"]}


def reseal(directory: Path) -> None:
    """Podmiana „spójna”: case.json dostaje skróty bieżących plików, jak zrobiłby to ktoś, kto zmienia wynik świadomie."""
    case = json.loads((directory / "case.json").read_text(encoding="utf-8"))
    case["outputs"] = {name: sha256(directory / name) for name in case["outputs"]}
    case["report"]["sha256"] = case["outputs"]["report.json"]
    (directory / "case.json").write_text(json.dumps(case), encoding="utf-8")


def edit_json(path: Path, change) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document)
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")


# --- wynik spójny ------------------------------------------------------------------------------------------

def test_fresh_results_verify(results, capsys):
    code, outcome = check(results, capsys)

    assert code == verify.EXIT_VERIFIED == 0
    assert outcome == {"status": "VERIFIED", "exit_code": 0, "case_id": "T701-SYNTH", "files_checked": 9, "problems": [], "notes": []}


def test_text_output_names_the_verdict_and_the_limits_of_verification(results, capsys):
    capsys.readouterr()
    assert cli.main(["report", "verify", "--case", str(results)]) == 0

    text = capsys.readouterr().out
    assert "ZGODNY" in text and "nie potwierdza autentyczności źródeł" in text


def test_pseudonymized_results_verify(demo_case, tmp_path, capsys):
    """``report.html`` zależy od ``flags.pseudonymize``; weryfikacja wylicza go z tą samą flagą."""
    out = tmp_path / "pseudo"
    cli.main(["--files", str(demo_case / "site"), "--logs", str(demo_case / "logs"), "--output", str(out), "--pseudonymize"])

    assert check(out, capsys)[0] == 0


def test_migrated_report_from_another_tool_version_verifies_by_digests_with_a_note(tmp_path, capsys):
    document = migrate_0_1_0(json.loads(LEGACY_REPORT_PATH.read_text(encoding="utf-8")))
    described = {"schema_version": "case-poc-1", "case_id": document["case_id"], "operator_id": None,
                 "created_at_utc": "2026-11-11T00:00:00+00:00", "sources": {}, "limits": {}, "flags": {}}
    report.write(tmp_path / "migrated", document, described, cli.exit_code(document))

    code, outcome = check(tmp_path / "migrated", capsys)

    assert code == 0 and outcome["problems"] == []
    assert len(outcome["notes"]) == 1 and "innej wersji narzędzia" in outcome["notes"][0]


# --- podmiany i braki ---------------------------------------------------------------------------------------

def test_modified_report_json_is_a_mismatch(results, capsys):
    with (results / "report.json").open("a", encoding="utf-8") as handle:
        handle.write(" ")

    code, outcome = check(results, capsys)

    assert code == verify.EXIT_MISMATCH == 1
    assert problems(outcome) == {("report.json", "MODIFIED")}


@pytest.mark.parametrize("name", VIEWS)
def test_modified_view_is_a_mismatch(results, capsys, name):
    with (results / name).open("ab") as handle:
        handle.write(b"\n")

    code, outcome = check(results, capsys)

    assert code == 1 and problems(outcome) == {(name, "MODIFIED")}


@pytest.mark.parametrize("name", ["findings.json", "report.html", "run.log"])
def test_view_rewritten_together_with_case_json_is_stale_against_report_json(results, capsys, name):
    with (results / name).open("ab") as handle:
        handle.write(b"\n")
    reseal(results)

    code, outcome = check(results, capsys)

    assert code == 1 and problems(outcome) == {(name, "INCONSISTENT")}


def test_report_json_changed_and_resealed_leaves_its_views_stale(results, capsys):
    edit_json(results / "report.json", lambda document: document["findings"][0].update(reason="synthetic replaced reason"))
    reseal(results)

    code, outcome = check(results, capsys)

    assert code == 1
    assert {("findings.json", "INCONSISTENT"), ("report.html", "INCONSISTENT")} <= problems(outcome)


@pytest.mark.parametrize("name", ["report.json", *VIEWS])
def test_missing_result_file_is_a_mismatch(results, capsys, name):
    (results / name).unlink()

    code, outcome = check(results, capsys)

    assert code == 1 and (name, "MISSING") in problems(outcome)


def test_extra_file_is_reported_by_neutralised_name_only(results, capsys):
    write(results / "notes\x1b[31m‮.txt", "SYNTHETIC-EXTRA-CONTENT")

    capsys.readouterr()
    code = cli.main(["report", "verify", str(results)])
    text = capsys.readouterr().out

    assert code == 1
    assert "EXTRA notes\\x1b\\x5b31m\\u202e.txt" in text
    assert "\x1b" not in text and "‮" not in text and "SYNTHETIC-EXTRA-CONTENT" not in text


def test_leftover_temporary_file_of_an_interrupted_write_is_extra(results, capsys):
    write(results / ".report.json.0123456789abcdef.tmp", "{}")

    assert problems(check(results, capsys)[1]) == {(".report.json.0123456789abcdef.tmp", "EXTRA")}


def test_files_in_a_subdirectory_are_extra(results, capsys):
    write(results / "nested" / "report.json", "{}")

    assert problems(check(results, capsys)[1]) == {("nested/report.json", "EXTRA")}


@pytest.mark.parametrize("name", ["report.json", "run.log"])
def test_result_replaced_by_a_symlink_is_not_followed(results, tmp_path, capsys, name):
    copy = write(tmp_path / "elsewhere" / name, (results / name).read_bytes())
    (results / name).unlink()
    (results / name).symlink_to(copy)

    code, outcome = check(results, capsys)

    assert code == 1 and (name, "NOT_REGULAR") in problems(outcome)


def test_fifo_named_like_a_result_does_not_block_verification(results, capsys):
    (results / "timeline.json").unlink()
    os.mkfifo(results / "timeline.json")

    code, outcome = check(results, capsys)

    assert code == 1 and ("timeline.json", "NOT_REGULAR") in problems(outcome)


def test_oversized_file_is_refused_without_reading(results, capsys):
    limit = max((results / name).stat().st_size for name in os.listdir(results)) + 1
    sparse(results / "report.html", limit + 1)

    code, outcome = check(results, capsys, "--max-file-bytes", str(limit))

    assert code == 1 and problems(outcome) == {("report.html", "TOO_LARGE")}


def test_report_json_that_is_not_json_is_a_mismatch(results, capsys):
    write(results / "report.json", '{"schema_version": "poc-1", <script>')
    reseal(results)

    code, outcome = check(results, capsys)

    assert code == 1 and problems(outcome) == {("report.json", "INVALID_JSON")}


def test_report_json_breaking_the_contract_is_reported_without_its_values(results, capsys):
    edit_json(results / "report.json", lambda document: document.update(assessment="NO_INDICATORS_IN_ANALYZED_SCOPE",
                                                                        case_id="\x1b]0;SYNTHETIC-TITLE\x07"))
    reseal(results)

    capsys.readouterr()
    code = cli.main(["report", "verify", str(results)])
    text = capsys.readouterr().out

    assert code == 1 and "INVALID_REPORT report.json" in text
    assert "NO_INDICATORS" not in text and "SYNTHETIC-TITLE" not in text


def test_report_json_with_duplicated_key_is_invalid(results, capsys):
    text = (results / "report.json").read_text(encoding="utf-8")
    write(results / "report.json", text.replace('"schema_version": "poc-1",', '"schema_version": "poc-1", "schema_version": "poc-1",', 1))
    reseal(results)

    assert problems(check(results, capsys)[1]) == {("report.json", "INVALID_JSON")}


@pytest.mark.parametrize("field, value", [("exit_code", 0), ("assessment", "INCONCLUSIVE"), ("case_id", "OTHER-CASE")])
def test_case_json_field_contradicting_report_json_is_a_mismatch(results, capsys, field, value):
    edit_json(results / "case.json", lambda case: case.update({field: value}))

    code, outcome = check(results, capsys)

    assert code == 1 and {"file": "case.json", "problem": "CASE_MISMATCH", "detail": field} in outcome["problems"]


def test_result_file_dropped_from_case_json_together_with_its_file_is_still_reported(results, capsys):
    (results / "timeline.json").unlink()
    edit_json(results / "case.json", lambda case: case["outputs"].pop("timeline.json"))

    code, outcome = check(results, capsys)

    assert code == 1 and problems(outcome) == {("timeline.json", "NOT_LISTED")}


# --- wejście nieużyteczne -----------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["../outside.json", "nested/report.json", "/etc/passwd", "case.json"])
def test_case_json_listing_a_name_outside_the_result_files_is_unusable(results, capsys, name):
    edit_json(results / "case.json", lambda case: case["outputs"].update({name: "0" * 64}))

    code, outcome = check(results, capsys)

    assert code == verify.EXIT_UNUSABLE == 2 and outcome["status"] == "UNUSABLE"
    assert outcome["error"].startswith("case.json: outputs wymienia plik spoza listy plików wyniku")  # stały tekst, bez nazwy


@pytest.mark.parametrize("content", ["not json", '{"schema_version": "case-poc-1", "schema_version": "case-poc-1"}', "[]",
                                     '{"schema_version": "case-poc-2"}'])
def test_unreadable_case_json_is_unusable(results, capsys, content):
    write(results / "case.json", content)

    assert check(results, capsys)[0] == 2


def test_case_json_without_outputs_is_unusable(results, capsys):
    edit_json(results / "case.json", lambda case: case.pop("outputs"))

    assert check(results, capsys)[0] == 2


def test_missing_case_json_is_unusable(results, capsys):
    (results / "case.json").unlink()

    code, outcome = check(results, capsys)

    assert code == 2 and "case.json" in outcome["error"]


def test_symlinked_case_json_is_unusable(results, tmp_path, capsys):
    copy = write(tmp_path / "case-copy.json", (results / "case.json").read_bytes())
    (results / "case.json").unlink()
    (results / "case.json").symlink_to(copy)

    assert check(results, capsys)[0] == 2


def test_oversized_case_json_is_unusable(results, capsys):
    sparse(results / "case.json", verify.MAX_CASE_BYTES + 1)

    assert check(results, capsys)[0] == 2


@pytest.mark.parametrize("make", [lambda path, real: path.symlink_to(real), lambda path, real: write(path, "x"), lambda path, real: None],
                         ids=["symlink", "regular-file", "missing"])
def test_directory_that_cannot_be_opened_safely_is_unusable(results, tmp_path, capsys, make):
    target = tmp_path / "given"
    make(target, results)

    code, outcome = check(target, capsys)

    assert code == 2 and str(tmp_path) not in outcome["error"]


def test_text_mode_reports_unusable_input_on_stderr(tmp_path, capsys):
    assert cli.main(["report", "verify", str(tmp_path / "missing")]) == 2

    assert "NIE MOŻNA ZWERYFIKOWAĆ" in capsys.readouterr().err


# --- wywołanie ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv", [["report"], ["report", "verify"], ["report", "verify", "a", "--case", "b"], ["report", "sign", "x"],
                                  ["report", "verify", "x", "--max-file-bytes", "0"]])
def test_invalid_report_invocation_is_a_usage_error(argv, capsys):
    with pytest.raises(SystemExit) as stop:
        cli.main(argv)

    assert stop.value.code == 2


def test_report_verify_help_documents_its_exit_codes(capsys):
    with pytest.raises(SystemExit) as stop:
        cli.main(["report", "verify", "--help"])

    text = " ".join(capsys.readouterr().out.split())
    assert stop.value.code == 0
    assert "0 — wynik spójny" in text and "1 — niezgodność" in text and "2 — wejście nieużyteczne" in text
