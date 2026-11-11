"""Reporter (C12): bezpieczny i atomowy zapis wyników (T-101, ADR 0002 D4).

Wyłącznie dane syntetyczne w ``tmp_path``; „dowód” to obojętny plik tekstowy.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from conftest import sha256, tamper_before_reverification, write

from wptrace import cli, report

OUTPUTS = ("report.json", "report.html", "case.json")
# Opis sprawy sprzed analizy w kształcie ``CaseContext.describe()``; pisarz przenosi go do case.json bez interpretacji.
DESCRIBED = {"schema_version": "case-poc-1", "case_id": "T101-SYNTH", "operator_id": None,
             "created_at_utc": "2026-11-11T00:00:00+00:00", "sources": {}, "limits": {}, "flags": {}}


def run(site: Path, out: Path) -> int:
    return cli.main(["--files", str(site), "--output", str(out), "--case-id", "T101-SYNTH"])


def publish(directory: Path, document: dict) -> None:
    report.write(directory, document, DESCRIBED, cli.exit_code(document))


@pytest.fixture
def document(site: Path) -> dict:
    """Raport ``poc-1`` z syntetycznego materiału, gotowy do zapisu."""
    return cli.compose_report(site, None, None, None, set(), "T101-SYNTH")


@pytest.fixture
def out(tmp_path: Path) -> Path:
    return tmp_path / "out"


def test_run_leaves_only_the_result_files_in_the_output_directory(site, out):
    run(site, out)

    assert sorted(os.listdir(out)) == sorted(OUTPUTS)


@pytest.mark.parametrize("name", OUTPUTS)
def test_new_result_file_is_readable_by_the_owner_only(site, out, name):
    run(site, out)

    assert stat.S_IMODE((out / name).stat().st_mode) == 0o600


def test_report_json_keeps_its_serialisation(out, document):
    publish(out, document)

    assert (out / "report.json").read_bytes() == json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8")


# --- dowiązania w katalogu wyników ---------------------------------------------------------------

@pytest.mark.parametrize("name", OUTPUTS)
def test_symlink_named_like_a_result_is_replaced_and_its_target_left_untouched(site, out, name):
    victim = site / "index.php"
    before = sha256(victim)
    out.mkdir()
    (out / name).symlink_to(victim)

    run(site, out)

    assert sha256(victim) == before
    assert stat.S_ISREG((out / name).lstat().st_mode)


def test_dangling_symlink_named_like_a_result_does_not_create_its_target(site, out, tmp_path):
    out.mkdir()
    (out / "report.json").symlink_to(tmp_path / "planted.json")

    run(site, out)

    assert not (tmp_path / "planted.json").exists()


def test_output_directory_given_as_symlink_is_refused_before_anything_is_written(site, out, tmp_path, capsys):
    real = tmp_path / "real-out"
    real.mkdir()
    out.symlink_to(real)

    with pytest.raises(SystemExit) as refusal:
        run(site, out)

    assert refusal.value.code == 2
    assert "--output" in capsys.readouterr().err
    assert os.listdir(real) == []


def test_output_directory_swapped_for_symlink_during_analysis_is_refused(site, out, tmp_path, monkeypatch, capsys):
    real = tmp_path / "real-out"
    real.mkdir()
    tamper_before_reverification(monkeypatch, lambda: out.symlink_to(real))

    with pytest.raises(SystemExit) as refusal:
        run(site, out)

    assert refusal.value.code == 2
    assert "--output" in capsys.readouterr().err
    assert os.listdir(real) == []


@pytest.mark.parametrize("make", [lambda path, real: path.symlink_to(real), lambda path, real: write(path, "synthetic")],
                         ids=["symlink", "regular-file"])
def test_writer_refuses_a_directory_that_is_not_a_real_directory(out, tmp_path, document, make):
    (tmp_path / "real-out").mkdir()
    make(out, tmp_path / "real-out")

    with pytest.raises(report.OutputRefusal) as refusal:
        publish(out, document)

    assert str(tmp_path) not in str(refusal.value)
    assert os.listdir(tmp_path / "real-out") == []


def test_trailing_slash_does_not_make_the_writer_follow_a_symlinked_directory(out, tmp_path, document):
    (tmp_path / "real-out").mkdir()
    out.symlink_to(tmp_path / "real-out")

    with pytest.raises(report.OutputRefusal):
        publish(f"{out}/", document)


def test_write_html_replaces_a_symlink_without_touching_its_target(site, tmp_path, document):
    victim = site / "index.php"
    before = sha256(victim)
    (tmp_path / "report.html").symlink_to(victim)

    cli.write_html(document, tmp_path / "report.html")

    assert sha256(victim) == before
    assert stat.S_ISREG((tmp_path / "report.html").lstat().st_mode)


# --- błąd w trakcie zapisu -----------------------------------------------------------------------

def _fail(monkeypatch, call: str) -> None:
    def broken(*args, **kwargs):
        raise OSError(28, "synthetic write failure")
    monkeypatch.setattr(os, call, broken)


@pytest.mark.parametrize("call", ["fsync", "replace"], ids=["while-writing", "while-renaming"])
def test_failed_write_leaves_no_partial_or_temporary_file(out, document, monkeypatch, call):
    _fail(monkeypatch, call)

    with pytest.raises(OSError):
        publish(out, document)

    assert os.listdir(out) == []


@pytest.mark.parametrize("call", ["fsync", "replace"], ids=["while-writing", "while-renaming"])
def test_failed_write_keeps_the_previous_results_intact(out, document, monkeypatch, call):
    previous = {name: write(out / name, "previous synthetic result").read_bytes() for name in OUTPUTS}
    _fail(monkeypatch, call)

    with pytest.raises(OSError):
        publish(out, document)

    assert {name: (out / name).read_bytes() for name in os.listdir(out)} == previous


def test_writer_leaks_no_file_descriptor_after_a_failed_write(out, document, monkeypatch):
    before = len(os.listdir("/dev/fd"))
    _fail(monkeypatch, "fsync")

    with pytest.raises(OSError):
        publish(out, document)

    assert len(os.listdir("/dev/fd")) == before


# --- kodowanie -----------------------------------------------------------------------------------

def test_value_that_cannot_be_encoded_is_escaped_instead_of_losing_the_json_report(out, document):
    document["coverage_gaps"] = ["synthetic \ud800 gap"]

    publish(out, document)

    assert json.loads((out / "report.json").read_bytes())["coverage_gaps"] == ["synthetic \ud800 gap"]


def test_value_that_cannot_be_encoded_is_escaped_instead_of_losing_the_html_report(out, document):
    document["coverage_gaps"] = ["synthetic \ud800 gap"]

    publish(out, document)

    assert "synthetic \\ud800 gap" in (out / "report.html").read_text(encoding="utf-8")
