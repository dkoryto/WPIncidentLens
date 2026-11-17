"""Przykładowa sprawa (M7, T-701): polecenie i oczekiwany wynik z examples/synthetic-case/README.md muszą zgadzać się
z narzędziem. Test czyta polecenie, ocenę, kod wyjścia i zbiór reguł z samego dokumentu, więc opis nie może się rozjechać."""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

from wpincidentlens.cli import main
from wpincidentlens.rules import REGISTRY

ROOT = Path(__file__).parents[1]
SAMPLE = ROOT / "examples" / "synthetic-case" / "README.md"


def _documented() -> tuple[list[str], dict[str, str], set[str]]:
    text = SAMPLE.read_text(encoding="utf-8")
    commands = re.findall(r"^python -m wpincidentlens (.+)$", text, re.M)
    assert len(commands) == 1, "README przykładowej sprawy ma mieć dokładnie jedno polecenie python -m wpincidentlens"
    fields = dict(re.findall(r"^\| `(assessment|scope_complete|exit_code)` \| `([^`]+)` \|$", text, re.M))
    findings = text.split("### Ustalenia", 1)[1].split("\n#", 1)[0]
    rules = set(re.findall(r"^\| `([A-Z][A-Z0-9_]+)` \|", findings, re.M))
    return shlex.split(commands[0]), fields, rules


def _with_output(argv: list[str], output: Path) -> list[str]:
    position = argv.index("--output")
    return [*argv[:position + 1], str(output), *argv[position + 2:]]


def test_sample_case_document_is_complete():
    argv, fields, rules = _documented()

    assert set(fields) == {"assessment", "scope_complete", "exit_code"}
    assert "--output" in argv
    assert rules and rules <= REGISTRY.keys()


def test_sample_case_command_gives_documented_result(tmp_path, monkeypatch):
    argv, fields, rules = _documented()
    monkeypatch.chdir(ROOT)  # ścieżki fixtures/ w poleceniu są względne do katalogu głównego repozytorium

    code = main(_with_output(argv, tmp_path / "out"))

    report = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert code == int(fields["exit_code"])
    assert report["assessment"] == fields["assessment"]
    assert json.dumps(report["scope_complete"]) == fields["scope_complete"]
    assert {finding["rule_id"] for finding in report["findings"]} == rules
