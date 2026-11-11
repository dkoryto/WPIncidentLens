"""Niezmienniki S-15–S-18: brak sieci, brak zapisu w dowodach, brak wykonywania treści, deterministyczność."""
import ast
import os
import socket
import subprocess
from pathlib import Path

import pytest
from conftest import access_line, analyze_demo, strip_time, tree_digest, write

import wptrace
from wptrace.cli import main

SOURCES = sorted(Path(wptrace.__file__).parent.glob("*.py"))
NETWORK_MODULES = {"socket", "ssl", "urllib", "http", "ftplib", "smtplib", "asyncio", "requests", "httpx", "xmlrpc"}
EXECUTION_MODULES = {"subprocess", "multiprocessing", "ctypes", "pickle", "marshal", "importlib", "runpy", "pty"}
DEMO_RULES = {"EXECUTABLE_IN_UPLOADS", "SUSPICIOUS_PHP_EVAL_DECODE", "UNRECOGNIZED_ADMIN",
              "SUSPICIOUS_DB_MARKUP", "HTTP_EXECUTABLE_IN_UPLOADS", "CORRELATED_UPLOAD_REQUEST"}


def _forbid(monkeypatch, owner, names):
    def refuse(*args, **kwargs):
        raise AssertionError("narzędzie analityczne użyło zabronionego wywołania")
    for name in names:
        monkeypatch.setattr(owner, name, refuse)


def _imported_modules() -> set[str]:
    found = set()
    for source in SOURCES:
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                found |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.add(node.module.split(".")[0])
    return found


def test_s15_full_analysis_runs_with_sockets_blocked(demo_case, analyze, monkeypatch):
    _forbid(monkeypatch, socket, ["socket", "create_connection", "getaddrinfo"])

    assert analyze_demo(analyze, demo_case).rules == DEMO_RULES


def test_s15_engine_imports_no_network_modules():
    assert _imported_modules() & NETWORK_MODULES == set()


def test_s16_analysis_leaves_evidence_tree_unchanged(demo_case, analyze):
    (demo_case / "site" / "dangling-link.php").symlink_to(demo_case / "missing.php")
    before = tree_digest(demo_case)

    analyze_demo(analyze, demo_case)

    assert tree_digest(demo_case) == before


@pytest.mark.xfail(strict=True, reason="--output wewnątrz katalogu --logs nie jest odrzucane; raport ląduje w dowodach (#4)")
def test_s16_output_inside_logs_directory_is_refused(site, evidence):
    logs = write(evidence / "logs" / "access.log", access_line("/")).parent

    with pytest.raises(SystemExit):
        main(["--files", str(site), "--logs", str(logs), "--output", str(logs / "report")])


def test_s17_full_analysis_runs_with_process_spawning_blocked(demo_case, analyze, monkeypatch):
    _forbid(monkeypatch, subprocess, ["Popen", "run"])
    _forbid(monkeypatch, os, ["system", "popen", "posix_spawn", "execv", "execve", "fork"])

    assert analyze_demo(analyze, demo_case).rules == DEMO_RULES


def test_s17_engine_has_no_dynamic_execution_primitives():
    calls = {node.func.id for source in SOURCES for node in ast.walk(ast.parse(source.read_text(encoding="utf-8")))
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}

    assert calls & {"eval", "exec", "compile", "__import__"} == set()
    assert _imported_modules() & EXECUTION_MODULES == set()


def test_s18_two_runs_on_same_evidence_give_identical_json(demo_case, analyze):
    first, second = analyze_demo(analyze, demo_case), analyze_demo(analyze, demo_case)

    assert strip_time(first.report) == strip_time(second.report)


def test_s18_two_runs_on_same_evidence_give_identical_html(demo_case, analyze):
    first, second = analyze_demo(analyze, demo_case), analyze_demo(analyze, demo_case)

    assert first.html.replace(first.report["analyzed_at_utc"], "") == second.html.replace(second.report["analyzed_at_utc"], "")
