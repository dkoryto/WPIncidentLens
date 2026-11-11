"""Niezmienniki S-15–S-18: brak sieci, brak zapisu w dowodach, brak wykonywania treści, deterministyczność."""
import ast
import os
import socket
import subprocess
from collections import Counter
from pathlib import Path

import pytest
from conftest import access_line, analyze_demo, open_fd_count, strip_time, tree_digest, write

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


def test_s16_output_inside_logs_directory_is_refused(site, evidence):
    logs = write(evidence / "logs" / "access.log", access_line("/")).parent

    with pytest.raises(SystemExit):
        main(["--files", str(site), "--logs", str(logs), "--output", str(logs / "report")])


@pytest.mark.parametrize("output", ["evidence/site/report", "evidence/logs", "evidence", "evidence/db.sql"],
                         ids=["inside-files", "equal-to-logs", "contains-every-source", "equal-to-database-file"])
def test_s16_output_overlapping_any_source_is_refused_before_anything_is_written(site, evidence, tmp_path, capsys, output):
    write(evidence / "logs" / "access.log", access_line("/"))
    write(evidence / "db.sql", "-- synthetic\n")
    write(evidence / "baseline.json", "{}")
    before = tree_digest(tmp_path)

    with pytest.raises(SystemExit) as refusal:
        main(["--files", str(site), "--database", str(evidence / "db.sql"), "--logs", str(evidence / "logs"),
              "--baseline", str(evidence / "baseline.json"), "--output", str(tmp_path / output)])

    assert refusal.value.code == 2
    assert "--output" in capsys.readouterr().err
    assert tree_digest(tmp_path) == before


def test_s16_analysis_with_every_flag_leaves_evidence_tree_unchanged(demo_case, analyze):
    os.link(demo_case / "site" / "index.php", demo_case / "site" / "hardlinked.php")
    os.mkfifo(demo_case / "logs" / "pipe.log")
    before = tree_digest(demo_case)

    analyze(demo_case / "site", database=demo_case / "database.sql", logs=demo_case / "logs",
            baseline=demo_case / "baseline.json", flags=("--allow-hardlinks",))

    assert tree_digest(demo_case) == before


def test_full_analysis_leaks_no_file_descriptor(demo_case, analyze):
    os.mkfifo(demo_case / "site" / "pipe.php")
    (demo_case / "logs" / "link.log").symlink_to(demo_case / "database.sql")
    before = open_fd_count()

    analyze_demo(analyze, demo_case)

    assert open_fd_count() == before


def test_report_keeps_the_0_1_0_shape(demo_case, analyze):
    """T-101 nie zmienia schematu: statusy odczytu trafiają do raportu wyłącznie jako teksty w ``coverage_gaps``."""
    report = analyze_demo(analyze, demo_case).report

    assert report["schema_version"] == "0.1.0"
    assert list(report) == ["schema_version", "tool", "tool_version", "case_id", "analyzed_at_utc", "assessment", "disclaimer",
                            "findings", "counts", "timeline", "coverage_gaps", "evidence_manifest"]
    assert {entry["source"].split("/")[0]: sorted(entry) for entry in report["evidence_manifest"]} == {
        "baseline": ["sha256", "size", "source"], "database": ["sha256", "size", "source"],
        "files": ["mtime_ns", "sha256", "size", "source"], "logs": ["sha256", "size", "source"]}
    assert all(isinstance(gap, str) for gap in report["coverage_gaps"])


# --- D4: dowody otwiera wyłącznie wptrace.ingest ---------------------------------------------------

FILE_CALLS = {"open", "fdopen", "read_bytes", "read_text", "write_bytes", "write_text", "scandir", "listdir", "walk", "fwalk",
              "rglob", "glob", "iglob", "iterdir", "stat", "lstat", "fstat", "exists", "lexists", "is_file", "is_dir",
              "is_symlink", "is_fifo", "is_socket", "is_mount", "samefile", "readlink", "realpath", "resolve", "getsize",
              "getmtime", "access", "mkdir", "makedirs", "unlink", "remove", "rmdir", "rename", "touch", "chmod", "truncate",
              "link", "symlink", "symlink_to", "hardlink_to", "mkfifo", "sendfile", "copyfile", "copytree", "rmtree"}
FILE_MODULES = {"shutil", "glob", "tempfile", "mmap", "fileinput", "linecache", "zipfile", "tarfile", "gzip", "bz2", "lzma",
                "sqlite3", "dbm", "shelve"}
UNQUALIFIED_IMPORTS = {"os", "os.path", "posix", "posixpath", "io", "builtins"}
# Wyjątki D4: Reporter nie jest jeszcze wydzielony, więc cli.py tworzy katalog wyników i zapisuje do niego
# report.json oraz report.html. Lista może się TYLKO skracać; nowe wywołanie plikowe poza ingest.py = błąd.
ALLOWED_FILE_CALLS = {("cli.py", "mkdir"): 1, ("cli.py", "write_text"): 2}


def _file_access(tree: ast.AST, module: str) -> Counter:
    """Zlicza wywołania i importy dające dostęp do systemu plików. Strażnik działa po nazwach — to potykacz, nie piaskownica."""
    found = Counter()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "attr", getattr(node.func, "id", None))
            if name in FILE_CALLS:
                found[(module, name)] += 1
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FILE_MODULES:
                    found[(module, f"import {alias.name}")] += 1
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in FILE_MODULES:
                found[(module, f"import {node.module}")] += 1
            elif node.module in UNQUALIFIED_IMPORTS:  # „from os import open” ukryłoby nazwę przed tym strażnikiem
                found[(module, f"from {node.module} import …")] += 1
    return found


def test_d4_only_ingest_touches_the_filesystem():
    found = Counter()
    for source in SOURCES:
        if source.name != "ingest.py":
            found += _file_access(ast.parse(source.read_text(encoding="utf-8")), source.name)

    assert dict(found) == ALLOWED_FILE_CALLS


@pytest.mark.parametrize("snippet", [
    "open(p)", "os.open(p, 0)", "p.open()", "p.read_bytes()", "p.read_text()", "os.scandir(p)", "os.listdir(p)", "p.rglob('*')",
    "p.glob('*')", "p.iterdir()", "p.stat()", "os.lstat(p)", "p.is_file()", "p.exists()", "p.resolve()", "os.path.realpath(p)",
    "import shutil", "from tempfile import mkstemp", "from os import scandir as s", "from io import open",
])
def test_d4_guard_recognises_file_access(snippet):
    found = _file_access(ast.parse(snippet), "new_module.py")

    assert found and not set(found) & set(ALLOWED_FILE_CALLS)


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
