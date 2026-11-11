"""Wspólne helpery testów T-003.

Wyłącznie dane syntetyczne tworzone w ``tmp_path``. Łańcuchy „złośliwe” to obojętne
znaczniki tekstowe: nic z materiału testowego nie jest wykonywane ani importowane.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest

from wptrace.cli import main

FIXTURES = Path(__file__).parents[1] / "fixtures"
HARMLESS_PHP = "<?php // synthetic placeholder, never executed\n"
EVAL_MARKER = "<?php // SYNTHETIC indicator text, never executed: eval(base64_decode('synthetic'));\n"
ADMIN_CAPS = 'a:1:{s:13:"administrator";b:1;}'
UPLOAD_PHP = "wp-content/uploads/2026/11/cache-view.php"
CANARY = "CANARY-T003-SYNTHETIC-0000"
XSS = "<img src=x onerror=alert(1)>"


def write(path: Path, content: str | bytes = HARMLESS_PHP) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root: Path) -> str:
    """Skrót drzewa: ścieżki, tryby, rozmiary, mtime i treść (bez atime, bez podążania za linkami)."""
    h = hashlib.sha256()
    for path in sorted([root, *root.rglob("*")]):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            body = os.readlink(path)
        elif stat.S_ISREG(info.st_mode):
            body = sha256(path)
        else:
            body = ""
        h.update(repr((path.relative_to(root).as_posix(), info.st_mode, info.st_size, info.st_mtime_ns, body)).encode())
    return h.hexdigest()


def sparse(path: Path, size: int, head: str | bytes = b"") -> Path:
    """Plik rzadki: nagłówek z treścią i dziura do ``size`` bajtów (bez zapisu danych)."""
    write(path, head)
    os.truncate(path, size)
    return path


def open_fd_count() -> int:
    """Liczba deskryptorów otwartych w procesie testowym (Linux i macOS)."""
    return len(os.listdir("/dev/fd"))


def access_line(uri: str, *, ip: str = "192.0.2.10", when: str = "09/Nov/2026:02:14:01 +0100",
                method: str = "GET", status: int = 200, extra: str = "") -> str:
    return f'{ip} - - [{when}] "{method} {uri} HTTP/1.1" {status} 75 "-" "SyntheticTest"{extra}\n'


def _quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def admin_sql(*logins: str, caps: str = ADMIN_CAPS, password: str = "x") -> str:
    """mysqldump-podobne INSERT-y: każdy login dostaje wiersz users i usermeta z rolą."""
    users = ",".join(f"({i},'{login}','{password}','{login}','{login}@example.invalid','','2026-01-01 00:00:00','',0,'{login}')"
                     for i, login in enumerate(logins, start=1))
    meta = ",".join(f"({i},{i},'wp_capabilities','{caps}')" for i, _ in enumerate(logins, start=1))
    return f"INSERT INTO `wp_users` VALUES {users};\nINSERT INTO `wp_usermeta` VALUES {meta};\n"


def option_sql(name: str, value: str) -> str:
    return ("INSERT INTO `wp_options` (`option_id`,`option_name`,`option_value`,`autoload`) "
            f"VALUES (1,'{_quote(name)}','{_quote(value)}','yes');\n")


def strip_time(report: dict) -> dict:
    return {key: value for key, value in report.items() if key != "analyzed_at_utc"}


def replace_at(document: dict, path: tuple, value) -> None:
    """Podmienia (albo dodaje) wartość w zagnieżdżonym dokumencie; ``path`` to kolejne klucze i indeksy."""
    *parents, last = path
    for step in parents:
        document = document[step]
    document[last] = value


def remove_at(document: dict, path: tuple) -> None:
    *parents, last = path
    for step in parents:
        document = document[step]
    del document[last]


class TimeBudgetExceeded(AssertionError):
    """Nie ``TimeoutError``: to podklasa ``OSError``, którą odczyt dowodów zamienia w lukę — zawieszenie zostałoby ukryte."""


@contextmanager
def time_limit(seconds: float):
    """Przerywa blokujące wywołanie (także wewnątrz ``re``) zamiast zawieszać cały zestaw testów."""
    def expired(signum, frame):
        raise TimeBudgetExceeded(f"przekroczono budżet {seconds} s")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@dataclass
class Run:
    report: dict
    json_text: str
    html: str
    stdout: str
    out: Path

    @property
    def findings(self) -> list[dict]:
        return self.report["findings"]

    @property
    def rules(self) -> set[str]:
        return {item["rule"] for item in self.findings}

    @property
    def gaps(self) -> list[str]:
        return self.report["coverage_gaps"]

    @property
    def everything(self) -> str:
        """Wszystko, co narzędzie wypisało: JSON, HTML i stdout."""
        return self.json_text + self.html + self.stdout

    def finding(self, rule: str) -> dict:
        matches = [item for item in self.findings if item["rule"] == rule]
        assert len(matches) == 1, f"oczekiwano jednego {rule}, jest {len(matches)}"
        return matches[0]

    def has_gap(self, fragment: str) -> bool:
        return any(fragment.lower() in gap.lower() for gap in self.gaps)


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    """Katalog materiału dowodowego; raporty trafiają obok, nigdy do środka."""
    path = tmp_path / "evidence"
    path.mkdir()
    return path


@pytest.fixture
def site(evidence: Path) -> Path:
    write(evidence / "site" / "index.php")
    return evidence / "site"


@pytest.fixture
def demo_case(evidence: Path) -> Path:
    """Kopia syntetycznego incydentu z ``fixtures/`` (site, database.sql, logs, baseline.json)."""
    shutil.copytree(FIXTURES, evidence, dirs_exist_ok=True)
    return evidence


@pytest.fixture
def analyze(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """Uruchamia publiczny interfejs ``wptrace`` i zwraca odczytany raport."""
    counter = iter(range(1, 1000))

    def run(site: Path, *, database: Path | None = None, logs: Path | None = None,
            baseline: Path | dict | None = None, known_admins: tuple[str, ...] = (), case_id: str = "T003-SYNTH",
            flags: tuple[str, ...] = ()) -> Run:
        number = next(counter)
        out = tmp_path / f"out-{number}"
        argv = ["--files", str(site), "--output", str(out), "--case-id", case_id, *flags]
        if database is not None:
            argv += ["--database", str(database)]
        if logs is not None:
            argv += ["--logs", str(logs)]
        if isinstance(baseline, dict):
            baseline = write(tmp_path / f"baseline-{number}.json", json.dumps(baseline))
        if baseline is not None:
            argv += ["--baseline", str(baseline)]
        for login in known_admins:
            argv += ["--known-admin", login]
        capsys.readouterr()
        assert main(argv) == 0
        json_text = (out / "report.json").read_text(encoding="utf-8")
        return Run(json.loads(json_text), json_text, (out / "report.html").read_text(encoding="utf-8"),
                   capsys.readouterr().out, out)

    return run


@pytest.fixture
def refuse(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """Uruchamia ``wptrace`` oczekując odmowy (kod 2); zwraca komunikat błędu, a wyniki nie mogą powstać."""
    def run(*argv: str) -> str:
        out = tmp_path / "refused-out"
        capsys.readouterr()
        with pytest.raises(SystemExit) as stop:
            main([*argv, "--output", str(out)])
        assert stop.value.code == 2
        assert not out.exists()
        return capsys.readouterr().err

    return run


def analyze_demo(analyze, case: Path) -> Run:
    return analyze(case / "site", database=case / "database.sql", logs=case / "logs", baseline=case / "baseline.json")
