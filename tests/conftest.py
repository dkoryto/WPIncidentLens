"""Wspólne helpery testów (T-003, T-102).

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
from dataclasses import dataclass, field
from pathlib import Path

import jsonschema
import pytest

from wpincidentlens import ingest
from wpincidentlens.cli import EXIT_COMPLETE, EXIT_PARTIAL, EXIT_UNPROCESSED, main
from wpincidentlens.models import describe_location, validate_report

FIXTURES = Path(__file__).parents[1] / "fixtures"
SCHEMA_PATH = Path(__file__).parents[1] / "docs" / "schema" / "report-poc-1.schema.json"
CASE_SCHEMA_PATH = SCHEMA_PATH.with_name("case-poc-1.schema.json")
LEGACY_REPORT_PATH = Path(__file__).parent / "data" / "report-0.1.0.json"  # raport 0.1.0 z danych syntetycznych (dawne demo/report.json)
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


def schema_errors(report: dict, schema: Path = SCHEMA_PATH) -> list[str]:
    """Komunikaty walidacji raportu opublikowanym JSON Schema (draft 2020-12); pusta lista oznacza zgodność."""
    validator = jsonschema.Draft202012Validator(json.loads(schema.read_text(encoding="utf-8")))
    return sorted(error.message for error in validator.iter_errors(report))


def case_schema_errors(case: dict) -> list[str]:
    return schema_errors(case, CASE_SCHEMA_PATH)


def tamper_before_reverification(monkeypatch, tamper) -> None:
    """Hak: tuż przed ponowną weryfikacją (po zakończeniu analizy treści) materiał zostaje zmieniony."""
    real_finish = ingest.Session.finish

    def finish(session):
        tamper()
        return real_finish(session)

    monkeypatch.setattr(ingest.Session, "finish", finish)


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
    """Wynik uruchomienia ``wpincidentlens``: surowy raport ``poc-1`` oraz widoki łączące ustalenie z jego obserwacją i dowodem."""
    report: dict
    json_text: str
    html: str
    stdout: str
    out: Path
    exit_code: int = 0
    case: dict = field(default_factory=dict)  # odczytany case.json

    @property
    def findings(self) -> list[dict]:
        """Ustalenia razem z faktami pierwszej wskazanej obserwacji: miejsce (``source``) i atrybuty (``metadata``)."""
        observations = {item["id"]: item for item in self.report["observations"]}
        evidence = {item["id"]: item for item in self.report["evidence"]}
        views = []
        for finding in self.report["findings"]:
            fact = observations[finding["observations"][0]]
            views.append({"rule": finding["rule_id"], "severity": finding["severity"], "confidence": finding["confidence"],
                          "source_type": finding["category"], "source": describe_location(fact["location"]),
                          "explanation": finding["reason"], "metadata": _facts(fact, evidence[fact["evidence_id"]])})
        return views

    @property
    def rules(self) -> set[str]:
        return {item["rule"] for item in self.findings}

    @property
    def manifest(self) -> list[dict]:
        """Dowody, których bajty przeczytano (mają skrót), w kolejności ścieżek logicznych."""
        return [{"source": item["logical_path"], "sha256": item["sha256"], "size": item["size_bytes"]}
                for item in self.report["evidence"] if item["sha256"] is not None]

    def evidence(self, logical_path: str) -> dict:
        matches = [item for item in self.report["evidence"] if item["logical_path"] == logical_path]
        assert len(matches) == 1, f"oczekiwano jednego dowodu {logical_path}, jest {len(matches)}"
        return matches[0]

    def coverage(self, source: str) -> dict:
        return self.report["coverage"][source]

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


def _facts(observation: dict, evidence: dict) -> dict:
    """Fakty obserwacji uzupełnione o skrót pliku-dowodu albo, gdy pliku nie przeczytano, o status odczytu."""
    facts = dict(observation["attributes"])
    if observation["timestamp_raw"] is not None:
        facts["observed_time"] = observation["timestamp_raw"]
    if evidence["origin_kind"] == "file":
        facts.update({"sha256": evidence["sha256"]} if evidence["sha256"] else {"read_status": evidence["read_status"]})
    return facts


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
def complete_case(site: Path, evidence: Path) -> dict:
    """Argumenty ``analyze`` dla materiału bez wskaźników, z kompletem źródeł krytycznych: pliki, baza i logi."""
    return {"site": site, "database": write(evidence / "db.sql", admin_sql("siteadmin")),
            "logs": write(evidence / "logs" / "access.log", access_line("/about/")).parent, "known_admins": ("siteadmin",)}


@pytest.fixture
def demo_case(evidence: Path) -> Path:
    """Kopia syntetycznego incydentu z ``fixtures/`` (site, database.sql, logs, baseline.json)."""
    shutil.copytree(FIXTURES, evidence, dirs_exist_ok=True)
    return evidence


@pytest.fixture
def analyze(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """Uruchamia publiczny interfejs ``wpincidentlens`` i zwraca odczytany raport."""
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
        code = main(argv)
        assert code in (EXIT_COMPLETE, EXIT_PARTIAL, EXIT_UNPROCESSED), f"nieoczekiwany kod wyjścia {code}"
        json_text = (out / "report.json").read_text(encoding="utf-8")
        report = json.loads(json_text)
        validate_report(report)  # każdy raport zapisany w testach musi spełniać cały kontrakt poc-1…
        assert schema_errors(report) == []  # …i opublikowany JSON Schema
        case = json.loads((out / "case.json").read_text(encoding="utf-8"))
        assert case_schema_errors(case) == []
        return Run(report, json_text, (out / "report.html").read_text(encoding="utf-8"), capsys.readouterr().out, out, code, case)

    return run


@pytest.fixture
def refuse(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """Uruchamia ``wpincidentlens`` oczekując odmowy (kod 2); zwraca komunikat błędu, a wyniki nie mogą powstać."""
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
