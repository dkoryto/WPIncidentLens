"""Łańcuch dostaw (T-601, ADR 0009 pkt 2).

Lock z hashami musi odpowiadać extras z ``pyproject.toml``, a silnik nie może mieć
zależności runtime ani importować modułów spoza biblioteki standardowej.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
DEV_LOCK = ROOT / "requirements" / "dev.lock"
AUDIT_LOCK = ROOT / "requirements" / "audit.lock"
AUDIT_IN = ROOT / "requirements" / "audit.in"
YARA_LOCK = ROOT / "requirements" / "yara.lock"
YARA_IN = ROOT / "requirements" / "yara.in"
YARA_LOCK_COMMAND = "uv pip compile requirements/yara.in --generate-hashes --python-version 3.12 --universal -o requirements/yara.lock"
DEV_LOCK_COMMAND = "uv pip compile pyproject.toml --extra dev --generate-hashes --python-version 3.12 --universal -o requirements/dev.lock"

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")


def _parse_lock(path: Path) -> dict[str, tuple[str, int]]:
    """Zwraca {nazwa kanoniczna: (wersja, liczba hashy sha256)} dla wpisów locka."""
    pins: dict[str, tuple[str, int]] = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _PIN.match(line)
        if match:
            current = canonicalize_name(match.group(1))
            assert current not in pins, f"{path.name}: powtórzony wpis {current}"
            pins[current] = (match.group(2), 0)
        elif current and line.strip().startswith("--hash=sha256:"):
            version, hashes = pins[current]
            pins[current] = (version, hashes + 1)
        elif line and not line.startswith((" ", "#")):
            pytest.fail(f"{path.name}: wpis bez przypięcia ==: {line!r}")
    return pins


def _extras() -> dict[str, list[str]]:
    return PYPROJECT["project"]["optional-dependencies"]


def test_dev_lock_header_names_regeneration_command():
    assert DEV_LOCK_COMMAND in DEV_LOCK.read_text(encoding="utf-8").splitlines()[1]


def test_dev_extras_cover_test_extras():
    """Jeden lock (dev) wystarcza tylko wtedy, gdy dev zawiera wszystko z test."""
    test = {str(Requirement(r)) for r in _extras()["test"]}
    dev = {str(Requirement(r)) for r in _extras()["dev"]}
    assert test <= dev


@pytest.mark.parametrize("extra", ["test", "dev"])
def test_dev_lock_pins_every_extra_requirement_with_hash(extra):
    pins = _parse_lock(DEV_LOCK)
    for raw in _extras()[extra]:
        req = Requirement(raw)
        name = canonicalize_name(req.name)
        assert name in pins, f"{name} z extras '{extra}' nie ma w dev.lock — wygeneruj lock ponownie"
        version, hashes = pins[name]
        assert req.specifier.contains(version, prereleases=True), f"{name}=={version} nie spełnia {req.specifier}"
        assert hashes >= 1, f"{name} bez --hash=sha256 w dev.lock"


@pytest.mark.parametrize("lock", [DEV_LOCK, AUDIT_LOCK, YARA_LOCK], ids=lambda p: p.name)
def test_every_locked_package_has_a_hash(lock):
    pins = _parse_lock(lock)
    assert pins
    assert [name for name, (_, hashes) in pins.items() if hashes == 0] == []


def test_audit_lock_pins_audit_tools_exactly():
    pins = _parse_lock(AUDIT_LOCK)
    for line in AUDIT_IN.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        req = Requirement(line)
        (spec,) = req.specifier
        assert spec.operator == "==", f"narzędzie audytu bez dokładnej wersji: {line}"
        assert pins[canonicalize_name(req.name)][0] == spec.version


def test_engine_declares_no_runtime_dependencies():
    assert PYPROJECT["project"]["dependencies"] == []


# ADR 0010: jedyny import spoza biblioteki standardowej — opcjonalny YARA-X, wyłącznie w funkcji procesu potomnego.
OPTIONAL_IMPORTS = {("yarax.py", "yara_x"): "_engine"}


def _imports(source: Path) -> list[tuple[str, str]]:
    """(moduł, funkcja zawierająca import albo ``<module>``) dla każdego importu bezwzględnego."""
    found = []

    def visit(node: ast.AST, function: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else function
            if isinstance(child, ast.Import):
                found.extend((alias.name, function) for alias in child.names)
            elif isinstance(child, ast.ImportFrom) and child.level == 0:
                found.append((child.module, function))
            visit(child, inner)
    visit(ast.parse(source.read_text(encoding="utf-8"), filename=str(source)), "<module>")
    return found


def test_engine_imports_only_stdlib():
    allowed = set(sys.stdlib_module_names) | {"wpincidentlens"}
    offenders, optional = [], {}
    for source in sorted((ROOT / "wpincidentlens").glob("*.py")):
        for name, function in _imports(source):
            if (source.name, name) in OPTIONAL_IMPORTS:
                optional.setdefault((source.name, name), []).append(function)
            elif name.split(".")[0] not in allowed:
                offenders.append(f"{source.name}: {name}")
    assert offenders == []
    assert optional == {key: [function] for key, function in OPTIONAL_IMPORTS.items()}  # jeden import, w tej funkcji


def test_optional_yara_extra_is_pinned_exactly_and_locked_with_hashes():
    (raw,) = _extras()["yara"]
    req = Requirement(raw)
    (spec,) = req.specifier
    pins = _parse_lock(YARA_LOCK)

    assert canonicalize_name(req.name) == "yara-x" and spec.operator == "=="
    assert pins == {"yara-x": (spec.version, pins["yara-x"][1])} and pins["yara-x"][1] >= 2
    assert [line for line in YARA_IN.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")] == [raw]
    assert YARA_LOCK_COMMAND in YARA_LOCK.read_text(encoding="utf-8").splitlines()[1]


def test_yara_x_is_not_part_of_the_default_or_dev_environment():
    assert all(not canonicalize_name(Requirement(raw).name).startswith("yara") for extra in ("test", "dev") for raw in _extras()[extra])
    assert "yara-x" not in _parse_lock(DEV_LOCK)


def test_importing_the_engine_does_not_load_yara_x():
    code = "import sys, wpincidentlens.cli, wpincidentlens.yarax; print('yara_x' in sys.modules)"
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, cwd=ROOT)

    assert result.stdout.strip() == "False"
