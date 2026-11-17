"""Spójność dokumentacji M7 (T-701) z kodem: flagi i identyfikatory reguł wymienione w dokumentach muszą istnieć.

- Każda flaga ``--…`` z dokumentów jest opcją któregoś parsera argparse budowanego przez ``cli.main`` (także parserów
  podkomend, jeśli są) albo flagą narzędzia zewnętrznego (pip, Docker) z jawnej listy lub z ``docker/run-flags.txt``.
- Każdy identyfikator w postaci ``WIELKIE_LITERY`` w odwrotnych apostrofach jest regułą z ``rules.REGISTRY`` albo
  występuje w łańcuchach znaków kodu ``wpincidentlens/`` (statusy, rodzaje obserwacji, luki). Literówka w nazwie
  reguły nie występuje nigdzie w kodzie, więc test ją wychwyci.
- Przewodnik analityka opisuje każdą regułę rejestru.
"""
from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path

import pytest

from wpincidentlens import cli
from wpincidentlens.rules import REGISTRY

ROOT = Path(__file__).parents[1]
DOCS = [ROOT / "docs" / name for name in ("INSTALL.md", "ARCHITECTURE.md", "FORMATS.md", "ANALYST_GUIDE.md")]
DOCS.append(ROOT / "examples" / "synthetic-case" / "README.md")
# Flagi pip i Docker Compose użyte w poleceniach instalacji; flagi ``docker run`` pochodzą z docker/run-flags.txt.
EXTERNAL_FLAGS = {"--require-hashes", "--no-deps", "--only-binary", "--build", "--rm", "--user"}
# Ponowne wywołania ``main`` z ``--help`` dla podkomend; gdy podkomendy nie istnieje, parser kończy się błędem (też SystemExit).
HELP_ARGV = (["--help"], ["analyze", "--help"], ["report", "--help"], ["report", "verify", "--help"], ["version", "--help"])

FLAG = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*")
IDENTIFIER = re.compile(r"`([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)`")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def cli_flags() -> set[str]:
    """Opcje wszystkich parserów, które ``cli.main`` buduje (rejestrowane przy ``add_argument``)."""
    found: set[str] = set()
    original = argparse._ActionsContainer.add_argument

    def recording(self, *args, **kwargs):
        action = original(self, *args, **kwargs)
        found.update(option for option in action.option_strings if option.startswith("--"))
        return action

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(argparse._ActionsContainer, "add_argument", recording)
        for argv in HELP_ARGV:
            with pytest.raises(SystemExit):
                cli.main(argv)
    return found


def _external_flags() -> set[str]:
    lines = _text(ROOT / "docker" / "run-flags.txt").splitlines()
    return EXTERNAL_FLAGS | {line.split("=", 1)[0] for line in lines if line.startswith("--")}


def _code_identifiers() -> set[str]:
    names: set[str] = set()
    for source in (ROOT / "wpincidentlens").rglob("*.py"):
        for node in ast.walk(ast.parse(_text(source))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                names.update(re.findall(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", node.value))
            elif isinstance(node, ast.Name):  # stałe modułów, np. MAX_FINDINGS_PER_RULE
                names.add(node.id)
            elif isinstance(node, ast.keyword) and node.arg:  # np. _confine(RLIMIT_CPU=…) w yarax
                names.add(node.arg)
    return names


def test_cli_parser_is_found(cli_flags):
    assert {"--files", "--output", "--pseudonymize", "--yara-rules"} <= cli_flags


@pytest.mark.parametrize("doc", DOCS, ids=lambda path: path.name if path.parent.name == "docs" else "examples")
def test_every_flag_in_docs_exists(doc, cli_flags):
    unknown = set(FLAG.findall(_text(doc))) - cli_flags - _external_flags()

    assert not unknown, f"{doc.relative_to(ROOT)}: flagi spoza parsera CLI: {sorted(unknown)}"


@pytest.mark.parametrize("doc", DOCS, ids=lambda path: path.name if path.parent.name == "docs" else "examples")
def test_every_identifier_in_docs_exists(doc):
    unknown = set(IDENTIFIER.findall(_text(doc))) - REGISTRY.keys() - _code_identifiers()

    assert not unknown, f"{doc.relative_to(ROOT)}: identyfikatory nieobecne w rejestrze reguł ani w kodzie: {sorted(unknown)}"


def test_analyst_guide_describes_every_rule():
    described = set(IDENTIFIER.findall(_text(ROOT / "docs" / "ANALYST_GUIDE.md")))

    assert REGISTRY.keys() <= described, f"reguły bez opisu w ANALYST_GUIDE.md: {sorted(REGISTRY.keys() - described)}"
