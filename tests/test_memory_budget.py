"""Budżet pamięci (Issue #67): domyślne limity mieszczą się w limicie pamięci kontenera, a koszt wpisu nie rośnie.

Pamięć analizy rośnie z liczbą wpisów rejestru (plików przeczytanych i pominiętych), a tych jest najwyżej
``--max-entries``. Zamiast zabicia procesu przez OOM nadmiar wpisów kończy się luką ``MAX_ENTRIES``.
"""
from __future__ import annotations

import gc
import os
import tracemalloc
from pathlib import Path

import pytest

from wpincidentlens import cli, ingest

RUN_FLAGS = Path(__file__).parents[1] / "docker" / "run-flags.txt"
UNITS = {"k": 1024, "m": 1024**2, "g": 1024**3}


def container_memory() -> int:
    flags = dict(line.split("=", 1) for line in RUN_FLAGS.read_text(encoding="utf-8").splitlines()
                 if line.startswith("--") and "=" in line)
    memory = flags["--memory"]
    return int(memory[:-1]) * UNITS[memory[-1]]


def test_default_entry_limit_keeps_the_estimated_memory_under_the_container_limit():
    limits = ingest.Limits()

    estimate = limits.max_entries * ingest.ENTRY_MEMORY_BYTES + ingest.MEMORY_RESERVE_BYTES

    assert estimate <= container_memory()
    assert limits.max_files < limits.max_entries  # limit plików pozostaje osiągalny mimo katalogów


def make_tree(root: Path, count: int, kind: str) -> Path:
    for number in range(count):
        directory = root / "wp-content" / "plugins" / f"p{number // 250:03d}"
        directory.mkdir(parents=True, exist_ok=True)
        if kind == "symlink":  # wpis pominięty z własną luką: najdroższy rodzaj wpisu
            os.symlink("/nonexistent-target", directory / f"l{number:05d}.php")
        else:
            (directory / f"f{number:05d}.php").write_bytes(b"<?php // %d\n" % number)
    return root


def peak_of_run(site: Path, out: Path) -> int:
    """Szczyt pamięci Pythona (tracemalloc) całego przebiegu ``main``: skan, raport, zapis wszystkich plików."""
    gc.collect()
    tracemalloc.start()
    try:
        start = tracemalloc.get_traced_memory()[0]
        assert cli.main(["--files", str(site), "--output", str(out)]) in (cli.EXIT_PARTIAL, cli.EXIT_UNPROCESSED)
        return tracemalloc.get_traced_memory()[1] - start
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("kind", ["symlink", "file"])
def test_memory_per_entry_stays_within_the_budget_estimate(tmp_path, capsys, kind):
    """Przyrost szczytu między drzewem 1000 i 3000 wpisów, na wpis; koszty stałe (moduły, raport HTML) się znoszą."""
    small, large = 1000, 3000
    peaks = [peak_of_run(make_tree(tmp_path / f"site-{count}", count, kind), tmp_path / f"out-{count}") for count in (small, large)]

    per_entry = (peaks[1] - peaks[0]) / (large - small)

    assert per_entry <= ingest.ENTRY_MEMORY_BYTES
