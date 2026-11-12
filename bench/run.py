"""Benchmarki S-06/S-07 (ADR 0009 pkt 5): ``python -m wpincidentlens`` na syntetycznych danych z ``bench/generate.py``.

Każdy przebieg to osobny podproces. Mierzone: czas ścienny, CPU user/sys i maksymalny RSS z ``resource.getrusage``
(``RUSAGE_CHILDREN`` przed i po przebiegu daje czas CPU; maksymalny RSS jednego dziecka pochodzi z ``os.wait4``, bo
``RUSAGE_CHILDREN.ru_maxrss`` jest maksimum ze wszystkich dotąd zakończonych dzieci), kod wyjścia, ocena, statusy
pokrycia i luki związane z limitami. Każdy scenariusz jest też uruchamiany z ciasnym ``--max-seconds``.

Uruchomienie::

    python bench/run.py --data DIR [--scale 0.01] [--generate] [--keep] [--json out.json] [--markdown out.md]

Bez twardych progów: wynik jest pomiarem, nie testem. Skrypt nie jest zbierany przez ``pytest`` (``testpaths``).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate  # noqa: E402

# Fragmenty treści luk związanych z limitami (ingest, httplog, sqldump, dbrules).
LIMIT_MARKERS = ("limit", "Limit", "przeanalizowany do", "pominięt", "czas", "Czas", "dłuższ", "za dług", "Nie sparsowano")


def _rss_bytes(ru_maxrss: int) -> int:
    return ru_maxrss if sys.platform == "darwin" else ru_maxrss * 1024  # macOS: bajty, Linux: KiB


def run_case(name: str, args: list[str], workdir: Path) -> dict:
    output = workdir / f"out-{name}"
    shutil.rmtree(output, ignore_errors=True)
    command = [sys.executable, "-m", "wpincidentlens", *args, "--output", str(output)]
    env = {**os.environ, "PYTHONPATH": str(REPO)}
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.monotonic()
    with open(workdir / f"stdout-{name}.txt", "wb") as stdout, open(workdir / f"stderr-{name}.txt", "wb") as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr, env=env, cwd=REPO)
        _, status, usage = os.wait4(process.pid, 0)
    wall = time.monotonic() - start
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    result = {
        "scenario": name, "args": args, "wall_s": round(wall, 2),
        "user_s": round(after.ru_utime - before.ru_utime, 2), "sys_s": round(after.ru_stime - before.ru_stime, 2),
        "max_rss_mib": round(_rss_bytes(usage.ru_maxrss) / 1024**2, 1), "exit_code": os.waitstatus_to_exitcode(status),
    }
    report = output / "report.json"
    if report.is_file():
        data = json.loads(report.read_text(encoding="utf-8"))
        result.update({
            "report_mib": round(report.stat().st_size / 1024**2, 2), "assessment": data.get("assessment"),
            "scope_complete": data.get("scope_complete"), "findings": len(data.get("findings", [])),
            "coverage": {source: entry.get("status") for source, entry in data.get("coverage", {}).items()},
            "limit_gaps": [gap[:300] for gap in data.get("coverage_gaps", []) if any(m in gap for m in LIMIT_MARKERS)],
        })
    else:
        result["stderr_tail"] = (workdir / f"stderr-{name}.txt").read_text(errors="replace")[-2000:]
    shutil.rmtree(output, ignore_errors=True)
    return result


def scenarios(data: Path, tight_seconds: float, files_count: int) -> list[tuple[str, list[str]]]:
    site, tree = str(data / "site"), str(data / "files")
    roomy = ["--max-files", str(files_count * 2 + 100), "--max-entries", str(files_count * 3 + 1000)]
    tight = ["--max-seconds", str(tight_seconds)]
    out: list[tuple[str, list[str]]] = []
    if (data / "files").is_dir():
        out += [("files-default-limits", ["--files", tree]),
                ("files-raised-limits", ["--files", tree, *roomy]),
                ("files-tight-time", ["--files", tree, *roomy, *tight])]
    if (data / "access.log").is_file():
        log = ["--files", site, "--logs", str(data / "access.log")]
        out += [("log", log), ("log-tight-time", [*log, *tight])]
    if (data / "dump.sql").is_file():
        sql = ["--files", site, "--database", str(data / "dump.sql")]
        out += [("sql", sql), ("sql-tight-time", [*sql, *tight])]
    return out


def markdown(results: list[dict]) -> str:
    head = ("| Scenariusz | Wall [s] | User [s] | Sys [s] | Max RSS [MiB] | Kod | Ocena | Pokrycie | Luki limitów |\n"
            "|---|---:|---:|---:|---:|---:|---|---|---|\n")
    rows = []
    for r in results:
        coverage = ", ".join(f"{k}={v}" for k, v in r.get("coverage", {}).items() if k != "baseline")
        gaps = "<br>".join(g.replace("|", "\\|")[:160] for g in r.get("limit_gaps", [])) or "—"
        rows.append(f"| {r['scenario']} | {r['wall_s']} | {r['user_s']} | {r['sys_s']} | {r['max_rss_mib']} | {r['exit_code']} "
                    f"| {r.get('assessment', 'BRAK RAPORTU')} | {coverage} | {gaps} |")
    return head + "\n".join(rows) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", type=Path, required=True, help="katalog danych syntetycznych (poza repozytorium)")
    parser.add_argument("--scale", type=float, default=1.0, help="ułamek pełnego rozmiaru dla --generate")
    parser.add_argument("--generate", action="store_true", help="najpierw wygeneruj dane do --data")
    parser.add_argument("--only", choices=("files", "log", "sql"), action="append", help="ogranicz scenariusze")
    parser.add_argument("--tight-seconds", type=float, default=2.0, help="wartość --max-seconds w przebiegach *-tight-time")
    parser.add_argument("--keep", action="store_true", help="nie usuwaj wygenerowanych danych")
    parser.add_argument("--json", type=Path, help="zapisz wyniki JSON")
    parser.add_argument("--markdown", type=Path, help="zapisz tabelę Markdown")
    args = parser.parse_args()
    generate._refuse_repo(args.data)
    meta: dict = {}
    timings: dict[str, float] = {}
    if args.generate:
        for scenario in args.only or ("files", "log", "sql"):
            start = time.monotonic()
            meta.update(generate.generate(args.data, args.scale, scenario))
            timings[scenario] = round(time.monotonic() - start, 1)
        generate.generate(args.data, args.scale, "site")
        (args.data / "generated.json").write_text(json.dumps(meta, indent=2))
    elif (args.data / "generated.json").is_file():
        meta = json.loads((args.data / "generated.json").read_text())
    work = args.data / "_runs"
    work.mkdir(exist_ok=True)
    results = []
    for name, case_args in scenarios(args.data, args.tight_seconds, meta.get("files", 0)):
        if args.only and not any(name.startswith(prefix) for prefix in args.only):
            continue
        result = run_case(name, case_args, work)
        print(json.dumps(result, ensure_ascii=False), flush=True)
        results.append(result)
    summary = {"machine": {"platform": platform.platform(), "python": platform.python_version(), "cpus": os.cpu_count()},
               "generated": meta, "generation_s": timings, "results": results}
    if args.json:
        args.json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    table = markdown(results)
    if args.markdown:
        args.markdown.write_text(table, encoding="utf-8")
    print(table)
    # Usuwany jest tylko katalog ze znacznikiem generatora: pomyłka w --data nie skasuje cudzych plików.
    if not args.keep and (args.data / "generated.json").is_file():
        shutil.rmtree(args.data, ignore_errors=True)


if __name__ == "__main__":
    main()
