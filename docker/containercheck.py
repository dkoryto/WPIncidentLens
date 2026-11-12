"""Pomocnik zadania CI ``container`` (T-601): flagi, demo i porównanie z hostem.

Uruchamiany na hoście CI (nie w kontenerze), tylko biblioteka standardowa:

* ``flags`` — argumenty ``docker run`` z docker/run-flags.txt, jeden na wiersz;
* ``demo volumes OUT`` — wolumeny z docker/compose.yaml jako ``--volume=``
  (``/results`` -> katalog hosta OUT);
* ``demo command`` — ``command`` z docker/compose.yaml (argumenty w kontenerze);
* ``demo host OUT`` — to samo polecenie dla ``python -m wpincidentlens`` na
  hoście: ścieżki kontenera zastąpione źródłami wolumenów;
* ``compare DIR_A RC_A DIR_B RC_B`` — ta sama ocena, pełność zakresu,
  ustalenia (id, reguła) i kod wyjścia; kod 1 przy różnicy.

Parser compose obsługuje wyłącznie konstrukcje używane w docker/compose.yaml
(skalar, lista w nawiasach JSON, lista blokowa ``- x``); nie jest parserem YAML.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

DOCKER_DIR = Path(__file__).resolve().parent
RUN_FLAGS = DOCKER_DIR / "run-flags.txt"
COMPOSE = DOCKER_DIR / "compose.yaml"
SERVICE = "wpincidentlens"
CONTAINER_OUTPUT = "/results"
ACCEPTED_EXIT_CODES = {0, 3}  # 2 = błąd wywołania, 4 = źródło nieprzetworzone


def load_run_flags(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def parse_compose_service(text: str, service: str = SERVICE) -> dict:
    """Klucze usługi ``service`` z prostego compose.yaml (wcięcie 4, listy 6)."""
    result: dict = {}
    in_service = False
    current: str | None = None
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if not line:
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent == 2:
            in_service = stripped == f"{service}:"
            current = None
            continue
        if not in_service or indent < 4:
            continue
        if indent == 4:
            key, _, value = stripped.partition(":")
            value = value.strip()
            current = key
            if not value:
                result[key] = []
            elif value.startswith("["):
                result[key] = json.loads(value)
            else:
                result[key] = value.strip('"')
        elif stripped.startswith("- ") and current is not None and isinstance(result.get(current), list):
            result[current].append(stripped[2:].strip().strip('"'))
    return result


def compose_to_flags(service: dict) -> list[str]:
    """Ograniczenia usługi compose w postaci docker/run-flags.txt."""
    flags = []
    if service.get("network_mode"):
        flags.append(f"--network={service['network_mode']}")
    if service.get("read_only") == "true":
        flags.append("--read-only")
    if service.get("user"):
        flags.append(f"--user={service['user']}")
    flags += [f"--cap-drop={cap}" for cap in service.get("cap_drop", [])]
    flags += [f"--security-opt={opt}" for opt in service.get("security_opt", [])]
    if service.get("pids_limit"):
        flags.append(f"--pids-limit={service['pids_limit']}")
    if service.get("mem_limit"):
        flags.append(f"--memory={service['mem_limit']}")
    if service.get("memswap_limit"):
        flags.append(f"--memory-swap={service['memswap_limit']}")
    if service.get("cpus"):
        cpus = float(service["cpus"])
        flags.append(f"--cpus={int(cpus) if cpus.is_integer() else cpus}")
    flags += [f"--tmpfs={mount}" for mount in service.get("tmpfs", [])]
    return flags


def parse_volume(spec: str) -> tuple[str, str, str]:
    source, target, mode = (spec.split(":") + ["rw"])[:3]
    return source, target, mode


def demo_volumes(service: dict, output: Path) -> list[str]:
    """Wolumeny compose jako ``--volume=``; ``/results`` trafia do ``output``."""
    args = []
    for source, target, vmode in map(parse_volume, service["volumes"]):
        host = output if target == CONTAINER_OUTPUT else (DOCKER_DIR / source).resolve()
        args.append(f"--volume={host}:{target}:{vmode}")
    return args


def demo_host_command(service: dict, output: Path) -> list[str]:
    """``command`` z compose ze ścieżkami kontenera zamienionymi na źródła na hoście."""
    mapping = {target: str((DOCKER_DIR / source).resolve()) for source, target, _ in map(parse_volume, service["volumes"])}
    mapping[CONTAINER_OUTPUT] = str(output)
    return [mapping.get(arg, arg) for arg in service["command"]]


def summarize(report: dict, exit_code: int) -> dict:
    return {
        "assessment": report.get("assessment"),
        "scope_complete": report.get("scope_complete"),
        "findings": sorted((f.get("id"), f.get("rule_id")) for f in report.get("findings", [])),
        "exit_code": exit_code,
    }


def compare(a: dict, b: dict) -> list[str]:
    """Różnice między podsumowaniami; pusta lista = zgodne i sensowne."""
    problems = [f"{key}: {a.get(key)!r} != {b.get(key)!r}" for key in sorted(set(a) | set(b)) if a.get(key) != b.get(key)]
    for name, summary in (("A", a), ("B", b)):
        if summary.get("exit_code") not in ACCEPTED_EXIT_CODES:
            problems.append(f"{name}: exit code {summary.get('exit_code')} not in {sorted(ACCEPTED_EXIT_CODES)}")
        if not summary.get("assessment"):
            problems.append(f"{name}: no assessment")
    return problems


def _load_summary(directory: str, exit_code: str) -> dict:
    report = json.loads((Path(directory) / "report.json").read_text(encoding="utf-8"))
    return summarize(report, int(exit_code))


def main(argv: list[str]) -> int:
    if argv[:1] == ["flags"]:
        print("\n".join(load_run_flags(RUN_FLAGS.read_text(encoding="utf-8"))))
        return 0
    if argv[:1] == ["demo"] and len(argv) in (2, 3):
        service = parse_compose_service(COMPOSE.read_text(encoding="utf-8"))
        output = Path(argv[2]).resolve() if len(argv) == 3 else None
        if argv[1] == "command":
            lines = service["command"]
        elif argv[1] == "volumes" and output:
            lines = demo_volumes(service, output)
        elif argv[1] == "host" and output:
            lines = demo_host_command(service, output)
        else:
            print(__doc__, file=sys.stderr)
            return 2
        print("\n".join(lines))
        return 0
    if len(argv) == 5 and argv[0] == "compare":
        a, b = _load_summary(argv[1], argv[2]), _load_summary(argv[3], argv[4])
        problems = compare(a, b)
        print(json.dumps({"a": a, "b": b, "problems": problems}, indent=2))
        return 1 if problems else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
