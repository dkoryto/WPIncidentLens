"""Sonda kontenera i pomocnik zadania CI ``container`` (T-601, ADR 0009 pkt 1).

Sama izolacja jest mierzona wyłącznie w CI (.github/workflows/container.yml).
Tu: czyste parsery sondy na przykładowych tekstach ``/proc``, negatywne
przypadki (sonda nie może przejść w środowisku bez ograniczeń) oraz zgodność
docker/compose.yaml, docker/run-flags.txt, stałych sondy i workflow.
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
DOCKER = ROOT / "docker"
WORKFLOW = ROOT / ".github" / "workflows" / "container.yml"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"_t601_{name}", DOCKER / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


probe = _load("probe")
cc = _load("containercheck")

STATUS_RESTRICTED = """Name:\tpython
Uid:\t65532\t65532\t65532\t65532
Gid:\t65532\t65532\t65532\t65532
NoNewPrivs:\t1
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t0000000000000000
CapAmb:\t0000000000000000
"""
STATUS_DEFAULT_ROOT = STATUS_RESTRICTED.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0").replace(
    "CapEff:\t0000000000000000", "CapEff:\t00000000a80425fb").replace(
    "CapBnd:\t0000000000000000", "CapBnd:\t00000000a80425fb")

MOUNTINFO = """\
1520 1430 0:150 / / ro,relatime master:600 - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w
1521 1520 0:153 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1530 1520 259:1 /home/runner/work/x/fixtures/site /evidence/files ro,relatime - ext4 /dev/root rw,discard
1531 1520 259:1 /home/runner/work/x/my\\040dir /evidence/with\\040space ro,relatime - ext4 /dev/root rw
1540 1520 0:160 / /tmp rw,nosuid,noexec,relatime - tmpfs tmpfs rw,size=65536k
1541 1520 0:161 / /tmp rw,relatime - tmpfs tmpfs rw
"""

NET_DEV = """Inter-|   Receive                            |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
  eth0:    1234      10    0    0    0     0          0         0      567       5    0    0    0     0       0          0
"""


def test_status_parsing_restricted_passes():
    checks = probe.check_status(probe.parse_status(STATUS_RESTRICTED))
    assert [c["name"] for c in checks] == ["CapEff", "CapPrm", "CapBnd", "NoNewPrivs"]
    assert all(c["ok"] for c in checks)


def test_status_default_root_container_fails():
    failed = {c["name"] for c in probe.check_status(probe.parse_status(STATUS_DEFAULT_ROOT)) if not c["ok"]}
    assert failed == {"CapEff", "CapBnd", "NoNewPrivs"}


@pytest.mark.parametrize("value", [None, "", "zz", "0000000000000001"])
def test_caps_zero_rejects_missing_garbage_and_nonzero(value):
    assert probe.caps_zero(value) is False


def test_mountinfo_uses_mount_options_not_superblock():
    mounts = probe.parse_mountinfo(MOUNTINFO)
    assert "ro" in mounts["/"] and "rw" not in mounts["/"]  # superblok overlay ma "rw"
    assert "ro" in mounts["/evidence/files"]
    assert "ro" in mounts["/evidence/with space"]


def test_mountinfo_last_mount_on_same_point_wins():
    # Druga, późniejsza montownia /tmp bez noexec przesłania pierwszą: sonda ma to wykryć.
    checks = probe.check_mounts(probe.parse_mountinfo(MOUNTINFO), ["/evidence/files"])
    assert {c["name"]: c["ok"] for c in checks} == {
        "mount_ro:/": True, "mount_ro:/evidence/files": True, "mount_noexec_nosuid:/tmp": False}


def test_mountinfo_rw_root_and_missing_evidence_fail():
    text = "1 0 0:1 / / rw,relatime - overlay overlay rw\n"
    checks = probe.check_mounts(probe.parse_mountinfo(text), ["/evidence/files"])
    assert not any(c["ok"] for c in checks)


def test_mountinfo_ignores_malformed_lines():
    assert probe.parse_mountinfo("garbage\n1 2 3\n") == {}


def test_net_dev_lists_interfaces():
    assert probe.parse_net_dev(NET_DEV) == ["eth0", "lo"]
    assert probe.parse_net_dev("h1\nh2\n    lo: 0 0\n") == ["lo"]


@pytest.mark.parametrize(("text", "expected"), [
    ("0::/\n", "/"),
    ("0::\n", "/"),
    ("12:pids:/docker/abc\n1:name=systemd:/x\n0::/docker/abc\n", "/docker/abc"),
    ("12:pids:/docker/abc\n", None),
    ("", None),
])
def test_cgroup_v2_path(text, expected):
    assert probe.parse_cgroup_v2_path(text) == expected


def test_parse_limit():
    assert probe.parse_limit("1073741824\n") == 1073741824
    assert probe.parse_limit("max\n") == "max"


def test_write_probe_fails_where_writing_is_allowed(tmp_path):
    check = probe.check_write_denied(str(tmp_path))
    assert check["ok"] is False
    assert list(tmp_path.iterdir()) == []  # sonda sprząta po sobie


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root omija uprawnienia katalogu")
def test_write_probe_passes_on_denied_directory(tmp_path):
    tmp_path.chmod(0o500)
    try:
        check = probe.check_write_denied(str(tmp_path))
    finally:
        tmp_path.chmod(0o700)
    assert check["ok"] is True and check["detail"] == "EACCES"


@pytest.mark.skipif(not Path("/bin/sh").exists(), reason="wymaga /bin/sh")
def test_noexec_probe_fails_on_executable_tmp(tmp_path):
    checks = {c["name"]: c["ok"] for c in probe.check_tmp_noexec(str(tmp_path))}
    assert checks == {"tmp_writable": True, "tmp_noexec": False}
    assert list(tmp_path.iterdir()) == []


# --- zgodność: compose, run-flags, stałe sondy, workflow -------------------

def _compose() -> dict:
    return cc.parse_compose_service((DOCKER / "compose.yaml").read_text(encoding="utf-8"))


def _run_flags() -> list[str]:
    return cc.load_run_flags((DOCKER / "run-flags.txt").read_text(encoding="utf-8"))


def test_compose_and_ci_run_flags_are_the_same_set():
    assert sorted(cc.compose_to_flags(_compose())) == sorted(_run_flags())


def test_run_flags_cover_required_restrictions():
    flags = set(_run_flags())
    assert {"--network=none", "--read-only", "--user=65532:65532", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true"} <= flags
    assert any(f.startswith("--tmpfs=/tmp:") and "noexec" in f and "nosuid" in f for f in flags)


def test_probe_expectations_match_run_flags():
    flags = dict(f.split("=", 1) for f in _run_flags() if "=" in f)
    units = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}
    memory = flags["--memory"]
    assert probe.EXPECTED_MEMORY_MAX == int(memory[:-1]) * units[memory[-1]]
    assert flags["--memory-swap"] == memory and probe.EXPECTED_SWAP_MAX == 0
    assert probe.EXPECTED_PIDS_MAX == int(flags["--pids-limit"])
    assert probe.EXPECTED_CPU_MAX == f"{int(float(flags['--cpus']) * 100000)} 100000"
    assert f"{probe.EXPECTED_UID}:{probe.EXPECTED_GID}" == flags["--user"]


def test_compose_mounts_evidence_read_only_and_only_results_writable():
    volumes = [cc.parse_volume(spec) for spec in _compose()["volumes"]]
    assert {target for _, target, mode in volumes if mode != "ro"} == {"/results"}
    assert all(mode == "ro" for _, target, mode in volumes if target.startswith("/evidence"))


def test_compose_parser_reads_flow_and_block_lists():
    text = 'services:\n  other:\n    user: "0:0"\n  wpincidentlens:\n    cap_drop: ["ALL"]\n    tmpfs:\n      - /tmp:rw  # c\n    cpus: 0.5\n'
    service = cc.parse_compose_service(text)
    assert service == {"cap_drop": ["ALL"], "tmpfs": ["/tmp:rw"], "cpus": "0.5"}
    assert cc.compose_to_flags(service) == ["--cap-drop=ALL", "--cpus=0.5", "--tmpfs=/tmp:rw"]


def test_demo_host_command_maps_container_paths_to_volume_sources(tmp_path):
    command = cc.demo_host_command(_compose(), tmp_path)
    assert str(tmp_path) in command and "/results" not in command
    assert not any(arg.startswith("/evidence") for arg in command)
    # Ta sama nazwa pliku bazy w kontenerze i na hoście: identyfikatory dowodów zależą od niej.
    database = command[command.index("--database") + 1]
    container = _compose()["command"]
    assert Path(database).name == Path(container[container.index("--database") + 1]).name


def test_compare_runs():
    a = cc.summarize({"assessment": "SUSPICIOUS", "scope_complete": False, "findings": [{"id": "fnd_1", "rule_id": "R"}]}, 3)
    assert cc.compare(a, dict(a)) == []
    assert cc.compare(a, {**a, "findings": []})
    assert cc.compare(a, {**a, "exit_code": 0})
    broken = cc.summarize({}, 2)
    assert cc.compare(broken, dict(broken))  # zgodne, ale oba to błąd wywołania


def test_dockerfile_base_image_pinned_by_digest_and_non_root():
    text = (DOCKER / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^FROM python:3\.12-slim@sha256:[0-9a-f]{64}$", text, re.M)
    assert re.search(r"^USER 65532:65532$", text, re.M)
    assert "PYTHONDONTWRITEBYTECODE=1" in text
    assert [line.split()[1] for line in text.splitlines() if line.startswith("COPY ")] == ["wpincidentlens"]


def test_workflow_uses_shared_flags_probe_and_pinned_actions():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "containercheck.py flags" in text and "/probe/probe.py" in text
    assert "containercheck.py compare" in text
    assert "format: cyclonedx-json" in text  # SBOM obrazu (ADR 0009 pkt 2)
    assert "permissions:\n  contents: read" in text
    uses = re.findall(r"uses:\s*(\S+)", text)
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u) for u in uses)
    assert ":ro" in text and "chmod 777" not in text
