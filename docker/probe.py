"""Sonda izolacji uruchamiana WEWNĄTRZ kontenera (ADR 0009 pkt 1, T-601).

Mierzy, a nie deklaruje: tożsamość procesu, zapis do rootfs i dowodów, tmpfs
``noexec``, capability i ``no_new_privs``, brak sieci oraz limity cgroup v2.
Wypisuje JSON na stdout; kod wyjścia 0 tylko wtedy, gdy żadne sprawdzenie nie
zawiodło (sprawdzenie ``ok: null`` = niedostępne w jądrze, odnotowane, nie błąd).

Wyłącznie biblioteka standardowa. Nie łączy się z niczym poza adresem
dokumentacyjnym TEST-NET-1 (RFC 5737), który ma być nieosiągalny.
Funkcje ``parse_*`` są czyste i testowane w tests/test_container_probe.py.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
import platform
import socket
import subprocess
import sys

PROBE_VERSION = 1
EXPECTED_UID = 65532
EXPECTED_GID = 65532
EXPECTED_PYTHON = (3, 12)
EXPECTED_MEMORY_MAX = 1024 ** 3  # --memory=1g
EXPECTED_SWAP_MAX = 0  # --memory-swap równe --memory
EXPECTED_PIDS_MAX = 128  # --pids-limit=128
EXPECTED_CPU_MAX = "100000 100000"  # --cpus=1: quota i okres w mikrosekundach
UNREACHABLE_ADDR = ("192.0.2.1", 80)  # TEST-NET-1


# --- czyste parsery -------------------------------------------------------

def parse_status(text: str) -> dict[str, str]:
    """``/proc/self/status`` -> {klucz: wartość}."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return fields


def caps_zero(value: str | None) -> bool:
    """Maska capability w hex (np. ``0000000000000000``) jest pusta."""
    if not value:
        return False
    try:
        return int(value, 16) == 0
    except ValueError:
        return False


def _unescape_mount(field: str) -> str:
    # mountinfo koduje spację, tab, \n i \ jako ósemkowe \ooo.
    out, i = [], 0
    while i < len(field):
        if field[i] == "\\" and len(field[i + 1:i + 4]) == 3 and field[i + 1:i + 4].isdigit():
            out.append(chr(int(field[i + 1:i + 4], 8)))
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def parse_mountinfo(text: str) -> dict[str, set[str]]:
    """``/proc/self/mountinfo`` -> {punkt montowania: opcje tego montowania}.

    Brane są tylko opcje montowania (pole 6: ``ro``, ``noexec``, ``nosuid``),
    nie opcje superbloku po `` - `` — bind mount ``:ro`` ma superblok ``rw``.
    Przy wielokrotnym montowaniu w tym samym miejscu wygrywa ostatni wpis
    (to on jest widoczny).
    """
    mounts: dict[str, set[str]] = {}
    for line in text.splitlines():
        left, sep, _ = line.partition(" - ")
        parts = left.split()
        if not sep or len(parts) < 6:
            continue
        mounts[_unescape_mount(parts[4])] = set(parts[5].split(","))
    return mounts


def parse_net_dev(text: str) -> list[str]:
    """``/proc/net/dev`` -> nazwy interfejsów (dwa pierwsze wiersze to nagłówek)."""
    names = []
    for line in text.splitlines()[2:]:
        name, sep, _ = line.partition(":")
        if sep and name.strip():
            names.append(name.strip())
    return sorted(names)


def parse_cgroup_v2_path(text: str) -> str | None:
    """``/proc/self/cgroup`` -> ścieżka w hierarchii v2 (wiersz ``0::``) albo None."""
    for line in text.splitlines():
        if line.startswith("0::"):
            return line[3:].strip() or "/"
    return None


def parse_limit(text: str) -> int | str:
    """Wartość pliku limitu cgroup: liczba albo ``max``."""
    value = text.strip()
    return int(value) if value.isdigit() else value


# --- pomiary -------------------------------------------------------------

def _read(path: str) -> str | None:
    try:
        with open(path, encoding="ascii", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def _check(name: str, ok: bool | None, detail: object) -> dict:
    return {"name": name, "ok": ok, "detail": detail}


def _errname(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno or 0, str(exc.errno))


def check_write_denied(directory: str) -> dict:
    target = os.path.join(directory, ".wpincidentlens-probe-write")
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        return _check(f"write_denied:{directory}", True, _errname(exc))
    os.close(fd)
    os.unlink(target)
    return _check(f"write_denied:{directory}", False, "write succeeded")


def check_tmp_noexec(tmp: str = "/tmp") -> list[dict]:
    target = os.path.join(tmp, f".wpincidentlens-probe-exec-{os.getpid()}")
    try:
        with open(target, "w", encoding="ascii") as handle:
            handle.write("#!/bin/sh\nexit 0\n")
        os.chmod(target, 0o700)
    except OSError as exc:
        return [_check("tmp_writable", False, _errname(exc))]
    checks = [_check("tmp_writable", True, tmp)]
    try:
        subprocess.run([target], check=False, timeout=5)
        checks.append(_check("tmp_noexec", False, "exec succeeded"))
    except PermissionError as exc:
        checks.append(_check("tmp_noexec", True, _errname(exc)))
    except (OSError, subprocess.SubprocessError) as exc:
        checks.append(_check("tmp_noexec", False, f"unexpected {type(exc).__name__}"))
    finally:
        os.unlink(target)
    return checks


def check_mounts(mounts: dict[str, set[str]], evidence: list[str], tmp: str = "/tmp") -> list[dict]:
    checks = [_check("mount_ro:/", "ro" in mounts.get("/", set()), sorted(mounts.get("/", set())))]
    for path in evidence:
        opts = mounts.get(path, set())
        checks.append(_check(f"mount_ro:{path}", "ro" in opts, sorted(opts)))
    tmp_opts = mounts.get(tmp, set())
    checks.append(_check(f"mount_noexec_nosuid:{tmp}", {"noexec", "nosuid"} <= tmp_opts, sorted(tmp_opts)))
    return checks


def check_status(status: dict[str, str]) -> list[dict]:
    checks = [_check(key, caps_zero(status.get(key)), status.get(key)) for key in ("CapEff", "CapPrm", "CapBnd")]
    checks.append(_check("NoNewPrivs", status.get("NoNewPrivs") == "1", status.get("NoNewPrivs")))
    return checks


def check_network() -> list[dict]:
    try:
        ifaces = sorted(os.listdir("/sys/class/net"))
        source = "/sys/class/net"
    except OSError:
        ifaces = parse_net_dev(_read("/proc/net/dev") or "")
        source = "/proc/net/dev"
    checks = [_check("net_only_lo", ifaces == ["lo"], {"source": source, "interfaces": ifaces})]
    try:
        with socket.create_connection(UNREACHABLE_ADDR, timeout=2):
            checks.append(_check("net_connect_fails", False, "connected"))
    except OSError as exc:
        checks.append(_check("net_connect_fails", True, type(exc).__name__ + ":" + _errname(exc)))
    return checks


def check_cgroup(root: str = "/sys/fs/cgroup") -> list[dict]:
    rel = parse_cgroup_v2_path(_read("/proc/self/cgroup") or "")
    if rel is None:
        return [_check("cgroup_v2", False, "no 0:: entry in /proc/self/cgroup")]
    # Z prywatną przestrzenią nazw cgroup (domyślnie przy v2) ścieżka to "/".
    base = os.path.join(root, rel.lstrip("/"))
    if not os.path.exists(os.path.join(base, "memory.max")):
        base = root

    def limit(name: str) -> int | str | None:
        text = _read(os.path.join(base, name))
        return None if text is None else parse_limit(text)

    memory, pids, swap = limit("memory.max"), limit("pids.max"), limit("memory.swap.max")
    cpu = (_read(os.path.join(base, "cpu.max")) or "").strip() or None
    return [
        _check("cgroup_memory_max", memory == EXPECTED_MEMORY_MAX, memory),
        _check("cgroup_pids_max", pids == EXPECTED_PIDS_MAX, pids),
        _check("cgroup_cpu_max", cpu == EXPECTED_CPU_MAX, cpu),
        # Bez rozliczania swap w jądrze pliku nie ma: odnotowane jako null, nie błąd.
        _check("cgroup_memory_swap_max", None if swap is None else swap == EXPECTED_SWAP_MAX, swap),
    ]


def run(evidence: list[str]) -> dict:
    checks = [
        _check("uid", os.getuid() == EXPECTED_UID, os.getuid()),
        _check("gid", os.getgid() == EXPECTED_GID, os.getgid()),
        _check("python", tuple(sys.version_info[:2]) == EXPECTED_PYTHON, platform.python_version()),
    ]
    checks += [check_write_denied(path) for path in ["/", "/app", *evidence]]
    checks += check_tmp_noexec()
    checks += check_mounts(parse_mountinfo(_read("/proc/self/mountinfo") or ""), evidence)
    checks += check_status(parse_status(_read("/proc/self/status") or ""))
    checks += check_network()
    checks += check_cgroup()
    return {
        "probe_version": PROBE_VERSION,
        "python": platform.python_version(),
        "ok": all(check["ok"] is not False for check in checks),
        "failed": [check["name"] for check in checks if check["ok"] is False],
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--evidence", action="append", default=[], help="katalog dowodów zamontowany :ro (powtarzalna)")
    args = parser.parse_args(argv)
    result = run(args.evidence)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
