"""Generator syntetycznego materiału do benchmarków S-06/S-07 (ADR 0009 pkt 5).

Tworzy wyłącznie dane syntetyczne (adresy z TEST-NET, domeny ``example.invalid``, bez haseł i danych osób) w podanym
katalogu, który nie może leżeć w repozytorium. Scenariusze:

* ``files`` — drzewo podobne do WordPressa z ``1 000 000 × scale`` małymi plikami,
* ``log``   — log dostępu w formacie combined o rozmiarze ``1 GiB × scale`` (zwykłe żądania, żądania do PHP w uploads,
  pojedyncze wiersze dłuższe niż limit wiersza parsera),
* ``sql``   — zrzut w stylu mysqldump o rozmiarze ``1 GiB × scale`` (wp_users, wp_usermeta, wp_options),
* ``site``  — minimalna witryna, która towarzyszy scenariuszom ``log`` i ``sql`` (``--files`` jest wymagane).

Uruchomienie: ``python bench/generate.py --out DIR [--scale 0.01] [--scenario files|log|sql|site|all]``.
Skrypt nie jest testem: ``pytest`` zbiera tylko ``tests/`` (``testpaths``).
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

FULL_FILES = 1_000_000
FULL_BYTES = 1024**3
FILES_PER_DIR = 250
OVERLONG_LINE_BYTES = 80 * 1024          # powyżej limitu wiersza logu (64 KiB)
OVERLONG_EVERY = 200_000                 # co ile wierszy logu wiersz za długi
UPLOADS_PHP_EVERY = 20_000               # co ile wierszy żądanie do PHP w uploads
ROWS_PER_INSERT = 500                    # wiersze na jedną instrukcję INSERT (mysqldump --extended-insert)
ADMINS = 3                               # tylu użytkowników ma rolę administratora
OPTION_BLOCKS = 4                        # bloki wp_options na jeden blok wp_users + wp_usermeta

WP_CONFIG = b"<?php\n// Synthetic benchmark site; no credentials.\n$table_prefix = 'wp_';\n"
VERSION_PHP = b"<?php\n$wp_version = '6.6.2';\n$wp_db_version = 57155;\n$required_php_version = '7.2.24';\n"
PHP_STUB = b"<?php\n// synthetic benchmark file %d\nfunction bench_fn_%d() { return %d; }\n"
UPLOAD_PHP = b"<?php /* synthetic benchmark marker, not executable payload */ echo 'bench';\n"


def _refuse_repo(out: Path) -> None:
    repo = Path(__file__).resolve().parent.parent
    target = out.resolve()
    if target == repo or repo in target.parents:
        sys.exit(f"--out {out} leży w repozytorium; użyj katalogu tymczasowego")


def site(root: Path) -> None:
    """Minimalna witryna: konfiguracja z prefiksem ``wp_``, wersja rdzenia i jeden plik motywu."""
    (root / "wp-includes").mkdir(parents=True, exist_ok=True)
    (root / "wp-content/themes/bench").mkdir(parents=True, exist_ok=True)
    (root / "wp-content/uploads").mkdir(parents=True, exist_ok=True)
    (root / "wp-config.php").write_bytes(WP_CONFIG)
    (root / "wp-includes/version.php").write_bytes(VERSION_PHP)
    (root / "index.php").write_bytes(b"<?php\n// synthetic\nrequire __DIR__ . '/wp-blog-header.php';\n")
    (root / "wp-content/themes/bench/style.css").write_bytes(b"/* Theme Name: Bench */\n")


def files(root: Path, count: int) -> int:
    """``count`` małych plików: rdzeń, wtyczki, motywy i uploads (głównie obrazy, kilka plików PHP)."""
    site(root)
    written = 4
    rng = random.Random(1)
    jpeg = b"\xff\xd8\xff\xe0" + bytes(rng.randrange(256) for _ in range(120)) + b"\xff\xd9"
    # Udziały: rdzeń 15%, wtyczki 45%, motywy 10%, uploads 30%.
    plan = [("wp-includes/bench", 0.15, "php"), ("wp-content/plugins", 0.45, "php"),
            ("wp-content/themes", 0.10, "php"), ("wp-content/uploads", 0.30, "jpg")]
    for base, share, kind in plan:
        n = int(count * share) if base != "wp-content/uploads" else count - written
        for start in range(0, n, FILES_PER_DIR):
            block = start // FILES_PER_DIR
            if kind == "jpg":
                folder = root / base / f"{2000 + block // 1200}" / f"{block // 100 % 12 + 1:02d}" / f"b{block:05d}"
            else:
                folder = root / base / f"pkg{block // 40:04d}" / f"dir{block:05d}"
            folder.mkdir(parents=True, exist_ok=True)
            for i in range(start, min(start + FILES_PER_DIR, n)):
                if kind == "jpg":
                    if i % 50_000 == 7:
                        (folder / f"cache-{i}.php").write_bytes(UPLOAD_PHP)
                    else:
                        (folder / f"img-{i}.jpg").write_bytes(jpeg)
                else:
                    (folder / f"f{i}.php").write_bytes(PHP_STUB % (i, i, i))
                written += 1
    return written


def _log_line(rng: random.Random, number: int, when: datetime) -> str:
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
    ip = f"198.51.100.{number % 250 + 1}" if number % 3 else f"203.0.113.{number % 250 + 1}"
    if number % UPLOADS_PHP_EVERY == 11:
        return (f'{ip} - - [{stamp}] "POST /wp-content/uploads/2026/11/cache-{number % 7}.php HTTP/1.1" 200 75 '
                f'"-" "SyntheticBench/1.0"\n')
    if number % OVERLONG_EVERY == 13:
        return f'{ip} - - [{stamp}] "GET /?q={"a" * OVERLONG_LINE_BYTES} HTTP/1.1" 414 0 "-" "SyntheticBench/1.0"\n'
    path = rng.choice(("/", "/about/", "/blog/page/2/", "/wp-login.php", "/feed/", "/wp-content/themes/bench/style.css",
                       f"/wp-content/uploads/2026/{number % 12 + 1:02d}/img-{number % 9999}.jpg", f"/?p={number % 5000}"))
    method = "POST" if path == "/wp-login.php" and number % 2 else "GET"
    return (f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" 200 {rng.randrange(200, 90_000)} '
            f'"https://example.invalid/" "Mozilla/5.0 (SyntheticBench; rv:{number % 100})"\n')


def access_log(path: Path, target: int) -> int:
    rng = random.Random(2)
    start = datetime(2026, 11, 1, tzinfo=timezone.utc)
    size = number = 0
    with path.open("w", encoding="ascii", newline="\n", buffering=8 * 1024 * 1024) as out:
        batch: list[str] = []
        while size < target:
            line = _log_line(rng, number, start + timedelta(seconds=number // 20))
            batch.append(line)
            size += len(line)
            number += 1
            if len(batch) == 10_000:
                out.write("".join(batch))
                batch.clear()
        out.write("".join(batch))
    return number


def _users(first: int, count: int) -> str:
    rows = ",".join(f"({i},'bench{i}','$P$Bsynthetic{i:010d}','bench{i}','bench{i}@example.invalid','',"
                    f"'2026-01-{i % 28 + 1:02d} 10:00:00','',0,'Bench User {i}')" for i in range(first, first + count))
    return f"INSERT INTO `wp_users` VALUES {rows};\n"


def _usermeta(first: int, count: int) -> str:
    out = []
    for i in range(first, first + count):
        role = 'a:1:{s:13:"administrator";b:1;}' if i <= ADMINS else 'a:1:{s:10:"subscriber";b:1;}'
        out.append(f"({2 * i},{i},'wp_capabilities','{role}'),({2 * i + 1},{i},'wp_user_level','{10 if i <= ADMINS else 0}')")
    return f"INSERT INTO `wp_usermeta` VALUES {','.join(out)};\n"


def _options(first: int, count: int) -> str:
    rows = []
    for i in range(first, first + count):
        value = ("<p>synthetic widget text " + "lorem ipsum " * (i % 40) + "</p>").replace("'", "")
        if i % 100_000 == 5:
            value = '<script src="https://example.invalid/bench.js"></script>'
        rows.append(f"({i},'bench_option_{i}','{value}','yes')")
    return f"INSERT INTO `wp_options` VALUES {','.join(rows)};\n"


def sql_dump(path: Path, target: int) -> dict[str, int]:
    counts = {"users": 0, "options": 0}
    size = 0
    with path.open("w", encoding="ascii", newline="\n", buffering=8 * 1024 * 1024) as out:
        header = ("-- Synthetic mysqldump-style benchmark dump. No real accounts or data.\n"
                  "SET NAMES utf8mb4;\nDROP TABLE IF EXISTS `wp_options`;\n")
        out.write(header)
        size += len(header)
        # Na zmianę: blok użytkowników z metadanymi i OPTION_BLOCKS bloków opcji, aż do docelowego rozmiaru.
        while size < target:
            first = counts["users"] + 1
            for statement in (_users(first, ROWS_PER_INSERT), _usermeta(first, ROWS_PER_INSERT)):
                out.write(statement)
                size += len(statement)
            counts["users"] += ROWS_PER_INSERT
            for _ in range(OPTION_BLOCKS):
                statement = _options(counts["options"] + 1, ROWS_PER_INSERT)
                out.write(statement)
                size += len(statement)
                counts["options"] += ROWS_PER_INSERT
    return counts


def generate(out: Path, scale: float, scenario: str) -> dict:
    _refuse_repo(out)
    out.mkdir(parents=True, exist_ok=True)
    meta: dict = {"scale": scale}
    if scenario in ("site", "log", "sql", "all"):
        site(out / "site")
    if scenario in ("files", "all"):
        meta["files"] = files(out / "files", max(10, int(FULL_FILES * scale)))
    if scenario in ("log", "all"):
        meta["log_lines"] = access_log(out / "access.log", int(FULL_BYTES * scale))
        meta["log_bytes"] = os.path.getsize(out / "access.log")
    if scenario in ("sql", "all"):
        meta["sql_rows"] = sql_dump(out / "dump.sql", int(FULL_BYTES * scale))
        meta["sql_bytes"] = os.path.getsize(out / "dump.sql")
    (out / "generated.json").write_text(json.dumps(meta, indent=2))
    return meta


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="katalog docelowy poza repozytorium")
    parser.add_argument("--scale", type=float, default=1.0, help="ułamek pełnego rozmiaru (1.0 = 1 mln plików, 1 GiB)")
    parser.add_argument("--scenario", choices=("files", "log", "sql", "site", "all"), default="all")
    args = parser.parse_args()
    if not 0 < args.scale <= 10:
        parser.error("--scale musi być w przedziale (0, 10]")
    print(json.dumps(generate(args.out, args.scale, args.scenario)))


if __name__ == "__main__":
    main()
