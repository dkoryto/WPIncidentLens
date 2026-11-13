"""Opcjonalny adapter YARA-X (T-202, ADR 0010). Wyłącznie syntetyczne reguły i pliki.

Bez YARA-X (domyślne CI) działają: pakiet reguł, ścieżka „nie zainstalowano”, nadzór procesu potomnego na atrapie
mówiącej tym samym protokołem (zawieszenie, awaria, odpowiedź niewiarygodna, limit czasu sesji). Scenariusze z
prawdziwym silnikiem (``NEEDS_YARA_X``) uruchamia zadanie CI ``yara`` z ``requirements/yara.lock``.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from pathlib import Path

import pytest
from conftest import HARMLESS_PHP, time_limit, trusted, write

from wpincidentlens import ingest, yarax
from wpincidentlens.analysis import SourceCoverage
from wpincidentlens.cli import EXIT_PARTIAL, main

NEEDS_YARA_X = pytest.mark.skipif(importlib.util.find_spec("yara_x") is None,
                                  reason="yara-x nie jest zainstalowany (extra 'yara'); scenariusze uruchamia zadanie CI yara")
PLUGIN = "wp-content/plugins/synthetic/"
MARKER = "synthetic-yara-marker-7d1"
CANARY = "CANARY-T202-MATCHED-BYTES"  # leży w dopasowanym zakresie; nie może trafić do żadnego wyjścia
RULE = f'rule Synthetic_Marker {{ meta: confidence = "medium" strings: $a = "{MARKER}" condition: $a }}\n'
NOT_INSTALLED = ("import sys; sys.modules['yara_x'] = None; sys.path.insert(0, sys.argv[1]); "
                 "from wpincidentlens.yarax import worker_main; worker_main()")

# Atrapa procesu potomnego: ten sam protokół, bez YARA-X. Zachowanie wybiera znacznik w treści pliku.
FAKE_WORKER = r'''
import json, struct, sys, time
src, out = sys.stdin.buffer, sys.stdout.buffer
def frame():
    head = src.read(16)
    if len(head) < 16:
        return None
    number, size = struct.unpack(">QQ", head)
    data = b""
    while len(data) < size:
        chunk = src.read(size - len(data))
        if not chunk:
            return None
        data += chunk
    return number, data
def reply(number, obj):
    out.write(json.dumps({"seq": number, **obj}).encode() + b"\n"); out.flush()
number, _ = frame()
reply(number, {"ready": True, "engine": "fake-1.0", "rules": ["Synthetic_Marker"], "limits": {"RLIMIT_DATA": True}})
while (got := frame()) is not None:
    number, data = got
    hit = {"rule": "Synthetic_Marker", "offset": 0, "length": 1, "count": 1}
    if b"HANG" in data:
        time.sleep(60)
    elif b"CRASH" in data:
        sys.exit(1)
    elif b"GARBAGE" in data:
        out.write(b"not json\n"); out.flush()
    elif b"DEEP" in data:
        out.write(b"[" * 100000 + b"]" * 100000 + b"\n"); out.flush()
    elif b"EXTRA" in data:
        reply(number, {"total": 0, "matches": []}); reply(number + 1, {"total": 0, "matches": []})
    elif b"WRONGSEQ" in data:
        reply(number + 7, {"total": 0, "matches": []})
    elif b"BEYOND" in data:
        reply(number, {"total": 2, "matches": [{**hit, "offset": len(data), "length": 5}, hit]})
    elif b"FOREIGN" in data:
        reply(number, {"total": 2, "matches": [{**hit, "rule": "Not_In_Pack"}, hit]})
    elif b"SCANERR" in data:
        reply(number, {"scan_error": "ScanError"})
    elif b"SHAPE" in data:
        reply(number, {"total": 1, "matches": "not-a-list"})
    elif b"OVERFULL" in data:
        reply(number, {"total": 60, "matches": [hit] * 60})
    elif b"SLOW" in data:
        reply(number, {"timeout": True})
    elif b"MANY" in data:
        reply(number, {"total": 60, "matches": [hit] * 50})
    else:
        at = data.find(b"MATCH")
        reply(number, {"total": int(at >= 0), "matches": [] if at < 0 else [{"rule": "Synthetic_Marker", "confidence": "high", "offset": at, "length": 5, "count": 2}]})
'''


def _pack(tmp_path: Path, text: str = RULE, *, name: str = "pack.yar") -> Path:
    return write(tmp_path / "rules" / name, text)


def _item(rel: str, content: bytes) -> ingest.Evidence:
    return ingest.Evidence("files", rel, ingest.ReadStatus.READ, sha256="0" * 64, size=len(content), content=content)


@pytest.fixture
def fake(monkeypatch):
    monkeypatch.setattr(yarax, "worker_argv", lambda: [sys.executable, "-I", "-c", FAKE_WORKER])
    monkeypatch.setattr(yarax, "GRACE_SECONDS", 0.3)


@pytest.fixture
def not_installed(monkeypatch):
    monkeypatch.setattr(yarax, "worker_argv", lambda: [sys.executable, "-I", "-c", NOT_INSTALLED, str(Path(yarax.__file__).parents[1])])


def _adapter(tmp_path: Path, timeout: int = 1, text: str = RULE) -> yarax.Adapter:
    return yarax.Adapter(yarax.load_pack(_pack(tmp_path, text)), timeout).start()


def _run(analyze, site: Path, pack: Path, *flags: str, baseline: bool = True):
    return analyze(site, baseline=trusted(site) if baseline else None, flags=("--yara-rules", str(pack), *flags))


def _yara_gaps(run) -> list[str]:
    return [reason for reason in run.coverage("files")["reasons"] if reason.startswith("YARA-X")]


# --- pakiet reguł ------------------------------------------------------------------------------------

def test_directory_pack_has_a_content_version_and_the_declared_version(tmp_path):
    write(tmp_path / "rules" / "a.yar", RULE)
    write(tmp_path / "rules" / "nested" / "b.yara", "rule Second { condition: false }\n")
    write(tmp_path / "rules" / "README.txt", "ignored")
    write(tmp_path / "rules" / "VERSION", "2026.11-synthetic\n")

    pack = yarax.load_pack(tmp_path / "rules")

    assert pack.problem is None and pack.declared_version == "2026.11-synthetic"
    assert [rel for rel, _ in pack.sources] == ["a.yar", "nested/b.yara"]
    assert len(pack.sha256) == 64 and yarax.load_pack(tmp_path / "rules").sha256 == pack.sha256


@pytest.mark.parametrize("change", [lambda root: write(root / "a.yar", RULE + "// x\n"), lambda root: write(root / "VERSION", "2"),
                                    lambda root: (root / "a.yar").rename(root / "c.yar")], ids=["content", "declared", "name"])
def test_pack_version_changes_with_any_rule_file_or_the_declared_version(tmp_path, change):
    write(tmp_path / "rules" / "a.yar", RULE)
    write(tmp_path / "rules" / "VERSION", "1")
    before = yarax.load_pack(tmp_path / "rules").sha256

    change(tmp_path / "rules")

    assert yarax.load_pack(tmp_path / "rules").sha256 != before


def _symlinked_rule(root: Path) -> None:
    write(root / "a.yar", RULE)
    os.symlink(write(root.parent / "outside.yar", RULE), root / "b.yar")


@pytest.mark.parametrize("prepare, expected", [
    (lambda root: None, "nieodczytany"),
    (lambda root: root.mkdir(), "nie zawiera plików"),
    (lambda root: write(root / "notes.txt", "rule X { condition: true }"), "nie zawiera plików"),
    (lambda root: write(root / "a.yar", b"rule \xff { condition: true }"), "UTF-8"),
    (lambda root: write(root / "a.yar", RULE) and write(root / "VERSION", "../../etc"), "VERSION"),
    (_symlinked_rule, "SKIPPED_SYMLINK"),
    (lambda root: write(root / "a.yar", "x" * (yarax.MAX_PACK_FILE_BYTES + 1)), "SKIPPED_LIMIT"),
], ids=["missing", "empty", "no-rule-files", "not-utf8", "bad-version", "symlink", "too-large"])
def test_unusable_pack_is_a_problem_not_an_exception(tmp_path, prepare, expected):
    prepare(tmp_path / "rules")

    pack = yarax.load_pack(tmp_path / "rules")

    assert pack.sources == () and pack.sha256 is None and expected in pack.problem


# --- brak silnika i pakietu: luka, nigdy „czysto” ----------------------------------------------------

def test_missing_yara_x_is_a_coverage_gap_and_never_a_clean_result(site, analyze, tmp_path, not_installed):
    run = _run(analyze, site, _pack(tmp_path))

    assert run.exit_code == EXIT_PARTIAL and run.report["assessment"] == "INCONCLUSIVE"
    assert run.coverage("files")["status"] == "PARTIAL"
    assert [gap for gap in _yara_gaps(run) if "nie jest zainstalowany" in gap and "nie oznacza czystości" in gap]
    assert run.case["yara"] == {"provided": True, "name": "pack.yar", "applied": False, "pack_sha256": yarax.load_pack(_pack(tmp_path)).sha256,
                                "pack_version": None, "engine": None, "rules": None, "file_timeout_seconds": yarax.FILE_TIMEOUT_SECONDS}
    assert "yara_x" not in sys.modules


def test_missing_pack_is_a_coverage_gap_not_a_usage_error(site, analyze, tmp_path):
    run = _run(analyze, site, tmp_path / "no-such-pack.yar")

    assert run.report["assessment"] == "INCONCLUSIVE" and run.coverage("files")["status"] == "PARTIAL"
    assert [gap for gap in _yara_gaps(run) if "nieodczytany" in gap]
    assert run.case["yara"]["applied"] is False and run.case["yara"]["pack_sha256"] is None


def test_without_the_flag_nothing_changes(site, analyze):
    run = analyze(site, baseline=trusted(site))

    assert "yara" not in run.case and not _yara_gaps(run) and run.coverage("files")["status"] == "ANALYZED"


@pytest.mark.parametrize("inside", ["site/rules.yar", "rules-dir", "."], ids=["file-in-files", "dir-in-evidence", "contains-evidence"])
def test_pack_inside_the_evidence_is_a_usage_error(site, evidence, tmp_path, capsys, inside):
    pack = evidence / inside if inside != "." else tmp_path
    write(evidence / "rules-dir" / "a.yar", RULE)
    write(site / "rules.yar", RULE)

    with pytest.raises(SystemExit) as exit_info:
        main(["--files", str(site), "--logs", str(evidence / "rules-dir"), "--output", str(tmp_path / "out"), "--yara-rules", str(pack)])

    assert exit_info.value.code == 2 and "nie może leżeć w źródle dowodów" in capsys.readouterr().err


def test_engine_version_from_the_worker_is_validated(tmp_path, monkeypatch):
    code = FAKE_WORKER.replace('"engine": "fake-1.0"', '"engine": "<b>x</b> " * 40')
    monkeypatch.setattr(yarax, "worker_argv", lambda: [sys.executable, "-I", "-c", code])
    adapter = _adapter(tmp_path)
    adapter.close()

    assert adapter.engine == "?" and adapter.describe()["engine"] == "yara-x ?"


def test_yara_timeout_flag_is_validated(site, tmp_path):
    for bad in ("0", "-1", "1.5", "3601"):
        with pytest.raises(SystemExit) as exit_info:
            main(["--files", str(site), "--output", str(tmp_path / "out"), "--yara-timeout", bad])
        assert exit_info.value.code == 2


# --- nadzór procesu potomnego (atrapa protokołu) -----------------------------------------------------

def test_fake_worker_match_becomes_a_detection_with_capped_confidence(tmp_path, fake):
    adapter = _adapter(tmp_path)
    content = b"<?php // xx MATCH yy\n"

    (found,) = adapter.scan(_item(PLUGIN + "a.php", content), lambda: False)
    adapter.close()

    assert (found.rule, found.severity, found.confidence, found.category) == ("YARA_MATCH", "medium", "low", "file")
    assert found.observation.attributes == {"yara_rule": "Synthetic_Marker", "pack_sha256": adapter.pack.sha256,
                                            "offset": content.index(b"MATCH"), "length": 5, "match_count": 2}


@pytest.mark.parametrize("marker, bucket, restarted", [
    (b"HANG", "lost", True), (b"CRASH", "lost", True), (b"GARBAGE", "lost", True), (b"DEEP", "lost", True),
    (b"EXTRA", "lost", True), (b"WRONGSEQ", "lost", True), (b"SHAPE", "lost", True), (b"OVERFULL", "lost", True),
    (b"BEYOND", "rejected", False), (b"FOREIGN", "rejected", False), (b"SCANERR", "failed", False),
    (b"SLOW", "timed_out", False),
], ids=["hang", "crash", "garbage", "deeply-nested-json", "extra-line", "wrong-sequence", "bad-shape", "more-than-cap",
        "offset-beyond-file", "rule-not-in-pack", "scan-error", "engine-timeout"])
def test_untrusted_or_stuck_worker_gives_a_gap_and_the_next_file_is_still_scanned(tmp_path, fake, marker, bucket, restarted):
    adapter = _adapter(tmp_path)
    cover = SourceCoverage()

    with time_limit(20):
        assert len(adapter.scan(_item("bad.php", b"<?php " + marker), lambda: False)) == (bucket == "rejected")  # wpis poprawny zostaje
        after = adapter.scan(_item("next.php", b"<?php MATCH"), lambda: False)
    adapter.finish(cover, 1024)
    adapter.close()

    assert [item.rule for item in after] == ["YARA_MATCH"]
    assert getattr(adapter, bucket) == ["bad.php"] and adapter.restarts == int(restarted)
    assert cover.partial and [reason for reason in cover.reasons if reason.startswith("YARA-X") and "bad.php" in reason]


def test_hung_worker_is_killed_within_the_file_timeout_plus_grace(tmp_path, fake):
    adapter = _adapter(tmp_path, timeout=1)
    started = time.monotonic()

    adapter.scan(_item("bad.php", b"HANG"), lambda: False)

    assert time.monotonic() - started < 1 + yarax.GRACE_SECONDS + 2
    adapter.close()


def test_rejected_entries_are_dropped_but_valid_ones_from_the_same_reply_are_kept(tmp_path, fake):
    adapter = _adapter(tmp_path)

    found = adapter.scan(_item("x.php", b"<?php FOREIGN"), lambda: False)
    adapter.close()

    assert [item.observation.attributes["yara_rule"] for item in found] == ["Synthetic_Marker"] and adapter.restarts == 0


def test_worker_that_keeps_failing_is_disabled_and_remaining_files_are_a_gap(tmp_path, fake):
    adapter = _adapter(tmp_path)
    cover = SourceCoverage()

    with time_limit(30):
        for number in range(yarax.MAX_FAILURES + 3):
            adapter.scan(_item(f"crash-{number}.php", b"CRASH"), lambda: False)
    adapter.finish(cover, 1024)

    assert len(adapter.lost) == yarax.MAX_FAILURES + 1 and len(adapter.unscanned) == 2
    assert [reason for reason in cover.reasons if "wyłączony" in reason]


def test_hostile_files_between_good_ones_never_switch_yara_off(tmp_path, fake):
    """Budżet ponownych uruchomień liczy tylko kolejne awarie: jedna klasa wrogich plików nie wyłącza YARA dla reszty."""
    adapter = _adapter(tmp_path)

    with time_limit(60):
        results = [adapter.scan(_item(f"{number}.php", b"CRASH" if number % 2 else b"MATCH"), lambda: False)
                   for number in range(4 * yarax.MAX_FAILURES)]
    adapter.close()

    assert adapter.unscanned == [] and adapter.restarts == 2 * yarax.MAX_FAILURES
    assert [len(found) for found in results[::2]] == [1] * 2 * yarax.MAX_FAILURES


def test_worker_line_after_its_reply_is_detected_before_the_next_file(tmp_path, fake):
    adapter = _adapter(tmp_path)

    first = adapter.scan(_item("a.php", b"MATCH"), lambda: False)
    adapter._worker._replies.put_nowait({"seq": 99})  # wiersz bez żądania, jak od skompromitowanego procesu
    second = adapter.scan(_item("b.php", b"MATCH"), lambda: False)
    adapter.close()

    assert len(first) == len(second) == 1 and adapter.restarts == 1 and adapter.lost == []


def test_too_many_matching_rules_in_one_file_is_a_gap(tmp_path, fake):
    adapter = _adapter(tmp_path)
    cover = SourceCoverage()

    found = adapter.scan(_item("many.php", b"MANY"), lambda: False)
    adapter.finish(cover, 1024)
    adapter.close()

    assert len(found) == yarax.MAX_RULES_PER_FILE and adapter.truncated == ["many.php"] and cover.partial


def test_session_deadline_stops_yara_scans_with_a_gap(tmp_path, fake):
    adapter = _adapter(tmp_path)
    cover = SourceCoverage()
    clock = iter([False, True, True])

    results = [adapter.scan(_item(f"{n}.php", b"MATCH"), lambda: next(clock)) for n in range(3)]
    adapter.finish(cover, 1024)
    adapter.close()

    assert [len(found) for found in results] == [1, 0, 0] and adapter.expired == 2
    assert [reason for reason in cover.reasons if "limit czasu analizy" in reason and "2 plików" in reason]


def test_session_deadline_in_a_full_run_leaves_a_yara_gap(site, analyze, tmp_path, fake, monkeypatch):
    write(site / PLUGIN / "a.php", "<?php MATCH\n")
    real = ingest.Session.expired
    monkeypatch.setattr(ingest.Session, "expired", lambda self: any(f.rel.endswith("a.php") for f in self.ledger) or real(self))

    run = _run(analyze, site, _pack(tmp_path))

    assert "YARA_MATCH" not in run.rules and run.coverage("files")["status"] == "PARTIAL"


def test_compile_error_reported_by_the_worker_is_a_pack_error(tmp_path, monkeypatch):
    code = ("import json, sys; sys.stdin.buffer.read(16); "
            "sys.stdout.write(json.dumps({'seq': 1, 'compile_error': 'error[E001]: syntax error --> pack.yar:1:6'}) + '\\n')")
    monkeypatch.setattr(yarax, "worker_argv", lambda: [sys.executable, "-I", "-c", code])

    with pytest.raises(yarax.PackError, match="E001"):
        _adapter(tmp_path)


def test_worker_that_never_answers_at_start_is_a_problem_not_a_hang(tmp_path, monkeypatch):
    monkeypatch.setattr(yarax, "worker_argv", lambda: [sys.executable, "-I", "-c", "import time; time.sleep(60)"])
    monkeypatch.setattr(yarax, "START_TIMEOUT_SECONDS", 1)

    with time_limit(10):
        adapter = _adapter(tmp_path)

    assert adapter.engine is None and "gotowości" in adapter.problem


# --- prawdziwy YARA-X --------------------------------------------------------------------------------

@NEEDS_YARA_X
def test_positive_match_reports_rule_pack_offset_length_and_count_but_no_bytes(site, analyze, tmp_path):
    content = f"<?php // synthetic, never executed\n$x = '{MARKER} {CANARY}';\n// {MARKER}\n"
    write(site / PLUGIN / "a.php", content)
    write(tmp_path / "rules" / "VERSION", "2026.11-synthetic")
    write(tmp_path / "rules" / "a.yar",
          f'rule Synthetic_Marker {{ meta: confidence = "medium" strings: $a = "{MARKER} {CANARY}" condition: $a }}\n'
          f'rule Second_Marker {{ meta: confidence = "high" strings: $a = "{MARKER}" condition: $a }}\n')

    run = _run(analyze, site, tmp_path / "rules")
    by_rule = {item["metadata"]["yara_rule"]: item for item in run.findings if item["rule"] == "YARA_MATCH"}
    raw = content.encode()

    assert set(by_rule) == {"Synthetic_Marker", "Second_Marker"}
    first = by_rule["Synthetic_Marker"]
    assert (first["severity"], first["confidence"], first["source"]) == ("medium", "medium", f"{PLUGIN}a.php")
    assert first["metadata"]["offset"] == raw.index(MARKER.encode()) and first["metadata"]["length"] == len(f"{MARKER} {CANARY}")
    assert first["metadata"]["match_count"] == 1 and first["metadata"]["pack_version"] == "2026.11-synthetic"
    assert by_rule["Second_Marker"]["confidence"] == "low" and by_rule["Second_Marker"]["metadata"]["match_count"] == 2
    assert first["metadata"]["pack_sha256"] == run.case["yara"]["pack_sha256"]
    assert run.case["yara"]["applied"] is True and run.case["yara"]["rules"] == 2 and run.case["yara"]["engine"].startswith("yara-x ")
    assert run.report["assessment"] == "SUSPICIOUS"  # nigdy STRONG_INDICATORS: pewność najwyżej medium
    outputs = "".join(path.read_text(encoding="utf-8") for path in run.out.iterdir())
    assert CANARY not in run.everything and CANARY not in outputs
    assert "yara_x" not in sys.modules


@NEEDS_YARA_X
def test_negative_no_match_gives_no_finding_and_only_a_scope_note(site, analyze, tmp_path):
    write(site / PLUGIN / "a.php", HARMLESS_PHP)

    run = _run(analyze, site, _pack(tmp_path))

    assert run.rules == set() and run.coverage("files")["status"] == "ANALYZED"
    notes = _yara_gaps(run)
    assert [note for note in notes if "przeskanowano 2 plików" in note]
    assert all("limit pamięci" in note or "przeskanowano" in note for note in notes)


@NEEDS_YARA_X
def test_false_positive_marker_in_a_comment_is_a_low_confidence_heuristic(site, analyze, tmp_path):
    """Sygnatura w komentarzu legalnej wtyczki (np. lista wzorców skanera) też pasuje: ustalenie, ale nie silny wskaźnik."""
    write(site / PLUGIN / "scanner-signatures.php", f"<?php\n// Known malware strings checked by this plugin: {MARKER}\n")

    run = _run(analyze, site, _pack(tmp_path, RULE.replace('meta: confidence = "medium" ', "")))

    assert [(item["rule"], item["confidence"]) for item in run.findings] == [("YARA_MATCH", "low")]
    assert run.report["assessment"] == "SUSPICIOUS"


@NEEDS_YARA_X
def test_files_whose_content_is_not_kept_are_not_scanned(site, analyze, tmp_path):
    write(site / "wp-content/uploads/2026/11/photo.jpg", f"JFIF {MARKER}")

    run = _run(analyze, site, _pack(tmp_path))

    assert "YARA_MATCH" not in run.rules


@NEEDS_YARA_X
@pytest.mark.parametrize("text", ["rule {", 'include "/etc/hosts"\nrule A { condition: true }', RULE + RULE],
                         ids=["syntax", "include-disabled", "duplicate-rule"])
def test_compile_error_is_a_usage_error_with_a_clear_message(site, tmp_path, capsys, text):
    with pytest.raises(SystemExit) as exit_info:
        main(["--files", str(site), "--output", str(tmp_path / "out"), "--yara-rules", str(_pack(tmp_path, text))])

    assert exit_info.value.code == 2
    assert "--yara-rules: pakiet reguł się nie kompiluje" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


@NEEDS_YARA_X
def test_pathological_rule_hits_the_per_file_timeout_and_the_run_finishes(site, analyze, tmp_path):
    write(site / PLUGIN / "big.php", "<?php //" + "a " * 150_000 + "\n")
    slow = "rule Quadratic { condition: for all i in (0..filesize) : ( for all j in (0..filesize) : ( uint8(i) != 0x100 ) ) }\n"

    with time_limit(60):
        run = _run(analyze, site, _pack(tmp_path, slow), "--yara-timeout", "1")

    assert [gap for gap in _yara_gaps(run) if "limit czasu skanu 1 s" in gap and f"{PLUGIN}big.php" in gap]
    assert run.coverage("files")["status"] == "PARTIAL" and run.report["assessment"] == "INCONCLUSIVE"


@NEEDS_YARA_X
def test_rule_name_longer_than_the_report_pattern_is_a_usage_error(tmp_path):
    with pytest.raises(yarax.PackError, match="nazwa reguły spoza wzorca"):
        _adapter(tmp_path, text=f"rule {'R' * 200} {{ condition: true }}\n")


@NEEDS_YARA_X
def test_thousands_of_matching_rules_give_a_bounded_reply_and_yara_stays_on(tmp_path):
    """Odpowiedź z tysiącami trafień przekroczyłaby limit wiersza: proces odsyła pierwsze ``MAX_RULES_PER_FILE`` i łączną
    liczbę, więc kolejne pliki są nadal skanowane, a nadmiar jest luką."""
    pack = "\n".join(f'rule Webshell_Generic_Signature_{n:05d} {{ meta: confidence = "medium" strings: $a = "eval(" condition: $a }}'
                     for n in range(6000))
    adapter = _adapter(tmp_path, timeout=30, text=pack)
    cover = SourceCoverage()

    with time_limit(120):
        results = [adapter.scan(_item(f"{n}.php", b"<?php eval($x);"), lambda: False) for n in range(5)]
    adapter.finish(cover, 1024)
    adapter.close()

    assert [len(found) for found in results] == [yarax.MAX_RULES_PER_FILE] * 5
    assert adapter.lost == [] and adapter.restarts == 0 and len(adapter.truncated) == 5
    assert [reason for reason in cover.reasons if f"ponad {yarax.MAX_RULES_PER_FILE} pasujących reguł" in reason]


@NEEDS_YARA_X
def test_worker_report_has_no_matched_bytes_and_respects_the_byte_range(tmp_path):
    adapter = _adapter(tmp_path)
    content = f"<?php {CANARY} {MARKER} {MARKER}".encode()

    (found,) = adapter.scan(_item("x.php", content), lambda: False)
    adapter.close()

    facts = found.observation.attributes
    assert content[facts["offset"]:facts["offset"] + facts["length"]] == MARKER.encode() and facts["match_count"] == 2
    assert CANARY not in json.dumps(facts) + found.explanation
