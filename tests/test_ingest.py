"""SecureIngest (T-101, ADR 0002 B2–B6, B8): jedyny punkt odczytu nieufnego materiału dowodowego.

Wyłącznie dane syntetyczne w ``tmp_path``. Wyścigi są symulowane deterministycznie hakami,
prawdziwy wyścig wątków nie jest uruchamiany.
"""
import ast
import errno
import hashlib
import os
import socket
from pathlib import Path

import pytest
from conftest import EVAL_MARKER, open_fd_count, sha256, sparse, time_limit, tree_digest, write

from wptrace import ingest
from wptrace.ingest import IngestRefusal, Limits, ReadStatus, Session

CHANGED = "SOURCE_CHANGED_DURING_ANALYSIS"
needs_permission_bits = pytest.mark.skipif(os.geteuid() == 0, reason="root ignoruje bity uprawnień")


def read(root, session=None, source="files", **options):
    return list((session or Session()).read(root, source, **options))


def one(records, rel):
    matches = [record for record in records if record.rel == rel]
    assert len(matches) == 1, f"oczekiwano jednego wpisu {rel}, jest {len(matches)}"
    return matches[0]


def rels(records, status=ReadStatus.READ):
    return [record.rel for record in records if record.status is status]


@pytest.fixture
def outside(tmp_path):
    """Plik spoza materiału dowodowego; jego treść i skrót nigdy nie mogą pojawić się w wyniku."""
    return write(tmp_path / "outside" / "secret.php", EVAL_MARKER)


def assert_not_read(records, outside_file):
    digest = sha256(outside_file)
    assert all(record.sha256 != digest and record.content != outside_file.read_bytes() for record in records)


# --- B3/B4: odczyt deskryptorowy, jeden strumień na skrót i treść ---------------------------------

def test_regular_file_yields_hash_size_and_content_of_the_same_bytes(site):
    body = b"<?php // synthetic body\n"
    write(site / "theme.php", body)

    record = one(read(site), "theme.php")

    assert (record.status, record.sha256, record.size, record.content) == (
        ReadStatus.READ, hashlib.sha256(body).hexdigest(), len(body), body)


def test_file_larger_than_one_chunk_is_hashed_whole(site):
    body = os.urandom(ingest.CHUNK_BYTES + 17)
    write(site / "big.bin", body)

    assert one(read(site), "big.bin").sha256 == hashlib.sha256(body).hexdigest()


def test_content_above_scan_limit_is_hashed_but_not_retained(site):
    write(site / "big.php", b"123456")

    record = one(read(site, Session(Limits(max_scan_bytes=5))), "big.php")

    assert (record.status, record.size, record.content) == (ReadStatus.READ, 6, None)
    assert record.sha256 == sha256(site / "big.php")


def test_content_is_retained_only_for_wanted_paths(site):
    write(site / "photo.jpg", b"synthetic")

    records = read(site, wanted=lambda rel: rel.endswith(".php"))

    assert one(records, "photo.jpg").content is None
    assert one(records, "index.php").content is not None


def test_entries_are_visited_in_bytewise_sorted_preorder(site):
    for rel in ["b.php", "a/z.php", "a/b/c.php", "a.php", "Z.php"]:
        write(site / rel)

    assert rels(read(site)) == ["Z.php", "a/b/c.php", "a/z.php", "a.php", "b.php", "index.php"]


def test_single_file_source_is_read_under_its_name(evidence):
    dump = write(evidence / "db.sql", "-- synthetic\n")

    record = Session().read_file(dump, "database")

    assert (record.status, record.source, record.rel, record.sha256) == (ReadStatus.READ, "database", "db.sql", sha256(dump))


def test_ledger_keeps_every_outcome_without_content(site):
    (site / "link.php").symlink_to(site / "index.php")
    session = Session()

    read(site, session)

    assert [(entry.rel, entry.status, entry.content) for entry in session.ledger] == [
        ("index.php", ReadStatus.READ, None), ("link.php", ReadStatus.SKIPPED_SYMLINK, None)]


# --- Z-06: dowiązania symboliczne ------------------------------------------------------------------

@pytest.mark.parametrize("target_is_dir", [False, True], ids=["file-link", "dir-link"])
def test_symlink_inside_tree_is_skipped_without_following(site, outside, target_is_dir):
    (site / "link.php").symlink_to(outside.parent if target_is_dir else outside)

    records = read(site)

    assert one(records, "link.php").status is ReadStatus.SKIPPED_SYMLINK
    assert rels(records) == ["index.php"]
    assert_not_read(records, outside)


def test_symlink_to_parent_directory_does_not_escape_or_loop(site):
    (site / "up").symlink_to("..", target_is_directory=True)

    with time_limit(5):
        records = read(site)

    assert rels(records) == ["index.php"]


@pytest.mark.parametrize("expect, target_is_dir", [("dir", True), ("file", False), ("any", True), ("any", False)],
                         ids=["dir-source", "file-source", "any-to-dir", "any-to-file"])
def test_symlink_given_as_source_root_is_refused(site, outside, tmp_path, expect, target_is_dir):
    link = tmp_path / "link"
    link.symlink_to(site if target_is_dir else outside)

    with pytest.raises(IngestRefusal) as refusal:
        ingest.check_source(link, expect)

    assert refusal.value.status is ReadStatus.SKIPPED_SYMLINK
    assert str(tmp_path) not in str(refusal.value)


def test_symlink_root_read_through_api_yields_a_skip_not_data(outside, tmp_path):
    link = tmp_path / "link.sql"
    link.symlink_to(outside)

    records = read(link, source="database")

    assert [(record.status, record.sha256) for record in records] == [(ReadStatus.SKIPPED_SYMLINK, None)]


@pytest.mark.parametrize("build, expect, reason", [
    (lambda tmp: tmp / "missing", "any", "ENOENT"),
    (lambda tmp: write(tmp / "file.sql"), "dir", "ENOTDIR"),
    (lambda tmp: write(tmp / "dir" / "x").parent, "file", "NOT_A_REGULAR_FILE"),
], ids=["missing", "file-instead-of-directory", "directory-instead-of-file"])
def test_unusable_source_root_is_refused_by_name_of_error(tmp_path, build, expect, reason):
    with pytest.raises(IngestRefusal) as refusal:
        ingest.check_source(build(tmp_path), expect)

    assert refusal.value.reason == reason
    assert str(tmp_path) not in str(refusal.value)


# --- Z-07: dowiązania twarde ------------------------------------------------------------------------

def test_hardlinked_file_is_not_read_by_default(site, outside):
    os.link(outside, site / "shared.php")

    records = read(site)

    shared = one(records, "shared.php")
    assert (shared.status, shared.sha256, shared.content) == (ReadStatus.SKIPPED_HARDLINK, None, None)
    assert any("shared.php" in gap for gap in shared.gaps)
    assert_not_read(records, outside)


def test_hardlinked_file_is_read_and_marked_when_allowed(site, outside):
    os.link(outside, site / "shared.php")

    shared = one(read(site, Session(allow_hardlinks=True)), "shared.php")

    assert (shared.status, shared.hardlinked, shared.sha256) == (ReadStatus.READ, True, sha256(outside))


def test_allowed_hardlinks_are_counted_in_an_informational_gap(site, outside):
    os.link(outside, site / "one.php")
    os.link(outside, site / "two.php")
    session = Session(allow_hardlinks=True)

    read(site, session)

    assert any("--allow-hardlinks" in gap and "2" in gap for gap in session.finish())


# --- S-03: pliki specjalne i nieczytelne ------------------------------------------------------------

def test_fifo_is_skipped_without_blocking(site):
    os.mkfifo(site / "pipe.php")

    with time_limit(5):
        pipe = one(read(site), "pipe.php")

    assert (pipe.status, pipe.reason) == (ReadStatus.SKIPPED_SPECIAL, "FIFO")


def test_unix_socket_is_skipped_without_connecting(site, monkeypatch):
    monkeypatch.chdir(site)  # ścieżka gniazda ma limit ok. 100 bajtów; nazwa względna zawsze się mieści
    listener = socket.socket(socket.AF_UNIX)
    try:
        listener.bind("sock.php")
    except OSError:
        pytest.skip("system plików nie pozwala utworzyć gniazda")
    finally:
        listener.close()

    with time_limit(5):
        sock = one(read(site), "sock.php")

    assert (sock.status, sock.reason) == (ReadStatus.SKIPPED_SPECIAL, "SOCKET")


def test_fifo_given_as_source_root_is_refused_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "pipe.sql")

    with time_limit(5), pytest.raises(IngestRefusal) as refusal:
        ingest.check_source(tmp_path / "pipe.sql", "file")

    assert refusal.value.status is ReadStatus.SKIPPED_SPECIAL


@needs_permission_bits
@pytest.mark.parametrize("locked_rel, expected_rel", [("locked.php", "locked.php"), ("locked-dir/inner.php", "locked-dir")],
                         ids=["file", "directory"])
def test_unreadable_entry_is_an_error_record_named_by_errno(site, locked_rel, expected_rel):
    write(site / locked_rel)
    locked = site / expected_rel
    locked.chmod(0o000)
    try:
        records = read(site)
    finally:
        locked.chmod(0o700)

    entry = one(records, expected_rel)
    assert (entry.status, entry.reason) == (ReadStatus.ERROR, "EACCES")
    assert rels(records) == ["index.php"]


def _fail_listing_of(monkeypatch, directory):
    real, inode = ingest._sorted_names, directory.stat().st_ino

    def listing(dir_fd, limit):
        if os.fstat(dir_fd).st_ino == inode:
            raise OSError(errno.EIO, "synthetic I/O error")
        return real(dir_fd, limit)

    monkeypatch.setattr(ingest, "_sorted_names", listing)


def _fail_reading_of(monkeypatch, file):
    real, inode = os.read, file.stat().st_ino

    def reading(fd, size):
        if os.fstat(fd).st_ino == inode:
            raise OSError(errno.EIO, "synthetic I/O error")
        return real(fd, size)

    monkeypatch.setattr(ingest.os, "read", reading)


@pytest.mark.parametrize("broken_rel, break_it", [("wp-content", _fail_listing_of), ("wp-content/theme.php", _fail_reading_of), (".", _fail_listing_of)],
                         ids=["directory-listing", "file-read", "root-listing"])
def test_io_error_becomes_an_error_record_without_leaking_descriptors(site, monkeypatch, broken_rel, break_it):
    write(site / "wp-content" / "theme.php")
    break_it(monkeypatch, site / broken_rel)
    before = open_fd_count()

    records = read(site)

    assert (one(records, broken_rel).status, one(records, broken_rel).reason) == (ReadStatus.ERROR, "EIO")
    assert open_fd_count() == before


def test_path_with_nul_byte_is_refused_not_raised(tmp_path):
    with pytest.raises(IngestRefusal) as refusal:
        ingest.check_source(str(tmp_path) + "/a\0b")

    assert refusal.value.reason == "INVALID_PATH"


# --- S-02 / Z-08: TOCTOU ----------------------------------------------------------------------------

def _swap_after_listing(monkeypatch, victim, replacement):
    """Hak: zaraz po wylistowaniu katalogu wpis ``victim`` zostaje podmieniony na symlink do ``replacement``."""
    real = ingest._sorted_names

    def listing(dir_fd, limit):
        names = real(dir_fd, limit)
        if victim.name in names and not victim.is_symlink():
            if victim.is_dir():
                victim.rename(victim.with_name("moved-away"))
            else:
                victim.unlink()
            victim.symlink_to(replacement)
        return names

    monkeypatch.setattr(ingest, "_sorted_names", listing)


@pytest.mark.parametrize("victim_is_dir", [False, True], ids=["file", "directory"])
def test_entry_swapped_for_symlink_after_enumeration_is_not_followed(site, outside, monkeypatch, victim_is_dir):
    victim = write(site / "theme" / "x.php").parent if victim_is_dir else write(site / "theme")
    _swap_after_listing(monkeypatch, victim, outside.parent if victim_is_dir else outside)

    records = read(site)

    assert one(records, "theme").status is ReadStatus.SKIPPED_SYMLINK
    assert_not_read(records, outside)


def _grow_during_read(monkeypatch, victim):
    """Hak: przy pierwszym odczycie deskryptora pliku ``victim`` plik zostaje dopisany."""
    real, inode, done = os.read, victim.stat().st_ino, []

    def reading(fd, size):
        if not done and os.fstat(fd).st_ino == inode:
            done.append(True)
            with victim.open("ab") as stream:
                stream.write(b"// appended during read\n")
        return real(fd, size)

    monkeypatch.setattr(ingest.os, "read", reading)


def test_file_modified_while_being_read_is_marked_changed(site, monkeypatch):
    victim = write(site / "theme.php")
    _grow_during_read(monkeypatch, victim)

    record = one(read(site), "theme.php")

    assert record.status is ReadStatus.CHANGED
    assert any(CHANGED in gap and "theme.php" in gap for gap in record.gaps)


def test_hash_of_a_changed_file_still_describes_the_bytes_handed_to_analysis(site, monkeypatch):
    victim = write(site / "theme.php")
    _grow_during_read(monkeypatch, victim)

    record = one(read(site), "theme.php")

    assert (record.sha256, record.size) == (hashlib.sha256(record.content).hexdigest(), len(record.content))


def test_file_growing_on_every_read_does_not_stall_the_reader(site, monkeypatch):
    victim = write(site / "theme.php")
    real, inode = os.read, victim.stat().st_ino

    def reading(fd, size):
        if os.fstat(fd).st_ino == inode:
            with victim.open("ab") as stream:
                stream.write(b"x")
        return real(fd, size)

    monkeypatch.setattr(ingest.os, "read", reading)

    with time_limit(5):
        record = one(read(site), "theme.php")

    assert record.status is ReadStatus.CHANGED


def _rewrite_keeping_size_and_mtime(path):
    info = path.stat()
    path.write_bytes(b"X" * info.st_size)
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))


def _replace_with_identical_copy(path):
    """Nowy i-węzeł o tej samej treści, rozmiarze i mtime (kopia powstaje obok, więc numer nie może się powtórzyć)."""
    info = path.stat()
    copy = write(path.with_name("copy.tmp"), path.read_bytes())
    os.utime(copy, ns=(info.st_atime_ns, info.st_mtime_ns))
    os.replace(copy, path)


def _replace_with_symlink(path):
    path.unlink()
    path.symlink_to(path.with_name("elsewhere.php"))


@pytest.mark.parametrize("tamper", [
    _rewrite_keeping_size_and_mtime, _replace_with_identical_copy, _replace_with_symlink,
    lambda path: path.unlink(), lambda path: os.truncate(path, 1), lambda path: os.utime(path, ns=(1, 1)),
], ids=["same-size-and-mtime", "new-inode-same-bytes", "swapped-for-symlink", "deleted", "truncated", "mtime-only"])
def test_change_between_read_and_reverification_is_reported(site, outside, tamper):
    victim = write(site / "wp-content" / "theme.php")
    session = Session()
    read(site, session)

    tamper(victim)
    gaps = session.finish()

    assert [gap for gap in gaps if CHANGED in gap and "wp-content/theme.php" in gap]
    assert one(session.ledger, "wp-content/theme.php").status is ReadStatus.CHANGED
    assert one(session.ledger, "index.php").status is ReadStatus.READ


def test_single_file_source_changed_after_read_is_reported(evidence):
    dump = write(evidence / "db.sql", "-- synthetic\n")
    session = Session()
    session.read_file(dump, "database")

    dump.write_text("-- tampered\n", encoding="utf-8")

    assert any(CHANGED in gap and "database/db.sql" in gap for gap in session.finish())


def test_source_root_replaced_by_another_directory_with_the_same_files_is_reported(site, tmp_path):
    session = Session()
    read(site, session)

    site.rename(tmp_path / "moved")
    site.mkdir()
    (tmp_path / "moved" / "index.php").rename(site / "index.php")  # ten sam i-węzeł, rozmiar i mtime pliku

    assert session.finish() == [f"{CHANGED}: źródło files zostało podmienione po odczycie"]


def test_source_root_removed_after_read_is_reported_once_for_the_whole_source(site, tmp_path):
    write(site / "second.php")
    session = Session()
    read(site, session)

    site.rename(tmp_path / "moved")

    assert session.finish() == [f"{CHANGED}: źródło files niedostępne przy ponownej weryfikacji (ENOENT)"]
    assert {entry.status for entry in session.ledger} == {ReadStatus.CHANGED}


def test_file_changed_during_read_is_not_reported_again_by_reverification(site, monkeypatch):
    _grow_during_read(monkeypatch, write(site / "theme.php"))
    session = Session()

    read(site, session)

    assert session.finish() == []


def test_unchanged_evidence_passes_reverification_silently(demo_case):
    session = Session()
    read(demo_case / "site", session)
    read(demo_case / "logs", session, source="logs")

    assert session.finish() == []


def test_disabled_reverification_is_itself_reported_and_detects_nothing(site):
    session = Session(reverify=False)
    read(site, session)

    (site / "index.php").write_text("tampered", encoding="utf-8")
    gaps = session.finish()

    assert len(gaps) == 1 and "--no-reverify" in gaps[0]


# --- B6: limity (każdy osobno) ----------------------------------------------------------------------

def test_default_limits_match_adr_0002():
    assert Limits() == Limits(max_files=200_000, max_entries=1_000_000, max_file_bytes=2 * 1024**3, max_total_bytes=20 * 1024**3,
                              max_scan_bytes=4 * 1024**2, max_path_bytes=4096, max_depth=64, max_seconds=1800)


@pytest.mark.parametrize("field", ["max_files", "max_entries", "max_file_bytes", "max_total_bytes", "max_scan_bytes",
                                   "max_path_bytes", "max_depth", "max_seconds"])
def test_limits_reject_non_positive_values(field):
    with pytest.raises(ValueError):
        Limits(**{field: 0})


def test_file_count_limit_stops_the_walk_with_a_named_skip(site):
    for number in range(4):
        write(site / f"file-{number}.php")

    records = read(site, Session(Limits(max_files=2)))

    assert rels(records) == ["file-0.php", "file-1.php"]
    assert [(record.rel, record.reason) for record in records if record.status is ReadStatus.SKIPPED_LIMIT] == [("file-2.php", "MAX_FILES")]


def test_file_count_limit_is_shared_by_all_sources(site, evidence):
    dump = write(evidence / "db.sql", "-- synthetic\n")
    session = Session(Limits(max_files=1))
    read(site, session)

    record = session.read_file(dump, "database")

    assert (record.status, record.reason, record.sha256) == (ReadStatus.SKIPPED_LIMIT, "MAX_FILES", None)


def test_file_above_size_limit_is_skipped_before_hashing(site, monkeypatch):
    sparse(site / "huge.bin", 101)
    inode = (site / "huge.bin").stat().st_ino
    real = os.read

    def no_read_of_huge(fd, size):
        assert os.fstat(fd).st_ino != inode, "plik ponad limit nie może być czytany"
        return real(fd, size)

    monkeypatch.setattr(ingest.os, "read", no_read_of_huge)

    records = read(site, Session(Limits(max_file_bytes=100)))

    huge = one(records, "huge.bin")
    assert (huge.status, huge.reason, huge.sha256) == (ReadStatus.SKIPPED_LIMIT, "MAX_FILE_BYTES", None)
    assert rels(records) == ["index.php"]


def test_total_volume_limit_skips_what_does_not_fit_and_continues(evidence):
    root = evidence / "tree"
    write(root / "a.bin", b"123456")
    write(root / "b.bin", b"123456")
    write(root / "c.bin", b"123")

    records = read(root, Session(Limits(max_total_bytes=10)))

    assert rels(records) == ["a.bin", "c.bin"]
    assert (one(records, "b.bin").status, one(records, "b.bin").reason) == (ReadStatus.SKIPPED_LIMIT, "MAX_TOTAL_BYTES")


def test_relative_path_above_byte_limit_is_skipped(site):
    write(site / "long-directory-name" / "inner.php")

    records = read(site, Session(Limits(max_path_bytes=len("long-directory-name"))))

    assert rels(records) == ["index.php"]
    assert [record.reason for record in records if record.status is ReadStatus.SKIPPED_LIMIT] == ["MAX_PATH_BYTES"]


def _nest_beyond_path_max(root, levels=20, name="d" * 250):
    """Drzewo o ścieżce ok. 5 kB (ponad PATH_MAX): da się je zbudować tylko względem deskryptora katalogu."""
    fd = os.open(root, os.O_RDONLY)
    try:
        for _ in range(levels):
            os.mkdir(name, dir_fd=fd)
            deeper = os.open(name, os.O_RDONLY, dir_fd=fd)
            os.close(fd)
            fd = deeper
        os.close(os.open("leaf.php", os.O_CREAT | os.O_WRONLY, dir_fd=fd))
    finally:
        os.close(fd)


def test_tree_nested_beyond_path_max_is_cut_off_at_the_default_path_limit(site):
    _nest_beyond_path_max(site)

    with time_limit(5):
        records = read(site)

    assert [record.reason for record in records if record.status is not ReadStatus.READ] == ["MAX_PATH_BYTES"]
    assert rels(records) == ["index.php"]


def test_tree_nested_beyond_path_max_is_readable_when_the_limit_allows(site):
    _nest_beyond_path_max(site)

    with time_limit(5):
        records = read(site, Session(Limits(max_path_bytes=1_000_000)))

    assert [len(rel) for rel in rels(records)] == [20 * 251 + len("leaf.php"), len("index.php")]


def test_directory_below_depth_limit_is_not_entered(site):
    write(site / "a" / "b" / "ok.php")
    write(site / "a" / "b" / "c" / "deep.php")

    records = read(site, Session(Limits(max_depth=2)))

    assert rels(records) == ["a/b/ok.php", "index.php"]
    assert (one(records, "a/b/c").status, one(records, "a/b/c").reason) == (ReadStatus.SKIPPED_LIMIT, "MAX_DEPTH")


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_time_budget_exhausted_between_files_stops_reading_everywhere(site, evidence):
    write(site / "later.php")
    dump = write(evidence / "db.sql", "-- synthetic\n")
    clock = FakeClock()
    session = Session(Limits(max_seconds=10), clock=clock)
    walk = session.read(site, "files")

    first = next(walk)
    clock.now = 11.0
    rest = list(walk)
    database = session.read_file(dump, "database")

    assert first.status is ReadStatus.READ
    assert [(record.status, record.reason) for record in rest] == [(ReadStatus.SKIPPED_LIMIT, "MAX_SECONDS")]
    assert (database.status, database.reason) == (ReadStatus.SKIPPED_LIMIT, "MAX_SECONDS")


def test_time_budget_exhausted_before_reverification_is_reported(site):
    clock = FakeClock()
    session = Session(Limits(max_seconds=10), clock=clock)
    read(site, session)

    clock.now = 11.0

    assert any("weryfikacj" in gap and "0/1" in gap for gap in session.finish())


@pytest.mark.parametrize("build, reason", [
    (lambda root: [write(root / f"f{n}.php") for n in range(3)], "MAX_FILES"),
    (lambda root: sparse(root / "huge.bin", 99), "MAX_FILE_BYTES"),
    (lambda root: [write(root / name, b"1234567") for name in ("a.bin", "b.bin")], "MAX_TOTAL_BYTES"),
    (lambda root: write(root / "long-directory-name" / "inner.php"), "MAX_PATH_BYTES"),
    (lambda root: write(root / "a" / "b" / "c" / "deep.php"), "MAX_DEPTH"),
], ids=["files", "file-bytes", "total-bytes", "path-bytes", "depth"])
def test_every_exceeded_limit_produces_a_gap_naming_its_value(evidence, build, reason):
    limits = Limits(max_files=2, max_file_bytes=50, max_total_bytes=10, max_path_bytes=19, max_depth=2)
    root = evidence / "tree"
    root.mkdir()
    build(root)

    skipped = [record for record in read(root, Session(limits)) if record.reason == reason]

    assert skipped and all(str(getattr(limits, reason.lower())) in gap for record in skipped for gap in record.gaps)


# --- S-05: nazwy spoza UTF-8 ------------------------------------------------------------------------

def test_non_utf8_filename_is_read_and_reported_under_an_encodable_name(site):
    try:
        os.close(os.open(os.fsencode(site) + b"/\xff.php", os.O_CREAT | os.O_WRONLY))
    except OSError:
        pytest.skip("system plików odrzuca nazwy spoza UTF-8 (np. APFS)")

    record = next(record for record in read(site) if record.rel != "index.php")

    assert record.status is ReadStatus.READ
    assert record.rel.encode("utf-8") == b"\\xff.php"
    assert any("UTF-8" in gap for gap in record.gaps)


# --- B8: komunikaty bez ścieżek hosta ---------------------------------------------------------------

@needs_permission_bits
def test_no_message_contains_an_absolute_host_path(site, outside, tmp_path):
    (site / "link.php").symlink_to(outside)
    os.link(outside, site / "shared.php")
    os.mkfifo(site / "pipe.php")
    locked = write(site / "locked.php")
    locked.chmod(0o000)
    session = Session(Limits(max_depth=1))
    write(site / "a" / "b" / "deep.php")
    try:
        records = read(site, session) + read(tmp_path / "missing", session, source="logs")
        write(site / "index.php", "tampered")
        messages = [gap for record in records for gap in record.gaps] + session.finish()
    finally:
        locked.chmod(0o600)

    assert len(messages) >= 7
    assert not [message for message in messages if str(tmp_path) in message or "/private/" in message]


# --- S-16: niezmienność źródeł, determinizm, deskryptory --------------------------------------------

def test_reading_and_reverifying_leaves_the_evidence_tree_unchanged(demo_case, outside):
    (demo_case / "site" / "link.php").symlink_to(outside)
    os.mkfifo(demo_case / "site" / "pipe")
    before = tree_digest(demo_case)
    session = Session(allow_hardlinks=True)

    for source in ("site", "logs", "database.sql", "baseline.json"):
        read(demo_case / source, session, source=source)
    session.finish()

    assert tree_digest(demo_case) == before


def test_two_sessions_report_identical_records_in_identical_order(demo_case):
    def snapshot():
        return [(r.rel, r.status, r.sha256, r.size, r.mtime_ns, r.gaps) for r in read(demo_case / "site")]

    assert snapshot() == snapshot()


def _messy_tree(site, outside):
    (site / "link.php").symlink_to(outside)
    os.mkfifo(site / "pipe.php")
    write(site / "a" / "b" / "c" / "deep.php")


def _read_and_reverify(site):
    session = Session()
    read(site, session)
    session.finish()


@pytest.mark.parametrize("use", [
    lambda site: read(site),
    lambda site: read(site, Session(Limits(max_files=1))),
    lambda site: read(site, Session(Limits(max_depth=1))),
    lambda site: Session().read(site, "files").close(),
    lambda site: next(Session().read(site, "files")),
    _read_and_reverify,
    lambda site: read(site / "missing"),
    lambda site: read(site / "index.php", expect="dir"),
], ids=["full-walk", "file-limit", "depth-limit", "unstarted-generator", "abandoned-generator", "reverification",
        "missing-root", "wrong-root-type"])
def test_no_file_descriptor_is_leaked(site, outside, use):
    _messy_tree(site, outside)
    before = open_fd_count()

    use(site)

    assert open_fd_count() == before


def test_platform_without_descriptor_relative_open_is_refused(monkeypatch):
    monkeypatch.setattr(os, "supports_dir_fd", set())

    with pytest.raises(IngestRefusal) as refusal:
        Session()

    assert refusal.value.reason == "UNSUPPORTED_PLATFORM"


# --- Z-05: położenie katalogu wyników ---------------------------------------------------------------

@pytest.mark.parametrize("output, source", [
    ("evidence/site/report", "evidence/site"),
    ("evidence/site", "evidence/site"),
    ("evidence/logs/new/deeper", "evidence/logs"),
    ("evidence", "evidence/site"),
    ("evidence", "evidence/db.sql"),
    ("via-link/report", "evidence/site"),
], ids=["inside-source", "equal-to-source", "missing-dirs-inside-source", "contains-source-dir", "contains-source-file",
        "inside-source-through-symlink"])
def test_output_overlapping_a_source_is_refused(site, evidence, tmp_path, output, source):
    write(evidence / "db.sql", "-- synthetic\n")
    (evidence / "logs").mkdir()
    (tmp_path / "via-link").symlink_to(site)

    with pytest.raises(IngestRefusal) as refusal:
        ingest.resolve_output(tmp_path / output, [tmp_path / source])

    assert str(tmp_path) not in str(refusal.value)


def test_output_inside_source_spelled_in_another_letter_case_is_refused(site, tmp_path):
    spelled = Path(str(site).replace("evidence", "EVIDENCE"))
    if not spelled.exists():
        pytest.skip("system plików rozróżnia wielkość liter")

    with pytest.raises(IngestRefusal):
        ingest.resolve_output(spelled / "report", [site])


def test_output_next_to_sources_is_accepted_and_returned_as_real_path(site, evidence, tmp_path):
    dump = write(evidence / "db.sql", "-- synthetic\n")

    assert ingest.resolve_output(tmp_path / "out", [site, dump]) == Path(os.path.realpath(tmp_path)) / "out"


# --- D4: strażnik samego modułu ---------------------------------------------------------------------

INGEST_TREE = ast.parse(Path(ingest.__file__).read_text(encoding="utf-8"))
ALLOWED_IMPORTS = {"__future__", "collections", "dataclasses", "enum", "errno", "hashlib", "itertools", "os", "pathlib", "stat", "time", "typing"}
WRITING_CALLS = {"fdopen", "write", "writev", "pwrite", "write_text", "write_bytes", "mkdir", "makedirs", "mkfifo", "mknod",
                 "unlink", "remove", "rmdir", "removedirs", "rename", "renames", "truncate", "ftruncate", "chmod",
                 "fchmod", "lchmod", "chown", "fchown", "lchown", "utime", "link", "symlink", "symlink_to", "hardlink_to",
                 "touch", "sendfile", "copy_file_range", "fsync", "posix_fallocate", "setxattr", "removexattr"}
WRITING_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_EXCL", "O_TMPFILE"}


def test_ingest_imports_only_allowlisted_standard_modules():
    imported = {alias.name.split(".")[0] for node in ast.walk(INGEST_TREE) if isinstance(node, ast.Import) for alias in node.names}
    imported |= {node.module.split(".")[0] for node in ast.walk(INGEST_TREE) if isinstance(node, ast.ImportFrom) and node.module}

    assert imported <= ALLOWED_IMPORTS


def test_ingest_contains_no_writing_call_or_flag():
    """Jedyne otwarcie to ``os.open`` bez flag zapisu; wbudowane ``open`` i ``os.replace`` są zabronione wprost."""
    calls = [node.func for node in ast.walk(INGEST_TREE) if isinstance(node, ast.Call)]
    bare = {func.id for func in calls if isinstance(func, ast.Name)}
    methods = {func.attr for func in calls if isinstance(func, ast.Attribute)}
    os_calls = {func.attr for func in calls if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "os"}
    attributes = {node.attr for node in ast.walk(INGEST_TREE) if isinstance(node, ast.Attribute)}

    assert "open" not in bare
    assert methods & WRITING_CALLS == set()
    assert "replace" not in os_calls
    assert attributes & WRITING_FLAGS == set()


# --- budżet wpisów: dowiązania i katalogi nie omijają limitu plików ------------------------------

@pytest.mark.parametrize("populate", [
    lambda root, target: [(root / f"link-{n:02}").symlink_to(target) for n in range(30)],
    lambda root, target: [(root / f"dir-{n:02}").mkdir() for n in range(30)],
], ids=["symlinks", "empty-directories"])
def test_entries_other_than_regular_files_are_bounded_by_the_entry_limit(tmp_path, populate):
    root = tmp_path / "many"
    root.mkdir()
    populate(root, write(tmp_path / "target.php"))
    session = Session(Limits(max_entries=5))

    records = read(root, session)

    assert len(records) <= 6
    assert len(session.ledger) <= 6
    assert [record.reason for record in records if record.status is ReadStatus.SKIPPED_LIMIT] == ["MAX_ENTRIES"]


def test_directory_listing_never_returns_more_than_the_requested_names(tmp_path):
    for number in range(20):
        write(tmp_path / f"f{number:02}")
    dir_fd = os.open(tmp_path, os.O_RDONLY)
    try:
        assert len(ingest._sorted_names(dir_fd, 3)) == 4
    finally:
        os.close(dir_fd)


def test_entry_limit_spans_all_sources_of_a_session(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    for root in (first, second):
        root.mkdir()
        for number in range(3):
            write(root / f"f{number}.php")
    session = Session(Limits(max_entries=4))
    read(first, session)

    records = read(second, session, source="logs")

    # Obcięta lista katalogu bierze nazwy w kolejności systemu plików, więc sprawdzamy liczbę, nie nazwę.
    assert len(rels(records)) == 1
    assert any(record.reason == "MAX_ENTRIES" for record in records)


def test_names_listed_in_parent_directories_count_against_the_entry_budget(tmp_path, monkeypatch):
    root = tmp_path / "nested"
    (root / "a" / "b").mkdir(parents=True)
    for directory in (root, root / "a", root / "a" / "b"):
        for number in range(3):
            write(directory / f"z{number}.php")
    requested = []
    real = ingest._sorted_names
    monkeypatch.setattr(ingest, "_sorted_names", lambda dir_fd, limit: requested.append(limit) or real(dir_fd, limit))
    session = Session(Limits(max_entries=20))

    read(root, session)

    assert requested == [20, 16, 12]
    assert session._pending == 0
