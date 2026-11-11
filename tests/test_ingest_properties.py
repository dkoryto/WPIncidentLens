"""Bramka M1 (#4): własności SecureIngest na losowych drzewach dowodów i prawdziwy wyścig.

``tests/test_ingest.py`` sprawdza pojedyncze, ręcznie ułożone przypadki i symuluje wyścigi hakami. Tutaj
każda własność jest sprawdzana na drzewach z generatora ``random.Random(seed)``; identyfikator testu
(``[tight-a-17]``) podaje konfigurację sesji i ziarno potrzebne do odtworzenia porażki.

Oczekiwania pochodzą z niezależnego wyliczenia drzewa (``os.walk`` bez podążania za dowiązaniami, ``lstat``,
własny skrót), nigdy z zamiaru generatora, więc nie zależą od systemu plików ani kolejności ``scandir``.
Wyłącznie dane syntetyczne w ``tmp_path``; nic z materiału testowego nie jest wykonywane.

Czego te testy NIE dowodzą: patrz komentarze przy ``unaccounted`` (katalog odwiedzony bez wpisu) i przy
testach wyścigu (próbkowanie, nie dowód braku okna).
"""
from __future__ import annotations

import gc
import hashlib
import itertools
import os
import random
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from conftest import open_fd_count, sparse, time_limit

from wptrace.ingest import CHANGED_GAP, ROOT, Limits, ReadStatus, Session
from wptrace.models import validate_report

SEEDS = range(25)
CONFIGS = ("default", "hardlinks", "tight-a", "tight-b")
E2E_SEEDS = range(6)
IS_ROOT = os.geteuid() == 0  # root ignoruje bity uprawnień: generator nie tworzy wtedy wpisów „bez odczytu”
MARKER = b"CANARY-M1-OUTSIDE"
TREE_BUDGET = 48  # najwyżej tyle losowych wpisów w drzewie
READ_BUDGET = 15.0  # sekundy na jedno przejście drzewa; zwykle trwa ono milisekundy
NAMES = {
    "plain": "index.php", "config": "wp-config.php", "space": "with space", "newline": "new\nline", "tab": "tab\there",
    "dotdot": "..a..", "dots": "...", "dash": "-rf", "double_dash": "--output=", "polish": "zażółć", "cjk": "日本語",
    "combining": "é", "emoji": "\U0001f600", "shell": "$(id);`x`", "glob": "*?", "markup": "<b>&amp;", "quote": "'\"",
}
KINDS = {
    "file": 8, "directory": 6, "big_file": 0.4, "raw_name": 1, "fifo": 1, "locked_file": 1, "locked_dir": 1.5,
    "link_inside_file": 1, "link_inside_dir": 1, "link_canary": 1, "link_outside_dir": 1, "link_dangling": 1, "link_loop": 1,
    "link_parent": 1, "hardlink_inside": 1.5, "hardlink_canary": 1, "hardlink_outward": 1,
}

every_seed = pytest.mark.parametrize("seed", SEEDS)
every_config = pytest.mark.parametrize("config", CONFIGS)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def printable(parts: tuple[str, ...]) -> str:
    """Postać ścieżki względnej w rejestrze, wyliczona niezależnie od ``ingest``: ``/`` i ``\\xNN`` dla bajtów spoza UTF-8."""
    return os.fsencode("/".join(parts)).decode("utf-8", "backslashreplace")


def order(parts: tuple[str, ...]) -> tuple[bytes, ...]:
    """Klucz kolejności odwiedzin: przejście w głąb po nazwach sortowanych bajtowo."""
    return tuple(os.fsencode(part) for part in parts)


def walk(top: Path) -> list[Path]:
    def fail(error: OSError):
        raise error

    found = []
    for folder, folders, files in os.walk(top, followlinks=False, onerror=fail):
        found += [Path(folder, name) for name in folders + files]
    return found


# --- generator losowych drzew --------------------------------------------------------------------

@dataclass
class Tree:
    seed: int
    base: Path
    root: Path
    outside: Path
    canary: Path  # plik poza korzeniem; bywa osiągalny z drzewa dowiązaniem symbolicznym lub twardym
    hidden: Path  # plik w katalogu poza korzeniem; osiągalny wyłącznie przez dowiązanie symboliczne do katalogu
    scan_limit: int
    kinds: set[str] = field(default_factory=set)
    canary_links: list[Path] = field(default_factory=list)  # dowiązania twarde kanarka wewnątrz drzewa
    locks: list[tuple[Path, int, int]] = field(default_factory=list)  # (ścieżka, tryb blokady, tryb pierwotny)
    entries: dict[tuple[str, ...], os.stat_result] = field(default_factory=dict)
    before: dict = field(default_factory=dict)

    def lock(self) -> None:
        for path, mode, _ in reversed(self.locks):  # najpierw wpisy głębsze: zablokowany rodzic nie pozwoliłby ich zmienić
            os.chmod(path, mode)

    def unlock(self) -> None:
        for path, _, original in self.locks:
            os.chmod(path, original)

    def path_of(self) -> dict[str, Path]:
        return {printable(parts): self.root.joinpath(*parts) for parts in self.entries}

    def snapshot(self) -> dict:
        """Stan drzewa i otoczenia: typ, tryb, rozmiar, mtime, liczba dowiązań, cel dowiązania, skrót treści. Bez atime."""
        state = {}
        for path in [self.root, self.outside, *walk(self.root), *walk(self.outside)]:
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                body = os.readlink(path)
            elif stat.S_ISREG(info.st_mode):
                body = digest(path.read_bytes())
            else:
                body = ""
            state[os.path.relpath(path, self.base)] = (
                stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode), info.st_size, info.st_mtime_ns, info.st_nlink, body)
        return state


class _Builder:
    def __init__(self, seed: int, base: Path):
        self.rng = random.Random(seed)
        outside = base / "outside"
        self.tree = Tree(seed, base, base / "evidence" / "site", outside, outside / "canary.bin", outside / "dir" / "hidden.bin",
                         scan_limit=self.rng.choice([16, 64, 257]))
        self.tree.root.mkdir(parents=True)
        self.tree.hidden.parent.mkdir(parents=True)
        self.tree.canary.write_bytes(MARKER + b"-FILE seed=%d\n" % seed)
        self.tree.hidden.write_bytes(MARKER + b"-DIR seed=%d\n" % seed)
        self.files: list[Path] = []
        self.dirs: list[Path] = [self.tree.root]
        self.count = 0

    def build(self, snapshot: bool = False) -> Tree:
        tree = self.tree
        self.add_file(tree.root, 0)
        self.fill(tree.root, 0)
        self.add_file(tree.root, 0)  # dodany po wszystkich dowiązaniach twardych: zawsze jest plik, który wolno przeczytać…
        self.add_link_canary(tree.root, 0)  # …i wpis, którego przeczytać nie wolno
        tree.entries = {path.relative_to(tree.root).parts: os.lstat(path) for path in walk(tree.root)}
        if snapshot:  # przed blokadą uprawnień: potem części plików nie da się już przeczytać
            tree.before = tree.snapshot()
        tree.lock()
        return tree

    def fill(self, folder: Path, depth: int) -> None:
        for _ in range(self.rng.randint(1, 5) if depth else self.rng.randint(8, 14)):
            if self.count >= TREE_BUDGET:
                return
            kind = self.rng.choices(list(KINDS), weights=list(KINDS.values()))[0]
            getattr(self, f"add_{kind}")(folder, depth)

    def fresh(self, folder: Path) -> Path:
        """Nowa nazwa; numer czyni ją unikalną także na systemie plików nieodróżniającym wielkości liter i normalizacji."""
        self.count += 1
        label = self.rng.choice(list(NAMES))
        self.tree.kinds.add(f"name:{label}")
        return folder / f"{NAMES[label]}{self.count}"

    def random_bytes(self, size: int) -> bytes:
        return self.rng.randbytes(size)

    def add_file(self, folder: Path, depth: int) -> None:
        size = self.rng.choice([0, 1, self.rng.randint(2, 200), self.tree.scan_limit, self.tree.scan_limit + 1])
        path = self.fresh(folder)
        path.write_bytes(self.random_bytes(size))
        self.files.append(path)
        self.tree.kinds.add({0: "file:empty", self.tree.scan_limit + 1: "file:over_tight_scan"}.get(size, "file"))

    def add_big_file(self, folder: Path, depth: int) -> None:
        if "file:over_default_scan" in self.tree.kinds:  # jeden na drzewo: skrót 4 MiB kosztuje
            return self.add_file(folder, depth)
        sparse(self.fresh(folder), Limits().max_scan_bytes + 1, self.random_bytes(8))
        self.tree.kinds.add("file:over_default_scan")

    def add_raw_name(self, folder: Path, depth: int) -> None:
        self.count += 1
        try:
            path = folder / os.fsdecode(b"raw-\xff\xfe-%d" % self.count)
            path.write_bytes(self.random_bytes(9))
        except OSError:  # m.in. APFS odrzuca nazwy spoza UTF-8
            return self.add_file(folder, depth)
        self.tree.kinds.add("name:non_utf8")

    def add_directory(self, folder: Path, depth: int) -> None:
        if depth >= 4:
            return self.add_file(folder, depth)
        path = self.fresh(folder)
        path.mkdir()
        self.dirs.append(path)
        self.tree.kinds.add("directory")
        self.fill(path, depth + 1)

    def add_fifo(self, folder: Path, depth: int) -> None:
        os.mkfifo(self.fresh(folder))
        self.tree.kinds.add("fifo")

    def add_locked_file(self, folder: Path, depth: int) -> None:
        if IS_ROOT:
            return self.add_file(folder, depth)
        path = self.fresh(folder)
        path.write_bytes(self.random_bytes(12))
        self.tree.locks.append((path, 0, stat.S_IMODE(os.lstat(path).st_mode)))
        self.tree.kinds.add("locked_file")

    def add_locked_dir(self, folder: Path, depth: int) -> None:
        if IS_ROOT:
            return self.add_directory(folder, depth)
        path = self.fresh(folder)
        path.mkdir()
        self.fresh(path).write_bytes(self.random_bytes(7))
        nested = self.fresh(path)
        nested.mkdir()
        self.fresh(nested).write_bytes(self.random_bytes(5))
        mode = self.rng.choice([0, 0o400, 0o300])  # nic; listowanie bez wejścia; wejście bez listowania
        self.tree.locks.append((path, mode, stat.S_IMODE(os.lstat(path).st_mode)))
        self.tree.kinds.add(f"locked_dir:{mode:o}")

    def link(self, folder: Path, target: Path | str, kind: str) -> None:
        if isinstance(target, Path) and self.rng.random() < 0.5:
            target = os.path.relpath(target, folder)
        os.symlink(target, self.fresh(folder))
        self.tree.kinds.add(kind)

    def add_link_inside_file(self, folder: Path, depth: int) -> None:
        self.link(folder, self.rng.choice(self.files), "link_inside_file")

    def add_link_inside_dir(self, folder: Path, depth: int) -> None:
        self.link(folder, self.rng.choice(self.dirs), "link_inside_dir")

    def add_link_canary(self, folder: Path, depth: int) -> None:
        self.link(folder, self.tree.canary, "link_canary")

    def add_link_outside_dir(self, folder: Path, depth: int) -> None:
        self.link(folder, self.tree.hidden.parent, "link_outside_dir")

    def add_link_dangling(self, folder: Path, depth: int) -> None:
        self.link(folder, self.rng.choice(["no-such-target", str(self.tree.base / "gone" / "x")]), "link_dangling")

    def add_link_parent(self, folder: Path, depth: int) -> None:
        self.link(folder, "..", "link_parent")

    def add_link_loop(self, folder: Path, depth: int) -> None:
        first, second = self.fresh(folder), self.fresh(folder)
        os.symlink(second.name, first)
        os.symlink(self.rng.choice([first.name, second.name]), second)  # pętla dwuelementowa albo wskazanie na siebie
        self.tree.kinds.add("link_loop")

    def add_hardlink_inside(self, folder: Path, depth: int) -> None:
        path = self.fresh(folder)
        os.link(self.rng.choice(self.files), path)
        self.files.append(path)
        self.tree.kinds.add("hardlink_inside")

    def add_hardlink_canary(self, folder: Path, depth: int) -> None:
        path = self.fresh(folder)
        os.link(self.tree.canary, path)
        self.tree.canary_links.append(path)
        self.tree.kinds.add("hardlink_canary")

    def add_hardlink_outward(self, folder: Path, depth: int) -> None:
        self.count += 1
        os.link(self.rng.choice(self.files), self.tree.outside / f"extra-{self.count}")
        self.tree.kinds.add("hardlink_outward")


def accepts_raw_names(folder: Path) -> bool:
    """Czy system plików przyjmuje nazwy spoza UTF-8 (ext4, overlayfs, tmpfs: tak; APFS: nie)."""
    try:
        (folder / os.fsdecode(b"probe-\xff")).write_bytes(b"")
    except OSError:
        return False
    return True


@pytest.fixture
def grow(tmp_path: Path):
    """Buduje drzewo dla ziarna; po teście przywraca uprawnienia, żeby ``tmp_path`` dało się posprzątać."""
    grown: list[Tree] = []

    def build(seed: int, **options) -> Tree:
        grown.append(_Builder(seed, tmp_path).build(**options))
        return grown[-1]

    yield build
    for tree in grown:
        tree.unlock()


# --- sesje -----------------------------------------------------------------------------------------

def open_session(tree: Tree, config: str, *, full_listing: bool = False) -> Session:
    """Sesja dla konfiguracji: domyślna, z dowiązaniami twardymi albo z małymi limitami losowanymi z (ziarno, konfiguracja).

    Limit czasu jest liczony zegarem-licznikiem wywołań, więc jego przekroczenie nie zależy od szybkości maszyny.
    ``full_listing`` zdejmuje limit wpisów: obcięta lista katalogu bierze nazwy w kolejności systemu plików.
    """
    if config == "default":
        return Session()
    if config == "hardlinks":
        return Session(allow_hardlinks=True)
    rng = random.Random(f"{tree.seed}/{config}")
    files = sum(stat.S_ISREG(info.st_mode) for info in tree.entries.values())
    drawn = {
        "max_files": rng.randint(1, files + 1),
        "max_entries": rng.randint(1, len(tree.entries) + 2),
        "max_file_bytes": rng.choice([1, tree.scan_limit, tree.scan_limit + 1, 150]),
        "max_total_bytes": rng.randint(1, 600),
        "max_path_bytes": rng.randint(8, 40),
        "max_depth": rng.randint(1, 3),
        "max_seconds": rng.randint(1, 4 * len(tree.entries)),
    }
    chosen = {name: value for name, value in drawn.items() if rng.random() < 0.4}
    allow_hardlinks = rng.random() < 0.5
    if full_listing:
        chosen.pop("max_entries", None)
    clock = itertools.count().__next__ if "max_seconds" in chosen else None
    return Session(Limits(max_scan_bytes=tree.scan_limit, **chosen), allow_hardlinks=allow_hardlinks, clock=clock)


@dataclass
class Outcome:
    session: Session
    records: list  # wpisy zwrócone analizie (z treścią), przed ponowną weryfikacją
    gaps: list[str]  # luki całej sesji z ``finish()``

    @property
    def ledger(self) -> list:
        return self.session.ledger


def ingest_tree(tree: Tree, config: str, **options) -> Outcome:
    session = open_session(tree, config, **options)
    with time_limit(READ_BUDGET):  # np. podążanie za pętlą dowiązań ma być porażką testu, nie zawieszeniem zestawu
        records = list(session.read(tree.root, "files"))
        return Outcome(session, records, session.finish())


# --- generator: czy w ogóle tworzy to, co ma sprawdzać --------------------------------------------

def test_generator_produces_every_kind_of_entry_across_the_seeds(tmp_path):
    kinds = set()
    for seed in SEEDS:
        tree = _Builder(seed, tmp_path / str(seed)).build()
        tree.unlock()
        kinds |= tree.kinds

    expected = ({kind for kind in KINDS if kind not in ("big_file", "raw_name", "locked_dir")}
                | {"file:empty", "file:over_tight_scan", "file:over_default_scan"} | {f"name:{label}" for label in NAMES})
    if not IS_ROOT:
        expected |= {"locked_dir:0", "locked_dir:400", "locked_dir:300"}
    else:
        expected -= {"locked_file"}
    if accepts_raw_names(tmp_path):
        expected |= {"name:non_utf8"}
    assert expected - kinds == set()


@every_seed
def test_generator_is_reproducible_from_its_seed(tmp_path, seed):
    def shape(tree: Tree) -> list:
        tree.unlock()
        # bez celów i rozmiarów dowiązań: cele bezwzględne zawierają katalog, w którym drzewo powstało
        return sorted((key, kind, body if stat.S_ISREG(kind) else "") for key, (kind, _, _, _, _, body) in tree.snapshot().items())

    assert shape(_Builder(seed, tmp_path / "a").build()) == shape(_Builder(seed, tmp_path / "b").build())


# --- własność: zupełność rejestru ---------------------------------------------------------------

def unaccounted(tree: Tree, ledger: list) -> list[str]:
    """Wpisy drzewa, których los nie wynika z rejestru, oraz wpisy rejestru bez pokrycia w drzewie.

    Wpis niebędący katalogiem musi mieć dokładnie jeden wpis w rejestrze albo nazwaną przyczynę braku:
    - katalog nadrzędny z wpisem ERROR/SKIPPED_* innym niż obcięcie listy (katalog nieprzeglądany w całości),
    - katalog nadrzędny z obciętą listą (MAX_ENTRIES), o ile z gałęzi prowadzącej do wpisu nie pochodzi żaden wpis,
    - zatrzymanie przejścia (MAX_FILES, MAX_SECONDS), o ile wpis leży w kolejności odwiedzin za punktem zatrzymania.

    Ograniczenie: katalog przejrzany bez przeszkód nie zostawia wpisu, więc z rejestru nie da się odróżnić
    „pusty katalog odwiedzony” od „pusty katalog pominięty”.
    """
    known = {printable(parts): parts for parts in tree.entries}
    problems = [f"wpis rejestru spoza drzewa: {record.rel!r}" for record in ledger if record.rel != ROOT and record.rel not in known]
    by_parts: dict[tuple[str, ...], list] = {}
    for record in ledger:
        if record.rel in known:
            by_parts.setdefault(known[record.rel], []).append(record)
    notes = {parts: records[0] for parts, records in by_parts.items() if stat.S_ISDIR(tree.entries[parts].st_mode)}
    stop = None  # klucz kolejności, za którym przejście zostało jawnie przerwane
    for index, record in enumerate(ledger):
        if record.rel == ROOT and record.reason == "MAX_ENTRIES":
            notes[()] = record
        elif record.rel == ROOT:
            earlier = [known[item.rel] for item in ledger[:index] if item.rel in known]
            stop = order(earlier[-1]) if earlier else ()
        elif record.reason == "MAX_FILES":
            stop = order(known[record.rel])

    def explained(parts: tuple[str, ...]) -> bool:
        for depth in range(len(parts)):
            note = notes.get(parts[:depth])
            if note is None:
                continue
            if note.reason != "MAX_ENTRIES" or not any(seen[:depth + 1] == parts[:depth + 1] for seen in by_parts):
                return True
        return stop is not None and order(parts) > stop

    for parts, info in tree.entries.items():
        records = by_parts.get(parts, [])
        if len(records) > 1:
            problems.append(f"{len(records)} wpisy rejestru dla {parts}")
        if stat.S_ISDIR(info.st_mode):
            if records and records[0].status is ReadStatus.READ:
                problems.append(f"katalog ze statusem READ: {parts}")
            if records and records[0].reason != "MAX_ENTRIES" and any(seen[:len(parts)] == parts and seen != parts for seen in by_parts):
                problems.append(f"wpisy rejestru spod nieprzeglądanego katalogu: {parts}")
        elif not records and not explained(parts):
            problems.append(f"wpis bez statusu: {parts}")
    return problems


@every_seed
@every_config
def test_every_tree_entry_is_accounted_for_in_the_ledger(grow, seed, config):
    tree = grow(seed)

    outcome = ingest_tree(tree, config)

    assert unaccounted(tree, outcome.ledger) == []


# --- własność: brak wyjścia poza korzeń ---------------------------------------------------------

@every_seed
@every_config
def test_nothing_outside_the_root_is_read_except_an_allowed_marked_hardlink(grow, seed, config):
    tree = grow(seed)
    canary, hidden = digest(tree.canary.read_bytes()), digest(tree.hidden.read_bytes())
    linked = {printable(path.relative_to(tree.root).parts) for path in tree.canary_links}

    outcome = ingest_tree(tree, config)

    seen = [*outcome.records, *outcome.ledger]
    outside = [record for record in seen if record.sha256 in (canary, hidden) or MARKER in (record.content or b"")]
    permitted = [record for record in outside
                 if outcome.session.allow_hardlinks and record.hardlinked and record.sha256 == canary and record.rel in linked]
    assert outside == permitted


# --- własność: zgodność skrótu ------------------------------------------------------------------

@every_seed
@every_config
def test_read_records_describe_exactly_the_bytes_on_disk(grow, seed, config):
    tree = grow(seed)
    paths = tree.path_of()

    outcome = ingest_tree(tree, config)

    read = [record for record in outcome.records if record.status is ReadStatus.READ]
    assert read or config != "default"  # sesja domyślna zawsze ma co czytać: własność nie jest pusta
    for record in read:
        data = paths[record.rel].read_bytes()
        assert (record.sha256, record.size) == (digest(data), len(data)), record.rel
        assert record.content in (None, data), record.rel
        assert (record.content is None) == (len(data) > outcome.session.limits.max_scan_bytes), record.rel


# --- własność: status inny niż READ niesie lukę, a nic nie zdradza ścieżki hosta ----------------

@every_seed
@every_config
def test_every_unread_entry_carries_a_gap_and_nothing_names_a_host_path(grow, tmp_path, seed, config):
    tree = grow(seed)

    outcome = ingest_tree(tree, config)

    records = [*outcome.records, *outcome.ledger]
    assert not [record for record in records if record.status is not ReadStatus.READ and not (record.gaps and all(record.gaps))]
    texts = [text for record in records for text in (record.source, record.rel, record.reason, *record.gaps)]
    texts += [*outcome.gaps, *(text for _, text in outcome.session.integrity_notes)]
    host_paths = {str(tmp_path), os.path.realpath(tmp_path)}
    assert not [text for text in texts if any(path in text for path in host_paths)]


# --- własność: limity ----------------------------------------------------------------------------

@every_seed
@every_config
def test_limits_are_never_exceeded(grow, seed, config):
    tree = grow(seed)
    folders = sum(stat.S_ISDIR(info.st_mode) for info in tree.entries.values())

    outcome = ingest_tree(tree, config)

    limits = outcome.session.limits
    read = [record for record in outcome.ledger if record.status is ReadStatus.READ]
    hashed = [record for record in outcome.ledger if record.sha256 is not None]
    overflow = [record for record in outcome.ledger if record.reason == "MAX_ENTRIES"]
    counted = [record for record in outcome.ledger if record.reason != "MAX_ENTRIES" and record.rel != ROOT]
    assert len(read) <= limits.max_files
    assert sum(record.size for record in hashed) <= limits.max_total_bytes
    assert all(record.size <= limits.max_file_bytes for record in hashed)
    assert len(counted) <= limits.max_entries
    assert len(overflow) <= folders + 1  # najwyżej jeden wpis o obcięciu na katalog (i korzeń)


# --- własność: niezmienność źródeł --------------------------------------------------------------

@every_seed
@every_config
def test_sources_are_left_exactly_as_they_were(grow, seed, config):
    tree = grow(seed, snapshot=True)

    ingest_tree(tree, config)

    tree.unlock()
    after = tree.snapshot()
    assert {key: (tree.before.get(key), after.get(key)) for key in tree.before.keys() | after.keys()
            if tree.before.get(key) != after.get(key)} == {}


# --- własność: determinizm ----------------------------------------------------------------------

@every_seed
@every_config
def test_two_sessions_over_the_same_tree_give_the_same_ledger(grow, seed, config):
    tree = grow(seed)

    first, second = ingest_tree(tree, config, full_listing=True), ingest_tree(tree, config, full_listing=True)

    assert not [record for record in first.ledger if record.reason == "MAX_ENTRIES"]  # warunek wstępny: żadna lista nie została obcięta
    assert first.ledger == second.ledger
    assert first.gaps == second.gaps


# --- własność: brak wycieku deskryptorów --------------------------------------------------------

@every_seed
@every_config
def test_no_descriptor_stays_open_after_a_full_read(grow, seed, config):
    tree = grow(seed)
    before = open_fd_count()

    ingest_tree(tree, config)

    assert open_fd_count() == before


@every_seed
@every_config
def test_no_descriptor_stays_open_when_the_reader_is_abandoned_midway(grow, seed, config):
    tree = grow(seed)
    session = open_session(tree, config)
    before = open_fd_count()

    stream = session.read(tree.root, "files")
    list(itertools.islice(stream, random.Random(seed).randint(1, 6)))
    del stream
    gc.collect()

    assert open_fd_count() == before


# --- własność: ponowna weryfikacja niezmienionego drzewa ----------------------------------------

@every_seed
@every_config
def test_reverification_of_an_untouched_tree_reports_no_change(grow, seed, config):
    tree = grow(seed)

    outcome = ingest_tree(tree, config)

    notes = [*outcome.gaps, *(text for _, text in outcome.session.integrity_notes)]
    assert not [text for text in notes if CHANGED_GAP in text]
    assert not [record for record in outcome.ledger if record.status is ReadStatus.CHANGED]


# --- własności, których kod dziś NIE spełnia (zgłoszone w #4; testy pilnują, żeby poprawka je odblokowała) ---

def test_distinct_files_never_share_a_ledger_path(tmp_path):
    site = tmp_path / "site"
    site.mkdir()
    if not accepts_raw_names(tmp_path):
        pytest.skip("system plików nie przyjmuje nazw spoza UTF-8")
    (site / os.fsdecode(b"x\xff.php")).write_bytes(b"<?php // synthetic one\n")
    (site / "x\\xff.php").write_bytes(b"<?php // synthetic two\n")
    session = Session()

    records = list(session.read(site, "files"))

    assert len(records) == 2
    assert len({record.rel for record in session.ledger}) == 2


def test_entry_marked_changed_by_reverification_carries_its_own_gap(tmp_path):
    site = tmp_path / "site"
    site.mkdir()
    (site / "index.php").write_bytes(b"<?php // synthetic before\n")
    session = Session()
    list(session.read(site, "files"))
    (site / "index.php").write_bytes(b"<?php // synthetic after, longer\n")

    gaps = session.finish()

    assert [(entry.rel, entry.status) for entry in session.ledger] == [("index.php", ReadStatus.CHANGED)]
    assert any(CHANGED_GAP in gap for gap in gaps)  # luka sesji istnieje…
    assert session.ledger[0].gaps  # …ale sam wpis jej nie niesie


# --- własności end-to-end: przez publiczny interfejs wptrace -----------------------------------

def cli_flags(tree: Tree, variant: str) -> tuple[str, ...]:
    if variant == "default":
        return ()
    if variant == "hardlinks":
        return ("--allow-hardlinks",)
    rng = random.Random(f"{tree.seed}/cli")
    files = sum(stat.S_ISREG(info.st_mode) for info in tree.entries.values())
    drawn = {"--max-files": rng.randint(1, files + 1), "--max-entries": rng.randint(1, len(tree.entries) + 2),
             "--max-file-bytes": rng.choice([1, tree.scan_limit, 150]), "--max-total-bytes": rng.randint(1, 600)}
    chosen = rng.sample(sorted(drawn), rng.randint(1, len(drawn)))
    return tuple(part for flag in chosen for part in (flag, str(drawn[flag])))


every_e2e_case = pytest.mark.parametrize("seed", E2E_SEEDS)
every_cli_variant = pytest.mark.parametrize("variant", ["default", "hardlinks", "limits"])


@every_e2e_case
@every_cli_variant
def test_report_over_a_tree_with_anything_skipped_is_never_complete(analyze, grow, seed, variant):
    tree = grow(seed)
    assert any(stat.S_ISLNK(info.st_mode) for info in tree.entries.values())  # warunek wstępny: jest co pominąć

    with time_limit(READ_BUDGET):
        run = analyze(tree.root, flags=cli_flags(tree, variant))

    validate_report(run.report)
    assert run.coverage("files")["status"] != "ANALYZED"
    assert run.report["scope_complete"] is False
    assert run.exit_code != 0


@every_e2e_case
@every_cli_variant
def test_report_and_html_name_no_host_path_and_no_content_from_outside(analyze, grow, tmp_path, seed, variant):
    tree = grow(seed)
    flags = cli_flags(tree, variant)

    with time_limit(READ_BUDGET):
        run = analyze(tree.root, flags=flags)

    written = run.json_text + run.html
    assert str(tmp_path) not in written
    assert os.path.realpath(tmp_path) not in written
    assert tree.hidden.read_bytes().decode().strip() not in written
    if "--allow-hardlinks" not in flags:
        assert MARKER.decode() not in written


# --- prawdziwy wyścig: osobny proces podmienia wpisy, gdy sesja czyta ---------------------------
#
# Bez haków i bez monkeypatch. To próbkowanie, nie dowód: test pokazuje, że w tysiącach rzeczywistych przeplotów
# nic spoza korzenia nie zostało przeczytane, ale nie wyklucza okna, w które podmiana akurat nie trafiła.
# Wyłączenie: ``pytest -m "not race"``.

RACE_SECONDS = 1.5  # tyle co najmniej trwa czytanie pod ostrzałem
RACE_BUDGET = 20.0  # twardy limit testu i czasu życia procesu podmieniającego
SWAPPER = """
import os, sys, time
mode, target, stage, outside, budget = sys.argv[1:]
parent, deadline, rounds = os.getppid(), time.monotonic() + float(budget), 0
stop, ready, link, spare = (os.path.join(stage, name) for name in ("stop", "ready", "link", "spare"))
if mode == "file":
    with open(target, "rb") as handle:
        original = handle.read()
else:
    os.symlink(outside, link)
while time.monotonic() < deadline and os.getppid() == parent and not os.path.exists(stop):
    if mode == "file":  # zwykły plik <-> dowiązanie do kanarka; każda podmiana to jedno atomowe rename
        os.symlink(outside, link)
        os.replace(link, target)
        with open(spare, "wb") as handle:
            handle.write(original)
        os.replace(spare, target)
    else:  # katalog <-> dowiązanie do katalogu poza korzeniem; niepustego katalogu nie da się nadpisać, więc dwa rename
        os.rename(target, spare)
        os.rename(link, target)
        os.rename(target, link)
        os.rename(spare, target)
    rounds += 1
    if rounds == 1:
        open(ready, "w").close()
"""


@contextmanager
def swapping(mode: str, target: Path, stage: Path, outside: Path):
    """Proces podmieniający ``target``; kończy się sam po utracie rodzica lub po budżecie i jest dobijany w ``finally``."""
    stage.mkdir()
    swapper = subprocess.Popen([sys.executable, "-I", "-c", SWAPPER, mode, str(target), str(stage), str(outside), str(RACE_BUDGET)],
                               stdin=subprocess.DEVNULL)
    try:
        started = time.monotonic()
        while not (stage / "ready").exists():
            assert swapper.poll() is None, "proces podmieniający zakończył się przed pierwszą podmianą"
            assert time.monotonic() - started < RACE_BUDGET, "proces podmieniający nie wystartował"
            time.sleep(0.005)
        yield swapper
    finally:
        (stage / "stop").touch()
        try:
            swapper.wait(timeout=5)
        except subprocess.TimeoutExpired:
            swapper.kill()
            swapper.wait()


def read_under_fire(site: Path, judge) -> tuple[int, set, list]:
    """Czyta drzewo w kółko; ``judge(record)`` zwraca etykietę dozwolonego wyniku albo None, gdy wynik jest niedozwolony.

    Kończy po ``RACE_SECONDS``, ale nie wcześniej, niż zobaczy obie strony podmiany (inaczej test niczego by nie sprawdził).
    """
    rounds, labels, violations = 0, set(), []
    until = time.monotonic() + RACE_SECONDS
    with time_limit(RACE_BUDGET):
        while not violations and (time.monotonic() < until or not {"original", "blocked"} <= labels):
            session = Session()
            records = list(session.read(site, "files"))
            session.finish()
            rounds += 1
            for record in [*records, *session.ledger]:
                label = judge(record)
                if label is None:
                    violations.append((rounds, record))
                labels.add(label)
    return rounds, labels, violations


@pytest.fixture
def battlefield(tmp_path):
    """Drzewo z podmienianym plikiem i katalogiem oraz ich „bliźniakami” poza korzeniem (kanarki)."""
    site, outside = tmp_path / "evidence" / "site", tmp_path / "outside"
    genuine = {"index.php": b"<?php // synthetic index\n", "mid/a.php": b"<?php // synthetic a\n",
               "mid/victim.php": b"<?php // synthetic ORIGINAL victim\n", "mid/z.php": b"<?php // synthetic z\n",
               "zz.php": b"<?php // synthetic zz\n"}
    for rel, body in genuine.items():
        (site / rel).parent.mkdir(parents=True, exist_ok=True)
        (site / rel).write_bytes(body)
    canaries = {"canary.php": MARKER + b"-FILE race\n", "twin/victim.php": MARKER + b"-TWIN victim\n", "twin/a.php": MARKER + b"-TWIN a\n"}
    for rel, body in canaries.items():
        (outside / rel).parent.mkdir(parents=True, exist_ok=True)
        (outside / rel).write_bytes(body)
    return site, outside, {rel: digest(body) for rel, body in genuine.items()}, {digest(body) for body in canaries.values()}


def judge_with(genuine: dict[str, str], forbidden: set[str], swapped: str):
    """Ocena wyniku: nic spoza korzenia; pod podmienianą ścieżką tylko oryginał albo jawna odmowa."""
    def judge(record) -> str | None:
        if record.sha256 in forbidden or MARKER in (record.content or b""):
            return None
        if record.rel != swapped and not record.rel.startswith(swapped + "/"):
            return "bystander"
        if record.status in (ReadStatus.READ, ReadStatus.CHANGED):
            return "original" if record.sha256 == genuine.get(record.rel) else None
        if record.status is ReadStatus.SKIPPED_SYMLINK:
            return "blocked"
        return "error" if record.status is ReadStatus.ERROR else None

    return judge


@pytest.mark.race
def test_file_swapped_for_a_symlink_by_another_process_is_never_followed(battlefield, tmp_path):
    site, outside, genuine, forbidden = battlefield

    with swapping("file", site / "mid" / "victim.php", tmp_path / "stage", outside / "canary.php") as swapper:
        rounds, labels, violations = read_under_fire(site, judge_with(genuine, forbidden, "mid/victim.php"))

    assert violations == [], f"po {rounds} odczytach"
    assert {"original", "blocked"} <= labels
    assert swapper.returncode == 0


@pytest.mark.race
def test_directory_swapped_for_a_symlink_by_another_process_is_never_entered(battlefield, tmp_path):
    site, outside, genuine, forbidden = battlefield

    with swapping("dir", site / "mid", tmp_path / "stage", outside / "twin") as swapper:
        rounds, labels, violations = read_under_fire(site, judge_with(genuine, forbidden, "mid"))

    assert violations == [], f"po {rounds} odczytach"
    assert {"original", "blocked"} <= labels
    assert swapper.returncode == 0
