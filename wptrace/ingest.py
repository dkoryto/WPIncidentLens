"""SecureIngest: jedyny punkt, w którym WPTrace otwiera nieufny materiał dowodowy (ADR 0002: B2–B6, B8).

Moduł niczego nie interpretuje i nigdzie nie pisze. Każdy wpis jest otwierany względem deskryptora
katalogu z ``O_NOFOLLOW``, a jego typ ustala ``fstat`` na już otwartym deskryptorze — nie ma kroku
„sprawdź po ścieżce, potem otwórz po ścieżce”. Skrót i bajty przekazane do analizy pochodzą z jednego
odczytu tego samego deskryptora.

Czego moduł NIE gwarantuje: nie wykrywa punktów montowania wewnątrz drzewa, nie chroni przed zmianą
wykonaną przez administratora hosta ani przed zmianą cofniętą przed ponowną weryfikacją, a samo
otwarcie pliku urządzenia (zanim ``fstat`` pozwoli go odrzucić) może wywołać efekt uboczny sterownika —
materiał należy montować z ``nodev``.
"""
from __future__ import annotations

import errno
import hashlib
import itertools
import os
import stat
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, fields, replace
from enum import StrEnum
from pathlib import Path

CHUNK_BYTES = 1024 * 1024
CHANGED_GAP = "SOURCE_CHANGED_DURING_ANALYSIS"
ROOT = "."  # ``Evidence.rel`` wpisu opisującego samo źródło, a nie plik w jego wnętrzu

# O_NONBLOCK: otwarcie FIFO bez piszącego nie blokuje; O_NOCTTY: terminal nie staje się terminalem sterującym.
_OPEN_ENTRY = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
               | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOCTTY", 0))
_OPEN_DIR = _OPEN_ENTRY | getattr(os, "O_DIRECTORY", 0)
_SPECIAL_KINDS = ((stat.S_ISFIFO, "FIFO"), (stat.S_ISSOCK, "SOCKET"), (stat.S_ISCHR, "CHAR_DEVICE"), (stat.S_ISBLK, "BLOCK_DEVICE"))
_HEX_DIGITS = "0123456789abcdef"  # cyfry, którymi ``backslashreplace`` zapisuje bajt spoza UTF-8 jako ``\xNN``


class ReadStatus(StrEnum):
    READ = "READ"
    SKIPPED_SYMLINK = "SKIPPED_SYMLINK"
    SKIPPED_HARDLINK = "SKIPPED_HARDLINK"
    SKIPPED_SPECIAL = "SKIPPED_SPECIAL"
    SKIPPED_LIMIT = "SKIPPED_LIMIT"
    ERROR = "ERROR"
    CHANGED = "CHANGED"


class IngestRefusal(Exception):
    """Źródła nie da się bezpiecznie użyć. Komunikat nie zawiera ścieżki ani celu dowiązania."""

    _MESSAGES = {
        "SYMLINK": "ścieżka jest dowiązaniem symbolicznym; podaj ścieżkę rzeczywistą",
        "ENOENT": "brak wskazanej ścieżki",
        "ENOTDIR": "ścieżka nie jest katalogiem",
        "NOT_A_REGULAR_FILE": "ścieżka nie jest zwykłym plikiem",
        "OUTPUT_OVERLAPS_EVIDENCE": "katalog wyników nie może leżeć w źródle dowodów ani go zawierać",
        "UNSUPPORTED_PLATFORM": "platforma nie wspiera odczytu względem deskryptora katalogu (dir_fd, O_NOFOLLOW); odmowa pracy",
    }

    def __init__(self, status: ReadStatus, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason

    def __str__(self) -> str:
        return self._MESSAGES.get(self.reason, f"nie można bezpiecznie otworzyć ({self.reason})")


@dataclass(frozen=True)
class Limits:
    """Limity ADR 0002 B6; obowiązują łącznie dla wszystkich źródeł jednej sesji."""
    max_files: int = 200_000
    max_entries: int = 1_000_000  # wszystkie wpisy: pliki, katalogi, dowiązania, pliki specjalne
    max_file_bytes: int = 2 * 1024**3
    max_total_bytes: int = 20 * 1024**3
    max_scan_bytes: int = 4 * 1024**2
    max_path_bytes: int = 4096
    max_depth: int = 64
    max_seconds: float = 30 * 60

    def __post_init__(self) -> None:
        for limit in fields(self):
            if not getattr(self, limit.name) > 0:
                raise ValueError(f"limit {limit.name} musi być dodatni")


@dataclass(frozen=True)
class Evidence:
    """Wynik próby odczytu jednego wpisu. ``sha256`` jest ustawione wtedy i tylko wtedy, gdy bajty przeczytano."""
    source: str
    rel: str
    status: ReadStatus
    reason: str = ""
    sha256: str | None = None
    size: int | None = None
    mtime_ns: int | None = None
    hardlinked: bool = False
    content: bytes | None = field(default=None, repr=False)
    gaps: tuple[str, ...] = ()


@dataclass
class _Seen:
    entry: int  # indeks w Session.ledger
    parts: tuple[str, ...]
    identity: tuple[int, int]


@dataclass
class _Root:
    path: str
    source: str
    is_dir: bool
    identity: tuple[int, int]
    seen: list[_Seen] = field(default_factory=list)


def _require_platform() -> None:
    flags = all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_CLOEXEC"))
    if not (flags and {os.open, os.stat} <= os.supports_dir_fd and os.stat in os.supports_follow_symlinks
            and os.scandir in os.supports_fd):
        raise IngestRefusal(ReadStatus.ERROR, "UNSUPPORTED_PLATFORM")


def _error_name(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno, "OSError")


def _kind(mode: int) -> str:
    return next((name for matches, name in _SPECIAL_KINDS if matches(mode)), "OTHER")


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _printable(name: str) -> str:
    """Nazwa spoza UTF-8 dostaje postać ``\\xNN`` zamiast surogatów, których nie da się zapisać w raporcie.

    Odwzorowanie jest różnowartościowe: dwie różne nazwy bajtowe nigdy nie dają tej samej postaci. Nazwa poprawna
    w UTF-8 zostaje bez zmian, chyba że sama zawiera dosłowną sekwencję ``\\xNN`` (ukośnik, ``x``, dwie małe cyfry
    szesnastkowe) — wtedy, tak jak w nazwie z bajtami spoza UTF-8, każdy jej ukośnik wsteczny jest podwajany.
    Postać z sekwencją ``\\xNN`` jest więc zawsze zakodowana (``\\\\`` to ukośnik, ``\\xNN`` to bajt), a bez niej dosłowna.
    """
    raw = os.fsencode(name)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.replace(b"\\", b"\\\\").decode("utf-8", "backslashreplace")
    spelled_out = any(len(rest) >= 2 and rest[0] in _HEX_DIGITS and rest[1] in _HEX_DIGITS for rest in text.split("\\x")[1:])
    return text.replace("\\", "\\\\") if spelled_out else text


def _where(source: str, rel: str) -> str:
    if rel == ROOT:
        return f"źródło {source}"
    return rel if source == "files" else f"{source}/{rel}"


def _sorted_names(dir_fd: int, limit: int) -> list[str]:
    """Najwyżej ``limit + 1`` nazw z katalogu: nadmiarowa nazwa sygnalizuje obcięcie, a lista nie rośnie bez ograniczeń."""
    with os.scandir(dir_fd) as entries:
        names = [entry.name for entry in itertools.islice(entries, limit + 1)]
    return sorted(names, key=os.fsencode)


def _open_at(name: str, flags: int, dir_fd: int | None = None) -> tuple[int, os.stat_result]:
    fd = os.open(name, flags, dir_fd=dir_fd)
    try:
        return fd, os.fstat(fd)
    except BaseException:
        os.close(fd)
        raise


def _why_not_opened(exc: OSError, lstat: Callable[[], os.stat_result]) -> tuple[ReadStatus, str]:
    """Nazywa przyczynę nieudanego otwarcia. ``lstat`` służy tylko opisowi: wpis nie został i nie zostanie otwarty."""
    try:
        mode = lstat().st_mode
    except (OSError, ValueError):
        return ReadStatus.ERROR, _error_name(exc)
    if stat.S_ISLNK(mode):
        return ReadStatus.SKIPPED_SYMLINK, "SYMLINK"
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        return ReadStatus.SKIPPED_SPECIAL, _kind(mode)
    return ReadStatus.ERROR, _error_name(exc)


def _open_root(path: str | os.PathLike[str], expect: str) -> tuple[int, os.stat_result]:
    """Otwiera źródło wskazane przez operatora; ``expect`` to "dir", "file" albo "any"."""
    _require_platform()
    target = os.fspath(Path(path))  # Path usuwa końcowy "/", który kazałby jądru podążyć za dowiązaniem
    try:
        fd, info = _open_at(target, _OPEN_DIR if expect == "dir" else _OPEN_ENTRY)
    except ValueError:
        raise IngestRefusal(ReadStatus.ERROR, "INVALID_PATH") from None
    except OSError as exc:
        raise IngestRefusal(*_why_not_opened(exc, lambda: os.lstat(target))) from None
    if stat.S_ISREG(info.st_mode) or (stat.S_ISDIR(info.st_mode) and expect != "file"):
        return fd, info
    os.close(fd)
    if stat.S_ISDIR(info.st_mode):
        raise IngestRefusal(ReadStatus.ERROR, "NOT_A_REGULAR_FILE")
    raise IngestRefusal(ReadStatus.SKIPPED_SPECIAL, _kind(info.st_mode))


def _hash_fd(fd: int, expected: int, keep: bool) -> tuple[str, int, bytes | None]:
    """Jeden strumieniowy odczyt: skrót, liczba bajtów i (opcjonalnie) treść. Plik rosnący nie zatrzyma narzędzia."""
    digest, kept, got = hashlib.sha256(), [], 0
    while got <= expected:
        chunk = os.read(fd, CHUNK_BYTES)
        if not chunk:
            break
        got += len(chunk)
        digest.update(chunk)
        if keep:
            kept.append(chunk)
    return digest.hexdigest(), got, b"".join(kept) if keep else None


def check_source(path: str | os.PathLike[str], expect: str = "any") -> None:
    """Wczesna walidacja ścieżki operatora (B5). Właściwy odczyt otwiera źródło ponownie na tych samych zasadach."""
    fd, _ = _open_root(path, expect)
    os.close(fd)


def resolve_output(output: str | os.PathLike[str], sources: Iterable[str | os.PathLike[str]]) -> Path:
    """Zwraca rzeczywistą ścieżkę katalogu wyników albo odmawia, gdy pokrywa się on ze źródłem dowodów.

    Porównywane są ścieżki rzeczywiste oraz tożsamość (urządzenie, i-węzeł) istniejących przodków, żeby
    kolizji nie ukryła inna pisownia tej samej ścieżki (wielkość liter, drugie dowiązanie do katalogu).
    """
    def identity(path: Path) -> tuple[int, int] | None:
        try:
            return _identity(os.stat(path))
        except (OSError, ValueError):
            return None

    out = Path(os.path.realpath(output))
    out_chain = [out, *out.parents]
    out_identities = {found for path in out_chain if (found := identity(path))}
    out_identity = identity(out)
    for source in sources:
        real = Path(os.path.realpath(source))
        source_chain = [real, *real.parents]
        if (real in out_chain or out in source_chain or identity(real) in out_identities
                or (out_identity and any(identity(path) == out_identity for path in source_chain))):
            raise IngestRefusal(ReadStatus.ERROR, "OUTPUT_OVERLAPS_EVIDENCE")
    return out


class Session:
    """Jedna analiza: wspólne limity, rejestr wszystkich wpisów i ponowna weryfikacja przeczytanych dowodów."""

    def __init__(self, limits: Limits | None = None, *, allow_hardlinks: bool = False, reverify: bool = True,
                 clock: Callable[[], float] | None = None):
        _require_platform()
        self.limits = limits or Limits()
        self.allow_hardlinks = allow_hardlinks
        self.reverify = reverify
        self.ledger: list[Evidence] = []
        # Rozbieżności z ponownej weryfikacji jako (źródło, tekst luki); źródło None = cała sesja (weryfikacja przerwana).
        self.integrity_notes: list[tuple[str | None, str]] = []
        self._clock = clock or time.monotonic  # zegar monotoniczny: zmiana czasu systemowego nie wydłuża budżetu
        self._deadline = self._clock() + self.limits.max_seconds
        self._roots: list[_Root] = []
        self._files = self._entries = self._pending = self._bytes = self._hardlinked = 0

    def read(self, path: str | os.PathLike[str], source: str, *, expect: str = "any",
             wanted: Callable[[str], bool] | None = None, keep_limit: int | None = None) -> Iterator[Evidence]:
        """Czyta źródło (katalog rekurencyjnie albo pojedynczy plik) i zwraca po jednym ``Evidence`` na wpis.

        Treść jest zachowywana tylko dla plików nie większych niż ``keep_limit`` (domyślnie limit skanowania),
        dla których ``wanted(rel)`` jest prawdą. Źródła, którego nie da się otworzyć, dotyczy wpis ``rel == ROOT``.
        """
        keep_limit = self.limits.max_scan_bytes if keep_limit is None else keep_limit
        if self._expired():
            yield self._skip(source, ROOT, ReadStatus.SKIPPED_LIMIT, "MAX_SECONDS")
            return
        try:
            fd, info = _open_root(path, expect)
        except IngestRefusal as refusal:
            yield self._skip(source, ROOT, refusal.status, refusal.reason)
            return
        root = _Root(os.fspath(Path(path)), source, stat.S_ISDIR(info.st_mode), _identity(info))
        self._roots.append(root)
        if root.is_dir:
            yield from self._walk(fd, root, wanted, keep_limit)
            return
        try:
            yield self._read_regular(fd, info, root, (), Path(path).name, wanted, keep_limit)
        finally:
            os.close(fd)

    def read_file(self, path: str | os.PathLike[str], source: str, *, keep_limit: int | None = None) -> Evidence:
        """Czyta źródło, które musi być pojedynczym zwykłym plikiem."""
        return list(self.read(path, source, expect="file", keep_limit=keep_limit))[0]

    def finish(self) -> list[str]:
        """Kończy analizę: ponownie weryfikuje przeczytane dowody (B4) i zwraca luki dotyczące całej sesji."""
        gaps = []
        if self._hardlinked:
            gaps.append(f"Odczytano {self._hardlinked} plików z wieloma dowiązaniami twardymi (--allow-hardlinks); "
                        "ich treść może być współdzielona z plikami spoza materiału dowodowego")
        if not self.reverify:
            return [*gaps, "Ponowna weryfikacja dowodów wyłączona (--no-reverify): zmiana źródeł po odczycie nie zostałaby wykryta"]
        return gaps + self._reverify()

    # --- odczyt ---------------------------------------------------------------------------------

    def _expired(self) -> bool:
        return self._clock() > self._deadline

    def _walk(self, root_fd: int, root: _Root, wanted, keep_limit: int) -> Iterator[Evidence]:
        """Przejście w głąb bez rekurencji: na stosie leżą otwarte katalogi, więc deskryptorów jest najwyżej tyle, ile poziomów."""
        frames: list[tuple[int, Iterator[str], tuple[str, ...]]] = []
        try:
            if note := self._enter(frames, root_fd, (), root.source):
                yield note
            while frames:
                dir_fd, names, parts = frames[-1]
                name = next(names, None)
                if name is None:
                    frames.pop()
                    os.close(dir_fd)
                    continue
                self._pending -= 1
                if self._expired():
                    yield self._skip(root.source, ROOT, ReadStatus.SKIPPED_LIMIT, "MAX_SECONDS")
                    return
                here = (*parts, name)
                rel = "/".join(here)
                self._entries += 1
                if self._entries > self.limits.max_entries:
                    yield self._skip(root.source, rel, ReadStatus.SKIPPED_LIMIT, "MAX_ENTRIES")
                    return
                if len(os.fsencode(rel)) > self.limits.max_path_bytes:
                    yield self._skip(root.source, rel, ReadStatus.SKIPPED_LIMIT, "MAX_PATH_BYTES")
                    continue
                try:
                    fd, info = _open_at(name, _OPEN_ENTRY, dir_fd)
                except OSError as exc:
                    yield self._skip(root.source, rel, *_why_not_opened(
                        exc, lambda: os.stat(name, dir_fd=dir_fd, follow_symlinks=False)))
                    continue
                if stat.S_ISDIR(info.st_mode):
                    if len(here) > self.limits.max_depth:
                        os.close(fd)
                        yield self._skip(root.source, rel, ReadStatus.SKIPPED_LIMIT, "MAX_DEPTH")
                    elif note := self._enter(frames, fd, here, root.source):
                        yield note
                    continue
                try:
                    if stat.S_ISREG(info.st_mode):
                        record = self._read_regular(fd, info, root, here, rel, wanted, keep_limit)
                    else:
                        record = self._skip(root.source, rel, ReadStatus.SKIPPED_SPECIAL, _kind(info.st_mode))
                finally:
                    os.close(fd)
                yield record
                if record.reason == "MAX_FILES":  # dalsze pliki i tak byłyby pominięte
                    return
        finally:
            for dir_fd, names, _ in frames:
                self._pending -= sum(1 for _ in names)
                os.close(dir_fd)

    def _enter(self, frames: list, fd: int, parts: tuple[str, ...], source: str) -> Evidence | None:
        """Listuje otwarty katalog i odkłada go na stos. Lista jest ograniczona pozostałym budżetem wpisów, żeby
        miliony dowiązań lub pustych katalogów nie ominęły limitu plików ani nie rozdęły rejestru i raportu. Zwraca wpis do raportu: ERROR, gdy katalogu nie da się
        wylistować (deskryptor jest wtedy zamykany), albo SKIPPED_LIMIT, gdy lista została obcięta budżetem wpisów."""
        where = "/".join(parts) or ROOT
        # Nazwy wylistowane, lecz jeszcze nieodwiedzone (na stosie katalogów nadrzędnych) też zajmują budżet:
        # inaczej każdy poziom zagnieżdżenia mógłby trzymać w pamięci osobną, pełną listę.
        budget = max(self.limits.max_entries - self._entries - self._pending, 0)
        try:
            names = _sorted_names(fd, budget)
        except OSError as exc:
            os.close(fd)
            return self._skip(source, where, ReadStatus.ERROR, _error_name(exc))
        frames.append((fd, iter(names[:budget]), parts))
        self._pending += min(len(names), budget)
        if len(names) > budget:
            return self._skip(source, where, ReadStatus.SKIPPED_LIMIT, "MAX_ENTRIES")
        return None

    def _read_regular(self, fd: int, info: os.stat_result, root: _Root, parts: tuple[str, ...], rel: str,
                      wanted, keep_limit: int) -> Evidence:
        self._files += 1
        hardlinked = info.st_nlink > 1
        if self._files > self.limits.max_files:
            return self._skip(root.source, rel, ReadStatus.SKIPPED_LIMIT, "MAX_FILES")
        if hardlinked and not self.allow_hardlinks:
            return self._skip(root.source, rel, ReadStatus.SKIPPED_HARDLINK, "NLINK")
        if info.st_size > self.limits.max_file_bytes:
            return self._skip(root.source, rel, ReadStatus.SKIPPED_LIMIT, "MAX_FILE_BYTES")
        if self._bytes + info.st_size > self.limits.max_total_bytes:
            return self._skip(root.source, rel, ReadStatus.SKIPPED_LIMIT, "MAX_TOTAL_BYTES")
        shown = _printable(rel)
        keep = info.st_size <= keep_limit and (wanted is None or wanted(shown))
        try:
            sha, got, content = _hash_fd(fd, info.st_size, keep)
            after = os.fstat(fd)
        except OSError as exc:
            return self._skip(root.source, rel, ReadStatus.ERROR, _error_name(exc))
        self._bytes += got
        self._hardlinked += hardlinked
        changed = got != info.st_size or (_identity(after), after.st_size, after.st_mtime_ns) != (
            _identity(info), info.st_size, info.st_mtime_ns)
        gaps = [f"{CHANGED_GAP}: {_where(root.source, shown)} (zmiana w trakcie odczytu)"] if changed else []
        if shown == rel.replace("\\", "\\\\") != rel:  # nazwa poprawna w UTF-8, tylko z dosłowną sekwencją \xNN
            gaps.append(f"Nazwa z dosłowną sekwencją \\xNN zapisana z podwojonymi ukośnikami wstecznymi: {_where(root.source, shown)}")
        elif shown != rel:
            gaps.append(f"Nazwa spoza UTF-8 zapisana w postaci zastępczej: {_where(root.source, shown)}")
        record = Evidence(root.source, shown, ReadStatus.CHANGED if changed else ReadStatus.READ, "DURING_READ" if changed else "",
                          sha, got, info.st_mtime_ns, hardlinked, content, tuple(gaps))
        self.ledger.append(replace(record, content=None))
        if not changed:
            root.seen.append(_Seen(len(self.ledger) - 1, parts, _identity(info)))
        return record

    def _skip(self, source: str, rel: str, status: ReadStatus, reason: str) -> Evidence:
        shown = _printable(rel)
        record = Evidence(source, shown, status, reason, gaps=(self._gap(status, reason, _where(source, shown)),))
        self.ledger.append(record)
        return record

    def _gap(self, status: ReadStatus, reason: str, where: str) -> str:
        """Tekst luki pokrycia: tylko ścieżka względna do źródła i nazwa przyczyny (B8)."""
        limits = self.limits
        if status is ReadStatus.SKIPPED_SYMLINK:
            return f"Łącze symboliczne pominięte (bez podążania): {where}"
        if status is ReadStatus.SKIPPED_HARDLINK:
            return f"Plik z wieloma dowiązaniami twardymi pominięty (SKIPPED_HARDLINK; odczyt wymaga --allow-hardlinks): {where}"
        if status is ReadStatus.SKIPPED_SPECIAL:
            return f"Plik specjalny pominięty: {where} ({reason})"
        if status is ReadStatus.SKIPPED_LIMIT:
            return {
                "MAX_FILES": f"Limit {limits.max_files} plików; analiza katalogu niepełna (pierwszy pominięty wpis: {where})",
                "MAX_ENTRIES": f"Limit {self.limits.max_entries} wpisów (pliki, katalogi, dowiązania) wyczerpany; "
                               f"analiza niepełna od: {where}",
                "MAX_FILE_BYTES": f"Plik większy niż limit {limits.max_file_bytes} B pominięty bez obliczania skrótu: {where}",
                "MAX_TOTAL_BYTES": f"Limit łącznego rozmiaru {limits.max_total_bytes} B wyczerpany; plik pominięty: {where}",
                "MAX_PATH_BYTES": f"Ścieżka dłuższa niż {limits.max_path_bytes} bajtów pominięta: {where[:200]}…",
                "MAX_DEPTH": f"Katalog poniżej limitu głębokości {limits.max_depth} nieprzeglądany: {where}",
                "MAX_SECONDS": f"Limit czasu analizy {limits.max_seconds:g} s przekroczony; nieodczytana pozostała część: {where}",
            }[reason]
        return f"Odczyt nieudany ({reason}): {where}"

    # --- ponowna weryfikacja --------------------------------------------------------------------

    def _reverify(self) -> list[str]:
        gaps: list[str] = []

        def note(source: str | None, text: str) -> None:
            self.integrity_notes.append((source, text))
            gaps.append(text)

        total, done = sum(len(root.seen) for root in self._roots), 0
        for root in self._roots:
            if not root.seen:
                continue
            try:
                root_fd, info = _open_root(root.path, "dir" if root.is_dir else "file")
            except IngestRefusal as refusal:
                note(root.source, f"{CHANGED_GAP}: źródło {root.source} niedostępne przy ponownej weryfikacji ({refusal.reason})")
                for seen in root.seen:
                    self._mark_changed(seen, refusal.reason)
                continue
            if _identity(info) != root.identity and root.is_dir:
                note(root.source, f"{CHANGED_GAP}: źródło {root.source} zostało podmienione po odczycie")
            dir_parts, dir_fd = (), root_fd  # katalog ostatnio sprawdzanego pliku: sąsiednie wpisy dzielą jedno otwarcie
            try:
                for seen in root.seen:
                    if self._expired():
                        note(None, f"Ponowna weryfikacja przerwana limitem czasu {self.limits.max_seconds:g} s: "
                                   f"sprawdzono {done}/{total} dowodów")
                        return gaps
                    done += 1
                    try:
                        if seen.parts[:-1] != dir_parts:
                            if dir_fd != root_fd:
                                os.close(dir_fd)
                            dir_parts, dir_fd = (), root_fd
                            dir_parts, dir_fd = seen.parts[:-1], self._descend(root_fd, seen.parts[:-1])
                        difference = self._difference(None if root.is_dir else root_fd, dir_fd, seen)
                    except OSError as exc:  # m.in. ELOOP, gdy wpis lub katalog nadrzędny stał się dowiązaniem
                        difference = _error_name(exc)
                    if difference:
                        note(root.source, self._mark_changed(seen, difference))
            finally:
                if dir_fd != root_fd:
                    os.close(dir_fd)
                os.close(root_fd)
        return gaps

    def _descend(self, root_fd: int, parts: tuple[str, ...]) -> int:
        fd = root_fd
        for part in parts:
            try:
                deeper = os.open(part, _OPEN_DIR, dir_fd=fd)
            finally:
                if fd != root_fd:
                    os.close(fd)
            fd = deeper
        return fd

    def _difference(self, file_fd: int | None, dir_fd: int, seen: _Seen) -> str | None:
        """Nazwa pierwszej różnicy między dowodem z rejestru a tym, co leży teraz pod tą samą ścieżką; None = bez zmian."""
        entry = self.ledger[seen.entry]
        if file_fd is not None:
            return self._compare(file_fd, os.fstat(file_fd), seen, entry)
        fd, info = _open_at(seen.parts[-1], _OPEN_ENTRY, dir_fd)
        try:
            return self._compare(fd, info, seen, entry)
        finally:
            os.close(fd)

    def _compare(self, fd: int, info: os.stat_result, seen: _Seen, entry: Evidence) -> str | None:
        if not stat.S_ISREG(info.st_mode):
            return "TYPE"
        if _identity(info) != seen.identity:
            return "INODE"
        if info.st_size != entry.size:
            return "SIZE"
        if info.st_mtime_ns != entry.mtime_ns:
            return "MTIME"
        return None if _hash_fd(fd, info.st_size, keep=False)[0] == entry.sha256 else "SHA256"

    def _mark_changed(self, seen: _Seen, difference: str) -> str:
        entry = self.ledger[seen.entry]
        self.ledger[seen.entry] = replace(entry, status=ReadStatus.CHANGED, reason=f"REVERIFY_{difference}")
        return f"{CHANGED_GAP}: {_where(entry.source, entry.rel)} (rozbieżność przy ponownej weryfikacji: {difference})"
