"""Analiza logów HTTP: odczyt strumieniowy przez SecureIngest, parser wiersza (``logformats``), pokrycie per plik
i reguła ``HTTP_EXECUTABLE_IN_UPLOADS`` (ADR 0007 pkt 1–7).

Każdy zwykły plik źródła ``logs`` jest czytany raz: porcje z odczytu liczącego SHA-256 trafiają do ``LogFileParser``
tego pliku (``ingest.Session.read(..., sink_factory=...)``). W pamięci zostają tylko żądania do ścieżek z rozszerzeniem
kodu (najwyżej ``MAX_REQUESTS`` w całym przebiegu) i jeden niedokończony wiersz (najwyżej ``MAX_LINE_BYTES``).
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from . import filerules, ingest, logformats, models, redact
from .analysis import Detection, SourceCoverage
from .analysis import evidence_of as _evidence

MAX_LINE_BYTES = logformats.MAX_LINE_BYTES
MAX_REQUESTS = 50_000  # obserwacji HTTP_REQUEST (i wykryć z nich) w całym przebiegu; nadmiar jest luką
MAX_HELD_CHARS = 32 * 1024 * 1024  # znaków ścieżek, uri i czasu trzymanych żądań w całym przebiegu; nadmiar jest luką
MAX_URI_CHARS = 300
MAX_FILE_NOTES = 20  # plików wymienionych z nazwy w luce o odrzuconych wierszach
FORMATS = tuple(logformats.FORMATS)
_BLANK = b" \t\r"
_EXPLANATION = "Żądanie HTTP do pliku PHP w uploads; brak dowodu wykonania kodu."
_DOUBLE_EXTENSION = (" Ścieżka ma podwójne rozszerzenie: plik wykona się tylko przy konfiguracji serwera, która "
                     "przekazuje go do PHP po rozszerzeniu innym niż ostatnie (np. AddHandler w Apache).")


@dataclass(frozen=True)
class LogConfig:
    """Wybory operatora dotyczące logów: format (``--log-format``), zaufane proxy (``--trusted-proxy``)
    i deklarowana niepewność zegara serwera w sekundach (``--log-clock-skew``; ``None`` = niezadeklarowana)."""
    fmt: str = "combined"
    trusted_proxies: tuple[logformats.Network, ...] = ()
    clock_skew: float | None = None

    def __post_init__(self) -> None:
        if self.fmt not in logformats.FORMATS:
            raise ValueError(f"nieznany format logów: {self.fmt!r}")

    @property
    def uncertainty(self) -> int | None:
        """Niepewność zegara w pełnych sekundach (w górę): atrybut obserwacji jest liczbą całkowitą."""
        return None if self.clock_skew is None else -int(-self.clock_skew // 1)


@dataclass(frozen=True)
class LogScan:
    """Wynik analizy logów: wykrycia, pokrycie źródła i obserwacje ``HTTP_REQUEST`` dla korelacji (pkt 7).

    ``requests`` nie trafiają do raportu same z siebie: korelacja wybiera te, na które wskazuje ustalenie.
    """
    detections: list[Detection]
    cover: SourceCoverage
    requests: list[models.Observation]


@dataclass(frozen=True)
class _Held:
    """Żądanie do ścieżki kodu, zapamiętane do chwili, gdy znany jest dowód (``Evidence``) jego pliku.

    Tylko pola potrzebne obserwacji, z ``uri`` już zredagowanym i skróconym: pełny cel żądania (do 64 KiB) nie jest
    trzymany, więc pamięć jednego wpisu ogranicza ``MAX_URI_CHARS``, ``logformats.MAX_PATH_CHARS`` i ``MAX_TIME_CHARS``.
    """
    line: int
    path: str
    uri: str
    method: str
    status: int
    bytes: int | None
    precision: str
    timestamp_raw: str
    timestamp_utc: str | None
    client_ip: str
    basis: str


@dataclass
class _Budget:
    left: int = field(default_factory=lambda: MAX_REQUESTS)  # czytane przy tworzeniu: test może obniżyć limit
    chars: int = field(default_factory=lambda: MAX_HELD_CHARS)
    dropped: int = 0

    def take(self, held: _Held) -> bool:
        cost = _cost(held)
        if self.left <= 0 or cost > self.chars:
            self.dropped += 1
            return False
        self.left, self.chars = self.left - 1, self.chars - cost
        return True

    def give_back(self, held: list[_Held]) -> None:
        self.left += len(held)
        self.chars += sum(map(_cost, held))


def _cost(held: _Held) -> int:
    return len(held.path) + len(held.uri) + len(held.timestamp_raw)


@dataclass
class LogFileParser:
    """Stan jednego pliku logu: dzieli porcje na wiersze, parsuje je i liczy.

    Wynik nie zależy od podziału bajtów na porcje. Znakiem końca wiersza jest ``\\n``; końcowe ``\\r`` jest usuwane.
    Wiersz pusty (same spacje i tabulacje) nie jest liczony. Wiersz dłuższy niż ``max_line`` bajtów jest odrzucany
    (``too_long``) i pomijany do najbliższego ``\\n`` bez buforowania. Wiersz spoza UTF-8 jest dekodowany ze znakami
    zastępczymi, parsowany i liczony w ``lossy``.
    """
    config: LogConfig = field(default_factory=LogConfig)
    budget: _Budget = field(default_factory=_Budget)
    max_line: int = MAX_LINE_BYTES
    lines: int = 0
    parsed: int = 0
    lossy: int = 0
    first_lossy: int | None = None
    untimed: int = 0
    first_untimed: str | None = None
    unresolved: int = 0     # żądania, których ścieżki nie da się ustalić (``..`` ponad katalogiem głównym, znak sterujący)
    malformed_forwarded: int = 0
    rejected: Counter = field(default_factory=Counter)
    first_rejected: dict[str, int] = field(default_factory=dict)
    held: list[_Held] = field(default_factory=list)
    _buf: bytearray = field(default_factory=bytearray)
    _number: int = 0
    _skipping: bool = False

    def feed(self, chunk: bytes) -> None:
        start = 0
        while (end := chunk.find(b"\n", start)) >= 0:
            self._number += 1
            if self._skipping:
                self._skipping = False
            elif len(self._buf) + end - start > self.max_line:
                self._buf.clear()
                self._reject("too_long")
            else:
                self._buf += chunk[start:end]
                self._take(bytes(self._buf))
                self._buf.clear()
            start = end + 1
        if not self._skipping and start < len(chunk):
            if len(self._buf) + len(chunk) - start > self.max_line:
                self._buf.clear()
                self._skipping = True
                self._reject("too_long", self._number + 1)
            else:
                self._buf += chunk[start:]

    def close(self) -> None:
        """Ostatni wiersz bez znaku końca wiersza jest czytany jak każdy inny."""
        if self._skipping:
            self._skipping = False
            self._number += 1
        elif self._buf:
            self._number += 1
            self._take(bytes(self._buf))
            self._buf.clear()

    def _reject(self, reason: str, number: int | None = None) -> None:
        self.lines += 1
        self.rejected[reason] += 1
        self.first_rejected.setdefault(reason, self._number if number is None else number)

    def _take(self, raw: bytes) -> None:
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if not raw.strip(_BLANK):
            return
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", "replace")
            self.lossy += 1
            if self.first_lossy is None:
                self.first_lossy = self._number
        record = logformats.parse(self.config.fmt, text)
        if isinstance(record, str):
            self._reject(record)
            return
        self.lines += 1
        self.parsed += 1
        if record.timestamp_utc is None:
            self.untimed += 1
            self.first_untimed = self.first_untimed or record.timestamp_raw
        path = logformats.request_path(record.target)
        if path is None:
            self.unresolved += 1
            return
        path = _script_path(path)
        if path is None:
            return
        client, basis, malformed = logformats.client_address(record, self.config.trusted_proxies)
        self.malformed_forwarded += malformed
        held = _Held(self._number, path, redacted_uri(record.target), record.method, record.status,
                     record.bytes, record.precision, redact.neutralise(record.timestamp_raw), record.timestamp_utc, client, basis)
        if self.budget.take(held):
            self.held.append(held)


def redacted_uri(target: str) -> str:
    """``uri`` do raportu: query i fragment usunięte w całości strukturalnie (od pierwszego ``?`` albo ``#``), a nie
    wzorcem ``redact``, który zatrzymuje się na cudzysłowie, ``<`` albo ukośniku wstecznym; reszta po redakcji."""
    cut = min((at for at in (target.find("?"), target.find("#")) if at >= 0), default=len(target))
    tail = f"{target[cut]}{redact.MARK}" if cut < len(target) else ""
    return redact.excerpt(target[:cut], limit=MAX_URI_CHARS - len(tail)) + tail


def _probe(path: str) -> str:
    """Ścieżka do porównań z regułami: prefiks ``wp-content/uploads/`` bez względu na wielkość liter (serwer na systemie
    plików nierozróżniającym jej trafi w ten sam katalog); ``filerules`` porównuje rozszerzenia już bez niej."""
    head = path[:len(filerules.UPLOADS)]
    return filerules.UPLOADS + path[len(head):] if head.lower() == filerules.UPLOADS else path


def _is_code(path: str) -> bool:
    """Rozszerzenie kodu (``filerules.CODE_SUFFIXES``) albo podwójne rozszerzenie w uploads (pkt 4)."""
    probe = _probe(path)
    return filerules.is_code(probe) or filerules.is_double_extension_in_uploads(probe)


def _script_path(path: str) -> str | None:
    """Plik kodu, który obsłuży żądanie: pierwszy segment z rozszerzeniem kodu, reszta to ``PATH_INFO``
    (``/uploads/x.php/a.jpg`` wykona ``x.php``). ``None``, gdy żaden segment nie wskazuje pliku kodu."""
    end = 0
    while (end := path.find("/", end + 1)) >= 0:
        if _is_code(path[:end]):
            return path[:end]
    return path if _is_code(path) else None


def _in_uploads(path: str) -> bool:
    probe = _probe(path)
    return filerules.is_code_in_uploads(probe) or filerules.is_double_extension_in_uploads(probe)


def scan_logs(root: Path, session: ingest.Session, config: LogConfig | None = None) -> LogScan:
    """Analizuje źródło ``logs`` (katalog albo plik). Plik, którego nie udało się przeczytać, nie wnosi wierszy."""
    config = config or LogConfig()
    fmt = logformats.FORMATS[config.fmt]
    cover, detections, requests = SourceCoverage(), [], []
    budget, parsers = _Budget(), {}
    totals: Counter = Counter()
    rejected, first_rejected, noted_files, unparsed_files = Counter(), {}, [], []
    first_lossy = first_untimed = None
    hashed = 0

    def open_parser(rel: str) -> Callable[[bytes], None]:
        parsers[rel] = LogFileParser(config, budget)
        return parsers[rel].feed

    for item in session.read(root, "logs", keep_limit=0, sink_factory=open_parser):
        name = PurePosixPath(item.rel).name
        if item.status is ingest.ReadStatus.SKIPPED_SYMLINK and item.rel != ingest.ROOT:
            cover.note(f"Pominięto link w logach: {name}")
        else:
            cover.note(*item.gaps)
        parser = parsers.pop(item.rel, None)
        if item.sha256 is None or parser is None:
            if parser is not None:  # błąd w trakcie odczytu: wiersze tego pliku nie należą do żadnego dowodu
                budget.give_back(parser.held)
            continue
        hashed += 1
        parser.close()
        totals.update(lines=parser.lines, parsed=parser.parsed, lossy=parser.lossy, untimed=parser.untimed,
                      unresolved=parser.unresolved, malformed=parser.malformed_forwarded)
        rejected.update(parser.rejected)
        for reason, number in parser.first_rejected.items():
            first_rejected.setdefault(reason, f"{item.rel}:{number}")
        if parser.lossy and first_lossy is None:
            first_lossy = f"{item.rel}:{parser.first_lossy}"
        first_untimed = first_untimed or parser.first_untimed
        if parser.lines and not parser.parsed:
            unparsed_files.append(item.rel)
        if parser.rejected:
            noted_files.append(f"{item.rel} ({sum(parser.rejected.values())}/{parser.lines})")
        evidence_id = _evidence(item).id
        for held in parser.held:
            request = _observation(evidence_id, item.rel, held, fmt, config, "HTTP_REQUEST")
            requests.append(request)
            if _in_uploads(held.path):
                double = filerules.is_double_extension_in_uploads(_probe(held.path))
                detections.append(Detection(
                    "HTTP_EXECUTABLE_IN_UPLOADS", "high", "low" if double else "medium", "http_log",
                    _EXPLANATION + (_DOUBLE_EXTENSION if double else ""),
                    _observation(evidence_id, item.rel, held, fmt, config, "HTTP_REQUEST_FOR_PHP_IN_UPLOADS")))
    _summarise(cover, fmt, hashed, totals, rejected, first_rejected, noted_files, unparsed_files, first_lossy, first_untimed, budget)
    return LogScan(detections, cover, requests)


def _observation(evidence_id: str, rel: str, held: _Held, fmt: str, config: LogConfig, kind: str) -> models.Observation:
    return models.Observation(
        evidence_id, kind, models.Location(path=rel, line=held.line),
        {"path": held.path, "uri": held.uri, "method": held.method, "status": held.status, "bytes": held.bytes,
         "client_ip": held.client_ip, "client_ip_basis": held.basis, "log_format": fmt, "timestamp_precision": held.precision,
         "clock_uncertainty_seconds": config.uncertainty},
        timestamp_raw=held.timestamp_raw, timestamp_utc=held.timestamp_utc, time_source=models.TimeSource.LOG)


def _summarise(cover: SourceCoverage, fmt: str, hashed: int, totals: Counter, rejected: Counter, first_rejected: dict,
               noted_files: list[str], unparsed_files: list[str], first_lossy: str | None, first_untimed: str | None, budget: _Budget) -> None:
    lines, parsed = totals["lines"], totals["parsed"]
    if not hashed:
        cover.fail("Źródło logów nie zawiera żadnego odczytanego pliku: brak wierszy do analizy")
    elif lines and not parsed:
        cover.fail(f"Logi nie odpowiadają obsługiwanemu formatowi {fmt} (wybór --log-format): "
                   f"żaden z {lines} wierszy nie został sparsowany")
    elif not lines and not cover.partial:
        cover.fail("Logi nie zawierają żadnego wiersza do analizy")
    if unparsed_files and parsed:
        cover.degrade(f"{len(unparsed_files)} plików logów bez żadnego wiersza w formacie {fmt}: "
                      + ", ".join(unparsed_files[:MAX_FILE_NOTES]) + (", …" if len(unparsed_files) > MAX_FILE_NOTES else ""))
    if rejected and parsed:
        reasons = ", ".join(f"{logformats.REASONS[reason]} ×{number} (pierwszy: {first_rejected[reason]})"
                            for reason, number in sorted(rejected.items(), key=lambda pair: (-pair[1], pair[0])))
        share = 100 * (lines - parsed) / lines
        files = ", ".join(noted_files[:MAX_FILE_NOTES]) + (", …" if len(noted_files) > MAX_FILE_NOTES else "")
        cover.degrade(f"Nie sparsowano {lines - parsed}/{lines} wierszy logów ({share:.1f}%, format {fmt}): {reasons}"
                      + (f"; pliki: {files}" if files else ""))
    if totals["lossy"]:
        cover.degrade(f"{totals['lossy']} wierszy logów nie jest poprawnym UTF-8: zdekodowano je ze znakami zastępczymi, "
                      f"mogą być zniekształcone (pierwszy: {first_lossy})")
    if totals["untimed"]:
        cover.note(f"Nie można znormalizować czasu logu do UTC w {totals['untimed']} wierszach (np. brak strefy); "
                   f"pierwszy zapis: {redact.neutralise(first_untimed or '')}")
    if totals["unresolved"]:
        cover.note(f"{totals['unresolved']} żądań ma ścieżkę, której nie da się przypisać do pliku (\"..\" ponad katalogiem "
                   "głównym, znak sterujący po dekodowaniu %XX, cel inny niż ścieżka); reguły ich nie sprawdzają")
    if totals["malformed"]:
        cover.note(f"{totals['malformed']} żądań przez zaufane proxy ma odrzucone forwarded_for (niepoprawny wpis albo "
                   f"dłuższe niż {logformats.MAX_FORWARDED_CHARS} znaków): "
                   "adresem klienta jest adres połączenia")
    if budget.dropped:
        cover.degrade(f"Limit {MAX_REQUESTS} żądań do plików kodu albo {MAX_HELD_CHARS} znaków ich ścieżek i adresów "
                      f"przekroczony: pominięto {budget.dropped}; "
                      "nie sprawdzono ich regułą HTTP_EXECUTABLE_IN_UPLOADS ani korelacją")
