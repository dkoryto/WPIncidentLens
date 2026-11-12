"""Analiza logów HTTP: odczyt strumieniowy przez SecureIngest, parser wiersza (``logformats``), pokrycie per plik
i reguła ``HTTP_EXECUTABLE_IN_UPLOADS`` (ADR 0007 pkt 1–7).

Każdy zwykły plik źródła ``logs`` jest czytany raz: porcje z odczytu liczącego SHA-256 trafiają do ``LogFileParser``
tego pliku (``ingest.Session.read(..., sink_factory=...)``). Reguła jest sprawdzana przy parsowaniu wiersza, niezależnie
od puli korelacji (najwyżej ``MAX_RULE_FINDINGS`` wykryć w przebiegu). W pamięci zostają: wykrycia reguły, żądania do
ścieżek kodu, których korelacja może użyć (``correlate.Focus``; najwyżej ``MAX_REQUESTS`` w przebiegu), i jeden
niedokończony wiersz (najwyżej ``MAX_LINE_BYTES``). Limit czasu sesji jest sprawdzany co ``CLOCK_EVERY_LINES`` wierszy.
"""
from __future__ import annotations

import re

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from . import filerules, ingest, logformats, models, redact, rules
from .analysis import Detection, SourceCoverage
from .correlate import Focus
from .analysis import evidence_of as _evidence

MAX_LINE_BYTES = logformats.MAX_LINE_BYTES
MAX_REQUESTS = 50_000  # obserwacji HTTP_REQUEST (materiał korelacji) w całym przebiegu; nadmiar jest luką
MAX_RULE_FINDINGS = 1000  # wykryć HTTP_EXECUTABLE_IN_UPLOADS w całym przebiegu; nadmiar jest luką z łączną liczbą
CLOCK_EVERY_LINES = 256  # co tyle wierszy parser sprawdza limit czasu sesji
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
class _RuleCap:
    """Wspólny dla przebiegu limit wykryć reguły."""
    left: int = field(default_factory=lambda: MAX_RULE_FINDINGS)  # czytane przy tworzeniu: test może obniżyć limit

    def take(self) -> bool:
        if self.left <= 0:
            return False
        self.left -= 1
        return True


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
    focus: Focus | None = None  # None: trzymane są wszystkie żądania do ścieżek kodu
    cap: _RuleCap = field(default_factory=_RuleCap)
    expired: Callable[[], bool] | None = None  # limit czasu sesji (``ingest.Session.expired``)
    stopped_at: int | None = None  # ostatni przeanalizowany wiersz, gdy limit czasu przerwał plik
    lines: int = 0
    parsed: int = 0
    lossy: int = 0
    first_lossy: int | None = None
    untimed: int = 0
    first_untimed: str | None = None
    unresolved: int = 0     # żądania, których ścieżki nie da się ustalić (``..`` ponad katalogiem głównym, NUL, ``%2F``)
    unresolved_code: int = 0  # z nich te, których cel wygląda na żądanie pliku kodu
    first_unresolved_code: int | None = None
    lossy_paths: int = 0    # ścieżki, których bajty po dekodowaniu nie są poprawnym UTF-8
    malformed_forwarded: int = 0
    rejected: Counter = field(default_factory=Counter)
    first_rejected: dict[str, int] = field(default_factory=dict)
    held: list[_Held] = field(default_factory=list)
    hits: list[tuple[_Held, bool]] = field(default_factory=list)  # wykrycia reguły: (żądanie, podwójne rozszerzenie)
    hits_seen: int = 0  # wszystkie trafienia reguły w pliku, także ponad limit
    # typ wyjątku reguły → [liczba, pierwszy wiersz]; scan_logs zamienia je w lukę (``rules.rule_failed``)
    rule_errors: dict = field(default_factory=dict)
    _buf: bytearray = field(default_factory=bytearray)
    _number: int = 0
    _skipping: bool = False

    def feed(self, chunk: bytes) -> None:
        if self.stopped_at is not None:
            return
        start = 0
        while (end := chunk.find(b"\n", start)) >= 0:
            self._number += 1
            if self._out_of_time():
                return
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
        if self.stopped_at is not None:
            return
        if self._skipping:
            self._skipping = False
            self._number += 1
        elif self._buf:
            self._number += 1
            self._take(bytes(self._buf))
            self._buf.clear()

    def _out_of_time(self) -> bool:
        """Co ``CLOCK_EVERY_LINES`` wierszy: po limicie czasu reszta pliku nie jest analizowana (bufor jest zwalniany)."""
        if self.expired is None or self._number % CLOCK_EVERY_LINES or not self.expired():
            return False
        self.stopped_at = self._number - 1
        self._buf.clear()
        self._skipping = False
        return True

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
        resolved = logformats.resolve_target(record.target, record.escaped)
        self.lossy_paths += resolved.lossy
        if resolved.path is None:
            self.unresolved += 1
            if _mentions_code(resolved.text):
                self.unresolved_code += 1
                self.first_unresolved_code = self.first_unresolved_code or self._number
            return
        script = _script_path(resolved.path)
        if script is None:
            return
        # Reguły widzą ścieżkę zdekodowaną; do raportu (i do porównań korelacji) idzie postać bez znaków sterujących.
        shown = redact.neutralise(script)
        uploads, double = self._rule(script)
        wanted = self.focus is None or self.focus.wants(shown, record.timestamp_utc)
        if not (uploads or wanted):
            return
        client, basis, malformed = logformats.client_address(record, self.config.trusted_proxies)
        self.malformed_forwarded += malformed
        held = _Held(self._number, shown, redacted_uri(record.target), record.method, record.status,
                     record.bytes, record.precision, redact.neutralise(record.timestamp_raw), record.timestamp_utc, client, basis)
        if uploads:
            self.hits_seen += 1
            if self.cap.take():
                self.hits.append((held, double))
        if wanted and self.budget.take(held):
            self.held.append(held)

    def _rule(self, script: str) -> tuple[bool, bool]:
        """Reguła ``HTTP_EXECUTABLE_IN_UPLOADS``: (trafienie, podwójne rozszerzenie). Wyjątek reguły (błąd kodu wywołany
        danymi) nie przerywa odczytu: wiersz nie daje trafienia, a typ wyjątku trafia do luki pokrycia logów."""
        try:
            uploads = _in_uploads(script)
            return uploads, uploads and filerules.is_double_extension_in_uploads(_probe(script))
        except rules.NOT_RULE_ERRORS:
            raise
        except Exception as error:
            self.rule_errors.setdefault(type(error), [0, self._number])[0] += 1
            return False, False


_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{0,31}://")


def redacted_uri(target: str) -> str:
    """``uri`` do raportu: query i fragment usunięte w całości strukturalnie (od pierwszego ``?`` albo ``#``), a nie
    wzorcem ``redact``, który zatrzymuje się na cudzysłowie, ``<`` albo ukośniku wstecznym; reszta po redakcji.

    W formie absolutnej (``http://użytkownik:hasło@host/…``) wszystko od ``://`` do ostatniego ``@`` przed ``?``/``#``
    zastępuje znacznik — także gdy hasło zawiera ``/`` i granica ``authority`` według RFC wypada wcześniej. Może to
    zamaskować ``@`` w ścieżce; w raporcie lepiej za dużo niż ujawnione hasło."""
    if (found := _SCHEME.match(target)) is not None:
        stop = min((at for at in (target.find("?"), target.find("#")) if at >= 0), default=len(target))
        at = target.rfind("@", found.end(), stop)
        if at >= 0:
            target = f"{target[:found.end()]}{redact.MARK}{target[at:]}"
    cut = min((at for at in (target.find("?"), target.find("#")) if at >= 0), default=len(target))
    tail = f"{target[cut]}{redact.MARK}" if cut < len(target) else ""
    return redact.excerpt(target[:cut], limit=MAX_URI_CHARS - len(tail)) + tail


def _probe(path: str) -> str:
    """Ścieżka do porównań z regułami: prefiks ``wp-content/uploads/`` bez względu na wielkość liter (serwer na systemie
    plików nierozróżniającym jej trafi w ten sam katalog); ``filerules`` porównuje rozszerzenia już bez niej."""
    head = path[:len(filerules.UPLOADS)]
    return filerules.UPLOADS + path[len(head):] if head.lower() == filerules.UPLOADS else path


def _script_path(path: str) -> str | None:
    """Plik kodu, który obsłuży żądanie: pierwszy segment z rozszerzeniem kodu (albo, w uploads, z podwójnym
    rozszerzeniem), reszta to ``PATH_INFO`` (``/uploads/x.php/a.jpg`` wykona ``x.php``). ``None``, gdy żaden segment nie
    wskazuje pliku kodu. Jedno przejście po segmentach; każdy jest sprawdzany jako nazwa, nie jako prefiks ścieżki (S-08)."""
    uploads = path[:len(filerules.UPLOADS)].lower() == filerules.UPLOADS
    offset = 0
    for name in path.split("/"):
        if "." in name and (filerules.is_code_name(name) or (
                uploads and offset >= len(filerules.UPLOADS) and filerules.has_code_part_before_suffix(name))):
            return path[:offset + len(name)]
        offset += len(name) + 1
    return None


def _mentions_code(text: str) -> bool:
    """Czy zdekodowany cel bez przypisanej ścieżki zawiera rozszerzenie kodu (``.php``, ``.phtml`` …)."""
    lower = text.lower()
    return any(suffix in lower for suffix in filerules.CODE_SUFFIXES)


def _in_uploads(path: str) -> bool:
    probe = _probe(path)
    return filerules.is_code_in_uploads(probe) or filerules.is_double_extension_in_uploads(probe)


@dataclass
class _Run:
    """Sumy przebiegu po plikach przeczytanych w całości (pierwsze miejsca jako ``plik:wiersz``)."""
    hashed: int = 0
    totals: Counter = field(default_factory=Counter)
    rejected: Counter = field(default_factory=Counter)
    first_rejected: dict[str, str] = field(default_factory=dict)
    first: dict[str, str] = field(default_factory=dict)  # lossy, unresolved_code
    first_untimed: str | None = None
    noted_files: list[str] = field(default_factory=list)
    unparsed_files: list[str] = field(default_factory=list)
    stopped: list[str] = field(default_factory=list)  # pliki przerwane limitem czasu: "plik (do wiersza N)"

    def add(self, rel: str, parser: LogFileParser) -> None:
        self.hashed += 1
        self.totals.update(lines=parser.lines, parsed=parser.parsed, lossy=parser.lossy, untimed=parser.untimed,
                           unresolved=parser.unresolved, unresolved_code=parser.unresolved_code,
                           lossy_paths=parser.lossy_paths, malformed=parser.malformed_forwarded, hits=parser.hits_seen)
        self.rejected.update(parser.rejected)
        for reason, number in parser.first_rejected.items():
            self.first_rejected.setdefault(reason, f"{rel}:{number}")
        for key, number in (("lossy", parser.first_lossy), ("unresolved_code", parser.first_unresolved_code)):
            if number is not None:
                self.first.setdefault(key, f"{rel}:{number}")
        self.first_untimed = self.first_untimed or parser.first_untimed
        if parser.lines and not parser.parsed:
            self.unparsed_files.append(rel)
        if parser.rejected:
            self.noted_files.append(f"{rel} ({sum(parser.rejected.values())}/{parser.lines})")
        if parser.stopped_at is not None:
            self.stopped.append(f"{redact.neutralise(rel)} przeanalizowany do wiersza {parser.stopped_at}")


def scan_logs(root: Path, session: ingest.Session, config: LogConfig | None = None, focus: Focus | None = None) -> LogScan:
    """Analizuje źródło ``logs`` (katalog albo plik). Plik, którego nie udało się przeczytać, nie wnosi wierszy.

    ``focus`` (``correlate.focus``) wybiera żądania trzymane dla korelacji; ``None`` trzyma każde żądanie do ścieżki
    kodu (do limitu). Reguła ``HTTP_EXECUTABLE_IN_UPLOADS`` nie zależy od ``focus`` ani od limitu żądań.
    """
    config = config or LogConfig()
    fmt = logformats.FORMATS[config.fmt]
    cover, detections, requests = SourceCoverage(), [], []
    budget, cap, parsers, run = _Budget(), _RuleCap(), {}, _Run()

    def open_parser(rel: str) -> Callable[[bytes], None]:
        parsers[rel] = LogFileParser(config, budget, focus=focus, cap=cap, expired=session.expired)
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
                cap.left += len(parser.hits)
            continue
        parser.close()
        for error, (count, line) in parser.rule_errors.items():
            rules.rule_failed(cover, "HTTP_EXECUTABLE_IN_UPLOADS", error, f"logs/{item.rel}:{line}", count)
        run.add(item.rel, parser)
        evidence_id = _evidence(item).id
        requests.extend(_observation(evidence_id, item.rel, held, fmt, config, "HTTP_REQUEST") for held in parser.held)
        for held, double in parser.hits:
            detections.append(Detection(
                "HTTP_EXECUTABLE_IN_UPLOADS", "high", "low" if double else "medium", "http_log",
                _EXPLANATION + (_DOUBLE_EXTENSION if double else ""),
                _observation(evidence_id, item.rel, held, fmt, config, "HTTP_REQUEST_FOR_PHP_IN_UPLOADS")))
    _summarise(cover, fmt, run, budget, len(detections), session.limits.max_seconds)
    return LogScan(detections, cover, requests)


def _observation(evidence_id: str, rel: str, held: _Held, fmt: str, config: LogConfig, kind: str) -> models.Observation:
    return models.Observation(
        evidence_id, kind, models.Location(path=rel, line=held.line),
        {"path": held.path, "uri": held.uri, "method": held.method, "status": held.status, "bytes": held.bytes,
         "client_ip": held.client_ip, "client_ip_basis": held.basis, "log_format": fmt, "timestamp_precision": held.precision,
         "clock_uncertainty_seconds": config.uncertainty},
        timestamp_raw=held.timestamp_raw, timestamp_utc=held.timestamp_utc, time_source=models.TimeSource.LOG)


def _listed(items: list[str]) -> str:
    return ", ".join(items[:MAX_FILE_NOTES]) + (", …" if len(items) > MAX_FILE_NOTES else "")


def _summarise(cover: SourceCoverage, fmt: str, run: _Run, budget: _Budget, reported: int, max_seconds: float) -> None:
    totals = run.totals
    lines, parsed = totals["lines"], totals["parsed"]
    if not run.hashed:
        cover.fail("Źródło logów nie zawiera żadnego odczytanego pliku: brak wierszy do analizy")
    elif lines and not parsed:
        cover.fail(f"Logi nie odpowiadają obsługiwanemu formatowi {fmt} (wybór --log-format): "
                   f"żaden z {lines} wierszy nie został sparsowany")
    elif not lines and not cover.partial and not run.stopped:
        cover.fail("Logi nie zawierają żadnego wiersza do analizy")
    if run.stopped:
        cover.degrade(f"Limit czasu analizy {max_seconds:g} s przekroczony w trakcie pliku logu: {_listed(run.stopped)}; "
                      "dalszych wierszy nie sprawdzono (skrót SHA-256 obejmuje cały plik)")
    if run.unparsed_files and parsed:
        cover.degrade(f"{len(run.unparsed_files)} plików logów bez żadnego wiersza w formacie {fmt}: {_listed(run.unparsed_files)}")
    if run.rejected and parsed:
        reasons = ", ".join(f"{logformats.REASONS[reason]} ×{number} (pierwszy: {run.first_rejected[reason]})"
                            for reason, number in sorted(run.rejected.items(), key=lambda pair: (-pair[1], pair[0])))
        share = 100 * (lines - parsed) / lines
        files = _listed(run.noted_files)
        cover.degrade(f"Nie sparsowano {lines - parsed}/{lines} wierszy logów ({share:.1f}%, format {fmt}): {reasons}"
                      + (f"; pliki: {files}" if files else ""))
    if totals["lossy"]:
        cover.degrade(f"{totals['lossy']} wierszy logów nie jest poprawnym UTF-8: zdekodowano je ze znakami zastępczymi, "
                      f"mogą być zniekształcone (pierwszy: {run.first['lossy']})")
    if totals["untimed"]:
        cover.note(f"Nie można znormalizować czasu logu do UTC w {totals['untimed']} wierszach (np. brak strefy); "
                   f"pierwszy zapis: {redact.neutralise(run.first_untimed or '')}")
    if totals["unresolved_code"]:
        cover.degrade(f"{totals['unresolved_code']} żądań wygląda na żądania plików kodu, ale ich ścieżki nie da się przypisać "
                      "do pliku (bajt NUL, zakodowany ukośnik %2F, \"..\" ponad katalogiem głównym, ścieżka dłuższa niż "
                      f"{logformats.MAX_PATH_CHARS} znaków albo cel inny niż ścieżka): reguła HTTP_EXECUTABLE_IN_UPLOADS "
                      f"i korelacja ich nie sprawdzają (pierwsze: {run.first['unresolved_code']})")
    if other := totals["unresolved"] - totals["unresolved_code"]:
        cover.note(f"{other} żądań ma ścieżkę, której nie da się przypisać do pliku (\"..\" ponad katalogiem głównym, "
                   "bajt NUL, zakodowany ukośnik %2F, cel inny niż ścieżka); cel nie wskazuje pliku kodu")
    if totals["lossy_paths"]:
        cover.note(f"{totals['lossy_paths']} żądań ma ścieżkę, której bajty po dekodowaniu nie są poprawnym UTF-8: zapisano ją "
                   "ze znakami zastępczymi, więc nie spotka się w korelacji z nazwą pliku z obrazu witryny")
    if totals["malformed"]:
        cover.note(f"{totals['malformed']} żądań przez zaufane proxy ma odrzucone forwarded_for (niepoprawny wpis albo "
                   f"dłuższe niż {logformats.MAX_FORWARDED_CHARS} znaków): "
                   "adresem klienta jest adres połączenia")
    if totals["hits"] > reported:
        cover.degrade(f"Limit {MAX_RULE_FINDINGS} wykryć reguły HTTP_EXECUTABLE_IN_UPLOADS wyczerpany: żądań do kodu w uploads "
                      f"było {totals['hits']}; pozostałe {totals['hits'] - reported} nie mają osobnych ustaleń")
    if budget.dropped:
        cover.degrade(f"Limit {MAX_REQUESTS} żądań do plików kodu albo {MAX_HELD_CHARS} znaków ich ścieżek i adresów "
                      f"przekroczony: pominięto {budget.dropped}; nie sprawdzono ich korelacją")
