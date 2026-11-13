"""Opcjonalny adapter YARA-X (ADR 0010, T-202): lokalny, wersjonowany pakiet reguł operatora; domyślnie wyłączony.

Granice:

- reguły YARA dostają wyłącznie bajty przeczytane przez SecureIngest — tę samą treść co reguły treści wbudowane
  (``item.content``: pliki kodu i konfiguracji nie większe niż limit skanu); adapter niczego sam nie otwiera
  poza pakietem reguł, który czyta osobna sesja SecureIngest;
- YARA-X to kod natywny, który parsuje dane atakującego, więc działa **w osobnym procesie** (``worker_main``) z limitami
  ``setrlimit`` (CPU, pamięć danych, zakaz zapisu plików i zrzutu pamięci) i limitem czasu na plik po obu stronach:
  ``Scanner.set_timeout`` w procesie potomnym i nadzór rodzica, który zabija proces, gdy odpowiedź nie nadejdzie;
- moduł ``yara_x`` importuje wyłącznie proces potomny, w funkcji ``_engine``; proces analizy go nie ładuje;
- to jedyny moduł silnika, który uruchamia proces (``subprocess``, wyjątek od S-17 opisany w ADR 0010): zawsze ten sam
  interpreter z tą samą, stałą listą argumentów, bez powłoki, bez wartości z materiału dowodowego i z pustym środowiskiem;
- odpowiedź procesu potomnego jest nieufna: rodzic sprawdza nazwę reguły, offset, długość i liczbę trafień względem
  długości pliku, a do raportu trafia tylko identyfikator reguły, wersja pakietu, offset, długość i liczba trafień —
  nigdy dopasowane bajty;
- brak YARA-X, nieczytelny pakiet, zawieszenie albo awaria procesu to luka pokrycia ``files``, nigdy „czysto”;
  błąd kompilacji pakietu to błąd wywołania (``PackError``, kod wyjścia 2).
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import subprocess
import queue
import sys
import threading
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from . import ingest, redact
from .analysis import Detection, SourceCoverage, seen_in

RULE_ID = "YARA_MATCH"
KIND = "YARA_RULE_MATCH"
CONFIDENCES = ("low", "medium")  # ``confidence`` z meta reguły; inna wartość albo jej brak → ``low``
RULE_SUFFIXES = (".yar", ".yara")
VERSION_FILE = "VERSION"  # opcjonalna wersja deklarowana w katalogu pakietu (jeden wiersz)
INSTALL_HINT = "pip install --require-hashes -r requirements/yara.lock"

MAX_PACK_FILES = 256
MAX_PACK_FILE_BYTES = 1024 * 1024
MAX_PACK_BYTES = 8 * 1024 * 1024
FILE_TIMEOUT_SECONDS = 10  # domyślny limit skanu jednego pliku (``--yara-timeout``)
GRACE_SECONDS = 5          # zapas rodzica ponad limit YARA-X, zanim uzna proces za zawieszony
START_TIMEOUT_SECONDS = 60  # uruchomienie procesu i kompilacja pakietu
MEMORY_LIMIT_BYTES = 2 * 1024**3  # RLIMIT_DATA procesu potomnego
CPU_SLACK_SECONDS = 60
MAX_MATCHES_PER_PATTERN = 1000
MAX_RULES_PER_FILE = 50    # proces potomny odsyła najwyżej tyle reguł na plik i łączną liczbę; nadmiar → luka
MAX_FAILURES = 3           # tyle kolejnych awarii procesu (bez udanej odpowiedzi pomiędzy) wyłącza YARA do końca przebiegu
MAX_REPLY_BYTES = 16 * 1024 * 1024  # wiersz odpowiedzi; największy to lista nazw reguł (pakiet ≤ 8 MiB)
MAX_OPEN_FILES = 64        # RLIMIT_NOFILE procesu potomnego
MAX_COMPILE_MESSAGE = 2000
EXAMPLES = 3               # ile ścieżek pliku wymienia luka

RULE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_DECLARED = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
_FRAME = struct.Struct(">QQ")  # numer żądania, długość treści
# Proces potomny: izolowany interpreter (-I: bez PYTHON*, katalogu bieżącego i site użytkownika), pakiet z jawnej ścieżki.
_BOOTSTRAP = "import sys; sys.path.insert(0, sys.argv[1]); from wpincidentlens.yarax import worker_main; worker_main()"


class PackError(ValueError):
    """Pakiet reguł się nie kompiluje: błąd wywołania (kod wyjścia 2), nie luka pokrycia."""


# --- pakiet reguł ------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Pack:
    """Pakiet reguł wczytany przez SecureIngest. ``problem`` ustawiony: pakietu nie da się użyć (luka pokrycia)."""
    name: str | None
    sources: tuple[tuple[str, str], ...] = ()  # (ścieżka względna, tekst reguł), posortowane
    sha256: str | None = None
    declared_version: str | None = None
    problem: str | None = None


def _is_pack_file(rel: str) -> bool:
    return rel.lower().endswith(RULE_SUFFIXES) or rel == VERSION_FILE


def _digest(sources: tuple[tuple[str, str], ...], declared: str | None) -> str:
    """SHA-256 wersji pakietu: posortowane ścieżki i skróty treści plików reguł oraz wersja deklarowana."""
    document = {"declared_version": declared,
                "files": [[rel, hashlib.sha256(text.encode("utf-8")).hexdigest()] for rel, text in sources]}
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def load_pack(path: Path) -> Pack:
    """Czyta pakiet (plik ``*.yar``/``*.yara`` albo katalog takich plików z opcjonalnym ``VERSION``) osobną sesją
    SecureIngest: bez podążania za dowiązaniami, z limitami liczby i rozmiaru plików. Każdy wpis, którego nie
    przeczytano, unieważnia cały pakiet — częściowy zestaw reguł po cichu zawęziłby analizę."""
    name = path.name or None
    limits = ingest.Limits(max_files=MAX_PACK_FILES, max_entries=4 * MAX_PACK_FILES, max_file_bytes=MAX_PACK_FILE_BYTES,
                           max_total_bytes=MAX_PACK_BYTES, max_scan_bytes=MAX_PACK_FILE_BYTES, max_depth=8, max_seconds=60)
    session = ingest.Session(limits, reverify=False)
    texts: dict[str, str] = {}
    with closing(session.read(path, "yara_rules", wanted=_is_pack_file, keep_limit=MAX_PACK_FILE_BYTES)) as entries:
        problem = _collect(entries, texts)
    if problem is not None:
        return Pack(name, problem=problem)
    declared = texts.pop(VERSION_FILE, "").strip() or None
    if declared is not None and _DECLARED.fullmatch(declared) is None:
        return Pack(name, problem=f"plik {VERSION_FILE} pakietu reguł ma niedozwoloną postać")
    if not texts:
        return Pack(name, problem=f"pakiet reguł nie zawiera plików {'/'.join(RULE_SUFFIXES)}")
    sources = tuple(sorted(texts.items()))
    return Pack(name, sources, _digest(sources, declared), declared)


def _collect(entries, texts: dict[str, str]) -> str | None:
    """Teksty plików pakietu do ``texts``; zwraca opis problemu, gdy któregoś wpisu nie da się użyć."""
    for item in entries:
        if item.status is not ingest.ReadStatus.READ:  # także katalog: nieodczytany mógłby ukrywać pliki reguł
            where = "" if item.rel == ingest.ROOT else f" {redact.neutralise(item.rel)[:200]}"
            return f"wpis pakietu reguł{where} nieodczytany ({item.status}, {item.reason})"
        if item.content is None:  # plik bez rozszerzenia reguł
            continue
        try:
            texts[item.rel] = item.content.decode("utf-8")
        except UnicodeDecodeError:
            return f"plik pakietu reguł {redact.neutralise(item.rel)[:200]} nie jest poprawnym UTF-8"
    return None


# --- proces potomny (natywny YARA-X) -----------------------------------------------------------------

def _engine():
    """Jedyny import zależności spoza biblioteki standardowej (extra ``yara``); wołany tylko w procesie potomnym."""
    try:
        import yara_x
    except ImportError:
        return None
    return yara_x


def _confine(**limits: int) -> dict[str, bool]:
    """Limity procesu potomnego (nazwa ``RLIMIT_*`` → wartość); zwraca, które udało się ustawić (np. macOS odrzuca
    RLIMIT_DATA)."""
    import resource

    applied = {}
    for name, value in limits.items():
        try:
            limit = getattr(resource, name)
            _, hard = resource.getrlimit(limit)
            value = value if hard == resource.RLIM_INFINITY else min(value, hard)
            resource.setrlimit(limit, (value, value))
            applied[name] = True
        except (AttributeError, ValueError, OSError):
            applied[name] = False
    return applied


def _read_exact(stream, size: int) -> bytes | None:
    chunks, left = [], size
    while left:
        chunk = stream.read(left)
        if not chunk:
            return None
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def _read_frame(stream) -> tuple[int, bytes] | None:
    header = _read_exact(stream, _FRAME.size)
    if header is None:
        return None
    number, size = _FRAME.unpack(header)
    data = _read_exact(stream, size)
    return None if data is None else (number, data)


def _summary(rule) -> dict:
    """Trafienie jednej reguły bez dopasowanych bajtów: nazwa, pewność z meta, pierwszy zakres i liczba trafień."""
    spans = [(match.offset, match.length) for pattern in rule.patterns for match in pattern.matches]
    confidence = dict(rule.metadata).get("confidence")
    first = min(spans) if spans else None
    return {"rule": rule.identifier, "confidence": confidence if confidence in CONFIDENCES else None,
            "offset": first[0] if first else None, "length": first[1] if first else None, "count": len(spans)}


def worker_main() -> None:
    """Proces potomny: pierwsza ramka to konfiguracja (źródła reguł, limity), kolejne to treść plików do skanu.
    Odpowiedź na każdą ramkę to jeden wiersz JSON na stdout (komunikaty modułu ``console`` YARA-X są odrzucane)."""
    source, out = sys.stdin.buffer, sys.stdout.buffer

    def reply(number: int, message: dict) -> None:
        out.write(json.dumps({"seq": number, **message}, separators=(",", ":")).encode("utf-8") + b"\n")
        out.flush()

    frame = _read_frame(source)
    if frame is None:
        return
    number, raw = frame
    config = json.loads(raw)
    limits = _confine(RLIMIT_CPU=config["cpu_seconds"], RLIMIT_DATA=config["memory_bytes"], RLIMIT_FSIZE=0, RLIMIT_CORE=0,
                      RLIMIT_NOFILE=MAX_OPEN_FILES)
    yara_x = _engine()
    if yara_x is None:
        reply(number, {"unavailable": "not-installed"})
        return
    try:
        compiler = yara_x.Compiler()
        compiler.enable_includes(False)  # include czytałby pliki z pominięciem SecureIngest
        for rel, text in config["sources"]:
            compiler.add_source(text, origin=rel)
        rules = compiler.build()
    except yara_x.CompileError as error:
        reply(number, {"compile_error": str(error)[:MAX_COMPILE_MESSAGE]})
        return
    names = [rule.identifier for rule in rules]
    if bad := [name for name in names if RULE_NAME.fullmatch(name) is None]:
        reply(number, {"compile_error": f"nazwa reguły spoza wzorca {RULE_NAME.pattern} (najwyżej 128 znaków): {bad[0][:200]}"})
        return
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(config["timeout"])
    scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN)
    scanner.console_log(lambda _message: None)
    scanner.scan(b"")  # rozgrzewka: wątek zegara limitu czasu YARA-X powstaje przed zakazem tworzenia procesów
    limits.update(_confine(RLIMIT_NPROC=0))
    from importlib.metadata import version
    reply(number, {"ready": True, "engine": version("yara-x"), "rules": names, "limits": limits})
    while (frame := _read_frame(source)) is not None:
        number, data = frame
        try:
            results = scanner.scan(data)
        except yara_x.TimeoutError:
            reply(number, {"timeout": True})
            continue
        except Exception as error:  # błąd skanu jednego pliku nie kończy procesu
            reply(number, {"scan_error": type(error).__name__})
            continue
        matching = results.matching_rules
        reply(number, {"total": len(matching), "matches": [_summary(rule) for rule in matching[:MAX_RULES_PER_FILE]]})


def worker_argv() -> list[str]:
    """Polecenie procesu potomnego (testy podmieniają je na atrapę bez YARA-X)."""
    return [sys.executable, "-I", "-c", _BOOTSTRAP, str(Path(__file__).absolute().parents[1])]


class _Worker:
    """Rodzic: ramki do procesu potomnego i wiersze JSON z powrotem. Zapis i odczyt potoku działają w wątkach, więc
    rodzic czeka na odpowiedź z terminem; po jego upływie zabija proces, co odblokowuje oba wątki. Odpowiedź musi nieść
    numer żądania, a po niej nie może czekać żadna inna: nadmiarowe wiersze to naruszenie protokołu (``PROTOCOL``)."""

    PROTOCOL = {"protocol_error": True}

    def __init__(self) -> None:
        self.process = subprocess.Popen(worker_argv(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        env={}, cwd="/", close_fds=True, start_new_session=True)
        self._replies: queue.Queue[dict | None] = queue.Queue(maxsize=2)
        self._overflow = False
        self._number = 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        """Wiersz odpowiedzi najwyżej ``MAX_REPLY_BYTES``; dłuższy, niepoprawny, koniec strumienia albo więcej niż dwie
        nieodebrane odpowiedzi kończą odczyt, a rodzic dostaje ``None``."""
        try:
            while line := self.process.stdout.readline(MAX_REPLY_BYTES + 1):
                message = json.loads(line) if line.endswith(b"\n") else None
                if not isinstance(message, dict):
                    break
                self._replies.put_nowait(message)
        except queue.Full:
            self._overflow = True
        except Exception:  # każdy błąd odczytu, także RecursionError z json, to koniec strumienia
            pass
        finally:
            try:
                self._replies.put_nowait(None)
            except queue.Full:
                self._overflow = True

    def _write(self, frame: bytes) -> None:
        try:
            self.process.stdin.write(frame)
            self.process.stdin.flush()
        except (OSError, ValueError):  # proces zakończony (BrokenPipeError) albo potok zamknięty
            pass

    def healthy(self) -> bool:
        """Proces żyje i nie wysłał niczego bez żądania."""
        return self.process.poll() is None and self._replies.empty() and not self._overflow

    def request(self, data: bytes, seconds: float) -> dict | None:
        """Wysyła ramkę i czeka na odpowiedź najwyżej ``seconds``; ``None``: brak odpowiedzi albo koniec strumienia,
        ``PROTOCOL``: odpowiedź z innym numerem żądania albo nadmiarowe wiersze."""
        number = self._number = self._number + 1
        threading.Thread(target=self._write, args=(_FRAME.pack(number, len(data)) + data,), daemon=True).start()
        try:
            reply = self._replies.get(timeout=seconds)
        except queue.Empty:
            return None
        if reply is None:
            return None
        if reply.get("seq") != number or self._overflow or not self._replies.empty():
            return self.PROTOCOL
        return reply

    def close(self, kill: bool = False) -> None:
        if kill:
            self.process.kill()
        try:
            self.process.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process.stdout.close()


# --- adapter -----------------------------------------------------------------------------------------

def _count(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _paths(paths: list[str]) -> str:
    shown = ", ".join(paths[:EXAMPLES])
    return f"{len(paths)} (np. {shown})" if len(paths) > EXAMPLES else str(len(paths)) + f" ({shown})"


class Adapter:
    """Jeden przebieg: proces potomny z pakietem skompilowanym raz, ``scan`` na plik, ``finish`` dopisuje pokrycie."""

    def __init__(self, pack: Pack, file_timeout: int = FILE_TIMEOUT_SECONDS, cpu_seconds: int = 3600) -> None:
        self.pack = pack
        self.file_timeout = file_timeout
        self.cpu_seconds = cpu_seconds
        self.problem = pack.problem
        self.engine: str | None = None
        self.rule_count: int | None = None
        self.memory_limited = True
        self.scanned = 0
        self.timed_out: list[str] = []
        self.failed: list[str] = []
        self.lost: list[str] = []         # proces zawieszony, zakończony albo łamiący protokół w trakcie pliku
        self.rejected: list[str] = []     # odpowiedź z wpisami spoza pakietu albo spoza treści pliku
        self.unscanned: list[str] = []    # proces wyłączony po MAX_FAILURES kolejnych awariach
        self.expired = 0                  # pliki pominięte po upływie limitu czasu sesji
        self.truncated: list[str] = []
        self.restarts = 0                 # wszystkie ponowne uruchomienia procesu w przebiegu
        self.failures = 0                 # kolejne awarie bez poprawnej odpowiedzi pomiędzy
        self._worker: _Worker | None = None
        self._names: frozenset[str] = frozenset()

    # -- cykl życia procesu

    def start(self) -> Adapter:
        """Uruchamia proces i kompiluje pakiet. ``PackError`` przy błędzie kompilacji; inne problemy → ``problem``."""
        if self.problem is None:
            self._spawn()
        return self

    def _spawn(self) -> bool:
        config = json.dumps({"sources": self.pack.sources, "timeout": self.file_timeout, "cpu_seconds": self.cpu_seconds,
                             "memory_bytes": MEMORY_LIMIT_BYTES}).encode("utf-8")
        try:
            worker = _Worker()
        except OSError as error:
            self.problem = f"procesu YARA-X nie da się uruchomić ({type(error).__name__})"
            return False
        hello = worker.request(config, START_TIMEOUT_SECONDS)
        names = hello.get("rules") if hello is not None and hello.get("ready") is True else None
        if isinstance(names, list) and all(isinstance(name, str) and RULE_NAME.fullmatch(name) for name in names):
            self._worker = worker
            engine = hello.get("engine")
            self.engine = engine if isinstance(engine, str) and _DECLARED.fullmatch(engine) else "?"
            self._names, self.rule_count = frozenset(names), len(names)
            limits = hello.get("limits")
            self.memory_limited = isinstance(limits, dict) and limits.get("RLIMIT_DATA") is True
            return True
        worker.close(kill=True)
        self.failures = MAX_FAILURES + 1  # po nieudanym uruchomieniu kolejne pliki nie próbują od nowa
        if hello is not None and "compile_error" in hello:
            raise PackError(redact.neutralise(str(hello["compile_error"]))[:MAX_COMPILE_MESSAGE])
        if hello is not None and hello.get("unavailable") == "not-installed":
            self.problem = f"moduł YARA-X (yara-x) nie jest zainstalowany; instalacja: {INSTALL_HINT}"
        else:
            self.problem = "proces YARA-X nie zgłosił gotowości (awaria albo limit czasu uruchomienia)"
        return False

    def _drop(self) -> None:
        if self._worker is not None:
            self._worker.close(kill=True)
            self._worker = None
        self.restarts += 1
        self.failures += 1

    def close(self) -> None:
        if self._worker is not None:
            self._worker.close()
            self._worker = None

    # -- skan

    def scan(self, item: ingest.Evidence, expired: Callable[[], bool]) -> list[Detection]:
        """Wykrycia YARA dla treści jednego pliku (tej samej, którą dostają reguły treści wbudowane)."""
        if item.content is None:
            return []
        where = redact.neutralise(item.rel)[:200]
        if self.pack.problem is not None or self.engine is None:
            return []  # pakiet albo silnik niedostępny od początku: jedna luka w ``finish``
        if expired():
            self.expired += 1
            return []
        if self._worker is not None and not self._worker.healthy():  # zakończony albo nadawał bez żądania
            self._drop()
        if self._worker is None and (self.failures > MAX_FAILURES or not self._spawn()):
            self.unscanned.append(where)
            return []
        reply = self._worker.request(item.content, self.file_timeout + GRACE_SECONDS)
        if reply is None or reply is _Worker.PROTOCOL:
            self.lost.append(where)
            self._drop()
            return []
        total, matches = reply.get("total"), reply.get("matches")
        if reply.get("timeout") is True:
            self.timed_out.append(where)
            found = []
        elif "scan_error" in reply:  # wyjątek YARA-X przy tym pliku; proces działa dalej
            self.failed.append(where)
            found = []
        elif (isinstance(matches, list) and len(matches) <= MAX_RULES_PER_FILE and all(isinstance(match, dict) for match in matches)
              and _count(total) is not None and total >= len(matches)):
            found = [self._detection(item, match) for match in matches]
            if None in found:  # wpisy spoza pakietu albo spoza treści odrzucone; pozostałe zostają
                self.rejected.append(where)
                found = [detection for detection in found if detection is not None]
            if total > len(matches):
                self.truncated.append(where)
            self.scanned += 1
        else:  # odpowiedź niezgodna z protokołem: proces potomny nie jest wiarygodny
            self.lost.append(where)
            self._drop()
            return []
        self.failures = 0
        return found

    def _detection(self, item: ingest.Evidence, match: dict) -> Detection | None:
        name, count = match.get("rule"), _count(match.get("count"))
        offset, length = match.get("offset"), match.get("length")
        if not isinstance(name, str) or name not in self._names or count is None:
            return None
        if (offset, length) == (None, None):
            if count:
                return None
            span = {}
        else:
            offset, length = _count(offset), _count(length)
            if offset is None or length is None or offset + length > len(item.content) or not count:
                return None
            span = {"offset": offset, "length": length}
        confidence = match.get("confidence") if match.get("confidence") in CONFIDENCES else "low"
        facts = {"yara_rule": name, "pack_sha256": self.pack.sha256, **span, "match_count": count}
        if self.pack.declared_version is not None:
            facts["pack_version"] = self.pack.declared_version
        explanation = (f"Reguła YARA {name} z pakietu operatora pasuje do treści pliku; to sygnatura spoza wbudowanego "
                       "zestawu reguł, nie dowód — wymaga ręcznej weryfikacji.")
        return Detection("YARA_MATCH", "medium", confidence, "file", explanation, seen_in(item, KIND, **facts))

    # -- pokrycie i opis

    def finish(self, cover: SourceCoverage, scan_limit: int) -> None:
        """Pokrycie ``files``: nota o zakresie skanu YARA albo luki, gdy którykolwiek plik nie przeszedł przez reguły."""
        fix = "brak trafień YARA nie oznacza czystości"
        if self.problem is not None and self.engine is None:
            cover.degrade(f"YARA-X: {self.problem}; reguły pakietu nie zostały zastosowane ({fix})")
            return
        declared = f"wersja deklarowana {self.pack.declared_version}" if self.pack.declared_version else "bez wersji deklarowanej"
        cover.note(f"YARA-X {self.engine}: pakiet {redact.neutralise(self.pack.name or '?')[:80]} ({declared}; skrót w case.json, "
                   f"pole yara.pack_sha256), reguł: {self.rule_count}; przeskanowano {self.scanned} plików — wyłącznie treść "
                   f"plików kodu i konfiguracji analizowaną przez reguły wbudowane (do {scan_limit} B); inne pliki nie przeszły przez YARA")
        if not self.memory_limited:
            cover.note("YARA-X: limit pamięci procesu skanującego (RLIMIT_DATA) niedostępny na tej platformie; obowiązują "
                       "limit czasu na plik i limity kontenera")
        for paths, what in ((self.timed_out, f"limit czasu skanu {self.file_timeout} s na plik przekroczony"),
                            (self.lost, "proces skanujący zawieszony, zakończony albo łamiący protokół w trakcie pliku (uruchomiony ponownie)"),
                            (self.failed, "błąd skanu YARA-X"),
                            (self.rejected, "trafienia spoza pakietu albo spoza treści pliku odrzucone"),
                            (self.unscanned, f"proces skanujący wyłączony po {MAX_FAILURES} kolejnych awariach; pliki bez skanu"),
                            (self.truncated, f"ponad {MAX_RULES_PER_FILE} pasujących reguł w pliku; pozostałe pominięte")):
            if paths:
                cover.degrade(f"YARA-X: {what}: {_paths(paths)}; {fix}")
        if self.expired:
            cover.degrade(f"YARA-X: limit czasu analizy przekroczony; {self.expired} plików bez skanu YARA ({fix})")

    def describe(self) -> dict:
        """Pole ``yara`` w ``case.json``: pakiet i silnik użyte w przebiegu (bez ścieżki hosta)."""
        return {"provided": True, "name": self.pack.name, "applied": self.engine is not None and self.pack.problem is None,
                "pack_sha256": self.pack.sha256, "pack_version": self.pack.declared_version,
                "engine": None if self.engine is None else f"yara-x {self.engine}", "rules": self.rule_count,
                "file_timeout_seconds": self.file_timeout}


def open_adapter(path: Path, file_timeout: int = FILE_TIMEOUT_SECONDS, max_seconds: float = 3600) -> Adapter:
    """Wczytuje pakiet i uruchamia proces skanujący; ``PackError`` przy błędzie kompilacji pakietu."""
    return Adapter(load_pack(path), file_timeout, math.ceil(max_seconds) + CPU_SLACK_SECONDS).start()
