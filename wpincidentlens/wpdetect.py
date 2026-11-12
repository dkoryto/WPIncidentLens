"""WPDetector: wersja, locale i prefiks tabel WordPressa jako kandydaci z poziomem pewności (ADR 0005 pkt 1).

Czyta wyłącznie bajty już przeczytane przez SecureIngest i nazwy plików; niczego nie wykonuje i nie interpretuje PHP
poza rozpoznaniem przypisania pojedynczego literału. Kandydat to wskazówka z pliku, który mógł zostać zmieniony:
nie powstaje z niego ustalenie i nie wpływa na ocenę. Z ``wp-config.php`` do raportu trafia tylko wartość prefiksu
i locale, sprawdzona ścisłym wzorcem; żadna inna treść tego pliku nie jest kopiowana ani cytowana.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import ingest, models
from .analysis import SourceCoverage, seen_in

VERSION_FILE = "wp-includes/version.php"
CONFIG_FILE = "wp-config.php"
MAX_PARSE_BYTES = 256 * 1024  # prawdziwe version.php i wp-config.php mają kilka KiB
MAX_LANGUAGE_FILES = 16

LOCALE_KIND = "WP_LOCALE_CANDIDATE"
_LOCALE = r"[A-Za-z]{2,3}(?:_[A-Za-z0-9]{2,8}){0,2}"  # pl_PL, de_DE_formal, pt_PT_ao90
_LANGUAGE_FILE = re.compile(rf"wp-content/languages/({_LOCALE})\.mo")
_PLAIN = re.compile(rb"[A-Za-z0-9_.+\-]*")

# Każda alternatywa zawsze się dopasowuje i zużywa znaki (niedomknięty napis lub komentarz sięga końca pliku),
# więc podział na tokeny jest liniowy także dla wrogiego wejścia.
_TOKEN = re.compile(rb"""
    (?P<skip> \s+ | //[^\n]* | \#[^\n]* | /\*.*?(?:\*/|\Z) )
  | (?P<text> '[^'\\]*(?:\\(?:.|\Z)[^'\\]*)*(?:'|\Z) | "[^"\\]*(?:\\(?:.|\Z)[^"\\]*)*(?:"|\Z) )
  | (?P<name> \$?[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]* )
  | (?P<number> [0-9]+ )
  | (?P<other> . )
""", re.DOTALL | re.VERBOSE)


@dataclass(frozen=True)
class _Setting:
    """Jedno przypisanie literału: ``head`` to tokeny przed wartością, ``end`` — token zaraz po niej."""
    kind: str
    origin: str
    name: str                # nazwa w komunikatach
    marker: bytes            # token, którego każde wystąpienie liczy się jako użycie ustawienia
    head: tuple[bytes, ...]
    end: bytes
    pattern: re.Pattern[bytes]
    unknown: str | None = None  # początek noty, gdy wartości nie da się ustalić; None — brak nie jest notowany osobno


def _variable(kind: str, origin: str, name: str, pattern: str, unknown: str | None = None) -> _Setting:
    return _Setting(kind, origin, name, name.encode(), (name.encode(), b"="), b";", re.compile(pattern.encode()), unknown)


_SETTINGS: dict[str, tuple[_Setting, ...]] = {
    VERSION_FILE: (
        _variable("WP_VERSION_CANDIDATE", "WP_VERSION_ASSIGNMENT", "$wp_version", r"[0-9][0-9A-Za-z.+\-]{0,31}",
                  "wersja WordPressa nieustalona"),
        _variable("WP_DB_VERSION_CANDIDATE", "WP_DB_VERSION_ASSIGNMENT", "$wp_db_version", r"[0-9]{1,10}"),
        _variable(LOCALE_KIND, "WP_LOCAL_PACKAGE_ASSIGNMENT", "$wp_local_package", _LOCALE),
    ),
    CONFIG_FILE: (
        _variable("WP_TABLE_PREFIX_CANDIDATE", "TABLE_PREFIX_ASSIGNMENT", "$table_prefix", r"[A-Za-z0-9_]{1,64}",
                  "prefiks tabel nieustalony"),
        _Setting(LOCALE_KIND, "WPLANG_DEFINE", "define('WPLANG')", b"'WPLANG'", (b"define", b"(", b"'WPLANG'", b","), b")",
                 re.compile(_LOCALE.encode())),
    ),
}


@dataclass
class _Candidate:
    item: ingest.Evidence
    kind: str
    origin: str
    value: str
    confidence: str
    basis: str


def _tokens(content: bytes) -> list[bytes]:
    """Tokeny kodu bez odstępów i komentarzy; napis w cudzysłowach bez znaków specjalnych ma postać ``'...'``."""
    tokens = []
    for match in _TOKEN.finditer(content):
        if match.lastgroup == "skip":
            continue
        token = match.group()
        if token[:1] == b'"' and token[-1:] == b'"' and len(token) > 1 and _PLAIN.fullmatch(token, 1, len(token) - 1):
            token = b"'" + token[1:-1] + b"'"
        tokens.append(token)
    return tokens


def _literals(tokens: list[bytes], setting: _Setting) -> tuple[list[bytes], int]:
    """Wartości przypisań pojedynczego literału oraz liczba pozostałych użyć (odczyt, wyrażenie, konkatenacja)."""
    literals, other = [], 0
    offset, size = setting.head.index(setting.marker), len(setting.head)
    for index, token in enumerate(tokens):
        if token != setting.marker:
            continue
        start = index - offset
        value, end = (tokens[start + size:start + size + 2] + [b"", b""])[:2]
        quoted = len(value) > 1 and value[:1] == value[-1:] == b"'"
        if start >= 0 and tuple(tokens[start:start + size]) == setting.head and end == setting.end and (quoted or value.isdigit()):
            literals.append(value[1:-1] if quoted else value)
        else:
            other += 1
    return literals, other


class WPDetector:
    """Zbiera kandydatów podczas przejścia drzewa plików; ``finish`` oddaje obserwacje i zapisuje, czego nie ustalono."""

    def __init__(self, baseline: dict | None) -> None:
        self._ref: dict[str, str] = (baseline or {}).get("files", {})
        self._fed: set[str] = set()
        self._found: list[_Candidate] = []
        self._notes: list[str] = []
        self._language_files = 0
        self._any_read = False

    def feed(self, item: ingest.Evidence) -> None:
        """Przyjmuje każdy wpis drzewa, także pominięty: nieodczytany plik to nota, nie zgadywanie."""
        self._any_read = self._any_read or item.sha256 is not None
        settings = _SETTINGS.get(item.rel)
        if settings is None:
            if item.sha256 is not None and (named := _LANGUAGE_FILE.fullmatch(item.rel)):
                self._language_files += 1
                if self._language_files <= MAX_LANGUAGE_FILES:
                    self._found.append(_Candidate(item, LOCALE_KIND, "LANGUAGE_FILE_NAME", named.group(1), "low",
                                                  "sama nazwa pliku językowego; zainstalowany język nie musi być używany"))
            return
        self._fed.add(item.rel)
        if item.sha256 is None:
            unusable = f"plik {item.rel} nieodczytany ({item.status})"
        elif item.content is None or len(item.content) > MAX_PARSE_BYTES:
            unusable = f"plik {item.rel} ma {item.size} B, więcej niż limit analizy ({MAX_PARSE_BYTES} B)"
        else:
            tokens = _tokens(item.content)
            for setting in settings:
                self._read(item, setting, tokens)
            return
        self._notes.extend(f"{setting.unknown}: {unusable}" for setting in settings if setting.unknown)

    def _read(self, item: ingest.Evidence, setting: _Setting, tokens: list[bytes]) -> None:
        literals, other = _literals(tokens, setting)
        uses = len(literals) + other
        values = sorted({value.decode("ascii") for value in literals if setting.pattern.fullmatch(value)})
        if not values:
            if setting.unknown:  # wartości spoza wzorca nie cytujemy: to nieufne bajty
                reason = (f"{setting.name} w {item.rel} nie jest przypisaniem pojedynczego literału o dozwolonej postaci"
                          if uses else f"brak przypisania {setting.name} w {item.rel}")
                self._notes.append(f"{setting.unknown}: {reason}")
            return
        confidence, basis = self._reference(item)
        if uses > 1:
            confidence, basis = "low", f"{basis}; {setting.name} występuje w pliku {uses} razy"
            self._notes.append(f"{setting.name} w {item.rel} niejednoznaczne: {uses} wystąpień, "
                               f"kandydaci ({len(values)}) mają niską pewność")
        if setting.kind == LOCALE_KIND and confidence == "high":
            confidence = "medium"  # język witryny od WordPressa 4.0 jest opcją w bazie; plik podaje tylko wskazówkę
        self._found.extend(_Candidate(item, setting.kind, setting.origin, value, confidence, basis) for value in values)

    def _reference(self, item: ingest.Evidence) -> tuple[str, str]:
        expected = self._ref.get(item.rel)
        if expected is None:
            return "medium", "brak zaufanej referencji dla pliku; wartość jest wskazówką"
        if expected == item.sha256:
            return "high", "plik zgodny z baseline"
        return "low", "plik różni się od baseline; wartość jest tylko wskazówką"

    def finish(self, cover: SourceCoverage) -> list[models.Observation]:
        """Kandydaci jako obserwacje; wszystko, czego nie ustalono albo co jest niejednoznaczne, trafia do jednej noty pokrycia."""
        notes = list(self._notes)
        for rel, settings in _SETTINGS.items():
            if rel not in self._fed:
                notes.extend(f"{setting.unknown}: brak pliku {rel}" for setting in settings if setting.unknown)
        locales = [found for found in self._found if found.kind == LOCALE_KIND]
        distinct = len({found.value for found in locales})
        if not locales:
            notes.append("locale nieustalone: brak jednoznacznego źródła w plikach (ustawienie może być zapisane tylko w bazie)")
        elif distinct > 1:
            for found in locales:
                found.confidence, found.basis = "low", f"{found.basis}; źródła wskazują różne locale"
            notes.append(f"locale niejednoznaczne: {distinct} różnych kandydatów z plików, żaden nie został wybrany")
        if self._language_files > MAX_LANGUAGE_FILES:
            notes.append(f"uwzględniono {MAX_LANGUAGE_FILES} z {self._language_files} plików językowych")
        if notes and self._any_read:  # gdy nie odczytano niczego, przyczynę podaje status źródła, nie detektor
            cover.note("WPDetector: " + "; ".join(sorted(notes)))
        return [seen_in(found.item, found.kind, value=found.value, confidence=found.confidence, origin=found.origin,
                        basis=found.basis) for found in self._found]
