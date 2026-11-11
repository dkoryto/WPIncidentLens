"""Kontrakty danych raportu ``poc-1`` (ADR 0002 D2/D5, ADR 0003): fakty (Observation) oddzielone od oceny (Finding).

Moduł niczego nie czyta ani nie zapisuje. Każdy obiekt sprawdza własne pola przy tworzeniu, a ``Report``
dodatkowo spójność całości: unikalność identyfikatorów, istnienie wskazywanych dowodów i obserwacji oraz
zgodność ``assessment`` z regułą ``assess``. Błąd to zawsze ``ModelError`` z nazwą pola.

Identyfikator jest skrótem treści, więc ten sam materiał daje te same identyfikatory w każdym uruchomieniu.
Opublikowany JSON Schema (``docs/schema/report-poc-1.schema.json``) opisuje tylko kształt; referencji
i reguły oceny pilnuje ten moduł.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from .ingest import ReadStatus

SCHEMA_VERSION = "poc-1"
MIGRATED_FROM = ("0.1.0",)
SOURCES = ("files", "database", "logs", "baseline")
CRITICAL_SOURCES = ("files", "database", "logs")  # bez każdego z nich brak ustaleń nie może znaczyć „brak wskaźników”
UNKNOWN_LEGACY = "UNKNOWN_LEGACY"  # wyłącznie w raportach przeniesionych z 0.1.0: stary raport tej informacji nie niósł
READ_STATUSES = (*(str(status) for status in ReadStatus), UNKNOWN_LEGACY)
HASHED_STATUSES = (str(ReadStatus.READ), str(ReadStatus.CHANGED))  # tylko przy nich bajty przeczytano i istnieje skrót

_ID_HEX = 32  # 128 bitów skrótu SHA-256; kolizja identyfikatorów kończy się błędem walidacji, nie cichym scaleniem
_SHA256 = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[A-Z][A-Z0-9_]*")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|\+00:00)")
_SCALARS = (str, int, bool, type(None))


class ModelError(ValueError):
    """Dane nie spełniają kontraktu ``poc-1``."""


class Assessment(StrEnum):
    STRONG_INDICATORS = "STRONG_INDICATORS"
    SUSPICIOUS = "SUSPICIOUS"
    NO_INDICATORS_IN_ANALYZED_SCOPE = "NO_INDICATORS_IN_ANALYZED_SCOPE"
    INCONCLUSIVE = "INCONCLUSIVE"


class Severity(StrEnum):
    """Potencjalny skutek faktu; nie prawdopodobieństwo ataku."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """Siła dowodów stojących za ustaleniem; niezależna od wagi."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CoverageStatus(StrEnum):
    ANALYZED = "ANALYZED"
    PARTIAL = "PARTIAL"
    NOT_PROVIDED = "NOT_PROVIDED"
    FAILED = "FAILED"
    UNKNOWN_LEGACY = UNKNOWN_LEGACY


class OriginKind(StrEnum):
    FILE = "file"
    SQL_DUMP = "sql_dump"
    LOG = "log"
    BASELINE = "baseline"


class Category(StrEnum):
    FILE = "file"
    DATABASE = "database"
    HTTP_LOG = "http_log"
    CORRELATION = "correlation"


class TimeSource(StrEnum):
    """Skąd pochodzi znacznik czasu; żadne z tych źródeł nie jest zweryfikowanym zegarem."""
    LOG = "log"
    MTIME = "mtime"
    TOOL_CLOCK = "tool_clock"


ORIGIN_OF_SOURCE = {"files": OriginKind.FILE, "database": OriginKind.SQL_DUMP, "logs": OriginKind.LOG, "baseline": OriginKind.BASELINE}
SOURCE_OF_ORIGIN = {origin: source for source, origin in ORIGIN_OF_SOURCE.items()}
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(Severity)}


# --- walidacja pól ------------------------------------------------------------------------------

def _wrong(where: str, expected: str, value: Any) -> ModelError:
    return ModelError(f"{where}: oczekiwano {expected}, jest {type(value).__name__}")


def _optional(check: Callable[..., Any], value: Any, where: str, *options: Any) -> Any:
    """``None`` jest dozwolone; każdą inną wartość sprawdza ``check``."""
    return None if value is None else check(value, where, *options)


def _str(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise _wrong(where, "tekstu", value)
    return value


def _matching(value: Any, where: str, pattern: re.Pattern[str]) -> str:
    if not pattern.fullmatch(_str(value, where)):
        raise ModelError(f"{where}: wartość {value[:80]!r} nie ma wymaganej postaci")
    return value


def _int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _wrong(where, "liczby całkowitej", value)
    return value


def _count(value: Any, where: str) -> int:
    if _int(value, where) < 0:
        raise ModelError(f"{where}: liczba nie może być ujemna")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise _wrong(where, "wartości logicznej", value)
    return value


def _enum(value: Any, where: str, kind: type[StrEnum]) -> Any:
    if isinstance(value, str):
        try:
            return kind(value)
        except ValueError:
            pass
    raise ModelError(f"{where}: nieznana wartość {str(value)[:80]!r}; dozwolone: {', '.join(kind)}")


def _utc(value: Any, where: str) -> str:
    try:
        valid = _UTC.fullmatch(_str(value, where)) is not None and datetime.fromisoformat(value) is not None
    except ValueError:  # poprawny kształt, niemożliwa fields (np. miesiąc 13)
        valid = False
    if not valid:
        raise ModelError(f"{where}: czas musi być w UTC, w ISO 8601 z 'Z' lub '+00:00'")
    return value


def _strings(values: Any, where: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        raise _wrong(where, "listy tekstów", values)
    values = tuple(values)
    for value in values:
        _str(value, where)
    if len(set(values)) != len(values):
        raise ModelError(f"{where}: powtórzone wartości")
    return values


def _items(values: Any, kind: type, where: str) -> tuple:
    if isinstance(values, (str, bytes, Mapping)) or not isinstance(values, Iterable):
        raise _wrong(where, "listy", values)
    values = tuple(values)
    for value in values:
        if not isinstance(value, kind):
            raise _wrong(where, f"obiektów {kind.__name__}", value)
    return values


def _object(fields: Any, where: str, required: Iterable[str], optional: Iterable[str] = ()) -> Mapping[str, Any]:
    """Sprawdza, że ``fields`` jest obiektem JSON o dokładnie znanych polach."""
    if not isinstance(fields, Mapping):
        raise _wrong(where, "obiektu", fields)
    required, known = set(required), set(required) | set(optional)
    if missing := sorted(required - fields.keys()):
        raise ModelError(f"{where}: brak pól: {', '.join(missing)}")
    if unknown := sorted(str(key)[:80] for key in fields.keys() - known):
        raise ModelError(f"{where}: nieznane pola: {', '.join(unknown)}")
    return fields


def _list(fields: Any, where: str) -> list:
    if not isinstance(fields, list):
        raise _wrong(where, "listy", fields)
    return fields


def _build(kind: type, where: str, fields: Mapping[str, Any], **replaced: Any) -> Any:
    """Tworzy obiekt z pól słownika (bez ``id``); błąd pola dostaje miejsce w raporcie, a ``id`` musi wynikać z treści."""
    try:
        built = kind(**{**{name: value for name, value in fields.items() if name != "id"}, **replaced})
    except ModelError as error:
        raise ModelError(f"{where}: {error}") from None
    if "id" in fields and fields["id"] != built.id:
        raise ModelError(f"{where}: identyfikator {str(fields['id'])[:80]!r} nie wynika z treści (oczekiwano {built.id})")
    return built


def content_id(prefix: str, identity: Mapping[str, Any]) -> str:
    """Identyfikator ``<prefix>_<32 hex>``: SHA-256 z kanonicznego JSON pól tożsamości.

    Kanoniczny JSON ma posortowane klucze, brak odstępów i wyłącznie ASCII, więc wynik nie zależy od
    kolejności wstawiania do słownika, od ``PYTHONHASHSEED`` ani od kodowania platformy.
    """
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"{prefix}_{hashlib.sha256(canonical.encode('ascii')).hexdigest()[:_ID_HEX]}"


def utc_iso(moment: datetime) -> str:
    """Czas ze strefą → ISO 8601 w UTC (``+00:00``). Czas bez strefy jest odrzucany: nie zgadujemy strefy."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ModelError("czas bez strefy nie może być zapisany jako UTC")
    return moment.astimezone(timezone.utc).isoformat()


def describe_location(location: Mapping[str, Any]) -> str:
    """Krótki opis miejsca do raportu: ``tabela:klucz``, ``ścieżka:wiersz`` albo sama ścieżka."""
    if location.get("table") is not None:
        return location["table"] if location.get("key") is None else f"{location['table']}:{location['key']}"
    if location.get("path") is not None:
        return location["path"] if location.get("line") is None else f"{location['path']}:{location['line']}"
    return ""


# --- obiekty kontraktu --------------------------------------------------------------------------

@dataclass(frozen=True)
class Evidence:
    """Jeden wpis materiału wejściowego wraz z wynikiem próby odczytu — także wpis pominięty.

    ``logical_path`` to ``<źródło>/<ścieżka względna>``; ścieżka hosta nigdy tu nie trafia. Wpis ``<źródło>/.``
    opisuje samo źródło (np. nieudane otwarcie katalogu). ``sha256`` istnieje wtedy i tylko wtedy, gdy bajty przeczytano.
    """
    origin_kind: OriginKind
    logical_path: str
    read_status: str
    sha256: str | None = None
    size_bytes: int | None = None
    mtime_ns: int | None = None
    read_reason: str | None = None
    hardlinked: bool = False
    id: str = field(init=False)

    def __post_init__(self) -> None:
        where = "evidence"
        object.__setattr__(self, "origin_kind", _enum(self.origin_kind, f"{where}.origin_kind", OriginKind))
        _str(self.logical_path, f"{where}.logical_path")
        if not self.logical_path.startswith(SOURCE_OF_ORIGIN[self.origin_kind] + "/") or "\0" in self.logical_path:
            raise ModelError(f"{where}.logical_path: ścieżka musi być względna i zaczynać się od '{SOURCE_OF_ORIGIN[self.origin_kind]}/'")
        if _str(self.read_status, f"{where}.read_status") not in READ_STATUSES:
            raise ModelError(f"{where}.read_status: nieznana wartość {self.read_status[:80]!r}; dozwolone: {', '.join(READ_STATUSES)}")
        object.__setattr__(self, "read_status", str(self.read_status))
        _optional(_matching, self.sha256, f"{where}.sha256", _SHA256)
        _optional(_count, self.size_bytes, f"{where}.size_bytes")
        _optional(_int, self.mtime_ns, f"{where}.mtime_ns")  # czas sprzed 1970 r. jest ujemny
        _optional(_str, self.read_reason, f"{where}.read_reason")
        _bool(self.hardlinked, f"{where}.hardlinked")
        if self.read_status != UNKNOWN_LEGACY and (self.sha256 is not None) != (self.read_status in HASHED_STATUSES):
            raise ModelError(f"{where}: sha256 musi istnieć dla statusów {', '.join(HASHED_STATUSES)} i tylko dla nich "
                             f"(status {self.read_status})")
        unread = None if self.sha256 is not None else f"{self.read_status}:{self.read_reason or ''}"
        object.__setattr__(self, "id", content_id("ev", {
            "origin_kind": self.origin_kind, "logical_path": self.logical_path, "sha256": self.sha256, "unread": unread}))

    def to_dict(self) -> dict:
        return {"id": self.id, "origin_kind": str(self.origin_kind), "logical_path": self.logical_path, "read_status": self.read_status,
                "read_reason": self.read_reason, "sha256": self.sha256, "size_bytes": self.size_bytes, "mtime_ns": self.mtime_ns,
                "hardlinked": self.hardlinked}

    @classmethod
    def from_dict(cls, fields: Any, where: str = "evidence") -> Evidence:
        fields = _object(fields, where, ("id", "origin_kind", "logical_path", "read_status", "read_reason", "sha256", "size_bytes",
                                     "mtime_ns", "hardlinked"))
        return _build(cls, where, fields)


@dataclass(frozen=True)
class Location:
    """Miejsce faktu w dowodzie; wypełniane są tylko pola znane parserowi."""
    path: str | None = None   # ścieżka względna do źródła (plik witryny albo plik logu)
    line: int | None = None   # numer wiersza logu, od 1
    table: str | None = None  # tabela zrzutu SQL
    key: str | None = None    # klucz wiersza, np. nazwa opcji
    row: int | None = None    # numer kolejny sparsowanego wiersza INSERT w zrzucie, od 1

    def __post_init__(self) -> None:
        for name in ("path", "table", "key"):
            _optional(_str, getattr(self, name), f"location.{name}")
        for name in ("line", "row"):
            _optional(_count, getattr(self, name), f"location.{name}")

    def to_dict(self) -> dict:
        return {name: value for name in ("path", "line", "table", "key", "row") if (value := getattr(self, name)) is not None}

    @classmethod
    def from_dict(cls, fields: Any, where: str = "location") -> Location:
        return _build(cls, where, _object(fields, where, (), ("path", "line", "table", "key", "row")))


@dataclass(frozen=True)
class Observation:
    """Fakt odczytany przez parser, bez oceny. Wskazuje dokładnie jeden dowód."""
    evidence_id: str
    kind: str
    location: Location = field(default_factory=Location)
    attributes: Mapping[str, str | int | bool | None] = field(default_factory=dict)
    timestamp_raw: str | None = None
    timestamp_utc: str | None = None
    time_source: TimeSource | None = None
    id: str = field(init=False)

    def __post_init__(self) -> None:
        where = "observation"
        _str(self.evidence_id, f"{where}.evidence_id")
        _matching(self.kind, f"{where}.kind", _NAME)
        if not isinstance(self.location, Location):
            raise _wrong(f"{where}.location", "obiektu Location", self.location)
        if not isinstance(self.attributes, Mapping):
            raise _wrong(f"{where}.attributes", "obiektu", self.attributes)
        for name, value in self.attributes.items():
            _str(name, f"{where}.attributes (nazwa)")
            if not isinstance(value, _SCALARS):
                raise _wrong(f"{where}.attributes.{name[:80]}", "tekstu, liczby całkowitej, wartości logicznej albo null", value)
        object.__setattr__(self, "attributes", dict(sorted(self.attributes.items())))
        _optional(_str, self.timestamp_raw, f"{where}.timestamp_raw")
        _optional(_utc, self.timestamp_utc, f"{where}.timestamp_utc")
        object.__setattr__(self, "time_source", _optional(_enum, self.time_source, f"{where}.time_source", TimeSource))
        if (self.timestamp_raw is None) != (self.time_source is None) or (self.timestamp_utc is not None and self.timestamp_raw is None):
            raise ModelError(f"{where}: time_source towarzyszy timestamp_raw, a timestamp_utc wymaga obu")
        object.__setattr__(self, "id", content_id("obs", {
            "evidence_id": self.evidence_id, "kind": self.kind, "location": self.location.to_dict(),
            "attributes": self.attributes, "timestamp_raw": self.timestamp_raw}))

    def to_dict(self) -> dict:
        return {"id": self.id, "evidence_id": self.evidence_id, "kind": self.kind, "location": self.location.to_dict(),
                "attributes": dict(self.attributes), "timestamp_raw": self.timestamp_raw, "timestamp_utc": self.timestamp_utc,
                "time_source": None if self.time_source is None else str(self.time_source)}

    @classmethod
    def from_dict(cls, fields: Any, where: str = "observation") -> Observation:
        fields = _object(fields, where, ("id", "evidence_id", "kind", "location", "attributes", "timestamp_raw", "timestamp_utc", "time_source"))
        return _build(cls, where, fields, location=Location.from_dict(fields["location"], f"{where}.location"))


@dataclass(frozen=True)
class Finding:
    """Interpretacja co najmniej jednej obserwacji. ``severity`` i ``confidence`` są od siebie niezależne."""
    rule_id: str
    category: Category
    severity: Severity
    confidence: Confidence
    reason: str
    observations: tuple[str, ...]
    id: str = field(init=False)

    def __post_init__(self) -> None:
        where = "finding"
        _matching(self.rule_id, f"{where}.rule_id", _NAME)
        object.__setattr__(self, "category", _enum(self.category, f"{where}.category", Category))
        object.__setattr__(self, "severity", _enum(self.severity, f"{where}.severity", Severity))
        object.__setattr__(self, "confidence", _enum(self.confidence, f"{where}.confidence", Confidence))
        _str(self.reason, f"{where}.reason")
        object.__setattr__(self, "observations", tuple(sorted(_strings(self.observations, f"{where}.observations"))))
        if not self.observations:
            raise ModelError(f"{where}.observations: ustalenie musi wskazywać co najmniej jedną obserwację")
        object.__setattr__(self, "id", content_id("fnd", {"rule_id": self.rule_id, "observations": list(self.observations)}))

    def to_dict(self) -> dict:
        return {"id": self.id, "rule_id": self.rule_id, "category": str(self.category), "severity": str(self.severity),
                "confidence": str(self.confidence), "reason": self.reason, "observations": list(self.observations)}

    @classmethod
    def from_dict(cls, fields: Any, where: str = "finding") -> Finding:
        fields = _object(fields, where, ("id", "rule_id", "category", "severity", "confidence", "reason", "observations"))
        return _build(cls, where, fields, observations=_list(fields["observations"], f"{where}.observations"))


@dataclass(frozen=True)
class Coverage:
    """Pokrycie jednego źródła: status, liczniki wpisów według statusu odczytu i powody.

    ``entries`` to liczniki z SecureIngest (każdy wpis, także pominięty). ``None`` oznacza brak tej informacji
    i występuje tylko ze statusem ``UNKNOWN_LEGACY``. Status inny niż ``ANALYZED`` zawsze ma co najmniej jeden powód.
    """
    source: str
    status: CoverageStatus
    entries: Mapping[str, int] | None
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        where = f"coverage.{str(self.source)[:80]}"
        if self.source not in SOURCES:
            raise ModelError(f"coverage: nieznane źródło {str(self.source)[:80]!r}; dozwolone: {', '.join(SOURCES)}")
        object.__setattr__(self, "status", _enum(self.status, f"{where}.status", CoverageStatus))
        object.__setattr__(self, "reasons", tuple(sorted(_strings(self.reasons, f"{where}.reasons"))))
        legacy = self.status is CoverageStatus.UNKNOWN_LEGACY
        if (self.entries is None) != legacy:
            raise ModelError(f"{where}.entries: null jest dozwolony wyłącznie ze statusem {UNKNOWN_LEGACY}")
        if not legacy:
            statuses = [str(status) for status in ReadStatus]
            if not isinstance(self.entries, Mapping) or sorted(self.entries) != sorted(statuses):
                raise ModelError(f"{where}.entries: wymagane liczniki dokładnie dla: {', '.join(statuses)}")
            for name in statuses:
                _count(self.entries[name], f"{where}.entries.{name}")
            object.__setattr__(self, "entries", {name: self.entries[name] for name in statuses})
            read = self.entries[str(ReadStatus.READ)]
            other = sum(self.entries.values()) - read
            if self.status is CoverageStatus.ANALYZED and (read == 0 or other):
                raise ModelError(f"{where}: status ANALYZED wymaga co najmniej jednego wpisu READ i żadnego wpisu o innym statusie")
            if self.status is CoverageStatus.NOT_PROVIDED and read + other:
                raise ModelError(f"{where}: status NOT_PROVIDED wyklucza jakiekolwiek wpisy")
            if self.status is not CoverageStatus.ANALYZED and not self.reasons:
                raise ModelError(f"{where}: status {self.status} wymaga co najmniej jednego powodu")

    def to_dict(self) -> dict:
        return {"status": str(self.status), "entries": None if self.entries is None else dict(self.entries), "reasons": list(self.reasons)}

    @classmethod
    def from_dict(cls, source: str, fields: Any) -> Coverage:
        fields = _object(fields, f"coverage.{source}", ("status", "entries", "reasons"))
        return cls(source, fields["status"], fields["entries"], _list(fields["reasons"], f"coverage.{source}.reasons"))


@dataclass(frozen=True)
class TimelineEvent:
    """Orientacyjny znacznik czasu z jawnym źródłem; nie dowodzi kolejności ani przyczynowości."""
    time_utc: str
    time_source: TimeSource
    timestamp_basis: str
    event: str
    source: str
    confidence: Confidence
    evidence_id: str
    observation_id: str | None = None

    def __post_init__(self) -> None:
        where = "timeline"
        _utc(self.time_utc, f"{where}.time_utc")
        object.__setattr__(self, "time_source", _enum(self.time_source, f"{where}.time_source", TimeSource))
        if self.time_source is TimeSource.TOOL_CLOCK:
            raise ModelError(f"{where}.time_source: zegar narzędzia nie jest źródłem czasu zdarzeń")
        _str(self.timestamp_basis, f"{where}.timestamp_basis")
        _matching(self.event, f"{where}.event", _NAME)
        _str(self.source, f"{where}.source")
        object.__setattr__(self, "confidence", _enum(self.confidence, f"{where}.confidence", Confidence))
        _str(self.evidence_id, f"{where}.evidence_id")
        _optional(_str, self.observation_id, f"{where}.observation_id")

    def to_dict(self) -> dict:
        return {"time_utc": self.time_utc, "time_source": str(self.time_source), "timestamp_basis": self.timestamp_basis,
                "event": self.event, "source": self.source, "confidence": str(self.confidence),
                "evidence_id": self.evidence_id, "observation_id": self.observation_id}

    @classmethod
    def from_dict(cls, fields: Any, where: str = "timeline") -> TimelineEvent:
        return _build(cls, where, _object(fields, where, ("time_utc", "time_source", "timestamp_basis", "event", "source", "confidence",
                                                        "evidence_id", "observation_id")))


# --- reguła oceny -------------------------------------------------------------------------------

def scope_complete(coverage: Mapping[str, Coverage]) -> bool:
    """Zakres jest pełny, gdy pliki, baza i logi mają status ``ANALYZED``, a baseline ``ANALYZED`` albo ``NOT_PROVIDED``.

    Każdy wpis pominięty, zmieniony (``CHANGED``) lub ucięty limitem obniża status źródła do ``PARTIAL``,
    więc tutaj wystarczy porównać statusy.
    """
    if any(coverage[source].status is not CoverageStatus.ANALYZED for source in CRITICAL_SOURCES):
        return False
    return coverage["baseline"].status in (CoverageStatus.ANALYZED, CoverageStatus.NOT_PROVIDED)


def is_strong(finding: Finding) -> bool:
    """Silny wskaźnik: waga ``high`` lub ``critical`` i jednocześnie pewność ``high``."""
    return finding.severity in (Severity.HIGH, Severity.CRITICAL) and finding.confidence is Confidence.HIGH


def assess(findings: Iterable[Finding], coverage: Mapping[str, Coverage]) -> Assessment:
    """Etykieta triage dla całej analizy (specyfikacja §9.2, ADR 0003); nie jest werdyktem.

    1. choć jedno silne ustalenie → ``STRONG_INDICATORS`` (także przy niepełnym zakresie);
    2. jakiekolwiek inne ustalenie → ``SUSPICIOUS``;
    3. brak ustaleń i pełny zakres → ``NO_INDICATORS_IN_ANALYZED_SCOPE``;
    4. brak ustaleń i niepełny zakres → ``INCONCLUSIVE``.
    """
    findings = tuple(findings)
    if any(is_strong(finding) for finding in findings):
        return Assessment.STRONG_INDICATORS
    if findings:
        return Assessment.SUSPICIOUS
    return Assessment.NO_INDICATORS_IN_ANALYZED_SCOPE if scope_complete(coverage) else Assessment.INCONCLUSIVE


# --- raport -------------------------------------------------------------------------------------

def _unique(items: Iterable[Any], where: str) -> dict[str, Any]:
    index: dict[str, Any] = {}
    for item in items:
        if item.id in index:
            raise ModelError(f"{where}: powtórzony identyfikator {item.id}")
        index[item.id] = item
    return index


@dataclass(frozen=True)
class Report:
    """Raport ``poc-1``. Utworzenie obiektu oznacza, że wszystkie niezmienniki kontraktu są spełnione."""
    case_id: str
    tool: str
    tool_version: str
    analyzed_at_utc: str | None  # None wyłącznie w raporcie przeniesionym, którego czasu nie dało się znormalizować
    assessment: Assessment
    disclaimer: str
    evidence: tuple[Evidence, ...]
    observations: tuple[Observation, ...]
    findings: tuple[Finding, ...]
    coverage: Mapping[str, Coverage]
    coverage_gaps: tuple[str, ...]
    timeline: tuple[TimelineEvent, ...] = ()
    migrated_from: str | None = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ModelError(f"schema_version: oczekiwano {SCHEMA_VERSION!r}, jest {str(self.schema_version)[:80]!r}")
        if self.migrated_from is not None and self.migrated_from not in MIGRATED_FROM:
            raise ModelError(f"migrated_from: dozwolone wartości: {', '.join(MIGRATED_FROM)}")
        for name in ("case_id", "tool", "tool_version", "disclaimer"):
            _str(getattr(self, name), name)
        if self.analyzed_at_utc is not None or self.migrated_from is None:
            _utc(self.analyzed_at_utc, "analyzed_at_utc")
        object.__setattr__(self, "assessment", _enum(self.assessment, "assessment", Assessment))
        evidence = _unique(_items(self.evidence, Evidence, "evidence"), "evidence")
        observations = _unique(_items(self.observations, Observation, "observations"), "observations")
        findings = _unique(_items(self.findings, Finding, "findings"), "findings")
        timeline = _items(self.timeline, TimelineEvent, "timeline")
        self._check_references(evidence, observations, findings.values(), timeline)
        coverage = self._checked_coverage()
        gaps = tuple(sorted(_strings(self.coverage_gaps, "coverage_gaps")))
        for entry in coverage.values():
            if missing := sorted(set(entry.reasons) - set(gaps)):
                raise ModelError(f"coverage.{entry.source}.reasons: powód nieobecny w coverage_gaps: {missing[0][:120]!r}")
        self._check_legacy_markers(evidence.values(), coverage.values())
        self._check_assessment(findings.values(), coverage)
        object.__setattr__(self, "evidence", tuple(sorted(evidence.values(), key=lambda item: (item.logical_path, item.id))))
        object.__setattr__(self, "observations", tuple(sorted(observations.values(), key=lambda item: item.id)))
        object.__setattr__(self, "findings", tuple(sorted(
            findings.values(), key=lambda item: (-_SEVERITY_RANK[item.severity], item.rule_id, item.id))))
        object.__setattr__(self, "timeline", tuple(sorted(timeline, key=lambda item: (
            item.time_utc, item.source, item.event, item.evidence_id, item.observation_id or ""))))
        object.__setattr__(self, "coverage", coverage)
        object.__setattr__(self, "coverage_gaps", gaps)

    def _check_references(self, evidence: Mapping, observations: Mapping, findings: Iterable[Finding], timeline: Iterable[TimelineEvent]) -> None:
        for observation in observations.values():
            if observation.evidence_id not in evidence:
                raise ModelError(f"observations: {observation.id} wskazuje nieistniejący dowód {observation.evidence_id[:80]!r}")
        for finding in findings:
            for reference in finding.observations:
                if reference not in observations:
                    raise ModelError(f"findings: {finding.id} wskazuje nieistniejącą obserwację {reference[:80]!r}")
        for event in timeline:
            if event.evidence_id not in evidence:
                raise ModelError(f"timeline: zdarzenie {event.event} wskazuje nieistniejący dowód {event.evidence_id[:80]!r}")
            if event.observation_id is not None and event.observation_id not in observations:
                raise ModelError(f"timeline: zdarzenie {event.event} wskazuje nieistniejącą obserwację {event.observation_id[:80]!r}")

    def _checked_coverage(self) -> dict[str, Coverage]:
        if not isinstance(self.coverage, Mapping) or sorted(self.coverage) != sorted(SOURCES):
            raise ModelError(f"coverage: wymagane dokładnie źródła: {', '.join(SOURCES)}")
        for source, entry in self.coverage.items():
            if not isinstance(entry, Coverage) or entry.source != source:
                raise ModelError(f"coverage.{source}: oczekiwano obiektu Coverage tego źródła")
        return {source: self.coverage[source] for source in SOURCES}

    def _check_legacy_markers(self, evidence: Iterable[Evidence], coverage: Iterable[Coverage]) -> None:
        legacy = any(item.read_status == UNKNOWN_LEGACY for item in evidence) or any(
            entry.status is CoverageStatus.UNKNOWN_LEGACY for entry in coverage)
        if legacy and self.migrated_from is None:
            raise ModelError(f"{UNKNOWN_LEGACY} jest dozwolone wyłącznie w raporcie z polem migrated_from")

    def _check_assessment(self, findings: Iterable[Finding], coverage: Mapping[str, Coverage]) -> None:
        """``assessment`` musi wynikać z reguły; raport przeniesiony może jedynie zaniżyć STRONG_INDICATORS do SUSPICIOUS."""
        expected = assess(findings, coverage)
        downgraded = self.migrated_from is not None and (expected, self.assessment) == (Assessment.STRONG_INDICATORS, Assessment.SUSPICIOUS)
        if self.assessment is not expected and not downgraded:
            raise ModelError(f"assessment: jest {self.assessment}, a z ustaleń i pokrycia wynika {expected}")

    @property
    def scope_complete(self) -> bool:
        return scope_complete(self.coverage)

    def to_dict(self) -> dict:
        """Słownik gotowy do zapisu jako JSON, w deterministycznym porządku (ADR 0003 §Porządek)."""
        report = {"schema_version": self.schema_version, "tool": self.tool, "tool_version": self.tool_version, "case_id": self.case_id,
                  "analyzed_at_utc": self.analyzed_at_utc, "analyzed_at_time_source": str(TimeSource.TOOL_CLOCK),
                  "assessment": str(self.assessment), "scope_complete": self.scope_complete, "disclaimer": self.disclaimer,
                  "findings": [item.to_dict() for item in self.findings],
                  "observations": [item.to_dict() for item in self.observations],
                  "evidence": [item.to_dict() for item in self.evidence],
                  "coverage": {source: entry.to_dict() for source, entry in self.coverage.items()},
                  "coverage_gaps": list(self.coverage_gaps),
                  "timeline": [item.to_dict() for item in self.timeline]}
        if self.migrated_from is not None:
            report["migrated_from"] = self.migrated_from
        return report

    @classmethod
    def from_dict(cls, document: Any) -> Report:
        document = _object(document, "raport", ("schema_version", "tool", "tool_version", "case_id", "analyzed_at_utc", "analyzed_at_time_source",
                                        "assessment", "scope_complete", "disclaimer", "findings", "observations", "evidence", "coverage",
                                        "coverage_gaps", "timeline"), ("migrated_from",))
        if document["analyzed_at_time_source"] != TimeSource.TOOL_CLOCK:
            raise ModelError(f"analyzed_at_time_source: oczekiwano {TimeSource.TOOL_CLOCK!s}")
        coverage = _object(document["coverage"], "coverage", SOURCES)
        report = cls(
            case_id=document["case_id"], tool=document["tool"], tool_version=document["tool_version"], analyzed_at_utc=document["analyzed_at_utc"],
            assessment=document["assessment"], disclaimer=document["disclaimer"],
            evidence=tuple(Evidence.from_dict(item, f"evidence[{index}]") for index, item in enumerate(_list(document["evidence"], "evidence"))),
            observations=tuple(Observation.from_dict(item, f"observations[{index}]")
                               for index, item in enumerate(_list(document["observations"], "observations"))),
            findings=tuple(Finding.from_dict(item, f"findings[{index}]") for index, item in enumerate(_list(document["findings"], "findings"))),
            coverage={source: Coverage.from_dict(source, coverage[source]) for source in SOURCES},
            coverage_gaps=tuple(_list(document["coverage_gaps"], "coverage_gaps")),
            timeline=tuple(TimelineEvent.from_dict(item, f"timeline[{index}]") for index, item in enumerate(_list(document["timeline"], "timeline"))),
            migrated_from=document.get("migrated_from"), schema_version=document["schema_version"])
        if document["scope_complete"] is not report.scope_complete:
            raise ModelError(f"scope_complete: jest {str(document['scope_complete'])[:80]}, a z pokrycia wynika {report.scope_complete}")
        return report


def validate_report(document: Any) -> Report:
    """Sprawdza słownik raportu ``poc-1`` względem całego kontraktu; zwraca zbudowany ``Report`` albo zgłasza ``ModelError``."""
    return Report.from_dict(document)
