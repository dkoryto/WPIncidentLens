"""CaseManager (C01): walidacja wywołania i zamrożony kontekst sprawy (ADR 0001, krok migracji 6).

Moduł nie czyta treści dowodów i niczego nie zapisuje. Ścieżki sprawdza wyłącznie przez
``ingest.check_source`` i ``ingest.resolve_output``. Nie pobiera nazwy użytkownika systemu, nazwy hosta
ani zmiennych środowiskowych: operatora opisuje tylko pseudonim podany wprost w ``--operator-id``.
"""
from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import ingest, models

SCHEMA_VERSION = "case-poc-1"
# (nazwa źródła, oczekiwany rodzaj wpisu); kolejność jak w raporcie
SOURCES = (("files", "dir"), ("database", "file"), ("logs", "any"), ("baseline", "file"))
_IDENTIFIER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}")
_NOT_UTF8 = "tekst, którego nie da się zapisać w UTF-8 (samotny surogat)"


class CaseError(ValueError):
    """Niepoprawne wywołanie. Komunikat nie powtarza odrzuconej wartości ani ścieżki."""


@dataclass(frozen=True)
class CaseContext:
    case_id: str
    operator_id: str | None
    files: Path
    database: Path | None
    logs: Path | None
    baseline: Path | None
    output: Path  # rzeczywista ścieżka katalogu wyników
    limits: ingest.Limits
    allow_hardlinks: bool
    reverify: bool
    known_admins: frozenset[str]
    created_at_utc: str

    def describe(self) -> dict:
        """Część ``case.json`` znana przed analizą. Ze ścieżek źródeł zostaje tylko nazwa ostatniego składnika."""
        return {
            "schema_version": SCHEMA_VERSION, "case_id": self.case_id, "operator_id": self.operator_id,
            "created_at_utc": self.created_at_utc,
            "sources": {name: {"provided": getattr(self, name) is not None, "name": _label(getattr(self, name))} for name, _ in SOURCES},
            "limits": asdict(self.limits),
            "flags": {"allow_hardlinks": self.allow_hardlinks, "reverify": self.reverify},
        }


def _encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _label(path: Path | None) -> str | None:
    """Nazwa ostatniego składnika ścieżki; ``None`` dla źródła niepodanego i ścieżki bez nazwy (np. ``.``)."""
    name = path.name if path is not None else ""
    return name.encode("utf-8", "backslashreplace").decode("utf-8") or None


def _identifier(flag: str, value: str) -> str:
    if _IDENTIFIER.fullmatch(value) is None:
        raise CaseError(f"{flag}: dozwolone są 1–64 znaki A-Z, a-z, 0-9, kropka, podkreślenie i łącznik; pierwszy znak nie może być kropką ani łącznikiem")
    return value


def _limits(values: Mapping[str, float]) -> ingest.Limits:
    try:
        limits = ingest.Limits(**values)
    except ValueError as invalid:
        raise CaseError(str(invalid)) from None
    for name, value in asdict(limits).items():
        if not math.isfinite(value):  # nieskończoność nie jest poprawną liczbą JSON i wyłączałaby limit
            raise CaseError(f"limit {name} musi być skończony")
    return limits


def _output(output: Path, sources: list[Path]) -> Path:
    try:
        resolved = ingest.resolve_output(output, sources)
    except ingest.IngestRefusal as refusal:
        raise CaseError(f"--output: {refusal}") from None
    except ValueError:  # np. bajt zerowy albo samotny surogat w ścieżce
        raise CaseError("--output: niepoprawna ścieżka") from None
    try:
        ingest.check_source(output, "dir")  # istniejący wpis musi być prawdziwym katalogiem, nie dowiązaniem
    except ingest.IngestRefusal as refusal:
        if refusal.reason != "ENOENT":  # katalog, którego jeszcze nie ma, utworzy Reporter
            raise CaseError(f"--output: {refusal}") from None
    return resolved


def build(*, files: Path, output: Path, case_id: str, database: Path | None = None, logs: Path | None = None,
          baseline: Path | None = None, operator_id: str | None = None, known_admins: Iterable[str] = (),
          limits: Mapping[str, float] | None = None, allow_hardlinks: bool = False, reverify: bool = True) -> CaseContext:
    """Waliduje wywołanie w kolejności: wartości tekstowe i limity, ścieżki źródeł, katalog wyników.

    Zgłasza ``CaseError`` z nazwą flagi. Źródło bez uprawnień do odczytu nie jest błędem wywołania:
    staje się luką pokrycia w raporcie.
    """
    _identifier("--case-id", case_id)
    if operator_id is not None:
        _identifier("--operator-id", operator_id)
    admins = frozenset(known_admins)
    if not all(map(_encodable, admins)):
        raise CaseError(f"--known-admin: {_NOT_UTF8}")
    checked = _limits(limits or {})
    paths = {"files": files, "database": database, "logs": logs, "baseline": baseline}
    given = [(name, paths[name], expect) for name, expect in SOURCES if paths[name] is not None]
    for name, path, expect in given:
        try:
            ingest.check_source(path, expect)
        except ingest.IngestRefusal as refusal:
            if refusal.reason not in ("EACCES", "EPERM"):
                raise CaseError(f"--{name}: {refusal}") from None
    return CaseContext(
        case_id=case_id, operator_id=operator_id, files=files, database=database, logs=logs, baseline=baseline,
        output=_output(output, [path for _, path, _ in given]), limits=checked, allow_hardlinks=allow_hardlinks,
        reverify=reverify, known_admins=admins, created_at_utc=models.utc_iso(datetime.now(timezone.utc)))


def check_baseline(baseline: dict) -> dict:
    """Odrzuca baseline z tekstem nie do zapisania w UTF-8, zanim taka wartość trafi do raportu po całej analizie."""
    files = baseline.get("files", {})
    if not all(map(_encodable, (*files, *files.values(), *baseline.get("known_admins", [])))):
        raise CaseError(f"baseline zawiera {_NOT_UTF8}")
    return baseline
