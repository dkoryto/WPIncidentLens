"""Wspólne typy skanerów: wykrycie (fakt + ocena reguły) i robocze pokrycie źródła. Bez dostępu do plików."""
from __future__ import annotations

import io
from dataclasses import dataclass, field

from . import ingest, models


@dataclass(frozen=True)
class Detection:
    """Wykrycie parsera: fakt (``observation``) i ocena, jaką nadaje mu reguła PoC. Z niego powstaje ``Finding``."""
    rule: str
    severity: str
    confidence: str
    category: str
    explanation: str
    observation: models.Observation


@dataclass
class SourceCoverage:
    """Roboczy zapis pokrycia jednego źródła. Status końcowy wynika z niego i z rejestru sesji."""
    provided: bool = True
    failed: bool = False   # źródło podano, ale nic z niego nie przeanalizowano
    partial: bool = False  # część materiału pominięta przez limit albo nieobsługiwany format
    reasons: list[str] = field(default_factory=list)
    # (reguła, typ wyjątku) → [liczba, pierwsze miejsce, indeks luki w ``reasons``] (``rules.rule_failed``)
    rule_errors: dict = field(default_factory=dict, repr=False)

    def note(self, *texts: str) -> None:
        """Informacja o zakresie (np. stałe ograniczenie parsera); sama nie obniża statusu."""
        self.reasons.extend(texts)

    def degrade(self, text: str) -> None:
        self.partial = True
        self.reasons.append(text)

    def fail(self, text: str) -> None:
        self.failed = True
        self.reasons.append(text)


def evidence_of(record: ingest.Evidence) -> models.Evidence:
    """Wpis rejestru SecureIngest jako dowód raportu; ścieżka logiczna jest względna do źródła."""
    return models.Evidence(models.ORIGIN_OF_SOURCE[record.source], f"{record.source}/{record.rel}", str(record.status),
                           sha256=record.sha256, size_bytes=record.size, mtime_ns=record.mtime_ns,
                           read_reason=record.reason or None, hardlinked=record.hardlinked)


def observe(evidence: ingest.Evidence, kind: str, location: models.Location, **facts: str | int | None) -> models.Observation:
    """Fakt bez czasu własnego, stwierdzony w podanym wpisie materiału."""
    return models.Observation(evidence_of(evidence).id, kind, location, facts)


def seen_in(item: ingest.Evidence, kind: str, **facts: str | int | None) -> models.Observation:
    """Fakt dotyczący całego pliku ``item``."""
    return observe(item, kind, models.Location(path=item.rel), **facts)


def decoded(content: bytes) -> io.TextIOWrapper:
    """Dekoduje jak dotychczasowe otwarcie w trybie tekstowym: UTF-8 ze znakami zastępczymi, uniwersalne końce wierszy."""
    return io.TextIOWrapper(io.BytesIO(content), encoding="utf-8", errors="replace")


def is_lossy(content: bytes) -> bool:
    """Czy dekodowanie UTF-8 musiało podstawić znaki zastępcze (część treści mogła zmienić znaczenie)."""
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False
