"""Porównanie plików z zaufaną referencją (baseline). Brak referencji to luka w zakresie, nie wynik „czysto”."""
from __future__ import annotations

from . import ingest, models
from .analysis import Detection, SourceCoverage, observe, seen_in


def baseline_record(session: ingest.Session) -> ingest.Evidence | None:
    """Wpis rejestru dla wczytanego baseline (dowód, na który powołują się ustalenia o brakujących plikach)."""
    return next((record for record in session.ledger if record.source == "baseline" and record.sha256 is not None), None)


class BaselineComparison:
    """Zbiera wpisy drzewa plików i porównuje je ze skrótami SHA-256 z baseline."""

    def __init__(self, baseline: dict | None) -> None:
        self.baseline = baseline
        self.ref: dict[str, str] = (baseline or {}).get("files", {})
        self.observed: set[str] = set()  # przeczytane
        self.unread: set[str] = set()    # widziane, lecz nieprzeczytane
        self.complete = True             # czy przejście objęło całe drzewo

    def check(self, item: ingest.Evidence) -> list[Detection]:
        """Rejestruje wpis; dla przeczytanego pliku zwraca wykrycie różnicy względem baseline."""
        if item.sha256 is None:
            self.unread.add(item.rel)
            self.complete = self.complete and item.rel != ingest.ROOT and item.reason not in ("MAX_FILES", "MAX_ENTRIES")
            return []
        self.observed.add(item.rel)
        if item.rel in self.ref and self.ref[item.rel] != item.sha256:
            return [Detection("BASELINE_FILE_CHANGED", "medium", "high", "file",
                              "Plik zmieniony względem zaufanej migawki (zmiana nie przesądza o ataku).",
                              seen_in(item, "FILE_DIFFERS_FROM_BASELINE", baseline_sha256=self.ref[item.rel]))]
        return []

    def finish(self, session: ingest.Session, cover: SourceCoverage) -> list[Detection]:
        """Po przejściu drzewa: nota o plikach bez referencji i wykrycia plików, których w materiale brakuje."""
        found = []
        if self.ref and (unreferenced := sorted(self.observed - self.ref.keys())):
            # Plik bez wpisu w baseline nie jest porównywany: bez tej noty nowy plik znikałby z raportu bez śladu.
            examples = ", ".join(unreferenced[:3]) + (", …" if len(unreferenced) > 3 else "")
            cover.note(f"NO_TRUSTED_REFERENCE: {len(unreferenced)} odczytanych plików nie ma wpisu w baseline, "
                       f"więc ich zmiany lub pojawienia się nie da się ocenić ({examples})")
        if self.baseline and self.ref and self.complete:  # po przerwanym przejściu nie wiadomo, czego w materiale brakuje
            reference = baseline_record(session)  # dowodem braku pliku jest baseline, który ten plik wymienia
            for rel in sorted(self.ref.keys() - self.observed):
                parts = rel.split("/")
                if any("/".join(parts[:depth]) in self.unread for depth in range(1, len(parts) + 1)):
                    continue  # plik (lub jego katalog) istnieje, tylko nie został przeczytany — luka, nie „brak pliku”
                found.append(Detection("BASELINE_FILE_MISSING", "low", "high", "file",
                                       "Plik obecny w migawce bazowej nie występuje w materiale wejściowym.",
                                       observe(reference, "BASELINE_ENTRY_NOT_IN_FILES", models.Location(path=rel))))
        return found
