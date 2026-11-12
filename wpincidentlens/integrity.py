"""Porównanie plików z zaufaną referencją: baseline (SHA-256) i lokalny manifest sum rdzenia WordPress.org (MD5).

Brak referencji to luka w zakresie (``NOT_CHECKED``), nie wynik „bez zmian”. Moduł nie dotyka systemu plików:
dostaje wpisy już przeczytane przez SecureIngest. MD5 służy wyłącznie do porównania z publicznym manifestem
i występuje tylko w atrybutach obserwacji; skrótem dowodu pozostaje SHA-256 (ADR 0005).
"""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath

from . import case, filerules, ingest, models
from .analysis import Detection, SourceCoverage, observe, seen_in
from .fileclass import AUTOLOADED, FileClass, classify

MAX_CORE_CHECKSUMS = 50_000  # pełny manifest WordPressa ma kilka tysięcy wpisów
MAX_MANIFEST_PATH = 1024
_MD5 = re.compile(r"[0-9a-f]{32}")
# Klasy, dla których brak referencji jest zapisywany w pokryciu osobno (ADR 0005, pkt 3).
CHECKED_CLASSES = (FileClass.CORE, FileClass.PLUGIN, FileClass.THEME, FileClass.MU_PLUGIN, FileClass.DROPIN)
_NOT_PROOF = "Nowy plik nie dowodzi włamania: baseline może być po prostu starszy niż legalna zmiana."


@dataclass(frozen=True)
class CoreChecksums:
    """Zweryfikowany manifest sum rdzenia razem z wpisem rejestru pliku, z którego pochodzi."""
    record: ingest.Evidence
    checksums: Mapping[str, str]
    version: str | None = None
    label: str | None = None


def _relative_posix(path: object) -> bool:
    return (isinstance(path, str) and 0 < len(path) <= MAX_MANIFEST_PATH and path.isprintable() and "\\" not in path
            and all(part not in ("", ".", "..") for part in path.split("/")))


def parse_core_checksums(data: object, record: ingest.Evidence) -> CoreChecksums:
    """Sprawdza kształt ``{"checksums": {ścieżka: md5}}`` (api.wordpress.org ``core/checksums/1.0``); ``ValueError`` przy odstępstwie.

    Przyjmuje też wariant ``{"checksums": {"<wersja>": {ścieżka: md5}}}``. Komunikaty nie powtarzają odrzuconych wartości.
    """
    if not isinstance(data, dict) or not isinstance(data.get("checksums"), dict):
        raise ValueError('manifest musi być obiektem JSON {"checksums": {ścieżka: md5}}')
    version, label = case.reference_labels(data)
    checksums = data["checksums"]
    if len(checksums) == 1 and isinstance(next(iter(checksums.values())), dict):
        (nested_version, checksums), = checksums.items()
        case.reference_labels({"wordpress_version": nested_version})
        if version not in (None, nested_version):
            raise ValueError("wordpress_version różni się od wersji w kluczu checksums")
        version = nested_version
    if not 0 < len(checksums) <= MAX_CORE_CHECKSUMS:
        raise ValueError(f"manifest musi zawierać od 1 do {MAX_CORE_CHECKSUMS} sum")
    if not all(map(_relative_posix, checksums)):
        raise ValueError("klucze checksums muszą być ścieżkami względnymi z ukośnikami „/”, bez „..”, "
                         f"znaków sterujących i dłuższych niż {MAX_MANIFEST_PATH} znaków")
    if not all(isinstance(value, str) and _MD5.fullmatch(value) for value in checksums.values()):
        raise ValueError("wartości checksums muszą być skrótami MD5: 32 małe cyfry szesnastkowe")
    return CoreChecksums(record, checksums, version, label)


def baseline_record(session: ingest.Session, core: CoreChecksums | None = None) -> ingest.Evidence | None:
    """Wpis rejestru dla wczytanego baseline (dowód, na który powołują się ustalenia o brakujących plikach).

    Manifest sum rdzenia należy do tego samego źródła ``baseline``, więc jest tu pomijany po nazwie.
    """
    skip = core.record.rel if core else None
    return next((record for record in session.ledger
                 if record.source == "baseline" and record.sha256 is not None and record.rel != skip), None)


def _reference_facts(version: str | None, label: str | None) -> dict[str, str]:
    return {name: value for name, value in (("reference_version", version), ("reference", label)) if value is not None}


def _is_code(rel: str) -> bool:
    return PurePosixPath(rel).suffix.lower() in filerules.CODE_SUFFIXES


class ReferenceComparison:
    """Zbiera wpisy drzewa plików i porównuje je z baseline (SHA-256) oraz z manifestem sum rdzenia (MD5)."""

    def __init__(self, baseline: dict | None, core: CoreChecksums | None = None) -> None:
        self.baseline = baseline
        self.ref: dict[str, str] = (baseline or {}).get("files", {})
        self.baseline_facts = _reference_facts((baseline or {}).get("wordpress_version"), (baseline or {}).get("reference"))
        self.core = core
        self.core_facts = {} if core is None else {
            **_reference_facts(core.version, core.label), "reference_file": f"{core.record.source}/{core.record.rel}"}
        self.observed: set[str] = set()      # przeczytane
        self.unread: set[str] = set()        # widziane, lecz nieprzeczytane
        self.unreferenced: set[str] = set()  # przeczytane, bez wpisu w żadnej referencji i bez własnego ustalenia
        self.read_in_class: Counter = Counter()
        self.unchecked_in_class: Counter = Counter()
        self.complete = True                 # czy przejście objęło całe drzewo

    def check(self, item: ingest.Evidence) -> list[Detection]:
        """Rejestruje wpis; dla przeczytanego pliku zwraca wykrycia różnic względem referencji."""
        kind = classify(item.rel)
        if item.sha256 is None:
            self.unread.add(item.rel)
            self.complete = self.complete and item.rel != ingest.ROOT and item.reason not in ("MAX_FILES", "MAX_ENTRIES")
            # Katalog, którego pliki baseline wymienia, nie jest nowy — tylko nieprzejrzany.
            if self._new_autoloaded(item.rel, kind) and not any(listed.startswith(item.rel + "/") for listed in self.ref):
                return [Detection("NEW_FILE_SINCE_BASELINE", "medium", "low", "file",
                                  "Wpis w miejscu ładowanym automatycznie nie występuje w baseline; treść nieodczytana, "
                                  f"wymaga ręcznej analizy. {_NOT_PROOF}",
                                  seen_in(item, "ENTRY_NOT_IN_BASELINE", file_class=str(kind), **self.baseline_facts))]
            return []
        self.observed.add(item.rel)
        self.read_in_class[kind] += 1
        found, reported = [], False
        expected = self.ref.get(item.rel)
        if expected is not None and expected != item.sha256:
            found.append(Detection("BASELINE_FILE_CHANGED", "medium", "high", "file",
                                   "Plik zmieniony względem zaufanej migawki (zmiana nie przesądza o ataku).",
                                   seen_in(item, "FILE_DIFFERS_FROM_BASELINE", baseline_sha256=expected, **self.baseline_facts)))
        elif self._new_autoloaded(item.rel, kind):
            reported = True
            found.append(Detection("NEW_FILE_SINCE_BASELINE", "medium", "medium", "file",
                                   f"Plik w miejscu ładowanym automatycznie nie występuje w baseline. {_NOT_PROOF}",
                                   seen_in(item, "FILE_NOT_IN_BASELINE", file_class=str(kind), **self.baseline_facts)))
        in_manifest = self.core is not None and item.rel in self.core.checksums
        if self.core is not None and item.md5 is not None:
            if in_manifest:
                found.extend(self._against_manifest(item, self.core.checksums[item.rel]))
            elif kind is FileClass.CORE and _is_code(item.rel):
                # Kod w wp-admin, wp-includes i w katalogu głównym jest osiągalny wprost z sieci, a legalne dodatki tam
                # nie trafiają. Pewność niska: manifest innej wersji lub locale daje ten sam obraz.
                reported = True
                found.append(Detection("CORE_FILE_NOT_IN_MANIFEST", "medium", "low", "file",
                                       "Plik PHP w miejscu rdzenia nie występuje w manifeście sum; może pochodzić z innej wersji "
                                       "lub locale WordPressa albo być plikiem dodanym — wymaga ręcznej weryfikacji.",
                                       seen_in(item, "FILE_NOT_IN_CORE_MANIFEST", **self.core_facts)))
        if expected is None and not in_manifest:
            self.unchecked_in_class[kind] += 1
            if not reported:
                self.unreferenced.add(item.rel)
        return found

    def _new_autoloaded(self, rel: str, kind: FileClass) -> bool:
        return bool(self.ref) and rel not in self.ref and kind in AUTOLOADED

    def _against_manifest(self, item: ingest.Evidence, reference_md5: str) -> list[Detection]:
        if item.md5 == reference_md5:
            return []
        stated = f"dla wersji {self.core.version}" if self.core.version else "z podanego manifestu (bez oznaczenia wersji)"
        return [Detection("CORE_CHECKSUM_MISMATCH", "medium", "high", "file",
                          f"Plik różni się od publicznej referencji WordPress.org {stated}. Manifest innej wersji lub innego locale "
                          "także daje rozbieżności; sama różnica nie przesądza o ataku.",
                          seen_in(item, "FILE_DIFFERS_FROM_CORE_MANIFEST", observed_sha256=item.sha256, observed_md5=item.md5,
                                  reference_md5=reference_md5, **self.core_facts))]

    def _absent(self, listed: Mapping[str, str]) -> list[str]:
        """Ścieżki z referencji, których w materiale na pewno nie ma: bez wpisów, które istnieją, lecz są nieprzeczytane."""
        absent = []
        for rel in sorted(listed.keys() - self.observed):
            parts = rel.split("/")
            if not any("/".join(parts[:depth]) in self.unread for depth in range(1, len(parts) + 1)):
                absent.append(rel)
        return absent

    def finish(self, session: ingest.Session, cover: SourceCoverage) -> list[Detection]:
        """Po przejściu drzewa: noty o plikach bez referencji i wykrycia plików, których w materiale brakuje."""
        found = []
        if (self.ref or self.core) and self.unreferenced:
            # Plik bez wpisu w referencji nie jest porównywany: bez tej noty nowy plik znikałby z raportu bez śladu.
            unreferenced = sorted(self.unreferenced)
            examples = ", ".join(unreferenced[:3]) + (", …" if len(unreferenced) > 3 else "")
            cover.note(f"NO_TRUSTED_REFERENCE: {len(unreferenced)} odczytanych plików nie ma wpisu w podanej referencji, "
                       f"więc ich zmiany lub pojawienia się nie da się ocenić ({examples})")
        for kind in CHECKED_CLASSES:
            if unchecked := self.unchecked_in_class[kind]:
                total = self.read_in_class[kind]
                count = f"{unchecked}" if unchecked == total else f"{unchecked} z {total}"
                cover.note(f"NOT_CHECKED: integralność plików klasy {kind} (plików: {count}) niezweryfikowana — brak zaufanej referencji")
        if not self.complete:  # po przerwanym przejściu nie wiadomo, czego w materiale brakuje
            return found
        if self.ref:
            reference = baseline_record(session, self.core)  # dowodem braku pliku jest baseline, który ten plik wymienia
            for rel in self._absent(self.ref):
                found.append(Detection("BASELINE_FILE_MISSING", "low", "high", "file",
                                       "Plik obecny w migawce bazowej nie występuje w materiale wejściowym.",
                                       observe(reference, "BASELINE_ENTRY_NOT_IN_FILES", models.Location(path=rel), **self.baseline_facts)))
        if self.core is not None:
            bundled = 0
            for rel in self._absent(self.core.checksums):
                if rel.startswith("wp-content/"):  # dołączone motywy i wtyczki są rutynowo usuwane
                    bundled += 1
                    continue
                found.append(Detection("CORE_FILE_MISSING", "low", "high", "file",
                                       "Plik wymieniony w manifeście sum rdzenia nie występuje w materiale wejściowym; "
                                       "manifest innej wersji także daje takie braki.",
                                       observe(self.core.record, "CORE_MANIFEST_ENTRY_NOT_IN_FILES", models.Location(path=rel),
                                               reference_md5=self.core.checksums[rel], **_reference_facts(self.core.version, self.core.label))))
            if bundled:
                cover.note(f"Manifest sum rdzenia wymienia {bundled} plików w wp-content, których nie ma w materiale "
                           "(dołączone motywy i wtyczki bywają usuwane); nie powstają z nich ustalenia")
        return found
