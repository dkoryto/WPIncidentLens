"""``wpincidentlens report verify`` (R-90, ADR 0011): spójność katalogu wyników z ``case.json`` i ``report.json``.

Katalog wyników jest tu **nieufnym wejściem**: mógł zostać podmieniony, uzupełniony albo przerwany w trakcie zapisu.
Odczyt idzie wyłącznie przez ``ingest.Session`` (ADR 0002 D4): katalog i pliki bez podążania za dowiązaniami, pliki
specjalne pomijane, rozmiar pliku i liczba wpisów ograniczone. Treść zatrzymują tylko ``case.json`` i ``report.json``;
pozostałe pliki są jedynie haszowane strumieniowo.

Co jest sprawdzane:

1. ``case.json``: poprawny JSON (bez powtórzonych kluczy), schemat ``case-poc-1``, w ``outputs`` wyłącznie nazwy
   plików wyniku (``report.RESULT_FILES``) i skróty SHA-256. Inaczej wejście jest nieużyteczne (kod 2).
2. Zestaw plików: brakujące, nadmiarowe, niebędące zwykłym plikiem (dowiązanie, FIFO), zbyt duże, nieczytelne.
3. SHA-256 każdego pliku z ``outputs`` i ``report.sha256``.
4. ``report.json``: cały kontrakt ``poc-1`` (``models.Report.from_dict``, także raport z ``migrated_from``) i postać
   kanoniczna (słownik równy ``to_dict()`` zbudowanego raportu); pola ``case.json`` zgodne z raportem, a ``exit_code``
   równy kodowi wynikającemu z pokrycia.
5. Widoki i ``report.html``: wyliczone ponownie z ``report.json`` (``outputs.streams``, ``report.render_html``) i
   porównane skrótem z plikami — tylko gdy ``case.json`` pochodzi z tej samej wersji narzędzia (inna wersja może
   legalnie renderować inaczej; wtedy zostaje nota, a pliki są sprawdzane wyłącznie skrótami z ``case.json``).

Weryfikacja nie certyfikuje autentyczności źródeł ani autorstwa wyniku: kto podmieni wszystkie pliki spójnie
(łącznie z ``case.json``), przejdzie ją. Wynik nie powtarza treści plików; nazwy spoza listy wyników są pokazywane
w postaci zneutralizowanej (``shown``).
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__, cli, ingest, models, outputs, report
from .case import SCHEMA_VERSION as CASE_SCHEMA_VERSION

EXIT_VERIFIED, EXIT_MISMATCH, EXIT_UNUSABLE = 0, 1, 2
MAX_FILE_BYTES = 512 * 1024**2  # domyślny limit jednego pliku wyniku (``--max-file-bytes``)
MAX_CASE_BYTES = 1024**2
MAX_ENTRIES = 256  # wyników jest 9; więcej wpisów to już na pewno nadmiar
MAX_SHOWN = 120
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SAFE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-/")
SOURCE = "output"

PROBLEMS = {
    "MISSING": "brak pliku wymienionego w case.json",
    "EXTRA": "plik spoza zestawu wyników",
    "NOT_REGULAR": "nie jest zwykłym plikiem (dowiązanie symboliczne albo plik specjalny); nie odczytano",
    "TOO_LARGE": "plik większy niż limit --max-file-bytes; nie odczytano",
    "TOO_MANY_ENTRIES": "katalog ma zbyt wiele wpisów; reszta nie została sprawdzona",
    "UNREADABLE": "nie udało się odczytać",
    "CHANGED_DURING_READ": "plik zmienił się w trakcie weryfikacji",
    "MODIFIED": "SHA-256 inny niż zapisany w case.json",
    "NOT_LISTED": "plik wyniku niewymieniony w outputs w case.json",
    "INVALID_JSON": "niepoprawny JSON (wymagany UTF-8, bez powtórzonych kluczy)",
    "INVALID_REPORT": "raport niezgodny z kontraktem poc-1",
    "NOT_CANONICAL": "raport nie jest w postaci zapisywanej przez narzędzie",
    "INCONSISTENT": "treść niezgodna z widokiem wyliczonym ponownie z report.json",
    "CASE_MISMATCH": "pole case.json niezgodne z report.json",
}


class Unusable(Exception):
    """Katalogu nie da się zweryfikować (brak odniesienia). Komunikat nie zawiera treści ani ścieżek z wejścia."""


@dataclass
class Result:
    problems: list[tuple[str, str, str]] = field(default_factory=list)  # (plik, kod problemu, szczegół z kodu)
    notes: list[str] = field(default_factory=list)
    checked: int = 0
    case_id: str = ""

    def add(self, name: str, problem: str, detail: str = "") -> None:
        self.problems.append((shown(name), problem, detail))

    @property
    def exit_code(self) -> int:
        return EXIT_MISMATCH if self.problems else EXIT_VERIFIED


def shown(name: str) -> str:
    """Nazwa z nieufnego katalogu do wypisania: tylko ``A-Z a-z 0-9 . _ - /``, reszta jako ``\\xNN``/``\\uXXXX``, przycięta."""
    text = "".join(char if char in _SAFE else (f"\\x{ord(char):02x}" if ord(char) < 0x100 else f"\\u{ord(char):04x}"
                                                  if ord(char) < 0x10000 else f"\\U{ord(char):08x}") for char in name[:MAX_SHOWN])
    return text + ("…" if len(name) > MAX_SHOWN else "")


class _DuplicateKey(ValueError):
    pass


def _unique(pairs: list[tuple[str, object]]) -> dict:
    data = dict(pairs)
    if len(data) != len(pairs):
        raise _DuplicateKey
    return data


def _json(content: bytes) -> object:
    return json.loads(content.decode("utf-8"), object_pairs_hook=_unique)


def _digest(chunks: Iterable[bytes]) -> str:
    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(chunk)
    return digest.hexdigest()


def _read(directory: Path, max_file_bytes: int) -> tuple[dict[str, ingest.Evidence], Result]:
    """Wpisy katalogu po nazwie; nieczytelny katalog (dowiązanie, brak, nie katalog) to ``Unusable``."""
    limits = ingest.Limits(max_files=MAX_ENTRIES, max_entries=MAX_ENTRIES, max_file_bytes=max_file_bytes,
                           max_total_bytes=max_file_bytes * (len(report.RESULT_FILES) + 1), max_depth=1, max_seconds=600)
    session = ingest.Session(limits, allow_hardlinks=True, reverify=False)
    result, entries = Result(), {}
    for item in session.read(directory, SOURCE, expect="dir", keep_limit=max_file_bytes,
                             wanted=lambda rel: rel in (report.CASE_JSON, report.REPORT_JSON)):
        if item.rel == ingest.ROOT:
            if item.reason == "MAX_ENTRIES":
                result.add(".", "TOO_MANY_ENTRIES")
                continue
            raise Unusable(f"katalogu wyników nie da się otworzyć: {ingest.IngestRefusal(item.status, item.reason)}")
        if item.reason in ("MAX_ENTRIES", "MAX_FILES"):
            result.add(item.rel, "TOO_MANY_ENTRIES")
            continue
        entries[item.rel] = item
    return entries, result


def _problem_of(item: ingest.Evidence) -> str | None:
    """Kod problemu wpisu, którego bajtów nie odczytano w całości; ``None`` dla pliku przeczytanego bez zmian."""
    if item.status is ingest.ReadStatus.READ:
        return None
    if item.status in (ingest.ReadStatus.SKIPPED_SYMLINK, ingest.ReadStatus.SKIPPED_SPECIAL):
        return "NOT_REGULAR"
    if item.reason in ("MAX_FILE_BYTES", "MAX_TOTAL_BYTES"):
        return "TOO_LARGE"
    if item.status is ingest.ReadStatus.CHANGED:
        return "CHANGED_DURING_READ"
    return "UNREADABLE"


def _case(entries: dict[str, ingest.Evidence], result: Result) -> dict:
    """``case.json`` jako odniesienie; każdy błąd jego odczytu albo kształtu to ``Unusable``."""
    item = entries.get(report.CASE_JSON)
    if item is None:
        raise Unusable("brak case.json: katalog nie zawiera kompletnego wyniku (albo zapis przerwano przed jego końcem)")
    problem = _problem_of(item)
    if problem is not None:
        raise Unusable(f"case.json: {PROBLEMS[problem]}")
    if item.size > MAX_CASE_BYTES or item.content is None:
        raise Unusable(f"case.json większy niż {MAX_CASE_BYTES} B")
    try:
        case = _json(item.content)
    except (ValueError, RecursionError):
        raise Unusable(f"case.json: {PROBLEMS['INVALID_JSON']}") from None
    if not isinstance(case, dict) or case.get("schema_version") != CASE_SCHEMA_VERSION:
        raise Unusable(f"case.json: oczekiwano obiektu o schema_version {CASE_SCHEMA_VERSION}")
    reference, listed = case.get("report"), case.get("outputs")
    if not (isinstance(reference, dict) and reference.get("file") == report.REPORT_JSON
            and isinstance(reference.get("sha256"), str) and _SHA256.fullmatch(reference["sha256"])):
        raise Unusable("case.json: pole report musi wskazywać report.json i jego SHA-256")
    if listed is None:
        raise Unusable("case.json bez pola outputs (wynik sprzed M5): skrótów widoków nie ma z czym porównać")
    if not (isinstance(listed, dict) and all(isinstance(value, str) and _SHA256.fullmatch(value) for value in listed.values())):
        raise Unusable("case.json: outputs musi być obiektem {nazwa pliku: SHA-256}")
    if not set(listed) <= set(report.RESULT_FILES) - {report.CASE_JSON}:
        raise Unusable("case.json: outputs wymienia plik spoza listy plików wyniku (np. ścieżkę z „/” albo „..”)")
    if not (isinstance(case.get("flags"), dict) and isinstance(case.get("exit_code"), int)
            and all(isinstance(case.get(name), str) for name in ("case_id", "tool", "tool_version", "assessment"))):
        raise Unusable("case.json: brak wymaganych pól case_id, tool, tool_version, assessment, exit_code lub flags")
    if listed.get(report.REPORT_JSON, reference["sha256"]) != reference["sha256"]:
        result.add(report.REPORT_JSON, "CASE_MISMATCH", "report.sha256 różni się od outputs")
    result.case_id = shown(case["case_id"])
    return case


def _report(item: ingest.Evidence, result: Result) -> dict | None:
    """Treść ``report.json`` po walidacji kontraktu ``poc-1``; ``None`` (z problemem), gdy jej nie da się użyć."""
    try:
        document = _json(item.content)
    except (ValueError, RecursionError):
        result.add(report.REPORT_JSON, "INVALID_JSON")
        return None
    try:  # treść nieufna: dowolny błąd budowy raportu znaczy „niezgodny z kontraktem”; komunikatu (z wartościami) nie powtarzamy
        built = models.Report.from_dict(document)
        canonical = built.to_dict() == document
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
        result.add(report.REPORT_JSON, "INVALID_REPORT")
        return None
    if not canonical:
        result.add(report.REPORT_JSON, "NOT_CANONICAL")
    return document


def _compare_case(case: dict, document: dict, result: Result) -> None:
    for name, expected in (("case_id", document["case_id"]), ("tool", document["tool"]), ("tool_version", document["tool_version"]),
                           ("assessment", document["assessment"]), ("analysis_finished_at_utc", document["analyzed_at_utc"]),
                           ("exit_code", cli.exit_code(document))):
        if case.get(name) != expected:
            result.add(report.CASE_JSON, "CASE_MISMATCH", name)


def _recomputed(case: dict, document: dict) -> dict[str, str]:
    """SHA-256 plików, które narzędzie tej wersji zapisałoby z tego ``report.json`` i ``case.json``."""
    pseudonymized = case["flags"].get("pseudonymize", False) is True
    files = {report.REPORT_JSON: outputs.json_chunks(document),
             report.REPORT_HTML: [outputs.encode(report.render_html(document, pseudonymized=pseudonymized))],
             **outputs.streams(document, case["exit_code"])}
    return {name: _digest(chunks) for name, chunks in files.items()}


def verify(directory: Path, *, max_file_bytes: int = MAX_FILE_BYTES) -> Result:
    """Sprawdza katalog wyników; zgłasza ``Unusable``, gdy brak wiarygodnego odniesienia (``case.json``)."""
    entries, result = _read(Path(directory), max_file_bytes)
    case = _case(entries, result)
    listed: dict[str, str] = case["outputs"]
    expected = {report.CASE_JSON, *listed}
    for name in sorted(set(report.RESULT_FILES) - expected):
        result.add(name, "NOT_LISTED")
    for name in sorted(set(entries) - expected):
        result.add(name, "EXTRA")
    actual: dict[str, str] = {}
    for name in sorted(listed):
        item = entries.get(name)
        problem = "MISSING" if item is None else _problem_of(item)
        if problem is not None:
            result.add(name, problem)
            continue
        result.checked += 1
        actual[name] = item.sha256
        if item.sha256 != listed[name]:
            result.add(name, "MODIFIED")
    result.checked += 1  # case.json
    document = None
    if report.REPORT_JSON in actual:
        item = entries[report.REPORT_JSON]
        if item.content is None:
            result.add(report.REPORT_JSON, "TOO_LARGE")
        else:
            document = _report(item, result)
    if document is None:
        result.notes.append("report.json nie został zwalidowany, więc widoków nie porównano z jego treścią")
        return result
    _compare_case(case, document, result)
    if case["tool_version"] != __version__:
        result.notes.append(f"wynik innej wersji narzędzia ({shown(case['tool_version'])}, bieżąca {__version__}): "
                            "widoki sprawdzono tylko skrótami z case.json, bez ponownego wyliczenia z report.json")
        return result
    for name, digest in _recomputed(case, document).items():
        if name in actual and actual[name] == listed[name] != digest:  # plik zmieniony względem case.json już zgłoszono
            result.add(name, "INCONSISTENT")
    return result
