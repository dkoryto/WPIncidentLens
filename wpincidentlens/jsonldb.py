"""Ścisły, strumieniowy adapter eksportu bazy w JSONL. Niczego nie wykonuje (ADR 0006 pkt 3 i 9).

Kontrakt: jeden obiekt JSON na wiersz pliku, dokładnie dwa klucze::

    {"table": "<nazwa>", "row": {"<kolumna>": <wartość>, ...}}

Nazwy tabel i kolumn to ``[A-Za-z0-9_$]{1,64}``; wartość to łańcuch, liczba albo ``null``. Liczba zachowuje swój
zapis tekstowy z pliku (bez zamiany na ``int``/``float``). Wiersz niezgodny z kontraktem jest odrzucany i liczony
pod swoim powodem — wywołujący zamienia liczniki na lukę pokrycia. Format wybiera operator; parser nie zgaduje go po treści.

Interfejs jak ``sqldump.DumpParser``: ``feed`` dostaje kolejne porcje bajtów i oddaje wiersze
``(tabela, kolumny, komórki, numer)``; numer to numer wiersza pliku (od 1). Bufor obejmuje najwyżej jeden wiersz
pliku i jedną porcję: wiersz dłuższy niż ``MAX_LINE_BYTES`` jest pomijany do najbliższego znaku końca wiersza bez buforowania.
Limit czasu sesji (``expired``) jest sprawdzany przy każdej porcji i co ``CLOCK_EVERY_LINES`` wierszy; po jego upływie
dalsza część pliku nie jest analizowana.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

MAX_LINE_BYTES = 16 * 1024 * 1024
MAX_TABLES = 5000  # różnych nazw tabel zapamiętanych do raportu
MAX_COLUMNS = 1000  # kolumn w jednym wierszu; tabela WordPressa ma ich kilkanaście
CLOCK_EVERY_LINES = 256  # co tyle wierszy (oprócz każdej porcji ``feed``) parser sprawdza limit czasu sesji
_NAME = re.compile(r"[A-Za-z0-9_$]{1,64}")
_BLANK = b" \t\r"  # białe znaki JSON (\n dzieli wiersze); inne, np. \v, czynią wiersz niepoprawnym

# Powód odrzucenia → opis do luki pokrycia.
REASONS = {
    "too_long": f"dłuższy niż {MAX_LINE_BYTES} B",
    "not_utf8": "niepoprawne UTF-8",
    "not_json": "niepoprawny JSON",
    "duplicate_key": "powtórzony klucz",
    "shape": f'inna budowa niż {{"table": …, "row": {{…}}}} (1–{MAX_COLUMNS} kolumn)',
    "bad_name": "niepoprawna nazwa tabeli lub kolumny",
    "bad_value": "wartość inna niż łańcuch, liczba lub null",
}


class _Number(str):
    """Zapis liczby z pliku; odróżnia liczbę od łańcucha tam, gdzie kontrakt wymaga łańcucha (nazwa tabeli)."""


class _Rejected(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    """Obiekt JSON bez powtórzonych kluczy: ``json`` po cichu zostawiłby ostatnią wartość."""
    result = dict(pairs)
    if len(result) != len(pairs):
        raise _Rejected("duplicate_key")
    return result


def _constant(name: str) -> object:
    """``NaN``, ``Infinity`` i ``-Infinity`` nie są poprawnym JSON."""
    raise _Rejected("bad_value")


def _scalar(value: object) -> bool:
    """Liczby są tu już tekstem (``_Number``); łańcuch nie może zawierać samotnego surogatu."""
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


@dataclass
class JsonlParser:
    """Stan jednego pliku JSONL. ``wanted(tabela)`` wybiera tabele, których wiersze są oddawane; pozostałe są tylko
    sprawdzane i liczone. Po ``close()`` ``rejected`` i ``first_rejected`` opisują, czego parser nie przyjął."""
    wanted: Callable[[str], bool] | None = None
    max_line: int = MAX_LINE_BYTES
    expired: Callable[[], bool] | None = None  # limit czasu sesji (``ingest.Session.expired``)
    stopped_at: int | None = None  # ostatni przeanalizowany wiersz pliku, gdy limit czasu przerwał plik
    rows: int = 0
    tables: set[str] = field(default_factory=set)
    rejected: Counter = field(default_factory=Counter)        # powód → liczba odrzuconych wierszy pliku
    first_rejected: dict[str, int] = field(default_factory=dict)  # powód → numer pierwszego takiego wiersza
    _buf: bytearray = field(default_factory=bytearray)
    _line: int = 0             # numer ostatniego zakończonego wiersza pliku
    _skipping: bool = False    # bieżący wiersz przekroczył limit; czekamy na jego koniec

    def feed(self, chunk: bytes) -> list[tuple[str, list[str], list[str | None], int]]:
        out: list = []
        if self.stopped_at is not None or self._out_of_time():
            return out
        start = 0
        while (end := chunk.find(b"\n", start)) >= 0:
            if self._line % CLOCK_EVERY_LINES == 0 and self._line and self._out_of_time():
                return out
            if self._skipping:
                self._skipping = False
                self._line += 1
            elif len(self._buf) + end - start > self.max_line:
                self._buf.clear()
                self._reject("too_long", self._line + 1)
                self._line += 1
            else:
                self._buf += chunk[start:end]
                self._line += 1
                self._take(bytes(self._buf), out)
                self._buf.clear()
            start = end + 1
        if not self._skipping and start < len(chunk):
            if len(self._buf) + len(chunk) - start > self.max_line:
                self._buf.clear()
                self._skipping = True
                self._reject("too_long", self._line + 1)
            else:
                self._buf += chunk[start:]
        return out

    def close(self) -> list[tuple[str, list[str], list[str | None], int]]:
        """Ostatni wiersz bez znaku końca wiersza jest przyjmowany jak każdy inny."""
        out: list = []
        if self.stopped_at is not None:
            return out
        if self._skipping:
            self._skipping = False
            self._line += 1
        elif self._buf:
            self._line += 1
            self._take(bytes(self._buf), out)
            self._buf.clear()
        return out

    def _out_of_time(self) -> bool:
        """Po limicie czasu reszta pliku nie jest analizowana (bufor jest zwalniany); odczyt i skrót idą dalej."""
        if self.expired is None or not self.expired():
            return False
        self.stopped_at = self._line
        self._buf.clear()
        self._skipping = False
        return True

    def _reject(self, reason: str, line: int) -> None:
        self.rejected[reason] += 1
        self.first_rejected.setdefault(reason, line)

    def _take(self, line: bytes, out: list) -> None:
        if line.endswith(b"\r"):
            line = line[:-1]
        if not line.strip(_BLANK):
            return
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            self._reject("not_utf8", self._line)
            return
        try:
            table, row = self._parse(text)
        except _Rejected as rejected:
            self._reject(rejected.reason, self._line)
            return
        self.rows += 1
        if len(self.tables) < MAX_TABLES:
            self.tables.add(table)
        if self.wanted is None or self.wanted(table):
            out.append((table, list(row), [None if cell is None else str(cell) for cell in row.values()], self._line))

    @staticmethod
    def _parse(text: str) -> tuple[str, dict]:
        try:
            document = json.loads(text, parse_int=_Number, parse_float=_Number, parse_constant=_constant, object_pairs_hook=_pairs)
        except _Rejected:
            raise
        except (ValueError, RecursionError):
            raise _Rejected("not_json") from None
        if not (isinstance(document, dict) and document.keys() == {"table", "row"}
                and type(document["table"]) is str and isinstance(document["row"], dict)
                and 0 < len(document["row"]) <= MAX_COLUMNS):
            raise _Rejected("shape")
        table, row = document["table"], document["row"]
        if not all(_NAME.fullmatch(name) for name in (table, *row)):
            raise _Rejected("bad_name")
        if not all(map(_scalar, row.values())):
            raise _Rejected("bad_value")
        return table, row

