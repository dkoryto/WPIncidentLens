"""Odczyt danych serializowanych PHP (``serialize()``) jako DANYCH. Niczego nie odtwarza i niczego nie wykonuje.

Obsługiwane: ``N;``, ``b:``, ``i:``, ``d:``, ``s:n:"…";`` i ``a:n:{…}``. Wynik to wartości Pythona:
``None``, ``bool``, ``int``, ``float``, ``str`` oraz ``dict`` (tablica PHP, kolejność kluczy jak w danych).

Obiekty (``O:``), serializacja własna (``C:``), wyliczenia (``E:``) i referencje (``R:``, ``r:``) nie są
odtwarzane ani rozwiązywane: w ich miejscu zostaje znacznik ``Opaque``. Nazwa klasy to nieufny tekst —
jest pomijana, nigdzie nie trafia i niczego się po niej nie szuka.

Długości łańcuchów PHP to BAJTY. Tekst wejściowy jest kodowany do UTF-8 i długość musi trafić dokładnie
w zamykające ``";``. Jeżeli zrzut przekodowano z innego zestawu znaków (np. tabela latin1 zrzucona jako
UTF-8), długości łańcuchów ze znakami spoza ASCII przestają się zgadzać: to ``SerializedError``, nigdy
zgadywanie długości w znakach. Tak samo zachowuje się ``unserialize()`` na tych samych bajtach.

Czas liniowy względem długości wejścia; bez rekurencji (jawny stos z limitem głębokości).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

MAX_BYTES = 1024 * 1024
MAX_DEPTH = 32
MAX_ITEMS = 50_000


class SerializedError(ValueError):
    """Wartość nie jest poprawnym, obsługiwanym zapisem ``serialize()`` albo przekracza limit."""


@dataclass(frozen=True)
class Opaque:
    """Miejsce po elemencie, którego parser celowo nie odtwarza. Nie niesie nazwy klasy ani treści."""
    kind: str  # "object" | "custom" | "enum" | "reference"


Value = None | bool | int | float | str | dict | Opaque

_UINT = re.compile(rb"[0-9]{1,10}")
_INT = re.compile(rb"[+-]?[0-9]{1,20}")
_FLOAT = re.compile(rb"[+-]?(?:[0-9]{1,40}(?:\.[0-9]{0,40})?|\.[0-9]{1,40})(?:[eE][+-]?[0-9]{1,5})?|-?INF|NAN")
_INT_KEY = re.compile(r"0|-?[1-9][0-9]{0,18}")
_INT64 = range(-2**63, 2**63)
_OPEN = object()   # wartość jeszcze niegotowa: właśnie otwarto tablicę albo obiekt
_NO_KEY = object()


class _Frame:
    """Otwarta tablica (``items`` to słownik) albo obiekt (``items`` to ``None``: zawartość jest sprawdzana i porzucana)."""
    __slots__ = ("items", "left", "key")

    def __init__(self, items: dict | None, left: int) -> None:
        self.items, self.left, self.key = items, left, _NO_KEY


def _expect(data: bytes, pos: int, literal: bytes) -> int:
    if data[pos:pos + len(literal)] != literal:
        raise SerializedError(f"oczekiwano {literal.decode('ascii')!r} na pozycji {pos}")
    return pos + len(literal)


def _number(data: bytes, pos: int, pattern: re.Pattern[bytes], end: bytes) -> tuple[bytes, int]:
    found = pattern.match(data, pos)
    if found is None:
        raise SerializedError(f"oczekiwano liczby na pozycji {pos}")
    return found.group(), _expect(data, found.end(), end)


def _quoted(data: bytes, pos: int) -> tuple[bytes, int]:
    """``<długość>:"<bajty>"`` — zwraca bajty i pozycję za zamykającym cudzysłowem."""
    length, pos = _number(data, pos, _UINT, b':"')
    end = pos + int(length)
    if data[end:end + 1] != b'"':
        raise SerializedError(f"długość łańcucha na pozycji {pos} nie zgadza się z danymi (długości PHP są w bajtach)")
    return data[pos:end], end + 1


def _key(value: object, pos: int) -> int | str:
    """Klucz tablicy PHP: liczba albo łańcuch; łańcuch z zapisem liczby całkowitej PHP zamienia na liczbę."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise SerializedError(f"klucz tablicy przed pozycją {pos} nie jest liczbą ani łańcuchem")
    if isinstance(value, str) and _INT_KEY.fullmatch(value) and int(value) in _INT64:
        return int(value)
    return value


def _scalar(data: bytes, pos: int) -> tuple[Value, int]:
    tag = data[pos:pos + 2]
    if tag == b"N;":
        return None, pos + 2
    if tag == b"b:":
        if data[pos + 2:pos + 4] not in (b"0;", b"1;"):
            raise SerializedError(f"niepoprawna wartość logiczna na pozycji {pos}")
        return data[pos + 2:pos + 3] == b"1", pos + 4
    if tag == b"i:":
        digits, pos = _number(data, pos + 2, _INT, b";")
        return int(digits), pos
    if tag == b"d:":
        digits, pos = _number(data, pos + 2, _FLOAT, b";")
        return float(digits.decode("ascii")), pos
    if tag == b"s:":
        raw, end = _quoted(data, pos + 2)
        # Wycinek zaczyna się i kończy na granicy znaku: po rozciętym znaku stałby bajt kontynuacji, nie cudzysłów.
        return raw.decode("utf-8", "surrogatepass"), _expect(data, end, b";")
    if tag == b"E:":
        _, end = _quoted(data, pos + 2)
        return Opaque("enum"), _expect(data, end, b";")
    if tag in (b"R:", b"r:"):
        _, pos = _number(data, pos + 2, _UINT, b";")
        return Opaque("reference"), pos
    if tag == b"C:":
        _, pos = _quoted(data, pos + 2)
        length, pos = _number(data, _expect(data, pos, b":"), _UINT, b":{")
        return Opaque("custom"), _expect(data, pos + int(length), b"}")
    raise SerializedError(f"nieobsługiwany albo niepoprawny element na pozycji {pos}")


def parse(text: str, *, max_bytes: int = MAX_BYTES, max_depth: int = MAX_DEPTH, max_items: int = MAX_ITEMS) -> Value:
    """Zwraca wartość zapisaną w ``text`` albo zgłasza ``SerializedError`` (składnia, limit, śmieci po wartości)."""
    if not isinstance(text, str):
        raise SerializedError("oczekiwano tekstu")
    if len(text) > max_bytes:
        raise SerializedError(f"wartość dłuższa niż {max_bytes} B")
    data = text.encode("utf-8", "surrogatepass")
    if len(data) > max_bytes:
        raise SerializedError(f"wartość dłuższa niż {max_bytes} B")
    pos, budget, stack = 0, max_items, []
    while True:
        if data[pos:pos + 2] in (b"a:", b"O:"):
            is_array = data[pos:pos + 1] == b"a"
            pos += 2
            if not is_array:
                _, pos = _quoted(data, pos)  # nazwa klasy: pominięta, nigdzie nie zapisana
                pos = _expect(data, pos, b":")
            count, pos = _number(data, pos, _UINT, b":{")
            budget -= int(count)
            if len(stack) >= max_depth:
                raise SerializedError(f"zagnieżdżenie głębsze niż {max_depth}")
            stack.append(_Frame({} if is_array else None, int(count)))
            value = _OPEN
        else:
            value, pos = _scalar(data, pos)
            budget -= 1
        if budget < 0:
            raise SerializedError(f"więcej niż {max_items} elementów")
        while True:  # oddaje gotową wartość otwartej tablicy; zamyka tablice, w których nic już nie zostało
            if value is _OPEN:
                frame = stack[-1]
                if frame.left:
                    break
                pos = _expect(data, pos, b"}")
                stack.pop()
                value = Opaque("object") if frame.items is None else frame.items
            if not stack:
                if pos != len(data):
                    raise SerializedError(f"nieoczekiwane dane po wartości, od pozycji {pos}")
                return value
            frame = stack[-1]
            if frame.key is _NO_KEY:
                frame.key = _key(value, pos)
                break
            if frame.items is not None:
                frame.items[frame.key] = value  # powtórzony klucz: wygrywa ostatni, jak w PHP
            frame.key = _NO_KEY
            frame.left -= 1
            if frame.left:
                break
            value = _OPEN


def truthy(value: Value) -> bool:
    """Prawdziwość wartości według reguł PHP (``"0"``, ``""``, ``0``, ``0.0``, pusta tablica i ``null`` są fałszem)."""
    if isinstance(value, Opaque):
        return True
    return bool(value) and value != "0"
