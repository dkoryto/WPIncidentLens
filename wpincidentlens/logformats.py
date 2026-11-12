"""Czyste parsery jednego wiersza logu HTTP (ADR 0007 pkt 1, 4 i 5). Bez dostępu do plików, niczego nie wykonują.

Formaty są jawne i wersjonowane (``FORMATS``): wybiera je operator flagą ``--log-format``, parser nie zgaduje
formatu po treści. Wynik ``parse`` to ``HttpRecord`` albo nazwa powodu odrzucenia (klucz ``REASONS``).

- ``combined@1``: ``%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"`` (Apache ``combined``, Nginx ``combined``);
- ``common@1``: ``%h %l %u %t "%r" %>s %b``;
- ``json@1``: jeden obiekt JSON na wiersz (kontrakt w ``docs/RULES.md`` i w ``_json_record``).

Pola dopisane po polach formatu (po spacji) są ignorowane, także ``X-Forwarded-For``: formaty tekstowe nie niosą
adresu z nagłówka, którego można by użyć (pkt 5). Wszystkie wyrażenia mają kwantyfikatory zaborcze, więc dopasowanie
nie wraca i jego czas jest liniowy względem długości wiersza (S-08).
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import NamedTuple
from datetime import datetime, timedelta, timezone

from . import models

FORMATS = {"combined": "combined@1", "common": "common@1", "json": "json@1"}  # nazwa flagi → identyfikator z wersją
MAX_LINE_BYTES = 64 * 1024
MAX_PATH_CHARS = 4096
MAX_ADDRESS_CHARS = 255
MAX_FORWARDED_CHARS = 2048
MAX_TIME_CHARS = 64

# Powód odrzucenia → opis do luki pokrycia.
REASONS = {
    "too_long": f"dłuższy niż {MAX_LINE_BYTES} B",
    "layout": "układ pól inny niż w wybranym formacie",
    "request_line": 'wiersz żądania inny niż "METODA cel [HTTP/x.y]"',
    "bad_client": "adres klienta nie jest adresem IP ani nazwą hosta",
    "bad_number": "status spoza 100–599 albo liczba bajtów spoza zakresu",
    "not_json": "niepoprawny JSON",
    "duplicate_key": "powtórzony klucz",
    "shape": "brak wymaganego pola albo pole złego typu",
    "bad_value": "wartość złożona, NaN, nieskończoność albo samotny surogat",
}

_QUOTED = r'"(?:[^"\\]++|\\.)*+"'
_PREFIX = (r'(?P<client>[^ ]++) [^ ]++ [^ ]++ \[(?P<time>[^\]]*+)\] "(?P<request>(?:[^"\\]++|\\.)*+)" '
           r'(?P<status>[0-9]++) (?P<bytes>[0-9]++|-)')
_TAIL = r"(?: .*+)?"
_LAYOUTS = {
    "common": re.compile(_PREFIX + _TAIL),
    "combined": re.compile(_PREFIX + f" {_QUOTED} {_QUOTED}" + _TAIL),
}
_METHOD = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}")  # token z RFC 7230; PHP dostaje każdą metodę
_PROTOCOL = re.compile(r"HTTP/[0-9](?:\.[0-9])?")
_HOSTNAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}+)")
_CLF_TIME = re.compile(r"([0-9]{2})/([A-Z][a-z]{2})/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2}) ([+-])([0-9]{2})([0-9]{2})")
_ISO_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})?")
_MONTHS = {name: number for number, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}
SCHEME_AUTHORITY = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]{0,31})://(?P<authority>[^/?#]*+)")
_SLASHES = re.compile(r"/{2,}")
_PERCENT = re.compile(rb"%([0-9A-Fa-f]{2})")
_ENCODED_SLASH = re.compile(rb"%2[Ff]")
# Ucieczki, którymi Apache (``ap_escape_logitem``) i Nginx zapisują w ``%r`` bajty spoza ASCII drukowalnego.
_LOG_ESCAPE = re.compile(rb'\\(?:x([0-9A-Fa-f]{2})|(["\\bnrtv]))')
_LOG_ESCAPED_BYTES = {b'"': b'"', b"\\": b"\\", b"b": b"\b", b"n": b"\n", b"r": b"\r", b"t": b"\t", b"v": b"\v"}
_MAX_BYTES_DIGITS = 18  # liczba bajtów odpowiedzi poniżej 10**18: mieści się w int64 raportu
_JSON_REQUIRED = {"time": str, "remote_addr": str, "method": str, "uri": str, "status": int}
_JSON_OPTIONAL = {"bytes", "forwarded_for"}


@dataclass(frozen=True)
class HttpRecord:
    """Fakty jednego wiersza logu. ``client`` to adres połączenia (nie z nagłówka); ``target`` to surowy cel żądania."""
    client: str
    timestamp_raw: str
    timestamp_utc: str | None  # None: czasu nie da się jednoznacznie sprowadzić do UTC (np. brak strefy)
    precision: str             # second | millisecond | microsecond
    method: str
    target: str
    status: int
    bytes: int | None
    forwarded_for: str | None = None  # tylko json@1
    escaped: bool = False  # cel z ucieczkami logu Apache/Nginx (\xNN, \", \\): formaty tekstowe


class _Rejected(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def parse(fmt: str, line: str) -> HttpRecord | str:
    """Jeden wiersz (bez znaku końca wiersza) w formacie ``fmt`` (klucz ``FORMATS``) → rekord albo powód odrzucenia."""
    try:
        return _json_record(line) if fmt == "json" else _text_record(fmt, line)
    except _Rejected as rejected:
        return rejected.reason


# --- formaty tekstowe ---------------------------------------------------------------------------

def _text_record(fmt: str, line: str) -> HttpRecord:
    found = _LAYOUTS[fmt].fullmatch(line)
    if found is None:
        raise _Rejected("layout")
    method, target = _request_line(found["request"])
    stamp = found["time"][:MAX_TIME_CHARS]
    return HttpRecord(_client(found["client"]), stamp, _clf_time_utc(stamp), "second", method, target,
                      _status(int(found["status"]) if len(found["status"]) == 3 else 0), _size(found["bytes"]), escaped=True)


def _request_line(request: str) -> tuple[str, str]:
    """``METODA cel HTTP/x.y`` albo ``METODA cel`` (HTTP/0.9). Cel z białym znakiem w środku jest odrzucany."""
    parts = request.split(" ")
    if not (len(parts) == 2 or (len(parts) == 3 and _PROTOCOL.fullmatch(parts[2]))):
        raise _Rejected("request_line")
    method, target = parts[0], parts[1]
    if not (_METHOD.fullmatch(method) and target and target.isprintable() and not any(char.isspace() for char in target)):
        raise _Rejected("request_line")
    return method, target


def _client(text: str) -> str:
    """Adres połączenia: IP w postaci kanonicznej albo nazwa hosta (``HostnameLookups``); nazwa nigdy nie jest zaufanym proxy."""
    address = ip_or_none(text)
    if address is not None:
        return str(address)
    if len(text) <= MAX_ADDRESS_CHARS and _HOSTNAME.fullmatch(text):
        return text
    raise _Rejected("bad_client")


def _status(value: int) -> int:
    if not 100 <= value <= 599:
        raise _Rejected("bad_number")
    return value


def _size(text: str) -> int | None:
    if text == "-":
        return None
    if len(text) > _MAX_BYTES_DIGITS:
        raise _Rejected("bad_number")
    return int(text)


def _clf_time_utc(stamp: str) -> str | None:
    """``dd/Mon/rrrr:gg:mm:ss ±hhmm`` jako UTC; nazwy miesięcy angielskie niezależnie od locale procesu."""
    found = _CLF_TIME.fullmatch(stamp)
    if found is None or found[2] not in _MONTHS:
        return None
    day, _, year, hour, minute, second, sign, zone_hours, zone_minutes = found.groups()
    try:
        offset = timedelta(hours=int(zone_hours), minutes=int(zone_minutes))
        zone = timezone(-offset if sign == "-" else offset)
        return models.utc_iso(datetime(int(year), _MONTHS[found[2]], int(day), int(hour), int(minute), int(second), tzinfo=zone))
    except (ValueError, OverflowError):
        return None


# --- json@1 -------------------------------------------------------------------------------------

def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):  # json po cichu zostawiłby ostatnią wartość
        raise _Rejected("duplicate_key")
    return result


def _constant(name: str) -> object:
    raise _Rejected("bad_value")  # NaN, Infinity, -Infinity


def _encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _json_record(line: str) -> HttpRecord:
    """Kontrakt ``json@1``: obiekt z polami ``time`` (ISO 8601), ``remote_addr``, ``method``, ``uri`` (łańcuchy),
    ``status`` (liczba całkowita 100–599), opcjonalnie ``bytes`` (liczba całkowita ≥ 0 albo null) i ``forwarded_for``
    (łańcuch albo null). Inne pola są dozwolone i ignorowane, o ile mają wartość prostą."""
    try:
        document = json.loads(line, parse_constant=_constant, object_pairs_hook=_pairs)
    except _Rejected:
        raise
    except (ValueError, RecursionError):
        raise _Rejected("not_json") from None
    if not isinstance(document, dict):
        raise _Rejected("shape")
    for value in document.values():
        if isinstance(value, (dict, list)) or (isinstance(value, str) and not _encodable(value)):
            raise _Rejected("bad_value")
    for name, kind in _JSON_REQUIRED.items():
        if type(document.get(name)) is not kind:  # ``type``: wartość logiczna nie jest statusem
            raise _Rejected("shape")
    size, forwarded = document.get("bytes"), document.get("forwarded_for")
    if not (size is None or type(size) is int) or not (forwarded is None or isinstance(forwarded, str)):
        raise _Rejected("shape")
    if size is not None and not 0 <= size < 10**_MAX_BYTES_DIGITS:
        raise _Rejected("bad_number")
    method, target = document["method"], document["uri"]
    if not (_METHOD.fullmatch(method) and target and target.isprintable() and not any(char.isspace() for char in target)):
        raise _Rejected("request_line")
    stamp = document["time"][:MAX_TIME_CHARS]
    moment, precision = _iso_time_utc(stamp)
    return HttpRecord(_client(document["remote_addr"]), stamp, moment, precision, method, target, _status(document["status"]),
                      size, forwarded or None)


def _iso_time_utc(stamp: str) -> tuple[str | None, str]:
    """Czas ISO 8601 → (UTC albo None, precyzja). Czas bez przesunięcia strefy zostaje surowy (``None``), jak w combined."""
    found = _ISO_TIME.fullmatch(stamp)
    if found is None:
        return None, "second"
    digits = len(found[1] or "")
    precision = "second" if not digits else "millisecond" if digits <= 3 else "microsecond"
    if found[2] is None:
        return None, precision
    try:
        return models.utc_iso(datetime.fromisoformat(stamp)), precision
    except (ValueError, OverflowError):
        return None, precision


# --- ścieżka i adres klienta --------------------------------------------------------------------

class Resolved(NamedTuple):
    """Wynik ``resolve_target``: ścieżka (``None``, gdy nie da się jej przypisać do pliku), czy bajty ścieżki po
    dekodowaniu nie były poprawnym UTF-8 (``lossy``) i zdekodowany tekst celu bez query (do oceny, czy cel
    nieprzypisany wygląda na żądanie kodu)."""
    path: str | None
    lossy: bool
    text: str


def request_path(target: str, escaped: bool = False) -> str | None:
    """Cel żądania → ścieżka względna bez wiodącego ``/`` (pkt 4); ``None``, gdy ścieżki nie da się bezpiecznie ustalić."""
    return resolve_target(target, escaped).path


def resolve_target(target: str, escaped: bool = False) -> Resolved:
    """Cel żądania → ``Resolved`` (ADR 0007 pkt 4).

    Kolejno: usunięcie schematu i hosta (forma absolutna), query i fragmentu; dla formatów tekstowych (``escaped``)
    odwrócenie ucieczek logu (``\\xNN``, ``\\"``, ``\\\\``, ``\\n`` …) na bajtach; jednokrotne dekodowanie ``%XX``
    na bajtach i UTF-8 (bajty niepoprawne → znak zastępczy, ``lossy``); scalenie ``//``; rozwiązanie segmentów
    ``.`` i ``..`` tak jak serwer przed odwzorowaniem na plik. ``path`` jest ``None``, gdy ``..`` wychodzi ponad katalog
    główny, ścieżka zawiera bajt NUL albo zakodowany ukośnik ``%2F`` (domyślnie odrzucany przez Apache), jest dłuższa
    niż ``MAX_PATH_CHARS`` albo cel ma inną formę (np. ``*``). Inne znaki sterujące i formatujące zostają: wywołujący
    neutralizuje je przed zapisem do raportu. Wielkość liter zostaje; o rozszerzeniu decydują reguły bez względu na nią.
    """
    if (authority := SCHEME_AUTHORITY.match(target)) is not None:
        target = target[authority.end():] or "/"
    cut = min((at for at in (target.find("?"), target.find("#")) if at >= 0), default=len(target))
    raw = target[:cut].encode("utf-8", "surrogatepass")
    if escaped:
        raw = _LOG_ESCAPE.sub(_log_byte, raw)
    decoded_bytes = _PERCENT.sub(lambda found: bytes((int(found[1], 16),)), raw)
    try:
        decoded, lossy = decoded_bytes.decode("utf-8"), False
    except UnicodeDecodeError:
        decoded, lossy = decoded_bytes.decode("utf-8", "replace"), True
    if (not raw.startswith(b"/") or len(decoded) > MAX_PATH_CHARS or "\0" in decoded
            or _ENCODED_SLASH.search(raw) is not None):
        return Resolved(None, lossy, decoded)
    resolved: list[str] = []
    for segment in _SLASHES.sub("/", decoded).split("/")[1:]:
        if segment == "..":
            if not resolved:
                return Resolved(None, lossy, decoded)
            resolved.pop()
        elif segment not in ("", "."):
            resolved.append(segment)
    return Resolved("/".join(resolved), lossy, decoded)


def _log_byte(found: re.Match[bytes]) -> bytes:
    return bytes((int(found[1], 16),)) if found[1] is not None else _LOG_ESCAPED_BYTES[found[2]]


def ip_or_none(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Adres IP w ścisłej postaci (bez portu, bez strefy ``%eth0``); inaczej ``None``."""
    if len(text) > 64 or "%" in text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


FORWARDED_REJECTED = "connection_forwarded_for_rejected"


def client_address(record: HttpRecord, trusted: Iterable[Network]) -> tuple[str, str, bool]:
    """Adres klienta według pkt 5: (adres, podstawa, czy ``forwarded_for`` zaufanego proxy odrzucono).

    Nagłówek jest brany pod uwagę tylko wtedy, gdy format go niesie i adres połączenia należy do zaufanej sieci.
    Klientem jest wtedy ostatni od prawej adres spoza zaufanych; gdy cały łańcuch jest zaufany — pierwszy od lewej.
    Nagłówek dłuższy niż ``MAX_FORWARDED_CHARS`` albo niepoprawny wpis przed znalezieniem klienta: zostaje adres
    połączenia z podstawą ``FORWARDED_REJECTED``. Nagłówka nie skraca się: wpisy dopisane przez zaufane proxy są
    po prawej, więc ucięcie dowolnej strony mogłoby zostawić adres podstawiony przez klienta.
    """
    networks = tuple(trusted)
    if not (record.forwarded_for and networks and _within(ip_or_none(record.client), networks)):
        return record.client, "connection", False
    if len(record.forwarded_for) > MAX_FORWARDED_CHARS:
        return record.client, FORWARDED_REJECTED, True
    chain = [entry.strip() for entry in record.forwarded_for.split(",")]
    for entry in reversed(chain):
        address = ip_or_none(entry)
        if address is None:
            return record.client, FORWARDED_REJECTED, True
        if not _within(address, networks):
            return str(address), "forwarded_for_via_trusted_proxy", False
    return str(ip_or_none(chain[0])), "forwarded_for_via_trusted_proxy", False


def _within(address: ipaddress.IPv4Address | ipaddress.IPv6Address | None, networks: tuple[Network, ...]) -> bool:
    if address is None:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return any(address.version == network.version and address in network for network in networks)
