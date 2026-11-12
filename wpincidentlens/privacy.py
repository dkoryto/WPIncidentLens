"""Redakcja i pseudonimizacja raportu w jednym miejscu (ADR 0008 pkt 4–5, ADR 0002 B8). Bez dostępu do plików.

``sanitize`` przebudowuje gotowy ``models.Report``: każdy tekst swobodny przechodzi przez ``redact.redact``, a z
``Pseudonymizer`` adresy IP klientów, loginy i ``user_id`` kont zastępują pseudonimy. Obiekty są tworzone na nowo,
więc identyfikatory treściowe wynikają z treści po redakcji, a ``Report`` sprawdza cały kontrakt jeszcze raz.

Granica redakcji (decyzja domyślna: redagować):

- atrybut obserwacji jest **strukturalny** (bez redakcji) tylko wtedy, gdy jego nazwa jest na liście dla danego
  rodzaju obserwacji (``_STRUCTURAL``) i wartość pasuje do wzorca tego atrybutu (np. skrót SHA-256 to 64 cyfry
  szesnastkowe); każdy inny tekst, także atrybut nieznany, jest redagowany;
- atrybuty **tożsamości** (``client_ip``, ``username``, ``user_id``) nigdy nie przechodzą przez ``redact``: login
  w postaci adresu e-mail musi pozostać rozróżnialny. Chroni je wyłącznie pseudonimizacja;
- liczby, wartości logiczne, ``location``, czasy, identyfikatory, ``rule_id``, enumy, dowody i oś czasu (pola
  narzędzia: zdarzenie to nazwa, źródło to ``ścieżka:wiersz``) pozostają bez zmian;
- ``reason`` ustaleń, powody pokrycia i ``coverage_gaps`` są tekstem swobodnym.

Pseudonim to ``ip-``/``user-``/``uid-`` i 16 cyfr szesnastkowych (64 bity) HMAC-SHA256 z kluczem z ``secrets``
losowanym na jedno uruchomienie, trzymanym wyłącznie w pamięci obiektu ``Pseudonymizer``. Przed HMAC wartość jest
kanonizowana: adres IP do postaci ``ipaddress`` (IPv4 zmapowany w IPv6 → IPv4, IPv6 skrócony, małe litery), inna
wartość pola klienta (np. nazwa hosta) do małych liter; login i ``user_id`` dokładnie, jak w bazie.
W tekście swobodnym pseudonimizowane są: każdy literał adresu IPv4/IPv6, każde wystąpienie znanego loginu i wartości
pola klienta (jako osobne słowo) oraz identyfikatory po ``user_id``.

Pozostaje jawne także z pseudonimizacją: czas rejestracji konta i ``user_level``, nazwy w ścieżkach (``path``,
``location``, np. ``/author/<slug>/`` albo katalog w uploads), klucze lokalizacji (nazwa opcji, ``meta_key``),
domena adresu e-mail w cytatach, nazwy hostów w cytatach i ``operator_id`` w ``case.json``. Czteroczęściowy numer
wersji wygląda jak adres IPv4 i też zostanie zastąpiony.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import replace

from . import filerules, models, redact, wpdetect

PSEUDONYM_HEX = 16
IDENTITY = {"client_ip": "ip", "username": "user", "user_id": "uid"}  # atrybut → przedrostek pseudonimu
VARIANT = "redaction_variant"  # rozróżnia obserwacje, które po redakcji miałyby tę samą treść

_ANY = re.compile(r".*", re.S)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MD5 = re.compile(r"[0-9a-fA-F]{32}")
_TOKEN = re.compile(r"[A-Za-z0-9_.+@\-]{1,64}")  # enum, wersja, nazwa formatu (combined@1)
_DB_TIME = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
_LOGICAL_PATH = re.compile(r"(files|database|logs|baseline)/[^\0]{1,4096}")

_HTTP = {"path": _ANY, "method": _TOKEN, "client_ip_basis": _TOKEN, "log_format": _TOKEN, "timestamp_precision": _TOKEN}
_REFERENCE = {"reference_version": _TOKEN, "reference_file": _LOGICAL_PATH}
_STRUCTURAL: dict[str, Mapping[str, re.Pattern[str]]] = {
    "HTTP_REQUEST": _HTTP,
    "HTTP_REQUEST_FOR_PHP_IN_UPLOADS": _HTTP,
    "ADMINISTRATOR_ACCOUNT": {"registered": _DB_TIME, "role_value": _TOKEN},
    "FILE_DIFFERS_FROM_BASELINE": {"baseline_sha256": _SHA256, **_REFERENCE},
    "FILE_NOT_IN_BASELINE": {"file_class": _TOKEN, **_REFERENCE},
    "ENTRY_NOT_IN_BASELINE": {"file_class": _TOKEN, **_REFERENCE},
    "FILE_DIFFERS_FROM_CORE_MANIFEST": {"observed_sha256": _SHA256, "observed_md5": _MD5, "reference_md5": _MD5, **_REFERENCE},
    "FILE_NOT_IN_CORE_MANIFEST": _REFERENCE,
    "REFERENCE_ENTRY_NOT_READ": {"listed_in": _TOKEN, "listed_as": _TOKEN, **_REFERENCE},
    "BASELINE_ENTRY_NOT_IN_FILES": _REFERENCE,
    "CORE_MANIFEST_ENTRY_NOT_IN_FILES": {"reference_md5": _MD5, **_REFERENCE},
    **{kind: {"value": _TOKEN, "confidence": _TOKEN, "origin": _TOKEN}
       for kind in ("WP_VERSION_CANDIDATE", "WP_DB_VERSION_CANDIDATE", "WP_TABLE_PREFIX_CANDIDATE", wpdetect.LOCALE_KIND)},
    **{rule.kind: {"rule_version": _TOKEN} for rule in filerules.RULES.values()},
}

_IPV4 = r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w]|\.\d)"
_IPV6 = r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4})(?![\w:]|\.\d)"
_USER_IDS = re.compile(r"(\buser_id:? )([^\s,()…]+(?:, [^\s,()…]+)*)")
_WORD_EDGE_BEFORE, _WORD_EDGE_AFTER = r"(?<![\w.@+\-])", r"(?![\w@+\-]|\.\w)"
_ADDRESS = re.compile(f"{_IPV6}|{_IPV4}")


def _canonical_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return value.strip().lower()
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


class Pseudonymizer:
    """Pseudonimy jednego uruchomienia. Klucz nie wychodzi poza obiekt: brak go w ``repr`` i w komunikatach."""

    __slots__ = ("__key",)

    def __init__(self) -> None:
        self.__key = secrets.token_bytes(32)

    def __repr__(self) -> str:
        return "Pseudonymizer(klucz ukryty)"

    def pseudonym(self, attribute: str, value: str) -> str:
        prefix = IDENTITY[attribute]
        canonical = _canonical_address(value) if attribute == "client_ip" else value
        digest = hmac.new(self.__key, f"{prefix}\0{canonical}".encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()
        return f"{prefix}-{digest[:PSEUDONYM_HEX]}"


class _Text:
    """Przekształcenie tekstu swobodnego: pseudonimizacja (gdy włączona), potem redakcja."""

    def __init__(self, pseudonymizer: Pseudonymizer | None, report: models.Report) -> None:
        self.pseudonymizer = pseudonymizer
        self.pattern = None
        if pseudonymizer is None:
            return
        known: dict[str, str] = {}
        for observation in report.observations:
            for attribute in ("client_ip", "username"):
                value = observation.attributes.get(attribute)
                # Literał IP łapie wzorzec adresu; lista słów to tylko loginy i nazwy hostów, więc pozostaje krótka.
                if isinstance(value, str) and value.strip() and not (attribute == "client_ip" and _is_address(value)):
                    known[value] = pseudonymizer.pseudonym(attribute, value)
        self.known = known
        words = "|".join(re.escape(value) for value in sorted(known, key=lambda value: (-len(value), value)))
        alternatives = [f"(?P<word>{_WORD_EDGE_BEFORE}(?:{words}){_WORD_EDGE_AFTER})"] if words else []
        self.pattern = re.compile("|".join([*alternatives, f"(?P<ip>{_IPV6}|{_IPV4})"]))

    def _replace(self, found: re.Match[str]) -> str:
        if found.group("ip") is None:
            return self.known[found.group()]
        return self.pseudonymizer.pseudonym("client_ip", found.group()) if _is_address(found.group()) else found.group()

    def _user_ids(self, found: re.Match[str]) -> str:
        ids = (self.pseudonymizer.pseudonym("user_id", value) for value in found.group(2).split(", "))
        return found.group(1) + ", ".join(ids)

    def __call__(self, text: str) -> str:
        if self.pattern is not None:
            text = _USER_IDS.sub(self._user_ids, self.pattern.sub(self._replace, text))
        return redact.redact(text)


def is_structural(kind: str, attribute: str, value: object) -> bool:
    """Czy atrybut obserwacji pozostaje bez redakcji: nie-tekst albo nazwa z listy rodzaju i wartość zgodna ze wzorcem."""
    if not isinstance(value, str):
        return True
    pattern = _STRUCTURAL.get(kind, {}).get(attribute)
    return pattern is not None and pattern.fullmatch(value) is not None


def _attributes(observation: models.Observation, text: _Text) -> dict:
    cleaned = {}
    for name, value in observation.attributes.items():
        if name in IDENTITY and isinstance(value, str):
            cleaned[name] = value if text.pseudonymizer is None else text.pseudonymizer.pseudonym(name, value)
        elif is_structural(observation.kind, name, value):
            cleaned[name] = value
        else:
            cleaned[name] = text(value)
    return cleaned


def _observations(observations: Iterable[models.Observation], text: _Text) -> tuple[list[models.Observation], dict[str, str]]:
    """Obserwacje po redakcji i mapa starych identyfikatorów na nowe.

    Dwie różne obserwacje, które po redakcji miałyby tę samą treść (np. dwa sekrety w tym samym miejscu), dostają
    atrybut ``redaction_variant`` (1, 2, …, w porządku dawnych identyfikatorów), więc nie scalają się w raporcie.
    """
    rebuilt: dict[str, list[tuple[models.Observation, dict]]] = {}
    for observation in sorted(observations, key=lambda item: item.id):
        attributes = _attributes(observation, text)
        rebuilt.setdefault(replace(observation, attributes=attributes).id, []).append((observation, attributes))
    result, ids = [], {}
    for group in rebuilt.values():
        for number, (observation, attributes) in enumerate(group, start=1):
            if len(group) > 1:
                attributes = {**attributes, VARIANT: number}
            built = replace(observation, attributes=attributes)
            result.append(built)
            ids[observation.id] = built.id
    return result, ids


def sanitize(report: models.Report, pseudonymizer: Pseudonymizer | None = None) -> models.Report:
    """Raport po redakcji tekstów swobodnych i, z ``pseudonymizer``, po pseudonimizacji; ten sam kontrakt ``poc-1``."""
    text = _Text(pseudonymizer, report)
    observations, ids = _observations(report.observations, text)
    findings = {}
    for finding in report.findings:
        built = replace(finding, reason=text(finding.reason), observations=tuple(sorted({ids[ref] for ref in finding.observations})))
        findings.setdefault(built.id, built)
    coverage = {source: replace(entry, reasons=tuple(sorted({text(reason) for reason in entry.reasons})))
                for source, entry in report.coverage.items()}
    timeline = tuple(replace(event, observation_id=None if event.observation_id is None else ids[event.observation_id])
                     for event in report.timeline)
    return replace(report, observations=tuple(observations), findings=tuple(findings.values()), coverage=coverage,
                   coverage_gaps=tuple(sorted({text(gap) for gap in report.coverage_gaps})), timeline=timeline)


def personal_data(report: Mapping) -> bool:
    """Czy raport (słownik ``poc-1``) zawiera adres IP klienta albo login konta: atrybut tożsamości albo literał IP w tekście."""
    if any(observation["attributes"].get(name) not in (None, "") for observation in report["observations"] for name in IDENTITY):
        return True
    texts = [*report["coverage_gaps"], *(finding["reason"] for finding in report["findings"]),
             *(value for observation in report["observations"] for value in observation["attributes"].values() if isinstance(value, str))]
    return any(_is_address(found.group()) for value in texts for found in _ADDRESS.finditer(value))
