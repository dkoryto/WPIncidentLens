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
- nazwy z materiału, które są wskaźnikami (``path`` żądania, ``plugin``, ``hook``), są strukturalne: redakcja
  ukryłaby nazwę wybraną przez atakującego; z flagą dostają tylko pseudonimy adresów IP i nazw hostów;
- ``timestamp_raw`` o postaci czasu z logu zostaje; inny zapis jest tekstem z materiału;
- ``reason`` ustaleń, powody pokrycia i ``coverage_gaps`` są tekstem narzędzia z wstawkami z materiału: redakcja,
  a z flagą pseudonimy adresów IP i identyfikatorów po ``user_id`` (bez loginów — patrz ``_Text``).

Pseudonim to ``ip-``/``user-``/``uid-`` i 16 cyfr szesnastkowych (64 bity) HMAC-SHA256 z kluczem z ``secrets``
losowanym na jedno uruchomienie, trzymanym wyłącznie w pamięci obiektu ``Pseudonymizer``. Przed HMAC wartość jest
kanonizowana: adres IP do postaci ``ipaddress`` (IPv4 zmapowany w IPv6 → IPv4, IPv6 skrócony, małe litery), inna
wartość pola klienta (np. nazwa hosta) do małych liter; login i ``user_id`` dokładnie, jak w bazie.
W tekście z materiału pseudonimizowane są: każdy literał adresu IPv4/IPv6 (także przylegający do liter, z zerami
wiodącymi albo z portem), każde wystąpienie znanego loginu i wartości pola klienta (jako osobne słowo) oraz
identyfikatory po ``user_id``. Wszystkie skany są liniowe względem długości tekstu i liczby znanych wartości.

Pozostaje jawne także z pseudonimizacją: czas rejestracji konta i ``user_level``, loginy w ścieżkach (``path``,
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

from . import filerules, logformats, models, redact, wpdetect

PSEUDONYM_HEX = 16
IDENTITY = {"client_ip": "ip", "username": "user", "user_id": "uid"}  # atrybut → przedrostek pseudonimu
VARIANT = "redaction_variant"  # rozróżnia obserwacje, które po redakcji miałyby tę samą treść

_ANY = re.compile(r".*", re.S)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MD5 = re.compile(r"[0-9a-fA-F]{32}")
_TOKEN = re.compile(r"[A-Za-z0-9_.+@\-]{1,64}")  # enum, wersja, nazwa formatu (combined@1)
_DB_TIME = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
_LOGICAL_PATH = re.compile(r"(files|database|logs|baseline)/[^\s\0]{1,4096}")
_NAME = re.compile(r"[^\s\"'<>\\]{1,200}")  # nazwa z materiału, która jest wskaźnikiem (wtyczka, zadanie cron)

_HTTP = {"path": _ANY, "method": _TOKEN, "client_ip_basis": _TOKEN, "log_format": _TOKEN, "timestamp_precision": _TOKEN}
_REFERENCE = {"reference_version": _TOKEN, "reference_file": _LOGICAL_PATH}
_STRUCTURAL: dict[str, Mapping[str, re.Pattern[str]]] = {
    "HTTP_REQUEST": _HTTP,
    "HTTP_REQUEST_FOR_PHP_IN_UPLOADS": _HTTP,
    "ADMINISTRATOR_ACCOUNT": {"registered": _DB_TIME, "role_value": _TOKEN},
    "ACTIVE_PLUGIN": {"plugin": _NAME},
    "CRON_HOOK": {"hook": _NAME},
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
# Strukturalne nazwy z materiału, w których adres IP albo nazwa hosta klienta mogą wystąpić: z flagą dostają pseudonimy,
# nigdy redakcję. Korelacja porównała je wcześniej, więc pseudonim jej nie psuje.
_ADDRESS_BEARING = frozenset({"path", "plugin", "hook"})

# Skany liniowe: każdy wzorzec dopasowuje maksymalne ciągi znaków bez nawrotów; resztę rozstrzyga kod.
_IPV4 = re.compile(r"(?<![0-9.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9]|\.[0-9])")
_HEX_RUN = re.compile(r"[0-9A-Fa-f:.]{3,}")  # kandydat na IPv6: rozstrzyga ``_ipv6_in``
_MAX_IPV6_PARTS = 9  # 8 grup albo 7 i końcówka IPv4; „::” daje pustą część
_WORD = re.compile(r"\[usunięto\]|[\w.@+\-]+")  # słowo o tych samych granicach co login; znacznik redakcji pomijany
_SIMPLE = re.compile(r"[\w.@+\-]+")
_WORD_EDGE_BEFORE, _WORD_EDGE_AFTER = r"(?<![\w.@+\-])", r"(?![\w@+\-]|\.\w)"
_USER_IDS = re.compile(r"(\buser_id:? )([^\s,()…]+(?:, [^\s,()…]+)*)")


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


def _ipv4_in(text: str) -> str | None:
    """Czterooktetowy literał (także z zerami wiodącymi, np. ``192.0.2.010``) w postaci kanonicznej albo ``None``."""
    octets = [int(part) for part in text.split(".")]
    return ".".join(map(str, octets)) if all(octet <= 255 for octet in octets) else None


def _ipv6_in(run: str) -> tuple[str, int, int] | None:
    """Adres IPv6 w ciągu cyfr szesnastkowych, dwukropków i kropek (także jako jego część): adres, początek, koniec.

    Wymaga co najmniej dwóch niepustych grup oraz cyfry albo grupy dłuższej niż dwa znaki: ``Closure::bind`` czy
    ``e::b`` nie są adresem. Przegląda okna najwyżej ``_MAX_IPV6_PARTS`` kolejnych części, więc czas jest liniowy.
    Reszta ciągu (np. ``:51234`` po adresie albo ``c0000:`` przed nim) zostaje.
    """
    if run.count(":") < 2:
        return None
    parts = run.split(":")
    offsets = [0]
    for part in parts:
        offsets.append(offsets[-1] + len(part) + 1)
    for size in range(min(len(parts), _MAX_IPV6_PARTS), 2, -1):
        for start in range(len(parts) - size + 1):
            window = parts[start:start + size]
            groups = [part for part in window if part]
            if len(groups) < 2 or not (any(char.isdigit() for char in "".join(groups)) or any(len(part) > 2 for part in groups)):
                continue
            candidate = ":".join(window).rstrip(".")
            if _is_address(candidate):
                begin = offsets[start]
                return candidate, begin, begin + len(candidate)
    return None


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
        digest = self._digest(prefix + "\0" + canonical)
        return f"{prefix}-{digest[:PSEUDONYM_HEX]}"

    def order(self, value: str) -> str:
        """Klucz porządku zależny od klucza uruchomienia (np. kolejność wariantów po redakcji)."""
        return self._digest("order\0" + value)

    def _digest(self, text: str) -> str:
        return hmac.new(self.__key, text.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()


class _Words:
    """Znane wartości (loginy albo nazwy hostów) jako osobne słowa: słownik dla zwykłych, mały wzorzec dla reszty."""

    def __init__(self, values: Mapping[str, str]) -> None:
        self.plain: dict[str, str] = {}
        odd = []
        for value, pseudonym in values.items():
            stripped = value.rstrip(".")
            if _SIMPLE.fullmatch(value) and stripped:
                self.plain[stripped] = pseudonym  # „host.example.” w tekście bywa zakończony kropką zdania
            else:
                odd.append(value)
        self.odd_pseudonyms = {value: values[value] for value in odd}
        words = "|".join(re.escape(value) for value in sorted(odd, key=lambda value: (-len(value), value)))
        self.odd = re.compile(f"{_WORD_EDGE_BEFORE}(?:{words}){_WORD_EDGE_AFTER}") if words else None

    def _word(self, found: re.Match[str]) -> str:
        word = found.group()
        stripped = word.rstrip(".")
        if word == redact.MARK or stripped not in self.plain:
            return word
        return self.plain[stripped] + word[len(stripped):]

    def __call__(self, text: str) -> str:
        if self.odd is not None:
            text = self.odd.sub(lambda found: self.odd_pseudonyms[found.group()], text)
        return _WORD.sub(self._word, text) if self.plain else text


class _Text:
    """Przekształcenia tekstu: pseudonimizacja (gdy włączona), potem redakcja.

    Loginy i nazwy hostów są zastępowane wyłącznie w tekście pochodzącym z materiału (atrybuty obserwacji, zapis
    czasu): w tekstach narzędzia (``reason``, luki) login „nie” zamieniłby zaprzeczenie w pseudonim. Tam zastępowane
    są tylko literały adresów IP i identyfikatory po ``user_id``.
    """

    def __init__(self, pseudonymizer: Pseudonymizer | None, report: models.Report) -> None:
        self.pseudonymizer = pseudonymizer
        if pseudonymizer is None:
            return
        logins, hosts = {}, {}
        for observation in report.observations:
            for attribute, known in (("username", logins), ("client_ip", hosts)):
                value = observation.attributes.get(attribute)
                if isinstance(value, str) and value.strip() and not (attribute == "client_ip" and _is_address(value)):
                    known[value] = pseudonymizer.pseudonym(attribute, value)
        self.logins, self.hosts = _Words(logins), _Words(hosts)

    def _addresses(self, text: str) -> str:
        def ipv6(found: re.Match[str]) -> str:
            run, address = found.group(), _ipv6_in(found.group())
            if address is None:
                return run
            return run[:address[1]] + self.pseudonymizer.pseudonym("client_ip", address[0]) + run[address[2]:]

        def ipv4(found: re.Match[str]) -> str:
            address = _ipv4_in(found.group())
            return found.group() if address is None else self.pseudonymizer.pseudonym("client_ip", address)

        return _IPV4.sub(ipv4, _HEX_RUN.sub(ipv6, text))

    def _user_ids(self, text: str) -> str:
        return _USER_IDS.sub(lambda found: found.group(1) + ", ".join(
            self.pseudonymizer.pseudonym("user_id", value) for value in found.group(2).split(", ")), text)

    def evidence(self, text: str) -> str:
        """Tekst swobodny z materiału."""
        if self.pseudonymizer is not None:
            text = self._user_ids(self._addresses(self.hosts(self.logins(text))))
        return redact.redact(text)

    def tool(self, text: str) -> str:
        """Tekst narzędzia z wstawkami z materiału (``reason``, powody pokrycia, luki)."""
        if self.pseudonymizer is not None:
            text = self._user_ids(self._addresses(text))
        return redact.redact(text)

    def name(self, text: str) -> str:
        """Nazwa strukturalna (ścieżka, wtyczka, zadanie cron): bez redakcji, z flagą adresy i nazwy hostów jako pseudonimy."""
        return text if self.pseudonymizer is None else self._addresses(self.hosts(text))


def has_address(text: str) -> bool:
    """Czy tekst zawiera literał adresu IPv4 albo IPv6 (te same reguły co pseudonimizacja)."""
    return (any(_ipv4_in(found.group()) for found in _IPV4.finditer(text))
            or any(_ipv6_in(found.group()) for found in _HEX_RUN.finditer(text)))


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
        elif not is_structural(observation.kind, name, value):
            cleaned[name] = text.evidence(value)
        elif name in _ADDRESS_BEARING and isinstance(value, str):
            cleaned[name] = text.name(value)
        else:
            cleaned[name] = value
    return cleaned


def _timestamp(observation: models.Observation, text: _Text) -> str | None:
    """Surowy zapis czasu zostaje, gdy ma postać czasu z logu; inny (np. z wstawką z wiersza) jest tekstem z materiału."""
    raw = observation.timestamp_raw
    return raw if raw is None or logformats.is_time_shaped(raw) else text.evidence(raw)


def _observations(observations: Iterable[models.Observation], text: _Text) -> tuple[list[models.Observation], dict[str, str]]:
    """Obserwacje po redakcji i mapa starych identyfikatorów na nowe.

    Dwie różne obserwacje, które po redakcji miałyby tę samą treść (np. dwa sekrety w tym samym miejscu), dostają
    atrybut ``redaction_variant`` (1, 2, …), więc nie scalają się w raporcie. Po redakcji niczym się nie różnią, więc
    porządek musi wynikać z treści ukrytej: z flagą ``--pseudonymize`` jest to HMAC z kluczem uruchomienia (porządek
    nic nie mówi o sekrecie), bez niej — dawny identyfikator; ujawnia to najwyżej względny porządek skrótów SHA-256
    całych obserwacji, w zamian raport bez flagi pozostaje odtwarzalny (S-18).
    """
    order = (lambda item: item.id) if text.pseudonymizer is None else (lambda item: text.pseudonymizer.order(item.id))
    rebuilt: dict[str, list[tuple[models.Observation, dict, str | None]]] = {}
    for observation in observations:
        attributes, raw = _attributes(observation, text), _timestamp(observation, text)
        rebuilt.setdefault(replace(observation, attributes=attributes, timestamp_raw=raw).id, []).append((observation, attributes, raw))
    result, ids = [], {}
    for group in rebuilt.values():
        group.sort(key=lambda entry: order(entry[0]))
        for number, (observation, attributes, raw) in enumerate(group, start=1):
            if len(group) > 1:
                attributes = {**attributes, VARIANT: number}
            built = replace(observation, attributes=attributes, timestamp_raw=raw)
            result.append(built)
            ids[observation.id] = built.id
    return result, ids


def sanitize(report: models.Report, pseudonymizer: Pseudonymizer | None = None) -> models.Report:
    """Raport po redakcji tekstów swobodnych i, z ``pseudonymizer``, po pseudonimizacji; ten sam kontrakt ``poc-1``."""
    text = _Text(pseudonymizer, report)
    observations, ids = _observations(report.observations, text)
    findings = {}
    for finding in report.findings:
        built = replace(finding, reason=text.tool(finding.reason), observations=tuple(sorted({ids[ref] for ref in finding.observations})))
        findings.setdefault(built.id, built)
    coverage = {source: replace(entry, reasons=tuple(sorted({text.tool(reason) for reason in entry.reasons})))
                for source, entry in report.coverage.items()}
    timeline = tuple(replace(event, observation_id=None if event.observation_id is None else ids[event.observation_id])
                     for event in report.timeline)
    return replace(report, observations=tuple(observations), findings=tuple(findings.values()), coverage=coverage,
                   coverage_gaps=tuple(sorted({text.tool(gap) for gap in report.coverage_gaps})), timeline=timeline)


def personal_data(report: Mapping) -> bool:
    """Czy raport (słownik ``poc-1``) zawiera adres IP klienta albo login konta: atrybut tożsamości albo literał IP w tekście."""
    if any(observation["attributes"].get(name) not in (None, "") for observation in report["observations"] for name in IDENTITY):
        return True
    texts = [*report["coverage_gaps"], *(finding["reason"] for finding in report["findings"]),
             *(value for observation in report["observations"] for value in observation["attributes"].values() if isinstance(value, str))]
    return any(map(has_address, texts))
