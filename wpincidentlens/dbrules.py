"""Reguły bazy WordPressa: z wierszy tabel użytkowników, ról i opcji powstają wykrycia i inwentarz.

Wiersze to nieufne dane. Wartości serializowane PHP czyta ``phpserialize`` (nic nie jest odtwarzane),
a cytat wartości przechodzi przez ``redact``. Opis reguł i fałszywych alarmów: ``docs/RULES.md``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import ingest, models, phpserialize, redact
from .analysis import Detection, SourceCoverage, observe

# Tabela rdzenia = prefiks + przyrostek; liczba to minimum pól wiersza bez listy kolumn. ``usermeta`` musi stać przed ``users``.
CORE_TABLE_CELLS = {"usermeta": 4, "users": 2, "options": 3}
MAX_OPTION_CHARS = 1024 * 1024      # dłuższa wartość opcji nie jest sprawdzana wzorcami: luka
MAX_CAPABILITIES_CHARS = 64 * 1024
MAX_INVENTORY = 200                 # limit wpisów każdego rodzaju inwentarza w całym przebiegu i ustaleń o administratorach
MAX_PREFIXES = 50
MAX_TABLE_NAMES = 5000
MAX_LISTED = 5                      # ile identyfikatorów lub prefiksów wymienia jedna luka

# Każdy kwantyfikator jest ograniczony, a ``[^<>]`` kończy się na następnym znaczniku: czas liniowy.
# Znane fałszywe alarmy: fragmenty analityki i reklam (<script>), osadzone mapy i filmy (<iframe>, <object>, <embed>),
# atrybuty onclick= w widżetach, proza „JavaScript: …”.
MARKUP = re.compile(
    r"<script\b|<iframe\b|<object\b|<embed\b"
    r"|<meta\b[^<>]{0,300}?http-equiv\s{0,8}=\s{0,8}[\"']?\s{0,8}refresh"
    r"|<[a-z][^<>]{0,300}?[\s\"'/]on[a-z]{3,20}\s{0,8}="
    r"|j[\t\r\n]{0,4}a[\t\r\n]{0,4}v[\t\r\n]{0,4}a[\t\r\n]{0,4}s[\t\r\n]{0,4}c[\t\r\n]{0,4}r[\t\r\n]{0,4}i[\t\r\n]{0,4}p[\t\r\n]{0,4}t\s{0,8}:"
    r"|data\s{0,8}:\s{0,8}text/html", re.I)
_REGISTERED = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", re.ASCII)
_MULTISITE_TABLE = r"(?:\d{1,10}_(?:options|posts|postmeta)|blogs|sitemeta)"
_FALSE_ROLE_NOTE = (" Klucz roli ma wartość fałszywą; WordPress wyznacza role po kluczach tablicy uprawnień, więc konto ma uprawnienia administratora.")
_INVENTORY_OPTIONS = ("cron", "active_plugins")
_USERS_COLUMNS = 10  # układ wp_users bez listy kolumn; user_registered jest siódmą kolumną


def _label(value: object, limit: int = 40) -> str:
    """Nieufny tekst (prefiks, identyfikator) skrócony i bez znaków sterujących, do cytowania w luce."""
    return redact.neutralise(str(value)[:limit])


def _listed(values: list[str]) -> str:
    shown = ", ".join(_label(value) for value in values[:MAX_LISTED])
    return shown + (", …" if len(values) > MAX_LISTED else "")


@dataclass
class _Site:
    """Wiersze tabel o jednym prefiksie. Który prefiks jest witryną WordPressa, wiadomo dopiero po całym zrzucie."""
    kinds: set[str] = field(default_factory=set)
    users: dict[str, tuple[str, str | None]] = field(default_factory=dict)  # ID → (login, data rejestracji)
    admins: dict[str, models.Location] = field(default_factory=dict)        # user_id → pierwszy wiersz z rolą
    levels: dict[str, int] = field(default_factory=dict)
    false_role: set[str] = field(default_factory=set)     # administratorzy, których klucz roli ma wartość fałszywą
    unreadable: list[str] = field(default_factory=list)   # user_id, którego tablicy uprawnień nie odczytano
    confirmed: bool = False  # usermeta zawiera klucz ``<prefiks>capabilities``
    foreign_caps: int = 0
    malformed: int = 0
    oversize: int = 0
    repeated: dict[str, int] = field(default_factory=dict)  # opcja inwentarza → liczba jej wierszy
    findings: list[Detection] = field(default_factory=list)
    facts: list[models.Observation] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


def _root(prefixes: list[str]) -> str | None:
    """Prefiks, od którego zaczynają się wszystkie pozostałe (tabele wtyczek to ``<prefiks><wtyczka>_…``)."""
    shortest = min(prefixes, key=len)
    return shortest if all(prefix.startswith(shortest) for prefix in prefixes) else None


def is_core_table(table: str) -> bool:
    """Czy nazwa może być tabelą rdzenia (``<prefiks>users``, ``usermeta``, ``options``); tylko takich wierszy potrzebują reguły."""
    return table.endswith(tuple(CORE_TABLE_CELLS))


class RowAnalysis:
    """Przyjmuje kolejne wiersze INSERT (``feed``) i po ostatnim oddaje wykrycia (``finish``)."""

    def __init__(self, item: ingest.Evidence) -> None:
        self.item = item
        self.observations: list[models.Observation] = []  # fakty, z których nie powstaje ustalenie (inwentarz)
        self.core_seen = False
        self._sites: dict[str, _Site] = {}
        self._tables: set[str] = set()
        self._dropped_prefixes = 0

    def feed(self, table: str, cols: list[str], cells: list, count: int) -> None:
        """``count`` to numer wiersza w zrzucie (od 1), zapisywany jako położenie faktu."""
        if len(self._tables) < MAX_TABLE_NAMES:
            self._tables.add(table)
        suffix = next((suffix for suffix in CORE_TABLE_CELLS if table.endswith(suffix)), None)
        if suffix is None:
            return
        self.core_seen = True
        prefix = table[:-len(suffix)]
        if prefix not in self._sites and len(self._sites) >= MAX_PREFIXES:
            self._dropped_prefixes += 1
            return
        site = self._sites.setdefault(prefix, _Site())
        site.kinds.add(suffix)
        # Wiersz z wyrażeniem zamiast literału (np. CONCAT(...)) rozpada się na mniej pól, niż ma tabela.
        if (len(cells) != len(cols)) if cols else (len(cells) < CORE_TABLE_CELLS[suffix]):
            site.malformed += 1
            return
        if suffix == "users":
            row = dict(zip(cols, cells)) if cols else {
                "ID": cells[0], "user_login": cells[1], "user_registered": cells[6] if len(cells) == _USERS_COLUMNS else None}
            if row.get("ID") is not None:
                registered = str(row.get("user_registered") or "")
                site.users[str(row["ID"])] = (str(row.get("user_login") or ""), registered if _REGISTERED.fullmatch(registered) else None)
        elif suffix == "usermeta":
            row = dict(zip(cols, cells)) if cols else {"user_id": cells[1], "meta_key": cells[2], "meta_value": cells[3]}
            key, user_id, value = str(row.get("meta_key") or ""), str(row.get("user_id")), str(row.get("meta_value") or "")
            if key == prefix + "capabilities":
                site.confirmed = True
                self._role(site, user_id, value, models.Location(table=table, key=key[:200], row=count))
            elif key == prefix + "user_level":
                if value.isascii() and value.isdigit() and len(value) <= 3:
                    site.levels.setdefault(user_id, int(value))
            elif key.endswith("capabilities"):
                site.foreign_caps += 1
        else:
            row = dict(zip(cols, cells)) if cols else {"option_name": cells[1], "option_value": cells[2]}
            self._option(site, str(row.get("option_name") or ""), str(row.get("option_value") or ""), table, count)

    def note_tables(self, tables: set[str]) -> None:
        """Nazwy tabel z wierszami, których komórek nie dekodowano (rozpoznanie multisite)."""
        for table in sorted(tables):
            if len(self._tables) >= MAX_TABLE_NAMES:
                break
            self._tables.add(table)

    @staticmethod
    def _role(site: _Site, user_id: str, value: str, place: models.Location) -> None:
        """Rola wynika wyłącznie z kluczy odczytanej tablicy uprawnień; wartości nieodczytanej nie przeszukuje się podłańcuchem."""
        if not value:
            return
        try:
            caps = phpserialize.parse(value, max_bytes=MAX_CAPABILITIES_CHARS)
        except phpserialize.SerializedError:
            caps = None
        if not isinstance(caps, dict):
            site.unreadable.append(user_id)
        elif "administrator" in caps:
            # WordPress wyznacza role po KLUCZACH tablicy (WP_User::get_role_caps), więc wartość fałszywa nie odbiera roli.
            site.admins.setdefault(user_id, place)
            if not phpserialize.truthy(caps["administrator"]):
                site.false_role.add(user_id)

    def _option(self, site: _Site, name: str, value: str, table: str, count: int) -> None:
        if len(value) > MAX_OPTION_CHARS:
            site.oversize += 1
            return
        place = models.Location(table=table, key=name[:200], row=count)
        if MARKUP.search(value):
            site.findings.append(Detection(
                "SUSPICIOUS_DB_MARKUP", "medium", "low", "database",
                "Wartość opcji zawiera aktywny znacznik HTML, przekierowanie lub schemat JS; wymaga weryfikacji.",
                observe(self.item, "OPTION_VALUE_WITH_ACTIVE_MARKUP", place, excerpt=redact.excerpt(value, MARKUP), value_chars=len(value))))
        if name in _INVENTORY_OPTIONS:
            # Nazwa opcji jest w WordPressie unikalna. Do inwentarza trafia pierwszy wiersz, kolejne są luką:
            # dzięki temu limit inwentarza dotyczy całego przebiegu, a nie pojedynczego wiersza.
            site.repeated[name] = site.repeated.get(name, 0) + 1
            if site.repeated[name] == 1:
                (self._cron if name == "cron" else self._plugins)(site, value, place)

    def _cron(self, site: _Site, value: str, place: models.Location) -> None:
        """Opcja ``cron``: czas → nazwa zadania → …; do inwentarza trafia nazwa i najbliższy czas uruchomienia."""
        try:
            schedule = phpserialize.parse(value)
        except phpserialize.SerializedError:
            schedule = None
        if not isinstance(schedule, dict):
            site.gaps.append(f"Opcja cron (wiersz {place.row}) nie jest poprawną tablicą serializowaną PHP: zadań cron nie odczytano")
            return
        hooks: dict[str, int] = {}
        odd = 0
        for when, entries in schedule.items():
            if when == "version":
                continue
            if not isinstance(when, int) or not isinstance(entries, dict):
                odd += 1
                continue
            for hook in entries:
                hooks[str(hook)] = min(hooks.get(str(hook), when), when)
        if odd:
            site.gaps.append(f"Opcja cron (wiersz {place.row}): {odd} wpisów o nieoczekiwanej postaci pominięto")
        ordered = sorted(hooks.items(), key=lambda pair: (pair[1], pair[0]))
        if len(ordered) > MAX_INVENTORY:
            site.gaps.append(f"Opcja cron (wiersz {place.row}) ma {len(ordered)} zadań; w inwentarzu jest pierwsze {MAX_INVENTORY}")
        site.facts.extend(observe(self.item, "CRON_HOOK", place, hook=_label(hook, 120), next_run=when)
                          for hook, when in ordered[:MAX_INVENTORY])

    def _plugins(self, site: _Site, value: str, place: models.Location) -> None:
        try:
            plugins = phpserialize.parse(value)
        except phpserialize.SerializedError:
            plugins = None
        if not isinstance(plugins, dict) or not all(isinstance(plugin, str) for plugin in plugins.values()):
            site.gaps.append(f"Opcja active_plugins (wiersz {place.row}) nie jest listą nazw w zapisie serializowanym PHP: "
                             "aktywnych wtyczek nie odczytano")
            return
        names = sorted(set(plugins.values()))
        if len(names) > MAX_INVENTORY:
            site.gaps.append(f"Opcja active_plugins (wiersz {place.row}) ma {len(names)} wpisów; w inwentarzu jest pierwsze {MAX_INVENTORY}")
        site.facts.extend(observe(self.item, "ACTIVE_PLUGIN", place, plugin=_label(name, 200)) for name in names[:MAX_INVENTORY])

    def _choose(self, cover: SourceCoverage) -> str | None:
        """Prefiks witryny: para ``users`` + ``usermeta``, najlepiej potwierdzona kluczem ``<prefiks>capabilities``."""
        sites = self._sites
        if self._dropped_prefixes:
            cover.degrade(f"Zrzut ma tabele o więcej niż {MAX_PREFIXES} różnych prefiksach; wiersze kolejnych pominięto")
        paired = [prefix for prefix, site in sites.items() if {"users", "usermeta"} <= site.kinds]
        group = [prefix for prefix in paired if sites[prefix].confirmed] or paired or list(sites)
        if not group:
            return None
        chosen = _root(group)
        if chosen is None:
            cover.degrade(f"Zrzut zawiera tabele WordPressa o kilku prefiksach ({_listed(sorted(group))}) i nie da się wskazać "
                          "jednej witryny: reguły bazy nie zostały zastosowane do żadnej z nich")
            return None
        others = sorted(prefix for prefix in paired if prefix != chosen)
        if others:
            cover.degrade(f"Analizowano tylko tabele o prefiksie „{_label(chosen)}”; pominięto tabele WordPressa o prefiksach: {_listed(others)}")
        multisite = re.compile(re.escape(chosen) + _MULTISITE_TABLE)
        if any(multisite.fullmatch(table) for table in self._tables):
            cover.degrade(f"Zrzut wygląda na sieć witryn (multisite): analizowano tylko witrynę o prefiksie „{_label(chosen)}”; "
                          "witryny podrzędne i super administratorzy (site_admins) są poza zakresem")
        return chosen

    def finish(self, cover: SourceCoverage, known_admins: set[str], baseline_admins: set[str] | None = None) -> list[Detection]:
        """Porównuje administratorów z zaufaną listą; czego nie da się porównać, trafia do pokrycia jako luka.

        ``known_admins`` to wszystkie zaufane nazwy (flaga ``--known-admin`` i baseline razem), ``baseline_admins``
        — te z listy ``known_admins`` migawki bazowej. Konto spoza zaufanych nazw daje jedno ustalenie:
        ``NEW_SINCE_BASELINE``, gdy migawka ma listę, w przeciwnym razie ``UNRECOGNIZED_ADMIN``.
        """
        prefix = self._choose(cover)
        if prefix is None:
            return []
        site, item = self._sites[prefix], self.item
        findings = list(site.findings)
        self.observations.extend(site.facts)
        for text in site.gaps:
            cover.degrade(text)
        for name, rows in sorted(site.repeated.items()):
            if rows > 1:
                cover.degrade(f"Opcja {name} występuje w zrzucie {rows} razy; do inwentarza odczytano tylko pierwszy wiersz")
        if site.malformed:
            cover.degrade(f"Pominięto {site.malformed} wierszy tabel użytkowników lub opcji o nieoczekiwanej liczbie pól "
                          "(np. wyrażenie SQL zamiast literału)")
        if site.oversize:
            cover.degrade(f"Nie sprawdzono {site.oversize} wartości opcji dłuższych niż {MAX_OPTION_CHARS} znaków")
        if site.foreign_caps:
            cover.degrade(f"{site.foreign_caps} wierszy uprawnień ma klucz o innym prefiksie niż tabele („{_label(prefix)}”): "
                          "ról z tych wierszy nie oceniono (multisite albo zmieniony prefiks)")
        if site.unreadable:
            cover.degrade(f"Nie odczytano tablicy uprawnień {len(site.unreadable)} kont (user_id: {_listed(site.unreadable)}): "
                          "wartość nie jest poprawną tablicą serializowaną PHP, ról tych kont nie ustalono")
        if site.false_role:
            cover.note(f"{len(site.false_role)} kont administratorów (user_id: {_listed(sorted(site.false_role))}) ma klucz roli "
                       "z wartością fałszywą; WordPress wyznacza role po kluczach tablicy uprawnień, więc są liczone jako administratorzy")
        if len(site.admins) > MAX_INVENTORY:
            cover.degrade(f"Zrzut ma {len(site.admins)} kont z rolą administratora; raport obejmuje pierwsze {MAX_INVENTORY}")
        for user_id in sorted(site.admins)[:MAX_INVENTORY]:
            login, registered = site.users.get(user_id, ("", None))
            if not login:
                # Roli nie da się porównać z zaufaną listą: bez luki administrator zniknąłby z raportu bez śladu.
                cover.degrade(f"Rola administratora dla user_id {_label(user_id)} bez odczytanego wiersza w tabeli użytkowników; "
                              "nie można ustalić loginu ani porównać go z zaufaną listą")
                continue
            facts: dict[str, str | int | None] = {"username": _label(login, 200), "user_id": _label(user_id)}
            if registered:
                facts["registered"] = registered
            if user_id in site.levels:
                facts["user_level"] = site.levels[user_id]  # pole pomocnicze sprzed ról; nie jest źródłem roli
            odd = ""
            if user_id in site.false_role:
                facts["role_value"] = "false"
                odd = _FALSE_ROLE_NOTE
            account = observe(item, "ADMINISTRATOR_ACCOUNT", site.admins[user_id], **facts)
            if not known_admins or login in known_admins:
                self.observations.append(account)
            elif baseline_admins:
                findings.append(Detection("NEW_SINCE_BASELINE", "high", "medium", "database",
                    "Administrator nie figuruje na liście known_admins migawki bazowej (baseline) ani na liście operatora: "
                    "konto jest nowe względem migawki. Nie dowodzi to włamania — migawka może być nieaktualna." + odd, account))
            else:
                findings.append(Detection("UNRECOGNIZED_ADMIN", "high", "medium", "database",
                    "Administrator nie figuruje na dostarczonej, zaufanej liście; nie dowodzi to włamania." + odd, account))
        if site.admins and not known_admins:
            cover.note("Wykryto role administratorów, ale brak wiarygodnej listy porównawczej; sam fakt istnienia admina nie jest alertem")
        return findings
