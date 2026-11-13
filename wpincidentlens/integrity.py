"""Porównanie plików z zaufaną referencją: baseline (SHA-256) i lokalny manifest sum rdzenia WordPress.org (MD5).

Brak referencji to luka w zakresie (``NOT_CHECKED``), nie wynik „bez zmian”: plik kodu, którego nie zweryfikowano
względem żadnej referencji, obniża pokrycie źródła ``files`` (ADR 0005, pkt 6). Moduł nie dotyka systemu plików:
dostaje wpisy już przeczytane przez SecureIngest. MD5 służy wyłącznie do porównania z publicznym manifestem
i występuje tylko w atrybutach obserwacji; skrótem dowodu pozostaje SHA-256 (ADR 0005).
"""
from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from . import case, filerules, ingest, models, wpdetect
from .analysis import Detection, SourceCoverage, observe, seen_in
from .fileclass import AUTOLOADED, CONFIG_NAMES, FileClass, classify

MAX_CORE_CHECKSUMS = 50_000  # pełny manifest WordPressa ma kilka tysięcy wpisów
MAX_BASELINE_ENTRIES = 200_000  # jak domyślny limit liczby plików sesji; ponad limit baseline nie jest porównywany (luka)
MAX_FINDINGS_PER_RULE = 200  # ponad limit powstaje luka pokrycia z łączną liczbą wykryć, nie kolejne ustalenia
# Reguły porównania z manifestem sum rdzenia: wstrzymywane, gdy manifest opisuje inną wersję lub locale niż witryna.
CORE_RULES = ("CORE_CHECKSUM_MISMATCH", "CORE_FILE_NOT_IN_MANIFEST", "CORE_FILE_MISSING")
CORE_MANIFEST_MISMATCH = "CORE_MANIFEST_MISMATCH"  # początek tekstu luki
_MD5 = re.compile(r"[0-9a-f]{32}")
_LOCALE = re.compile(wpdetect.LOCALE)
_VERSION_KEY = re.compile(r"\d+(\.\d+){1,2}([-+][0-9A-Za-z.]+)?")
# Klasy, dla których brak referencji jest zapisywany w pokryciu także wtedy, gdy nie dotyczy pliku kodu (ADR 0005, pkt 3).
CHECKED_CLASSES = (FileClass.CORE, FileClass.PLUGIN, FileClass.THEME, FileClass.MU_PLUGIN, FileClass.DROPIN)
CORE_DIRS = ("wp-admin", "wp-includes")
MU_PLUGINS_DIR = "wp-content/mu-plugins"
_NOT_PROOF = "Nowy plik nie dowodzi włamania: baseline może być po prostu starszy niż legalna zmiana."


@dataclass(frozen=True)
class CoreChecksums:
    """Zweryfikowany manifest sum rdzenia razem z wpisem rejestru pliku, z którego pochodzi."""
    record: ingest.Evidence
    checksums: Mapping[str, str]
    version: str | None = None
    label: str | None = None
    locale: str | None = None


def parse_core_checksums(data: object, record: ingest.Evidence) -> CoreChecksums:
    """Sprawdza kształt ``{"checksums": {ścieżka: md5}}`` (api.wordpress.org ``core/checksums/1.0``); ``ValueError`` przy odstępstwie.

    Przyjmuje też wariant ``{"checksums": {"<wersja>": {ścieżka: md5}}}``, w którym jedyny klucz wygląda jak numer wersji,
    oraz opcjonalne pole ``locale`` (np. ``"pl_PL"``; api.wordpress.org go nie zwraca — dopisuje je operator).
    Komunikaty nie powtarzają odrzuconych wartości.
    """
    if not isinstance(data, dict) or not isinstance(data.get("checksums"), dict):
        raise ValueError('manifest musi być obiektem JSON {"checksums": {ścieżka: md5}}')
    version, label = case.reference_labels(data)
    locale = data.get("locale")
    if locale is not None and not (isinstance(locale, str) and _LOCALE.fullmatch(locale)):
        raise ValueError("locale: dozwolony jest kod locale WordPressa, np. pl_PL albo de_DE_formal")
    checksums = data["checksums"]
    if len(checksums) == 1 and isinstance(next(iter(checksums.values())), dict):
        (nested_version, checksums), = checksums.items()
        if _VERSION_KEY.fullmatch(nested_version) is None:
            raise ValueError("jedyny klucz checksums z obiektem musi być numerem wersji, np. 6.5.2")
        case.reference_labels({"wordpress_version": nested_version})
        if version not in (None, nested_version):
            raise ValueError("wordpress_version różni się od wersji w kluczu checksums")
        version = nested_version
    if not 0 < len(checksums) <= MAX_CORE_CHECKSUMS:
        raise ValueError(f"manifest musi zawierać od 1 do {MAX_CORE_CHECKSUMS} sum")
    if not all(map(case.is_relative_path, checksums)):
        raise ValueError("klucze checksums muszą być ścieżkami względnymi z ukośnikami „/”, bez „..”, "
                         f"znaków sterujących i dłuższych niż {case.MAX_REFERENCE_PATH} znaków")
    if not all(isinstance(value, str) and _MD5.fullmatch(value) for value in checksums.values()):
        raise ValueError("wartości checksums muszą być skrótami MD5: 32 małe cyfry szesnastkowe")
    return CoreChecksums(record, checksums, version, label, locale)


def baseline_record(session: ingest.Session, core: CoreChecksums | None = None) -> ingest.Evidence | None:
    """Wpis rejestru dla wczytanego baseline (dowód, na który powołują się ustalenia o brakujących plikach).

    Manifest sum rdzenia należy do tego samego źródła ``baseline``, więc jest tu pomijany po nazwie.
    """
    skip = core.record.rel if core else None
    return next((record for record in session.ledger
                 if record.source == "baseline" and record.sha256 is not None and record.rel != skip), None)


def _reference_facts(version: str | None, label: str | None) -> dict[str, str]:
    return {name: value for name, value in (("reference_version", version), ("reference", label)) if value is not None}


def _directories(paths: Iterable[str]) -> set[str]:
    """Wszystkie katalogi nadrzędne podanych ścieżek, policzone raz (bez przeszukiwania referencji przy każdym wpisie)."""
    found: set[str] = set()
    for path in paths:
        while "/" in path:
            path = path.rpartition("/")[0]
            if path in found:
                break
            found.add(path)
    return found


def _is_core_code(rel: str) -> bool:
    """Plik kodu lub konfiguracji PHP/serwera w katalogu głównym witryny, ``wp-admin`` albo ``wp-includes``.

    Bez plików konfiguracji z katalogu głównego (``wp-config.php``, ``.htaccess``, ``.user.ini``, ``php.ini``):
    są oczekiwane, a manifest dystrybucji nigdy ich nie zawiera.
    """
    parts = rel.split("/")
    if len(parts) == 1:
        return rel not in CONFIG_NAMES and filerules.wants_content(rel)
    return parts[0] in CORE_DIRS and filerules.wants_content(rel)


def _read_state(item: ingest.Evidence) -> str:
    return f"{item.status}/{item.reason}" if item.reason else str(item.status)


class ReferenceComparison:
    """Zbiera wpisy drzewa plików i porównuje je z baseline (SHA-256) oraz z manifestem sum rdzenia (MD5)."""

    def __init__(self, baseline: dict | None, core: CoreChecksums | None = None) -> None:
        self.baseline = baseline
        listed: dict[str, str] = (baseline or {}).get("files", {})
        # Baseline ponad limit nie jest porównywany wcale: obcięty dawałby fałszywe „nowe” i „brakujące” pliki.
        self.baseline_entries = len(listed)
        self.ref = listed if self.baseline_entries <= MAX_BASELINE_ENTRIES else {}
        self.ref_dirs = _directories(self.ref)
        self.baseline_facts = _reference_facts((baseline or {}).get("wordpress_version"), (baseline or {}).get("reference"))
        self.core = core
        self.checksums: Mapping[str, str] = core.checksums if core else {}
        self.core_dirs = _directories(self.checksums)
        self.core_facts = {} if core is None else {
            **_reference_facts(core.version, core.label), "reference_file": f"{core.record.source}/{core.record.rel}"}
        self.observed: set[str] = set()      # przeczytane
        self.unread: set[str] = set()        # widziane, lecz nieprzeczytane
        self.unreferenced: set[str] = set()  # przeczytane, bez wpisu w żadnej referencji i bez własnego ustalenia
        self.seen_in_class: Counter = Counter()            # wpisy przeczytane i nieprzeczytane
        self.unchecked_in_class: Counter = Counter()       # …z nich niezweryfikowane względem żadnej referencji
        self.unchecked_code_in_class: Counter = Counter()  # …z nich pliki kodu (``filerules.wants_content``)
        self.detected: Counter = Counter()   # wykrycia według reguły, także te ponad limit ustaleń
        self.complete = True                 # czy przejście objęło całe drzewo
        self.core_found: list[Detection] = []  # wykrycia reguł CORE_RULES, oddawane w ``finish`` po sprawdzeniu zgodności
        self.version_file_matches = False    # wp-includes/version.php ma MD5 z manifestu
        self.version_file: ingest.Evidence | None = None  # odczytany wp-includes/version.php (miejsce ustalenia o niezgodności)

    def _emit(self, found: list[Detection], rule: str, severity: str, confidence: str, explanation: str, fact) -> None:
        """Dodaje wykrycie, dopóki reguła nie wyczerpała limitu; ``fact`` buduje obserwację dopiero wtedy, gdy jest potrzebna."""
        self.detected[rule] += 1
        if self.detected[rule] <= MAX_FINDINGS_PER_RULE:
            found.append(Detection(rule, severity, confidence, "file", explanation, fact()))

    def _unchecked(self, kind: FileClass, rel: str) -> None:
        self.unchecked_in_class[kind] += 1
        self.unchecked_code_in_class[kind] += filerules.wants_content(rel)

    def check(self, item: ingest.Evidence) -> list[Detection]:
        """Rejestruje wpis i zwraca wykrycia różnic względem referencji; wpis nieprzeczytany ocenia po samej ścieżce."""
        rel, found = item.rel, []
        if rel == ingest.ROOT:  # wpis o samym źródle: przejście drzewa jest niepełne
            self.unread.add(rel)
            self.complete = False
            return found
        kind = classify(rel)
        self.seen_in_class[kind] += 1
        if item.sha256 is None:
            self.unread.add(rel)
            self.complete = self.complete and item.reason not in ("MAX_FILES", "MAX_ENTRIES")
            self._unchecked(kind, rel)
            self._check_unread(item, kind, found)
            return found
        self.observed.add(rel)
        reported = False
        expected = self.ref.get(rel)
        if expected is not None:
            if expected != item.sha256:
                self._emit(found, "BASELINE_FILE_CHANGED", "medium", "high",
                           "Plik zmieniony względem zaufanej migawki (zmiana nie przesądza o ataku).",
                           lambda: seen_in(item, "FILE_DIFFERS_FROM_BASELINE", baseline_sha256=expected, **self.baseline_facts))
        elif self.ref and kind in AUTOLOADED:
            reported = True
            self._emit(found, "NEW_FILE_SINCE_BASELINE", "medium", "medium",
                       f"Plik w miejscu ładowanym automatycznie nie występuje w baseline. {_NOT_PROOF}",
                       lambda: seen_in(item, "FILE_NOT_IN_BASELINE", file_class=str(kind), **self.baseline_facts))
        reference_md5 = self.checksums.get(rel)
        if self.core is not None and item.md5 is not None:
            if rel == wpdetect.VERSION_FILE:
                self.version_file, self.version_file_matches = item, reference_md5 == item.md5
            if reference_md5 is None:
                if _is_core_code(rel):
                    reported = True
                    self._not_in_manifest(item)
            elif reference_md5 != item.md5:
                stated = f"dla wersji {self.core.version}" if self.core.version else "z podanego manifestu (bez oznaczenia wersji)"
                self._emit(self.core_found, "CORE_CHECKSUM_MISMATCH", "medium", "high",
                           f"Plik różni się od publicznej referencji WordPress.org {stated}. Manifest innej wersji lub innego "
                           "locale także daje rozbieżności; sama różnica nie przesądza o ataku.",
                           lambda: seen_in(item, "FILE_DIFFERS_FROM_CORE_MANIFEST", observed_sha256=item.sha256,
                                           observed_md5=item.md5, reference_md5=reference_md5, **self.core_facts))
        if expected is None and reference_md5 is None:
            self._unchecked(kind, rel)
            if not reported:
                self.unreferenced.add(rel)
        return found

    def _check_unread(self, item: ingest.Evidence, kind: FileClass, found: list[Detection]) -> None:
        """Wpis, którego nie przeczytano (dowiązanie, drugi hardlink, brak uprawnień, limit): ocena wyłącznie po ścieżce."""
        rel, state = item.rel, _read_state(item)
        in_baseline, in_manifest = rel in self.ref, rel in self.checksums
        # Katalog, którego pliki wymienia referencja, a który przestał być czytelnym katalogiem. Limit operatora
        # (głębokość, liczba wpisów) nie jest zmianą w materiale i zostaje samą luką pokrycia.
        by_limit = item.status is ingest.ReadStatus.SKIPPED_LIMIT
        baseline_dir, manifest_dir = rel in self.ref_dirs and not by_limit, rel in self.core_dirs and not by_limit
        if in_baseline or in_manifest or baseline_dir or manifest_dir:
            listed = "+".join(name for name, present in (("baseline", in_baseline or baseline_dir),
                                                         ("core_manifest", in_manifest or manifest_dir)) if present)
            facts = {**(self.baseline_facts if in_baseline or baseline_dir else {}),
                     **({"reference_file": self.core_facts["reference_file"]} if in_manifest or manifest_dir else {})}
            self._emit(found, "REFERENCE_FILE_UNREADABLE", "medium", "low",
                       "Wpis wymieniony w zaufanej referencji nie został odczytany, więc nie dało się go zweryfikować "
                       f"(status odczytu: {state}; np. dowiązanie symboliczne, dodatkowe dowiązanie twarde, brak uprawnień). "
                       "Sam brak odczytu nie dowodzi zmiany pliku.",
                       lambda: seen_in(item, "REFERENCE_ENTRY_NOT_READ", listed_in=listed,
                                       listed_as="file" if in_baseline or in_manifest else "directory", **facts))
        elif self.ref and rel not in self.ref_dirs and (kind in AUTOLOADED or rel == MU_PLUGINS_DIR):
            self._emit(found, "NEW_FILE_SINCE_BASELINE", "medium", "low",
                       "Wpis w miejscu ładowanym automatycznie nie występuje w baseline; treść nieodczytana "
                       f"(status odczytu: {state}), wymaga ręcznej analizy. {_NOT_PROOF}",
                       lambda: seen_in(item, "ENTRY_NOT_IN_BASELINE", file_class=str(kind), **self.baseline_facts))
        elif self.core is not None and _is_core_code(rel):
            self._not_in_manifest(item, unread=state)

    def _not_in_manifest(self, item: ingest.Evidence, unread: str | None = None) -> None:
        # Katalog główny, wp-admin i wp-includes są osiągalne wprost z sieci, a dystrybucja WordPressa nie przewiduje tam
        # dodatkowych plików kodu ani konfiguracji. Pewność niska: manifest innej wersji lub locale daje ten sam obraz,
        # a w katalogu głównym bywają legalne pliki spoza dystrybucji (np. skrypty hostingu).
        note = f" Treść nieodczytana (status odczytu: {unread})." if unread else ""
        self._emit(self.core_found, "CORE_FILE_NOT_IN_MANIFEST", "medium", "low",
                   "Plik kodu lub konfiguracji w katalogu głównym, wp-admin albo wp-includes nie występuje w manifeście sum "
                   "rdzenia; może pochodzić z innej wersji lub locale WordPressa, z legalnego dodatku albo być plikiem "
                   f"podrzuconym — wymaga ręcznej weryfikacji.{note}",
                   lambda: seen_in(item, "FILE_NOT_IN_CORE_MANIFEST", **self.core_facts))

    def _absent(self, listed: Mapping[str, str]) -> list[str]:
        """Ścieżki z referencji, których w materiale na pewno nie ma: bez wpisów, które istnieją, lecz są nieprzeczytane."""
        absent = []
        for rel in sorted(listed.keys() - self.observed):
            parts = rel.split("/")
            if not any("/".join(parts[:depth]) in self.unread for depth in range(1, len(parts) + 1)):
                absent.append(rel)
        return absent

    def _note_unchecked(self, cover: SourceCoverage) -> None:
        """``NOT_CHECKED`` per klasa. Niezweryfikowany plik kodu obniża pokrycie, bo brak ustaleń nic o nim nie mówi."""
        for kind in FileClass:
            unchecked, code = self.unchecked_in_class[kind], self.unchecked_code_in_class[kind]
            if not (code or (unchecked and kind in CHECKED_CLASSES)):
                continue
            total = self.seen_in_class[kind]
            count = f"{unchecked}" if unchecked == total else f"{unchecked} z {total}"
            text = (f"NOT_CHECKED: integralność plików klasy {kind} (plików: {count}, w tym kodu: {code}) niezweryfikowana "
                    "— brak zaufanej referencji")
            if code:
                cover.degrade(text)
            else:
                cover.note(text)

    def _core_conflict(self, site: wpdetect.CoreIdentity, cover: SourceCoverage) -> str | None:
        """Opis niezgodności wersji lub locale manifestu z witryną (R-46) albo ``None``; niewiadome trafiają do noty.

        ``version.php`` zgodny z manifestem rozstrzyga sprawę bez etykiet: to ten sam pakiet. Kandydat z plików witryny
        mógł zostać zmieniony, dlatego niezgodność nie usuwa wykryć bez śladu: zostaje luka pokrycia i jedno ustalenie.
        """
        if self.version_file_matches:
            return None
        conflicts, unknown = [], []
        for name, of, stated, found, field_name in (("wersja", "wersji", self.core.version, site.version, "wordpress_version"),
                                                    ("locale", "locale", self.core.locale, site.locale, "locale")):
            if stated is None:
                unknown.append(f"brak {of} manifestu (pole {field_name})")
            elif found is None:
                unknown.append(f"brak {of} witryny w {wpdetect.VERSION_FILE}")
            elif stated != found:
                conflicts.append(f"{name} manifestu {stated}, witryny {found}")
        if conflicts:
            return "; ".join(conflicts)
        if unknown:
            cover.note("Zgodność manifestu sum rdzenia z witryną niesprawdzona: " + "; ".join(unknown)
                       + ". Manifest innej wersji lub locale daje rozbieżności niebędące zmianą plików")
        return None

    def _withhold_core(self, conflict: str, site: wpdetect.CoreIdentity, cover: SourceCoverage) -> Detection:
        """Manifest innej wersji lub locale: zamiast setek rozbieżności jedna luka z liczbą wstrzymanych wykryć i jedno
        ustalenie ``CORE_MANIFEST_MISMATCH``.

        Etykieta witryny pochodzi z ``version.php``, który napastnik może zmienić; samo wstrzymanie wykryć obniżyłoby
        wtedy ocenę (ADR 0008: warunek zależny od materiału nie może usuwać ustaleń), więc niezgodność zawsze zostawia
        ustalenie i ocena nie spada poniżej ``SUSPICIOUS``.
        """
        missing = sum(not rel.startswith("wp-content/") for rel in self._absent(self.checksums)) if self.complete else 0
        counts = {**{rule: self.detected.pop(rule, 0) for rule in CORE_RULES}, "CORE_FILE_MISSING": missing}
        withheld = ", ".join(f"{rule} ×{total}" for rule, total in counts.items() if total) or "brak"
        self.core_found = []
        cover.degrade(f"{CORE_MANIFEST_MISMATCH}: manifest sum rdzenia nie odpowiada witrynie ({conflict}); porównanie z nim "
                      f"pominięte, pliki rdzenia niezweryfikowane (wstrzymane wykrycia: {withheld}). Podaj manifest właściwej "
                      f"wersji i locale; kandydat z {wpdetect.VERSION_FILE} mógł zostać zmieniony, co samo wymaga sprawdzenia")
        facts = {key: value for key, value in (("reference_version", self.core.version), ("reference_locale", self.core.locale),
                                               ("site_version", site.version), ("site_locale", site.locale)) if value is not None}
        facts.update({f"withheld_{rule.lower()}": total for rule, total in counts.items()},
                     reference_file=f"{self.core.record.source}/{self.core.record.rel}")
        if self.version_file is not None:
            fact = seen_in(self.version_file, "CORE_MANIFEST_DIFFERS_FROM_SITE", **facts)
        else:
            fact = observe(self.core.record, "CORE_MANIFEST_DIFFERS_FROM_SITE", models.Location(path=self.core.record.rel), **facts)
        return Detection("CORE_MANIFEST_MISMATCH", "medium", "low", "file",
                         f"Manifest sum rdzenia nie odpowiada wersji lub locale witryny ({conflict}); wstrzymano wykrycia: "
                         f"{withheld}. Albo podano manifest innego pakietu, albo zmieniono {wpdetect.VERSION_FILE} "
                         "(np. by ukryć zmiany rdzenia) — wymaga ręcznej weryfikacji z manifestem właściwej wersji.", fact)

    def finish(self, session: ingest.Session, cover: SourceCoverage, site: wpdetect.CoreIdentity | None = None) -> list[Detection]:
        """Po przejściu drzewa: luki o plikach bez referencji i wykrycia plików, których w materiale brakuje.

        ``site`` (wersja i locale pakietu z WPDetector) jest porównywane z manifestem sum rdzenia; przy niezgodności
        wykrycia reguł ``CORE_RULES`` zastępuje jedna luka i jedno ustalenie ``CORE_MANIFEST_MISMATCH``.
        """
        found: list[Detection] = []
        if self.baseline_entries > MAX_BASELINE_ENTRIES:
            cover.degrade(f"Baseline ma {self.baseline_entries} wpisów files, więcej niż limit {MAX_BASELINE_ENTRIES}: "
                          "porównanie plików z baseline niewykonane")
        site = site or wpdetect.CoreIdentity()
        conflict = self._core_conflict(site, cover) if self.core is not None else None
        if conflict:
            found.append(self._withhold_core(conflict, site, cover))
        found.extend(self.core_found)
        if (self.ref or self.core) and self.unreferenced:
            # Plik bez wpisu w referencji nie jest porównywany: bez tej noty nowy plik znikałby z raportu bez śladu.
            unreferenced = sorted(self.unreferenced)
            # Nazwa pochodzi z materiału: cudzysłowy JSON nie pozwalają jej przecinkom ani znakom sterującym zmienić zdania.
            examples = ", ".join(json.dumps(rel, ensure_ascii=False) for rel in unreferenced[:3]) + (", …" if len(unreferenced) > 3 else "")
            cover.note(f"NO_TRUSTED_REFERENCE: {len(unreferenced)} odczytanych plików nie ma wpisu w podanej referencji, "
                       f"więc ich zmiany lub pojawienia się nie da się ocenić ({examples})")
        self._note_unchecked(cover)
        if self.complete:  # po przerwanym przejściu nie wiadomo, czego w materiale brakuje
            self._missing(session, cover, found, core=not conflict)
        for rule, total in sorted(self.detected.items()):
            if total > MAX_FINDINGS_PER_RULE:
                cover.degrade(filerules.cap_exceeded(rule, total, MAX_FINDINGS_PER_RULE))
        return found

    def _missing(self, session: ingest.Session, cover: SourceCoverage, found: list[Detection], core: bool = True) -> None:
        if self.ref:
            reference = baseline_record(session, self.core)  # dowodem braku pliku jest baseline, który ten plik wymienia
            for rel in self._absent(self.ref):
                self._emit(found, "BASELINE_FILE_MISSING", "low", "high",
                           "Plik obecny w migawce bazowej nie występuje w materiale wejściowym.",
                           lambda rel=rel: observe(reference, "BASELINE_ENTRY_NOT_IN_FILES", models.Location(path=rel),
                                                   **self.baseline_facts))
        if self.core is None or not core:
            return
        bundled = 0
        for rel in self._absent(self.checksums):
            if rel.startswith("wp-content/"):  # dołączone motywy i wtyczki są rutynowo usuwane
                bundled += 1
                continue
            self._emit(found, "CORE_FILE_MISSING", "low", "high",
                       "Plik wymieniony w manifeście sum rdzenia nie występuje w materiale wejściowym; "
                       "manifest innej wersji także daje takie braki.",
                       lambda rel=rel: observe(self.core.record, "CORE_MANIFEST_ENTRY_NOT_IN_FILES", models.Location(path=rel),
                                               reference_md5=self.checksums[rel],
                                               **_reference_facts(self.core.version, self.core.label)))
        if bundled:
            cover.note(f"Manifest sum rdzenia wymienia {bundled} plików w wp-content, których nie ma w materiale "
                       "(dołączone motywy i wtyczki bywają usuwane); nie powstają z nich ustalenia")
