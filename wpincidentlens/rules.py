"""Rejestr reguł (ADR 0008 pkt 2): jedyny spis reguł, z których narzędzie tworzy ustalenia, i jedyna droga od wykrycia
do ``models.Finding``.

Reguły plików (ścieżka i treść) mają wzorce i logikę w ``filerules.RULES``; rejestr przejmuje z nich opis, wagę i pewność.
Pozostałe moduły (``integrity``, ``dbrules``, ``httplog``, ``correlate``) nadają wagę i pewność w kodzie, a rejestr je
deklaruje i sprawdza przy każdym ustaleniu:

- reguła spoza rejestru to błąd kodu narzędzia (nie danych wejściowych): ``UnknownRule``, przebieg się przerywa,
  testy i CI to wychwytują;
- ``category``, ``severity`` albo ``confidence`` spoza deklaracji reguły: ustalenie zostaje **dokładnie takie, jak je
  wyemitowano** (ocena nie może przez to spaść), a pokrycie źródła dostaje lukę z identyfikatorem reguły
  (spec C10: błąd reguły to luka, nie cisza);
- wyjątek zgłoszony w trakcie oceny reguły (błąd kodu wywołany danymi) przechodzi przez ``guarded``: staje się luką
  źródła z identyfikatorem reguły (albo modułu) i nazwą typu wyjątku, a pozostałe reguły i pliki są analizowane dalej.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass

from . import filerules, ingest, models, redact
from .analysis import Detection, SourceCoverage

RULESET_ID = "wpincidentlens-poc"
# Zmienia się przy każdej zmianie rejestru (test pilnuje pary wersja–skrót) albo logiki dopasowania którejkolwiek reguły.
RULESET_VERSION = "2026.11.4"

# Źródło, którego pokrycie dostaje lukę, gdy ustalenie danej kategorii łamie deklarację reguły.
REGISTRY_GAP = "Błąd rejestru reguł"  # początek tekstu luki przy naruszeniu deklaracji reguły
RULE_ERROR_GAP = "Błąd reguły"  # początek tekstu luki, gdy reguła zgłosiła wyjątek
SOURCE_OF_CATEGORY = {"file": "files", "database": "database", "http_log": "logs", "correlation": "logs"}


class UnknownRule(LookupError):
    """Kod narzędzia wyemitował regułę spoza rejestru: błąd wewnętrzny, nie luka pokrycia."""


# Nie są błędem reguły wywołanym danymi i przerywają przebieg jak dotąd: odmowa SecureIngest i błąd wejścia-wyjścia
# (bezpieczeństwo odczytu), reguła spoza rejestru (błąd kodu narzędzia) i brak pamięci.
NOT_RULE_ERRORS = (ingest.IngestRefusal, OSError, UnknownRule, MemoryError)


def rule_failed(cover: SourceCoverage, rule: str, error: type[BaseException], where: str | None = None, count: int = 1) -> None:
    """Luka po wyjątku w regule: identyfikator reguły, nazwa typu wyjątku, liczba wystąpień i pierwsze miejsce
    (ścieżka dowodu po ``redact.neutralise``). Treść wyjątku (``str(exc)``) może zawierać bajty dowodu albo ścieżki
    hosta, więc nie trafia do raportu. Ten sam błąd powtórzony daje jedną lukę z licznikiem."""
    key = (rule, error.__name__)
    seen = cover.rule_errors.get(key)
    if seen is None:
        cover.degrade("")
        seen = cover.rule_errors[key] = [0, redact.neutralise(where)[:200] if where else None, len(cover.reasons) - 1]
    seen[0] += count
    first = f" (pierwsze: {seen[1]})" if seen[1] else ""
    cover.reasons[seen[2]] = (f"{RULE_ERROR_GAP} {rule}: wyjątek {error.__name__} ×{seen[0]}{first}; wynik tej reguły dla części "
                              "materiału jest nieznany, pozostałe reguły i pliki analizowano dalej")


def guarded(cover: SourceCoverage, rule: str, call: Callable, *args, default=None, where: str | None = None):
    """``call(*args)``; wyjątek oceny reguły zamienia w lukę ``cover`` (``rule_failed``, ``where`` = miejsce w dowodzie)
    i zwraca ``default``."""
    try:
        return call(*args)
    except NOT_RULE_ERRORS:
        raise
    except Exception as error:
        rule_failed(cover, rule, type(error), where)
        return default


@dataclass(frozen=True)
class Rule:
    id: str
    version: int
    category: str
    severity: str
    confidence: tuple[str, ...]  # dopuszczalne wartości ``confidence`` (posortowane)
    description: str
    false_positives: str


def _rule(id: str, category: str, severity: str, confidence: Iterable[str], description: str, false_positives: str,
          version: int = 1) -> Rule:
    return Rule(id, version, category, severity, tuple(sorted(set(confidence))), description, false_positives)


# Pewności, które ``filerules.path_rules`` nadaje poza domyślną pewnością reguły.
_PATH_RULE_CONFIDENCE = {"EXECUTABLE_IN_UPLOADS": ("low",),          # treść nieodczytana
                         "CODE_IN_UNEXPECTED_LOCATION": ("medium",)}  # katalog zasobów statycznych core


def _from_filerules(rule: filerules.Rule) -> Rule:
    confidence = {rule.confidence, *_PATH_RULE_CONFIDENCE.get(rule.id, ())}
    if rule.known_code_confidence:
        confidence.add(rule.known_code_confidence)
    return _rule(rule.id, "file", rule.severity, confidence, rule.explanation, rule.false_positives, rule.version)


_OTHER_RULES = (
    # --- integralność względem zaufanej referencji (integrity) ---
    _rule("BASELINE_FILE_CHANGED", "file", "medium", ("high",),
          "Odczytany plik ma inny SHA-256 niż wpis zaufanego baseline; zmiana nie przesądza o ataku.",
          "Aktualizacje, edycje administratora i wdrożenia wykonane po migawce."),
    _rule("BASELINE_FILE_MISSING", "file", "low", ("high",),
          "Plik wymieniony w baseline nie występuje w materiale wejściowym.",
          "Pliki usunięte legalnie po migawce; kopia wykonana bez części katalogów."),
    _rule("NEW_FILE_SINCE_BASELINE", "file", "medium", ("low", "medium"),
          "Plik albo wpis w miejscu ładowanym automatycznie (mu-plugins, drop-ins) spoza baseline; low, gdy wpisu nie odczytano.",
          "Wtyczki i drop-iny zainstalowane legalnie po migawce."),
    _rule("CORE_CHECKSUM_MISMATCH", "file", "medium", ("high",),
          "Plik rdzenia ma inną sumę MD5 niż lokalny manifest sum WordPress.org; wstrzymane, gdy manifest opisuje inną "
          "wersję lub locale niż witryna (luka CORE_MANIFEST_MISMATCH).",
          "Manifest innej wersji lub locale, gdy manifest albo witryna ich nie wskazuje; ręczne poprawki rdzenia przez "
          "administratora.", version=2),
    _rule("CORE_FILE_NOT_IN_MANIFEST", "file", "medium", ("low",),
          "Plik kodu lub konfiguracji w katalogu głównym, wp-admin albo wp-includes spoza manifestu sum rdzenia; wstrzymane "
          "przy niezgodności wersji lub locale manifestu z witryną.",
          "Manifest innej wersji lub locale, gdy nie da się tego ustalić; legalne pliki hostingu w katalogu głównym.",
          version=2),
    _rule("CORE_FILE_MISSING", "file", "low", ("high",),
          "Plik wymieniony w manifeście sum rdzenia nie występuje w materiale wejściowym; wstrzymane przy niezgodności "
          "wersji lub locale manifestu z witryną.",
          "Manifest innej wersji, gdy nie da się tego ustalić; kopia bez części katalogów.", version=2),
    _rule("CORE_MANIFEST_MISMATCH", "file", "medium", ("low",),
          "Manifest sum rdzenia opisuje inną wersję lub locale niż wp-includes/version.php witryny; wykrycia CORE_* są "
          "wstrzymane, a to jedno ustalenie podaje ich liczbę.",
          "Operator podał manifest innego pakietu (np. po aktualizacji witryny); ustalenie zostaje, bo tak samo wygląda "
          "zmieniony version.php ukrywający zmiany rdzenia."),
    _rule("REFERENCE_FILE_UNREADABLE", "file", "medium", ("low",),
          "Wpis wymieniony w zaufanej referencji nie został odczytany, więc nie dało się go zweryfikować.",
          "Dowiązania i dodatkowe dowiązania twarde w kopii, brak uprawnień przy zabezpieczaniu."),
    # --- baza danych (dbrules) ---
    _rule("UNRECOGNIZED_ADMIN", "database", "high", ("medium",),
          "Administrator spoza listy --known-admin, gdy baseline nie ma listy known_admins.",
          "Niepełna lista operatora; konto założone legalnie."),
    _rule("NEW_SINCE_BASELINE", "database", "high", ("medium",),
          "Administrator spoza listy known_admins z baseline (i spoza --known-admin).",
          "Nieaktualna migawka; konto założone legalnie po jej wykonaniu."),
    _rule("SUSPICIOUS_DB_MARKUP", "database", "medium", ("low",),
          "Wartość opcji zawiera aktywny znacznik HTML, przekierowanie lub schemat JS.",
          "Fragmenty analityki i reklam, osadzone filmy i mapy, onclick= w widżetach."),
    # --- logi HTTP (httplog) ---
    _rule("HTTP_EXECUTABLE_IN_UPLOADS", "http_log", "high", ("low", "medium"),
          "Żądanie do pliku z rozszerzeniem kodu w wp-content/uploads/; low dla podwójnego rozszerzenia.",
          "Skanery i boty odpytujące typowe ścieżki webshelli; legalne skrypty w uploads."),
    # --- korelacja plik–żądanie (correlate) ---
    _rule("CORRELATED_UPLOAD_REQUEST", "correlation", "high", ("medium",),
          "Ten sam plik wykonywalny w uploads występuje w obrazie witryny i w logu HTTP (SAME_PATH).",
          "Legalny skrypt w uploads odpytywany zgodnie z przeznaczeniem."),
    _rule("CORRELATED_FILE_REQUEST", "correlation", "medium", ("low",),
          "Żądanie HTTP do tej samej ścieżki co plik kodu z ustaleniem plikowym (SAME_PATH).",
          "Zwykły ruch do legalnego pliku, który ma ustalenie z innego powodu (np. zmiana względem baseline)."),
    _rule("REQUEST_NEAR_FILE_CHANGE", "correlation", "medium", ("low",),
          "Żądanie HTTP do pliku kodu w oknie --correlation-window od mtime pliku z ustaleniem (NEAR_IN_TIME).",
          "Przypadkowa bliskość w czasie; mtime zmieniony przez rozpakowanie kopii; przesunięty zegar serwera."),
)

REGISTRY: dict[str, Rule] = {rule.id: rule for rule in (*map(_from_filerules, filerules.RULES.values()), *_OTHER_RULES)}


def canonical() -> bytes:
    """Kanoniczny JSON rejestru: posortowane klucze, bez zbędnych białych znaków, UTF-8."""
    document = {"id": RULESET_ID, "version": RULESET_VERSION,
                "rules": [{**asdict(rule), "confidence": list(rule.confidence)} for _, rule in sorted(REGISTRY.items())]}
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def ruleset_sha256() -> str:
    return hashlib.sha256(canonical()).hexdigest()


def descriptor() -> dict:
    """Pole ``ruleset`` w ``case.json``."""
    return {"id": RULESET_ID, "version": RULESET_VERSION, "sha256": ruleset_sha256()}


def violations(rule_id: str, category: str, severity: str, confidence: str) -> list[str]:
    """Pola ustalenia spoza deklaracji reguły; ``UnknownRule`` dla reguły spoza rejestru."""
    rule = REGISTRY.get(rule_id)
    if rule is None:
        raise UnknownRule(f"reguła spoza rejestru: {str(rule_id)[:80]!r}")
    wrong = []
    if str(category) != rule.category:
        wrong.append(f"category={str(category)[:20]} (deklarowana {rule.category})")
    if str(severity) != rule.severity:
        wrong.append(f"severity={str(severity)[:20]} (deklarowana {rule.severity})")
    if str(confidence) not in rule.confidence:
        wrong.append(f"confidence={str(confidence)[:20]} (deklarowane {', '.join(rule.confidence)})")
    return wrong


def finding(rule_id: str, category: str, severity: str, confidence: str, reason: str, observations: tuple[str, ...],
            report_gap: Callable[[str, str], None]) -> models.Finding:
    """Jedyna droga od wykrycia do ustalenia. Ustalenie zawsze powstaje z wartości wyemitowanych; naruszenie deklaracji
    zgłasza ``report_gap(źródło, tekst)`` — tekst zawiera identyfikator reguły."""
    wrong = violations(rule_id, category, severity, confidence)
    if wrong:
        report_gap(SOURCE_OF_CATEGORY.get(str(category), "files"),
                   f"{REGISTRY_GAP}: ustalenie reguły {rule_id} ma wartości spoza deklaracji ({'; '.join(wrong)}); "
                   "ustalenie zachowano w postaci wyemitowanej")
    return models.Finding(rule_id, category, severity, confidence, reason, observations)


def findings(detections: Iterable[Detection], cover: Mapping[str, SourceCoverage]) -> list[models.Finding]:
    """Jedno ustalenie na wykrycie; naruszenie deklaracji reguły obniża pokrycie źródła (``degrade``)."""
    def gap(source: str, text: str) -> None:
        cover[source].degrade(text)

    return [finding(found.rule, found.category, found.severity, found.confidence, found.explanation, (found.observation.id,), gap)
            for found in detections]
