"""Reguły plików: ścieżka i treść. Dostają bajty już przeczytane przez SecureIngest; niczego nie wykonują.

Każda reguła to wiersz tabeli ``RULES``: identyfikator, wersja, waga, pewność, wyjaśnienie i znane fałszywe alarmy
(opis dla analityka: ``docs/RULES.md``). Reguły treści dopasowują tekst, nie składnię PHP: trafienie w komentarzu
albo w łańcuchu znaków liczy się tak samo, dlatego żadna z nich nie nadaje pewności ``high``.
Do raportu trafia identyfikator reguły, offset i długość trafienia — nigdy dopasowana treść pliku.
"""
from __future__ import annotations

import re
from bisect import bisect_left
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath

from . import ingest
from .analysis import Detection, seen_in
from .fileclass import FileClass, classify

RULESET_VERSION = "2026.11.1"  # zmienia się przy każdej zmianie tabeli RULES albo logiki dopasowania

CODE_SUFFIXES = frozenset({".php", ".phtml", ".phar", ".inc", ".pht", ".php3", ".php4", ".php5", ".php7", ".php8"})
CONFIG_NAMES = frozenset({".htaccess", ".user.ini", "php.ini"})
UPLOADS = "wp-content/uploads/"
# Katalogi zasobów statycznych core: WordPress nie dostarcza tam kodu PHP.
STATIC_CORE_DIRS = ("wp-includes/images/", "wp-includes/fonts/", "wp-includes/css/", "wp-admin/images/", "wp-admin/css/")
# Położenia, w których kod jest oczekiwany; tam słabsze heurystyki dostają niższą pewność.
KNOWN_CODE = frozenset({FileClass.CORE, FileClass.PLUGIN, FileClass.THEME})
BLOB_MIN_BYTES = 4096

Spans = Iterator[tuple[int, int]]


@dataclass(frozen=True)
class Rule:
    id: str
    version: int
    severity: str
    confidence: str
    kind: str                # rodzaj obserwacji (faktu), z której powstaje ustalenie
    explanation: str
    false_positives: str
    spec: str | None = None  # identyfikator ze specyfikacji (WP-FILE-00x), jeśli reguła go realizuje
    known_code_confidence: str | None = None  # pewność w core, wtyczce i motywie, gdy niższa niż domyślna
    applies: Callable[[str], bool] | None = None  # reguła treści: których plików dotyczy
    find: Callable[[bytes], Spans] | None = None  # reguła treści: (offset, długość) kolejnych trafień


def _code_part_before_suffix(rel: str) -> bool:
    return any(f".{part}" in CODE_SUFFIXES for part in PurePosixPath(rel).name.lower().split(".")[1:-1])


def is_code(rel: str) -> bool:
    return PurePosixPath(rel).suffix.lower() in CODE_SUFFIXES


def is_code_in_uploads(rel: str) -> bool:
    return rel.startswith(UPLOADS) and is_code(rel)


def is_double_extension_in_uploads(rel: str) -> bool:
    return rel.startswith(UPLOADS) and not is_code(rel) and _code_part_before_suffix(rel)


def _php(rel: str) -> bool:
    return is_code(rel) or is_double_extension_in_uploads(rel)


def _php_config(rel: str) -> bool:
    return PurePosixPath(rel).name in CONFIG_NAMES


def _uploads_htaccess(rel: str) -> bool:
    return rel.startswith(UPLOADS) and PurePosixPath(rel).name == ".htaccess"


def wants_content(rel: str) -> bool:
    """Czy reguły treści obejmują ten plik (tylko takie pliki SecureIngest zatrzymuje w pamięci)."""
    return _php(rel) or _php_config(rel)


# --- wzorce -------------------------------------------------------------------------------------
# Dopasowanie na bajtach sprowadzonych do małych liter (ASCII), więc offsety odpowiadają plikowi. Wszystkie
# kwantyfikatory są ograniczone, a serie dowolnej długości zaczynają się od lookbehind: czas jest liniowy.

_CALL = rb"(?<![\w>:$])"  # nazwa funkcji, nie końcówka innej nazwy, metoda ani zmienna
_WS = rb"\s{0,16}"
_REQUEST = rb"(?:\$_(?:post|get|request|cookie)\s{0,8}\[|\$_server\s{0,8}\[\s{0,8}['\"]http_)"
_DECODER = rb"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|convert_uudecode)"
_OPEN = _WS + rb"\(" + _WS


def _matches(pattern: bytes, flags: int = 0) -> Callable[[bytes], Spans]:
    compiled = re.compile(pattern, flags)
    return lambda raw: ((found.start(), found.end() - found.start()) for found in compiled.finditer(raw))


def _near(sink: bytes, source: bytes, before: int, after: int) -> Callable[[bytes], Spans]:
    """Trafienia ``sink``, przy których ``source`` zaczyna się najwyżej ``before`` bajtów wcześniej albo ``after`` później.

    Dwa niezależne przejścia i wyszukiwanie binarne zamiast jednego wyrażenia z ``.{0,n}``: koszt nie zależy od treści.
    """
    sink_re, source_re = re.compile(sink), re.compile(source)

    def find(raw: bytes) -> Spans:
        starts = [found.start() for found in source_re.finditer(raw)]
        if not starts:
            return
        for found in sink_re.finditer(raw):
            at = bisect_left(starts, found.start() - before)
            if at < len(starts) and starts[at] <= found.end() + after:
                yield found.start(), found.end() - found.start()

    return find


_HEURISTIC = " To heurystyka tekstowa, nie dowód; wymaga ręcznej weryfikacji."

RULES: dict[str, Rule] = {rule.id: rule for rule in (
    # --- reguły ścieżki (działają także dla plików nieodczytanych) ---
    Rule("EXECUTABLE_IN_UPLOADS", 2, "high", "medium", "PHP_FILE_IN_UPLOADS",
         "Plik wykonywalny PHP w uploads; wymaga analizy kontekstu.",
         "Nietypowe wdrożenia i wtyczki zapisujące kod w uploads (cache, generowane szablony).", spec="WP-FILE-001"),
    Rule("DOUBLE_EXTENSION_IN_UPLOADS", 1, "medium", "low", "CODE_EXTENSION_BEFORE_FINAL_SUFFIX",
         "Nazwa pliku w uploads ma rozszerzenie kodu przed ostatnim rozszerzeniem (np. .php.jpg); taki plik wykonuje się "
         "tylko przy podatnej konfiguracji serwera. To heurystyka nazwy, nie dowód.",
         "Kopie i eksporty nazwane np. plik.php.txt albo plik.php.bak.", spec="WP-FILE-005"),
    Rule("CODE_IN_UNEXPECTED_LOCATION", 1, "medium", "low", "CODE_FILE_IN_UNEXPECTED_LOCATION",
         "Plik kodu PHP w katalogu, w którym WordPress nie przechowuje kodu. To heurystyka położenia, nie dowód.",
         "Starsze paczki językowe z plikiem <locale>.php w wp-content/languages; pliki *.l10n.php są pomijane.",
         spec="WP-FILE-005"),
    # --- reguły treści plików kodu ---
    Rule("SUSPICIOUS_PHP_EVAL_DECODE", 2, "high", "medium", "EVAL_BASE64_DECODE_PATTERN",
         "Wykryto wykonanie zdekodowanej treści, np. łańcuch eval(base64_decode(...)); to heurystyka, nie dowód malware.",
         "Licencjonowane pakery i obfuskatory, stare wtyczki komercyjne, tekst wzorca w komentarzu lub sygnaturze skanera.",
         spec="WP-FILE-004", applies=_php,
         find=_matches(_CALL + rb"(?:(?:eval|assert)" + _OPEN + rb"|create_function" + _OPEN + rb"(?:''|\"\")" + _WS + rb"," + _WS
                       + rb")@?" + _DECODER + _WS + rb"\(")),
    Rule("REQUEST_TO_COMMAND_EXEC", 2, "high", "medium", "REQUEST_INPUT_NEAR_COMMAND_EXEC_PATTERN",
         "Potencjalne powiązanie danych żądania z wykonaniem komendy; wymaga ręcznej weryfikacji. To heurystyka bliskości "
         "w tekście, nie analiza przepływu danych.",
         "Wtyczki kopii zapasowych i narzędzia administracyjne, które uruchamiają polecenia obok obsługi formularza.",
         applies=_php,
         find=_near(_CALL + rb"(?:shell_exec|system|passthru|exec|popen|proc_open|pcntl_exec)\s{0,8}\(", _REQUEST, 300, 60)),
    Rule("REQUEST_TO_CODE_EVAL", 1, "high", "medium", "REQUEST_INPUT_IN_EVAL_PATTERN",
         "Dane żądania przekazane wprost do eval/assert (także przez najwyżej trzy funkcje pośrednie)." + _HEURISTIC,
         "Tekst wzorca w komentarzu, dokumentacji albo sygnaturze skanera bezpieczeństwa.",
         applies=_php,
         find=_matches(_CALL + rb"(?:eval|assert)" + _OPEN + rb"@?(?:[a-z0-9_]{1,32}" + _OPEN + rb"@?){0,3}" + _REQUEST)),
    Rule("REQUEST_VARIABLE_FUNCTION_CALL", 1, "high", "medium", "REQUEST_INPUT_CALLED_AS_FUNCTION_PATTERN",
         "Wartość z danych żądania wywołana jak funkcja ($_POST[...](...))." + _HEURISTIC,
         "Tekst wzorca w komentarzu albo sygnaturze skanera; bardzo rzadkie w legalnym kodzie.",
         applies=_php,
         find=_matches(rb"\$_(?:post|get|request|cookie)\s{0,8}\[[^\]\n]{0,64}\]\s{0,8}\(")),
    Rule("PHP_PREG_REPLACE_EVAL", 1, "high", "medium", "PREG_REPLACE_E_MODIFIER_PATTERN",
         "preg_replace z modyfikatorem /e, który wykonuje zamiennik jako kod (PHP < 7)." + _HEURISTIC,
         "Stary, legalny kod sprzed PHP 5.5; na PHP 7+ modyfikator nie działa.",
         spec="WP-FILE-004", known_code_confidence="low", applies=_php,
         find=_matches(_CALL + rb"preg_replace" + _OPEN + rb"(['\"])([^\w\s\\'\"])[^\n'\"]{0,120}\2[a-df-z]{0,8}e[a-z]{0,8}\1")),
    Rule("LONG_ENCODED_BLOB", 1, "medium", "medium", "LONG_ENCODED_BLOB_IN_CODE",
         f"Ciąg co najmniej {BLOB_MIN_BYTES} znaków base64/hex bez przerwy albo długa seria sekwencji \\x w pliku kodu."
         + _HEURISTIC,
         "Osadzone obrazy, fonty i ikony (data URI), tablice kryptograficzne, zminifikowane zasoby.",
         spec="WP-FILE-004", known_code_confidence="low", applies=_php,
         find=_matches(rb"(?<![a-z0-9+/])[a-z0-9+/]{%d,}|(?<!\\x[0-9a-f]{2})(?:\\x[0-9a-f]{2}){64,}" % BLOB_MIN_BYTES)),
    Rule("REQUEST_INPUT_TO_INCLUDE", 1, "high", "medium", "REQUEST_INPUT_IN_INCLUDE_PATTERN",
         "include/require dostaje ścieżkę wprost z danych żądania." + _HEURISTIC,
         "Stary, podatny (LFI), ale niezłośliwy kod motywów i wtyczek.",
         known_code_confidence="low", applies=_php,
         find=_matches(_CALL + rb"(?:include|require)(?:_once)?[\s(]{1,8}" + _REQUEST)),
    Rule("REQUEST_CONTROLLED_FILE_WRITE", 1, "high", "medium", "REQUEST_INPUT_AS_WRITE_TARGET_PATTERN",
         "file_put_contents dostaje ścieżkę docelową wprost z danych żądania." + _HEURISTIC,
         "Podatny, ale niezłośliwy kod edytorów plików i narzędzi deweloperskich.",
         known_code_confidence="low", applies=_php,
         find=_matches(_CALL + rb"file_put_contents" + _OPEN + _REQUEST)),
    # --- reguły treści plików konfiguracji serwera i PHP ---
    Rule("HTACCESS_ENABLES_PHP_IN_UPLOADS", 1, "high", "medium", "HTACCESS_PHP_HANDLER_IN_UPLOADS",
         "Plik .htaccess w uploads włącza wykonywanie PHP (AddHandler/AddType/SetHandler z typem PHP albo "
         "php_flag engine on)." + _HEURISTIC,
         "Nietypowa konfiguracja hostingu; dyrektywy wyłączające PHP (np. AddType text/plain .php) nie są zgłaszane.",
         spec="WP-FILE-006", applies=_uploads_htaccess,
         find=_matches(rb"^[ \t]{0,32}(?:(?:addhandler|addtype|sethandler)[ \t]{1,8}[^\s#]{0,80}php"
                       rb"|php_flag[ \t]{1,8}engine[ \t]{1,8}(?:on|1|true)\b)", re.MULTILINE)),
    Rule("PHP_AUTO_PREPEND_CONFIG", 1, "high", "low", "AUTO_PREPEND_OR_APPEND_FILE_DIRECTIVE",
         "Konfiguracja dołącza plik PHP do każdego żądania (auto_prepend_file/auto_append_file); to mechanizm utrwalenia "
         "dostępu, ale i legalne ustawienie." + _HEURISTIC,
         "Zapory aplikacyjne (np. tryb rozszerzonej ochrony Wordfence) i ustawienia hostingu.",
         spec="WP-FILE-006", applies=_php_config,
         find=_matches(rb"^[ \t]{0,32}(?:php_(?:admin_)?value[ \t]{1,8})?auto_(?:prepend|append)_file(?:[ \t]{0,8}=[ \t]{0,8}|[ \t]{1,8})"
                       rb"['\"]?(?!none\b)[^\s'\"#;=]", re.MULTILINE)),
)}


def _confidence(rule: Rule, rel: str) -> str:
    return rule.known_code_confidence if rule.known_code_confidence and classify(rel) in KNOWN_CODE else rule.confidence


def path_rules(item: ingest.Evidence) -> list[Detection]:
    """Reguły zależne tylko od ścieżki: pominięcie odczytu (hardlink, symlink, błąd) nie może ich wyłączyć."""
    rel = item.rel

    def detect(rule_id: str, confidence: str | None = None, explanation: str | None = None) -> Detection:
        rule = RULES[rule_id]
        return Detection(rule.id, rule.severity, confidence or rule.confidence, "file", explanation or rule.explanation,
                         seen_in(item, rule.kind))

    found = []
    if is_code_in_uploads(rel):
        if item.sha256 is None:
            found.append(detect("EXECUTABLE_IN_UPLOADS", "low",
                                "Plik wykonywalny PHP w uploads; treść nieodczytana, wymaga ręcznej analizy."))
        else:
            found.append(detect("EXECUTABLE_IN_UPLOADS"))
    elif is_double_extension_in_uploads(rel):
        found.append(detect("DOUBLE_EXTENSION_IN_UPLOADS"))
    if is_code(rel):
        if rel.startswith(STATIC_CORE_DIRS):
            found.append(detect("CODE_IN_UNEXPECTED_LOCATION", "medium"))
        elif classify(rel) is FileClass.LANGUAGE and not rel.lower().endswith(".l10n.php"):
            found.append(detect("CODE_IN_UNEXPECTED_LOCATION"))
    return found


def content_rules(item: ingest.Evidence) -> list[Detection]:
    """Heurystyki treści pliku, którego bajty zatrzymano (``item.content``): jedno wykrycie na regułę i plik."""
    found = []
    raw = item.content.lower()
    for rule in RULES.values():
        if rule.find is None or not rule.applies(item.rel):
            continue
        first, count = None, 0
        for span in rule.find(raw):
            first, count = first or span, count + 1
        if first:
            offset, length = first
            found.append(Detection(rule.id, rule.severity, _confidence(rule, item.rel), "file", rule.explanation,
                                   seen_in(item, rule.kind, rule_version=rule.version, offset=offset, length=length,
                                           match_count=count)))
    return found
