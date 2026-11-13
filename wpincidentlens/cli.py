"""WPIncidentLens proof of concept. Only read static inputs; never execute WordPress code."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from . import case, files, ingest, integrity, models, privacy, report, rules, yarax
from . import database as database_scan
from .analysis import Detection, SourceCoverage
from .correlate import DEFAULT_WINDOW_SECONDS, Correlation, check_window, correlate, focus as _focus, timeline as _timeline  # noqa: F401  (testy wołają _timeline przez cli)
from .httplog import FORMATS as FORMATS_OF_LOGS, LogConfig, scan_logs
from .sqldump import iter_insert_rows  # noqa: F401  (ADR 0001: testy wołają go przez cli)
from .analysis import evidence_of as _evidence

VERSION = "0.1.0-poc"
DISCLAIMER = "Brak alertów nie dowodzi braku włamania. PoC, nie certyfikacja śledcza."
# Kody wyjścia (specyfikacja §11, ADR 0003): 2 zgłasza argparse przy błędzie wywołania; ustalenia nie zmieniają kodu.
EXIT_COMPLETE, EXIT_PARTIAL, EXIT_UNPROCESSED = 0, 3, 4
# Materiał dowodowy otwiera wyłącznie wpincidentlens.ingest (ADR 0002 D4); ten moduł dostaje już przeczytane bajty.
MAX_FILES = ingest.Limits().max_files
MAX_SCAN_BYTES = ingest.Limits().max_scan_bytes
MAX_BASELINE_BYTES = 64 * 1024 * 1024
MAX_CORE_CHECKSUMS_BYTES = 8 * 1024 * 1024
PERSONAL_DATA_WARNING = ("Uwaga: raport zawiera dane osobowe (adresy IP klientów, loginy kont); "
                         "aby zastąpić je pseudonimami, uruchom ponownie z --pseudonymize.")


def _session() -> ingest.Session:
    """Sesja odczytu z limitami domyślnymi; stałe MAX_* są czytane w chwili wywołania."""
    return ingest.Session(ingest.Limits(max_files=MAX_FILES, max_scan_bytes=MAX_SCAN_BYTES))


class _DuplicateKey(ValueError):
    pass


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    data = dict(pairs)
    if len(data) != len(pairs):  # json bierze po cichu ostatnią wartość: dwa wpisy tej samej ścieżki ukryłyby jeden skrót
        raise _DuplicateKey
    return data


def _reference_json(content: bytes) -> object:
    """JSON zaufanej referencji (baseline, manifest sum); powtórzony klucz obiektu jest błędem, nie cichym nadpisaniem."""
    try:
        return json.loads(content.decode("utf-8"), object_pairs_hook=_unique_keys)
    except _DuplicateKey:
        raise ValueError("powtórzony klucz w obiekcie JSON") from None
    except (ValueError, RecursionError):
        raise ValueError("niepoprawny JSON (wymagany UTF-8)") from None


def load_baseline(path: Path, session: ingest.Session) -> dict:
    """Czyta zaufany baseline tym samym bezpiecznym odczytem co dowody; wpis dowodu i jego luki zostają w rejestrze sesji.

    Baseline, którego nie da się odczytać albo który ma zły kształt, to błąd wejścia (``ValueError``), nie luka:
    operator jawnie zażądał porównania, więc ciche pominięcie byłoby mylące.
    """
    item = session.read_file(path, "baseline", keep_limit=MAX_BASELINE_BYTES)
    if item.content is None:
        raise ValueError(item.gaps[0] if item.sha256 is None else f"plik większy niż {MAX_BASELINE_BYTES} B")
    data = _reference_json(item.content)
    if not isinstance(data, dict):
        raise ValueError("baseline musi być obiektem JSON")
    files, admins = data.get("files", {}), data.get("known_admins", [])
    if not (isinstance(files, dict) and all(isinstance(value, str) for value in files.values())):
        raise ValueError("baseline.files musi być obiektem {ścieżka: sha256}")
    if not (isinstance(admins, list) and all(isinstance(value, str) for value in admins)):
        raise ValueError("baseline.known_admins musi być listą nazw")
    return data


def load_core_checksums(path: Path, session: ingest.Session) -> integrity.CoreChecksums:
    """Czyta lokalny manifest sum rdzenia WordPress.org tak samo jak baseline; narzędzie niczego nie pobiera z sieci.

    Manifest jest dowodem źródła ``baseline``. Nieczytelny albo o złym kształcie to błąd wejścia (``ValueError``).
    """
    item = session.read_file(path, "baseline", keep_limit=MAX_CORE_CHECKSUMS_BYTES)
    if item.content is None:
        raise ValueError(item.gaps[0] if item.sha256 is None else f"plik większy niż {MAX_CORE_CHECKSUMS_BYTES} B")
    return integrity.parse_core_checksums(_reference_json(item.content), replace(item, content=None))


def _coverage(source: str, cover: SourceCoverage, ledger: list[ingest.Evidence]) -> models.Coverage:
    """Status źródła z ustaleń skanera i z rejestru: każdy wpis o statusie innym niż READ wyklucza ``ANALYZED``."""
    records = [record for record in ledger if record.source == source]
    counted = Counter(str(record.status) for record in records)
    entries = {str(status): counted[str(status)] for status in ingest.ReadStatus}
    hashed = sum(record.sha256 is not None for record in records)
    reasons = set(cover.reasons)
    if not cover.provided:
        status = models.CoverageStatus.NOT_PROVIDED
    elif cover.failed or not hashed:
        status = models.CoverageStatus.FAILED
    elif cover.partial or len(records) != entries[str(ingest.ReadStatus.READ)]:
        status = models.CoverageStatus.PARTIAL
    else:
        status = models.CoverageStatus.ANALYZED
    if status in (models.CoverageStatus.FAILED, models.CoverageStatus.PARTIAL) and not reasons:
        reasons.add(f"Źródło {source}: nie odczytano żadnego pliku" if not hashed else f"Źródło {source}: część wpisów nie została odczytana")
    return models.Coverage(source, status, entries, tuple(reasons))


def _log_scan(result) -> tuple[list[Detection], SourceCoverage, list[models.Observation]]:
    """Wynik ``scan_logs``: krotka ``(detections, cover)`` albo ``LogScan(detections, cover, requests)`` z ADR 0007 pkt 7."""
    if isinstance(result, tuple) and len(result) == 2:
        return result[0], result[1], []
    return result.detections, result.cover, list(result.requests)


def _scan_sources(root: Path, database: Path | None, logs: Path | None, baseline: dict | None, known_admins: set[str],
                  session: ingest.Session, core: integrity.CoreChecksums | None = None, database_format: str = "sql",
                  log_config: LogConfig | None = None, correlation_window: int = DEFAULT_WINDOW_SECONDS,
                  yara: yarax.Adapter | None = None) -> tuple[list[Detection], dict[str, SourceCoverage], list[models.Observation], list[models.Observation]]:
    """Uruchamia skanery podanych źródeł; źródło niepodane dostaje powód zamiast skanu.

    Trzeci wynik: fakty bez ustalenia; czwarty: obserwacje ``HTTP_REQUEST`` z logów, materiał korelacji. Logi są
    czytane po plikach i bazie: ustalenia plikowe wyznaczają, które żądania korelacja może wykorzystać (``Focus``).
    """
    cover = {source: SourceCoverage(provided=False) for source in models.SOURCES}
    scan = files.scan_files(root, baseline, session, core, yara)
    detections, cover["files"], facts = scan.detections, scan.cover, list(scan.observations)
    if database:
        found, cover["database"], database_facts = database_scan.scan_database(
            database, known_admins, session, baseline_admins=set((baseline or {}).get("known_admins", [])), fmt=database_format)
        detections.extend(found)
        facts.extend(database_facts)
    else:
        cover["database"].note("Brak zrzutu bazy danych")
    requests: list[models.Observation] = []
    if logs:
        evidence = {item.id: item for item in map(_evidence, session.ledger)}
        # Bez ``Focus`` (wyjątek w nim to luka logów) parser trzyma każde żądanie do pliku kodu, do limitu.
        focus_errors = SourceCoverage()
        focus = rules.guarded(focus_errors, "correlate", _focus, detections, evidence, correlation_window,
                              (log_config or LogConfig()).uncertainty)
        found, cover["logs"], requests = _log_scan(scan_logs(logs, session, log_config, focus))
        for text in focus_errors.reasons:
            cover["logs"].degrade(text)
        detections.extend(found)
    else:
        cover["logs"].note("Brak logów HTTP")
    if baseline is None and core is None:
        cover["baseline"].note("Brak zaufanej migawki bazowej (baseline): porównanie plików z referencją niewykonane")
    else:  # manifest sum rdzenia jest częścią źródła ``baseline`` (zaufane referencje)
        cover["baseline"] = SourceCoverage()
        cover["baseline"].note(*(gap for record in session.ledger if record.source == "baseline" for gap in record.gaps))
        if baseline is None:
            cover["baseline"].note("Brak zaufanej migawki bazowej (baseline): referencją jest wyłącznie manifest sum rdzenia")
        elif not baseline.get("files"):
            cover["baseline"].note("Baseline nie zawiera skrótów plików (files): porównanie plików z referencją niewykonane")
        if core is not None:
            cover["baseline"].note("Manifest sum rdzenia (MD5) obejmuje tylko pliki dystrybucji WordPressa; zgodność z nim "
                                   "nie mówi nic o wtyczkach, motywach, uploads ani konfiguracji")
    return detections, cover, facts, requests


def compose_report(root: Path, database: Path | None, logs: Path | None,
                   baseline: dict | None, known_admins: set[str], case_id: str, *,
                   session: ingest.Session | None = None, core: integrity.CoreChecksums | None = None,
                   database_format: str = "sql", correlation_window: int = DEFAULT_WINDOW_SECONDS,
                   log_config: LogConfig | None = None, pseudonymizer: privacy.Pseudonymizer | None = None,
                   yara: yarax.Adapter | None = None) -> dict:
    """Zwraca raport ``poc-1`` jako słownik gotowy do zapisu.

    ``baseline`` musi pochodzić z ``load_baseline``, a ``core`` z ``load_core_checksums`` tej samej sesji.
    ``database_format`` (``sql`` albo ``jsonl``) wybiera parser zrzutu bazy; formatu nie zgaduje się po treści.
    ``correlation_window`` to okno relacji ``NEAR_IN_TIME`` w sekundach (ADR 0007 pkt 8).
    ``log_config`` to wybory operatora dotyczące logów (format, zaufane proxy, niepewność zegara); domyślnie combined.
    Teksty swobodne raportu są redagowane w jednym miejscu (``privacy.sanitize``); z ``pseudonymizer`` adresy IP
    klientów, loginy i ``user_id`` kont zastępują pseudonimy. Porównanie z ``known_admins`` odbywa się wcześniej, na loginach.
    ``yara`` to uruchomiony adapter YARA-X (``yarax.open_adapter``); jego cyklem życia zarządza wywołujący.
    """
    session = session or _session()
    check_window(correlation_window)
    if baseline is not None and integrity.baseline_record(session, core) is None:
        raise ValueError("baseline musi być wczytany przez load_baseline w tej samej sesji odczytu")
    if core is not None and core.record not in session.ledger:
        raise ValueError("manifest sum musi być wczytany przez load_core_checksums w tej samej sesji odczytu")
    detections, cover, facts, requests = _scan_sources(root, database, logs, baseline, known_admins, session, core,
                                                        database_format, log_config, correlation_window, yara)
    session_gaps = session.finish()  # od tej chwili rejestr sesji ma ostateczne statusy (także CHANGED z ponownej weryfikacji)
    for source, text in session.integrity_notes:
        for name in [source] if source else [name for name in models.SOURCES if cover[name].provided]:
            cover[name].degrade(text)
    evidence = {item.id: item for item in map(_evidence, session.ledger)}
    correlation = Correlation()
    if logs:  # bez logów nie ma żądań ani wykryć HTTP: korelacja nie miałaby czego łączyć
        correlation = rules.guarded(cover["logs"], "correlate", correlate, detections, requests, evidence, correlation_window,
                                    session.expired, default=Correlation())
    for note in correlation.notes:
        cover["logs"].degrade(note)
    timeline, undated = _timeline(detections, evidence, correlation.requests)
    cover["files"].note(*undated)
    findings = {item.id: item for item in [*rules.findings(detections, cover), *correlation.findings]}
    coverage = {source: _coverage(source, cover[source], session.ledger) for source in models.SOURCES}
    gaps = {reason for entry in coverage.values() for reason in entry.reasons} | set(session_gaps)
    return privacy.sanitize(models.Report(
        case_id=case_id, tool="WPIncidentLens PoC", tool_version=VERSION, analyzed_at_utc=models.utc_iso(datetime.now(timezone.utc)),
        assessment=models.assess(findings.values(), coverage), disclaimer=DISCLAIMER,
        evidence=tuple(evidence.values()), observations=tuple({item.id: item for item in [*(found.observation for found in detections), *facts, *correlation.requests]}.values()),
        findings=tuple(findings.values()), coverage=coverage, coverage_gaps=tuple(gaps), timeline=tuple(timeline)), pseudonymizer).to_dict()


def exit_code(report: dict) -> int:
    """Kod wyjścia z pokrycia, nigdy z ustaleń: 0 pełny zakres, 4 podane źródło nieprzetworzone, 3 każda inna niepełność."""
    if any(entry["status"] == models.CoverageStatus.FAILED for entry in report["coverage"].values()):
        return EXIT_UNPROCESSED
    return EXIT_COMPLETE if report["scope_complete"] else EXIT_PARTIAL


write_html = report.write_html  # reeksport: Reporter jest w wpincidentlens/report.py (ADR 0001, krok migracji 1)


def _positive_seconds(value: str) -> int:
    if not value.isascii() or not value.isdigit() or int(value) <= 0:
        raise argparse.ArgumentTypeError("wymagana dodatnia liczba całkowita sekund")
    return int(value)


def _timeout_seconds(value: str) -> int:
    seconds = _positive_seconds(value)
    if seconds > 3600:
        raise argparse.ArgumentTypeError("najwyżej 3600 sekund")
    return seconds


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="WPIncidentLens PoC — statyczna analiza kopii WordPressa, bazy SQL i logów",
        epilog="Kody wyjścia: 0 — zakres analizy pełny (ustalenia możliwe); 2 — błąd wywołania; 3 — zakres niepełny: "
               "najczęściej plik kodu niezweryfikowany względem zaufanej referencji (bez --baseline i --core-checksums "
               "dotyczy to każdego pliku kodu) albo brak --database lub --logs; także pominięte lub zmienione wpisy, "
               "limit, manifest sum innej wersji lub locale; 4 — podane źródło nieprzetworzone. "
               "Kod nie jest oceną kompromitacji: ocenę podaje pole assessment w report.json.")
    parser.add_argument("--files", type=Path, required=True)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--database-format", choices=database_scan.FORMATS, default="sql",
                        help="Format pliku --database: zrzut SQL (INSERT … VALUES) albo JSONL, jeden obiekt "
                             '{"table": …, "row": {…}} na wiersz; nie jest zgadywany po treści (%(default)s)')
    parser.add_argument("--logs", type=Path)
    parser.add_argument("--log-format", choices=FORMATS_OF_LOGS, default="combined",
                        help="Format wierszy --logs: combined i common (Apache/Nginx) albo json — jeden obiekt na wiersz "
                             "(kontrakt w docs/RULES.md); nie jest zgadywany po treści (%(default)s)")
    parser.add_argument("--trusted-proxy", action="append", default=[], metavar="CIDR",
                        help="Sieć zaufanego proxy (powtarzalna). Adres z forwarded_for (tylko format json) jest brany "
                             "pod uwagę wyłącznie dla połączeń z tych sieci; domyślnie brak")
    parser.add_argument("--log-clock-skew", type=float, metavar="SECONDS",
                        help="Deklarowana przez operatora niepewność zegara serwera logów w sekundach (nieujemna); "
                             "bez flagi zegar jest niezweryfikowany")
    parser.add_argument("--baseline", type=Path, help="Zaufany JSON: {files: {ścieżka: sha256}, known_admins: [...]} ")
    parser.add_argument("--core-checksums", type=Path,
                        help="Lokalny plik JSON z sumami MD5 rdzenia w kształcie api.wordpress.org core/checksums/1.0: "
                             "{checksums: {ścieżka: md5}}, opcjonalnie z wordpress_version i locale, porównywanymi "
                             "z wersją i locale witryny; narzędzie niczego nie pobiera z sieci")
    parser.add_argument("--known-admin", action="append", default=[])
    parser.add_argument("--case-id", default="WPINCIDENTLENS-DEMO",
                        help="Identyfikator sprawy: 1–64 znaki A-Z a-z 0-9 . _ -, pierwszy znak inny niż kropka i łącznik (%(default)s)")
    parser.add_argument("--operator-id", help="Pseudonim operatora zapisywany w case.json (te same znaki co --case-id); domyślnie brak")
    parser.add_argument("--correlation-window", type=_positive_seconds, default=DEFAULT_WINDOW_SECONDS, metavar="SECONDS",
                        help="Okno relacji NEAR_IN_TIME między żądaniem HTTP a mtime pliku z ustaleniem, w sekundach; "
                             "bliskość w czasie nie dowodzi przyczynowości (%(default)s)")
    parser.add_argument("--pseudonymize", action="store_true",
                        help="Zastąp adresy IP klientów, loginy i user_id kont pseudonimami ip-/user-/uid-<16 hex> (HMAC-SHA256 "
                             "z kluczem losowanym na jedno uruchomienie i nigdzie niezapisywanym): ta sama wartość ma ten sam "
                             "pseudonim tylko w obrębie jednego raportu. Jawne pozostają m.in. czas rejestracji konta, nazwy "
                             "w ścieżkach i kluczach (np. slug autora w URL) oraz domeny e-mail w cytatach")
    parser.add_argument("--yara-rules", type=Path, metavar="PATH",
                        help="Opcjonalnie: lokalny pakiet reguł YARA (plik .yar/.yara albo katalog takich plików z opcjonalnym "
                             "plikiem VERSION), skanowany YARA-X w osobnym procesie z limitami. Wymaga extra 'yara' (yara-x); "
                             "bez niego albo przy nieczytelnym pakiecie raport ma lukę pokrycia files. Błąd kompilacji: kod 2")
    parser.add_argument("--yara-timeout", type=_timeout_seconds, default=yarax.FILE_TIMEOUT_SECONDS, metavar="SECONDS",
                        help="Limit czasu skanu YARA jednego pliku w sekundach (%(default)s)")
    parser.add_argument("--output", type=Path, required=True)
    defaults = ingest.Limits()
    parser.add_argument("--allow-hardlinks", action="store_true",
                        help="Czytaj pliki z wieloma dowiązaniami twardymi (domyślnie pomijane z luką pokrycia)")
    parser.add_argument("--no-reverify", action="store_true",
                        help="Pomiń ponowną weryfikację skrótów po analizie (odnotowane w raporcie jako luka)")
    parser.add_argument("--max-files", type=int, default=MAX_FILES, help="Limit liczby plików, łącznie we wszystkich źródłach (%(default)s)")
    parser.add_argument("--max-entries", type=int, default=defaults.max_entries,
                        help="Limit liczby wszystkich wpisów: plików, katalogów, dowiązań i plików specjalnych (%(default)s)")
    parser.add_argument("--max-file-bytes", type=int, default=defaults.max_file_bytes, help="Limit rozmiaru jednego pliku (%(default)s)")
    parser.add_argument("--max-total-bytes", type=int, default=defaults.max_total_bytes, help="Limit łącznego rozmiaru czytanych plików (%(default)s)")
    parser.add_argument("--max-seconds", type=float, default=defaults.max_seconds, help="Limit czasu całej analizy w sekundach (%(default)s)")
    parser.add_argument("--max-depth", type=int, default=defaults.max_depth, help="Limit głębokości katalogów (%(default)s)")
    parser.add_argument("--max-path-bytes", type=int, default=defaults.max_path_bytes,
                        help="Limit długości ścieżki względnej do źródła w bajtach (%(default)s)")
    args = parser.parse_args(argv)
    try:
        context = case.build(
            files=args.files, database=args.database, database_format=args.database_format, logs=args.logs, baseline=args.baseline, output=args.output,
            case_id=args.case_id, operator_id=args.operator_id, known_admins=args.known_admin,
            allow_hardlinks=args.allow_hardlinks, reverify=not args.no_reverify, core_checksums=args.core_checksums,
            log_format=args.log_format, trusted_proxies=args.trusted_proxy, log_clock_skew=args.log_clock_skew,
            pseudonymize=args.pseudonymize,
            limits={"max_files": args.max_files, "max_entries": args.max_entries, "max_file_bytes": args.max_file_bytes,
                    "max_total_bytes": args.max_total_bytes, "max_scan_bytes": MAX_SCAN_BYTES, "max_seconds": args.max_seconds,
                    "max_depth": args.max_depth, "max_path_bytes": args.max_path_bytes})
    except case.CaseError as invalid:
        parser.error(str(invalid))
    session = ingest.Session(context.limits, allow_hardlinks=context.allow_hardlinks, reverify=context.reverify)
    baseline = None
    if context.baseline:
        try:
            baseline = case.check_baseline(load_baseline(context.baseline, session))
        except ValueError as invalid:
            parser.error(f"--baseline: {invalid}")
    core = None
    if context.core_checksums:
        try:
            core = load_core_checksums(context.core_checksums, session)
        except ValueError as invalid:
            parser.error(f"--core-checksums: {invalid}")
    admins = set(context.known_admins) | set((baseline or {}).get("known_admins", []))
    described = context.describe()
    yara = None
    if args.yara_rules is not None:
        evidence = [path for path in (context.files, context.database, context.logs) if path is not None]
        try:  # pakiet w materiale dowodowym byłby regułami napisanymi przez napastnika
            ingest.resolve_output(args.yara_rules, evidence)
        except ingest.IngestRefusal:
            parser.error("--yara-rules: pakiet reguł nie może leżeć w źródle dowodów (--files, --database, --logs) ani go zawierać")
        try:
            yara = yarax.open_adapter(args.yara_rules, args.yara_timeout, context.limits.max_seconds)
        except yarax.PackError as invalid:
            parser.error(f"--yara-rules: pakiet reguł się nie kompiluje:\n{invalid}")
    try:
        output = compose_report(context.files, context.database, context.logs, baseline, admins, context.case_id, session=session, core=core,
                                database_format=context.database_format, correlation_window=args.correlation_window,
                                log_config=LogConfig(context.log_format, context.proxy_networks(), context.log_clock_skew),
                                pseudonymizer=privacy.Pseudonymizer() if context.pseudonymize else None, yara=yara)
    finally:
        if yara is not None:
            yara.close()
    if yara is not None:
        described["yara"] = yara.describe()
    code = exit_code(output)
    try:
        report.write(context.output, output, described, code)
    except report.OutputRefusal as refusal:
        parser.error(f"--output: {refusal}")
    if not context.pseudonymize and privacy.personal_data(output):
        print(PERSONAL_DATA_WARNING, file=sys.stderr)
    print(json.dumps({"assessment": output["assessment"], "scope_complete": output["scope_complete"], "findings":len(output["findings"]),
                      "coverage_gaps":len(output["coverage_gaps"]), "exit_code": code, "report":str(context.output / "report.html")}, ensure_ascii=False))
    return code

if __name__ == "__main__":
    raise SystemExit(main())
