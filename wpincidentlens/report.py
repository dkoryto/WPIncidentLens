"""Reporter (C12): jedyne miejsce, które pisze do katalogu wyników (ADR 0001, ADR 0002 D4).

Każdy plik powstaje jako plik tymczasowy tworzony względem deskryptora katalogu wyników
(``O_CREAT|O_EXCL|O_NOFOLLOW``, tryb 0600) i dopiero w całości zapisany trafia pod nazwę docelową
przez ``os.replace``. Wpis o nazwie docelowej jest więc zastępowany, nigdy otwierany: dowiązanie
``report.json → cokolwiek`` znika, a jego cel pozostaje nietknięty. Sam katalog wyników jest
otwierany z ``O_DIRECTORY|O_NOFOLLOW``.

Czego moduł NIE gwarantuje: zamiana kilku plików nie jest jedną operacją (błąd między zamianami
zostawia zestaw mieszany), a dowiązania w katalogach nadrzędnych katalogu wyników nie są sprawdzane.
"""
from __future__ import annotations

import base64
import contextlib
import errno
import hashlib
import html
import os
import secrets
from pathlib import Path

from . import ingest, models, outputs, redact, rules
from .outputs import encode as _encode
from .outputs import to_json as _json

REPORT_JSON = "report.json"
REPORT_HTML = "report.html"
CASE_JSON = "case.json"


class OutputRefusal(Exception):
    """Katalogu wyników nie da się bezpiecznie użyć. Komunikat nie zawiera ścieżki ani celu dowiązania."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason

    def __str__(self) -> str:
        if self.reason in ("ELOOP", "ENOTDIR"):  # symlink daje ELOOP (macOS) albo ENOTDIR (Linux)
            return "katalog wyników jest dowiązaniem symbolicznym albo nie jest katalogiem; podaj ścieżkę rzeczywistą"
        return f"nie można przygotować katalogu wyników ({self.reason})"


def _open_directory(directory: str | os.PathLike[str], *, create: bool) -> int:
    target = os.fspath(Path(directory))  # Path usuwa końcowy "/", który kazałby jądru podążyć za dowiązaniem
    try:
        if create:
            os.makedirs(target, exist_ok=True)
        return os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise OutputRefusal(errno.errorcode.get(exc.errno, "OSError")) from None


def _create(dir_fd: int, name: str, data: bytes) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish(dir_fd: int, files: dict[str, bytes]) -> None:
    """Zapisuje wszystkie pliki pod nazwami tymczasowymi, potem zamienia je na docelowe; po błędzie sprząta."""
    pending = {name: f".{name}.{secrets.token_hex(8)}.tmp" for name in files}
    try:
        for name, data in files.items():
            _create(dir_fd, pending[name], data)
        for name in files:
            os.replace(pending[name], name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            del pending[name]
    finally:
        for temporary in pending.values():
            with contextlib.suppress(OSError):
                os.unlink(temporary, dir_fd=dir_fd)


# --- raport HTML (ADR 0002 D3, ADR 0008 pkt 3) -------------------------------------------------
#
# Stronę składają wyłącznie pomocniki poniżej. Wartość spoza kodu (każda z raportu) trafia do HTML tylko
# przez ``_text``, jedyne miejsce escapowania; bez zmian przechodzi jedynie ``_Markup``, czyli fragment
# złożony przez te pomocniki. Nazwy znaczników i atrybutów pochodzą wyłącznie z kodu.

_STYLE = ("body{font:16px/1.5 system-ui,sans-serif;margin:3em auto;max-width:1100px;padding:0 1em;color:#192938}"
          "h1{font-size:2em}h2{margin-top:2em}table{border-collapse:collapse;width:100%}"
          "td,th{border-bottom:1px solid #cbd5e1;padding:.65em;text-align:left;vertical-align:top}th{background:#edf2f7}"
          "small{color:#48596c}code{word-break:break-all}"
          ".notice{border-left:4px solid #b7791f;background:#fffaf0;padding:.65em 1em}")
_STYLE_SHA256 = base64.b64encode(hashlib.sha256(_STYLE.encode("utf-8")).digest()).decode("ascii")
CONTENT_SECURITY_POLICY = f"default-src 'none'; style-src 'sha256-{_STYLE_SHA256}'; base-uri 'none'; form-action 'none'"


class _Markup(str):
    """Fragment HTML złożony przez pomocniki tego modułu; nigdy wartość z raportu."""


_VIEWPORT = "width=device-width,initial-scale=1"
# Wartość z raportu nigdy nie trafia do atrybutu (href, src, title, id, class…): atrybut przyjmuje tylko te stałe.
_ATTRIBUTE_VALUES = frozenset({"pl", "utf-8", "Content-Security-Policy", CONTENT_SECURITY_POLICY, "referrer", "no-referrer",
                               "viewport", _VIEWPORT, "notice"})


def _text(value: object) -> _Markup:
    """Jedyne miejsce escapowania: każda wartość staje się tekstem, nie znacznikiem (``_Markup`` przechodzi bez zmian).

    Przed escapowaniem ``redact.neutralise`` zastępuje znaki sterujące i formatujące (np. RLO, znaki zerowej
    szerokości), które zmieniłyby wygląd nazwy pliku lub loginu na stronie.
    """
    return value if isinstance(value, _Markup) else _Markup(html.escape(redact.neutralise(str(value)), quote=True))


def _attributes(attributes: dict[str, str]) -> str:
    """``class_`` → ``class``, ``http_equiv`` → ``http-equiv``; wartość musi być stałą z ``_ATTRIBUTE_VALUES``."""
    for value in attributes.values():
        if value not in _ATTRIBUTE_VALUES:
            raise ValueError("atrybut HTML przyjmuje tylko stałe z kodu, nie wartości z raportu")
    return "".join(f' {name.rstrip("_").replace("_", "-")}="{_text(value)}"' for name, value in attributes.items())


def _element(tag: str, *children: object, **attributes: str) -> _Markup:
    return _Markup(f"<{tag}{_attributes(attributes)}>{''.join(_text(child) for child in children)}</{tag}>")


def _void(tag: str, **attributes: str) -> _Markup:
    return _Markup(f"<{tag}{_attributes(attributes)}>")


def _join(*parts: object) -> _Markup:
    return _Markup("".join(_text(part) for part in parts))


def _table(headers: tuple[str, ...], rows: list[tuple]) -> _Markup:
    return _element("table", _element("thead", _element("tr", *(_element("th", header) for header in headers))),
                    _element("tbody", *(_element("tr", *(_element("td", cell) for cell in row)) for row in rows)))


def _counted(entries: dict | None) -> tuple:
    """Liczba wpisów odczytanych i pozostałych (pominiętych, błędnych, zmienionych); raport przeniesiony z 0.1.0 ich nie zna."""
    if entries is None:
        return "brak danych", "brak danych"
    read = str(ingest.ReadStatus.READ)
    return entries.get(read, 0), sum(count for status, count in entries.items() if status != read)


def _privacy_notice(pseudonymized: bool) -> _Markup:
    """Ostrzeżenie B8 (ADR 0008 pkt 5): bez ``--pseudonymize`` raport zawiera jawne adresy IP i loginy."""
    if pseudonymized:
        return _element("p", "Adresy IP klientów i loginy kont zastąpiono pseudonimami (--pseudonymize); "
                             "ten sam pseudonim oznacza tę samą wartość tylko w obrębie tego uruchomienia.", class_="notice")
    return _element("p", _element("strong", "Raport zawiera dane osobowe"),
                    ": adresy IP klientów i loginy kont. Przed przekazaniem raportu dalej rozważ analizę z opcją "
                    "--pseudonymize, która zastępuje je pseudonimami.", class_="notice")


def render_html(report: dict, *, pseudonymized: bool = False) -> str:
    places = {item["id"]: models.describe_location(item["location"]) for item in report.get("observations", [])}

    def where(finding: dict) -> str:
        return "; ".join(dict.fromkeys(places.get(reference, reference) for reference in finding["observations"]))

    findings = [(item["severity"], item["confidence"], item["rule_id"], where(item), item["reason"]) for item in report["findings"]]
    coverage = [(source, entry["status"], *_counted(entry["entries"])) for source, entry in report.get("coverage", {}).items()]
    timeline = [(item["time_utc"], item["event"], item["source"], item["timestamp_basis"]) for item in report.get("timeline", [])]
    scope = {True: "pełny", False: "niepełny"}.get(report.get("scope_complete"), "nieokreślony")
    head = _join(_void("meta", charset="utf-8"),
                 _void("meta", http_equiv="Content-Security-Policy", content=CONTENT_SECURITY_POLICY),
                 _void("meta", name="referrer", content="no-referrer"),
                 _void("meta", name="viewport", content=_VIEWPORT),
                 _element("title", f"WPIncidentLens · {report['case_id']}"),
                 _Markup(f"<style>{_STYLE}</style>"))  # stała z kodu; jej skrót jest w CSP
    body = _join(
        _element("h1", "WPIncidentLens — raport analityczny"),
        _element("p", "Sprawa: ", _element("b", report["case_id"]), " · ", report["analyzed_at_utc"]),
        _element("p", "Stan: ", _element("strong", report["assessment"]), ". Zakres analizy: ", _element("strong", scope), ". ",
                 report["disclaimer"]),
        _privacy_notice(pseudonymized),
        _element("h2", f"Ustalenia ({len(report['findings'])})"),
        _table(("Waga", "Pewność", "Reguła", "Źródło", "Wyjaśnienie"), findings),
        _element("h2", "Pokrycie źródeł"),
        _table(("Źródło", "Status", "Wpisy odczytane", "Wpisy pominięte lub zmienione"), coverage),
        _element("h2", "Oś czasu (orientacyjna)"),
        _table(("UTC", "Zdarzenie", "Źródło", "Podstawa czasu"), timeline),
        _element("h2", "Ograniczenia danych"),
        _element("ul", *(_element("li", gap) for gap in report["coverage_gaps"])),
        _element("p", _element("small", "Pełny manifest SHA-256 i metadane są w report.json. Dane wejściowe nie są modyfikowane.")))
    return "<!doctype html>" + _element("html", _element("head", head), _element("body", body), lang="pl")


def write_html(report: dict, path: Path, *, pseudonymized: bool = False) -> None:
    """Zapisuje sam raport HTML pod wskazaną ścieżką; katalog nadrzędny musi istnieć."""
    path = Path(path)
    dir_fd = _open_directory(path.parent, create=False)
    try:
        _publish(dir_fd, {path.name: _encode(render_html(report, pseudonymized=pseudonymized))})
    finally:
        os.close(dir_fd)


def case_record(case: dict, report: dict, report_sha256: str, exit_code: int, output_digests: dict[str, str] | None = None) -> dict:
    """Dokument ``case.json``: opis sprawy sprzed analizy (``CaseContext.describe()``) uzupełniony o jej wynik.

    ``output_digests`` trafia do pola ``outputs`` (opcjonalnego w ``case-poc-1``): SHA-256 każdego innego pliku zapisanego w tym przebiegu.
    """
    record = {
        "schema_version": case["schema_version"], "case_id": case["case_id"], "operator_id": case["operator_id"],
        "tool": report["tool"], "tool_version": report["tool_version"],
        "created_at_utc": case["created_at_utc"], "analysis_finished_at_utc": report["analyzed_at_utc"],
        "sources": case["sources"], "limits": case["limits"], "flags": case["flags"],
        "report": {"file": REPORT_JSON, "sha256": report_sha256},
        "assessment": report["assessment"], "exit_code": exit_code,
        "ruleset": rules.descriptor(),
    }
    if output_digests is not None:
        record["outputs"] = output_digests
    return record


def write(directory: Path, report: dict, case: dict, exit_code: int) -> None:
    """Tworzy katalog wyników, jeśli go nie ma, i zapisuje w nim ``report.json``, ``report.html``, widoki z ``outputs.VIEWS``
    oraz ``case.json``.

    Wszystkie pliki przechodzą przez jeden ``_publish``; ``case.json`` jest zamieniany jako ostatni i podaje SHA-256
    każdego pozostałego pliku (``report`` i ``outputs``).
    """
    html_page = render_html(report, pseudonymized=case["flags"].get("pseudonymize", False))
    files = {REPORT_JSON: _json(report), REPORT_HTML: _encode(html_page), **outputs.render(report, exit_code)}
    digests = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    files[CASE_JSON] = _json(case_record(case, report, digests[REPORT_JSON], exit_code, digests))
    dir_fd = _open_directory(directory, create=True)
    try:
        _publish(dir_fd, files)
    finally:
        os.close(dir_fd)
