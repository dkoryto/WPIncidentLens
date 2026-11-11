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

import contextlib
import errno
import html
import json
import os
import secrets
from pathlib import Path

from . import ingest, models

REPORT_JSON = "report.json"
REPORT_HTML = "report.html"


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


def _encode(text: str) -> bytes:
    """UTF-8; znak, którego nie da się zakodować (samotny surogat), dostaje postać ``\\uXXXX`` zamiast gubić cały raport."""
    return text.encode("utf-8", "backslashreplace")


def _json(document: dict) -> bytes:
    return _encode(json.dumps(document, indent=2, ensure_ascii=False))


def render_html(report: dict) -> str:
    esc = lambda s: html.escape(str(s), quote=True)
    places = {item["id"]: models.describe_location(item["location"]) for item in report.get("observations", [])}
    where = lambda item: "; ".join(dict.fromkeys(places.get(reference, reference) for reference in item["observations"]))
    rows = "".join(f"<tr><td>{esc(i['severity'])}</td><td>{esc(i['confidence'])}</td><td>{esc(i['rule_id'])}</td><td>{esc(where(i))}</td><td>{esc(i['reason'])}</td></tr>" for i in report["findings"])
    gaps = "".join(f"<li>{esc(g)}</li>" for g in report["coverage_gaps"])
    timeline_rows = "".join(f"<tr><td>{esc(i['time_utc'])}</td><td>{esc(i['event'])}</td><td>{esc(i['source'])}</td><td>{esc(i['timestamp_basis'])}</td></tr>" for i in report.get("timeline", []))

    def counted(entries: dict | None) -> tuple:
        """Liczba wpisów odczytanych i pozostałych (pominiętych, błędnych, zmienionych); raport przeniesiony z 0.1.0 ich nie zna."""
        if entries is None:
            return "brak danych", "brak danych"
        read = str(ingest.ReadStatus.READ)
        return entries[read], sum(count for status, count in entries.items() if status != read)

    coverage_rows = "".join(
        f"<tr><td>{esc(source)}</td><td>{esc(entry['status'])}</td>" + "".join(f"<td>{esc(count)}</td>" for count in counted(entry["entries"])) + "</tr>"
        for source, entry in report.get("coverage", {}).items())
    scope = {True: "pełny", False: "niepełny"}.get(report.get("scope_complete"), "nieokreślony")
    return f"""<!doctype html><html lang=\"pl\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>WPTrace · {esc(report['case_id'])}</title>
<style>body{{font:16px/1.5 system-ui,sans-serif;margin:3em auto;max-width:1100px;padding:0 1em;color:#192938}}h1{{font-size:2em}}h2{{margin-top:2em}}table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #cbd5e1;padding:.65em;text-align:left;vertical-align:top}}th{{background:#edf2f7}}small{{color:#48596c}}code{{word-break:break-all}}</style>
<h1>WPTrace — raport analityczny</h1><p>Sprawa: <b>{esc(report['case_id'])}</b> · {esc(report['analyzed_at_utc'])}</p>
<p>Stan: <strong>{esc(report['assessment'])}</strong>. Zakres analizy: <strong>{esc(scope)}</strong>. {esc(report['disclaimer'])}</p>
<h2>Ustalenia ({len(report['findings'])})</h2><table><thead><tr><th>Waga</th><th>Pewność</th><th>Reguła</th><th>Źródło</th><th>Wyjaśnienie</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Pokrycie źródeł</h2><table><thead><tr><th>Źródło</th><th>Status</th><th>Wpisy odczytane</th><th>Wpisy pominięte lub zmienione</th></tr></thead><tbody>{coverage_rows}</tbody></table>
<h2>Oś czasu (orientacyjna)</h2><table><thead><tr><th>UTC</th><th>Zdarzenie</th><th>Źródło</th><th>Podstawa czasu</th></tr></thead><tbody>{timeline_rows}</tbody></table>
<h2>Ograniczenia danych</h2><ul>{gaps}</ul><p><small>Pełny manifest SHA-256 i metadane są w report.json. Dane wejściowe nie są modyfikowane.</small></p></html>"""


def write_html(report: dict, path: Path) -> None:
    """Zapisuje sam raport HTML pod wskazaną ścieżką; katalog nadrzędny musi istnieć."""
    path = Path(path)
    dir_fd = _open_directory(path.parent, create=False)
    try:
        _publish(dir_fd, {path.name: _encode(render_html(report))})
    finally:
        os.close(dir_fd)


def write(directory: Path, report: dict) -> None:
    """Tworzy katalog wyników, jeśli go nie ma, i zapisuje w nim ``report.json`` oraz ``report.html``."""
    files = {REPORT_JSON: _json(report), REPORT_HTML: _encode(render_html(report))}
    dir_fd = _open_directory(directory, create=True)
    try:
        _publish(dir_fd, files)
    finally:
        os.close(dir_fd)
