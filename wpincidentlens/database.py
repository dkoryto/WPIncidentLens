"""Analiza zrzutu bazy: odczyt przez SecureIngest, parser wierszy (``sqldump``) i reguły (``dbrules``).

Zrzut jest czytany strumieniowo: porcje z tego samego odczytu, w którym SecureIngest liczy SHA-256, trafiają
wprost do parsera (ADR 0006 pkt 2). Rozmiar zrzutu ogranicza ogólny limit pliku (``--max-file-bytes``).
"""
from __future__ import annotations

from pathlib import Path

from . import dbrules, ingest, models, sqldump
from .analysis import Detection, SourceCoverage

MAX_ROWS = 1_000_000  # wierszy tabel rdzenia przekazanych regułom; dalsze są tylko liczone
MAX_ROW_BYTES = 256 * 1024 * 1024  # łączny rozmiar komórek czekających na reguły: granica pamięci przy zrzucie 2 GiB


def scan_database(path: Path, known_admins: set[str], session: ingest.Session,
                  baseline_admins: set[str] | None = None) -> tuple[list[Detection], SourceCoverage, list[models.Observation]]:
    """Trzeci wynik to fakty bez ustalenia (np. inwentarz). Zrzut, którego nie udało się bezpiecznie odczytać, nie ma skrótu w rejestrze sesji — pokrycie wychodzi wtedy ``FAILED``."""
    cover, findings, facts = SourceCoverage(), [], []
    parser = sqldump.DumpParser(wanted=dbrules.is_core_table)
    rows: list = []
    analysed, held = [0], [0]

    def consume(batch: list) -> None:
        for row in batch:
            analysed[0] += 1
            size = sum(len(cell) for cell in row[2] if cell is not None)
            if analysed[0] <= MAX_ROWS and held[0] + size <= MAX_ROW_BYTES:
                held[0] += size
                rows.append(row)

    # Reguły potrzebują wpisu rejestru (``Evidence``), który powstaje dopiero po odczycie: wiersze czekają w ``rows``,
    # a pamięć ograniczają ``MAX_ROWS`` i ``MAX_ROW_BYTES``.
    item = session.read_file(path, "database", keep_limit=0, sink=lambda chunk: consume(parser.feed(chunk)))
    cover.note(*item.gaps)
    if item.sha256 is None:
        return findings, cover, facts
    consume(parser.close())
    rules = dbrules.RowAnalysis(item)
    for table, columns, cells, number in rows:
        rules.feed(table, columns, cells, number)
    rules.note_tables(parser.tables)
    if analysed[0] > len(rows):
        cover.degrade(f"Reguły objęły {len(rows)} z {analysed[0]} wierszy tabel użytkowników i opcji "
                      f"(limit {MAX_ROWS} wierszy i {MAX_ROW_BYTES} B treści)")
    if parser.oversized_at is not None:
        cover.degrade(f"Instrukcja SQL dłuższa niż {parser.max_statement} B (od bajtu {parser.oversized_at}): "
                      "dalszej części zrzutu nie analizowano")
    if not parser.tables:
        cover.fail("Brak obsługiwanych instrukcji INSERT; parser PoC nie interpretuje tego formatu SQL")
    elif not rules.core_seen:
        cover.fail("Zrzut nie zawiera odczytanych wierszy tabel *_users, *_usermeta ani *_options; "
                   "analiza DB nie objęła danych WordPressa")
    if parser.lossy_cells:
        cover.degrade(f"Eksport SQL zawiera {parser.lossy_cells} wartości, które nie są poprawnym UTF-8: zdekodowano je "
                      "ze znakami zastępczymi, mogą być zniekształcone")
    if parser.truncated:
        cover.degrade(f"Pominięto {len(parser.truncated)} niedomkniętych instrukcji (zrzut ucięty lub uszkodzony)")
    findings.extend(rules.finish(cover, known_admins, baseline_admins))
    facts.extend(rules.observations)
    if parser.unanalysed:
        listed = ", ".join(f"{keyword} ×{number}" for keyword, number
                           in sorted(parser.unanalysed.items(), key=lambda pair: (-pair[1], pair[0]))[:8])
        cover.degrade(f"Zrzut zawiera {sum(parser.unanalysed.values())} instrukcji, których parser PoC nie analizuje: {listed}")
    if parser.unsupported:
        cover.degrade(f"Pominięto {parser.unsupported} instrukcji INSERT/REPLACE w nieobsługiwanej składni "
                      "(np. REPLACE INTO, INSERT IGNORE, nazwa z bazą, INSERT ... SET, ON DUPLICATE KEY UPDATE, "
                      "komentarz wykonywalny, DELIMITER, polecenie klienta)")
    if parser.expression_rows:
        cover.degrade(f"Pominięto {parser.expression_rows} wierszy INSERT z wyrażeniem SQL zamiast literału (np. CONCAT(...))")
    cover.note("Parser SQL obsługuje INSERT INTO … VALUES z literałami; nie interpretuje triggerów, procedur ani multisite")
    return findings, cover, facts
