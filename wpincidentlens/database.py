"""Analiza zrzutu bazy: odczyt przez SecureIngest, parser wierszy (``sqldump`` albo ``jsonldb``) i reguły (``dbrules``).

Zrzut jest czytany strumieniowo: porcje z tego samego odczytu, w którym SecureIngest liczy SHA-256, trafiają
wprost do parsera (ADR 0006 pkt 2). Rozmiar zrzutu ogranicza ogólny limit pliku (``--max-file-bytes``).
"""
from __future__ import annotations

from pathlib import Path

from . import dbrules, ingest, jsonldb, models, sqldump
from .analysis import Detection, SourceCoverage
from .case import DATABASE_FORMATS

MAX_ROWS = 1_000_000  # wierszy tabel rdzenia przekazanych regułom; dalsze są tylko liczone
MAX_ROW_BYTES = 256 * 1024 * 1024  # szacowana pamięć wierszy czekających na reguły: granica przy zrzucie 2 GiB
_ROW_COST, _CELL_COST = 120, 64  # narzut obiektów Pythona na wiersz i na komórkę (lista, krotka, str), z zapasem
FORMATS = DATABASE_FORMATS  # wybiera operator flagą --database-format; formatu nie zgaduje się po treści (ADR 0006 pkt 9)


def scan_database(path: Path, known_admins: set[str], session: ingest.Session,
                  baseline_admins: set[str] | None = None, fmt: str = "sql",
                  ) -> tuple[list[Detection], SourceCoverage, list[models.Observation]]:
    """Trzeci wynik to fakty bez ustalenia (np. inwentarz). Zrzut, którego nie udało się bezpiecznie odczytać, nie ma skrótu w rejestrze sesji — pokrycie wychodzi wtedy ``FAILED``."""
    if fmt not in FORMATS:
        raise ValueError(f"nieznany format bazy: {fmt!r}")
    cover, findings, facts = SourceCoverage(), [], []
    parser = (sqldump.DumpParser if fmt == "sql" else jsonldb.JsonlParser)(wanted=dbrules.is_core_table)
    rows: list = []
    analysed, held = [0], [0]

    def consume(batch: list) -> None:
        for row in batch:
            analysed[0] += 1
            size = (_ROW_COST + sum(_CELL_COST + len(cell or "") for cell in row[2])
                    + sum(_CELL_COST + len(column) for column in row[1]))
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
    # Na serwerze z lower_case_table_names=1 lub 2 tabela WP_USERMETA to wp_usermeta: jej wierszy reguły nie widzą.
    spellings: dict[str, set[str]] = {}
    for table in parser.tables | getattr(parser, "ddl_names", set()):
        if dbrules.is_core_table(table.lower()):
            spellings.setdefault(table.lower(), set()).add(table)
    variants = sorted(table for group in spellings.values() for table in group if not dbrules.is_core_table(table) or len(group) > 1)
    if getattr(parser, "names_overflow", False):
        cover.degrade(f"Zrzut ma więcej niż {sqldump.MAX_TABLES} różnych nazw tabel lub definicji: pisownia nazw tabel "
                      "i kolejność kolumn z CREATE TABLE nie zostały sprawdzone dla wszystkich")
    if variants:
        cover.degrade(f"Pominięto wiersze {len(variants)} tabel o nazwie różniącej się od tabel WordPressa tylko wielkością liter "
                      f"({', '.join(name[:40] for name in variants[:5])}{', …' if len(variants) > 5 else ''}); "
                      "na serwerze nierozróżniającym wielkości liter trafiłyby do tabel rdzenia")
    if analysed[0] > len(rows):
        cover.degrade(f"Reguły objęły {len(rows)} z {analysed[0]} wierszy tabel użytkowników i opcji "
                      f"(limit {MAX_ROWS} wierszy i {MAX_ROW_BYTES} B treści)")
    if fmt == "sql":
        _sql_read_gaps(parser, rules, cover)
    else:
        _jsonl_read_gaps(parser, rules, cover)
    findings.extend(rules.finish(cover, known_admins, baseline_admins))
    facts.extend(rules.observations)
    if fmt == "sql":
        _sql_grammar_gaps(parser, cover)
        cover.note("Parser SQL obsługuje INSERT INTO … VALUES z literałami; nie interpretuje triggerów, procedur ani multisite")
    else:
        cover.note('Adapter JSONL przyjmuje jeden obiekt na wiersz pliku: {"table": nazwa, "row": {kolumna: łańcuch, liczba '
                   "lub null}}; kompletność eksportu zależy od narzędzia, które go wykonało; nie interpretuje multisite")
    return findings, cover, facts


def _no_core_rows(rules: dbrules.RowAnalysis, cover: SourceCoverage) -> None:
    if not rules.core_seen:
        cover.fail("Zrzut nie zawiera odczytanych wierszy tabel *_users, *_usermeta ani *_options; "
                   "analiza DB nie objęła danych WordPressa")


def _sql_read_gaps(parser: sqldump.DumpParser, rules: dbrules.RowAnalysis, cover: SourceCoverage) -> None:
    if parser.oversized_at is not None:
        cover.degrade(f"Instrukcja SQL dłuższa niż {parser.max_statement} B (od bajtu {parser.oversized_at}): "
                      "dalszej części zrzutu nie analizowano")
    if parser.mode_change_at is not None:
        cover.degrade(f"Zrzut zmienia sposób czytania łańcuchów ({parser.mode_change}, instrukcja od bajtu "
                      f"{parser.mode_change_at}): parser tego trybu nie obsługuje, dalszej części zrzutu nie analizowano")
    if not parser.tables:
        cover.fail("Brak obsługiwanych instrukcji INSERT; parser PoC nie interpretuje tego formatu SQL")
    else:
        _no_core_rows(rules, cover)
    if parser.lossy_cells:
        cover.degrade(f"Eksport SQL zawiera {parser.lossy_cells} wartości, które nie są poprawnym UTF-8: zdekodowano je "
                      "ze znakami zastępczymi, mogą być zniekształcone")
    if parser.truncated:
        cover.degrade(f"Pominięto {len(parser.truncated)} niedomkniętych instrukcji (zrzut ucięty lub uszkodzony)")


def _sql_grammar_gaps(parser: sqldump.DumpParser, cover: SourceCoverage) -> None:
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


def _jsonl_read_gaps(parser: jsonldb.JsonlParser, rules: dbrules.RowAnalysis, cover: SourceCoverage) -> None:
    if parser.rejected:
        first = parser.first_rejected
        listed = ", ".join(f"{jsonldb.REASONS[reason]} ×{number} (pierwszy: wiersz {first[reason]})"
                           for reason, number in sorted(parser.rejected.items(), key=lambda pair: (-pair[1], first[pair[0]])))
        cover.degrade(f"Pominięto {sum(parser.rejected.values())} wierszy JSONL niezgodnych z kontraktem: {listed}")
    if not parser.rows:
        cover.fail('Plik JSONL nie zawiera żadnego wiersza zgodnego z kontraktem {"table": …, "row": {…}}; '
                   "sprawdź format wybrany flagą --database-format")
    else:
        _no_core_rows(rules, cover)
