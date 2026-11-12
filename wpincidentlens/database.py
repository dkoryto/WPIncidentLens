"""Analiza zrzutu bazy: odczyt przez SecureIngest, parser wierszy (``sqldump``) i reguły (``dbrules``)."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from . import dbrules, ingest, models, sqldump
from .analysis import Detection, SourceCoverage, decoded, is_lossy

MAX_SQL_BYTES = 20 * 1024 * 1024
MAX_ROWS = 100000


def scan_database(path: Path, known_admins: set[str], session: ingest.Session,
                  baseline_admins: set[str] | None = None) -> tuple[list[Detection], SourceCoverage, list[models.Observation]]:
    """Trzeci wynik to fakty bez ustalenia (np. inwentarz). Zrzut, którego nie udało się bezpiecznie odczytać, nie ma skrótu w rejestrze sesji — pokrycie wychodzi wtedy ``FAILED``."""
    cover, findings, facts = SourceCoverage(), [], []
    item = session.read_file(path, "database", keep_limit=MAX_SQL_BYTES)
    cover.note(*item.gaps)
    if item.sha256 is None:
        return findings, cover, facts
    if item.size > MAX_SQL_BYTES:
        cover.fail(f"Eksport SQL większy niż {MAX_SQL_BYTES} B: analiza DB pominięta w PoC")
        return findings, cover, facts
    if item.content is None:
        cover.fail("Treść eksportu SQL niedostępna po odczycie (plik zmienił się w trakcie): analiza DB pominięta")
        return findings, cover, facts
    if is_lossy(item.content):
        cover.degrade("Eksport SQL nie jest poprawnym UTF-8: zdekodowano ze znakami zastępczymi, wartości mogą być zniekształcone")
    sql = decoded(item.content).read()
    rules = dbrules.RowAnalysis(item)
    tables, count = set(), 0
    dropped: list[str] = []
    for table, cols, cells in sqldump.iter_insert_rows(sql, dropped):
        tables.add(table)
        count += 1
        if count > MAX_ROWS:
            cover.degrade(f"Przekroczono {MAX_ROWS} wierszy INSERT, analiza częściowa")
            break
        rules.feed(table, cols, cells, count)
    if not tables:
        cover.fail("Brak obsługiwanych instrukcji INSERT; parser PoC nie interpretuje tego formatu SQL")
    elif not rules.core_seen:
        cover.fail("Zrzut nie zawiera odczytanych wierszy tabel *_users, *_usermeta ani *_options; "
                   "analiza DB nie objęła danych WordPressa")
    if dropped:
        cover.degrade(f"Pominięto {len(dropped)} niedomkniętych instrukcji INSERT (zrzut ucięty lub uszkodzony)")
    findings.extend(rules.finish(cover, known_admins, baseline_admins))
    facts.extend(rules.observations)
    unanalysed: Counter = Counter()
    unsupported = sum(1 for start in sqldump._write_statement_starts(sql, unanalysed) if sqldump._INSERT_HEAD.match(sql, start) is None)
    if unanalysed:
        listed = ", ".join(f"{keyword} ×{number}" for keyword, number in sorted(unanalysed.items(), key=lambda pair: (-pair[1], pair[0]))[:8])
        cover.degrade(f"Zrzut zawiera {sum(unanalysed.values())} instrukcji, których parser PoC nie analizuje: {listed}")
    if unsupported:
        cover.degrade(f"Pominięto {unsupported} instrukcji INSERT/REPLACE w nieobsługiwanej składni "
                      "(np. REPLACE INTO, INSERT IGNORE, nazwa z bazą, INSERT ... SET, komentarz wykonywalny, DELIMITER)")
    cover.note("Parser SQL PoC obsługuje wybrane INSERT; nie obsługuje triggerów, procedur, pełnej składni ani multisite")
    return findings, cover, facts
