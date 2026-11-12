"""Parser zrzutu SQL (podzbiór mysqldump INSERT). Dostaje tekst już przeczytany przez SecureIngest; niczego nie wykonuje."""
from __future__ import annotations

import re
from collections import Counter


def _iter_row_groups(values: str):
    """Yield innermost top-level "(...)" groups of a VALUES list in one linear pass.

    Replaces a backtracking regex that took exponential time on crafted input.
    Parentheses inside quoted strings are ignored; a group containing a nested
    parenthesis outside a string is not a plain row and only its innermost part
    is yielded, as before.
    """
    start, quoted, escaped, i = None, False, False, 0
    while i < len(values):
        ch = values[i]
        if quoted:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "'":
                if i + 1 < len(values) and values[i+1] == "'":
                    i += 1
                else:
                    quoted = False
        elif ch == "'":
            quoted = True
        elif ch == "(":
            start = i
        elif ch == ")" and start is not None:
            yield values[start:i+1]
            start = None
        i += 1


# Lista kolumn nie zawiera nawiasów: [^;()]* kończy się na pierwszym nawiasie, więc nagłówek bez
# zamknięcia nie jest skanowany do końca pliku przy każdym wystąpieniu (czas kwadratowy, #17).
# Biały znak przed VALUES dopasowuje dokładnie jeden kwantyfikator, więc długi ciąg spacji nie daje nawrotów.
_INSERT_HEAD = re.compile(r"INSERT\s+INTO\s+`?([A-Za-z0-9_]+)(?![A-Za-z0-9_])`?\s*(?:(\([^;()]*\))\s*)?VALUES\s*", re.I)
# Leksemy zrzutu SQL potrzebne do znalezienia początków instrukcji. Każda alternatywa zawsze się dopasowuje
# (niedomknięty łańcuch lub komentarz sięga końca tekstu), a kwantyfikatory zaborcze wykluczają nawroty.
_SQL_TOKEN = re.compile(r"""
      '(?:[^'\\]|\\.|'')*+(?:'|\Z)
    | "(?:[^"\\]|\\.|"")*+(?:"|\Z)
    | `[^`]*+(?:`|\Z)
    | (?P<comment> --(?=\s|\Z)[^\n]*+ | \#[^\n]*+ | /\*.*?(?:\*/|\Z) )
    | (?P<end> ; )
    | (?P<space> \s++ )
    | (?P<word> [A-Za-z_]++ )
    | .
""", re.X | re.S)
# Bez \b z lewej: w "/*!50001INSERT" numer wersji przylega do słowa kluczowego i granicy słowa tam nie ma.
_WRITE_KEYWORD = re.compile(r"(?<![A-Za-z_])(?:INSERT|REPLACE)(?![A-Za-z0-9_])", re.I)
_CORE_TABLE_CELLS = {"_users": 2, "_usermeta": 4, "_options": 3}


# Instrukcje, które zrzut może zawierać, a których pominięcie nie ukrywa danych: ustawienia sesji i definicje tabel.
_INERT_STATEMENTS = frozenset({"SET", "USE", "LOCK", "UNLOCK", "START", "COMMIT", "BEGIN"})
_INERT_OBJECTS = frozenset({"TABLE", "DATABASE", "SCHEMA"})  # po CREATE / DROP / ALTER


def _write_statement_starts(sql: str, unanalysed: Counter | None = None):
    """Pozycje instrukcji INSERT/REPLACE: słowo kluczowe jako pierwszy leksem instrukcji, poza łańcuchami i komentarzami.

    Zgłasza też miejsca, których podział na instrukcje nie obejmuje wiarygodnie: komentarz wykonywalny ze słowem
    INSERT/REPLACE i dyrektywę DELIMITER. Wywołujący liczy je jako składnię nieobsługiwaną.

    Używa podziału na instrukcje po średniku, więc instrukcja w tym samym wierszu co poprzednia albo po
    komentarzu też jest widziana; słowo INSERT w treści wartości nie jest liczone.

    Każda inna instrukcja, która nie jest obojętnym ustawieniem ani definicją tabeli (np. UPDATE, DELETE,
    CREATE TRIGGER, CALL), jest liczona w ``unanalysed`` pod swoim początkowym słowem kluczowym: parser jej nie
    interpretuje, więc nie może zniknąć bez śladu.
    """
    at_start, definer = True, None  # definer: CREATE / DROP / ALTER czekające na nazwę rodzaju obiektu
    for token in _SQL_TOKEN.finditer(sql):
        if token["comment"]:
            # Komentarz wykonywalny (/*!NNNNN ... */, /*M! ... */) serwer traktuje jak kod.
            if token["comment"].startswith(("/*!", "/*M!")) and _WRITE_KEYWORD.search(token["comment"]):
                yield token.start()
            continue
        if token["space"]:
            continue
        if token["end"]:
            at_start, definer = True, None
            continue
        word = (token["word"] or "").upper()
        if unanalysed is not None:
            if definer:
                if word not in _INERT_OBJECTS:
                    unanalysed[f"{definer} {word}"[:40] if word else definer] += 1
                definer = None
            elif at_start and word in ("CREATE", "DROP", "ALTER"):
                definer = word
            elif at_start and word not in _INERT_STATEMENTS and word not in ("INSERT", "REPLACE", "DELIMITER"):
                unanalysed[word[:40] or "(nie słowo kluczowe)"] += 1
        # DELIMITER zmienia znak końca instrukcji: dalszego podziału po średniku nie można uznać za wiarygodny.
        # Ukośnik wsteczny poza łańcuchem i komentarzem to polecenie klienta (\d, \g, \G): może zakończyć
        # instrukcję albo zmienić jej terminator w dowolnym miejscu, a poprawny zrzut go tam nie zawiera.
        if token.group() == "\\" or (at_start and (token["word"] or "").upper() in ("INSERT", "REPLACE", "DELIMITER")):
            yield token.start()
        at_start = False


def iter_insert_rows(sql: str, dropped: list[str] | None = None):
    """Narrow PoC subset of mysqldump INSERT syntax; does NOT execute SQL.

    Supports quoted identifiers, optional column list, multi-row VALUES, MySQL
    backslash quotes, numeric and NULL literals. Unsupported INSERTs are ignored;
    a statement that is not terminated (truncated dump) is skipped and its table
    name is appended to ``dropped`` so the caller can report the gap.
    """
    pos = 0
    while (m := _INSERT_HEAD.search(sql, pos)) is not None:
        table = m.group(1)
        cols = re.findall(r"`([A-Za-z0-9_]+)`", m.group(2) or "")
        i, values, quoted, escaped, nesting = m.end(), "", False, False, 0
        while i < len(sql):
            ch = sql[i]
            if quoted:
                values += ch
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == "'":
                    if i + 1 < len(sql) and sql[i+1] == "'":
                        i += 1
                        values += sql[i]
                    else:
                        quoted = False
            else:
                if ch == "'":
                    quoted = True
                    values += ch
                elif ch == "(":
                    nesting += 1
                    values += ch
                elif ch == ")":
                    nesting -= 1
                    values += ch
                elif ch == ";" and nesting == 0:
                    break
                else:
                    values += ch
            i += 1
        pos = i + 1
        if i >= len(sql) or quoted or nesting != 0:
            if dropped is not None:
                dropped.append(table)
            continue
        for group in _iter_row_groups(values):
            inside = group[1:-1]
            items, buf, in_str, escape, j = [], [], False, False, 0
            while j < len(inside):
                ch = inside[j]
                if in_str:
                    buf.append(ch)
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == "'":
                        if j + 1 < len(inside) and inside[j+1] == "'":
                            j += 1
                            buf.append(inside[j])
                        else:
                            in_str = False
                elif ch == "'":
                    in_str = True
                    buf.append(ch)
                elif ch == ",":
                    items.append("".join(buf).strip()); buf = []
                else:
                    buf.append(ch)
                j += 1
            items.append("".join(buf).strip())
            cooked = []
            for item in items:
                if item.startswith("'") and item.endswith("'"):
                    v = item[1:-1].replace("''", "'")
                    v = re.sub(r"\\([\\'\"nrt0])", lambda m: {"n":"\n", "r":"\r", "t":"\t", "0":"\0"}.get(m[1], m[1]), v)
                    cooked.append(v)
                elif item.upper() == "NULL":
                    cooked.append(None)
                else:
                    cooked.append(item)
            yield table, cols, cooked
