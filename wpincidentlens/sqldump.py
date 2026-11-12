"""Ścisły, strumieniowy parser zrzutu SQL (podzbiór mysqldump / mariadb-dump). Niczego nie wykonuje (ADR 0006 pkt 1–2).

Parser dostaje kolejne porcje bajtów (``feed``) i oddaje wiersze instrukcji ``INSERT INTO … VALUES`` z samymi
literałami. Każda inna instrukcja jest rozpoznana jako obojętna (ustawienia sesji, definicje tabel, blokady)
albo liczona jako nieprzeanalizowana — nic nie znika bez śladu. Zrzut nie jest trzymany w pamięci w całości:
bufor obejmuje najwyżej jedną instrukcję (``MAX_STATEMENT_BYTES``).

Gramatyka wspierana:
    INSERT INTO <nazwa> [(<kolumna>, …)] VALUES (<literał>, …)[, (…)]… ;
gdzie nazwa i kolumna to ``[A-Za-z0-9_$]{1,64}``, opcjonalnie w odwrotnych apostrofach, a literał to łańcuch
w apostrofach (sekwencje ``\\x`` i ``''`` MySQL), ``NULL``, liczba, ``0x…``, ``X'…'`` lub ``_binary '…'``.
Wiersz z wyrażeniem (np. ``CONCAT(…)``) jest pomijany i liczony; instrukcja o innej budowie
(``REPLACE``, ``INSERT IGNORE``, ``INSERT … SET``, nazwa z bazą, ``ON DUPLICATE KEY UPDATE``) jest pomijana w całości.
"""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

MAX_STATEMENT_BYTES = 16 * 1024 * 1024
MAX_TABLES = 5000  # różnych nazw tabel zapamiętanych do raportu

# Wszystko, co nie zaczyna komentarza, nie kończy instrukcji i nie jest poleceniem klienta, w jednym przebiegu w C.
# Łańcuch musi być domknięty w buforze; ``''`` wewnątrz łańcucha to tu „zamknij i otwórz” — dla szukania granicy
# instrukcji to samo. Pojedynczy ``-`` lub ``/`` wymaga znanego następnego bajtu, żeby nie przeoczyć ``--`` ani ``/*``
# rozciętego granicą porcji.
_BODY = re.compile(rb"""(?:
      [^'"`;\#/\-\\]++
    | '(?:[^'\\]|\\.)*+'
    | "(?:[^"\\]|\\.)*+"
    | `[^`]*+`
    | -(?=[^-])
    | /(?=[^*])
)*+""", re.X | re.S)
# Pozostałe leksemy. Każda alternatywa się dopasowuje; niedomknięty łańcuch (także urwany na ukośniku wstecznym) lub komentarz
# sięga końca bufora.
_TOKEN = re.compile(rb"""
      (?P<quoted> '(?:[^'\\]|\\.)*+(?:'|\\?\Z) | "(?:[^"\\]|\\.)*+(?:"|\\?\Z) | `[^`]*+(?:`|\Z) )
    | (?P<comment> --(?=[ \t\r\n\f\v]|\Z)[^\n]*+ | \#[^\n]*+ | /\*.*?(?:\*/|\Z) )
    | (?P<end> ; )
    | (?P<client> \\ )
    | .
""", re.X | re.S)
# Początek instrukcji: białe znaki i komentarze (także wykonywalne — ich treść ocenia ``_TOKEN``).
_LEAD = re.compile(rb"(?:\s++|--(?=[ \t\r\n\f\v]|\Z)[^\n]*+|\#[^\n]*+|/\*.*?\*/)*+", re.S)
_WORD = re.compile(rb"[A-Za-z_]++")
_WRITE_KEYWORD = re.compile(rb"(?<![A-Za-z_])(?:INSERT|REPLACE)(?![A-Za-z0-9_])", re.I)
_NAME = rb"(?:`([A-Za-z0-9_$]{1,64})`|([A-Za-z0-9_$]{1,64})(?![A-Za-z0-9_$.]))"
_HEAD = re.compile(rb"INSERT\s++INTO\s++" + _NAME + rb"\s*+(?:\(([^()]*+)\)\s*+)?VALUES\s*+", re.I)
_COLUMN = re.compile(rb"\s*+" + _NAME + rb"\s*+")
_STRING = rb"'(?:[^'\\]|\\.|'')*+'"
_LITERAL = (rb"(?P<str>" + _STRING + rb")|(?P<bin>_binary\s*+" + _STRING + rb")|(?P<null>NULL)(?![A-Za-z0-9_])"
            rb"|(?P<hex>0x[0-9A-Fa-f]*+|[Xx]'[0-9A-Fa-f]*+')(?![A-Za-z0-9_])"
            rb"|(?P<num>[-+]?(?:\d++(?:\.\d*+)?|\.\d++)(?:[eE][-+]?\d++)?)(?![A-Za-z0-9_.])")
_CELL = re.compile(rb"\s*+(?:" + _LITERAL + rb")\s*+([,)])", re.S | re.I)
_PLAIN = re.sub(rb"\(\?P<\w+>", b"(?:", _LITERAL)
_ROW = re.compile(rb"\(\s*+(?:" + _PLAIN + rb")\s*+(?:,\s*+(?:" + _PLAIN + rb")\s*+)*+\)", re.S | re.I)
_SEPARATOR = re.compile(rb"\s*+(,)?\s*+")
# Wiersz z wyrażeniem: nawiasy liczone poza łańcuchami, żeby znaleźć jego koniec.
_EXPR_PART = re.compile(rb"[^()'\"]++|" + _STRING + rb"|\"(?:[^\"\\]|\\.|\"\")*+\"|[()]", re.S)
_ESCAPE = re.compile(rb"\\(.)|''", re.S)
_ESCAPES = {b"0": b"\0", b"b": b"\b", b"n": b"\n", b"r": b"\r", b"t": b"\t", b"Z": b"\x1a", b"%": b"\\%", b"_": b"\\_"}

# Instrukcje, które zrzut może zawierać, a których pominięcie nie ukrywa danych: ustawienia sesji i definicje tabel.
_INERT_STATEMENTS = frozenset({"SET", "USE", "LOCK", "UNLOCK", "START", "COMMIT", "BEGIN"})
_INERT_OBJECTS = frozenset({"TABLE", "DATABASE", "SCHEMA"})  # po CREATE / DROP / ALTER


def _unescape(match: re.Match) -> bytes:
    if match[1] is None:
        return b"'"
    return _ESCAPES.get(match[1], match[1])


@dataclass
class DumpParser:
    """Stan jednego zrzutu. Wiersz to ``(tabela, kolumny, komórki, numer)``; numer liczy wszystkie wiersze zrzutu od 1.

    ``wanted(tabela)`` wybiera tabele, których komórki są dekodowane; wiersze pozostałych są tylko sprawdzane i liczone.
    Liczniki po ``close()`` opisują, czego parser nie przeanalizował — wywołujący zamienia je na luki pokrycia.
    """
    wanted: Callable[[str], bool] | None = None
    max_statement: int = MAX_STATEMENT_BYTES
    rows: int = 0
    tables: set[str] = field(default_factory=set)
    unanalysed: Counter = field(default_factory=Counter)  # słowo kluczowe → liczba instrukcji poza gramatyką
    unsupported: int = 0       # INSERT/REPLACE w nieobsługiwanej składni, komentarz wykonywalny z zapisem, DELIMITER, polecenie klienta
    expression_rows: int = 0   # wiersze z wyrażeniem zamiast literału
    truncated: list[str] = field(default_factory=list)  # niedomknięta instrukcja na końcu zrzutu (tabela INSERT albo słowo)
    lossy_cells: int = 0       # komórki, które nie były poprawnym UTF-8
    oversized_at: int | None = None  # przesunięcie instrukcji dłuższej niż limit; dalszej części zrzutu nie analizowano
    _buf: bytes = b""
    _start: int = 0            # początek bieżącej instrukcji w buforze
    _pos: int = 0              # dokąd bufor został podzielony na leksemy
    _offset: int = 0           # przesunięcie początku bufora w całym zrzucie
    _flags: int = 0            # nieobsługiwane elementy bieżącej instrukcji (komentarz wykonywalny z zapisem, polecenie klienta)

    def feed(self, chunk: bytes) -> list[tuple[str, list[str], list[str | None], int]]:
        if self.oversized_at is not None:
            return []
        self._buf = self._buf[self._start:] + chunk
        self._offset += self._start
        self._pos -= self._start
        self._start = 0
        return self._scan(final=False)

    def close(self) -> list[tuple[str, list[str], list[str | None], int]]:
        if self.oversized_at is not None:
            return []
        out = self._scan(final=True)
        if self.oversized_at is None and self._buf[self._start:].strip():
            self._finish_statement(self._buf[self._start:], terminated=False, out=out)
        self._buf, self._start, self._pos = b"", 0, 0
        return out

    # --- podział na instrukcje --------------------------------------------------------------------

    def _scan(self, final: bool) -> list:
        out: list = []
        buf, pos = self._buf, self._pos
        while True:
            pos = _BODY.match(buf, pos).end()
            if pos >= len(buf):
                break
            token = _TOKEN.match(buf, pos)
            if token.end() == len(buf) and not final and not token["end"]:
                break  # leksem może ciągnąć się w następnej porcji
            if token["end"]:
                self._finish_statement(buf[self._start:pos], terminated=True, out=out)
                self._start = token.end()
            elif token["comment"]:
                text = token["comment"]
                # Komentarz wykonywalny (/*!NNNNN … */, /*M! … */) serwer traktuje jak kod.
                if text.startswith((b"/*!", b"/*M!")) and _WRITE_KEYWORD.search(text):
                    self._flags += 1
            elif token["client"]:
                # Ukośnik wsteczny poza łańcuchem to polecenie klienta (\d, \g, \G): może zakończyć instrukcję
                # albo zmienić jej terminator, a poprawny zrzut go tam nie zawiera.
                self._flags += 1
            pos = token.end()
        self._pos = pos
        if len(buf) - self._start > self.max_statement:
            self.oversized_at = self._offset + self._start
            self._buf = b""
        return out

    # --- jedna instrukcja -------------------------------------------------------------------------

    def _finish_statement(self, text: bytes, terminated: bool, out: list) -> None:
        flags, self._flags = self._flags, 0
        self.unsupported += flags
        lead = _LEAD.match(text).end()
        if lead == len(text):
            return
        word_match = _WORD.match(text, lead)
        word = word_match[0].decode("ascii").upper() if word_match else ""
        if not terminated:
            head = _HEAD.match(text, lead)
            self.truncated.append(self._table(head) if head else (word or "?")[:40])
            return
        if word == "INSERT":
            head = _HEAD.match(text, lead)
            if head is None or not self._insert(head, text, out):
                self.unsupported += 1
        elif word in ("REPLACE", "DELIMITER"):
            self.unsupported += 1
        elif word in ("CREATE", "DROP", "ALTER"):
            kind = _WORD.match(text, _LEAD.match(text, word_match.end()).end())
            kind_word = kind[0].decode("ascii").upper() if kind else ""
            if kind_word not in _INERT_OBJECTS:
                self.unanalysed[f"{word} {kind_word}"[:40] if kind_word else word] += 1
        elif word not in _INERT_STATEMENTS:
            self.unanalysed[word[:40] or "(nie słowo kluczowe)"] += 1

    @staticmethod
    def _table(head: re.Match) -> str:
        return (head[1] or head[2]).decode("ascii")

    def _insert(self, head: re.Match, text: bytes, out: list) -> bool:
        """Wiersze jednej instrukcji INSERT. Fałsz = instrukcja poza gramatyką; jej wierszy nie oddaje się wcale."""
        table = self._table(head)
        columns: list[str] = []
        if head[3] is not None:
            for part in head[3].split(b","):
                column = _COLUMN.fullmatch(part)
                if column is None:
                    return False
                columns.append((column[1] or column[2]).decode("ascii"))
        decode = self.wanted is None or self.wanted(table)
        rows: list = []
        expressions, pos, end = 0, head.end(), len(text.rstrip())
        while True:
            if decode:
                cells, after = self._cells(text, pos)
            else:
                row = _ROW.match(text, pos)
                cells, after = ([] if row else None), (row.end() if row else pos)
            if cells is None:
                after = self._expression_end(text, pos)
                if after is None:
                    return False
                expressions += 1
            else:
                rows.append(cells)
            separator = _SEPARATOR.match(text, after)
            pos = separator.end()
            if separator[1] is None:
                break
        if pos < end:
            return False  # np. ON DUPLICATE KEY UPDATE albo śmieci po liście wierszy
        if len(self.tables) < MAX_TABLES:
            self.tables.add(table)
        self.expression_rows += expressions
        for cells in rows:
            self.rows += 1
            if decode:
                out.append((table, columns, cells, self.rows))
        self.rows += expressions
        return True

    def _cells(self, text: bytes, pos: int) -> tuple[list[str | None] | None, int]:
        """Komórki wiersza zaczynającego się w ``pos``; ``None``, gdy wiersz nie jest listą literałów."""
        if text[pos:pos + 1] != b"(":
            return None, pos
        cells: list[str | None] = []
        pos += 1
        while True:
            cell = _CELL.match(text, pos)
            if cell is None:
                return None, pos
            cells.append(self._value(cell))
            pos = cell.end()
            if cell[_CELL.groups] == b")":
                return cells, pos

    def _value(self, cell: re.Match) -> str | None:
        if cell["null"]:
            return None
        if cell["num"]:
            return cell["num"].decode("ascii")
        if cell["hex"]:
            digits = cell["hex"][2:] if cell["hex"][:2] in (b"0x",) else cell["hex"][2:-1]
            if len(digits) % 2:
                digits = b"0" + digits
            raw = bytes.fromhex(digits.decode("ascii"))
        else:
            quoted = cell["str"] or cell["bin"][cell["bin"].index(b"'"):]
            raw = _ESCAPE.sub(_unescape, quoted[1:-1])
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            self.lossy_cells += 1
            return raw.decode("utf-8", errors="replace")

    @staticmethod
    def _expression_end(text: bytes, pos: int) -> int | None:
        """Koniec wiersza z wyrażeniem (nawiasy zrównoważone poza łańcuchami) albo ``None``, gdy go nie ma."""
        if text[pos:pos + 1] != b"(":
            return None
        depth = 0
        for part in _EXPR_PART.finditer(text, pos):
            if part[0] == b"(":
                depth += 1
            elif part[0] == b")":
                depth -= 1
                if depth == 0:
                    return part.end()
        return None


def parse(chunks: Iterable[bytes], wanted: Callable[[str], bool] | None = None) -> tuple[list, DumpParser]:
    """Cały zrzut naraz (testy, małe wejście): wiersze i stan parsera z licznikami pominięć."""
    parser = DumpParser(wanted)
    rows: list = []
    for chunk in chunks:
        rows.extend(parser.feed(chunk))
    rows.extend(parser.close())
    return rows, parser


def iter_insert_rows(sql: str | bytes, dropped: list[str] | None = None):
    """Wiersze ``(tabela, kolumny, komórki)`` zrzutu podanego w całości; niedomknięte instrukcje trafiają do ``dropped``."""
    rows, parser = parse([sql.encode("utf-8", errors="surrogateescape") if isinstance(sql, str) else sql])
    if dropped is not None:
        dropped.extend(parser.truncated)
    for table, columns, cells, _ in rows:
        yield table, columns, cells
