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
    | (?P<comment> --(?=[\x00-\x20\x7f]|\Z)[^\n]*+ | \#[^\n]*+ | /\*.*?(?:\*/|\Z) )
    | (?P<end> ; )
    | (?P<client> \\ )
    | .
""", re.X | re.S)
# ``--`` zaczyna komentarz, gdy po nim jest biały znak albo znak sterujący (lekser serwera MySQL: my_iscntrl).
# Początek instrukcji: białe znaki i zwykłe komentarze; komentarze wykonywalne są wcześniej rozwijane (``_unwrap``).
_LEAD = re.compile(rb"(?:\s++|--(?=[\x00-\x20\x7f]|\Z)[^\n]*+|\#[^\n]*+|/\*.*?\*/)*+", re.S)
_WORD = re.compile(rb"[A-Za-z_]++")
# Komentarz wykonywalny (/*!NNNNN … */, /*M!NNNNNN … */) serwer wykonuje jak kod: jego treść klasyfikuje się jak
# instrukcję, a zwykłe komentarze zastępuje spacja. Łańcuchy i nazwy w odwrotnych apostrofach zostają bez zmian.
_EXECUTABLE = re.compile(rb"/\*M?!")
_UNWRAP = re.compile(rb"""
      (?P<keep> '(?:[^'\\]|\\.)*+' | "(?:[^"\\]|\\.)*+" | `[^`]*+` )
    | /\*M?!\d{0,6}(?P<code>.*?)\*/
    | /\*.*?\*/ | --(?=[\x00-\x20\x7f]|\Z)[^\n]*+ | \#[^\n]*+
""", re.X | re.S)
_SCRUB = re.compile(rb"'(?:[^'\\]|\\.)*+'|\"(?:[^\"\\]|\\.)*+\"|`[^`]*+`")  # łańcuchy i nazwy poza sprawdzaniem słów
# SET jest obojętny tylko jako lista prostych przypisań (``SET STATEMENT … FOR …`` wykonuje dowolną instrukcję).
_SET_VALUE = (rb"(?:'(?:[^'\\]|\\.|'')*+'(?:\s*+'(?:[^'\\]|\\.|'')*+')*+|\"(?:[^\"\\]|\\.|\"\")*+\""
              rb"|[-+]?[0-9.]++[A-Za-z0-9.]*+|@@?(?:[A-Za-z_]++\.)?[A-Za-z0-9_$]++|[A-Za-z_][A-Za-z0-9_$]*+)")
_SET_TARGET = rb"(?:(?:GLOBAL|SESSION|LOCAL|PERSIST)\s++)?(?:@@?(?:[A-Za-z_]++\.)?)?`?[A-Za-z_][A-Za-z0-9_$]*+`?"
_ASSIGN = re.compile(rb"(?P<target>" + _SET_TARGET + rb")\s*+:?=\s*+(?P<value>" + _SET_VALUE + rb")", re.I | re.S)
_SET = re.compile(rb"SET\s++(?:NAMES\s++(?P<names>'?[A-Za-z0-9_]++'?)(?:\s++COLLATE\s++'?[A-Za-z0-9_]++'?)?"
                  rb"|CHARACTER\s++SET\s++(?P<charset>'?[A-Za-z0-9_]++'?)"
                  rb"|(?P<assign>" + _ASSIGN.pattern + rb"(?:\s*+,\s*+" + _ASSIGN.pattern.replace(b"?P<", b"?P<x") + rb")*+))\s*+",
                  re.I | re.S)
# Kodowania, w których bajt 0x5C (ukośnik wsteczny) i apostrof nie mogą być drugim bajtem znaku wielobajtowego.
_SAFE_CHARSETS = frozenset({"utf8", "utf8mb3", "utf8mb4", "latin1", "binary", "ascii", "default"})
_UNSAFE_MODES = re.compile(r"NO_BACKSLASH_ESCAPES|ANSI_QUOTES|(?<![A-Z_])ANSI(?![A-Z_])", re.I)
_ALTER_KEYS = re.compile(rb"ALTER\s++TABLE\s++(?:`[^`]{1,64}`|[A-Za-z0-9_$]{1,64})\s++(?:DISABLE|ENABLE)\s++KEYS\s*+", re.I)
_CREATE_TABLE = re.compile(rb"CREATE\s++TABLE\s++(?:IF\s++NOT\s++EXISTS\s++)?(?:`([A-Za-z0-9_$]{1,64})`|([A-Za-z0-9_$]{1,64}))\s*+\(", re.I)
# Definicja tabeli, która wstawia, kopiuje lub przenosi dane albo łączy tabele, nie jest obojętna.
_FORBIDDEN_DDL = re.compile(rb"(?<![A-Za-z0-9_$])(?:SELECT|LIKE|UNION|AS|GENERATED|RENAME|INSERT_METHOD|VALUES)"
                            rb"(?![A-Za-z0-9_$])|ENGINE\s*+=\s*+'?(?:MERGE|MRG_MYISAM|FEDERATED|CONNECT|SPIDER)", re.I)
_DDL_PART = re.compile(rb"[^()'\"`,]++|'(?:[^'\\]|\\.|'')*+'|\"(?:[^\"\\]|\\.|\"\")*+\"|`[^`]*+`|[(),]", re.S)
_DDL_COLUMN = re.compile(rb"\s*+(?:`([A-Za-z0-9_$]{1,64})`|([A-Za-z_][A-Za-z0-9_$]{0,63}))(?![A-Za-z0-9_$])")
_DDL_NOT_COLUMN = frozenset({"PRIMARY", "KEY", "UNIQUE", "INDEX", "CONSTRAINT", "FULLTEXT", "SPATIAL", "FOREIGN", "CHECK", "PERIOD"})
MAX_VARIABLES = 100  # zmiennych użytkownika i systemowych zapamiętanych z SET
_MODE_WORDS = re.compile(rb"sql_mode|character_set|(?<![A-Za-z0-9_])(?:NAMES|CHARSET)(?![A-Za-z0-9_])", re.I)
_QUOTED = re.compile(rb"'(?:[^'\\]|\\.|'')*+'|\"(?:[^\"\\]|\\.|\"\")*+\"", re.S)
_TABLE_OPTIONS = re.compile(
    rb"(?:\s*+,?\s*+(?:ENGINE\s*+=?\s*+(?:InnoDB|MyISAM|Aria|MEMORY|HEAP)(?![A-Za-z0-9_])"
    rb"|(?:DEFAULT\s++)?(?:CHARSET|CHARACTER\s++SET|COLLATE)\s*+=?\s*+[A-Za-z0-9_]++"
    rb"|(?:AUTO_INCREMENT|AVG_ROW_LENGTH|CHECKSUM|DELAY_KEY_WRITE|KEY_BLOCK_SIZE|MAX_ROWS|MIN_ROWS|PACK_KEYS|PAGE_CHECKSUM"
    rb"|STATS_AUTO_RECALC|STATS_PERSISTENT|STATS_SAMPLE_PAGES|TRANSACTIONAL|ROW_FORMAT)\s*+=?\s*+[A-Za-z0-9_]++"
    rb"|COMMENT\s*+=?\s*+'(?:[^'\\]|\\.|'')*+'))*+\s*+", re.I | re.S)
MAX_UNANALYSED_KEYS = 200  # różnych słów kluczowych w liczniku; dalsze trafiają pod „(inne)”
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
_INERT_STATEMENTS = frozenset({"USE", "LOCK", "UNLOCK", "START", "COMMIT", "BEGIN"})
# …ale tylko w dokładnej postaci: ``BEGIN NOT ATOMIC …`` (MariaDB) wykonuje dowolne instrukcje.
_INERT_FORM = re.compile(rb"(?:USE\s++[`A-Za-z0-9_$]++|LOCK\s++TABLES?\s++[^()]++|UNLOCK\s++TABLES?"
                         rb"|START\s++TRANSACTION[A-Za-z ,]*+|BEGIN(?:\s++WORK)?|COMMIT(?:\s++WORK)?)\s*+", re.I)
_INERT_OBJECTS = frozenset({"TABLE", "DATABASE", "SCHEMA"})  # po CREATE / DROP / ALTER


def _unwrap(text: bytes) -> bytes:
    """Treść komentarzy wykonywalnych zamiast nich, zwykłe komentarze jako spacja; łańcuchy i nazwy bez zmian."""
    return _UNWRAP.sub(lambda m: m["keep"] or b" " + (m["code"] or b"") + b" ", text)


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
    # Przesunięcie instrukcji SET, która zmienia sposób czytania łańcuchów (sql_mode, kodowanie klienta); od niej
    # podział na instrukcje byłby niepewny, więc dalszej części zrzutu nie analizowano. ``mode_change`` mówi, co zmieniła.
    mode_change_at: int | None = None
    mode_change: str = ""
    # Tabela (małymi literami: serwer może nie rozróżniać wielkości liter) → kolumny z CREATE TABLE, dla INSERT bez listy.
    ddl: dict[str, list[str]] = field(default_factory=dict)
    ddl_names: set[str] = field(default_factory=set)  # nazwy z CREATE TABLE w oryginalnej pisowni
    _vars: dict[str, str | None] = field(default_factory=dict)  # zmienne użytkownika z SET (np. @OLD_SQL_MODE)
    _sysvars: dict[str, str | None] = field(default_factory=dict)  # zmienne systemowe ustawione w zrzucie
    _sys_unknown: bool = False  # po nierozpoznanej instrukcji wartości zmiennych systemowych są nieznane
    # Rejestr nazw tabel lub definicji przekroczył limit: sprawdzenie pisowni i kolejności kolumn jest niepełne.
    names_overflow: bool = False
    _buf: bytes = b""
    _start: int = 0            # początek bieżącej instrukcji w buforze
    _pos: int = 0              # dokąd bufor został podzielony na leksemy
    _offset: int = 0           # przesunięcie początku bufora w całym zrzucie
    _flags: int = 0            # nieobsługiwane elementy bieżącej instrukcji (komentarz wykonywalny z zapisem, polecenie klienta)

    @property
    def stopped(self) -> bool:
        return self.oversized_at is not None or self.mode_change_at is not None

    def feed(self, chunk: bytes) -> list[tuple[str, list[str], list[str | None], int]]:
        if self.stopped:
            return []
        self._buf = self._buf[self._start:] + chunk
        self._offset += self._start
        self._pos -= self._start
        self._start = 0
        return self._scan(final=False)

    def close(self) -> list[tuple[str, list[str], list[str | None], int]]:
        if self.stopped:
            return []
        out = self._scan(final=True)
        if not self.stopped and self._buf[self._start:].strip():
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
                if self.mode_change_at is not None:
                    self.mode_change_at += self._offset + self._start
                    self._buf, self._start, self._pos = b"", 0, 0
                    return out
                self._start = token.end()
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
        before = (self.unsupported, sum(self.unanalysed.values()), self.expression_rows)
        self._classify(text, terminated, out)
        if (self.unsupported, sum(self.unanalysed.values()), self.expression_rows) != before:
            # Nierozpoznana instrukcja albo wiersz z wyrażeniem mógł zmienić zmienne (SELECT @m:=…, SET … = (SELECT …)):
            # od tej chwili ich wartości są nieznane.
            self._vars.clear()
            self._sys_unknown = True

    def _classify(self, text: bytes, terminated: bool, out: list) -> None:
        flags, self._flags = self._flags, 0
        self.unsupported += flags
        # Treść komentarzy wykonywalnych serwer wykonuje: klasyfikowana jest instrukcja po ich rozwinięciu.
        code = _unwrap(text) if _EXECUTABLE.search(text) else text
        lead = _LEAD.match(code).end()
        if lead == len(code):
            return
        word_match = _WORD.match(code, lead)
        word = word_match[0].decode("ascii").upper() if word_match else ""
        if not terminated:
            head = _HEAD.match(code, lead)
            self.truncated.append(self._table(head) if head else (word or "?")[:40])
            return
        if word == "INSERT":
            head = _HEAD.match(code, lead)
            # INSERT z komentarzem wykonywalnym w środku nie jest zwykłą listą literałów.
            if code != text or head is None or not self._insert(head, code, out):
                self.unsupported += 1
        elif word in ("REPLACE", "DELIMITER"):
            self.unsupported += 1
        elif word in ("CREATE", "DROP", "ALTER"):
            kind = _WORD.match(code, _LEAD.match(code, word_match.end()).end())
            kind_word = kind[0].decode("ascii").upper() if kind else ""
            if not self._definition(word, kind_word, code, lead):
                self._count(f"{word} {kind_word}" if kind_word else word)
        elif word == "SET":
            plain = _unwrap(code)  # bez komentarzy, które mogą stać na końcu przypisania
            if not self._set(plain, _LEAD.match(plain).end()):
                self._count("SET")
                if _MODE_WORDS.search(plain) and self.mode_change_at is None:
                    self.mode_change_at, self.mode_change = 0, "nierozpoznany SET trybu SQL lub kodowania"
        elif word not in _INERT_STATEMENTS:
            self._count(word or "(nie słowo kluczowe)")
        else:
            plain = _unwrap(code)
            if _INERT_FORM.fullmatch(plain, _LEAD.match(plain).end(), len(plain.rstrip())) is None:
                self._count(word)

    def _count(self, keyword: str) -> None:
        keyword = keyword[:40]
        if keyword not in self.unanalysed and len(self.unanalysed) >= MAX_UNANALYSED_KEYS:
            keyword = "(inne)"
        self.unanalysed[keyword] += 1

    def _set(self, code: bytes, lead: int) -> bool:
        """SET jako lista prostych przypisań jest obojętny; zmiana trybu czytania łańcuchów zatrzymuje analizę.

        Wartość ``sql_mode`` i kodowania klienta musi być znana: łańcuch, nazwa, kopia zmiennej systemowej albo zmienna
        użytkownika z taką wartością przypisaną wcześniej w tym zrzucie. Liczba (maska bitowa), zapis szesnastkowy
        i nieznana zmienna zatrzymują analizę jak tryb niebezpieczny.
        """
        match = _SET.fullmatch(code, lead, len(code.rstrip()))
        if match is None:
            return False
        settings: list[tuple[str, str | None]] = []
        if match["names"] or match["charset"]:
            settings.append(("names", (match["names"] or match["charset"]).strip(b"'\"").decode("latin-1")))
        for assign in _ASSIGN.finditer(match["assign"] or b""):
            target = assign["target"].decode("ascii").lower().replace("`", "")
            value = self._resolve(assign["value"])
            if target.startswith("@") and not target.startswith("@@"):
                if target in self._vars or len(self._vars) < MAX_VARIABLES:
                    self._vars[target] = value
                continue
            name = target.rsplit(".", 1)[-1].split()[-1].lstrip("@")
            if name in self._sysvars or len(self._sysvars) < MAX_VARIABLES:
                self._sysvars[name] = value
            else:
                self._sys_unknown = True
            if name in ("sql_mode", "character_set_client", "names"):
                settings.append((name, value))
        for name, value in settings:
            if value is None:
                self.mode_change_at, self.mode_change = 0, f"{name} z wartości, której parser nie zna"
            elif name == "sql_mode" and (found := _UNSAFE_MODES.search(value)):
                self.mode_change_at, self.mode_change = 0, f"sql_mode {found[0].upper()}"
            elif name != "sql_mode" and value and value.lower() not in _SAFE_CHARSETS:
                self.mode_change_at, self.mode_change = 0, f"kodowanie klienta {value[:40].lower()}"
            else:
                continue
            return True
        return True

    def _resolve(self, value: bytes) -> str | None:
        """Wartość przypisania jako tekst; ``""`` = kopia ustawienia sesji (``@@…``); ``None`` = nieznana."""
        if value.startswith(b"@@"):
            # Kopia zmiennej systemowej: wartość ustawiona wcześniej w zrzucie albo pierwotna wartość sesji ("").
            if self._sys_unknown:
                return None
            return self._sysvars.get(value.decode("ascii").lower().rsplit(".", 1)[-1].lstrip("@"), "")
        if value.startswith(b"@"):
            return self._vars.get(value.decode("ascii").lower())
        if value[:1] in (b"'", b'"'):
            return "".join(_ESCAPE.sub(_unescape, part[1:-1]).decode("latin-1") for part in _QUOTED.findall(value))
        if value[:1].isalpha() or value[:1] == b"_":
            return value.decode("latin-1")
        return None  # liczba lub zapis szesnastkowy: dla sql_mode to maska bitowa

    def _definition(self, word: str, kind: str, code: bytes, lead: int) -> bool:
        """Czy CREATE/DROP/ALTER jest obojętne: definicja tabeli bez danych, usunięcie tabeli, ALTER … KEYS.

        Sprawdzana jest postać bez komentarzy: apostrof w komentarzu nie może otworzyć łańcucha i ukryć słowa.
        """
        plain = _unwrap(code)
        lead = _LEAD.match(plain).end()
        end = len(plain.rstrip())
        if word == "DROP":
            return kind in _INERT_OBJECTS
        if word == "ALTER":
            return kind in ("DATABASE", "SCHEMA") or _ALTER_KEYS.fullmatch(plain, lead, end) is not None
        if kind in ("DATABASE", "SCHEMA"):
            return True
        head = _CREATE_TABLE.match(plain, lead)
        if head is None or _FORBIDDEN_DDL.search(_SCRUB.sub(b"''", plain)):
            return False
        found = self._columns_of(plain, head.end() - 1)
        # Po liście kolumn wolno stać tylko znanym opcjom tabeli (bez TABLE, SELECT, PARTITION, silnika CSV…).
        if found is None or _TABLE_OPTIONS.fullmatch(plain, found[1], end) is None:
            return False
        table = (head[1] or head[2]).decode("ascii")
        if len(self.ddl_names) < MAX_TABLES:
            self.ddl_names.add(table)
        else:
            self.names_overflow = True
        if table.lower() in self.ddl or len(self.ddl) < MAX_TABLES:
            self.ddl[table.lower()] = found[0]
        else:
            self.names_overflow = True
        return True

    @staticmethod
    def _columns_of(code: bytes, start: int) -> tuple[list[str], int] | None:
        """Nazwy kolumn z listy definicji w nawiasie od ``start`` i pozycja za nawiasem; ``None``, gdy się nie domyka."""
        depth, item, columns = 0, b"", []
        for part in _DDL_PART.finditer(code, start):
            token = part[0]
            if token == b"(":
                depth += 1
                if depth == 1:
                    continue
            elif token == b")":
                depth -= 1
                if depth == 0:
                    after = part.end()
                    break
            if depth == 1 and token == b",":
                columns.append(item)
                item = b""
            elif depth >= 1:
                item += token if len(item) < 200 else b""
        else:
            return None
        columns.append(item)
        names = []
        for definition in columns:
            column = _DDL_COLUMN.match(definition)
            if column is None:
                return None
            if column[2] and column[2].decode("ascii").upper() in _DDL_NOT_COLUMN:
                continue
            names.append((column[1] or column[2]).decode("ascii"))
        return names, after

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
        else:
            columns = list(self.ddl.get(table.lower(), ()))  # kolejność kolumn z CREATE TABLE tego zrzutu, jeśli była
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
        if table in self.tables or len(self.tables) < MAX_TABLES:
            self.tables.add(table)
        else:
            self.names_overflow = True
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
