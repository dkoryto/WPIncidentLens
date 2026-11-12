"""Redakcja nieufnego tekstu przed zacytowaniem go w raporcie. Funkcje czyste, bez dostępu do plików.

``redact`` usuwa z tekstu to, co najczęściej jest sekretem albo daną osobową, i zostawia to, co jest
wskaźnikiem (nazwę hosta, ścieżkę, znacznik). Kolejność kroków:

1. dane logowania w adresie (``://użytkownik:hasło@host``) → ``://[usunięto]@host``;
2. parametry zapytania: wszystko po ``?`` do końca adresu → ``?[usunięto]``;
3. wartość po nazwie wyglądającej na sekret (``key``, ``token``, ``password``, ``secret``, ``auth``,
   ``sig``, ``nonce``, ``session``, ``credential`` — także jako część dłuższej nazwy) → ``nazwa=[usunięto]``;
4. część lokalna adresu e-mail → ``[usunięto]@domena``;
5. długie ciągi: co najmniej 16 cyfr szesnastkowych albo co najmniej 24 znaki ``A-Z a-z 0-9 + _ -``
   zawierające literę i cyfrę → ``[usunięto]``. Nazwa hosta po ``://`` jest z tego kroku wyłączona;
6. znaki sterujące, formatujące (m.in. zmiana kierunku pisma, znaki zerowej szerokości), surogaty i
   znaki nieprzypisane → ``U+FFFD``; tabulacja i koniec wiersza → spacja.

Redakcja jest zachowawcza: usuwa też rzeczy niewinne (np. ``author: …``, długi identyfikator z cyfrą).
Nie jest gwarancją: sekret krótki, bez cyfr i poza parametrem o rozpoznawalnej nazwie zostanie w tekście.
Wszystkie wzorce mają ograniczone kwantyfikatory albo dopasowują bez nawrotów: czas liniowy względem wejścia.
"""
from __future__ import annotations

import re
import unicodedata

MARK = "[usunięto]"
ELLIPSIS = "…"
EXCERPT_CHARS = 200
EXCERPT_LEAD = 40  # ile znaków przed trafieniem zostaje w wycinku

_USERINFO = re.compile(r"(://)[^\s/@\"'<>]{1,200}@")
_QUERY = re.compile(r"\?[^\s\"'<>\\]+")
_SECRET = re.compile(
    r"(key|token|passw(?:or)?d|pass|pwd|secret|auth|sig|nonce|session|credential)"
    r"([\w\-\[\]]{0,40}?[\"']?\s{0,3}[=:]\s{0,3})"
    r"(?!\[usunięto\])(?:\"[^\"<>]{0,200}\"|'[^'<>]{0,200}'|[^\s\"'<>&;,]+)", re.I)  # wartość już zastąpiona zostaje
_AT_DOMAIN = re.compile(r"@(?=[\w\-]{1,63}\.[\w\-])")
_LOCAL_PART_CHARS = frozenset("._+-")
_MAX_LOCAL_PART = 64
_HOST_OR_RUN = re.compile(r"(?P<host>://[^\s/?#\"'<>\\]{1,255})|(?P<run>[A-Za-z0-9+_\-]{16,})")
_HEX = re.compile(r"[0-9A-Fa-f]+")
_MIN_MIXED_RUN = 24
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_MAX_PASSES = 8


def neutralise(text: str) -> str:
    """Zamienia znaki, które mogłyby zmienić wygląd lub układ cytatu; zwykły tekst zwraca bez zmian."""
    if text.isascii() and text.isprintable():
        return text
    return "".join(" " if char in "\t\n\r" else "\ufffd" if unicodedata.category(char) in _UNSAFE_CATEGORIES else char
                   for char in text)


def _mask_local_parts(text: str) -> str:
    """Część lokalna adresu e-mail; szuka od znaku ``@`` wstecz, więc długi ciąg bez ``@`` nie kosztuje nic."""
    parts, done = [], 0
    for found in _AT_DOMAIN.finditer(text):
        at = start = found.start()
        while start > done and at - start < _MAX_LOCAL_PART and (text[start - 1].isalnum() or text[start - 1] in _LOCAL_PART_CHARS):
            start -= 1
        if start < at:
            parts += [text[done:start], MARK]
            done = at
    parts.append(text[done:])
    return "".join(parts)


def _mask_run(found: re.Match[str]) -> str:
    run = found.group("run")
    if run is None:  # nazwa hosta: wskaźnik, zostaje
        return found.group()
    if _HEX.fullmatch(run) or (len(run) >= _MIN_MIXED_RUN and any(char.isdigit() for char in run) and any(char.isalpha() for char in run)):
        return MARK
    return run


def _pass(text: str) -> str:
    text = _USERINFO.sub(rf"\1{MARK}@", text)
    text = _QUERY.sub(f"?{MARK}", text)
    text = _SECRET.sub(rf"\1\2{MARK}", text)
    text = _mask_local_parts(text)
    text = _HOST_OR_RUN.sub(_mask_run, text)
    return neutralise(text)


def redact(text: str) -> str:
    """Tekst po redakcji. Wywołujący ogranicza długość wejścia.

    Funkcja jest idempotentna (``redact(redact(x)) == redact(x)``): pojedyncze przejście nie zawsze nią jest, bo
    znacznik wstawiony w miejsce wartości w cudzysłowie albo znak zastępczy może odsłonić nowe dopasowanie. Przejścia
    powtarza się więc do punktu stałego (w praktyce najwyżej trzy); gdy go nie ma po ``_MAX_PASSES``, cały tekst staje
    się znacznikiem — redakcja zawodzi bezpiecznie.
    """
    for _ in range(_MAX_PASSES):
        cleaned = _pass(text)
        if cleaned == text:
            return text
        text = cleaned
    return MARK


def excerpt(text: str, pattern: re.Pattern[str] | None = None, *, limit: int = EXCERPT_CHARS) -> str:
    """Wycinek zredagowanego tekstu, najwyżej ``limit`` znaków, wokół pierwszego trafienia ``pattern``.

    Najpierw redagowany jest cały tekst, dopiero potem wycinany jest fragment: granica wycinka nie może
    przeciąć sekretu tak, żeby jego reszta uszła redakcji. Jeżeli po redakcji wzorzec już nie pasuje
    (trafienie leżało w usuniętej części), wycinek zaczyna się od początku tekstu.
    """
    clean = redact(text)
    found = pattern.search(clean) if pattern is not None else None
    start = max(0, found.start() - EXCERPT_LEAD) if found else 0
    head = ELLIPSIS if start else ""
    cut = clean[start:start + limit - len(head)]
    if start + len(cut) < len(clean):
        cut = cut[:limit - len(head) - len(ELLIPSIS)] + ELLIPSIS
    return head + cut
