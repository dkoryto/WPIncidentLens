"""Redakcja nieufnego tekstu przed zacytowaniem go w raporcie. Funkcje czyste, bez dostępu do plików.

``redact`` usuwa z tekstu to, co najczęściej jest sekretem albo daną osobową, i zostawia to, co jest
wskaźnikiem (nazwę hosta, ścieżkę, znacznik). Kolejność kroków:

1. dane logowania w adresie (``://użytkownik:hasło@host``) → ``://[usunięto]@host``;
2. wartość po nazwie wyglądającej na sekret (``key``, ``token``, ``password``, ``secret``, ``auth``,
   ``sig``, ``nonce``, ``session``, ``credential``, ``salt``, ``db_user`` — także jako część dłuższej nazwy) →
   ``nazwa=[usunięto]``; separatorem jest ``=``, ``:``, ``=>`` albo przecinek po cudzysłowie, więc obejmuje to też
   ``define('DB_PASSWORD', '…')``, ``'AUTH_KEY' => '…'`` i ``$password = '…'``; wartość w cudzysłowie zastępowana jest
   cała, bez limitu długości, a niedomknięty cudzysłów sięga do końca tekstu albo do znacznika HTML;
   przed krokiem 3, bo ten zjadłby samą nazwę (``?token: wartość``) i zostawił wartość po spacji;
3. parametry zapytania: wszystko po ``?`` do końca adresu → ``?[usunięto]``;
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
_QUERY = re.compile(r"\?[^\s\"'<>]+")  # także „\”: inaczej „?c\sekret” zostawiłby resztę wartości
# Łańcuch w cudzysłowie ``q``, bez limitu długości (wartość dłuższa niż limit nie może zostawić jawnego ogona), z ucieczkami
# ``\\q``. Domknięty obejmuje wszystko do cudzysłowu zamykającego, także ``<``. Niedomknięty (wiersz ucięty) nie chroni
# wartości: sięga do końca tekstu albo do znacznika HTML (``<`` + litera, ``/``, ``!``, ``?``), żeby nie zjadał reszty
# dokumentu ze wskaźnikami. Kwantyfikatory zaborcze; wariant domknięty zawodzi tylko wtedy, gdy po cudzysłowie otwierającym
# nie ma już żadnego cudzysłowu tego rodzaju, a każde z tych przeszukań kończy się na następnym cudzysłowie: czas liniowy.
_NOT_TAG = r"<(?![A-Za-z/!?])"


def _rest(quote: str) -> str:
    """Treść po cudzysłowie ``quote`` do następnego takiego cudzysłowu włącznie, końca tekstu albo znacznika HTML."""
    return rf"(?:[^{quote}\\<]++|\\[\s\S]|{_NOT_TAG})*+{quote}?"


def _quoted(quote: str) -> str:
    return rf"{quote}(?:[^{quote}\\]++|\\[\s\S])*+{quote}|{quote}{_rest(quote)}"


# Cudzysłów „domykający” sklejony z dalszą treścią (``key=" password: "X y"``) w rzeczywistości otwierał kolejną wartość:
# ta treść, do następnego takiego cudzysłowu, też należy do wartości. Nie dotyczy cudzysłowu, po którym stoi odstęp,
# separator albo znak kończący wyrażenie (``'a'.$b``, ``"v",``, ``"x">``, ``"x"/>``).
_GLUED = r"(?![\s,;.)\]}&<>/?=:])"
_GLUED_REST = rf"(?:(?<=\"){_GLUED}{_rest(chr(34))}|(?<='){_GLUED}{_rest(chr(39))})"


# Jeden element wartości: łańcuch w cudzysłowie, schemat nagłówka Authorization z tokenem (``Bearer <token>``: sam
# token stoi po spacji) albo słowo bez białych znaków, opcjonalnie po ``<`` (``secret=<x>``). Słowo kończy się na
# ``=``/``:`` (dalej jest następny element: ``key=Bearer X``) i nie obejmuje „?”, więc znacznik zapytania zawsze
# zostaje dla _QUERY.
_SECRET_PART = (rf"(?:{_quoted(chr(34))}|{_quoted(chr(39))}"
                r"|(?:(?:Bearer|Basic|Digest|Negotiate|Token)\s{1,3}|<?)(?:[^\s\"'<>&;,?=:]++[=:]*+|[=:]++))")
# Separator nazwy i wartości: ``=``, ``:``, ``=>`` (tablica PHP: ``'DB_PASSWORD' => 'x'``) albo przecinek po
# cudzysłowie (``define('DB_PASSWORD', 'x')``, krotka SQL ``('auth_key','x')``). Przecinek bez cudzysłowu nie jest
# separatorem: w prozie (``key, value``) byłby za częsty. Do 40 odstępów wokół separatora (wyrównane tablice PHP).
_SEPARATOR = r"(?:[\"']\s{0,40}+,|[\"']?\s{0,40}+(?:=>|[=:]))"
# Sklejona treść mogła być nazwą kolejnego sekretu (``key="`` przed ``define("DB_PASSWORD", X)``): przecinek po niej
# też prowadzi do wartości.
_GLUED_CHAIN = _GLUED_REST + r"(?:\s{0,40}+,\s{0,40}+(?!\[usunięto\])" + _SECRET_PART + r")?+"
_SECRET = re.compile(
    # Nazwy: ``salt`` i ``db_user`` dla stałych wp-config (``*_SALT``, ``DB_USER``); ``DB_HOST`` i ``DB_NAME`` zostają —
    # nazwa hosta jest wskaźnikiem, nazwa bazy nie jest poświadczeniem.
    r"(key|token|passw(?:or)?d|pass|pwd|secret|auth|sig|nonce|session|credential|salt|db_?user)"
    r"([\w\-\[\]]{0,40}?" + _SEPARATOR + r"\s{0,40}+)"
    # Element kończący się na ``=``/``:`` albo z separatorem po nim wygląda jak kolejna nazwa (``key=token: X``,
    # ``key=token: "a b"``, ``key=key = X``, ``key=//Authorization: Bearer X``): wartość obejmuje wtedy także
    # następny element, dowolnej postaci (także po ``=>``: ``key=\n'DB_PASSWORD' => X``). Przecinek nie łączy elementów,
    # poza treścią sklejoną (_GLUED_CHAIN), bo zjadałby całe tablice PHP i krotki SQL po pierwszej wartości.
    # Lepiej za dużo niż jawne ``X``. Kwantyfikatory zaborcze i ograniczone: czas liniowy.
    r"(?!\[usunięto\])" + _SECRET_PART + r"(?:(?:(?<=[=:])|[\"']?\s{0,40}+(?:=>|[=:]))\s{0,40}+" + _SECRET_PART + "|" + _GLUED_CHAIN + r")*+",
    re.I)  # wartość już zastąpiona zostaje
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
    # _SECRET przed _QUERY: zapytanie kończy się na spacji, więc „?password: x” zjadłoby nazwę, a wartość zostałaby jawna.
    # Wartość bez cudzysłowu nie obejmuje „?”, więc znacznik zapytania zawsze zostaje dla _QUERY.
    text = _SECRET.sub(rf"\1\2{MARK}", text)
    text = _QUERY.sub(f"?{MARK}", text)
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
