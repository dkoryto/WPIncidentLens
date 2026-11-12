"""Raport HTML (T-501, ADR 0002 D3, ADR 0008 pkt 3 i 5): jedno miejsce escapowania, CSP, ostrzeżenie o danych osobowych.

Wyłącznie dane syntetyczne; łańcuchy ze znacznikami to obojętny tekst, którego żaden test nie wykonuje.
"""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import inspect
from html.parser import HTMLParser

import pytest
from conftest import analyze_demo

from wpincidentlens import report

# Jedyne znaczniki i atrybuty, jakie strona może zawierać; wszystko inne pochodzi z danych, które uciekły spod escapowania.
ALLOWED_TAGS = {"html", "head", "meta", "title", "style", "body", "h1", "h2", "p", "b", "strong", "small",
                "table", "thead", "tbody", "tr", "th", "td", "ul", "li"}
ALLOWED_ATTRIBUTES = {("html", "lang"), ("meta", "charset"), ("meta", "http-equiv"), ("meta", "content"), ("meta", "name"),
                      ("p", "class")}
PAYLOADS = ("<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "'><svg onload=alert(1)>",
            "</style><script>alert(1)</script>", "</title><script>alert(1)</script>", "<!--", "-->", "<![CDATA[x]]>",
            "&lt;script&gt;", '<a href="javascript:alert(1)">x</a>', "<style>*{x:y}</style>",
            '<meta http-equiv="refresh" content="0;url=https://example.invalid/">')
PERSONAL_DATA = "Raport zawiera dane osobowe"
PSEUDONYMIZED = "zastąpiono pseudonimami"
MINIMAL = {"case_id": "T501-SYNTH", "analyzed_at_utc": "2026-11-12T00:00:00+00:00", "assessment": "INCONCLUSIVE",
           "disclaimer": "x", "findings": [], "coverage_gaps": [], "timeline": []}


class Page(HTMLParser):
    """Znaczniki otwierające z atrybutami i treść bloków ``<style>`` odczytane parserem HTML (encje w atrybutach rozwinięte)."""

    def __init__(self, text: str):
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, tuple]] = []
        self.styles: list[str] = []
        self._in_style = False
        self.feed(text)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, tuple(attrs)))
        self._in_style = tag == "style"
        if self._in_style:
            self.styles.append("")

    def handle_endtag(self, tag):
        if tag == "style":
            self._in_style = False

    def handle_data(self, data):
        if self._in_style:
            self.styles[-1] += data

    @property
    def tags(self) -> list[str]:
        return [tag for tag, _ in self.elements]

    @property
    def attributes(self) -> list[tuple[str, str, str | None]]:
        return [(tag, name, value) for tag, attrs in self.elements for name, value in attrs]

    def head(self) -> list[tuple[str, tuple]]:
        """Elementy między ``<head>`` a ``<body>``."""
        tags = self.tags
        return self.elements[tags.index("head") + 1:tags.index("body")]


def csp_of(page: Page) -> str:
    policies = [dict(attrs)["content"] for tag, attrs in page.elements
                if tag == "meta" and dict(attrs).get("http-equiv", "").lower() == "content-security-policy"]
    assert len(policies) == 1
    return policies[0]


def assert_inert(text: str) -> None:
    """Strona zawiera tylko znaczniki i atrybuty z szablonu: jeden ``<style>``, zero skryptów i obsług zdarzeń."""
    page = Page(text)
    assert set(page.tags) <= ALLOWED_TAGS, set(page.tags) - ALLOWED_TAGS
    assert {(tag, name) for tag, name, _ in page.attributes} <= ALLOWED_ATTRIBUTES
    assert page.tags.count("style") == 1
    assert "<script" not in text.lower()


# --- CSP i szablon ------------------------------------------------------------------------------

def test_content_security_policy_allows_only_the_hash_of_the_single_style_block():
    page = Page(report.render_html(MINIMAL))
    digest = base64.b64encode(hashlib.sha256(page.styles[0].encode("utf-8")).digest()).decode("ascii")

    assert csp_of(page) == f"default-src 'none'; style-src 'sha256-{digest}'; base-uri 'none'; form-action 'none'"


def test_head_starts_with_charset_then_the_single_policy_before_title_and_style():
    head = Page(report.render_html(MINIMAL)).head()

    assert head[0] == ("meta", (("charset", "utf-8"),))
    assert head[1][0] == "meta" and dict(head[1][1])["http-equiv"] == "Content-Security-Policy"
    assert ("meta", (("name", "referrer"), ("content", "no-referrer"))) in head
    assert [tag for tag, _ in head][-2:] == ["title", "style"]


def test_page_has_no_scripts_external_resources_inline_styles_or_event_handlers():
    assert_inert(report.render_html(MINIMAL))


def test_html_escape_is_called_in_exactly_one_place():
    """D3: jedno miejsce escapowania; nowe pole raportu nie może dostać własnego, „zapomnianego” wywołania."""
    calls = [node for node in ast.walk(ast.parse(inspect.getsource(report)))
             if isinstance(node, ast.Call) and ast.unparse(node.func) == "html.escape"]

    assert len(calls) == 1
    assert "html.escape" in inspect.getsource(report._text)


def test_attribute_refuses_a_value_that_is_not_a_template_constant():
    with pytest.raises(ValueError):
        report._element("p", "x", class_='notice" onclick="alert(1)')


def test_bidi_and_zero_width_characters_from_evidence_are_neutralised():
    """RLO odwraca wyświetlaną nazwę (``gpj.php`` wygląda jak ``php.jpg``); znaki zerowej szerokości ukrywają różnice."""
    spoofed = "wp-content/uploads/‮gpj.php"
    page = report.render_html({**MINIMAL, "coverage_gaps": [spoofed, "admin​istrator"]})

    assert "‮" not in page and "​" not in page
    assert "wp-content/uploads/�gpj.php" in page


# --- ostrzeżenie o danych osobowych (B8) --------------------------------------------------------

def test_default_page_warns_about_personal_data_and_names_the_pseudonymize_option():
    page = report.render_html(MINIMAL)

    assert PERSONAL_DATA in page
    assert "adresy IP klientów i loginy kont" in page
    assert "--pseudonymize" in page
    assert PSEUDONYMIZED not in page


def test_pseudonymized_page_says_so_instead_of_warning():
    page = report.render_html(MINIMAL, pseudonymized=True)

    assert PSEUDONYMIZED in page
    assert PERSONAL_DATA not in page


@pytest.mark.parametrize(("flags", "expected"), [({}, PERSONAL_DATA), ({"pseudonymize": False}, PERSONAL_DATA),
                                                 ({"pseudonymize": True}, PSEUDONYMIZED)],
                         ids=["flag-absent", "flag-false", "flag-true"])
def test_written_report_follows_the_pseudonymize_flag_of_the_case(tmp_path, flags, expected):
    case = {"schema_version": "case-poc-1", "case_id": "T501-SYNTH", "operator_id": None,
            "created_at_utc": "2026-11-12T00:00:00+00:00", "sources": {}, "limits": {}, "flags": flags}
    document = {**MINIMAL, "tool": "WPIncidentLens", "tool_version": "synthetic", "scope_complete": False,
                "observations": [], "evidence": [], "coverage": {}}

    report.write(tmp_path / "out", document, case, 3)

    assert expected in (tmp_path / "out" / "report.html").read_text(encoding="utf-8")


def test_write_html_passes_the_pseudonymized_keyword(tmp_path):
    report.write_html(MINIMAL, tmp_path / "report.html", pseudonymized=True)

    assert PSEUDONYMIZED in (tmp_path / "report.html").read_text(encoding="utf-8")


def test_analysis_without_pseudonymization_warns_in_html(site, analyze):
    assert PERSONAL_DATA in analyze(site).html


# --- XSS w każdym liściu tekstowym --------------------------------------------------------------

def text_leaves(node, path=()):
    """Ścieżki do każdego łańcucha w dokumencie: wartości i klucze słowników (klucz jako ``(ścieżka, "key")``)."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield (path + (key,), "key")
            yield from text_leaves(value, path + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from text_leaves(value, path + (index,))
    elif isinstance(node, str):
        yield (path, "value")


def substituted(document: dict, leaf: tuple, payload: str) -> dict:
    path, kind = leaf
    marked = copy.deepcopy(document)
    *parents, last = path
    container = marked
    for step in parents:
        container = container[step]
    if kind == "value":
        container[last] = payload
    else:  # nowy klucz w tym samym miejscu kolejności
        items = list(container.items())
        container.clear()
        container.update((payload if key == last else key, value) for key, value in items)
    return marked


@pytest.fixture
def full_report(demo_case, analyze) -> dict:
    """Raport z syntetycznego incydentu ze wszystkimi źródłami: pliki, baza, logi i baseline."""
    run = analyze_demo(analyze, demo_case)
    assert {source for source, entry in run.report["coverage"].items() if entry["status"] != "NOT_PROVIDED"} >= {
        "files", "database", "logs", "baseline"}
    assert run.report["findings"] and run.report["timeline"] and run.report["coverage_gaps"]
    return run.report


def test_every_text_leaf_of_a_full_report_is_escaped(full_report):
    leaves = list(text_leaves(full_report))
    baseline = report.render_html(full_report)
    attributes = Page(baseline).attributes
    assert len(leaves) > 100  # przejście objęło cały raport, nie jego fragment

    for leaf in leaves:
        for payload in PAYLOADS:
            try:
                page = report.render_html(substituted(full_report, leaf, payload))
            except KeyError:  # przemianowany klucz obowiązkowego pola: strony nie ma, więc nie ma czego wstrzyknąć
                assert leaf[1] == "key", leaf
                continue
            assert page.count(payload) == baseline.count(payload), (leaf, payload)
            assert_inert(page)
            assert Page(page).attributes == attributes, (leaf, payload)  # wartość z raportu nigdy nie trafia do atrybutu


def test_markup_in_rendered_leaves_appears_escaped(full_report):
    """Kontrola testu wyżej: podstawienie w polach widocznych na stronie rzeczywiście do niej trafia (w postaci tekstu)."""
    payload = PAYLOADS[1]
    visible = [("findings", 0, "reason"), ("timeline", 0, "event"), ("coverage_gaps", 0), ("disclaimer",), ("case_id",)]

    for path in visible:
        page = report.render_html(substituted(full_report, (path, "value"), payload))
        assert "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;" in page, path


def test_markup_in_rendered_keys_and_title_appears_escaped(full_report):
    """Klucze pokrycia (nazwa źródła, status wpisu) trafiają na stronę; ``case_id`` trafia do ``<title>``."""
    payload = PAYLOADS[4]
    escaped = "&lt;/title&gt;&lt;script&gt;alert(1)&lt;/script&gt;"
    source = next(iter(full_report["coverage"]))

    renamed_source = report.render_html(substituted(full_report, (("coverage", source), "key"), payload))
    titled = report.render_html(substituted(full_report, (("case_id",), "value"), payload))

    assert f"<td>{escaped}</td>" in renamed_source
    assert f"<title>WPIncidentLens · {escaped}</title>" in titled
    assert titled.count("</title>") == 1

