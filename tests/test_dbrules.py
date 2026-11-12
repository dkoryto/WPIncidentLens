"""Reguły bazy (T-301, ADR 0006 pkt 4–8): prefiks tabel, role, inwentarz, opcje, cron.

Reguły są wołane przez publiczny interfejs (``analyze``), żeby testy nie zależały od parsera zrzutu.
Dane są syntetyczne; wartości „złośliwe” to obojętny tekst.
"""
import pytest
from conftest import ADMIN_CAPS, CANARY, admin_sql, option_sql, time_limit, trusted, write

from wpincidentlens import dbrules

MARKUP = "<script>synthetic()</script>"


def php(value) -> str:
    """Zapis ``serialize()`` dla danych testowych."""
    if value is None:
        return "N;"
    if isinstance(value, bool):
        return f"b:{int(value)};"
    if isinstance(value, int):
        return f"i:{value};"
    if isinstance(value, str):
        return f's:{len(value.encode())}:"{value}";'
    return f"a:{len(value)}:{{" + "".join(php(key) + php(item) for key, item in value.items()) + "}"


def meta_sql(user_id, key: str, value: str, table: str = "wp_usermeta") -> str:
    return f"INSERT INTO `{table}` VALUES (90,'{user_id}','{key}','{value}');\n"


def facts(run, kind: str) -> list[dict]:
    """Atrybuty obserwacji danego rodzaju, w stałej kolejności (raport nie obiecuje kolejności obserwacji)."""
    return sorted((item["attributes"] for item in run.report["observations"] if item["kind"] == kind), key=repr)


@pytest.fixture
def scan(site, evidence, analyze):
    """Analiza samego zrzutu o podanej treści; pozostałe argumenty trafiają do ``analyze``."""
    def run(sql: str, **options):
        return analyze(site, database=write(evidence / "db.sql", sql), **options)
    return run


# --- prefiks tabel (pkt 4) ------------------------------------------------------------------------

@pytest.mark.parametrize("prefix", ["site7_", "wp", ""], ids=["custom", "no-underscore", "empty"])
def test_core_tables_are_recognised_with_any_prefix(scan, prefix):
    run = scan(admin_sql("siteadmin", "newadmin", prefix=prefix) + option_sql("custom_footer", MARKUP, prefix=prefix),
               known_admins=("siteadmin",))

    assert run.rules == {"UNRECOGNIZED_ADMIN", "SUSPICIOUS_DB_MARKUP"}
    assert run.finding("UNRECOGNIZED_ADMIN")["source"] == f"{prefix}usermeta:{prefix}capabilities"


def test_plugin_table_ending_in_users_is_not_the_users_table(scan):
    """Fałszywy alarm: wiersz obcej tabeli ``wp_myplugin_users`` o tym samym ID nie podmienia loginu administratora."""
    plugin = "INSERT INTO `wp_myplugin_users` VALUES (1,'ghost');\n" + option_sql("x", MARKUP, prefix="wp_myplugin_")

    run = scan(admin_sql("siteadmin") + plugin, known_admins=("siteadmin",))

    assert run.findings == []
    assert "ghost" not in run.json_text
    assert run.coverage("database")["status"] == "ANALYZED"


def test_two_installations_in_one_dump_are_a_gap_and_neither_is_analysed(scan):
    run = scan(admin_sql("siteadmin", prefix="a_") + admin_sql("ghostadmin", prefix="b_"), known_admins=("siteadmin",))

    assert run.findings == []
    assert run.has_gap("o kilku prefiksach (a_, b_)")
    assert run.coverage("database")["status"] == "PARTIAL"


def test_second_installation_under_a_longer_prefix_is_named_as_skipped(scan):
    run = scan(admin_sql("siteadmin") + admin_sql("ghostadmin", prefix="wp_old_"), known_admins=("siteadmin",))

    assert run.findings == []
    assert run.has_gap("pominięto tabele WordPressa o prefiksach: wp_old_")


@pytest.mark.parametrize("extra", [
    option_sql("blogname", "Synthetic Two", prefix="wp_2_"),
    "INSERT INTO `wp_blogs` VALUES (2,1,'synthetic.example.net','/two/');\n",
    "INSERT INTO `wp_sitemeta` VALUES (1,1,'site_admins','a:0:{}');\n",
], ids=["numbered-site-table", "blogs", "sitemeta"])
def test_multisite_layout_is_a_gap_and_the_main_site_is_still_analysed(scan, extra):
    run = scan(admin_sql("siteadmin", "newadmin") + extra, known_admins=("siteadmin",))

    assert run.rules == {"UNRECOGNIZED_ADMIN"}
    assert run.has_gap("sieć witryn (multisite)")
    assert run.coverage("database")["status"] == "PARTIAL"


def test_plugin_table_with_a_number_is_not_multisite(scan):
    run = scan(admin_sql("siteadmin") + "INSERT INTO `wp_404_to_301` VALUES (1,'/old');\n", known_admins=("siteadmin",))

    assert not run.has_gap("sieć witryn")
    assert run.coverage("database")["status"] == "ANALYZED"


def test_capabilities_key_with_another_prefix_is_a_gap_not_a_role(scan):
    """Klucz ``wp_capabilities`` w tabelach ``new_``: WordPress nie nadaje z niego roli, narzędzie też nie."""
    run = scan(admin_sql("ghostadmin", prefix="new_").replace("new_capabilities", "wp_capabilities"), known_admins=("siteadmin",))

    assert run.findings == []
    assert facts(run, "ADMINISTRATOR_ACCOUNT") == []
    assert run.has_gap("klucz o innym prefiksie niż tabele („new_”)")


# --- role (pkt 5) ---------------------------------------------------------------------------------

@pytest.mark.parametrize("caps, is_admin", [
    ({"administrator": True}, True),
    ({"administrator": 1}, True),
    ({"administrator": "1"}, True),
    ({"editor": True, "administrator": True}, True),
    ({"editor": True}, False),
    ({}, False),
    ({"editor": "administrator"}, False),
    ({"Administrator": True}, False),
    ({"not_administrator": True}, False),
    ({0: "administrator"}, False),
], ids=["bool", "int", "string", "second-role", "other-role", "no-roles", "name-as-value", "other-case", "longer-key", "list-of-names"])
def test_administrator_is_a_key_of_the_parsed_capabilities_array(scan, caps, is_admin):
    run = scan(admin_sql("someuser", caps=php(caps)), known_admins=("siteadmin",))

    assert run.rules == ({"UNRECOGNIZED_ADMIN"} if is_admin else set())
    assert run.coverage("database")["status"] == "ANALYZED"


@pytest.mark.parametrize("caps", [
    'a:1:{s:13:"administrator";b:1;', "administrator", 's:13:"administrator";', 'a:1:{s:14:"administrator";b:1;}',
    'O:8:"stdClass":1:{s:13:"administrator";b:1;}', ADMIN_CAPS + " ",
], ids=["truncated", "plain-text", "scalar", "wrong-length", "object", "trailing-garbage"])
def test_unreadable_capabilities_are_a_gap_naming_the_user_never_a_substring_match(scan, caps):
    run = scan(admin_sql("someuser", caps=caps), known_admins=("siteadmin",))

    assert run.findings == []
    assert run.has_gap("Nie odczytano tablicy uprawnień 1 kont (user_id: 1)")
    assert run.coverage("database")["status"] == "PARTIAL"


def test_administrator_key_with_false_value_is_not_an_admin_but_is_not_hidden(scan):
    run = scan(admin_sql("editor", caps=php({"editor": True, "administrator": False})), known_admins=("siteadmin",))

    assert run.findings == []
    assert facts(run, "ADMINISTRATOR_ACCOUNT") == []
    assert run.has_gap("1 kont (user_id: 1) ma klucz roli administrator z wartością fałszywą")
    assert run.report["assessment"] == "INCONCLUSIVE"


def test_hostile_user_id_is_bounded_and_neutralised_in_the_gap(scan):
    run = scan(meta_sql("7\u202e" + "9" * 300, "wp_capabilities", "broken"))

    gap = next(gap for gap in run.gaps if "Nie odczytano tablicy uprawnień" in gap)
    assert "\u202e" not in gap and "9" * 41 not in gap


def test_user_level_alone_is_not_a_role(scan):
    run = scan(admin_sql("olduser", caps=php({"subscriber": True})) + meta_sql(1, "wp_user_level", "10"), known_admins=("siteadmin",))

    assert run.findings == []
    assert facts(run, "ADMINISTRATOR_ACCOUNT") == []


# --- inwentarz administratorów (pkt 6) ------------------------------------------------------------

def test_administrator_inventory_carries_no_personal_data(scan):
    run = scan(admin_sql("siteadmin", password=CANARY) + meta_sql(1, "wp_user_level", "10"))

    assert facts(run, "ADMINISTRATOR_ACCOUNT") == [
        {"username": "siteadmin", "user_id": "1", "registered": "2026-01-01 00:00:00", "user_level": 10}]
    assert run.findings == []
    assert "example.invalid" not in run.everything and CANARY not in run.everything


def test_existence_of_an_administrator_does_not_change_the_assessment(complete_case, analyze, evidence):
    with_admin = analyze(**{**complete_case, "known_admins": ()})
    without = analyze(**{**complete_case, "known_admins": (), "database": write(evidence / "no-admin.sql", option_sql("blogname", "Synthetic"))})

    assert facts(with_admin, "ADMINISTRATOR_ACCOUNT") and not facts(without, "ADMINISTRATOR_ACCOUNT")
    assert with_admin.report["assessment"] == without.report["assessment"] == "NO_INDICATORS_IN_ANALYZED_SCOPE"


def test_more_administrators_than_the_inventory_limit_is_a_gap(scan):
    run = scan(admin_sql(*(f"admin{n:03d}" for n in range(dbrules.MAX_INVENTORY + 1))))

    assert len(facts(run, "ADMINISTRATOR_ACCOUNT")) == dbrules.MAX_INVENTORY
    assert run.has_gap(f"{dbrules.MAX_INVENTORY + 1} kont z rolą administratora")


# --- NEW_SINCE_BASELINE (pkt 7) -------------------------------------------------------------------

def _baseline(*admins: str) -> dict:
    return {"files": {}, "known_admins": list(admins)}


@pytest.mark.parametrize("lists, expected", [
    ({}, set()),
    ({"known_admins": ("siteadmin",)}, {"UNRECOGNIZED_ADMIN"}),
    ({"baseline": _baseline("siteadmin")}, {"NEW_SINCE_BASELINE"}),
    ({"baseline": _baseline("siteadmin"), "known_admins": ("otheradmin",)}, {"NEW_SINCE_BASELINE"}),
    ({"baseline": _baseline("siteadmin"), "known_admins": ("newadmin",)}, set()),
    ({"baseline": _baseline("siteadmin", "newadmin")}, set()),
    ({"baseline": _baseline()}, set()),
    ({"baseline": _baseline(), "known_admins": ("siteadmin",)}, {"UNRECOGNIZED_ADMIN"}),
], ids=["no-list", "cli-list", "baseline-list", "both-lists", "operator-vouches", "in-baseline", "baseline-with-empty-list",
        "empty-baseline-list-and-cli-list"])
def test_admin_outside_the_lists_gives_one_finding_named_after_the_list(scan, lists, expected):
    run = scan(admin_sql("siteadmin", "newadmin"), **lists)

    assert run.rules == expected
    assert len(run.findings) == len(expected)
    assert [item["username"] for item in facts(run, "ADMINISTRATOR_ACCOUNT")] == ["siteadmin", "newadmin"]  # oba konta, także zaufane


def test_new_since_baseline_explains_that_the_snapshot_may_be_outdated(scan):
    flagged = scan(admin_sql("siteadmin", "newadmin"), baseline=_baseline("siteadmin")).finding("NEW_SINCE_BASELINE")

    assert flagged["metadata"]["username"] == "newadmin"
    assert "Nie dowodzi to włamania" in flagged["explanation"] and "migawka może być nieaktualna" in flagged["explanation"]
    assert (flagged["severity"], flagged["confidence"]) == ("high", "medium")


# --- reguły opcji (pkt 6 zadania) -----------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "<img src=x onerror=synthetic()>",
    "<svg/onload=synthetic()>",
    '<object data="https://redirect.example.net/x"></object>',
    '<embed src="https://redirect.example.net/x">',
    '<a href="JaVaScRiPt:synthetic()">x</a>',
    '<a href="java\tscript:synthetic()">x</a>',
    "<META  HTTP-EQUIV = refresh CONTENT='0; URL=https://redirect.example.net/'>",
    '<meta content="0;url=https://redirect.example.net/" http-equiv="refresh">',
    '<a href="data:text/html,synthetic">x</a>',
    "<SCRIPT\nsrc=//redirect.example.net/x.js>",
], ids=["event-handler", "svg-onload", "object", "embed", "mixed-case-scheme", "tab-in-scheme", "meta-refresh-unquoted",
        "meta-refresh-attribute-order", "data-html", "uppercase-script"])
def test_active_markup_variants_in_an_option_are_a_finding(scan, value):
    assert scan(option_sql("custom_footer", value)).rules == {"SUSPICIOUS_DB_MARKUP"}


@pytest.mark.parametrize("value", [
    "&lt;script&gt;synthetic()&lt;/script&gt;",
    "Opis: skrypty i ramki iframe są wyłączone, meta refresh też.",
    '<meta name="viewport" content="width=device-width">',
    '<a href="https://example.org/" class="button">Kontakt</a>',
    '<div data-onboarding="1" data-icon=x>ok</div>',
    "Wyślij raport on demand = tak",
    'a:1:{s:5:"title";s:11:"Scriptorium";}',
    "",
], ids=["escaped-markup", "prose", "other-meta", "plain-link", "data-attribute", "prose-with-on", "serialized-text", "empty"])
def test_inert_option_values_are_not_a_finding(scan, value):
    assert scan(option_sql("custom_footer", value)).findings == []


@pytest.mark.parametrize("value", [
    '<iframe src="https://www.example.org/embed/synthetic" width="560" height="315" allowfullscreen></iframe>',
    '<a href="/kontakt/" onclick="synthetic_track(\'cta\')">Kontakt</a>',
    "Wymagany JavaScript: tak",
], ids=["video-embed", "tracking-onclick", "prose-javascript-colon"])
def test_known_false_positives_stay_low_confidence_review_items(scan, value):
    """Legalne osadzenia i fragmenty analityki dają to samo ustalenie co przekierowanie: waga medium, pewność low."""
    run = scan(option_sql("widget_text", value))

    assert [(item["rule"], item["severity"], item["confidence"]) for item in run.findings] == [("SUSPICIOUS_DB_MARKUP", "medium", "low")]


def test_option_value_over_the_limit_is_a_gap_not_a_silent_pass(scan):
    run = scan(option_sql("big", MARKUP + "x" * dbrules.MAX_OPTION_CHARS))

    assert run.findings == []
    assert run.has_gap("Nie sprawdzono 1 wartości opcji dłuższych niż")
    assert run.coverage("database")["status"] == "PARTIAL"


@pytest.mark.parametrize("build", [
    lambda: "<a " * 300_000,
    lambda: "<a" + " onx" * 250_000,
    lambda: "<meta " + "http-equiv " * 80_000,
    lambda: "j\t\t\t\ta" * 150_000,
], ids=["unclosed-tags", "handler-prefixes", "meta-prefixes", "scheme-prefixes"])
def test_markup_pattern_is_fast_on_hostile_values(build):
    value = build()

    with time_limit(5):
        assert dbrules.MARKUP.search(value) is None


# --- cytat z redakcją (pkt 8) ---------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    f'<script src="https://synthetic:{CANARY}@redirect.example.net/x.js"></script>',
    f'<script>var token = "{CANARY}"; go("https://redirect.example.net/")</script>',
    f'{CANARY}@example.org <iframe src="https://redirect.example.net/"></iframe>',
    f'<iframe src="https://redirect.example.net/p?session={CANARY}&x=1#top"></iframe>',
], ids=["userinfo", "inline-secret", "email-local-part", "query"])
def test_quoted_excerpt_keeps_the_host_and_drops_the_secret(scan, value):
    run = scan(option_sql("custom_footer", value))

    quoted = run.finding("SUSPICIOUS_DB_MARKUP")["metadata"]["excerpt"]
    assert "redirect.example.net" in quoted
    assert CANARY not in run.everything


def test_excerpt_of_a_long_value_is_bounded_and_centred_on_the_match(scan):
    run = scan(option_sql("custom_footer", "lead " * 2000 + MARKUP + " tail" * 2000))

    facts_ = run.finding("SUSPICIOUS_DB_MARKUP")["metadata"]
    assert len(facts_["excerpt"]) <= 200 and "<script>" in facts_["excerpt"]
    assert facts_["value_chars"] == 20_000 + len(MARKUP)


def test_excerpt_with_markup_and_control_characters_is_inert_in_the_html_report(scan):
    run = scan(option_sql("custom_footer", f"\u202e{MARKUP}<iframe src=x></iframe>"))

    quoted = run.finding("SUSPICIOUS_DB_MARKUP")["metadata"]["excerpt"]
    assert MARKUP in quoted and "\u202e" not in run.everything
    assert "<script" not in run.html and "<iframe" not in run.html


# --- cron i aktywne wtyczki (pkt 6) ---------------------------------------------------------------

def _cron(*jobs: tuple[int, str], args=None) -> str:
    schedule: dict = {}
    for when, hook in jobs:
        schedule.setdefault(when, {})[hook] = {"0" * 32: {"schedule": "hourly", "args": args or {}, "interval": 3600}}
    return php({**schedule, "version": 2})


def test_cron_hooks_are_inventory_without_findings(scan):
    run = scan(option_sql("cron", _cron((1_800_000_500, "wp_version_check"), (1_800_000_100, "synthetic_job"), (1_800_000_900, "synthetic_job"))))

    assert facts(run, "CRON_HOOK") == [{"hook": "synthetic_job", "next_run": 1_800_000_100}, {"hook": "wp_version_check", "next_run": 1_800_000_500}]
    assert run.findings == []
    assert run.coverage("database")["status"] == "ANALYZED"
    assert {item["location"]["key"] for item in run.report["observations"]} == {"cron"}


@pytest.mark.parametrize("value, gap", [
    ("a:1:{i:1800000000;a:1:{", "nie jest poprawną tablicą serializowaną PHP"),
    ('s:4:"none";', "nie jest poprawną tablicą serializowaną PHP"),
    (php({"soon": {"synthetic_job": {}}, 1_800_000_000: "x", "version": 2}), "2 wpisów o nieoczekiwanej postaci"),
], ids=["truncated", "not-an-array", "odd-entries"])
def test_unreadable_cron_is_a_gap(scan, value, gap):
    run = scan(option_sql("cron", value))

    assert facts(run, "CRON_HOOK") == []
    assert run.has_gap(gap)
    assert run.coverage("database")["status"] == "PARTIAL"


def test_object_in_cron_arguments_is_never_named_or_rebuilt(scan):
    value = _cron((1_800_000_000, "synthetic_job")).replace('s:4:"args";a:0:{}', 's:4:"args";O:13:"SyntheticEvil":0:{}')

    run = scan(option_sql("cron", value))

    assert facts(run, "CRON_HOOK") == [{"hook": "synthetic_job", "next_run": 1_800_000_000}]
    assert "SyntheticEvil" not in run.everything


def test_cron_inventory_is_capped_with_a_gap_and_hook_names_are_bounded(scan):
    jobs = [(1_800_000_000 + n, f"job_{n:03d}") for n in range(dbrules.MAX_INVENTORY)] + [(1_700_000_000, "h\u202e" + "x" * 500)]

    run = scan(option_sql("cron", _cron(*jobs)))

    hooks = facts(run, "CRON_HOOK")
    assert len(hooks) == dbrules.MAX_INVENTORY
    assert {"hook": "h\ufffd" + "x" * 118, "next_run": 1_700_000_000} in hooks
    assert run.has_gap(f"ma {dbrules.MAX_INVENTORY + 1} zadań")


def test_active_plugins_are_inventory(scan):
    run = scan(option_sql("active_plugins", php({0: "synthetic/synthetic.php", 1: "hello.php"})))

    assert facts(run, "ACTIVE_PLUGIN") == [{"plugin": "hello.php"}, {"plugin": "synthetic/synthetic.php"}]
    assert run.findings == []


def test_unreadable_active_plugins_is_a_gap(scan):
    run = scan(option_sql("active_plugins", php({0: {"nested": True}})))

    assert facts(run, "ACTIVE_PLUGIN") == []
    assert run.has_gap("aktywnych wtyczek nie odczytano")


def test_inventory_of_a_table_outside_the_chosen_prefix_is_dropped(scan):
    run = scan(admin_sql("siteadmin") + option_sql("cron", _cron((1_800_000_000, "plugin_job")), prefix="wp_myplugin_"))

    assert facts(run, "CRON_HOOK") == []


def test_scope_stays_complete_for_a_database_with_inventory_only(complete_case, analyze, evidence):
    database = write(evidence / "full.sql", admin_sql("siteadmin") + option_sql("cron", _cron((1_800_000_000, "synthetic_job"))))

    run = analyze(**{**complete_case, "database": database, "baseline": {**trusted(complete_case["site"]), "known_admins": ["siteadmin"]}})

    assert run.findings == [] and run.report["assessment"] == "NO_INDICATORS_IN_ANALYZED_SCOPE"
