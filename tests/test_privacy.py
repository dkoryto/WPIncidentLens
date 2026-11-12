"""Redakcja w jednym miejscu i pseudonimizacja (ADR 0008 pkt 4–5, ADR 0002 B8). Wyłącznie dane syntetyczne:
adresy z zakresów dokumentacyjnych (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32), loginy i sekrety zmyślone."""
from __future__ import annotations

import json
import re

import pytest
from conftest import (ADMIN_CAPS, CANARY, EVAL_MARKER, UPLOAD_PHP, access_line, admin_sql, case_schema_errors, option_sql,
                      write)

from wpincidentlens import cli, ingest, models, privacy
from wpincidentlens.redact import MARK

IPV4, IPV6, MAPPED, OTHER_IPV4 = "192.0.2.10", "2001:db8::7", "::ffff:192.0.2.10", "198.51.100.23"
EMAIL_LOGIN = "mallory.synthetic@example.invalid"
PSEUDONYM = re.compile(r"(ip|user|uid)-[0-9a-f]{16}")


def outputs(run) -> str:
    return run.json_text + run.html + run.stdout + json.dumps(run.case, ensure_ascii=False)


def observations(run, kind: str) -> list[dict]:
    return [item for item in run.report["observations"] if item["kind"] == kind]


# --- budowa raportu bez skanerów (kontrakt poc-1) -------------------------------------------------

def _report(attributes: list[dict], *, reason: str = "Synthetic reason.", gaps: tuple[str, ...] = ()) -> models.Report:
    """Raport z jednym dowodem pliku i obserwacjami o podanych atrybutach w tym samym miejscu."""
    evidence = models.Evidence(models.OriginKind.FILE, "files/a.php", "READ", sha256="a" * 64, size_bytes=1)
    facts = tuple(models.Observation(evidence.id, "SYNTHETIC_FACT", models.Location(path="a.php"), values) for values in attributes)
    entries = {str(status): 0 for status in ingest.ReadStatus}
    coverage = {"files": models.Coverage("files", models.CoverageStatus.ANALYZED, {**entries, "READ": 1})}
    for source in ("database", "logs", "baseline"):
        coverage[source] = models.Coverage(source, models.CoverageStatus.NOT_PROVIDED, entries, (f"Brak {source}", *gaps))
    finding = models.Finding("SYNTHETIC_RULE", "file", "medium", "low", reason, tuple(item.id for item in facts))
    return models.Report("CASE", "tool", "0", "2026-11-12T00:00:00+00:00", models.assess([finding], coverage), "d", (evidence,), facts,
                         (finding,), coverage, tuple(sorted({reason for entry in coverage.values() for reason in entry.reasons})))


# --- redakcja: granica pól strukturalnych ------------------------------------------------------------

def test_observations_differing_only_in_a_redacted_secret_keep_distinct_ids():
    report = privacy.sanitize(_report([{"note": "token=synthetic-one"}, {"note": "token=synthetic-two"}]))

    assert len({item.id for item in report.observations}) == 2
    assert {item.attributes["note"] for item in report.observations} == {f"token={MARK}"}
    assert sorted(item.attributes[privacy.VARIANT] for item in report.observations) == [1, 2]
    assert set(report.findings[0].observations) == {item.id for item in report.observations}
    models.validate_report(report.to_dict())


def test_sanitized_report_is_stable_under_a_second_sanitize():
    once = privacy.sanitize(_report([{"note": f"key={CANARY} https://u:{CANARY}@example.invalid/?q={CANARY}"}],
                                    reason=f"auth={CANARY}", gaps=(f"gap secret={CANARY}",)))

    assert privacy.sanitize(once).to_dict() == once.to_dict()
    assert CANARY not in json.dumps(once.to_dict())


def test_unknown_string_attribute_is_redacted_but_numbers_and_booleans_are_kept():
    report = privacy.sanitize(_report([{"unknown": "d41d8cd98f00b204e9800998ecf8427e", "count": 12345678901234567, "flag": True}]))

    assert report.observations[0].attributes == {"unknown": MARK, "count": 12345678901234567, "flag": True}


@pytest.mark.parametrize("kind, attribute, value, kept", [
    ("FILE_DIFFERS_FROM_CORE_MANIFEST", "reference_md5", "0" * 32, True),
    ("FILE_DIFFERS_FROM_CORE_MANIFEST", "observed_sha256", "ab" * 32, True),
    ("FILE_DIFFERS_FROM_BASELINE", "baseline_sha256", "ab" * 32, True),
    ("FILE_DIFFERS_FROM_BASELINE", "baseline_sha256", f"{'ab' * 32} {CANARY}", False),
    ("HTTP_REQUEST", "path", "wp-content/uploads/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6/AbCdEfGhIjKlMnOpQrStUv0123.php", True),
    ("HTTP_REQUEST", "uri", "/x/d41d8cd98f00b204e9800998ecf8427e.php", False),
    ("HTTP_REQUEST", "client_ip_basis", "connection", True),
    ("OPTION_VALUE_WITH_ACTIVE_MARKUP", "path", "anything", False),
], ids=["md5", "sha256", "baseline-sha256", "hash-with-tail", "path", "uri", "enum", "path-of-another-kind"])
def test_structural_attribute_is_kept_only_for_its_kind_and_pattern(kind, attribute, value, kept):
    assert privacy.is_structural(kind, attribute, value) is kept


def test_hashes_of_integrity_findings_survive_redaction(site, tmp_path, analyze):
    write(site / "wp-includes" / "version.php", "<?php $wp_version = '9.9.9';\n")
    manifest = write(tmp_path / "core.json", json.dumps({"checksums": {"wp-includes/version.php": "0" * 32}}))

    run = analyze(site, core_checksums=manifest)

    fact = observations(run, "FILE_DIFFERS_FROM_CORE_MANIFEST")[0]["attributes"]
    assert fact["reference_md5"] == "0" * 32
    assert re.fullmatch(r"[0-9a-f]{32}", fact["observed_md5"]) and re.fullmatch(r"[0-9a-f]{64}", fact["observed_sha256"])


def test_hex_and_mixed_case_runs_in_a_relative_path_do_not_break_evidence_linkage(site, evidence, analyze):
    name = "wp-content/uploads/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6/AbCdEfGhIjKlMnOpQrStUv0123.php"
    write(site / name, EVAL_MARKER)
    logs = write(evidence / "logs" / "access.log", access_line("/" + name)).parent

    run = analyze(site, logs=logs)

    assert run.finding("EXECUTABLE_IN_UPLOADS")["source"] == name
    assert run.finding("HTTP_EXECUTABLE_IN_UPLOADS")["metadata"]["path"] == name
    assert run.finding("CORRELATED_UPLOAD_REQUEST")
    assert any(item["logical_path"] == f"files/{name}" for item in run.report["evidence"])


def test_every_string_attribute_of_a_full_run_is_classified(demo_case, analyze):
    """Nowy atrybut tekstowy bez decyzji (strukturalny, tożsamość, tekst swobodny) ma zatrzymać ten test, nie zniknąć po cichu."""
    free_text = {"excerpt", "uri", "hook", "plugin", "reference", "basis"}
    run = analyze(demo_case / "site", database=demo_case / "database.sql", logs=demo_case / "logs", baseline=demo_case / "baseline.json")

    unclassified = {(item["kind"], name) for item in run.report["observations"] for name, value in item["attributes"].items()
                    if isinstance(value, str) and name not in privacy.IDENTITY and name not in free_text
                    and not privacy.is_structural(item["kind"], name, value)}
    assert unclassified == set()


# --- S-13: kanarki w każdym źródle -------------------------------------------------------------------

def _canary_option_excerpt(site, evidence):
    value = f'<script src="https://cdn.example.invalid/x.js"></script> api_key={CANARY}'
    return {"database": write(evidence / "db.sql", admin_sql("siteadmin") + option_sql("widget_text", value)), "known_admins": ("siteadmin",)}


def _canary_cron_hook(site, evidence):
    cron = f'a:1:{{i:1700000000;a:1:{{s:{len(CANARY)}:"{CANARY}";a:0:{{}}}}}}'
    return {"database": write(evidence / "db.sql", admin_sql("siteadmin") + option_sql("cron", cron)), "known_admins": ("siteadmin",)}


def _canary_log_userinfo(site, evidence):
    line = access_line(f"http://synthetic:{CANARY}@site.example.invalid/{UPLOAD_PHP}")
    return {"logs": write(evidence / "logs" / "access.log", line).parent}


def _canary_log_query(site, evidence):
    return {"logs": write(evidence / "logs" / "access.log", access_line(f"/{UPLOAD_PHP}?session={CANARY}&x=1")).parent}


def _canary_gap_text(site, evidence):
    """Rola w ``usermeta`` dla ``user_id`` bez wiersza w ``users``: nieufny identyfikator trafia do tekstu luki."""
    orphan = f"INSERT INTO `wp_usermeta` VALUES (9,'{CANARY}','wp_capabilities','{ADMIN_CAPS}');\n"
    return {"database": write(evidence / "db.sql", admin_sql("siteadmin") + orphan), "known_admins": ("siteadmin",)}


@pytest.mark.parametrize("build", [_canary_option_excerpt, _canary_cron_hook, _canary_log_userinfo, _canary_log_query, _canary_gap_text],
                         ids=["option-excerpt", "cron-hook", "log-userinfo", "log-query", "gap-text"])
def test_canary_from_any_source_never_reaches_report_html_or_case(site, evidence, analyze, build):
    write(site / UPLOAD_PHP, EVAL_MARKER)

    run = analyze(site, **build(site, evidence))

    assert CANARY not in outputs(run)


# --- pseudonimizacja --------------------------------------------------------------------------------

@pytest.fixture
def personal(site, evidence):
    """Materiał z adresami IPv4, IPv6 i IPv4 zmapowanym w IPv6, loginem w postaci e-mail i loginem w cytacie."""
    write(site / UPLOAD_PHP, EVAL_MARKER)
    lines = "".join([access_line(f"/{UPLOAD_PHP}", ip=IPV4), access_line(f"/{UPLOAD_PHP}", ip=IPV4, when="09/Nov/2026:02:15:01 +0100"),
                     access_line(f"/{UPLOAD_PHP}/{OTHER_IPV4}", ip=IPV6), access_line(f"/{UPLOAD_PHP}", ip=MAPPED)])
    markup = '<script src="https://cdn.example.invalid/x.js"></script> ghostadmin'
    sql = admin_sql("siteadmin", "ghostadmin", EMAIL_LOGIN) + option_sql("widget_text", markup)
    return {"site": site, "database": write(evidence / "db.sql", sql), "logs": write(evidence / "logs" / "access.log", lines).parent,
            "known_admins": ("siteadmin",)}


def _run(analyze, personal, *flags):
    return analyze(personal["site"], database=personal["database"], logs=personal["logs"], known_admins=personal["known_admins"],
                   flags=flags)


def test_without_the_flag_personal_data_is_in_clear(analyze, personal):
    run = _run(analyze, personal)

    assert IPV4 in run.json_text and "ghostadmin" in run.json_text and EMAIL_LOGIN in run.json_text
    assert run.case["flags"]["pseudonymize"] is False


def test_with_the_flag_no_address_or_login_appears_in_any_output(analyze, personal):
    run = _run(analyze, personal, "--pseudonymize")

    text = outputs(run)
    for value in (IPV4, IPV6, MAPPED, OTHER_IPV4, "ghostadmin", "siteadmin", EMAIL_LOGIN, "mallory.synthetic"):
        assert value not in text
    assert run.case["flags"]["pseudonymize"] is True
    accounts = observations(run, "ADMINISTRATOR_ACCOUNT")
    assert all(PSEUDONYM.fullmatch(item["attributes"][name]) for item in accounts for name in ("username", "user_id"))
    assert all(PSEUDONYM.fullmatch(item["attributes"]["client_ip"]) for item in run.report["observations"] if "client_ip" in item["attributes"])


def test_same_value_gets_the_same_pseudonym_and_correlation_still_links(analyze, personal):
    run = _run(analyze, personal, "--pseudonymize")

    requests = observations(run, "HTTP_REQUEST_FOR_PHP_IN_UPLOADS")
    by_line = {item["location"]["line"]: item["attributes"]["client_ip"] for item in requests}
    assert by_line[1] == by_line[2] == by_line[4]  # IPv4 i ten sam adres zmapowany w IPv6
    assert by_line[3] != by_line[1]
    linked = [item for item in run.report["findings"] if item["rule_id"] == "CORRELATED_UPLOAD_REQUEST"]
    assert len(linked) == 4
    assert {event["observation_id"] for event in run.report["timeline"]} - {None} <= {item["id"] for item in requests}
    uri = next(item["attributes"]["uri"] for item in requests if item["location"]["line"] == 3)
    assert re.search(r"/ip-[0-9a-f]{16}$", uri)  # literał IP w tekście swobodnym: pseudonim z tym samym kluczem


def test_known_admin_comparison_happens_before_pseudonymization(analyze, personal):
    run = _run(analyze, personal, "--pseudonymize")

    assert [item["rule"] for item in run.findings].count("UNRECOGNIZED_ADMIN") == 2  # ghostadmin i login e-mail; siteadmin zaufany


def test_pseudonyms_differ_between_runs_with_the_same_case_id(analyze, personal):
    first, second = (_run(analyze, personal, "--pseudonymize") for _ in range(2))

    assert set(PSEUDONYM.findall(first.json_text)) and first.report["observations"] != second.report["observations"]


def test_key_never_reaches_any_output(analyze, personal, monkeypatch):
    key = bytes(range(32))
    monkeypatch.setattr(privacy.secrets, "token_bytes", lambda size: key)

    run = _run(analyze, personal, "--pseudonymize")

    text = outputs(run) + "".join(path.read_text(encoding="utf-8") for path in run.out.iterdir())
    for form in (key.hex(), key.hex().upper(), repr(key), key.decode("latin-1")):
        assert form not in text
    assert key.hex() not in repr(privacy.Pseudonymizer())


@pytest.mark.parametrize("first, second, same", [
    ("192.0.2.1", "::ffff:192.0.2.1", True),
    ("2001:DB8:0:0::1", "2001:db8::1", True),
    ("Host.Example.invalid", "host.example.invalid", True),
    ("192.0.2.1", "192.0.2.2", False),
], ids=["mapped-ipv4", "ipv6-forms", "hostname-case", "different"])
def test_client_addresses_are_canonicalised_before_hmac(first, second, same):
    pseudonymizer = privacy.Pseudonymizer()

    assert (pseudonymizer.pseudonym("client_ip", first) == pseudonymizer.pseudonym("client_ip", second)) is same


def test_logins_are_pseudonymised_by_exact_value():
    pseudonymizer = privacy.Pseudonymizer()

    assert pseudonymizer.pseudonym("username", "Admin") != pseudonymizer.pseudonym("username", "admin")
    assert re.fullmatch(r"user-[0-9a-f]{16}", pseudonymizer.pseudonym("username", "admin"))


def test_addresses_logins_and_user_ids_in_reasons_and_gaps_are_pseudonymised():
    report = _report([{"username": "ghostadmin", "client_ip": IPV4}], reason="Konto ghostadmin logowało się z 2001:db8::7.",
                     gaps=("Nie odczytano uprawnień 2 kont (user_id: 7, 12): ghostadmin", f"Adres {IPV4}, nie ghostadmin_x"))

    text = json.dumps(privacy.sanitize(report, privacy.Pseudonymizer()).to_dict(), ensure_ascii=False)

    assert "ghostadmin logowało" not in text and "2001:db8::7" not in text and IPV4 not in text
    assert re.search(r"user_id: uid-[0-9a-f]{16}, uid-[0-9a-f]{16}\)", text)
    assert "ghostadmin_x" in text  # login tylko jako osobne słowo


# --- ostrzeżenie CLI i case.json ----------------------------------------------------------------------

def _stderr(capsys, *argv) -> str:
    capsys.readouterr()
    cli.main(list(argv))
    return capsys.readouterr().err


def test_warning_is_printed_only_without_the_flag_and_only_with_personal_data(personal, tmp_path, capsys):
    base = ["--files", str(personal["site"]), "--logs", str(personal["logs"])]

    warned = _stderr(capsys, *base, "--output", str(tmp_path / "a"))
    assert warned.count("\n") == 1 and "--pseudonymize" in warned and "IP" in warned
    assert _stderr(capsys, *base, "--pseudonymize", "--output", str(tmp_path / "b")) == ""
    assert _stderr(capsys, "--files", str(personal["site"]), "--output", str(tmp_path / "c")) == ""


def test_case_json_without_the_pseudonymize_flag_still_validates(site, analyze):
    case = analyze(site).case

    del case["flags"]["pseudonymize"]
    assert case_schema_errors(case) == []
    case["flags"]["pseudonymize"] = "yes"
    assert case_schema_errors(case) != []
