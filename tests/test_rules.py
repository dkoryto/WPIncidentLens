"""Rejestr reguł (ADR 0008 pkt 2, T-501): kontrakt rejestru, tabele regresyjne wagi i pewności (spec §9.2),
zgodność z ``docs/RULES.md`` i ścieżka błędu reguły (spec C10). Wyłącznie dane syntetyczne.
"""
from __future__ import annotations

import ast
import dataclasses
import json
import os
import re
from pathlib import Path

import pytest
from conftest import access_line, trusted, write
from test_correlate import PLUGIN_PHP, flagged, request, run as correlate_run
from test_filerules import PLUGIN, POSITIVE

from wpincidentlens import cli, filerules, models, rules
from wpincidentlens.analysis import Detection, SourceCoverage

PACKAGE = Path(rules.__file__).parent
RULES_DOC = PACKAGE.parent / "docs" / "RULES.md"
UPLOAD = "wp-content/uploads/2026/11/"

# --- tabele regresyjne (spec §9.2): zmiana wagi albo pewności reguły musi zmienić tę tabelę ----------

EXPECTED_SEVERITY = {
    "EXECUTABLE_IN_UPLOADS": "high", "DOUBLE_EXTENSION_IN_UPLOADS": "medium", "CODE_IN_UNEXPECTED_LOCATION": "medium",
    "SUSPICIOUS_PHP_EVAL_DECODE": "high", "REQUEST_TO_COMMAND_EXEC": "high", "REQUEST_TO_CODE_EVAL": "high",
    "REQUEST_VARIABLE_FUNCTION_CALL": "high", "PHP_PREG_REPLACE_EVAL": "high", "LONG_ENCODED_BLOB": "medium",
    "REQUEST_INPUT_TO_INCLUDE": "high", "REQUEST_CONTROLLED_FILE_WRITE": "high", "HTACCESS_ENABLES_PHP_IN_UPLOADS": "high",
    "PHP_AUTO_PREPEND_CONFIG": "high",
    "BASELINE_FILE_CHANGED": "medium", "BASELINE_FILE_MISSING": "low", "NEW_FILE_SINCE_BASELINE": "medium",
    "CORE_CHECKSUM_MISMATCH": "medium", "CORE_FILE_NOT_IN_MANIFEST": "medium", "CORE_FILE_MISSING": "low",
    "REFERENCE_FILE_UNREADABLE": "medium",
    "UNRECOGNIZED_ADMIN": "high", "NEW_SINCE_BASELINE": "high", "SUSPICIOUS_DB_MARKUP": "medium",
    "HTTP_EXECUTABLE_IN_UPLOADS": "high",
    "CORRELATED_UPLOAD_REQUEST": "high", "CORRELATED_FILE_REQUEST": "medium", "REQUEST_NEAR_FILE_CHANGE": "medium",
}

EXPECTED_CONFIDENCE = {
    "EXECUTABLE_IN_UPLOADS": {"medium", "low"}, "DOUBLE_EXTENSION_IN_UPLOADS": {"low"}, "CODE_IN_UNEXPECTED_LOCATION": {"low", "medium"},
    "SUSPICIOUS_PHP_EVAL_DECODE": {"medium"}, "REQUEST_TO_COMMAND_EXEC": {"medium"}, "REQUEST_TO_CODE_EVAL": {"medium"},
    "REQUEST_VARIABLE_FUNCTION_CALL": {"medium"}, "PHP_PREG_REPLACE_EVAL": {"medium", "low"}, "LONG_ENCODED_BLOB": {"medium", "low"},
    "REQUEST_INPUT_TO_INCLUDE": {"medium", "low"}, "REQUEST_CONTROLLED_FILE_WRITE": {"medium", "low"},
    "HTACCESS_ENABLES_PHP_IN_UPLOADS": {"medium"}, "PHP_AUTO_PREPEND_CONFIG": {"low"},
    "BASELINE_FILE_CHANGED": {"high"}, "BASELINE_FILE_MISSING": {"high"}, "NEW_FILE_SINCE_BASELINE": {"medium", "low"},
    "CORE_CHECKSUM_MISMATCH": {"high"}, "CORE_FILE_NOT_IN_MANIFEST": {"low"}, "CORE_FILE_MISSING": {"high"},
    "REFERENCE_FILE_UNREADABLE": {"low"},
    "UNRECOGNIZED_ADMIN": {"medium"}, "NEW_SINCE_BASELINE": {"medium"}, "SUSPICIOUS_DB_MARKUP": {"low"},
    "HTTP_EXECUTABLE_IN_UPLOADS": {"medium", "low"},
    "CORRELATED_UPLOAD_REQUEST": {"medium"}, "CORRELATED_FILE_REQUEST": {"low"}, "REQUEST_NEAR_FILE_CHANGE": {"low"},
}


def test_severity_of_every_rule_matches_the_regression_table():
    assert {rule.id: rule.severity for rule in rules.REGISTRY.values()} == EXPECTED_SEVERITY


def test_confidence_of_every_rule_matches_the_regression_table():
    assert {rule.id: set(rule.confidence) for rule in rules.REGISTRY.values()} == EXPECTED_CONFIDENCE


def test_registry_entries_are_complete_and_use_report_enums():
    for rule in rules.REGISTRY.values():
        assert rule.description and rule.false_positives and rule.version >= 1
        assert rule.category in rules.SOURCE_OF_CATEGORY
        models.Finding(rule.id, rule.category, rule.severity, rule.confidence[0], rule.description, ("obs-synthetic",))
        assert all(models.Confidence(value) for value in rule.confidence)


def test_file_rules_are_taken_from_filerules_without_change():
    for rule in filerules.RULES.values():
        entry = rules.REGISTRY[rule.id]
        assert (entry.category, entry.severity, entry.version, entry.description, entry.false_positives) == (
            "file", rule.severity, rule.version, rule.explanation, rule.false_positives)
        assert rule.confidence in entry.confidence and (rule.known_code_confidence or rule.confidence) in entry.confidence


# --- identyfikator i skrót zestawu reguł -------------------------------------------------------------

def test_ruleset_digest_is_pinned_to_its_version():
    """Każda zmiana rejestru zmienia skrót; wtedy trzeba podnieść ``RULESET_VERSION`` i zaktualizować tę parę."""
    assert (rules.RULESET_ID, rules.RULESET_VERSION, rules.ruleset_sha256()) == (
        "wpincidentlens-poc", "2026.11.3", "95debea2451c955bcbb4d075779d29d2381709916688d3b13da77e64b9c6c9e5")


def test_ruleset_digest_is_computed_over_canonical_json():
    body = rules.canonical()
    document = json.loads(body)

    assert body == json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert [rule["id"] for rule in document["rules"]] == sorted(rules.REGISTRY)
    assert rules.descriptor() == {"id": rules.RULESET_ID, "version": rules.RULESET_VERSION, "sha256": rules.ruleset_sha256()}


def test_ruleset_digest_changes_with_any_declared_value(monkeypatch):
    before = rules.ruleset_sha256()
    monkeypatch.setitem(rules.REGISTRY, "CORE_FILE_MISSING", dataclasses.replace(rules.REGISTRY["CORE_FILE_MISSING"], confidence=("high", "low")))

    assert rules.ruleset_sha256() != before


# --- kontrakt kodu: każda emitowana reguła i wartość jest zadeklarowana ------------------------------

# Funkcja tworząca wykrycie albo ustalenie → pozycje argumentów (reguła, waga, pewność, kategoria); None: wartość
# stała dla tej funkcji (kategoria) albo pobierana z tabeli ``filerules.RULES`` (waga w ``detect``).
EMITTERS = {"Detection": (0, 1, 2, 3), "_emit": (1, 2, 3, None), "detect": (0, None, 1, None), "_finding": (0, 1, 2, None)}
FIXED_CATEGORY = {"_emit": "file", "detect": "file", "_finding": "correlation"}
EMITTING_MODULES = {"filerules.py", "integrity.py", "dbrules.py", "httplog.py", "correlate.py"}


def _literals(node: ast.AST | None) -> set[str]:
    """Stałe łańcuchowe wyrażenia: stała albo ``a if warunek else b`` ze stałych."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        return _literals(node.body) | _literals(node.orelse)
    return set()


def _calls() -> list[tuple[str, str, ast.Call]]:
    found = []
    for path in sorted(PACKAGE.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
                found.append((path.name, name, node))
    return found


def _emitted() -> list[tuple[str, str, set[str], set[str], set[str]]]:
    """(moduł, reguła, wagi, pewności, kategorie) dla każdego wywołania z regułą zapisaną stałą."""
    emitted = []
    for module, name, call in _calls():
        if name not in EMITTERS:
            continue
        positions = EMITTERS[name]
        arg = lambda at: call.args[at] if at is not None and at < len(call.args) else None  # noqa: E731
        for rule in _literals(arg(positions[0])):
            categories = _literals(arg(positions[3])) or {FIXED_CATEGORY.get(name, "")}
            emitted.append((module, rule, _literals(arg(positions[1])), _literals(arg(positions[2])), categories))
    return emitted


def test_every_rule_emitted_in_code_is_registered_and_every_registered_rule_is_emitted():
    emitted = _emitted()

    assert {module for module, *_ in emitted} == EMITTING_MODULES  # skan nie przechodzi pusto
    assert {rule for _, rule, *_ in emitted} - set(rules.REGISTRY) == set()
    assert set(rules.REGISTRY) == {rule for _, rule, *_ in emitted} | set(filerules.RULES)  # żadnej martwej reguły


def test_every_literal_severity_confidence_and_category_in_code_is_declared():
    for module, rule, severities, confidences, categories in _emitted():
        declared = rules.REGISTRY[rule]
        assert severities <= {declared.severity}, (module, rule)
        assert confidences <= set(declared.confidence), (module, rule)
        assert categories == {declared.category}, (module, rule)


def test_findings_are_built_only_by_the_registry():
    """``models.Finding`` powstaje wyłącznie w ``rules.finding``; ``migrate`` przenosi ustalenia ze starych raportów."""
    assert sorted({module for module, name, _ in _calls() if name == "Finding"}) == ["migrate.py", "rules.py"]


# --- gałęzie wybierane w czasie analizy: każda zadeklarowana pewność ma scenariusz -----------------

def _uploads_symlink(site: Path, evidence: Path) -> dict:
    (site / UPLOAD).mkdir(parents=True)
    os.symlink(write(evidence / "outside.php"), site / UPLOAD / "linked.php")
    return {}


def _mu_plugin_symlink(site: Path, evidence: Path) -> dict:
    baseline = trusted(site)
    (site / "wp-content" / "mu-plugins").mkdir(parents=True)
    os.symlink(write(evidence / "outside.php"), site / "wp-content" / "mu-plugins" / "loader.php")
    return {"baseline": baseline}


def _mu_plugin(site: Path, evidence: Path) -> dict:
    baseline = trusted(site)
    write(site / "wp-content" / "mu-plugins" / "loader.php")
    return {"baseline": baseline}


def _file(rel: str, content: str | None = None):
    return lambda site, evidence: write(site / rel, *([content] if content is not None else [])) and {}


def _log(uri: str):
    return lambda site, evidence: {"logs": write(evidence / "logs" / "access.log", access_line(uri)).parent}


BRANCHES = [
    pytest.param(_file(UPLOAD + "x.php"), "EXECUTABLE_IN_UPLOADS", "medium", id="uploads-read"),
    pytest.param(_uploads_symlink, "EXECUTABLE_IN_UPLOADS", "low", id="uploads-unread"),
    pytest.param(_file("wp-content/languages/helper.php"), "CODE_IN_UNEXPECTED_LOCATION", "low", id="languages"),
    pytest.param(_file("wp-admin/css/x.php"), "CODE_IN_UNEXPECTED_LOCATION", "medium", id="static-core-dir"),
    pytest.param(_mu_plugin, "NEW_FILE_SINCE_BASELINE", "medium", id="new-autoloaded-read"),
    pytest.param(_mu_plugin_symlink, "NEW_FILE_SINCE_BASELINE", "low", id="new-autoloaded-unread"),
    pytest.param(_log("/wp-content/uploads/x.php"), "HTTP_EXECUTABLE_IN_UPLOADS", "medium", id="log-code-in-uploads"),
    pytest.param(_log("/wp-content/uploads/x.php.jpg"), "HTTP_EXECUTABLE_IN_UPLOADS", "low", id="log-double-extension"),
    *(pytest.param(_file(PLUGIN + "a.php", POSITIVE[name][1]), name, "low", id=f"{name}-plugin")
      for name, rule in sorted(filerules.RULES.items()) if rule.known_code_confidence),
    *(pytest.param(_file("wp-content/mu-plugins/a.php", POSITIVE[name][1]), name, "medium", id=f"{name}-mu-plugin")
      for name, rule in sorted(filerules.RULES.items()) if rule.known_code_confidence),
]


@pytest.mark.parametrize("prepare, rule, confidence", BRANCHES)
def test_runtime_branch_emits_a_declared_confidence(site, evidence, analyze, prepare, rule, confidence):
    run = analyze(site, **prepare(site, evidence))  # fixture analyze odrzuca raport z luką rejestru reguł

    assert {(item["severity"], item["confidence"]) for item in run.findings if item["rule"] == rule} == {
        (rules.REGISTRY[rule].severity, confidence)}


def test_every_declared_confidence_of_a_multi_valued_rule_has_a_branch_scenario():
    covered = {(param.values[1], param.values[2]) for param in BRANCHES}

    assert covered == {(rule.id, value) for rule in rules.REGISTRY.values() if len(rule.confidence) > 1 for value in rule.confidence}


# --- ścieżka błędu reguły (spec C10) -----------------------------------------------------------------

def _detection(rule: str, severity: str, confidence: str, category: str = "file") -> Detection:
    fact = models.Observation("evd-synthetic", "SYNTHETIC_FACT", models.Location(path="x.php"), {})
    return Detection(rule, severity, confidence, category, "wykrycie syntetyczne", fact)


def _cover() -> dict[str, SourceCoverage]:
    return {source: SourceCoverage() for source in models.SOURCES}


def test_declared_detection_becomes_a_finding_without_a_gap():
    cover = _cover()

    found = rules.findings([_detection("EXECUTABLE_IN_UPLOADS", "high", "low")], cover)

    assert [(item.rule_id, item.severity, item.confidence) for item in found] == [("EXECUTABLE_IN_UPLOADS", "high", "low")]
    assert all(not entry.partial and not entry.reasons for entry in cover.values())


@pytest.mark.parametrize("detection, source, field", [
    (_detection("EXECUTABLE_IN_UPLOADS", "critical", "medium"), "files", "severity=critical"),
    (_detection("EXECUTABLE_IN_UPLOADS", "high", "high"), "files", "confidence=high"),
    (_detection("SUSPICIOUS_DB_MARKUP", "medium", "medium", "database"), "database", "confidence=medium"),
    (_detection("HTTP_EXECUTABLE_IN_UPLOADS", "high", "medium", "file"), "files", "category=file"),
], ids=["severity", "confidence", "database-source", "category"])
def test_undeclared_value_keeps_the_finding_as_emitted_and_adds_a_gap_naming_the_rule(detection, source, field):
    cover = _cover()

    found = rules.findings([detection], cover)

    assert [(item.rule_id, item.category, item.severity, item.confidence) for item in found] == [
        (detection.rule, detection.category, detection.severity, detection.confidence)]
    assert cover[source].partial
    assert [text for text in cover[source].reasons if detection.rule in text and field in text and text.startswith(rules.REGISTRY_GAP)]
    assert all(not cover[other].reasons for other in models.SOURCES if other != source)


def test_unknown_rule_is_an_internal_error_not_a_gap():
    with pytest.raises(rules.UnknownRule, match="NOT_A_REGISTERED_RULE"):
        rules.findings([_detection("NOT_A_REGISTERED_RULE", "high", "medium")], _cover())


def test_undeclared_value_in_a_full_run_keeps_the_finding_and_the_assessment(site, monkeypatch):
    """Naruszenie deklaracji nie może obniżyć oceny: ustalenie zostaje, dochodzi luka pokrycia ``files``."""
    write(site / UPLOAD / "x.php")
    clean = cli.compose_report(site, None, None, None, set(), "T501-SYNTH")
    monkeypatch.setitem(rules.REGISTRY, "EXECUTABLE_IN_UPLOADS",
                        dataclasses.replace(rules.REGISTRY["EXECUTABLE_IN_UPLOADS"], severity="low", confidence=("low",)))

    flawed = cli.compose_report(site, None, None, None, set(), "T501-SYNTH")

    assert flawed["findings"] == clean["findings"] and flawed["assessment"] == clean["assessment"] == "SUSPICIOUS"
    assert [gap for gap in flawed["coverage_gaps"] if gap.startswith(rules.REGISTRY_GAP)] == [
        gap for gap in flawed["coverage"]["files"]["reasons"] if "EXECUTABLE_IN_UPLOADS" in gap]
    assert flawed["coverage"]["files"]["status"] == "PARTIAL"
    models.validate_report(flawed)


def test_undeclared_value_in_a_correlation_keeps_the_finding_and_notes_a_logs_gap(monkeypatch):
    monkeypatch.setitem(rules.REGISTRY, "CORRELATED_FILE_REQUEST",
                        dataclasses.replace(rules.REGISTRY["CORRELATED_FILE_REQUEST"], severity="high"))

    result = correlate_run(flagged(PLUGIN_PHP, mtime_ns=None), requests=[request(PLUGIN_PHP)])

    assert [(item.rule_id, item.severity) for item in result.findings] == [("CORRELATED_FILE_REQUEST", "medium")]
    assert [note for note in result.notes if note.startswith(rules.REGISTRY_GAP) and "CORRELATED_FILE_REQUEST" in note]


def test_unknown_correlation_rule_is_an_internal_error(monkeypatch):
    monkeypatch.delitem(rules.REGISTRY, "CORRELATED_FILE_REQUEST")

    with pytest.raises(rules.UnknownRule):
        correlate_run(flagged(PLUGIN_PHP, mtime_ns=None), requests=[request(PLUGIN_PHP)])


# --- dokumentacja ------------------------------------------------------------------------------------

def _documented_rules() -> list[str]:
    """Identyfikatory z pierwszej kolumny tabel, których nagłówek zaczyna się od „Reguła”."""
    documented, in_rule_table = [], False
    for line in RULES_DOC.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            in_rule_table = False
            continue
        first = line.split("|")[1].strip()
        if first == "Reguła":
            in_rule_table = True
        elif in_rule_table and (named := re.fullmatch(r"`([A-Z][A-Z0-9_]*)`", first)):
            documented.append(named.group(1))
    return documented


def test_rules_doc_describes_every_registered_rule_and_no_other():
    documented = _documented_rules()

    assert len(documented) == len(set(documented))
    assert set(documented) == set(rules.REGISTRY)


def test_rules_doc_states_the_current_ruleset_version():
    assert f'RULESET_VERSION = "{rules.RULESET_VERSION}"' in RULES_DOC.read_text(encoding="utf-8")
