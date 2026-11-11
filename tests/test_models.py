"""Kontrakty danych ``poc-1`` (T-102, ADR 0003): pola, referencje, identyfikatory z treści i reguła oceny.

Wyłącznie obiekty syntetyczne budowane w pamięci; moduł ``wptrace.models`` niczego nie czyta ani nie zapisuje.
"""
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from conftest import remove_at, replace_at

from wptrace.ingest import ReadStatus
from wptrace.models import (
    SOURCES,
    Assessment,
    Confidence,
    Coverage,
    Evidence,
    Finding,
    Location,
    ModelError,
    Observation,
    Report,
    Severity,
    TimelineEvent,
    assess,
    content_id,
    describe_location,
    scope_complete,
    utc_iso,
    validate_report,
)

SHA, OTHER_SHA = "a" * 64, "b" * 64
MISSING_EVIDENCE, MISSING_OBSERVATION = "ev_" + "0" * 32, "obs_" + "0" * 32
LOG_TIME = "2026-11-09T01:14:01+00:00"
NO_ENTRIES = {str(status): 0 for status in ReadStatus}


def coverage(source: str, status: str = "ANALYZED") -> Coverage:
    """Pokrycie źródła w danym statusie, z licznikami i powodem, których ten status wymaga."""
    if status == "UNKNOWN_LEGACY":
        return Coverage(source, status, None)
    entries = {"ANALYZED": {"READ": 1}, "PARTIAL": {"READ": 1, "SKIPPED_LIMIT": 1}, "FAILED": {"ERROR": 1}, "NOT_PROVIDED": {}}[status]
    return Coverage(source, status, {**NO_ENTRIES, **entries}, () if status == "ANALYZED" else (f"powód {source}",))


def all_coverage(**statuses: str) -> dict[str, Coverage]:
    return {source: coverage(source, statuses.get(source, "ANALYZED")) for source in SOURCES}


def finding(severity: str = "high", confidence: str = "medium", observation: str = MISSING_OBSERVATION) -> Finding:
    return Finding("SYNTHETIC_RULE", "file", severity, confidence, "ustalenie syntetyczne", (observation,))


def parts() -> dict:
    """Składniki poprawnego raportu: plik z ustaleniem, wiersz logu z czasem i zdarzenie osi czasu."""
    upload = Evidence("file", "files/wp-content/uploads/a.php", "READ", sha256=SHA, size_bytes=3, mtime_ns=1_700_000_000_000_000_000)
    log = Evidence("log", "logs/access.log", "READ", sha256=OTHER_SHA, size_bytes=90, mtime_ns=1)
    in_uploads = Observation(upload.id, "PHP_FILE_IN_UPLOADS", Location(path="wp-content/uploads/a.php"))
    request = Observation(log.id, "HTTP_REQUEST_FOR_PHP_IN_UPLOADS", Location(path="access.log", line=1), {"status": 200},
                          timestamp_raw="09/Nov/2026:02:14:01 +0100", timestamp_utc=LOG_TIME, time_source="log")
    found = finding(observation=in_uploads.id)
    event = TimelineEvent(LOG_TIME, "log", "HTTP access log", "HTTP_EXECUTABLE_IN_UPLOADS", "access.log:1", "medium", log.id, request.id)
    return {"case_id": "SYNTH-1", "tool": "WPTrace PoC", "tool_version": "test", "analyzed_at_utc": "2026-11-11T10:00:00+00:00",
            "assessment": "SUSPICIOUS", "disclaimer": "syntetyczne", "evidence": (upload, log), "observations": (in_uploads, request),
            "findings": (found,), "coverage": all_coverage(), "coverage_gaps": (), "timeline": (event,)}


def report(**changes) -> Report:
    return Report(**{**parts(), **changes})


def report_dict() -> dict:
    """Raport w postaci, w jakiej trafia do pliku: po przejściu przez JSON."""
    return json.loads(json.dumps(report().to_dict()))


# --- poprawny raport ----------------------------------------------------------------------------

def test_valid_report_survives_a_json_round_trip_unchanged():
    assert validate_report(report_dict()) == report()


def test_report_dictionary_has_the_poc_1_top_level_fields():
    assert list(report().to_dict()) == [
        "schema_version", "tool", "tool_version", "case_id", "analyzed_at_utc", "analyzed_at_time_source", "assessment",
        "scope_complete", "disclaimer", "findings", "observations", "evidence", "coverage", "coverage_gaps", "timeline"]


def test_report_order_does_not_depend_on_the_order_of_its_inputs():
    given = parts()
    reordered = report(evidence=given["evidence"][::-1], observations=given["observations"][::-1])

    assert reordered.to_dict() == report().to_dict()


def test_findings_are_ordered_from_the_most_severe():
    fact = parts()["observations"][0]
    low, critical = Finding("B_RULE", "file", "low", "high", "x", (fact.id,)), Finding("A_RULE", "file", "critical", "low", "x", (fact.id,))

    ordered = report(findings=(low, parts()["findings"][0], critical)).to_dict()["findings"]

    assert [item["severity"] for item in ordered] == ["critical", "high", "low"]


# --- referencje i unikalność --------------------------------------------------------------------

def _event(**changes) -> TimelineEvent:
    return TimelineEvent(**{**parts()["timeline"][0].to_dict(), **changes})


@pytest.mark.parametrize("changes, message", [
    (lambda given: {"evidence": given["evidence"][1:]}, "nieistniejący dowód"),
    (lambda given: {"observations": given["observations"][1:]}, "nieistniejącą obserwację"),
    (lambda given: {"findings": (finding(observation=MISSING_OBSERVATION),)}, "nieistniejącą obserwację"),
    (lambda given: {"timeline": (_event(evidence_id=MISSING_EVIDENCE),)}, "timeline: zdarzenie HTTP_EXECUTABLE_IN_UPLOADS wskazuje nieistniejący dowód"),
    (lambda given: {"timeline": (_event(observation_id=MISSING_OBSERVATION),)}, "timeline: zdarzenie HTTP_EXECUTABLE_IN_UPLOADS wskazuje nieistniejącą obserwację"),
], ids=["observation-without-evidence", "finding-without-observation", "finding-points-nowhere", "timeline-without-evidence",
        "timeline-without-observation"])
def test_dangling_reference_is_rejected(changes, message):
    with pytest.raises(ModelError, match=message):
        report(**changes(parts()))


@pytest.mark.parametrize("collection", ["evidence", "observations", "findings"])
def test_duplicate_identifier_is_rejected(collection):
    doubled = parts()[collection] * 2

    with pytest.raises(ModelError, match=f"{collection}: powtórzony identyfikator"):
        report(**{collection: doubled})


def test_finding_must_point_to_at_least_one_observation():
    with pytest.raises(ModelError, match="co najmniej jedną obserwację"):
        Finding("SYNTHETIC_RULE", "file", "high", "medium", "x", ())


@pytest.mark.parametrize("changes, message", [
    ({"evidence": "files/a.php"}, "evidence: oczekiwano listy, jest str"),
    ({"evidence": 7}, "evidence: oczekiwano listy, jest int"),
    ({"findings": ({"rule_id": "SYNTHETIC_RULE"},)}, "findings: oczekiwano obiektów Finding, jest dict"),
    ({"coverage_gaps": "brak logów"}, "coverage_gaps: oczekiwano listy tekstów, jest str"),
    ({"coverage_gaps": ("brak", "brak")}, "coverage_gaps: powtórzone wartości"),
    ({"coverage": {"files": coverage("files")}}, "coverage: wymagane dokładnie źródła: files, database, logs, baseline"),
    ({"coverage": {**all_coverage(), "logs": coverage("files")}}, "coverage.logs: oczekiwano obiektu Coverage tego źródła"),
], ids=["evidence-as-text", "evidence-as-number", "finding-as-dictionary", "gaps-as-text", "repeated-gap", "coverage-of-one-source",
        "coverage-under-wrong-source"])
def test_report_built_from_wrong_kinds_of_parts_is_rejected(changes, message):
    with pytest.raises(ModelError, match=message):
        report(**changes)


@pytest.mark.parametrize("fields, message", [
    ({"location": {"path": "a.php"}}, "location: oczekiwano obiektu Location, jest dict"),
    ({"attributes": [("uri", "/a")]}, "attributes: oczekiwano obiektu, jest list"),
], ids=["location-as-dictionary", "attributes-as-list"])
def test_observation_built_from_wrong_kinds_of_parts_is_rejected(fields, message):
    with pytest.raises(ModelError, match=message):
        Observation(MISSING_EVIDENCE, "SYNTHETIC_FACT", **fields)


# --- błędne wartości i typy w zapisanym raporcie ------------------------------------------------

def _changed(path: tuple, value) -> dict:
    """Poprawny raport-słownik z jedną podmienioną wartością."""
    broken = report_dict()
    replace_at(broken, path, value)
    return broken


def _without(*path) -> dict:
    broken = report_dict()
    remove_at(broken, path)
    return broken


BROKEN_REPORTS = {
    "unknown-assessment": (_changed(("assessment",), "CLEAN"), "assessment: nieznana wartość 'CLEAN'"),
    "unknown-severity": (_changed(("findings", 0, "severity"), "HIGH"), "severity: nieznana wartość 'HIGH'"),
    "confidence-is-not-severity": (_changed(("findings", 0, "confidence"), "critical"), "confidence: nieznana wartość 'critical'"),
    "unknown-category": (_changed(("findings", 0, "category"), "network"), "category: nieznana wartość"),
    "unknown-read-status": (_changed(("evidence", 0, "read_status"), "SKIPPED"), "read_status: nieznana wartość 'SKIPPED'"),
    "unknown-origin": (_changed(("evidence", 0, "origin_kind"), "memory"), "origin_kind: nieznana wartość"),
    "unknown-coverage-status": (_changed(("coverage", "files", "status"), "COMPLETE"), "coverage.files.status: nieznana wartość"),
    "unknown-time-source": (_changed(("timeline", 0, "time_source"), "ntp"), "time_source: nieznana wartość"),
    "size-as-text": (_changed(("evidence", 0, "size_bytes"), "3"), "size_bytes: oczekiwano liczby całkowitej, jest str"),
    "size-as-boolean": (_changed(("evidence", 0, "size_bytes"), True), "size_bytes: oczekiwano liczby całkowitej, jest bool"),
    "negative-size": (_changed(("evidence", 0, "size_bytes"), -1), "size_bytes: liczba nie może być ujemna"),
    "hardlinked-as-text": (_changed(("evidence", 0, "hardlinked"), "no"), "hardlinked: oczekiwano wartości logicznej"),
    "malformed-sha256": (_changed(("evidence", 0, "sha256"), "ABC"), "sha256: wartość 'ABC' nie ma wymaganej postaci"),
    "findings-not-a-list": (_changed(("findings",), {}), "findings: oczekiwano listy, jest dict"),
    "finding-not-an-object": (_changed(("findings", 0), "x"), r"findings\[0\]: oczekiwano obiektu, jest str"),
    "observations-as-text": (_changed(("findings", 0, "observations"), "obs"), "observations: oczekiwano listy, jest str"),
    "nested-attribute": (_changed(("observations", 0, "attributes"), {"nested": {"a": 1}}), "attributes.nested: oczekiwano tekstu"),
    "lowercase-kind": (_changed(("observations", 0, "kind"), "php in uploads"), "kind: wartość 'php in uploads' nie ma wymaganej postaci"),
    "reason-as-number": (_changed(("findings", 0, "reason"), 7), "reason: oczekiwano tekstu, jest int"),
    "missing-top-level-field": (_without("coverage"), "raport: brak pól: coverage"),
    "missing-evidence-field": (_without("evidence", 0, "read_status"), r"evidence\[0\]: brak pól: read_status"),
    "unknown-top-level-field": (_changed(("verdict",), "clean"), "raport: nieznane pola: verdict"),
    "unknown-location-field": (_changed(("observations", 0, "location", "column"), 4), "nieznane pola: column"),
    "missing-coverage-source": (_without("coverage", "logs"), "coverage: brak pól: logs"),
    "extra-coverage-source": (_changed(("coverage", "memory"), {}), "coverage: nieznane pola: memory"),
    "wrong-schema-version": (_changed(("schema_version",), "0.1.0"), "schema_version: oczekiwano 'poc-1', jest '0.1.0'"),
    "report-not-an-object": ([], "raport: oczekiwano obiektu, jest list"),
    "host-path-as-evidence": (_changed(("evidence", 0, "logical_path"), "/srv/www/a.php"), "logical_path: ścieżka musi być względna"),
    "hash-without-read": (_changed(("evidence", 0, "read_status"), "SKIPPED_HARDLINK"), "sha256 musi istnieć dla statusów READ, CHANGED"),
    "read-without-hash": (_changed(("evidence", 0, "sha256"), None), "sha256 musi istnieć dla statusów READ, CHANGED"),
    "identifier-not-from-content": (_changed(("evidence", 0, "id"), MISSING_EVIDENCE), "identyfikator .* nie wynika z treści"),
    "content-changed-under-identifier": (_changed(("findings", 0, "rule_id"), "OTHER_RULE"), "identyfikator .* nie wynika z treści"),
    "wrong-clock-label": (_changed(("analyzed_at_time_source",), "log"), "analyzed_at_time_source: oczekiwano tool_clock"),
    "scope-flag-contradicts-coverage": (_changed(("scope_complete",), False), "scope_complete: jest False, a z pokrycia wynika True"),
    "reason-missing-from-gap-list": (_changed(("coverage", "baseline"), {"status": "NOT_PROVIDED", "entries": NO_ENTRIES, "reasons": ["brak"]}),
                                     "powód nieobecny w coverage_gaps"),
    "legacy-marker-in-native-report": (_changed(("coverage", "baseline"), {"status": "UNKNOWN_LEGACY", "entries": None, "reasons": []}),
                                       "UNKNOWN_LEGACY jest dozwolone wyłącznie w raporcie z polem migrated_from"),
    "unknown-migration-origin": (_changed(("migrated_from",), "0.0.1"), "migrated_from: dozwolone wartości: 0.1.0"),
}


@pytest.mark.parametrize("broken, message", BROKEN_REPORTS.values(), ids=BROKEN_REPORTS.keys())
def test_broken_report_is_rejected_with_a_message_naming_the_field(broken, message):
    with pytest.raises(ModelError, match=message):
        validate_report(broken)


def test_validation_does_not_modify_the_checked_dictionary():
    checked = report_dict()
    before = copy.deepcopy(checked)

    validate_report(checked)

    assert checked == before


# --- czas ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("moment", ["2026-11-09T01:14:01Z", "2026-11-09T01:14:01+00:00", "2026-11-09T01:14:01.250000+00:00"],
                         ids=["zulu", "zero-offset", "fraction"])
def test_utc_time_is_accepted_with_z_or_zero_offset(moment):
    assert validate_report(_changed(("analyzed_at_utc",), moment)).analyzed_at_utc == moment


@pytest.mark.parametrize("moment", ["2026-11-09T01:14:01", "2026-11-09T02:14:01+01:00", "2026-13-40T00:00:00Z", "09/Nov/2026:02:14:01 +0100",
                                    1762650841, None],
                         ids=["no-zone", "other-offset", "impossible-date", "log-format", "epoch-number", "null-in-native-report"])
def test_time_outside_utc_iso_8601_is_rejected(moment):
    with pytest.raises(ModelError, match="analyzed_at_utc"):
        validate_report(_changed(("analyzed_at_utc",), moment))


@pytest.mark.parametrize("path", [("timeline", 0, "time_utc"), ("observations", 0, "timestamp_utc")], ids=["timeline", "observation"])
def test_local_time_is_rejected_wherever_utc_is_required(path):
    with pytest.raises(ModelError, match=path[-1]):
        validate_report(_changed(path, "2026-11-09T02:14:01+01:00"))


def test_observation_time_needs_a_declared_source():
    evidence = parts()["evidence"][1]

    with pytest.raises(ModelError, match="time_source towarzyszy timestamp_raw"):
        Observation(evidence.id, "HTTP_REQUEST_FOR_PHP_IN_UPLOADS", timestamp_raw="09/Nov/2026:02:14:01 +0100", timestamp_utc=LOG_TIME)


def test_tool_clock_cannot_date_a_timeline_event():
    with pytest.raises(ModelError, match="zegar narzędzia nie jest źródłem czasu zdarzeń"):
        _event(time_source="tool_clock")


def test_utc_iso_converts_zoned_time_to_utc():
    warsaw = datetime(2026, 11, 9, 2, 14, 1, tzinfo=timezone(timedelta(hours=1)))

    assert utc_iso(warsaw) == LOG_TIME


def test_utc_iso_refuses_to_guess_a_missing_zone():
    with pytest.raises(ModelError, match="czas bez strefy"):
        utc_iso(datetime(2026, 11, 9, 2, 14, 1))


# --- identyfikatory z treści --------------------------------------------------------------------

def test_content_id_is_a_pinned_function_of_canonical_json():
    """Wzorzec: posortowane klucze, bez odstępów, tylko ASCII, 32 znaki skrótu. Zmiana unieważnia identyfikatory w istniejących raportach."""
    canonical = rb'{"a":"\u017c","b":1}'

    assert content_id("ev", {"b": 1, "a": "ż"}) == "ev_" + hashlib.sha256(canonical).hexdigest()[:32] == "ev_28c70b023f68c7f3db76ed1d95ea5678"


def _file(**changes) -> Evidence:
    fields = {"origin_kind": "file", "logical_path": "files/a.php", "read_status": "READ", "sha256": SHA, "size_bytes": 3,
              "mtime_ns": 5, "read_reason": None, "hardlinked": False}
    return Evidence(**{**fields, **changes})


@pytest.mark.parametrize("changes", [{"logical_path": "files/b.php"}, {"sha256": OTHER_SHA},
                                     {"origin_kind": "log", "logical_path": "logs/a.php"}],
                         ids=["path", "sha256", "origin"])
def test_evidence_id_changes_with_each_identity_field(changes):
    assert _file(**changes).id != _file().id


@pytest.mark.parametrize("changes", [{"mtime_ns": 6}, {"size_bytes": 4}, {"hardlinked": True},
                                     {"read_status": "CHANGED", "read_reason": "REVERIFY_SHA256"}],
                         ids=["mtime", "size", "hardlinked", "changed-after-read"])
def test_evidence_id_of_read_bytes_ignores_fields_outside_its_identity(changes):
    assert _file(**changes).id == _file().id


def test_unread_entries_at_one_path_are_told_apart_by_status_and_reason():
    skipped = {(status, reason): Evidence("file", "files/.", status, read_reason=reason).id
               for status, reason in [("SKIPPED_LIMIT", "MAX_ENTRIES"), ("SKIPPED_LIMIT", "MAX_SECONDS"), ("ERROR", "EACCES")]}

    assert len(set(skipped.values())) == 3


def test_observation_id_ignores_attribute_insertion_order():
    evidence = _file()
    first = Observation(evidence.id, "SYNTHETIC_FACT", Location(path="a.php"), {"uri": "/a", "status": 200})
    second = Observation(evidence.id, "SYNTHETIC_FACT", Location(path="a.php"), {"status": 200, "uri": "/a"})

    assert first.id == second.id and first == second


@pytest.mark.parametrize("changes", [{"kind": "OTHER_FACT"}, {"location": Location(path="a.php", line=2)}, {"attributes": {"status": 404}},
                                     {"evidence_id": MISSING_EVIDENCE}],
                         ids=["kind", "location", "attributes", "evidence"])
def test_observation_id_changes_with_each_identity_field(changes):
    fields = {"evidence_id": _file().id, "kind": "SYNTHETIC_FACT", "location": Location(path="a.php", line=1), "attributes": {"status": 200}}

    assert Observation(**{**fields, **changes}).id != Observation(**fields).id


def test_finding_id_depends_on_rule_and_observations_not_on_their_order_or_rating():
    first = Finding("SYNTHETIC_RULE", "file", "high", "medium", "x", ("obs_b", "obs_a"))
    second = Finding("SYNTHETIC_RULE", "correlation", "low", "high", "y", ("obs_a", "obs_b"))

    assert first.id == second.id
    assert Finding("OTHER_RULE", "file", "high", "medium", "x", ("obs_a", "obs_b")).id != first.id


# --- severity i confidence ----------------------------------------------------------------------

def test_severity_and_confidence_are_separate_scales():
    assert [str(level) for level in Severity] == ["low", "medium", "high", "critical"]
    assert [str(level) for level in Confidence] == ["low", "medium", "high"]


@pytest.mark.parametrize("severity", list(Severity))
@pytest.mark.parametrize("confidence", list(Confidence))
def test_every_severity_combines_with_every_confidence(severity, confidence):
    rated = finding(severity, confidence)

    assert (rated.severity, rated.confidence) == (severity, confidence)


# --- pokrycie -----------------------------------------------------------------------------------

@pytest.mark.parametrize("status, entries, reasons, message", [
    ("ANALYZED", {"READ": 2, "SKIPPED_HARDLINK": 1}, (), "ANALYZED wymaga co najmniej jednego wpisu READ i żadnego wpisu o innym statusie"),
    ("ANALYZED", {"READ": 1, "CHANGED": 1}, (), "ANALYZED wymaga"),
    ("ANALYZED", {}, (), "ANALYZED wymaga"),
    ("PARTIAL", {"READ": 1, "SKIPPED_LIMIT": 1}, (), "status PARTIAL wymaga co najmniej jednego powodu"),
    ("FAILED", {"ERROR": 1}, (), "status FAILED wymaga co najmniej jednego powodu"),
    ("NOT_PROVIDED", {}, (), "status NOT_PROVIDED wymaga co najmniej jednego powodu"),
    ("NOT_PROVIDED", {"READ": 1}, ("brak",), "NOT_PROVIDED wyklucza jakiekolwiek wpisy"),
    ("PARTIAL", {"READ": -1}, ("limit",), "entries.READ: liczba nie może być ujemna"),
], ids=["analyzed-with-skipped-entry", "analyzed-with-changed-entry", "analyzed-with-nothing-read", "partial-without-reason",
        "failed-without-reason", "not-provided-without-reason", "not-provided-with-entries", "negative-counter"])
def test_coverage_status_must_agree_with_its_counters_and_reasons(status, entries, reasons, message):
    with pytest.raises(ModelError, match=message):
        Coverage("files", status, {**NO_ENTRIES, **entries}, reasons)


@pytest.mark.parametrize("entries", [None, {"READ": 1}, {**NO_ENTRIES, "SKIPPED": 0}], ids=["missing", "incomplete", "unknown-status"])
def test_coverage_counters_must_name_every_read_status(entries):
    with pytest.raises(ModelError, match="entries"):
        Coverage("files", "PARTIAL", entries, ("limit",))


def test_unknown_coverage_source_is_rejected():
    with pytest.raises(ModelError, match="nieznane źródło 'memory'"):
        Coverage("memory", "ANALYZED", {**NO_ENTRIES, "READ": 1})


# --- reguła oceny -------------------------------------------------------------------------------

COMPLETE, NO_BASELINE = {}, {"baseline": "NOT_PROVIDED"}
ASSESSMENT_CASES = {
    # brak ustaleń: wynik zależy wyłącznie od zakresu
    "nothing-found-all-sources": ([], COMPLETE, Assessment.NO_INDICATORS_IN_ANALYZED_SCOPE),
    "nothing-found-without-baseline": ([], NO_BASELINE, Assessment.NO_INDICATORS_IN_ANALYZED_SCOPE),
    "nothing-found-no-database": ([], {"database": "NOT_PROVIDED"}, Assessment.INCONCLUSIVE),
    "nothing-found-no-logs": ([], {"logs": "NOT_PROVIDED"}, Assessment.INCONCLUSIVE),
    "nothing-found-no-database-no-logs": ([], {"database": "NOT_PROVIDED", "logs": "NOT_PROVIDED"}, Assessment.INCONCLUSIVE),
    "nothing-found-files-partial": ([], {"files": "PARTIAL"}, Assessment.INCONCLUSIVE),
    "nothing-found-files-failed": ([], {"files": "FAILED"}, Assessment.INCONCLUSIVE),
    "nothing-found-database-partial": ([], {"database": "PARTIAL"}, Assessment.INCONCLUSIVE),
    "nothing-found-database-failed": ([], {"database": "FAILED"}, Assessment.INCONCLUSIVE),
    "nothing-found-logs-partial": ([], {"logs": "PARTIAL"}, Assessment.INCONCLUSIVE),
    "nothing-found-logs-failed": ([], {"logs": "FAILED"}, Assessment.INCONCLUSIVE),
    "nothing-found-baseline-partial": ([], {"baseline": "PARTIAL"}, Assessment.INCONCLUSIVE),
    "nothing-found-baseline-failed": ([], {"baseline": "FAILED"}, Assessment.INCONCLUSIVE),
    "nothing-found-legacy-coverage": ([], dict.fromkeys(SOURCES, "UNKNOWN_LEGACY"), Assessment.INCONCLUSIVE),
    # ustalenia poniżej progu silnego wskaźnika: SUSPICIOUS, także przy niepełnym zakresie
    "weakest-finding": ([("low", "low")], COMPLETE, Assessment.SUSPICIOUS),
    "high-severity-medium-confidence": ([("high", "medium")], COMPLETE, Assessment.SUSPICIOUS),
    "critical-severity-medium-confidence": ([("critical", "medium")], COMPLETE, Assessment.SUSPICIOUS),
    "medium-severity-high-confidence": ([("medium", "high")], COMPLETE, Assessment.SUSPICIOUS),
    "low-severity-high-confidence": ([("low", "high")], COMPLETE, Assessment.SUSPICIOUS),
    "many-heuristics-do-not-add-up": ([("high", "medium")] * 5 + [("medium", "high")] * 5, COMPLETE, Assessment.SUSPICIOUS),
    "finding-with-partial-scope": ([("high", "medium")], {"database": "NOT_PROVIDED", "files": "PARTIAL"}, Assessment.SUSPICIOUS),
    # silny wskaźnik: waga high/critical i pewność high; luki pokrycia go nie ukrywają
    "high-severity-high-confidence": ([("high", "high")], COMPLETE, Assessment.STRONG_INDICATORS),
    "critical-severity-high-confidence": ([("critical", "high")], COMPLETE, Assessment.STRONG_INDICATORS),
    "strong-among-weak": ([("low", "low"), ("high", "high")], COMPLETE, Assessment.STRONG_INDICATORS),
    "strong-with-partial-scope": ([("high", "high")], {"logs": "NOT_PROVIDED", "files": "FAILED"}, Assessment.STRONG_INDICATORS),
}


@pytest.mark.parametrize("ratings, statuses, expected", ASSESSMENT_CASES.values(), ids=ASSESSMENT_CASES.keys())
def test_assessment_rule(ratings, statuses, expected):
    assert assess([finding(*rating) for rating in ratings], all_coverage(**statuses)) is expected


@pytest.mark.parametrize("statuses, expected", [
    (COMPLETE, True), (NO_BASELINE, True), ({"files": "PARTIAL"}, False), ({"database": "NOT_PROVIDED"}, False),
    ({"logs": "FAILED"}, False), ({"baseline": "PARTIAL"}, False), ({"baseline": "UNKNOWN_LEGACY"}, False),
], ids=["all-analyzed", "baseline-not-provided", "files-partial", "database-not-provided", "logs-failed", "baseline-partial", "baseline-legacy"])
def test_scope_is_complete_only_with_all_critical_sources_analyzed(statuses, expected):
    assert scope_complete(all_coverage(**statuses)) is expected


@pytest.mark.parametrize("claimed, findings, statuses", [
    ("NO_INDICATORS_IN_ANALYZED_SCOPE", (), {"database": "NOT_PROVIDED"}),
    ("NO_INDICATORS_IN_ANALYZED_SCOPE", None, COMPLETE),
    ("INCONCLUSIVE", (), COMPLETE),
    ("INCONCLUSIVE", None, {"logs": "NOT_PROVIDED"}),
    ("STRONG_INDICATORS", None, COMPLETE),
], ids=["clean-bill-with-missing-database", "clean-bill-despite-findings", "inconclusive-with-complete-scope",
        "inconclusive-despite-findings", "strong-without-strong-finding"])
def test_report_whose_assessment_contradicts_the_rule_is_rejected(claimed, findings, statuses):
    """``findings=None`` zostawia ustalenie z raportu wzorcowego (high/medium)."""
    changes = {"assessment": claimed, "coverage": all_coverage(**statuses),
               "coverage_gaps": tuple(f"powód {source}" for source in statuses)}
    if findings is not None:
        changes["findings"] = findings

    with pytest.raises(ModelError, match=f"assessment: jest {claimed}, a z ustaleń i pokrycia wynika"):
        report(**changes)


# --- opis miejsca -------------------------------------------------------------------------------

@pytest.mark.parametrize("location, expected", [
    ({"path": "wp-content/uploads/a.php"}, "wp-content/uploads/a.php"),
    ({"path": "access.log", "line": 12}, "access.log:12"),
    ({"table": "wp_options", "key": "custom_footer", "row": 3}, "wp_options:custom_footer"),
    ({"table": "wp_usermeta"}, "wp_usermeta"),
    ({}, ""),
], ids=["file", "log-line", "table-key", "table", "unknown"])
def test_location_description(location, expected):
    assert describe_location(Location(**location).to_dict()) == expected
