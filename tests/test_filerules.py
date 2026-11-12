"""Reguły plików (T-201): dla każdej reguły przypadek pozytywny, negatywny i fałszywy alarm wzorowany na legalnym kodzie.

Wyłącznie dane syntetyczne. Wzorce to obojętny tekst w komentarzu PHP albo w pliku konfiguracyjnym tworzonym
w ``tmp_path``: nic z tych plików nie jest wykonywane, importowane ani ładowane przez serwer.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import CANARY, EVAL_MARKER, HARMLESS_PHP, sparse, time_limit, write

from wpincidentlens import cli, filerules, ingest, models

NOTE = "<?php // SYNTHETIC indicator text, never executed: "
UPLOADS = "wp-content/uploads/2026/11/"
PLUGIN = "wp-content/plugins/demo/"
BLOB = "QUJD" * (filerules.BLOB_MIN_BYTES // 4)

# Po jednym trafieniu każdej reguły treści: (ścieżka, treść, początek dopasowania).
POSITIVE = {
    "SUSPICIOUS_PHP_EVAL_DECODE": (PLUGIN + "a.php", NOTE + "assert(gzinflate(str_rot13('synthetic')));\n", "assert("),
    "REQUEST_TO_COMMAND_EXEC": (PLUGIN + "a.php", NOTE + "passthru($_GET['synthetic']);\n", "passthru("),
    "REQUEST_TO_CODE_EVAL": (PLUGIN + "a.php", NOTE + "eval(stripslashes($_REQUEST['synthetic']));\n", "eval("),
    "REQUEST_VARIABLE_FUNCTION_CALL": (PLUGIN + "a.php", NOTE + "$_GET['f']('synthetic');\n", "$_GET["),
    "PHP_PREG_REPLACE_EVAL": (PLUGIN + "a.php", NOTE + "preg_replace('/.*/se', $synthetic, '');\n", "preg_replace("),
    "LONG_ENCODED_BLOB": (PLUGIN + "a.php", NOTE + f"'{BLOB}'\n", BLOB),
    "REQUEST_INPUT_TO_INCLUDE": (PLUGIN + "a.php", NOTE + "include($_GET['synthetic']);\n", "include("),
    "REQUEST_CONTROLLED_FILE_WRITE": (PLUGIN + "a.php", NOTE + "file_put_contents($_POST['synthetic'], 'x');\n", "file_put_contents("),
    "HTACCESS_ENABLES_PHP_IN_UPLOADS": (UPLOADS + ".htaccess", "# synthetic\nAddHandler application/x-httpd-php .jpg\n", "AddHandler"),
    "PHP_AUTO_PREPEND_CONFIG": (".user.ini", "; synthetic\nauto_prepend_file = /srv/synthetic.php\n", "auto_prepend_file"),
}


def case(rel: str, content: str, *rules: str, id: str):
    return pytest.param(rel, content, set(rules), id=id)


CASES = [
    # EXECUTABLE_IN_UPLOADS (istniejące testy P1/N5 obejmują .php)
    case(UPLOADS + "old.php5", HARMLESS_PHP, "EXECUTABLE_IN_UPLOADS", id="uploads-php5"),
    case(PLUGIN + "old.php5", HARMLESS_PHP, id="php5-in-plugin"),
    case(UPLOADS + "readme.txt", "synthetic", id="uploads-text-file"),
    # DOUBLE_EXTENSION_IN_UPLOADS
    case(UPLOADS + "photo.php.jpg", "synthetic", "DOUBLE_EXTENSION_IN_UPLOADS", id="double-extension"),
    case(UPLOADS + "Photo.PHTML.png", "synthetic", "DOUBLE_EXTENSION_IN_UPLOADS", id="double-extension-uppercase"),
    case(PLUGIN + "photo.php.jpg", "synthetic", id="double-extension-outside-uploads"),
    case(UPLOADS + "photo.final.jpg", "synthetic", id="fp-ordinary-two-dots"),
    case(UPLOADS + "php.jpg", "synthetic", id="fp-name-is-php"),
    # CODE_IN_UNEXPECTED_LOCATION
    case("wp-content/languages/helper.php", HARMLESS_PHP, "CODE_IN_UNEXPECTED_LOCATION", id="code-in-languages"),
    case("wp-includes/images/smilies/x.php", HARMLESS_PHP, "CODE_IN_UNEXPECTED_LOCATION", id="code-in-core-images"),
    case("wp-includes/class-synthetic.php", HARMLESS_PHP, id="code-in-wp-includes"),
    case("wp-content/languages/plugins/demo-pl_PL.l10n.php", "<?php return ['messages' => []];\n", id="fp-l10n-translation"),
    case("wp-content/languages/pl_PL.mo", "synthetic", id="fp-mo-translation"),
    # SUSPICIOUS_PHP_EVAL_DECODE
    case(*POSITIVE["SUSPICIOUS_PHP_EVAL_DECODE"][:2], "SUSPICIOUS_PHP_EVAL_DECODE", id="assert-gzinflate-rot13"),
    case(PLUGIN + "a.php", NOTE + "create_function('', gzuncompress(base64_decode('synthetic')));\n",
         "SUSPICIOUS_PHP_EVAL_DECODE", id="create-function-decoder"),
    case(PLUGIN + "a.php", NOTE + "eval (\n  @base64_decode('synthetic'));\n", "SUSPICIOUS_PHP_EVAL_DECODE", id="eval-spaced"),
    case(PLUGIN + "a.php", NOTE + "eval($template);\n", id="eval-without-decoder"),
    case(PLUGIN + "a.php", NOTE + "$png = base64_decode($data); imagecreatefromstring($png);\n", id="fp-decode-image"),
    case(PLUGIN + "a.php", NOTE + "$sandbox->eval(base64_decode($x)); medieval(strrev($y));\n", id="fp-method-named-eval"),
    # REQUEST_TO_COMMAND_EXEC
    case(*POSITIVE["REQUEST_TO_COMMAND_EXEC"][:2], "REQUEST_TO_COMMAND_EXEC", id="exec-of-request-input"),
    case(PLUGIN + "a.php", NOTE + "$c = $_SERVER['HTTP_X_SYNTHETIC']; echo 1; exec($c);\n", "REQUEST_TO_COMMAND_EXEC", id="header-then-exec"),
    case(PLUGIN + "a.php", NOTE + "system('uptime');\n", id="exec-without-request-input"),
    case(PLUGIN + "a.php", NOTE + "$_POST['x'];" + " " * 400 + "system('uptime');\n", id="request-input-far-from-exec"),
    case(PLUGIN + "a.php", NOTE + "$u = $_GET['url']; curl_exec($ch); WP_Filesystem(); $db->exec($sql); $s = $_SERVER['SERVER_NAME'];\n",
         id="fp-curl-exec-and-wp-filesystem"),
    # REQUEST_TO_CODE_EVAL
    case(*POSITIVE["REQUEST_TO_CODE_EVAL"][:2], "REQUEST_TO_CODE_EVAL", id="eval-of-wrapped-request-input"),
    case(PLUGIN + "a.php", NOTE + "eval($_POST['synthetic']);\n", "REQUEST_TO_CODE_EVAL", id="eval-of-request-input"),
    case(PLUGIN + "a.php", NOTE + "$expr = $_POST['expr']; eval($template);\n", id="eval-of-other-variable"),
    case(PLUGIN + "a.php", NOTE + "$calc->eval($_GET['formula']);\n", id="fp-method-eval-of-request-input"),
    # REQUEST_VARIABLE_FUNCTION_CALL
    case(*POSITIVE["REQUEST_VARIABLE_FUNCTION_CALL"][:2], "REQUEST_VARIABLE_FUNCTION_CALL", id="request-value-called"),
    case(PLUGIN + "a.php", NOTE + "$f = $_GET['f'];\n", id="request-value-read"),
    case(PLUGIN + "a.php", NOTE + "if (isset($_POST['a']) && (int) $_POST['b']) { $handlers[$_POST['action']]($arg); }\n",
         id="fp-dispatch-table"),
    # PHP_PREG_REPLACE_EVAL
    case(*POSITIVE["PHP_PREG_REPLACE_EVAL"][:2], "PHP_PREG_REPLACE_EVAL", id="preg-replace-e"),
    case(PLUGIN + "a.php", NOTE + "preg_replace('/\\s+/', ' ', $text);\n", id="preg-replace-plain"),
    case(PLUGIN + "a.php", NOTE + "preg_replace('/e/', 'E', $t); preg_replace('#</e>#i', '', $t); preg_replace_callback('/x/', $f, $t);\n",
         id="fp-letter-e-in-pattern"),
    # LONG_ENCODED_BLOB
    case(*POSITIVE["LONG_ENCODED_BLOB"][:2], "LONG_ENCODED_BLOB", id="base64-blob"),
    case(PLUGIN + "a.php", NOTE + "\\x41" * 64 + "\n", "LONG_ENCODED_BLOB", id="hex-escape-blob"),
    case(PLUGIN + "a.php", NOTE + f"'{BLOB[:-4]}'\n", id="blob-below-threshold"),
    case(PLUGIN + "a.php", NOTE + "\n// " + "\n// ".join([BLOB[:76]] * 120) + "\n", id="fp-wrapped-certificate"),
    case(PLUGIN + "icons.js", f"var icon = '{BLOB}';\n", id="fp-blob-in-script"),
    # REQUEST_INPUT_TO_INCLUDE
    case(*POSITIVE["REQUEST_INPUT_TO_INCLUDE"][:2], "REQUEST_INPUT_TO_INCLUDE", id="include-request-input"),
    case(PLUGIN + "a.php", NOTE + "require_once $_REQUEST['synthetic'];\n", "REQUEST_INPUT_TO_INCLUDE", id="require-once-request-input"),
    case(PLUGIN + "a.php", NOTE + "include 'header.php';\n", id="include-constant"),
    case(PLUGIN + "a.php", NOTE + "require_once ABSPATH . 'wp-admin/includes/file.php'; $page = sanitize_key($_GET['page']);\n",
         id="fp-include-next-to-sanitised-input"),
    # REQUEST_CONTROLLED_FILE_WRITE
    case(*POSITIVE["REQUEST_CONTROLLED_FILE_WRITE"][:2], "REQUEST_CONTROLLED_FILE_WRITE", id="write-to-request-path"),
    case(PLUGIN + "a.php", NOTE + "file_put_contents($path, $data);\n", id="write-to-fixed-path"),
    case(PLUGIN + "a.php", NOTE + "file_put_contents($css_file, wp_unslash($_POST['css']));\n", id="fp-save-custom-css"),
    # HTACCESS_ENABLES_PHP_IN_UPLOADS
    case(*POSITIVE["HTACCESS_ENABLES_PHP_IN_UPLOADS"][:2], "HTACCESS_ENABLES_PHP_IN_UPLOADS", id="addhandler-php"),
    case(UPLOADS + ".htaccess", "<FilesMatch \"synthetic\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n",
         "HTACCESS_ENABLES_PHP_IN_UPLOADS", id="sethandler-php"),
    case(UPLOADS + ".htaccess", "php_flag engine on\n", "HTACCESS_ENABLES_PHP_IN_UPLOADS", id="engine-on"),
    case(".htaccess", "AddHandler application/x-httpd-php81 .php\n", id="hosting-handler-in-site-root"),
    case(UPLOADS + ".htaccess", "php_flag engine off\nAddType text/plain .php .phtml\nRemoveHandler .php\n"
         "<Files *.php>\n  deny from all\n</Files>\n# AddHandler application/x-httpd-php .jpg\n", id="fp-htaccess-disables-php"),
    # PHP_AUTO_PREPEND_CONFIG
    case(*POSITIVE["PHP_AUTO_PREPEND_CONFIG"][:2], "PHP_AUTO_PREPEND_CONFIG", id="user-ini-prepend"),
    case("wp-admin/.htaccess", "php_value auto_append_file \"/srv/synthetic.php\"\n", "PHP_AUTO_PREPEND_CONFIG", id="htaccess-append"),
    case("php.ini", "auto_prepend_file=/srv/synthetic.php\n", "PHP_AUTO_PREPEND_CONFIG", id="php-ini-prepend"),
    case(".user.ini", "upload_max_filesize = 64M\n", id="user-ini-other-setting"),
    case(".htaccess", "php_value upload_max_filesize 64M\nphp_value auto_prepend_file none\n", id="fp-upload-limit-and-prepend-none"),
    case(".user.ini", "auto_prepend_file =\n; auto_prepend_file = /srv/synthetic.php\n", id="fp-empty-and-commented"),
    case("notes.txt", "auto_prepend_file = /srv/synthetic.php\n", id="directive-in-other-file"),
]


@pytest.mark.parametrize("rel, content, expected", CASES)
def test_rule_fires_only_for_its_indicator(site, analyze, rel, content, expected):
    write(site / rel, content)

    assert analyze(site).rules == expected


def test_every_rule_has_a_positive_case_and_a_documented_false_positive_note():
    covered = set().union(*(param.values[2] for param in CASES))
    documentation = (Path(__file__).parents[1] / "docs" / "RULES.md").read_text(encoding="utf-8")

    assert covered | {"EXECUTABLE_IN_UPLOADS"} == set(filerules.RULES)
    for rule in filerules.RULES.values():
        assert f"`{rule.id}`" in documentation
        assert rule.false_positives and ("heurysty" in rule.explanation or "wymaga" in rule.explanation)
        models.Finding(rule.id, "file", rule.severity, rule.confidence, rule.explanation, ("obs-synthetic",))  # poprawne wartości
        assert rule.find is None or models.Confidence.HIGH not in (rule.confidence, rule.known_code_confidence)


@pytest.mark.parametrize("rule", sorted(POSITIVE))
def test_content_finding_points_to_the_byte_offset_of_the_first_match(site, analyze, rule):
    rel, content, needle = POSITIVE[rule]
    data = ("<?php // zażółć gęślą jaźń\n" if rel.endswith(".php") else "# zażółć gęślą jaźń\n").encode() + content.encode() * 2
    write(site / rel, data)

    facts = analyze(site).finding(rule)["metadata"]

    assert facts["offset"] == data.index(needle.encode())
    assert data[facts["offset"]:facts["offset"] + facts["length"]].startswith(needle.encode())
    assert (facts["match_count"], facts["rule_version"]) == (2, filerules.RULES[rule].version)


def test_many_matches_in_one_file_give_one_finding_per_rule(site, analyze):
    write(site / PLUGIN / "a.php", EVAL_MARKER * 500)

    run = analyze(site)

    assert run.finding("SUSPICIOUS_PHP_EVAL_DECODE")["metadata"]["match_count"] == 500
    assert len(run.findings) == 1


@pytest.mark.parametrize("rule", sorted(name for name, rule in filerules.RULES.items() if rule.known_code_confidence))
@pytest.mark.parametrize("folder, confidence", [(PLUGIN, "low"), ("wp-content/themes/demo/", "low"), ("wp-includes/", "low"),
                                                ("wp-content/mu-plugins/", "medium"), ("vendor/", "medium")])
def test_weak_heuristic_is_less_confident_where_code_is_expected(site, analyze, rule, folder, confidence):
    write(site / folder / "a.php", POSITIVE[rule][1])

    finding = analyze(site).finding(rule)

    assert (finding["severity"], finding["confidence"]) == (filerules.RULES[rule].severity, confidence)


def test_code_in_static_core_directory_is_more_confident_than_in_languages(site, analyze):
    write(site / "wp-admin" / "css" / "x.php")
    write(site / "wp-content" / "languages" / "pl_PL.php")

    assert {item["source"]: item["confidence"] for item in analyze(site).findings} == {
        "wp-admin/css/x.php": "medium", "wp-content/languages/pl_PL.php": "low"}


def test_content_rules_never_make_a_strong_indicator_on_their_own(site, analyze):
    for number, (_, content, _) in enumerate(POSITIVE.values()):
        write(site / "wp-content" / "mu-plugins" / f"a{number}.php", content)

    run = analyze(site)

    assert len(run.findings) >= 8
    assert run.report["assessment"] == "SUSPICIOUS"


def test_matched_content_never_reaches_the_report(site, analyze):
    write(site / PLUGIN / "a.php", NOTE + f"eval(base64_decode('{CANARY}')); $_POST['{CANARY}']('x'); system($_GET['{CANARY}']);\n")
    write(site / UPLOADS / ".htaccess", f"AddHandler application/x-httpd-php-{CANARY} .jpg\nphp_value auto_prepend_file /srv/{CANARY}.php\n")
    write(site / ".user.ini", f"auto_append_file = /srv/{CANARY}.php\n")

    run = analyze(site)

    assert run.rules == {"SUSPICIOUS_PHP_EVAL_DECODE", "REQUEST_VARIABLE_FUNCTION_CALL", "REQUEST_TO_COMMAND_EXEC",
                         "HTACCESS_ENABLES_PHP_IN_UPLOADS", "PHP_AUTO_PREPEND_CONFIG"}
    assert CANARY not in run.everything


@pytest.mark.parametrize("rel, rule", [(UPLOADS + "photo.php.jpg", "DOUBLE_EXTENSION_IN_UPLOADS"),
                                       ("wp-content/languages/helper.php", "CODE_IN_UNEXPECTED_LOCATION")])
def test_path_rules_report_a_file_that_was_not_read(site, tmp_path, analyze, rel, rule):
    (site / rel).parent.mkdir(parents=True)
    os.link(write(tmp_path / "outside.bin", EVAL_MARKER), site / rel)

    finding = analyze(site).finding(rule)

    assert finding["metadata"] == {"read_status": "SKIPPED_HARDLINK"}


@pytest.mark.parametrize("rel, rules", [(UPLOADS + "photo.php.jpg", {"DOUBLE_EXTENSION_IN_UPLOADS"}), (".user.ini", set())])
def test_oversized_file_covered_by_content_rules_leaves_a_coverage_gap(site, analyze, rel, rules):
    sparse(site / rel, cli.MAX_SCAN_BYTES + 1, "auto_prepend_file = /srv/synthetic.php\n" + EVAL_MARKER)

    run = analyze(site)

    assert run.rules == rules
    assert run.has_gap(f"Analiza treści pominięta, plik > {cli.MAX_SCAN_BYTES} B: {rel}")
    assert run.coverage("files")["status"] == "PARTIAL"


def test_code_hidden_behind_a_double_extension_is_content_scanned(site, analyze):
    write(site / UPLOADS / "photo.php.jpg", EVAL_MARKER)

    assert analyze(site).rules == {"DOUBLE_EXTENSION_IN_UPLOADS", "SUSPICIOUS_PHP_EVAL_DECODE"}


# --- odporność: czas dopasowania rośnie liniowo także na wrogiej treści --------------------------

HOSTILE = [
    b"eval(" + b" " * 16,
    b"eval(aaaaaaaa(aaaaaaaa(aaaaaaaa(",
    b"create_function('' , ",
    b"$_get[" + b"]" * 120,
    b"$_get[ system( $_post[ exec(",
    b"$_get['" + b"a" * 64,
    b"preg_replace('/" + b"a/" * 60,
    b"a" * (filerules.BLOB_MIN_BYTES - 1) + b" ",
    b"\\x41" * 63 + b" ",
    b"include" + b"(" * 8,
    b"file_put_contents(" + b" " * 16,
    b"\n" + b" " * 32 + b"addhandler " + b"p" * 80,
    b"\n" + b"\t" * 32 + b"php_value auto_prepend_file" + b" " * 8 + b"=" + b" " * 8 + b"'",
]


@pytest.mark.parametrize("rel", [UPLOADS + "a.php", UPLOADS + ".htaccess"])
@pytest.mark.parametrize("chunk", HOSTILE, ids=range(len(HOSTILE)))
def test_s08_hostile_content_does_not_stall_the_file_rules(rel, chunk):
    content = chunk * (1024**2 // len(chunk))
    item = ingest.Evidence("files", rel, ingest.ReadStatus.READ, sha256="0" * 64, size=len(content), content=content)

    with time_limit(5):
        found = filerules.content_rules(item)

    assert len(found) <= len(filerules.RULES)
