import json
from pathlib import Path
from wpincidentlens.cli import main, iter_insert_rows, compose_report

FIX = Path(__file__).parents[1] / "fixtures"

def test_sql_rows_and_prefix():
    x=list(iter_insert_rows("INSERT INTO `abc_users` VALUES (7,'x'),(8,'y');"))
    assert x == [("abc_users", [], ["7", "x"]), ("abc_users", [], ["8", "y"])]

def test_poc_end_to_end(tmp_path):
    out=tmp_path/'out'
    code=main(["--files",str(FIX/'site'),"--database",str(FIX/'database.sql'),"--logs",str(FIX/'logs'),"--baseline",str(FIX/'baseline.json'),"--output",str(out),"--case-id","TEST-01"])
    assert code==3  # plik PHP w uploads nie ma zaufanej referencji: zakres niepełny (ADR 0005, pkt 6)
    data=json.loads((out/'report.json').read_text())
    rules={x['rule_id'] for x in data['findings']}
    assert {'EXECUTABLE_IN_UPLOADS','SUSPICIOUS_PHP_EVAL_DECODE','NEW_SINCE_BASELINE',  # lista adminów pochodzi z baseline
            'SUSPICIOUS_DB_MARKUP','HTTP_EXECUTABLE_IN_UPLOADS','CORRELATED_UPLOAD_REQUEST'} <= rules
    assert data['assessment']=='SUSPICIOUS'
    assert len(data['evidence'])>=5
    assert any(x['event']=='HTTP_EXECUTABLE_IN_UPLOADS' and x['time_utc'].startswith('2026-11-09T01:14') for x in data['timeline'])
    assert 'WPIncidentLens' in (out/'report.html').read_text()

def test_no_indicators_not_a_clean_bill(tmp_path):
    root=tmp_path/'wp';root.mkdir();(root/'index.php').write_text('<?php echo 1;')
    data=compose_report(root,None,None,None,set(),'TEST')
    assert data['assessment']=='INCONCLUSIVE'
    assert len(data['coverage_gaps'])>=2

def test_symlinks_never_followed(tmp_path):
    site=tmp_path/'site';site.mkdir()
    secret=tmp_path/'secret.php';secret.write_text('<?php eval(base64_decode("x")); ?>')
    (site/'link.php').symlink_to(secret)
    data=compose_report(site,None,None,None,set(),'TEST')
    assert not any(x['rule_id']=='SUSPICIOUS_PHP_EVAL_DECODE' for x in data['findings'])
    assert any('symboliczne' in x for x in data['coverage_gaps'])


def test_output_cannot_be_inside_evidence(tmp_path):
    import pytest
    root=tmp_path/'site';root.mkdir()
    with pytest.raises(SystemExit):
        main(['--files',str(root),'--output',str(root/'report')])

def test_report_escapes_html(tmp_path):
    from wpincidentlens.cli import write_html
    destination=tmp_path/'r.html'
    write_html({'case_id':'<img src=x onerror=alert(1)>','analyzed_at_utc':'2026-01-01',
      'assessment':'SUSPICIOUS','disclaimer':'x','findings':[], 'coverage_gaps':[], 'timeline':[]},destination)
    doc=destination.read_text()
    assert '&lt;img' in doc
    assert '<img src=x' not in doc


def test_help_names_unverified_code_as_the_usual_cause_of_exit_code_3(capsys):
    import pytest
    with pytest.raises(SystemExit) as stopped:
        main(["--help"])
    text = " ".join(capsys.readouterr().out.split())  # argparse łamie epilog na wiersze
    assert stopped.value.code == 0
    assert "3 — zakres niepełny: najczęściej plik kodu niezweryfikowany względem zaufanej referencji" in text
    assert "brak --database lub --logs" in text and "4 — podane źródło nieprzetworzone" in text


# --- podkomendy (R-90, ADR 0011) ----------------------------------------------------------------------------

import subprocess  # noqa: E402
import sys  # noqa: E402
import tomllib  # noqa: E402

import pytest  # noqa: E402

from wpincidentlens import __version__, cli, rules  # noqa: E402

ROOT = Path(__file__).parents[1]


def _without_time(out):
    data = json.loads((out / "report.json").read_text())
    return {key: value for key, value in data.items() if key != "analyzed_at_utc"}


def test_analyze_subcommand_is_the_flat_form(tmp_path):
    argv = ["--files", str(FIX / "site"), "--database", str(FIX / "database.sql"), "--case-id", "T701-SYNTH"]

    flat = main([*argv, "--output", str(tmp_path / "flat")])
    named = main(["analyze", *argv, "--output", str(tmp_path / "named")])

    assert flat == named == 3
    assert _without_time(tmp_path / "flat") == _without_time(tmp_path / "named")


def test_python_dash_m_with_flat_arguments_still_works(tmp_path):
    out = tmp_path / "out"
    done = subprocess.run([sys.executable, "-m", "wpincidentlens", "--files", str(FIX / "site"), "--output", str(out), "--case-id", "T701-SYNTH"],
                          cwd=ROOT, capture_output=True, text=True, timeout=120, env={"PYTHONPATH": str(ROOT)})

    assert done.returncode == 3, done.stderr
    assert json.loads(done.stdout)["exit_code"] == 3
    assert json.loads((out / "report.json").read_text())["tool_version"] == __version__


def test_python_dash_m_runs_subcommands(tmp_path):
    done = subprocess.run([sys.executable, "-m", "wpincidentlens", "version", "--json"], cwd=ROOT, capture_output=True, text=True,
                          timeout=60, env={"PYTHONPATH": str(ROOT)})

    assert done.returncode == 0 and json.loads(done.stdout)["tool_version"] == __version__


def test_version_lists_tool_schemas_ruleset_and_python(capsys):
    assert main(["version", "--json"]) == 0
    info = json.loads(capsys.readouterr().out)

    assert info == {"tool": "WPIncidentLens PoC", "tool_version": __version__, "report_schema": "poc-1", "case_schema": "case-poc-1",
                    "ruleset": rules.descriptor(), "python": sys.version.split()[0]}
    assert main(["version"]) == 0
    text = capsys.readouterr().out
    assert __version__ in text and rules.descriptor()["sha256"] in text and "case-poc-1" in text


def test_version_rejects_unknown_arguments():
    with pytest.raises(SystemExit) as stop:
        main(["version", "--yaml"])
    assert stop.value.code == 2


def test_tool_version_is_a_pep440_release_candidate_shared_with_the_package_metadata():
    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]

    assert declared == __version__ == cli.VERSION == "0.2.0rc1"


@pytest.mark.parametrize("argv, prog", [(["--help"], "usage: wpincidentlens [-h]"), (["analyze", "--help"], "usage: wpincidentlens analyze")])
def test_help_names_the_subcommands_and_the_force_flag(capsys, argv, prog):
    with pytest.raises(SystemExit) as stopped:
        main(argv)
    text = " ".join(capsys.readouterr().out.split())

    assert stopped.value.code == 0 and text.startswith(prog)
    assert "report verify KATALOG" in text and "version" in text and "--force" in text and "5 — błąd narzędzia" in text
