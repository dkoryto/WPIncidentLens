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
