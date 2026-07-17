"""Report quality — structure & correctness across all six formats (§18.2)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8ssec.agents.orchestrator import Orchestrator
from k8ssec.bootstrap import build_platform
from k8ssec.core.models import ScanRequest, Scope, ScopeLevel, Selector


def _result():
    p = build_platform()
    o = Orchestrator(p)
    req = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector())
    return p, o.run(req, p.make_collector(mock=True))


def test_all_formats_render_nonempty():
    p, res = _result()
    for fmt in ("terminal", "text", "markdown", "json", "sarif", "html"):
        out = p.reporting.render(res, fmt)
        assert isinstance(out, str) and len(out) > 500, fmt


def test_markdown_has_rich_structure():
    p, res = _result()
    md = p.reporting.render(res, "markdown")
    for marker in ("---", "# 🛡️ K8s Security Report", "## 1. 📊 Executive Summary",
                   "## 2. 🎯 Coverage & Exposure", "OWASP Kubernetes Top 10",
                   "## 3. 🚨 Findings", "## 4. 🛠️ Prioritized Remediation Plan",
                   "## 5. 📎 Appendix", "```bash"):
        assert marker in md, f"missing section: {marker!r}"


def test_markdown_embeds_real_fix_commands():
    p, res = _result()
    md = p.reporting.render(res, "markdown")
    # a concrete, resource-formatted kubectl command must appear in a fenced block
    assert "kubectl delete clusterrolebinding default-admin" in md


def test_markdown_tables_have_balanced_backticks():
    # broken table cells (inner backticks / newlines) would corrupt rendering
    p, res = _result()
    md = p.reporting.render(res, "markdown")
    for ln in md.splitlines():
        if ln.startswith("| "):
            assert ln.count("`") % 2 == 0, f"unbalanced backticks: {ln[:80]}"


def test_json_has_summary_and_remediation():
    p, res = _result()
    doc = json.loads(p.reporting.render(res, "json"))
    assert "summary" in doc
    assert set(doc["summary"]) >= {"rating", "risk_score", "security_score",
                                   "severity_percent", "owasp", "attack_path_amplified"}
    assert all("remediation" in f for f in doc["findings"])


def test_sarif_is_valid_and_enriched():
    p, res = _result()
    doc = json.loads(p.reporting.render(res, "sarif"))
    assert doc["version"] == "2.1.0"
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert rules, "no SARIF rules emitted"
    r0 = rules[0]
    assert "security-severity" in r0["properties"]
    assert any(t.startswith("mitre/") for t in r0["properties"]["tags"])
    for res_item in doc["runs"][0]["results"]:
        assert "partialFingerprints" in res_item


def test_html_is_self_contained_and_filterable():
    p, res = _result()
    html = p.reporting.render(res, "html")
    assert html.startswith("<!doctype html>")
    low = html.lower()
    assert "card" in low and html.count("card") >= 5   # multiple finding cards
    assert "data-f=" in html                            # interactive severity filters
    assert "gauge" in low                               # risk gauge
    # self-contained: no external stylesheets/scripts/fonts (URLs inside finding text are OK)
    assert "<script src" not in low
    assert "<link" not in low
    assert "url(http" not in low
