"""Report store: persist → list → download in any format (§16.4)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8ssec.agents.orchestrator import Orchestrator
from k8ssec.bootstrap import build_platform
from k8ssec.core.models import ScanRequest, Scope, ScopeLevel, Selector
from k8ssec.core.report_store import ReportStore
from k8ssec.core.results import ScanResult


def _scan():
    p = build_platform()
    o = Orchestrator(p)
    req = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector())
    return p, o.run(req, p.make_collector(mock=True))


def test_result_roundtrips_through_dict():
    _p, res = _scan()
    clone = ScanResult.from_dict(res.as_dict())
    assert clone.scan_id == res.scan_id
    assert len(clone.findings) == len(res.findings)
    assert clone.risk.cluster_risk == res.risk.cluster_risk
    assert clone.risk.rating_emoji                     # reconstructed
    # a reconstructed finding keeps its tags + score
    f0, c0 = res.findings[0], clone.findings[0]
    assert c0.rule_id == f0.rule_id
    assert c0.severity == f0.severity
    assert [m.technique_id for m in c0.mitre] == [m.technique_id for m in f0.mitre]
    assert round(c0.score, 3) == round(f0.score, 3)


def test_save_list_load():
    p, res = _scan()
    with tempfile.TemporaryDirectory() as d:
        store = ReportStore(d)
        store.save(res)
        listed = store.list()
        assert len(listed) == 1
        assert listed[0].scan_id == res.scan_id
        assert listed[0].total == res.total()
        loaded = store.load(res.scan_id)
        assert loaded.scan_id == res.scan_id
        assert store.load_latest().scan_id == res.scan_id
        assert store.resolve("latest").scan_id == res.scan_id


def test_stored_report_renders_all_formats():
    p, res = _scan()
    with tempfile.TemporaryDirectory() as d:
        store = ReportStore(d)
        store.save(res)
        loaded = store.load_latest()
        for fmt in ("markdown", "json", "sarif", "html", "text"):
            out = p.reporting.render(loaded, fmt)
            assert isinstance(out, str) and len(out) > 500, fmt
        # embedded fix command survives the round-trip
        md = p.reporting.render(loaded, "markdown")
        assert "kubectl delete clusterrolebinding default-admin" in md


def test_list_empty_dir():
    with tempfile.TemporaryDirectory() as d:
        assert ReportStore(d).list() == []
        assert ReportStore(d).load_latest() is None
