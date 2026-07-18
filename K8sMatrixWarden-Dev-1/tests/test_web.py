"""Web dashboard routing (socket-free) — WebApp.route covers every surface (§3.1, §19)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.web.app import WebApp


def _app():
    return WebApp(build_platform(), reports_dir=tempfile.mkdtemp())


def _scan(app, body=None):
    r = app.route("POST", "/api/scan", body=json.dumps(body or {"mock": True}).encode())
    return r, json.loads(r.text)


def test_health_reports_platform_stats():
    r = _app().route("GET", "/health")
    assert r.status == 200
    d = json.loads(r.text)
    assert d["status"] == "ok" and d["rules"] > 0 and d["shards"] == 10


def test_dashboard_is_spa_shell_and_api_reflects_scans():
    # The dashboard is now a client-side app; the shell always serves 200 and the data
    # comes from /api/dashboard. Assert the data contract, not scraped HTML.
    app = _app()
    assert app.route("GET", "/").status == 200
    empty = json.loads(app.route("GET", "/api/dashboard").text)
    assert empty["has_scan"] is False
    _, d = _scan(app)
    data = json.loads(app.route("GET", "/api/dashboard").text)
    assert data["has_scan"] is True
    assert data["scan"]["scan_id"] == d["scan_id"]
    assert "threat_matrix" in data and "attack_path" in data and "runtime" in data
    assert len(data["findings"]) > 0


def test_runtime_endpoint_correlates_and_detects_drift():
    app = _app()
    _scan(app)
    events = [{"source": "audit", "verb": "create",
               "resource": "clusterrolebindings", "namespace": "production"}]
    r = app.route("POST", "/api/runtime",
                  body=json.dumps({"events": events}).encode())
    assert r.status == 200
    out = json.loads(r.text)
    assert "correlation" in out and "drift" in out
    assert out["correlation"]["total_alerts"] >= 1


def test_scan_runs_saves_and_is_downloadable():
    app = _app()
    r, d = _scan(app)
    assert r.status == 200
    assert d["scan_id"] and d["total_findings"] > 0 and d["rating"]
    # report HTML carries the matrix heatmap
    rep = app.route("GET", f"/report/{d['scan_id']}")
    assert rep.status == 200 and "tmgrid" in rep.text
    # API JSON carries the threat_matrix block
    api = app.route("GET", f"/api/report/{d['scan_id']}", query="format=json")
    assert api.status == 200 and "threat_matrix" in api.text


def test_scan_by_free_text_selector():
    app = _app()
    _, d = _scan(app, {"scope_level": "cluster", "selector": "Persistence", "mock": True})
    assert d["total_findings"] > 0
    # the scan's matrix must implicate Persistence (multi-tactic findings may add others)
    m = json.loads(app.route("GET", f"/api/report/{d['scan_id']}/matrix").text)
    persistence = next(c for c in m["columns"] if c["tactic"] == "Persistence")
    assert persistence["techniques_hit"] > 0


def test_scan_forwards_context_and_kubeconfig_to_collector():
    # The Scan tab's live cluster selection (context + kubeconfig) must reach the
    # collector. Spy on make_collector: record what the route requested, but hand back a
    # working mock collector so the scan still runs without the kubernetes package.
    app = _app()
    captured = {}
    orig = app.p.make_collector

    def spy(**kwargs):
        captured.update(kwargs)
        return orig(mock=True, fixture=None)

    app.p.make_collector = spy
    r, d = _scan(app, {"scope_level": "cluster", "mock": False,
                       "context": "kind-kind", "kubeconfig": "/tmp/kc"})
    assert r.status == 200 and d["scan_id"]
    assert captured.get("mock") is False
    assert captured.get("context") == "kind-kind"
    assert captured.get("kubeconfig") == "/tmp/kc"


def test_coverage_matrix_route():
    r = _app().route("GET", "/matrix")
    assert r.status == 200 and "tmgrid" in r.text and "Threat Matrix" in r.text


def test_report_matrix_page():
    app = _app()
    _, d = _scan(app)
    r = app.route("GET", f"/report/{d['scan_id']}/matrix")
    assert r.status == 200 and "tmgrid" in r.text and d["scan_id"] in r.text


def test_api_reports_lists_saved():
    app = _app()
    _, d = _scan(app)
    rows = json.loads(app.route("GET", "/api/reports").text)
    assert any(row["scan_id"] == d["scan_id"] for row in rows)


def test_missing_report_returns_404():
    app = _app()
    assert app.route("GET", "/report/nope").status == 404
    assert app.route("GET", "/api/report/nope", query="format=json").status == 404


def test_unknown_route_is_404_not_500():
    app = _app()
    assert app.route("GET", "/totally/unknown").status == 404


def test_bad_format_is_rejected():
    app = _app()
    _, d = _scan(app)
    r = app.route("GET", f"/api/report/{d['scan_id']}", query="format=exe")
    assert r.status == 400 and "unknown format" in r.text


def test_scan_can_be_disabled():
    app = WebApp(build_platform(), reports_dir=tempfile.mkdtemp(), allow_scan=False)
    r = app.route("POST", "/api/scan", body=b"{}")
    assert r.status == 403


def test_invalid_json_body_is_400_not_crash():
    app = _app()
    r = app.route("POST", "/api/scan", body=b"{not json")
    assert r.status == 400 and "error" in r.text


def test_path_traversal_scan_id_is_rejected():
    # a report route param must never escape the store dir (defence in depth even though
    # the server binds localhost by default).
    app = _app()
    for evil in ("../../../../etc/passwd", "..%2f..%2fsecret", "foo/bar"):
        r = app.route("GET", f"/report/{evil}")
        assert r.status == 404
        j = app.route("GET", f"/api/report/{evil}", query="format=json")
        assert j.status == 404
