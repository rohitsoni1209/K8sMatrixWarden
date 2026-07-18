"""
WebApp — the dashboard's routing + logic, deliberately socket-free so it is unit-testable.

`WebApp.route(method, path, query, body)` returns a `Response`; `server.py` is a thin
`http.server` shell that just calls it. Every HTML surface reuses the same ReportingEngine,
ReportStore, and threat-matrix builder the CLI/MCP use — the dashboard is a *view* over the
one engine, it never re-implements scanning or reporting.

Read-mostly by design: the only state-changing route is `POST /api/scan`, which runs a
read-only scan and saves the result. Remediation/apply is NOT exposed here for the same
reason it is withheld from MCP (§9.1 — every fix needs interactive confirmation).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs

from ..core.models import (ScanMode, ScanRequest, Scope, ScopeLevel, Selector, Severity)
from ..core.report_store import ReportStore
from ..core.results import ScanResult
from ..core.threat_matrix import build_threat_matrix
from . import pages

_VALID_FORMATS = {"json", "markdown", "md", "sarif", "html", "text", "terminal"}


@dataclass
class Response:
    status: int = 200
    content_type: str = "text/html; charset=utf-8"
    body: bytes = b""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def _html(body: str, status: int = 200) -> Response:
    return Response(status, "text/html; charset=utf-8", body.encode("utf-8"))


def _json(obj, status: int = 200) -> Response:
    return Response(status, "application/json; charset=utf-8",
                    json.dumps(obj, indent=2, default=str).encode("utf-8"))


def _text(s: str, status: int = 200) -> Response:
    return Response(status, "text/plain; charset=utf-8", s.encode("utf-8"))


class WebApp:
    def __init__(self, platform, reports_dir: str = "k8smatrixwarden-reports",
                 allow_scan: bool = True):
        self.p = platform
        self.reports_dir = reports_dir
        self.allow_scan = allow_scan

    @property
    def store(self) -> ReportStore:
        return ReportStore(self.reports_dir)

    # ------------------------------------------------------------------ #
    # Router
    # ------------------------------------------------------------------ #
    def route(self, method: str, path: str, query: str = "",
              body: bytes = b"") -> Response:
        method = method.upper()
        path = "/" + path.strip("/") if path != "/" else "/"
        q = {k: v[0] for k, v in parse_qs(query or "").items()}
        parts = [p for p in path.split("/") if p]

        try:
            if method == "GET" and path == "/":
                return self._dashboard()
            if method == "GET" and path == "/health":
                return _json({"status": "ok", "rules": self.p.rule_count(),
                              "shards": len(self.p.registry.shard_names())})
            if method == "GET" and path == "/matrix":
                return self._coverage_matrix()
            if method == "GET" and path == "/api/reports":
                return self._api_reports(q)
            if method == "GET" and path == "/api/dashboard":
                return _json(self._dashboard_data())
            if method == "GET" and path == "/api/timeline":
                return _json(self.store.timeline())
            if method == "POST" and path == "/api/scan":
                return self._api_scan(body)
            if method == "POST" and path == "/api/runtime":
                return self._api_runtime(body)
            # /report/<id>  and  /report/<id>/matrix
            if method == "GET" and len(parts) >= 2 and parts[0] == "report":
                if len(parts) == 2:
                    return self._report_html(parts[1])
                if len(parts) == 3 and parts[2] == "matrix":
                    return self._report_matrix_html(parts[1])
            # /api/report/<id>  and  /api/report/<id>/matrix
            if method == "GET" and len(parts) >= 3 and parts[:2] == ["api", "report"]:
                if len(parts) == 3:
                    return self._api_report(parts[2], q)
                if len(parts) == 4 and parts[3] == "matrix":
                    return self._api_report_matrix(parts[2])
        except _NotFound as exc:
            return self._not_found(str(exc), q)
        except Exception as exc:  # never leak a stack trace to the browser
            if _wants_json(path, q):
                return _json({"error": str(exc)}, 500)
            return _html(pages.error_page(500, f"Internal error: {exc}"), 500)

        return self._not_found(f"no route for {method} {path}", q)

    # ------------------------------------------------------------------ #
    # HTML pages
    # ------------------------------------------------------------------ #
    def _dashboard(self) -> Response:
        # The dashboard is now a client-side app that fetches /api/dashboard — this
        # just serves the shell. All rendering (KPIs, findings table, matrix heatmap,
        # attack path, runtime) happens in the browser from that one JSON payload.
        return _html(pages.dashboard_page(has_scan=bool(self.store.list())))

    def _dashboard_data(self) -> dict:
        """Everything the dashboard needs, in one payload: latest scan + findings +
        threat matrix + attack path + runtime readiness + risk trend + history."""
        reports = self.store.list()
        if not reports:
            return {"has_scan": False, "history": []}
        latest = self._load(reports[0].scan_id)
        matrix = build_threat_matrix(latest, self.p.registry.rules)
        from ..core.threat_matrix import attack_paths
        from ..agents.runtime import RuntimeAgent

        catalog = RuntimeAgent().catalog()
        runtime_by_tactic: dict[str, list] = {}
        for r in catalog:
            runtime_by_tactic.setdefault(r["tactic"], []).append(r["title"])
        exposed = [c.tactic for c in matrix.columns if c.hit_count]

        return {
            "has_scan": True,
            "scan": {"scan_id": latest.scan_id, "generated_at": latest.generated_at,
                     "mode": latest.mode, "scope": latest.request.scope.describe(),
                     "rating": latest.risk.rating,
                     "cluster_risk": latest.risk.cluster_risk,
                     "security_score": latest.risk.security_score,
                     "counts": latest.counts, "total": latest.total()},
            "findings": [f.as_dict() for f in latest.findings],
            "threat_matrix": matrix.as_dict(),
            "attack_path": attack_paths(matrix),
            "runtime": {"armed": len(catalog), "by_tactic": runtime_by_tactic,
                        "exposed_tactics": exposed},
            "trend": [[r.generated_at, r.risk_score] for r in reversed(reports)],
            "timeline": self.store.timeline(),
            "history": [{"scan_id": r.scan_id, "generated_at": r.generated_at,
                         "rating": r.rating, "risk_score": r.risk_score,
                         "total": r.total, "scope": r.scope} for r in reports],
        }

    def _api_runtime(self, body: bytes) -> Response:
        """Ingest a batch of runtime events (Falco/audit JSON) and return both the
        scan-correlation and the config-drift analysis against the latest saved scan.
        Point falcosidekick (or `falco -o json_output`) at this endpoint, or POST a
        batch by hand. Body: {"events": [...], "scan_id"?: "...", "namespace"?: "..."}."""
        try:
            data = json.loads(body or b"{}")
        except Exception as exc:
            return _json({"error": f"invalid JSON body: {exc}"}, 400)
        from ..agents.runtime import RuntimeAgent, normalize_events
        from ..core.correlation import correlate, detect_drift

        # Body can be {"events":[...], "scan_id"?} (our batch), OR a bare Falco event
        # posted by falcosidekick (one event per request). Normalize either into the
        # flat internal shape the matchers use.
        scan_id = data.get("scan_id") if isinstance(data, dict) else None
        raw = data.get("events") if (isinstance(data, dict) and "events" in data) else data
        events = normalize_events(raw)
        result = self.store.resolve(scan_id)
        if result is None:
            return _json({"error": "no saved scan to correlate against — scan first"}, 400)
        alerts = RuntimeAgent().evaluate_stream(events)
        # drift needs live pod specs; reuse the scan's mode (mock/live) via a fresh fetch
        mock = result.mode != "live"
        try:
            collector = self.p.make_collector(mock=mock)
            pods = collector.collect({"Pod"}, Scope(ScopeLevel.CLUSTER)).get("Pod")
        except RuntimeError:
            pods = []
        return _json({"correlation": correlate(result.findings, alerts),
                      "drift": detect_drift(pods, events)})

    def _report_html(self, scan_id: str) -> Response:
        result = self._load(scan_id)
        return _html(self.p.reporting.render(result, "html"))

    def _report_matrix_html(self, scan_id: str) -> Response:
        result = self._load(scan_id)
        tm = build_threat_matrix(result, self.p.registry.rules)
        return _html(pages.matrix_page(tm, result=result))

    def _coverage_matrix(self) -> Response:
        """The global 'what can the tool detect' matrix — every registered rule's coverage,
        no findings. Distinct from a scan matrix, which overlays this scan's hits."""
        empty = _empty_result(self.p)
        tm = build_threat_matrix(empty, self.p.registry.rules)
        note = (f"Detection coverage across all {self.p.rule_count()} rules "
                f"(no scan overlaid)")
        return _html(pages.matrix_page(tm, result=None, title_note=note))

    # ------------------------------------------------------------------ #
    # JSON API
    # ------------------------------------------------------------------ #
    def _api_reports(self, q: dict) -> Response:
        limit = _int(q.get("limit"))
        return _json([{"scan_id": r.scan_id, "generated_at": r.generated_at,
                       "rating": r.rating, "risk_score": r.risk_score,
                       "total_findings": r.total, "scope": r.scope}
                      for r in self.store.list(limit=limit)])

    def _api_report(self, scan_id: str, q: dict) -> Response:
        result = self._load(scan_id)
        fmt = (q.get("format") or "json").lower()
        if fmt not in _VALID_FORMATS:
            return _json({"error": f"unknown format {fmt!r} — valid: "
                          f"{', '.join(sorted(_VALID_FORMATS))}"}, 400)
        content = self.p.reporting.render(result, fmt)
        if fmt == "json":
            return Response(200, "application/json; charset=utf-8",
                            content.encode("utf-8"))
        if fmt == "html":
            return _html(content)
        return _text(content)

    def _api_report_matrix(self, scan_id: str) -> Response:
        result = self._load(scan_id)
        return _json(build_threat_matrix(result, self.p.registry.rules).as_dict())

    def _api_scan(self, body: bytes) -> Response:
        if not self.allow_scan:
            return _json({"error": "scanning is disabled on this server "
                          "(started with --no-scan)"}, 403)
        try:
            data = json.loads(body or b"{}")
        except Exception as exc:
            return _json({"error": f"invalid JSON body: {exc}"}, 400)

        scope = self._scope_from(data)
        selector = self._selector_from(data)
        mock = bool(data.get("mock", True))
        try:
            collector = self.p.make_collector(
                mock=mock, fixture=data.get("fixture"),
                kubeconfig=data.get("kubeconfig"), context=data.get("context"))
        except RuntimeError as exc:
            return _json({"error": str(exc)}, 400)

        from ..agents.scanner import ScannerAgent
        request = ScanRequest(scope=scope, selector=selector, mode=ScanMode.SYNC)
        try:
            result = ScannerAgent(self.p).scan(
                request, collector, mode_label="mock" if mock else "live")
        except Exception as exc:
            return _json({"error": f"scan failed: {exc}"}, 400)

        self.store.save(result)
        return _json({"scan_id": result.scan_id, "rating": result.risk.rating,
                      "risk": result.risk.cluster_risk,
                      "security_score": result.risk.security_score,
                      "total_findings": result.total(),
                      "scope": result.request.scope.describe(),
                      "report_url": f"/report/{result.scan_id}",
                      "matrix_url": f"/report/{result.scan_id}/matrix"})

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def _scope_from(self, data: dict) -> Scope:
        key = str(data.get("scope_level") or "cluster").lower().replace("-", "_")
        try:
            level = ScopeLevel(key)
        except ValueError:
            level = ScopeLevel.CLUSTER
        return Scope(level=level, namespace=data.get("namespace"),
                     name=data.get("name"), kind=data.get("kind"),
                     image=data.get("image"))

    def _selector_from(self, data: dict) -> Selector:
        """Accept either a structured selector or a single free-text `selector` string
        (parsed with the same Orchestrator logic the CLI/chat use)."""
        text = data.get("selector")
        if isinstance(text, str) and text.strip():
            from ..agents.orchestrator import Orchestrator
            interp = Orchestrator(self.p).interpret(f"scan for {text.strip()}")
            return interp.request.selector
        sev = data.get("severity_min")
        return Selector(
            tactics=list(data.get("tactics", []) or []),
            techniques=list(data.get("techniques", []) or []),
            modules=list(data.get("modules", []) or []),
            rule_ids=list(data.get("rule_ids", []) or []),
            aliases=list(data.get("aliases", []) or []),
            frameworks=list(data.get("frameworks", []) or []),
            severity_min=Severity.parse(sev) if sev else None)

    def _load(self, scan_id: str) -> ScanResult:
        try:
            result = self.store.resolve(scan_id)
        except FileNotFoundError:
            raise _NotFound(f"no stored report with scan-id {scan_id!r}")
        if result is None:
            raise _NotFound("no stored reports yet — run a scan first")
        return result

    def _not_found(self, message: str, q: dict) -> Response:
        return _json({"error": message}, 404) if q.get("format") \
            else _html(pages.error_page(404, message), 404)


class _NotFound(Exception):
    pass


def _wants_json(path: str, q: dict) -> bool:
    return path.startswith("/api/") or (q.get("format") == "json")


def _aggregate(reports: list) -> dict:
    order = {"Critical": 5, "Poor": 4, "Fair": 3, "Good": 2, "Excellent": 1}
    worst = "—"
    worst_rank = 0
    for r in reports:
        rk = order.get(r.rating, 0)
        if rk > worst_rank:
            worst_rank, worst = rk, r.rating
    return {
        "total_reports": len(reports),
        "total_findings": sum(r.total for r in reports),
        "worst_rating": worst,
        "latest_risk": reports[0].risk_score if reports else 0,
    }


def _empty_result(platform) -> ScanResult:
    from ..core.scoring import RiskScoringEngine
    req = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector())
    risk = RiskScoringEngine().score([])
    return ScanResult(request=req, findings=[], risk=risk, resolved_rule_ids=[],
                      counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                      scan_id="coverage", cluster_name="(coverage)")


def _int(v) -> Optional[int]:
    try:
        return int(v) if v is not None else None
    except (ValueError, TypeError):
        return None
