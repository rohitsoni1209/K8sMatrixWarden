"""End-to-end mock scans through the Orchestrator + Scanner (§7.2)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.orchestrator import Orchestrator
from k8smatrixwarden.agents.runtime import RuntimeAgent
from k8smatrixwarden.agents.remediation import RemediationAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import ScanRequest, Scope, ScopeLevel, Selector


def _run(selector=None, scope=None):
    p = build_platform()
    orch = Orchestrator(p)
    req = ScanRequest(scope=scope or Scope(ScopeLevel.CLUSTER),
                      selector=selector or Selector())
    coll = p.make_collector(mock=True)
    return p, orch.run(req, coll)


def test_full_cluster_scan_finds_critical_issues():
    p, res = _run()
    assert res.counts["CRITICAL"] > 0
    assert res.risk.rating == "Critical"
    # Known planted findings.
    rule_ids = {f.rule_id for f in res.findings}
    assert "workload-privileged-container" in rule_ids
    assert "rbac-cluster-admin-default-sa" in rule_ids
    assert "admission-malicious-webhook" in rule_ids
    assert "iam-overpermissive" in rule_ids


def test_persistence_scan_matches_spec_workflow():
    # §17 Workflow 2: "Scan for Persistence" => rules from ② and ⑨ (+ hostPath).
    p, res = _run(selector=Selector(tactics=["Persistence"]))
    shards = {f.owning_shard for f in res.findings}
    assert "workload_pod_security" in shards
    assert "admission_control" in shards


def test_namespace_scope_filters_resources():
    p, res = _run(scope=Scope(ScopeLevel.NAMESPACE, namespace="staging"),
                  selector=Selector(modules=["workload_pod_security"]))
    # Only staging workloads (cache-redis) should appear; production pods excluded.
    ns = {f.resource.namespace for f in res.findings if f.resource.namespace}
    assert ns.issubset({"staging", None})


def test_attack_path_bonus_on_hostpath():
    p, res = _run(selector=Selector(rule_ids=["workload-hostpath-root"]))
    hp = [f for f in res.findings if f.rule_id == "workload-hostpath-root"]
    assert hp
    # hostPath rule carries 3 tactics => elevated score vs a 1-tactic baseline.
    assert len(hp[0].tactics) >= 3


def test_reporting_formats_render():
    p, res = _run()
    for fmt in ("text", "markdown", "json", "sarif", "html"):
        out = p.reporting.render(res, fmt)
        assert isinstance(out, str) and len(out) > 100


def test_runtime_agent_detects_events():
    rt = RuntimeAgent()
    alerts = rt.evaluate_stream([
        {"source": "falco", "proc": "bash"},
        {"source": "falco", "connect": "169.254.169.254:80"},
        {"source": "audit", "verb": "create", "resource": "clusterrolebindings"},
    ])
    ids = {a.rule_id for a in alerts}
    assert "rt-shell-in-container" in ids
    assert "rt-metadata-api" in ids
    assert "rt-new-rolebinding" in ids


def test_remediation_requires_confirmation_and_is_dry_run():
    p, res = _run(selector=Selector(rule_ids=["workload-sa-token-automount"]))
    agent = RemediationAgent(dry_run=True, confirm_fn=lambda _p: True)
    plan = agent.plan(res.findings[0])
    assert plan.snapshot_cmd.startswith("kubectl get")
    entry = agent.apply(plan, assume_yes=True)
    assert entry.result == "dry-run"          # never really mutates in dry-run

    declined = RemediationAgent(dry_run=True, confirm_fn=lambda _p: False)
    e2 = declined.apply(declined.plan(res.findings[0]))
    assert e2.result == "user-declined"       # confirmation is mandatory
