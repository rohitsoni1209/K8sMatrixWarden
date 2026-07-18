"""correlate(): scan findings × runtime alerts → confirmed / corroborated / runtime-only."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.correlation import correlate, detect_drift
from k8smatrixwarden.core.models import (Finding, MitreTag, ResourceRef, Severity,
                                         Tactic)
from k8smatrixwarden.agents.runtime import RuntimeAgent


def _pod(name, ns, sc=None, container_sc=None):
    return {"kind": "Pod", "metadata": {"name": name, "namespace": ns},
            "spec": {"securityContext": sc or {},
                     "containers": [{"name": "app",
                                     "securityContext": container_sc or {}}]}}


def _finding(tactic, ns="production", name="payment-api"):
    return Finding(
        rule_id="workload-privileged", title="Privileged container",
        severity=Severity.HIGH,
        resource=ResourceRef(kind="Pod", name=name, namespace=ns),
        message="privileged", owning_shard="workload_pod_security",
        mitre=[MitreTag(tactic, "T1610", "Deploy Container")])


def test_confirmed_when_tactic_and_namespace_match():
    findings = [_finding(Tactic.PRIVILEGE_ESCALATION, ns="production")]
    # audit event in the SAME namespace, PrivEsc tactic (new clusterrolebinding)
    alerts = RuntimeAgent().evaluate_stream([
        {"source": "audit", "verb": "create", "resource": "clusterrolebindings",
         "namespace": "production"}])
    out = correlate(findings, alerts)
    assert out["confirmed_exploitation"] == 1
    assert out["correlations"][0]["confidence"] == "confirmed"


def test_corroborated_when_tactic_matches_but_namespace_differs():
    findings = [_finding(Tactic.PRIVILEGE_ESCALATION, ns="production")]
    alerts = RuntimeAgent().evaluate_stream([
        {"source": "audit", "verb": "create", "resource": "clusterrolebindings",
         "namespace": "staging"}])
    out = correlate(findings, alerts)
    assert out["confirmed_exploitation"] == 0
    assert out["correlated"] == 1
    assert out["correlations"][0]["confidence"] == "corroborated"


def test_runtime_only_when_no_static_finding_shares_the_tactic():
    findings = [_finding(Tactic.PRIVILEGE_ESCALATION)]
    # crypto-miner = Impact tactic, no Impact finding in scan
    alerts = RuntimeAgent().evaluate_stream([{"source": "falco", "proc": "xmrig"}])
    out = correlate(findings, alerts)
    assert out["runtime_only"] == 1
    assert out["correlations"][0]["static_findings"] == []


def test_drift_root_despite_runasnonroot():
    pods = [_pod("api", "prod", sc={"runAsNonRoot": True})]
    out = detect_drift(pods, [{"source": "falco", "pod": "api", "namespace": "prod",
                               "uid": 0, "proc": "bash"}])
    assert out["drift_count"] == 1
    assert out["drift"][0]["policy"] == "runAsNonRoot"


def test_drift_write_despite_readonly_rootfs():
    pods = [_pod("api", "prod", container_sc={"readOnlyRootFilesystem": True})]
    out = detect_drift(pods, [{"source": "falco", "pod": "api", "namespace": "prod",
                               "op": "write", "file": "/etc/passwd"}])
    assert out["drift_count"] == 1
    assert out["drift"][0]["policy"] == "readOnlyRootFilesystem"


def test_write_to_tmp_is_allowed_not_drift():
    pods = [_pod("api", "prod", container_sc={"readOnlyRootFilesystem": True})]
    out = detect_drift(pods, [{"source": "falco", "pod": "api", "namespace": "prod",
                               "op": "write", "file": "/tmp/scratch"}])
    assert out["drift_count"] == 0


def test_unattributable_event_skipped():
    pods = [_pod("api", "prod", sc={"runAsNonRoot": True})]
    # event names no pod -> can't attribute -> skipped, no false positive
    out = detect_drift(pods, [{"source": "falco", "uid": 0}])
    assert out["drift_count"] == 0


if __name__ == "__main__":
    for fn in (test_confirmed_when_tactic_and_namespace_match,
               test_corroborated_when_tactic_matches_but_namespace_differs,
               test_runtime_only_when_no_static_finding_shares_the_tactic,
               test_drift_root_despite_runasnonroot,
               test_drift_write_despite_readonly_rootfs,
               test_write_to_tmp_is_allowed_not_drift,
               test_unattributable_event_skipped):
        fn()
    print("ok")
