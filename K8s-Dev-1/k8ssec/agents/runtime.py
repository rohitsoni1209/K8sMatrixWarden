"""
Runtime Agent (§8).

Uses the SAME rule/registry pattern as the Scanner (§8 intro): Falco/Tetragon syscall
rules, K8s audit-event rules, and drift rules are all tagged with MITRE tactics. In a live
deployment this runs as a DaemonSet tailing Falco/Tetragon and the audit stream; here it
provides the rule catalog and an event-matching engine that can be driven by a simulated
or real event feed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..core.models import (BlastRadius as BR, Exploitability as EX, MitreTag as M,
                           ResourceRef, Severity as S, Tactic as T)


@dataclass
class RuntimeRule:
    id: str
    title: str
    severity: S
    tactic: M
    matcher: Callable[[dict], bool]
    source: str = "falco"          # falco | audit | drift


@dataclass
class RuntimeAlert:
    rule_id: str
    title: str
    severity: S
    tactic: str
    event: dict


def _proc(name):        # process-name matcher for Falco-style events
    return lambda e: e.get("source") == "falco" and name in (e.get("proc") or "")


def _audit(verb=None, resource=None, ns=None):
    def _m(e):
        if e.get("source") != "audit":
            return False
        if verb and e.get("verb") != verb:
            return False
        if resource and e.get("resource") != resource:
            return False
        if ns and e.get("namespace") != ns:
            return False
        return True
    return _m


class RuntimeAgent:
    def __init__(self):
        self.rules = self._build_rules()

    def _build_rules(self) -> list[RuntimeRule]:
        return [
            RuntimeRule("rt-shell-in-container", "Shell spawned in container", S.HIGH,
                        M(T.EXECUTION, "T1059", "Command and Scripting Interpreter"),
                        lambda e: e.get("source") == "falco" and
                        (e.get("proc") or "") in ("bash", "sh", "zsh")),
            RuntimeRule("rt-metadata-api", "Metadata API access from container", S.CRITICAL,
                        M(T.CREDENTIAL_ACCESS, "T1552.005", "Cloud Instance Metadata API"),
                        lambda e: "169.254.169.254" in str(e.get("connect", ""))),
            RuntimeRule("rt-network-recon", "Network recon tool executed", S.HIGH,
                        M(T.DISCOVERY, "T1046", "Network Service Discovery"),
                        lambda e: (e.get("proc") or "") in ("nmap", "masscan", "nc",
                                                            "netcat")),
            RuntimeRule("rt-crypto-miner", "Crypto-miner signature", S.HIGH,
                        M(T.IMPACT, "T1496", "Resource Hijacking"),
                        lambda e: (e.get("proc") or "") in ("xmrig", "minerd", "cpuminer")),
            RuntimeRule("rt-container-escape", "Container escape indicator", S.CRITICAL,
                        M(T.PRIVILEGE_ESCALATION, "T1611", "Escape to Host"),
                        lambda e: any(x in str(e.get("file", "")) for x in
                                      ("release_agent", "/proc/1/root")) or
                        (e.get("proc") or "") in ("nsenter", "chroot")),
            RuntimeRule("rt-log-clear", "Container log cleared/truncated", S.HIGH,
                        M(T.DEFENSE_EVASION, "T1070", "Indicator Removal"),
                        lambda e: e.get("op") == "truncate" and
                        "/var/log" in str(e.get("file", "")), source="falco"),
            RuntimeRule("rt-new-rolebinding", "New (Cluster)RoleBinding created", S.CRITICAL,
                        M(T.PRIVILEGE_ESCALATION, "T1078", "Valid Accounts"),
                        _audit(verb="create", resource="clusterrolebindings"),
                        source="audit"),
            RuntimeRule("rt-exec-kube-system", "kubectl exec into kube-system", S.CRITICAL,
                        M(T.EXECUTION, "T1609", "Container Administration Command"),
                        _audit(verb="create", resource="pods/exec", ns="kube-system"),
                        source="audit"),
            RuntimeRule("rt-secret-enum", "Secret enumeration via API", S.HIGH,
                        M(T.CREDENTIAL_ACCESS, "T1552.007", "Container API Credentials"),
                        _audit(verb="list", resource="secrets"), source="audit"),
            RuntimeRule("rt-delete-events", "K8s events deleted", S.HIGH,
                        M(T.DEFENSE_EVASION, "T1070", "Indicator Removal"),
                        _audit(verb="delete", resource="events"), source="audit"),
            RuntimeRule("rt-mass-delete", "Mass deletion spike", S.CRITICAL,
                        M(T.IMPACT, "T1485", "Data Destruction"),
                        lambda e: e.get("source") == "audit" and
                        e.get("verb") == "delete" and e.get("count", 0) >= 10,
                        source="audit"),
        ]

    def evaluate(self, event: dict) -> list[RuntimeAlert]:
        alerts = []
        for r in self.rules:
            try:
                if r.matcher(event):
                    alerts.append(RuntimeAlert(r.id, r.title, r.severity,
                                               r.tactic.tactic.value, event))
            except Exception:
                continue
        return alerts

    def evaluate_stream(self, events: list[dict]) -> list[RuntimeAlert]:
        out = []
        for e in events:
            out.extend(self.evaluate(e))
        return out
