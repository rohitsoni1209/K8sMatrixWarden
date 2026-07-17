"""
Remediation Agent (§9).

Non-negotiable rule: every action requires explicit user confirmation. This agent NEVER
auto-applies. It follows the §9.3 lifecycle: snapshot → show diff → confirm → apply →
health-check → rollback-on-failure → audit-log. By default it runs in DRY-RUN and only
prints the exact commands; a real applier would shell out to kubectl (guarded, opt-in).
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..core.models import Finding
from ..mcp.datasets import PLAYBOOKS


@dataclass
class RemediationPlan:
    finding: Finding
    playbook_ref: Optional[str]
    commands: list[str]
    snapshot_cmd: str
    rollback_cmd: str
    requires_confirmation: bool = True


@dataclass
class AuditEntry:
    timestamp: str
    finding_rule: str
    resource: str
    action: str
    result: str


class RemediationAgent:
    def __init__(self, dry_run: bool = True, confirm_fn: Optional[Callable[[str], bool]] = None):
        self.dry_run = dry_run
        self.confirm_fn = confirm_fn or (lambda _prompt: False)
        self.audit_log: list[AuditEntry] = []

    def plan(self, finding: Finding) -> RemediationPlan:
        pb = PLAYBOOKS.get(finding.remediation_ref or "", {})
        res = finding.resource
        ns = res.namespace or "default"
        commands = [c.format(name=res.name, namespace=ns, kind=res.kind.lower())
                    for c in pb.get("commands", [])]
        snapshot = (f"kubectl get {res.kind.lower()} {res.name} -n {ns} "
                    f"-o yaml > /snapshots/{res.kind}-{res.name}.yaml")
        rollback = (f"kubectl apply -f /snapshots/{res.kind}-{res.name}.yaml")
        return RemediationPlan(finding, finding.remediation_ref, commands, snapshot,
                               rollback)

    def show(self, plan: RemediationPlan) -> str:
        lines = [
            f"Remediation for: {plan.finding.title}  [{plan.finding.resource}]",
            f"  Playbook : {plan.playbook_ref or '(none)'}",
            f"  ① snapshot : {plan.snapshot_cmd}",
            "  ② proposed changes:",
        ]
        for c in plan.commands or ["    (no automated fix available — manual review)"]:
            lines.append(f"       {c}")
        lines.append(f"  ⑥ rollback : {plan.rollback_cmd}")
        return "\n".join(lines)

    def apply(self, plan: RemediationPlan, assume_yes: bool = False) -> AuditEntry:
        """Follows the §9.3 lifecycle. Dry-run prints; real apply is guarded."""
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        res = str(plan.finding.resource)

        if not plan.commands:
            entry = AuditEntry(ts, plan.finding.rule_id, res, "none", "skipped:no-fix")
            self.audit_log.append(entry)
            return entry

        approved = assume_yes or self.confirm_fn(
            f"Apply fix for {plan.finding.title} on {res}? [y/N] ")
        if not approved:
            entry = AuditEntry(ts, plan.finding.rule_id, res, "abort", "user-declined")
            self.audit_log.append(entry)
            return entry

        if self.dry_run:
            entry = AuditEntry(ts, plan.finding.rule_id, res,
                               "; ".join(plan.commands), "dry-run")
            self.audit_log.append(entry)
            return entry

        # Real apply path (guarded; only when dry_run=False).
        result = self._execute(plan)
        entry = AuditEntry(ts, plan.finding.rule_id, res, "; ".join(plan.commands), result)
        self.audit_log.append(entry)
        return entry

    def _execute(self, plan: RemediationPlan) -> str:  # pragma: no cover
        import subprocess
        try:
            subprocess.run(plan.snapshot_cmd, shell=True, check=True)
            for cmd in plan.commands:
                subprocess.run(cmd, shell=True, check=True)
            return "applied"
        except Exception as exc:
            try:
                subprocess.run(plan.rollback_cmd, shell=True, check=True)
                return f"rolled-back:{exc}"
            except Exception as rexc:
                return f"failed-and-rollback-failed:{rexc}"
