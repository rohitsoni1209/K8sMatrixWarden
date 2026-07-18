"""
Remediation Agent (§9).

Non-negotiable rule: every action requires explicit user confirmation. This agent NEVER
auto-applies. It follows the §9.3 lifecycle: snapshot → show diff → confirm → apply →
health-check → rollback-on-failure → audit-log. By default it runs in DRY-RUN and only
prints the exact commands; a real applier would shell out to kubectl (guarded, opt-in).

Command generation itself is delegated to `core.remediation_engine.RemediationEngine` —
schema-aware and resource-aware (§ core/remediation_engine.py), so this agent never has
to know which JSON path a given Kubernetes kind uses; it only drives the lifecycle around
whatever the engine determined is (or isn't) safe to automate.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Callable, Optional

from ..core.models import Finding
from ..core.remediation_engine import RemediationEngine, RemediationResult


@dataclass
class RemediationPlan:
    finding: Finding
    result: RemediationResult
    snapshot_cmd: str
    requires_confirmation: bool = True

    @property
    def commands(self) -> list[str]:
        return [self.result.kubectl_command] if self.result.kubectl_command else []

    @property
    def rollback_cmd(self) -> str:
        return "; ".join(self.result.rollback_commands) if self.result.rollback_commands \
            else "# no rollback available"

    @property
    def playbook_ref(self) -> Optional[str]:
        return self.finding.remediation_ref


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
        self.engine = RemediationEngine()

    def plan(self, finding: Finding) -> RemediationPlan:
        result = self.engine.generate(finding)
        if result.target_kind and result.target_name:
            ns = finding.resource.namespace or "default"
            snapshot = (f"kubectl get {result.target_kind.lower()} {result.target_name} "
                       f"-n {ns} -o yaml > /snapshots/{result.target_kind}-"
                       f"{result.target_name}.yaml")
        else:
            snapshot = "# no identifiable target resource to snapshot"
        return RemediationPlan(finding, result, snapshot)

    def show(self, plan: RemediationPlan) -> str:
        return plan.result.render_text()

    def apply(self, plan: RemediationPlan, assume_yes: bool = False) -> AuditEntry:
        """Follows the §9.3 lifecycle. Dry-run prints; real apply is guarded."""
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        res = str(plan.finding.resource)

        if not plan.result.automatable:
            entry = AuditEntry(ts, plan.finding.rule_id, res, "none",
                               "skipped:not-automatable")
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
                               plan.result.kubectl_command or "", "dry-run")
            self.audit_log.append(entry)
            return entry

        # Real apply path (guarded; only when dry_run=False).
        result = self._execute(plan)
        entry = AuditEntry(ts, plan.finding.rule_id, res,
                           plan.result.kubectl_command or "", result)
        self.audit_log.append(entry)
        return entry

    def _execute(self, plan: RemediationPlan) -> str:  # pragma: no cover
        """The full §9.3 lifecycle: ① snapshot → ④ apply → ⑤ health-check →
        ⑥ rollback-on-failure. A patch that applies but then fails its health check
        (rollout doesn't become Ready) is rolled back — 'applied but broken' is a failure,
        not a success."""
        import subprocess

        def _run(cmd: str) -> None:
            subprocess.run(cmd, shell=True, check=True)

        # ① snapshot current state so ⑥ can restore it (rollout-based kinds also have
        #    `kubectl rollout undo`, but snapshotting first is cheap and universal).
        snap = plan.snapshot_cmd
        if snap and not snap.strip().startswith("#"):
            try:
                import os
                os.makedirs("/snapshots", exist_ok=True)
                _run(snap)
            except Exception as exc:
                return f"aborted:snapshot-failed:{exc}"

        # ④ apply.
        try:
            _run(plan.result.kubectl_command)
        except Exception as exc:
            return self._rollback(plan, f"apply-failed:{exc}")

        # ⑤ health-check — wait for the rollout to become Ready where applicable.
        for hc in plan.result.validation_commands:
            if "rollout status" in hc:
                try:
                    _run(hc)
                except Exception as exc:
                    return self._rollback(plan, f"healthcheck-failed:{exc}")
        return "applied"

    def _rollback(self, plan: RemediationPlan, cause: str) -> str:  # pragma: no cover
        import subprocess
        try:
            for cmd in plan.result.rollback_commands:
                if not cmd.strip().startswith("#"):
                    subprocess.run(cmd, shell=True, check=True)
            return f"rolled-back:{cause}"
        except Exception as rexc:
            return f"failed-and-rollback-failed:{cause}:{rexc}"
