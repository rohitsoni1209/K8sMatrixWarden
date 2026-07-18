"""
Scanner Agent (§5) — wires registry + evidence + detection + aggregate + score.

The scan path is identical for every request shape (§7.2):
    resolve(selector) → fetch-once evidence → execute rules → aggregate → score → result
"""
from __future__ import annotations

from ..bootstrap import Platform
from ..core.evidence import EvidenceCollector
from ..core.models import ScanRequest
from ..core.results import ScanResult


class ScannerAgent:
    def __init__(self, platform: Platform):
        self.p = platform

    def resolve(self, request: ScanRequest) -> list[str]:
        """Selector → concrete rule id set (the single choke point)."""
        return self.p.mapping.resolve(request.selector)

    def scan(self, request: ScanRequest, collector: EvidenceCollector,
             mode_label: str = "mock") -> ScanResult:
        rule_ids = self.resolve(request)

        # Evidence is already scope-constrained by the collector, so findings are in scope.
        # Cluster-scoped objects (RBAC, webhooks) intentionally remain visible.
        findings = self.p.detection.run(rule_ids, collector, request.scope)
        findings = self.p.aggregator.aggregate(findings)
        risk = self.p.scoring.score(findings)

        return ScanResult(
            request=request,
            findings=findings,
            risk=risk,
            resolved_rule_ids=rule_ids,
            counts=self.p.aggregator.counts(findings),
            by_tactic=self.p.aggregator.by_tactic(findings),
            by_shard=self.p.aggregator.by_shard(findings),
            mode=mode_label,
        )
