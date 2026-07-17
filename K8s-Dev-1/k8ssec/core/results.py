"""The aggregate result object produced by a scan and consumed by reporting."""
from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass, field
from typing import Optional

from .models import Finding, ScanRequest
from .scoring import RiskResult


def _scan_id() -> str:
    now = _dt.datetime.now(_dt.timezone.utc)
    digest = hashlib.sha1(now.isoformat().encode()).hexdigest()[:4]
    return f"scan-{now:%Y%m%d}-{digest}"


@dataclass
class ScanResult:
    request: ScanRequest
    findings: list[Finding]
    risk: RiskResult
    resolved_rule_ids: list[str]
    counts: dict[str, int] = field(default_factory=dict)
    by_tactic: dict[str, int] = field(default_factory=dict)
    by_shard: dict[str, int] = field(default_factory=dict)
    scan_id: str = field(default_factory=_scan_id)
    cluster_name: str = "target-cluster"
    generated_at: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"))
    tool_version: str = "3.0"
    mode: str = "mock"

    def total(self) -> int:
        return sum(v for k, v in self.counts.items() if k != "INFO")

    def as_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "cluster": self.cluster_name,
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "mode": self.mode,
            "scope": self.request.scope.describe(),
            "selector": self.request.selector.describe(),
            "resolved_rules": self.resolved_rule_ids,
            "risk": {
                "cluster_risk": self.risk.cluster_risk,
                "security_score": self.risk.security_score,
                "rating": self.risk.rating,
            },
            "counts": self.counts,
            "by_tactic": self.by_tactic,
            "by_shard": self.by_shard,
            "findings": [f.as_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        """Reconstruct a ScanResult from as_dict() — used by the report store so a stored
        scan can be re-rendered into any format later."""
        rk = d.get("risk", {}) or {}
        rating = rk.get("rating", "Fair")
        risk = RiskResult(
            cluster_risk=float(rk.get("cluster_risk", 0.0)),
            security_score=int(rk.get("security_score", 0)),
            rating=rating,
            rating_emoji=_RATING_EMOJI.get(rating, "🟡"),
            raw=0.0)
        return cls(
            request=_ReplayRequest(_Descr(d.get("scope", "")),
                                   _Descr(d.get("selector", ""))),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            risk=risk,
            resolved_rule_ids=list(d.get("resolved_rules", [])),
            counts=d.get("counts", {}) or {},
            by_tactic=d.get("by_tactic", {}) or {},
            by_shard=d.get("by_shard", {}) or {},
            scan_id=d.get("scan_id", ""),
            cluster_name=d.get("cluster", "target-cluster"),
            generated_at=d.get("generated_at", ""),
            tool_version=str(d.get("tool_version", "3.0")),
            mode=d.get("mode", "mock"))


_RATING_EMOJI = {"Excellent": "🟢", "Good": "🟢", "Fair": "🟡", "Poor": "🟠",
                 "Critical": "🔴"}


@dataclass
class _Descr:
    """A stand-in for Scope/Selector when replaying a stored report — reporting only
    ever calls .describe() on them."""
    _text: str

    def describe(self) -> str:
        return self._text


@dataclass
class _ReplayRequest:
    scope: _Descr
    selector: _Descr
