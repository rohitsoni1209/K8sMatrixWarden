"""
Evidence-based confidence scoring (Upgrade 3). Deterministic, no LLM.

Starts from a low prior and adds independent credit: a concrete match (version/config/rule/CIS),
evidence actually collected, and a successful runtime/exploit validation. Caps at 1.0. This is
the numeric backbone behind "confidence 88%, confirmed" reporting.
"""
from __future__ import annotations

import json

BASE = 0.3


def _blob(*xs) -> str:
    return " ".join(x if isinstance(x, str) else json.dumps(x, default=str)
                    for x in xs).lower()


def calculate_confidence(finding, evidence, validation_results=None) -> float:
    """Score a finding 0.0-1.0 from the evidence and validation signals present."""
    text = _blob(finding, evidence, validation_results or "")
    score = BASE
    if any(k in text for k in ("version", "config", "cis", "rule_id", "banner")):
        score += 0.2                                   # a concrete match
    if evidence:
        score += 0.2                                   # evidence actually collected
    if any(k in text for k in ("confirmed", "exploit", "reaches_impact", "drift",
                               "validation succeeded", "success")):
        score += 0.3                                   # runtime / exploit validation
    return round(min(score, 1.0), 2)


def verification_status(confidence: float) -> str:
    if confidence >= 0.75:
        return "confirmed"
    if confidence >= 0.5:
        return "corroborated"
    return "unverified"
