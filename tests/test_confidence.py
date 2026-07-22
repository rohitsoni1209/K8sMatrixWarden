"""
Evidence-based confidence scoring (Upgrade 3). Offline. Covers that evidence raises confidence,
its absence lowers it, a confirmed exploit is high, the critic rejects low-confidence verdicts,
and reports carry a confidence line.
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.confidence import calculate_confidence, verification_status
from k8smatrixwarden.agents import critic
from k8smatrixwarden.agents.llm_orchestrator import _report_footer


def test_evidence_increases_confidence():
    low = calculate_confidence("SSH weak config", "", None)
    high = calculate_confidence("SSH weak config", "ssh version 7.2 collected", None)
    assert high > low


def test_missing_evidence_lowers_confidence():
    assert calculate_confidence("some finding", "", None) <= 0.3


def test_confirmed_exploit_gives_high_confidence():
    c = calculate_confidence("SSH privilege escalation",
                             "ssh version collected", "exploit reproduction successful")
    assert c >= 0.75
    assert verification_status(c) == "confirmed"


def test_critic_rejects_low_confidence_even_if_it_says_approved():
    client = types.SimpleNamespace(messages=types.SimpleNamespace(
        create=lambda **_: types.SimpleNamespace(content=[types.SimpleNamespace(
            type="text",
            text='{"approved": true, "confidence": 0.4, "missing_evidence": [], '
                 '"recommended_tools": [], "reason": "shaky"}')])))
    v = critic.review("q", "draft", client=client, model="m")
    assert v["approved"] is False        # confidence < 0.5 overrides the LLM's approval
    assert v["confidence"] == 0.4


def test_report_includes_confidence_and_status():
    foot = _report_footer(0.88, "confirmed", ["run_scan", "correlate_runtime"])
    assert "Confidence: 88%" in foot and "confirmed" in foot
    assert "run_scan -> correlate_runtime" in foot
