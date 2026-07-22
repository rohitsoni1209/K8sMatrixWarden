"""
Tool-quality intelligence (Upgrade 2). Deterministic, offline. Covers scoring a complete vs a
thin result, error handling, persistence, and the injectable hint block the agent receives.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.tool_quality import evaluate_tool_result
from k8smatrixwarden.agents.memory import Memory


def test_complete_result_scores_high():
    r = evaluate_tool_result("run_scan",
                             {"severity": "HIGH", "rule_id": "x", "resource": "pod"})
    assert r["score"] == 1.0
    assert r["missing_information"] == []
    assert r["recommended_followups"] == []


def test_missing_evidence_reduces_score_and_recommends_followups():
    r = evaluate_tool_result("run_scan", {"severity": "HIGH"})
    assert r["score"] < 1.0
    assert "rule_id" in r["missing_information"] and "resource" in r["missing_information"]
    assert r["recommended_followups"], "a thin scan should point at deeper tools"


def test_error_result_scores_zero():
    r = evaluate_tool_result("run_scan", {"error": "boom"})
    assert r["score"] == 0.0


def test_quality_saved_and_injected_as_hint():
    m = Memory(":memory:")
    r = evaluate_tool_result("run_scan", {"severity": "HIGH"})
    m.save_tool_quality("run_scan", r["score"], ", ".join(r["missing_information"]),
                        ", ".join(r["recommended_followups"]))
    row = m.db.execute("SELECT * FROM tool_quality").fetchone()
    assert row["quality_score"] == r["score"]
    hints = m.tool_quality_hints()
    assert "run_scan" in hints and "incomplete" in hints
