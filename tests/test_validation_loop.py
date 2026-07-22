"""
Critic-triggered re-run loop (Upgrade 1). Offline: stubbed LLM + build_tools, :memory: SQLite.
Covers should_continue rules, that a rejection triggers a second tool round, that approval stops
the loop, and that the round cap prevents infinite re-runs.
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.validation_loop import should_continue


# --------------------------------------------------------------------------- #
# Pure decision logic.
# --------------------------------------------------------------------------- #
def test_should_continue_on_missing_evidence():
    assert should_continue({"approved": False, "missing_evidence": ["exploit"],
                            "confidence": 0.9})


def test_should_continue_on_recommended_tools():
    assert should_continue({"approved": False, "missing_evidence": [],
                            "recommended_tools": ["verify_exploit"], "confidence": 0.9})


def test_should_continue_on_low_confidence():
    assert should_continue({"approved": False, "missing_evidence": [],
                            "recommended_tools": [], "confidence": 0.4}, 0.75)


def test_should_stop_when_approved():
    assert not should_continue({"approved": True, "confidence": 0.2})


def test_should_stop_when_confident_enough():
    assert not should_continue({"approved": False, "missing_evidence": [],
                                "recommended_tools": [], "confidence": 0.9}, 0.75)


# --------------------------------------------------------------------------- #
# Integration: reject -> another round -> approve.
# --------------------------------------------------------------------------- #
def _fake_anthropic(client):
    mod = types.ModuleType("anthropic")
    mod.Anthropic = lambda *a, **k: client
    mod.APIError = Exception
    prev = sys.modules.get("anthropic")
    sys.modules["anthropic"] = mod
    return lambda: (sys.modules.__setitem__("anthropic", prev) if prev
                    else sys.modules.pop("anthropic", None))


def _tool(name):
    return types.SimpleNamespace(type="tool_use", name=name, id="t", input={})


def _txt(s):
    return types.SimpleNamespace(type="text", text=s)


def _client(script):
    return types.SimpleNamespace(
        messages=types.SimpleNamespace(create=lambda **_: script.pop(0)))


def test_critic_rejection_triggers_second_round_then_approves():
    import k8smatrixwarden.mcp.server as server
    from k8smatrixwarden.agents import llm_orchestrator as llm
    from k8smatrixwarden.agents.memory import Memory

    calls = []
    saved = server.build_tools
    server.build_tools = lambda *a, **k: {
        "run_scan": lambda **kw: (calls.append("run_scan")
                                  or {"severity": "HIGH", "rule_id": "x", "resource": "pod"}),
        "correlate_runtime": lambda **kw: (calls.append("correlate_runtime")
                                           or {"confidence": "high", "confirmed": True}),
    }
    script = [
        _R("tool_use", [_tool("run_scan")]),
        _R("end_turn", [_txt("Possible sudo issue")]),
        _R(None, [_txt('{"approved": false, "confidence": 0.4, '
                       '"missing_evidence": ["exploit validation"], '
                       '"recommended_tools": ["correlate_runtime"], "reason": "unvalidated"}')]),
        _R("tool_use", [_tool("correlate_runtime")]),
        _R("end_turn", [_txt("Confirmed sudo privilege escalation path")]),
        _R(None, [_txt('{"approved": true, "confidence": 0.9, "missing_evidence": [], '
                       '"recommended_tools": [], "reason": "validated"}')]),
    ]
    client = _client(script)
    restore = _fake_anthropic(client)
    cfg = {"memory": {"enabled": True},
           "critic": {"enabled": True, "max_validation_rounds": 3, "minimum_confidence": 0.75},
           "learning": {"enabled": True}, "max_tool_iterations": 10}
    os.environ["ANTHROPIC_API_KEY"] = "k"
    try:
        ans = llm.investigate("check server01 for privilege escalation",
                              memory=Memory(":memory:"), config=cfg, client=client)
    finally:
        restore()
        server.build_tools = saved
        os.environ.pop("ANTHROPIC_API_KEY", None)

    assert calls == ["run_scan", "correlate_runtime"], calls  # a second tool round happened
    assert "Confirmed" in ans
    assert "Confidence:" in ans


def test_round_cap_prevents_infinite_reruns():
    import k8smatrixwarden.mcp.server as server
    from k8smatrixwarden.agents import llm_orchestrator as llm

    calls = []
    saved = server.build_tools
    server.build_tools = lambda *a, **k: {
        "run_scan": lambda **kw: (calls.append("run_scan") or {"severity": "HIGH"})}
    reject = _R(None, [_txt('{"approved": false, "confidence": 0.2, '
                            '"missing_evidence": ["more"], "recommended_tools": [], '
                            '"reason": "still thin"}')])
    # 2 rounds worth of (tool_use, end_turn, reject); the cap must stop after 2.
    script = [_R("tool_use", [_tool("run_scan")]), _R("end_turn", [_txt("draft")]), reject,
              _R("tool_use", [_tool("run_scan")]), _R("end_turn", [_txt("draft")]), reject]
    client = _client(script)
    restore = _fake_anthropic(client)
    cfg = {"memory": {"enabled": False},
           "critic": {"enabled": True, "max_validation_rounds": 2, "minimum_confidence": 0.75},
           "learning": {"enabled": False}, "max_tool_iterations": 10}
    os.environ["ANTHROPIC_API_KEY"] = "k"
    try:
        ans = llm.investigate("check privilege escalation", config=cfg, client=client)
    finally:
        restore()
        server.build_tools = saved
        os.environ.pop("ANTHROPIC_API_KEY", None)

    assert len(calls) == 2, "loop must stop at max_validation_rounds, not run forever"
    assert not script, "exactly the scripted responses were consumed"
    assert "Critic flagged" in ans  # unresolved after the cap


def _R(stop_reason, content):
    return types.SimpleNamespace(stop_reason=stop_reason, content=content)
