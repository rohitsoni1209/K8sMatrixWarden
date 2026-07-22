"""
Learning + controlled loop (Phase 6/8). Everything offline: :memory: SQLite, stubbed LLM +
build_tools. Covers: lessons stored, similar query retrieves them, prior pattern injected, and
the full investigate() loop (memory injection -> tool loop -> critic -> save findings+lessons).
"""
import json
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.memory import Memory


def test_lessons_stored_and_retrieved_by_similar_query():
    m = Memory(":memory:")
    m.save_lesson(task="Find privilege escalation",
                  successful_tool_sequence=["enumerate_users", "check_sudo", "verify_exploit"],
                  lesson="User enumeration should happen before exploit search.")
    hits = m.search_memory("investigate privilege escalation on server01")
    assert hits["lessons"], "a similar query should retrieve the prior lesson"
    seq = json.loads(hits["lessons"][0]["successful_tool_sequence"])
    assert seq[0] == "enumerate_users"


def test_prelude_includes_prior_pattern():
    m = Memory(":memory:")
    m.save_lesson(task="Find privilege escalation",
                  successful_tool_sequence=["enumerate_users", "check_sudo"],
                  lesson="enumerate first")
    pre = m.prelude_for("find privilege escalation")
    assert "enumerate_users -> check_sudo" in pre


# --------------------------------------------------------------------------- #
# Full controlled loop, fully mocked.
# --------------------------------------------------------------------------- #
def _install_fake_anthropic(client):
    mod = types.ModuleType("anthropic")
    mod.Anthropic = lambda *a, **k: client
    mod.APIError = Exception
    prev = sys.modules.get("anthropic")
    sys.modules["anthropic"] = mod
    return lambda: (sys.modules.__setitem__("anthropic", prev) if prev
                    else sys.modules.pop("anthropic", None))


def test_investigate_runs_loop_saves_findings_and_lessons():
    import k8smatrixwarden.mcp.server as server
    from k8smatrixwarden.agents import llm_orchestrator as llm

    calls = []
    saved_build = server.build_tools
    server.build_tools = lambda *a, **k: {
        "run_scan": lambda **kw: (calls.append("run_scan") or {"findings": [{"severity": "HIGH"}]}),
    }

    tool_use = types.SimpleNamespace(
        type="tool_use", name="run_scan", id="t1", input={"tactics": ["Privilege Escalation"]})
    script = [
        types.SimpleNamespace(stop_reason="tool_use", content=[tool_use]),
        types.SimpleNamespace(stop_reason="end_turn",
                              content=[types.SimpleNamespace(type="text",
                                                             text="Weak config on server01")]),
        # critic call:
        types.SimpleNamespace(content=[types.SimpleNamespace(
            type="text", text='{"approved": true, "issues": [], "recommended_actions": []}')]),
    ]
    client = types.SimpleNamespace(
        messages=types.SimpleNamespace(create=lambda **_: script.pop(0)))
    restore = _install_fake_anthropic(client)

    mem = Memory(":memory:")
    mem.upsert_asset("server01", services=["ssh"])  # prior context to inject
    cfg = {"memory": {"enabled": True}, "critic": {"enabled": True},
           "learning": {"enabled": True}, "max_tool_iterations": 10}

    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    try:
        ans = llm.investigate("investigate server01 for privilege escalation",
                              memory=mem, config=cfg, client=client)
    finally:
        restore()
        server.build_tools = saved_build
        os.environ.pop("ANTHROPIC_API_KEY", None)

    assert calls == ["run_scan"], "existing MCP tool should be dispatched unchanged"
    assert "Weak config" in ans
    # lesson learned from this investigation:
    assert mem.search_memory("privilege escalation server01")["lessons"]
    # finding persisted against the asset:
    assert mem.get_asset_history("server01")["findings"]


def test_investigate_surfaces_critic_rejection():
    import k8smatrixwarden.mcp.server as server
    from k8smatrixwarden.agents import llm_orchestrator as llm

    saved_build = server.build_tools
    server.build_tools = lambda *a, **k: {"run_scan": lambda **kw: {"findings": []}}
    script = [
        types.SimpleNamespace(stop_reason="end_turn",
                              content=[types.SimpleNamespace(type="text",
                                                             text="RCE confirmed")]),
        types.SimpleNamespace(content=[types.SimpleNamespace(
            type="text", text='{"approved": false, "issues": ["no evidence for RCE"], '
                               '"recommended_actions": ["run correlate_runtime"]}')]),
    ]
    client = types.SimpleNamespace(
        messages=types.SimpleNamespace(create=lambda **_: script.pop(0)))
    restore = _install_fake_anthropic(client)
    # One validation round: this test checks a single-pass rejection is surfaced, not the re-run.
    cfg = {"memory": {"enabled": False},
           "critic": {"enabled": True, "max_validation_rounds": 1},
           "learning": {"enabled": False}, "max_tool_iterations": 10}

    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    try:
        ans = llm.investigate("scan for rce", config=cfg, client=client)
    finally:
        restore()
        server.build_tools = saved_build
        os.environ.pop("ANTHROPIC_API_KEY", None)

    assert "Critic flagged" in ans and "no evidence for RCE" in ans
    assert "correlate_runtime" in ans
