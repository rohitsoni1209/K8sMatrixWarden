"""
K8s Security MCP Server (§8/§10).

Exposes the knowledge datasets and the live rule registry as MCP tools so an external AI
agent can query commands, playbooks, CVEs, taxonomy, and resolve selectors → rules.

Uses the official `mcp` Python SDK (FastMCP) when installed. If it is not installed, the
same functions are still callable in-process via `build_tools()` — the server is a thin
protocol wrapper over them, so nothing is lost when running without the SDK.
"""
from __future__ import annotations

from typing import Any, Optional

from ..bootstrap import build_platform
from ..core.models import Selector
from . import datasets


def build_tools(config_path: Optional[str] = None) -> dict[str, Any]:
    """Return the callable tool implementations (usable with or without the MCP SDK)."""
    platform = build_platform(config_path)

    def list_rules(shard: Optional[str] = None, tactic: Optional[str] = None) -> list[dict]:
        rules = platform.registry.rules.all()
        if shard:
            rules = [r for r in rules if r.owning_shard == shard]
        if tactic:
            rules = [r for r in rules
                     if any(m.tactic.value.lower() == tactic.lower() for m in r.mitre)]
        return [r.metadata() for r in rules]

    def resolve_selector(tactics: Optional[list] = None, techniques: Optional[list] = None,
                         modules: Optional[list] = None, aliases: Optional[list] = None,
                         frameworks: Optional[list] = None,
                         rule_ids: Optional[list] = None) -> list[str]:
        sel = Selector(tactics=tactics or [], techniques=techniques or [],
                       modules=modules or [], aliases=aliases or [],
                       frameworks=frameworks or [], rule_ids=rule_ids or [])
        return platform.mapping.resolve(sel)

    def get_kubectl_command(name: str) -> str:
        return datasets.KUBECTL_COMMANDS.get(name, "")

    def get_tool_commands(tool: str) -> list:
        return datasets.TOOL_COMMANDS.get(tool, [])

    def get_playbook(ref: str) -> dict:
        return datasets.PLAYBOOKS.get(ref, {})

    def lookup_cve(cve_id: str) -> dict:
        return datasets.CVE_KB.get(cve_id.upper(), {})

    def get_taxonomy() -> dict:
        return {"techniques": platform.taxonomy.get("techniques", []),
                "coverage": platform.coverage()}

    def mitre_coverage() -> dict:
        return platform.coverage()

    return {
        "list_rules": list_rules,
        "resolve_selector": resolve_selector,
        "get_kubectl_command": get_kubectl_command,
        "get_tool_commands": get_tool_commands,
        "get_playbook": get_playbook,
        "lookup_cve": lookup_cve,
        "get_taxonomy": get_taxonomy,
        "mitre_coverage": mitre_coverage,
    }


def serve(config_path: Optional[str] = None) -> None:
    """Run the MCP server over stdio (requires the `mcp` SDK)."""
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore
    except Exception:
        raise SystemExit(
            "The MCP Python SDK is not installed.\n"
            "  pip install mcp\n"
            "The same datasets are available in-process via "
            "k8ssec.mcp.server.build_tools() without the SDK.")

    tools = build_tools(config_path)
    app = FastMCP("k8s-security-mcp")
    for name, fn in tools.items():
        app.tool(name=name)(fn)
    app.run()


if __name__ == "__main__":  # pragma: no cover
    serve()
