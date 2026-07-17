"""
k8ssec CLI (§7, §16.4) — argparse-based (stdlib only, always runnable).

Commands:
  scan       run a scan by scope × selector, OR a natural-language query
  rules      list / inspect the rule registry
  coverage   show MITRE tactic coverage
  report     render the last scan (alias of scan --output)
  roles      print the per-plugin scoped RBAC roles (§20/§21)
  mcp        run the MCP server (needs the mcp SDK) or list its tools
  doctor     validate the platform (taxonomy, aliases, duplicate rules)
"""
from __future__ import annotations

import argparse
import sys

from ..bootstrap import build_platform
from ..core.models import (ScanMode, ScanRequest, Scope, ScopeLevel, Selector, Severity)
from ..agents.orchestrator import Orchestrator
from ..agents.scanner import ScannerAgent


def _add_scope_args(p):
    g = p.add_argument_group("scope (choose one; default: cluster)")
    g.add_argument("--namespace", "-n")
    g.add_argument("--pod")
    g.add_argument("--workload", help="KIND/name, e.g. Deployment/api")
    g.add_argument("--node")
    g.add_argument("--image")
    g.add_argument("--helm-release")


def _add_selector_args(p):
    g = p.add_argument_group("selector (combine freely; default: all rules)")
    g.add_argument("--tactic", action="append", default=[])
    g.add_argument("--technique", action="append", default=[],
                   help="technique id/name or composite alias (e.g. 'Container Escape')")
    g.add_argument("--module", action="append", default=[], help="domain shard name")
    g.add_argument("--rule", action="append", default=[], dest="rule_ids")
    g.add_argument("--alias", action="append", default=[])
    g.add_argument("--framework", action="append", default=[], help="CIS | NSA | OWASP")
    g.add_argument("--severity-min", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])


def _build_scope(a) -> Scope:
    if getattr(a, "namespace", None):
        return Scope(ScopeLevel.NAMESPACE, namespace=a.namespace)
    if getattr(a, "pod", None):
        return Scope(ScopeLevel.POD, name=a.pod, namespace=getattr(a, "namespace", None))
    if getattr(a, "workload", None):
        kind, _, name = a.workload.partition("/")
        return Scope(ScopeLevel.WORKLOAD, kind=kind, name=name)
    if getattr(a, "node", None):
        return Scope(ScopeLevel.NODE, name=a.node)
    if getattr(a, "image", None):
        return Scope(ScopeLevel.IMAGE, image=a.image)
    if getattr(a, "helm_release", None):
        return Scope(ScopeLevel.HELM_RELEASE, name=a.helm_release)
    return Scope(ScopeLevel.CLUSTER)


def _build_selector(a) -> Selector:
    sev = Severity.parse(a.severity_min) if getattr(a, "severity_min", None) else None
    return Selector(tactics=a.tactic, techniques=a.technique, modules=a.module,
                    rule_ids=a.rule_ids, aliases=a.alias, frameworks=a.framework,
                    severity_min=sev)


def _warn_ignored_live_flags(a) -> None:
    """Warn if --context/--kubeconfig were given but the scan is not actually live —
    otherwise a forgotten --live silently runs against the mock cluster."""
    if not getattr(a, "live", False) and (getattr(a, "context", None)
                                          or getattr(a, "kubeconfig", None)):
        print("warning: --kubeconfig/--context are ignored without --live "
              "(scanning the bundled MOCK cluster). Add --live to scan a real cluster.",
              file=sys.stderr)


# --------------------------------------------------------------------------- #
def cmd_scan(a) -> int:
    platform = build_platform(a.config)
    orch = Orchestrator(platform)

    if a.query:
        interp = orch.interpret(" ".join(a.query))
        request = interp.request
        if not a.yes:
            print(orch.confirmation_summary(interp))
            if a.dry_run:
                return 0
    else:
        request = ScanRequest(scope=_build_scope(a), selector=_build_selector(a),
                              mode=ScanMode.SYNC, output=a.output)
        try:
            resolved = orch.scanner.resolve(request)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if a.dry_run:
            print(f"Scope={request.scope.describe()}  "
                  f"Selector={request.selector.describe()}")
            print(f"→ resolves to {len(resolved)} rule(s): {', '.join(resolved)}")
            return 0

    mode_label = "mock" if (a.mock or not a.live) else "live"
    _warn_ignored_live_flags(a)
    try:
        collector = platform.make_collector(mock=(mode_label == "mock"),
                                            fixture=a.fixture, kubeconfig=a.kubeconfig,
                                            context=a.context)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    result = orch.run(request, collector, mode_label=mode_label)
    print(platform.reporting.render(result, a.output))

    if a.output_file:
        with open(a.output_file, "w", encoding="utf-8") as fh:
            fh.write(platform.reporting.render(result, a.output))
        print(f"\n[written] {a.output_file}", file=sys.stderr)

    if getattr(a, "save", False):
        from ..core.report_store import ReportStore
        path = ReportStore(a.reports_dir).save(result)
        print(f"[saved] {result.scan_id} → {path}  "
              f"(download later: k8ssec report download --scan-id {result.scan_id})",
              file=sys.stderr)

    if a.fail_on:
        floor = Severity.parse(a.fail_on).order
        if any(f.severity.order >= floor for f in result.findings):
            return 1
    return 0


def cmd_rules(a) -> int:
    platform = build_platform(a.config)
    rules = platform.registry.rules.all()
    if a.module:
        rules = [r for r in rules if r.owning_shard == a.module]
    if a.tactic:
        rules = [r for r in rules
                 if any(m.tactic.value.lower() == a.tactic.lower() for m in r.mitre)]
    print(f"{len(rules)} rule(s):")
    for r in sorted(rules, key=lambda x: (x.owning_shard, x.id)):
        tags = ",".join(sorted({m.tactic.value for m in r.mitre}))
        print(f"  {r.severity.emoji} {r.id:<34} [{r.owning_shard}]  "
              f"owasp={r.owasp or '-'}  mitre=[{tags}]")
    return 0


def cmd_coverage(a) -> int:
    platform = build_platform(a.config)
    print("MITRE tactic coverage (rules per tactic):")
    for tactic, n in platform.coverage().items():
        bar = "█" * n
        print(f"  {tactic:<22} {n:>2}  {bar}")
    print(f"\nTotal rules: {platform.rule_count()} across "
          f"{len(platform.registry.shard_names())} shards")
    return 0


def cmd_roles(a) -> int:
    import json
    platform = build_platform(a.config)
    if a.bind:
        manifest = platform.loader.deployment_manifest(
            service_account=a.service_account, namespace=a.sa_namespace,
            create_namespace=not a.no_create_namespace)
        out = json.dumps(manifest, indent=2)
    else:
        out = json.dumps(platform.loader.scoped_roles(), indent=2)
    print(out)
    if a.output_file:
        with open(a.output_file, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"\n[written] {a.output_file}", file=sys.stderr)
    return 0


def cmd_doctor(a) -> int:
    platform = build_platform(a.config)
    print(f"Shards loaded : {len(platform.registry.shard_names())} "
          f"({', '.join(platform.registry.shard_names())})")
    print(f"Rules loaded  : {platform.rule_count()}")
    problems = platform.validation_problems
    if problems:
        print(f"Validation    : {len(problems)} problem(s):")
        for p in problems:
            print(f"  ✗ {p}")
        return 1
    print("Validation    : ✅ clean (taxonomy + aliases + no duplicate rule ids)")
    return 0


def cmd_chat(a) -> int:
    from ..bootstrap import build_platform
    from .chat import run_chat
    platform = build_platform(a.config)
    _warn_ignored_live_flags(a)
    mock = not a.live
    return run_chat(platform, mock=mock, fixture=a.fixture, kubeconfig=a.kubeconfig,
                    context=a.context)


def cmd_cis(a) -> int:
    import json as _json
    from ..bootstrap import build_platform
    from ..frameworks.cis import CISBenchmarkEngine, render_markdown, render_text
    from ..frameworks.kube_bench_adapter import maybe_load

    platform = build_platform(a.config)
    engine = CISBenchmarkEngine(platform)
    mode_label = "mock" if (a.mock or not a.live) else "live"
    _warn_ignored_live_flags(a)
    try:
        collector = platform.make_collector(mock=(mode_label == "mock"),
                                            fixture=a.fixture, kubeconfig=a.kubeconfig,
                                            context=a.context)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    kb = maybe_load(a.kube_bench_json)
    report = engine.evaluate(collector, kube_bench_results=kb, profile=a.profile)

    if a.output == "json":
        out = _json.dumps(report.as_dict(), indent=2)
    elif a.output in ("markdown", "md"):
        out = render_markdown(report)
    else:
        out = render_text(report, show="all" if a.show_all else "fail")
    print(out)

    if a.output_file:
        with open(a.output_file, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"\n[written] {a.output_file}", file=sys.stderr)

    if a.fail_on_fail and report.counts["FAIL"] > 0:
        return 1
    return 0


def cmd_report(a) -> int:
    """List and download stored scan reports (§16.4)."""
    from ..core.report_store import ReportStore
    store = ReportStore(a.reports_dir)

    if a.report_cmd == "list":
        reports = store.list(limit=a.limit)
        if not reports:
            print(f"No stored reports in '{a.reports_dir}'. "
                  f"Run a scan with --save first.")
            return 0
        print(f"{len(reports)} stored report(s) in '{a.reports_dir}':\n")
        print(f"  {'SCAN ID':<22} {'WHEN':<21} {'RATING':<10} {'RISK':<5} FINDINGS  SCOPE")
        for r in reports:
            print(f"  {r.scan_id:<22} {r.generated_at:<21} {r.rating:<10} "
                  f"{r.risk_score:<5} {r.total:<8}  {r.scope}")
        print("\nDownload:  k8ssec report download --scan-id <ID> "
              "--format markdown --output report.md")
        return 0

    # download
    try:
        result = store.resolve(a.scan_id)
    except FileNotFoundError:
        print(f"error: no stored report with scan-id '{a.scan_id}' in '{a.reports_dir}'",
              file=sys.stderr)
        return 2
    if result is None:
        print(f"error: no stored reports in '{a.reports_dir}' (scan with --save first)",
              file=sys.stderr)
        return 2

    rendered = platform_render(a, result)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"📄 Downloaded {result.scan_id} as {a.format} → {a.output} "
              f"({len(rendered):,} bytes)")
    else:
        print(rendered)
    return 0


def platform_render(a, result) -> str:
    platform = build_platform(a.config)
    return platform.reporting.render(result, a.format)


def cmd_mcp(a) -> int:
    from ..mcp import server
    if a.list_tools:
        tools = server.build_tools(a.config)
        print("MCP tools:", ", ".join(tools.keys()))
        return 0
    server.serve(a.config)
    return 0


# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="k8ssec",
                                description="K8s Security Tool v3.0 — MITRE-aligned scanner")
    p.add_argument("--config", help="path to a config JSON overriding defaults")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run a scan (by args or natural language)")
    s.add_argument("query", nargs="*", help="natural-language query, e.g. "
                   "\"scan production for Persistence\"")
    _add_scope_args(s)
    _add_selector_args(s)
    s.add_argument("--output", "-o", default="terminal",
                   choices=["terminal", "text", "markdown", "json", "sarif", "html"])
    s.add_argument("--output-file")
    s.add_argument("--mock", action="store_true", help="use the bundled mock cluster")
    s.add_argument("--live", action="store_true", help="scan the live cluster")
    s.add_argument("--fixture", help="path to a custom mock cluster JSON")
    s.add_argument("--kubeconfig", help="path to a kubeconfig file (default: ~/.kube/config)")
    s.add_argument("--context", help="kubeconfig context to use (default: current-context)")
    s.add_argument("--dry-run", action="store_true",
                   help="resolve the selector and show the rule set without scanning")
    s.add_argument("--yes", "-y", action="store_true", help="skip confirmation")
    s.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="exit 1 if a finding at/above this severity is found (CI mode)")
    s.add_argument("--save", action="store_true",
                   help="persist the result to the report store for later download")
    s.add_argument("--reports-dir", default="k8ssec-reports",
                   help="report store directory (default: ./k8ssec-reports)")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("rules", help="list the rule registry")
    r.add_argument("--module")
    r.add_argument("--tactic")
    r.set_defaults(func=cmd_rules)

    c = sub.add_parser("coverage", help="show MITRE tactic coverage")
    c.set_defaults(func=cmd_coverage)

    ro = sub.add_parser("roles", help="print per-plugin scoped RBAC roles")
    ro.add_argument("--bind", action="store_true",
                    help="emit a full deployable manifest (Namespace + ServiceAccount + "
                    "ClusterRoles + ClusterRoleBindings) instead of bare ClusterRoles")
    ro.add_argument("--service-account", default="k8ssec-scanner")
    ro.add_argument("--sa-namespace", default="k8ssec-system")
    ro.add_argument("--no-create-namespace", action="store_true",
                    help="assume --sa-namespace already exists")
    ro.add_argument("--output-file")
    ro.set_defaults(func=cmd_roles)

    d = sub.add_parser("doctor", help="validate the platform")
    d.set_defaults(func=cmd_doctor)

    ch = sub.add_parser("chat", help="interactive conversational security assistant")
    ch.add_argument("--live", action="store_true", help="scan the live cluster")
    ch.add_argument("--fixture", help="custom mock cluster JSON")
    ch.add_argument("--kubeconfig")
    ch.add_argument("--context", help="kubeconfig context to use")
    ch.set_defaults(func=cmd_chat)

    ci = sub.add_parser("cis", help="run the full CIS Kubernetes Benchmark v1.8 (130 controls)")
    ci.add_argument("--mock", action="store_true")
    ci.add_argument("--live", action="store_true")
    ci.add_argument("--fixture")
    ci.add_argument("--kubeconfig")
    ci.add_argument("--context", help="kubeconfig context to use")
    ci.add_argument("--kube-bench-json", help="kube-bench --json output to resolve "
                    "node file-permission controls")
    ci.add_argument("--profile", default="self-managed",
                    choices=["self-managed", "eks", "gke", "aks"],
                    help="managed profiles mark provider-owned control-plane controls N/A")
    ci.add_argument("--output", "-o", default="terminal",
                    choices=["terminal", "text", "markdown", "json"])
    ci.add_argument("--output-file")
    ci.add_argument("--show-all", action="store_true",
                    help="also list manual / node-dependent controls")
    ci.add_argument("--fail-on-fail", action="store_true",
                    help="exit 1 if any control FAILs (CI mode)")
    ci.set_defaults(func=cmd_cis)

    fmts = ["terminal", "text", "markdown", "json", "sarif", "html"]
    rp = sub.add_parser("report", help="list / download stored scan reports")
    rpsub = rp.add_subparsers(dest="report_cmd", required=True)
    rl = rpsub.add_parser("list", help="list stored reports")
    rl.add_argument("--reports-dir", default="k8ssec-reports")
    rl.add_argument("--limit", type=int)
    rl.set_defaults(func=cmd_report)
    rd = rpsub.add_parser("download",
                          help="re-render a stored report in any format, to any filename")
    rd.add_argument("--reports-dir", default="k8ssec-reports")
    rd.add_argument("--scan-id", help="scan id to download (default: latest)")
    rd.add_argument("--format", "-f", default="markdown", choices=fmts)
    rd.add_argument("--output", "-o", help="output filename (default: print to stdout)")
    rd.set_defaults(func=cmd_report)

    m = sub.add_parser("mcp", help="run the MCP server (or --list-tools)")
    m.add_argument("--list-tools", action="store_true")
    m.set_defaults(func=cmd_mcp)

    return p


def _force_utf8() -> None:
    # Windows consoles default to cp1252 and choke on emoji/box-drawing. Force UTF-8.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass


def main(argv=None) -> int:
    _force_utf8()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
