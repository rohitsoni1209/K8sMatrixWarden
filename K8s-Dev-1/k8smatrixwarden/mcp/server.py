"""
K8s Security MCP Server (§8/§10).

Exposes the full read-only capability surface of k8smatrixwarden as MCP tools, so any
MCP-compatible AI agent (Claude, Cursor, VS Code, Windsurf, ...) can do everything the
CLI can do short of applying a fix: scan, audit, browse the rule/knowledge datasets,
explain a hypothetical remediation, evaluate a runtime event stream, and list/export
previously-saved reports in any format — the same engine the CLI and chat use.

Deliberately NOT exposed: remediation / apply. §9.1 is explicit — "every remediation
action requires explicit user confirmation. No exceptions. No bypass. No auto-mode." An
MCP tool call has no interactive confirmation step, so wiring the Remediation Agent's
write path in here would violate that safety control. Everything below is read-only —
scanning (§4.4), the knowledge datasets, and report rendering/export never mutate the
cluster or delete anything; `tests/test_mcp.py::test_no_remediation_or_apply_tool_is_exposed`
enforces this stays true.

27 tools, four layers:
  1. Knowledge   — browse/query the rule registry, taxonomy, and the 6 MCP datasets
  2. Scan/audit  — scan / CIS benchmark / runtime detections + event eval / threat matrix
  3. Reports     — persist a scan and list/export it later in any of the 6 formats
  4. Platform    — validate the install, generate least-privilege RBAC

Uses the official `mcp` Python SDK (FastMCP) when installed. If it is not installed, the
same functions are still callable in-process via `build_tools()` — the server is a thin
protocol wrapper over them, so nothing is lost when running without the SDK. Each tool's
docstring below IS its description as surfaced to the calling LLM (FastMCP reads it
directly) — kept accurate and complete for exactly that reason.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from ..bootstrap import build_platform
from ..core.evidence import detect_provider
from ..core.models import ScanMode, ScanRequest, Scope, ScopeLevel, Selector, Severity
from . import datasets

#: ReportingEngine.render()'s valid `fmt` values — anything else silently falls back to
#: `terminal` there, which would make a typo'd output_format look "successful" while
#: quietly ignoring what was actually asked for. MCP tools validate against this
#: explicitly instead and return a clear error.
_VALID_REPORT_FORMATS = {"terminal", "text", "markdown", "json", "sarif", "html", "pdf"}
#: pdf is the only format that renders to bytes, not str — MCP responses are JSON, which
#: has no binary type, so pdf content travels as base64 instead of a plain `content` string.


def _encode_report(content) -> dict:
    """content is `str` for every format except pdf, where it's `bytes`. Return the
    right shape for either: {"content": "..."} for text formats, or
    {"content_base64": "...", "encoding": "base64"} for pdf — the caller must
    base64-decode and write the result in binary mode."""
    if isinstance(content, bytes):
        import base64
        return {"content_base64": base64.b64encode(content).decode("ascii"),
                "encoding": "base64"}
    return {"content": content}


def build_tools(config_path: Optional[str] = None) -> dict[str, Any]:
    """Return the callable tool implementations (usable with or without the MCP SDK)."""
    platform = build_platform(config_path)

    # ================================================================== #
    # LAYER 1 — Knowledge: rule registry + the 6 MCP datasets (§10)
    # ================================================================== #
    def list_rules(shard: Optional[str] = None, tactic: Optional[str] = None) -> list[dict]:
        """List rules in the registry, each with its id, title, owning shard, severity,
        and full taxonomy (MITRE tactic+technique, OWASP, CIS, NSA/CISA tags). Optionally
        filter to one domain shard (e.g. 'rbac_identity') and/or one MITRE tactic (e.g.
        'Privilege Escalation'). Use this to discover valid rule_id values for
        preview_scan/run_scan's `rule_ids` selector, or to browse what a shard covers."""
        rules = platform.registry.rules.all()
        if shard:
            rules = [r for r in rules if r.owning_shard == shard]
        if tactic:
            rules = [r for r in rules
                     if any(m.tactic.value.lower() == tactic.lower() for m in r.mitre)]
        return [r.metadata() for r in rules]

    def resolve_selector(tactics: Optional[list[str]] = None,
                         techniques: Optional[list[str]] = None,
                         modules: Optional[list[str]] = None,
                         aliases: Optional[list[str]] = None,
                         frameworks: Optional[list[str]] = None,
                         rule_ids: Optional[list[str]] = None) -> list[str]:
        """Resolve a selector (any combination of MITRE tactics, techniques/composite
        aliases like 'Container Escape', domain modules, compliance frameworks, or exact
        rule ids) to the concrete list of rule ids it expands to — WITHOUT scanning
        anything. Lower-level than preview_scan (no scope, no shard breakdown); use this
        when you only need the raw rule_id list, e.g. to feed into another tool."""
        sel = Selector(tactics=tactics or [], techniques=techniques or [],
                       modules=modules or [], aliases=aliases or [],
                       frameworks=frameworks or [], rule_ids=rule_ids or [])
        return platform.mapping.resolve(sel)

    def get_kubectl_command(name: str) -> str:
        """Look up ONE named kubectl security-inspection one-liner from the kubectl
        Security Commands dataset (e.g. 'list-privileged-pods', 'cluster-admin-bindings').
        Returns '' if the name isn't found — call list_kubectl_commands() first to see
        every available name and its command."""
        return datasets.KUBECTL_COMMANDS.get(name, "")

    def list_kubectl_commands() -> dict:
        """List every named kubectl security-inspection command in the dataset (name ->
        the full command, e.g. jq-piped one-liners to list privileged pods, cluster-admin
        bindings, wildcard ClusterRoles, NodePort services, mutating webhooks, ...). Use
        this to discover what's available before calling get_kubectl_command(name)."""
        return dict(datasets.KUBECTL_COMMANDS)

    def get_tool_commands(tool: str) -> list:
        """Look up the example invocation(s) for ONE named external security tool (e.g.
        'trivy', 'kube-bench', 'kubescape', 'cosign', 'trufflehog'). Returns [] if the
        tool name isn't found — call list_tool_commands() to see every available name."""
        return datasets.TOOL_COMMANDS.get(tool, [])

    def list_tool_commands() -> dict:
        """List every external security tool in the dataset with its example
        invocation(s) (trivy, kube-bench, kubeaudit, kubesec, kubescape, popeye,
        trufflehog, cosign). These are the tools k8smatrixwarden integrates as normalizing
        adapters (§22) — this dataset is how to run them directly."""
        return dict(datasets.TOOL_COMMANDS)

    def get_playbook(ref: str) -> dict:
        """Look up ONE remediation playbook by its ref string (a rule's
        `remediation_ref`, e.g. 'playbook/downgrade-binding') — returns {title,
        commands}. Only covers playbooks with a fixed, unambiguous target kind (a
        ClusterRoleBinding, NetworkPolicy, Namespace, ...); Pod-template fixes
        (securityContext, host namespaces, ...) are resource/owner-dependent and are
        NOT here — use explain_remediation or a real run_scan finding for those
        instead. Call list_playbooks() to see every ref, including which kind each is."""
        return datasets.PLAYBOOKS.get(ref, {})

    def list_playbooks() -> dict:
        """List every remediation playbook, both kinds: 'static' ones (a fixed command
        template for an unambiguous target kind — get_playbook(ref) returns their full
        command) and 'schema-aware' ones (a Pod-template field fix whose actual command
        depends on the resource's owning controller — resolved per-finding by
        explain_remediation or run_scan, never a single fixed string here)."""
        from ..core.remediation_engine import FIELD_PATCHES
        out = {ref: {"title": pb.get("title"), "kind": "static",
                    "commands": pb.get("commands", [])}
              for ref, pb in datasets.PLAYBOOKS.items()}
        out.update({ref: {"title": fp.title, "kind": "schema-aware",
                          "note": "resolved per-resource (owner-aware, schema-validated) "
                                  "— call explain_remediation to see the concrete "
                                  "command for a specific resource, or read it off a "
                                  "real finding's `remediation` field from run_scan"}
                   for ref, fp in FIELD_PATCHES.items()})
        return out

    def lookup_cve(cve_id: str) -> dict:
        """Look up ONE CVE by id (e.g. 'CVE-2024-9486') in the bundled Kubernetes CVE
        knowledge base — returns {severity, affects, desc}, or {} if not found. This is
        a curated subset (§15.1), not a live feed — call list_cves() to see every id
        that's actually in it before assuming a lookup miss means "not vulnerable"."""
        return datasets.CVE_KB.get(cve_id.upper(), {})

    def list_cves() -> dict:
        """List every CVE in the bundled Kubernetes CVE knowledge base, each with its
        severity, affected version range, and a one-line description."""
        return dict(datasets.CVE_KB)

    def get_compliance_ruleset(framework: Optional[str] = None) -> dict:
        """Get metadata about a compliance framework k8smatrixwarden tracks — 'CIS' (version,
        tool, pass threshold), 'PSS' (Pod Security Standard levels), or 'NSA_CISA' (the
        hardening-guide sections covered). Omit `framework` to get all three. This is
        summary metadata, not the controls themselves — for the full, evaluated CIS
        Kubernetes Benchmark (all 130 controls with PASS/FAIL/MANUAL/NA/NEEDS_NODE
        status), use run_cis_benchmark instead."""
        if framework:
            return datasets.COMPLIANCE_RULES.get(framework.upper(), {})
        return dict(datasets.COMPLIANCE_RULES)

    def get_taxonomy() -> dict:
        """Get the vendored MITRE ATT&CK for Containers technique catalog (the
        machine-readable technique ids/names every rule's `mitre` tags are validated
        against) plus the current rule-count-per-tactic coverage snapshot."""
        return {"techniques": platform.taxonomy.get("techniques", []),
                "coverage": platform.coverage()}

    def mitre_coverage() -> dict:
        """Get the number of registered rules per MITRE ATT&CK tactic (all 9: Initial
        Access, Execution, Persistence, Privilege Escalation, Defense Evasion,
        Credential Access, Discovery, Lateral Movement, Impact) — a quick "how well
        covered is each attacker behavior" snapshot, same data k8smatrixwarden's `coverage`
        CLI command and chat's "coverage" turn show."""
        return platform.coverage()

    def list_shards() -> list[dict]:
        """List the 10 domain shards (the scanner's execution boundary — RBAC, network,
        secrets, images, workload/pod security, control plane, compliance, attack
        surface, admission control, cloud IAM) with each shard's title and rule count.
        Shard names are the valid values for preview_scan/run_scan's `modules` selector
        and this tool's own `shard` filter on list_rules."""
        out = []
        for shard_name in platform.registry.shard_names():
            shard = platform.registry.get_shard(shard_name)
            rules = platform.registry.rules.by_shard(shard_name)
            out.append({"name": shard_name, "title": getattr(shard, "title", shard_name),
                       "index": getattr(shard, "index", ""), "rule_count": len(rules)})
        return out

    def list_namespaces(mock: bool = True, fixture: Optional[str] = None,
                        kubeconfig: Optional[str] = None,
                        context: Optional[str] = None) -> dict:
        """List namespace names visible in the target cluster (mock or live) — use this
        before scoping a scan to a namespace, to avoid guessing a name that doesn't
        exist (preview_scan/run_scan won't validate it for you, they'll just find
        nothing)."""
        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
            ev = collector.collect({"Namespace"}, Scope(ScopeLevel.CLUSTER))
            return {"namespaces": [n for n in ev.namespaces() if n]}
        except RuntimeError as exc:
            return {"error": str(exc)}

    def detect_cluster_provider(mock: bool = True, fixture: Optional[str] = None,
                                kubeconfig: Optional[str] = None,
                                context: Optional[str] = None) -> dict:
        """Detect which kind of cluster this is from its Node objects, so the right
        provider-specific choices are made without asking the user. Returns:
          cloud   — 'gcp' | 'aws' | 'azure' | 'local'  (which IaaS the nodes run on)
          managed — True if the control plane is a managed offering (GKE/EKS/AKS)
          profile — 'gke' | 'eks' | 'aks' | 'self-managed'  (pass straight to
                    run_cis_benchmark's `profile`, or leave it 'auto' to do this
                    automatically)
        Reads Node providerID + managed-service labels only — no writes, no control
        plane access. On the bundled mock cluster this returns local/self-managed."""
        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
            ev = collector.collect({"Node"}, Scope(ScopeLevel.CLUSTER))
        except RuntimeError as exc:
            return {"error": str(exc)}
        return detect_provider(ev.get("Node", all_scopes=True))

    def intelligent_scan(query: str, scope_level: str = "cluster",
                         namespace: Optional[str] = None, mock: bool = True,
                         fixture: Optional[str] = None, kubeconfig: Optional[str] = None,
                         context: Optional[str] = None,
                         output_format: str = "json") -> dict:
        """One-call intelligent scan: parse natural language, detect cluster type,
        resolve rules, run scan, return findings + risk + threat matrix.

        query: plain English security question, e.g. 'find exposed secrets',
          'scan for persistence techniques', 'check RBAC for privilege escalation'
        scope_level: cluster | namespace | workload | pod | node | image | helm_release
        namespace: filter scope to one namespace (only if scope_level=cluster/namespace)
        mock: True (default) scans bundled insecure cluster; False scans live cluster
        output_format: json | markdown | html | sarif | text | terminal | pdf

        Returns {intent, scope, selector, rule_count, resolved_rule_ids, cluster_info,
                 findings, risk, total_findings, threat_matrix}. Skips the
        confirm-then-run step — Claude already understood the intent. (If you need
        confirmation UX, use interpret_query + preview_scan instead.)"""
        from ..agents.orchestrator import Orchestrator
        from ..agents.scanner import ScannerAgent

        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
        except RuntimeError as exc:
            return {"error": f"collector: {exc}"}

        # Detect cluster type.
        try:
            ev_nodes = collector.collect({"Node"}, Scope(ScopeLevel.CLUSTER))
            cluster_info = detect_provider(ev_nodes.get("Node", all_scopes=True))
        except Exception:
            cluster_info = {"cloud": "unknown", "managed": False, "profile": "self-managed"}

        # Parse intent.
        try:
            orch = Orchestrator(platform)
            interp = orch.interpret(query)
            intent = interp.intent
            resolved_rule_ids = interp.resolved_rule_ids
            scope = interp.request.scope
        except ValueError as exc:
            return {"error": f"intent parse: {exc}"}
        except Exception as exc:
            return {"error": f"orchestrator: {exc}"}

        # Scan.
        fmt = (output_format or "json").lower()
        if fmt not in _VALID_REPORT_FORMATS:
            return {"error": f"unknown output_format {output_format!r}"}
        try:
            result = ScannerAgent(platform).scan(
                interp.request, collector, mode_label="mock" if mock else "live"
            )
        except Exception as exc:
            return {"error": f"scan: {exc}"}

        # Return findings + metadata in the requested format.
        if fmt == "json":
            doc = json.loads(platform.reporting.json(result))
            doc.update({
                "intent": intent,
                "scope": scope.describe(),
                "rule_count": len(resolved_rule_ids),
                "cluster": cluster_info,
            })
            return doc
        else:
            try:
                content = platform.reporting.render(result, fmt)
            except RuntimeError as exc:
                return {"error": str(exc)}
            return {
                "format": fmt,
                **_encode_report(content),
                "intent": intent,
                "scope": scope.describe(),
                "rule_count": len(resolved_rule_ids),
                "risk": {
                    "cluster_risk": result.risk.cluster_risk,
                    "security_score": result.risk.security_score,
                    "rating": result.risk.rating,
                },
                "total_findings": result.total(),
                "cluster": cluster_info,
            }

    def validate_platform() -> dict:
        """Validate the k8smatrixwarden install itself — equivalent to the `k8smatrixwarden doctor` CLI
        command. Checks: every shard/rule loaded correctly, every rule's MITRE technique
        id exists in the vendored ATT&CK-for-Containers taxonomy, every composite alias
        (e.g. 'Container Escape') resolves to real rule ids, and there are no duplicate
        rule ids across shards. Call this first if any other tool is behaving
        unexpectedly, or after editing a custom config (`--config`/`config_path`)."""
        return {
            "shards_loaded": len(platform.registry.shard_names()),
            "shard_names": platform.registry.shard_names(),
            "rules_loaded": platform.rule_count(),
            "valid": not platform.validation_problems,
            "problems": list(platform.validation_problems),
        }

    # ================================================================== #
    # LAYER 2 — Scan / audit / runtime: read-only, mirrors `scan` / `cis` / Runtime Agent
    # ================================================================== #
    def _make_scope(scope_level: Optional[str], namespace: Optional[str],
                    name: Optional[str], kind: Optional[str],
                    image: Optional[str]) -> Scope:
        key = (scope_level or "cluster").strip().lower().replace("-", "_")
        try:
            level = ScopeLevel(key)
        except ValueError:
            level = ScopeLevel.CLUSTER
        return Scope(level=level, namespace=namespace, name=name, kind=kind, image=image)

    def _make_selector(tactics, techniques, modules, rule_ids, aliases, frameworks,
                       severity_min) -> Selector:
        sev = Severity.parse(severity_min) if severity_min else None
        return Selector(tactics=tactics or [], techniques=techniques or [],
                        modules=modules or [], rule_ids=rule_ids or [],
                        aliases=aliases or [], frameworks=frameworks or [],
                        severity_min=sev)

    def preview_scan(scope_level: str = "cluster", namespace: Optional[str] = None,
                     name: Optional[str] = None, kind: Optional[str] = None,
                     image: Optional[str] = None, tactics: Optional[list[str]] = None,
                     techniques: Optional[list[str]] = None,
                     modules: Optional[list[str]] = None,
                     rule_ids: Optional[list[str]] = None,
                     aliases: Optional[list[str]] = None,
                     frameworks: Optional[list[str]] = None,
                     severity_min: Optional[str] = None) -> dict:
        """Resolve a scan's scope+selector to the exact rule set WITHOUT touching the
        cluster or running anything — the plan-before-you-scan step (mirrors `scan
        --dry-run` / the chat's confirmation prompt). Call this first, show the user
        what would run, then call run_scan with the same arguments to execute it."""
        scope = _make_scope(scope_level, namespace, name, kind, image)
        try:
            selector = _make_selector(tactics, techniques, modules, rule_ids, aliases,
                                      frameworks, severity_min)
            resolved = platform.mapping.resolve(selector)
        except ValueError as exc:
            return {"error": str(exc)}
        shards = sorted({platform.registry.rules.get(r).owning_shard for r in resolved
                         if platform.registry.rules.get(r)})
        return {"scope": scope.describe(), "selector": selector.describe(),
               "rule_count": len(resolved), "resolved_rule_ids": resolved,
               "shards": shards}

    def run_scan(scope_level: str = "cluster", namespace: Optional[str] = None,
                name: Optional[str] = None, kind: Optional[str] = None,
                image: Optional[str] = None, tactics: Optional[list[str]] = None,
                techniques: Optional[list[str]] = None,
                modules: Optional[list[str]] = None,
                rule_ids: Optional[list[str]] = None,
                aliases: Optional[list[str]] = None,
                frameworks: Optional[list[str]] = None,
                severity_min: Optional[str] = None, mock: bool = True,
                fixture: Optional[str] = None, kubeconfig: Optional[str] = None,
                context: Optional[str] = None, output_format: str = "json",
                save: bool = False, reports_dir: str = "k8smatrixwarden-reports",
                max_findings: Optional[int] = None) -> dict:
        """Run a k8smatrixwarden security scan (read-only) — mirrors `k8smatrixwarden scan`.

        scope_level: cluster | namespace | workload | node | pod | image | helm_release
        tactics/techniques/modules/rule_ids/aliases/frameworks: selector axes, union'd
          together (same semantics as the CLI's repeatable --tactic/--technique/... flags)
        mock: True (default) scans the bundled insecure mock cluster. False scans a real
          cluster and requires the 'kubernetes' extra + a reachable kubeconfig/context.
        output_format: 'json' (default) returns structured findings + risk score +
          per-finding remediation. Any of 'markdown'|'html'|'sarif'|'text'|'terminal'
          instead returns {scan_id, format, content, risk, total_findings} where
          `content` is the fully rendered report string — e.g. ask for 'markdown' to get
          a shareable report, or 'sarif' for a CI/GitHub-Code-Scanning-ready result.
          'pdf' returns {..., content_base64, encoding: "base64"} instead of `content`
          (PDF is binary; base64-decode it and write the bytes to a .pdf file yourself —
          requires the optional `pdf` extra installed server-side, `pip install -e
          ".[pdf]"`, or this returns an `error`).
        save: persist this scan to the report store (default dir './k8smatrixwarden-reports')
          so it can be listed later with list_reports and re-exported in a DIFFERENT
          format later with download_report, without re-scanning.
        max_findings: optionally cap how many findings are returned in JSON mode (all
          are still counted in the risk score / summary; only the returned list is
          truncated). Ignored for non-JSON output_format.
        """
        from ..agents.scanner import ScannerAgent

        fmt = (output_format or "json").lower()
        if fmt not in _VALID_REPORT_FORMATS:
            return {"error": f"unknown output_format {output_format!r} — valid values: "
                             f"{', '.join(sorted(_VALID_REPORT_FORMATS))}"}

        scope = _make_scope(scope_level, namespace, name, kind, image)
        try:
            selector = _make_selector(tactics, techniques, modules, rule_ids, aliases,
                                      frameworks, severity_min)
        except ValueError as exc:
            return {"error": str(exc)}

        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
        except RuntimeError as exc:
            return {"error": str(exc)}

        request = ScanRequest(scope=scope, selector=selector, mode=ScanMode.SYNC)
        try:
            result = ScannerAgent(platform).scan(
                request, collector, mode_label="mock" if mock else "live")
        except Exception as exc:
            return {"error": f"scan failed: {exc}"}

        if save:
            from ..core.report_store import ReportStore
            ReportStore(reports_dir).save(result)

        if fmt != "json":
            try:
                content = platform.reporting.render(result, fmt)
            except RuntimeError as exc:
                return {"error": str(exc)}
            return {"scan_id": result.scan_id, "format": fmt,
                   **_encode_report(content), "saved": save,
                   "risk": {"cluster_risk": result.risk.cluster_risk,
                           "security_score": result.risk.security_score,
                           "rating": result.risk.rating},
                   "total_findings": result.total()}

        doc = json.loads(platform.reporting.json(result))
        if max_findings is not None and len(doc["findings"]) > max_findings:
            doc["findings"] = doc["findings"][:max_findings]
            doc["findings_truncated"] = True
        doc["saved"] = save
        return doc

    def interpret_query(text: str) -> dict:
        """Parse a natural-language security request (e.g. 'scan production for
        persistence', 'any exposed secrets?') into scope/selector and the resolved rule
        plan, WITHOUT executing it — the exact parsing `k8smatrixwarden chat` uses before it asks
        for confirmation. Follow up with run_scan using the returned scope/selector to
        actually execute it."""
        from ..agents.orchestrator import Orchestrator
        orch = Orchestrator(platform)
        interp = orch.interpret(text)
        return {
            "intent": interp.intent,
            "scope": interp.request.scope.describe(),
            "selector": interp.request.selector.describe(),
            "rule_count": len(interp.resolved_rule_ids),
            "resolved_rule_ids": interp.resolved_rule_ids,
            "notes": interp.notes,
            "plan_summary": orch.confirmation_summary(interp),
        }

    def intelligent_scan(query: str, scope_level: Optional[str] = None,
                         namespace: Optional[str] = None, name: Optional[str] = None,
                         kind: Optional[str] = None, image: Optional[str] = None,
                         mock: bool = True, fixture: Optional[str] = None,
                         kubeconfig: Optional[str] = None, context: Optional[str] = None,
                         max_findings: Optional[int] = None,
                         include_attack_path: bool = True) -> dict:
        """One call, everything: parse a plain-English request into scope+selector, detect
        which kind of cluster it is, run the read-only scan, and return the findings, risk,
        threat matrix, and a kill-chain attack path — the composed shortcut for
        detect_cluster_provider + interpret_query + run_scan + build_threat_matrix +
        build_attack_path done by hand. The query drives scope/selector; pass any explicit
        scope arg (namespace/name/kind/image, or a non-cluster scope_level) to override
        what the query inferred. Returns: intent, scope, selector, rule_count, notes;
        `cluster` (detected cloud + CIS profile); `findings` + `risk` + embedded
        `threat_matrix`; and `attack_path` (the exploit chain; omit with
        include_attack_path=False). Use this to just ask and get the analysis — use
        preview_scan then run_scan when you need to confirm the plan before scanning."""
        from ..agents.orchestrator import Orchestrator
        from ..core.threat_matrix import build_threat_matrix as _build, attack_paths

        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
        except RuntimeError as exc:
            return {"error": str(exc)}
        orch = Orchestrator(platform)
        interp = orch.interpret(query)
        request = interp.request
        # Explicit scope args win over what the query inferred.
        if any((namespace, name, kind, image)) or (scope_level and scope_level != "cluster"):
            request.scope = _make_scope(scope_level or "cluster", namespace, name, kind, image)
        try:
            result = orch.run(request, collector,
                              mode_label="mock" if mock else "live")
        except Exception as exc:
            return {"error": f"scan failed: {exc}"}

        doc = json.loads(platform.reporting.json(result))
        if max_findings is not None and len(doc["findings"]) > max_findings:
            doc["findings"] = doc["findings"][:max_findings]
            doc["findings_truncated"] = True
        nodes = collector.collect({"Node"}, Scope(ScopeLevel.CLUSTER)).get(
            "Node", all_scopes=True)
        doc.update({
            "intent": interp.intent,
            "scope": request.scope.describe(),
            "selector": request.selector.describe(),
            "rule_count": len(interp.resolved_rule_ids),
            "notes": interp.notes,
            "cluster": detect_provider(nodes),
        })
        if include_attack_path:
            doc["attack_path"] = attack_paths(_build(result, platform.registry.rules))
        return doc

    def run_cis_benchmark(mock: bool = True, fixture: Optional[str] = None,
                          kubeconfig: Optional[str] = None, context: Optional[str] = None,
                          profile: str = "auto",
                          kube_bench_json: Optional[str] = None) -> dict:
        """Run the full CIS Kubernetes Benchmark v1.8 (130 controls, read-only) and
        return the report (PASS/FAIL/MANUAL/NA/NEEDS_NODE per control). Mirrors
        `k8smatrixwarden cis`. profile: auto (default) | self-managed | eks | gke | aks —
        'auto' detects the provider from Node objects (see detect_cluster_provider);
        managed profiles mark the provider-owned control plane NA instead of ungradeable.
        kube_bench_json: optional path to `kube-bench --json` output to resolve node
        file-permission controls that the K8s API alone cannot see."""
        from ..frameworks.cis import CISBenchmarkEngine
        from ..frameworks.kube_bench_adapter import maybe_load

        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
        except RuntimeError as exc:
            return {"error": str(exc)}
        if profile == "auto":
            ev = collector.collect({"Node"}, Scope(ScopeLevel.CLUSTER))
            profile = detect_provider(ev.get("Node", all_scopes=True))["profile"]
        kb = maybe_load(kube_bench_json)
        report = CISBenchmarkEngine(platform).evaluate(collector, kube_bench_results=kb,
                                                        profile=profile)
        return report.as_dict()

    def evaluate_runtime_events(events: list[dict]) -> list[dict]:
        """Evaluate a batch of runtime events (Falco-style syscall events or Kubernetes
        audit events) against the Runtime Agent's rule catalog (§8) and return any
        alerts that fired. Each event needs a `source` key of 'falco' or 'audit' plus
        the relevant fields for that source — Falco: `proc` (process name), `connect`
        (dest addr:port), `file`, `op`; audit: `verb`, `resource`, `namespace`, `count`.
        Detects: shell-in-container, metadata-API access, network-recon tools,
        crypto-miner signatures, container-escape indicators, log tampering, new
        (Cluster)RoleBindings, exec into kube-system, secret enumeration, event
        deletion, and mass-delete spikes. This evaluates a batch you provide — it does
        NOT tail a live cluster (there is no running Runtime Agent DaemonSet here)."""
        from ..agents.runtime import RuntimeAgent
        alerts = RuntimeAgent().evaluate_stream(events)
        return [{"rule_id": a.rule_id, "title": a.title, "severity": a.severity.label,
                "tactic": a.tactic, "surface": a.surface, "source": a.source,
                "event": a.event} for a in alerts]

    def correlate_runtime(events: list[dict], scan_id: Optional[str] = None,
                          scope_level: str = "cluster", namespace: Optional[str] = None,
                          name: Optional[str] = None, kind: Optional[str] = None,
                          image: Optional[str] = None, tactics: Optional[list[str]] = None,
                          techniques: Optional[list[str]] = None,
                          modules: Optional[list[str]] = None,
                          rule_ids: Optional[list[str]] = None,
                          aliases: Optional[list[str]] = None,
                          frameworks: Optional[list[str]] = None,
                          severity_min: Optional[str] = None, mock: bool = True,
                          fixture: Optional[str] = None, kubeconfig: Optional[str] = None,
                          context: Optional[str] = None,
                          reports_dir: str = "k8smatrixwarden-reports") -> dict:
        """Correlate a batch of runtime events against a scan's static findings — the
        "which weakness is being exploited RIGHT NOW" view. Evaluates `events` (same
        Falco/audit shape as evaluate_runtime_events) into runtime alerts, then joins them
        to scan findings by MITRE tactic (and namespace, when the event names one).
        Returns per-correlation `confidence` — 'confirmed' (same tactic + same namespace:
        the static weakness is being acted on), 'corroborated' (same tactic: behaviour
        aligns with a known gap), or 'runtime-only' (live behaviour the scan never
        predicted) — plus headline counts (confirmed_exploitation, correlated,
        runtime_only). scan_id: correlate against a saved report; otherwise runs a fresh
        read-only scan (same scope/selector args as run_scan)."""
        from ..agents.runtime import RuntimeAgent
        from ..core.correlation import correlate

        if scan_id:
            from ..core.report_store import ReportStore
            try:
                result = ReportStore(reports_dir).resolve(scan_id)
            except FileNotFoundError:
                return {"error": f"no stored report with scan-id {scan_id!r}"}
            if result is None:
                return {"error": f"no stored reports in {reports_dir!r}"}
        else:
            from ..agents.scanner import ScannerAgent
            scope = _make_scope(scope_level, namespace, name, kind, image)
            try:
                selector = _make_selector(tactics, techniques, modules, rule_ids, aliases,
                                          frameworks, severity_min)
                collector = platform.make_collector(mock=mock, fixture=fixture,
                                                    kubeconfig=kubeconfig, context=context)
            except (ValueError, RuntimeError) as exc:
                return {"error": str(exc)}
            request = ScanRequest(scope=scope, selector=selector, mode=ScanMode.SYNC)
            try:
                result = ScannerAgent(platform).scan(
                    request, collector, mode_label="mock" if mock else "live")
            except Exception as exc:
                return {"error": f"scan failed: {exc}"}
        alerts = RuntimeAgent().evaluate_stream(events or [])
        return correlate(result.findings, alerts)

    def detect_drift(events: list[dict], namespace: Optional[str] = None,
                     mock: bool = True, fixture: Optional[str] = None,
                     kubeconfig: Optional[str] = None,
                     context: Optional[str] = None) -> dict:
        """Detect runtime behaviour that CONTRADICTS a Pod's declared security posture —
        the strongest exploitation signal, because it means a control the operator thinks
        is enforced is not. Fetches Pod specs (optionally scoped to `namespace`), reads
        each pod's promise (runAsNonRoot / readOnlyRootFilesystem / not-privileged), then
        checks `events` against the pod they name (Falco k8s.pod.name enrichment; events
        that don't name a scanned pod are skipped). Flags: process as uid 0 despite
        runAsNonRoot; write outside tmp despite readOnlyRootFilesystem; a privileged-only
        op (nsenter/mount/release_agent) from a non-privileged pod. Returns drift findings
        (each CRITICAL: declared vs observed vs pod) + counts. Read-only."""
        from ..core.correlation import detect_drift as _drift

        level = ScopeLevel.NAMESPACE if namespace else ScopeLevel.CLUSTER
        scope = Scope(level=level, namespace=namespace)
        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
            ev = collector.collect({"Pod"}, scope)
        except RuntimeError as exc:
            return {"error": str(exc)}
        return _drift(ev.get("Pod"), events or [])

    def list_runtime_detections() -> list[dict]:
        """List the Runtime Agent's detection catalog (§8) — every rule tagged
        surface='runtime', i.e. what is caught by observing a LIVE stream (Falco/Tetragon
        syscalls, K8s audit events, container drift) rather than by a point-in-time scan.
        This is the runtime half of the runtime-vs-scan split: the Scanner's rules
        (list_rules) all carry surface='scan'. Each entry has id, title, severity, source
        (falco | audit | drift), and MITRE tactic/technique. Use evaluate_runtime_events to
        actually match a batch of events against these."""
        from ..agents.runtime import RuntimeAgent
        return RuntimeAgent().catalog()

    def explain_remediation(rule_id: str, resource_kind: str, resource_name: str,
                            namespace: Optional[str] = None,
                            owner_kind: Optional[str] = None,
                            owner_name: Optional[str] = None,
                            labels: Optional[dict] = None,
                            annotations: Optional[dict] = None) -> dict:
        """Get the full schema-aware, resource-aware remediation for a HYPOTHETICAL
        finding, without running a scan — useful when you already know the rule and the
        resource (e.g. from a finding you saw earlier, or a resource you're describing
        by hand) and just want the correctly-targeted fix. Given a rule_id (see
        list_rules) and the affected resource's kind/name/namespace, plus its owning
        controller (owner_kind/owner_name — e.g. a Pod owned by a DaemonSet) and
        labels/annotations if known (for Helm/ArgoCD/Flux detection), returns the same
        RemediationResult shape a real finding gets: root cause, risk, whether it's
        safely automatable, the exact validated kubectl command (only if it is),
        alternative YAML, validation/rollback commands, and warnings (e.g. system-
        workload or GitOps-managed). If owner_kind/owner_name are omitted for a Pod,
        it's treated as standalone — which correctly makes most security-context fixes
        NOT automatable (Pod specs are immutable after creation); this is intentional,
        not a bug — see core/remediation_engine.py."""
        from ..core.models import ResourceRef
        from ..core.remediation_engine import generate_remediation

        rule = platform.registry.rules.get(rule_id)
        if rule is None:
            return {"error": f"unknown rule id {rule_id!r} — see list_rules()"}
        res = ResourceRef(kind=resource_kind, name=resource_name, namespace=namespace,
                          owner_kind=owner_kind, owner_name=owner_name,
                          labels=labels or {}, annotations=annotations or {})
        finding = rule.finding(res, f"(hypothetical) {rule.title}")
        return generate_remediation(finding).as_dict()

    def build_threat_matrix(scope_level: str = "cluster", namespace: Optional[str] = None,
                            name: Optional[str] = None, kind: Optional[str] = None,
                            image: Optional[str] = None,
                            tactics: Optional[list[str]] = None,
                            techniques: Optional[list[str]] = None,
                            modules: Optional[list[str]] = None,
                            rule_ids: Optional[list[str]] = None,
                            aliases: Optional[list[str]] = None,
                            frameworks: Optional[list[str]] = None,
                            severity_min: Optional[str] = None,
                            scan_id: Optional[str] = None, coverage: bool = False,
                            mock: bool = True, fixture: Optional[str] = None,
                            kubeconfig: Optional[str] = None, context: Optional[str] = None,
                            reports_dir: str = "k8smatrixwarden-reports") -> dict:
        """Project findings onto the Kubernetes Threat Matrix (the 9-tactic
        Microsoft/Redguard matrix, MITRE ATT&CK for Containers, §12) and return the full
        structure: a `summary` (tactics/techniques hit, coverage %) plus `columns` — one
        per tactic, each a list of technique `cells` with state gap|covered|hit, worst
        severity, finding count, mapped resources, and the ATT&CK reference URL. This is
        the same matrix the HTML report/web dashboard heatmap and the JSON report's
        `threat_matrix` block use.

        Three modes:
          • scan_id set        → build the matrix from a previously saved report (no rescan)
          • coverage=True      → the GLOBAL detection-coverage matrix (which techniques any
                                 rule can detect at all), with no scan overlaid
          • otherwise (default)→ run a fresh read-only scan with the given scope/selector
                                 (same args as run_scan) and overlay its findings

        Cells are painted three ways: `hit` (a finding fired — coloured by worst severity),
        `covered` (a rule exists but nothing fired this scan), `gap` (no rule yet — an
        honest, un-hidden coverage hole)."""
        from ..core.threat_matrix import build_threat_matrix as _build

        if coverage:
            from ..web.app import _empty_result
            return _build(_empty_result(platform), platform.registry.rules).as_dict()

        if scan_id:
            from ..core.report_store import ReportStore
            try:
                result = ReportStore(reports_dir).resolve(scan_id)
            except FileNotFoundError:
                return {"error": f"no stored report with scan-id {scan_id!r}"}
            if result is None:
                return {"error": f"no stored reports in {reports_dir!r}"}
            return _build(result, platform.registry.rules).as_dict()

        from ..agents.scanner import ScannerAgent
        scope = _make_scope(scope_level, namespace, name, kind, image)
        try:
            selector = _make_selector(tactics, techniques, modules, rule_ids, aliases,
                                      frameworks, severity_min)
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
        except (ValueError, RuntimeError) as exc:
            return {"error": str(exc)}
        request = ScanRequest(scope=scope, selector=selector, mode=ScanMode.SYNC)
        try:
            result = ScannerAgent(platform).scan(
                request, collector, mode_label="mock" if mock else "live")
        except Exception as exc:
            return {"error": f"scan failed: {exc}"}
        return _build(result, platform.registry.rules).as_dict()

    def build_attack_path(scope_level: str = "cluster", namespace: Optional[str] = None,
                          name: Optional[str] = None, kind: Optional[str] = None,
                          image: Optional[str] = None, tactics: Optional[list[str]] = None,
                          techniques: Optional[list[str]] = None,
                          modules: Optional[list[str]] = None,
                          rule_ids: Optional[list[str]] = None,
                          aliases: Optional[list[str]] = None,
                          frameworks: Optional[list[str]] = None,
                          severity_min: Optional[str] = None,
                          scan_id: Optional[str] = None, mock: bool = True,
                          fixture: Optional[str] = None, kubeconfig: Optional[str] = None,
                          context: Optional[str] = None,
                          reports_dir: str = "k8smatrixwarden-reports") -> dict:
        """Chain a scan's threat-matrix HIT cells into a kill-chain exploit path — the
        tactics an attacker can actually string together in THIS cluster, Initial Access
        -> ... -> Impact. Returns `chain` (the tactic sequence), `steps` (per tactic: the
        available techniques, their worst severity, the exposing resources, and finding
        rule ids), `entry_points` (the first step's techniques — where the chain starts),
        and `reaches_impact` (does the chain terminate in the Impact tactic). scan_id:
        build from a previously saved report; otherwise runs a fresh read-only scan (same
        scope/selector args as run_scan). A coverage-only matrix has no hits, so no path."""
        from ..core.threat_matrix import build_threat_matrix as _build, attack_paths

        if scan_id:
            from ..core.report_store import ReportStore
            try:
                result = ReportStore(reports_dir).resolve(scan_id)
            except FileNotFoundError:
                return {"error": f"no stored report with scan-id {scan_id!r}"}
            if result is None:
                return {"error": f"no stored reports in {reports_dir!r}"}
        else:
            from ..agents.scanner import ScannerAgent
            scope = _make_scope(scope_level, namespace, name, kind, image)
            try:
                selector = _make_selector(tactics, techniques, modules, rule_ids, aliases,
                                          frameworks, severity_min)
                collector = platform.make_collector(mock=mock, fixture=fixture,
                                                    kubeconfig=kubeconfig, context=context)
            except (ValueError, RuntimeError) as exc:
                return {"error": str(exc)}
            request = ScanRequest(scope=scope, selector=selector, mode=ScanMode.SYNC)
            try:
                result = ScannerAgent(platform).scan(
                    request, collector, mode_label="mock" if mock else "live")
            except Exception as exc:
                return {"error": f"scan failed: {exc}"}
        return attack_paths(_build(result, platform.registry.rules))

    # ================================================================== #
    # LAYER 3 — Reports: persist + list + export in any format (§16.4)
    # ================================================================== #
    def list_reports(reports_dir: str = "k8smatrixwarden-reports",
                     limit: Optional[int] = None) -> list[dict]:
        """List previously saved scan reports (from a run_scan call with save=True) —
        mirrors `k8smatrixwarden report list`. Each entry has the scan_id (needed for
        download_report), when it was generated, its rating/risk score, total finding
        count, and scope. Returns [] if nothing has been saved yet in `reports_dir`."""
        from ..core.report_store import ReportStore
        store = ReportStore(reports_dir)
        return [{"scan_id": r.scan_id, "generated_at": r.generated_at,
                "rating": r.rating, "risk_score": r.risk_score,
                "total_findings": r.total, "scope": r.scope}
               for r in store.list(limit=limit)]

    def download_report(scan_id: Optional[str] = None, format: str = "markdown",
                        reports_dir: str = "k8smatrixwarden-reports") -> dict:
        """Re-render a previously saved scan report in ANY format, without re-scanning —
        mirrors `k8smatrixwarden report download`. This is how to get the same scan as a
        markdown write-up for a PR, a SARIF file for CI, and an HTML page for a
        stakeholder, all from one run_scan(save=True) call. Omit scan_id for the most
        recent saved report. format: terminal | text | markdown | json | sarif | html |
        pdf. Returns {scan_id, format, content} — `content` is the full rendered report
        string; write it to a file yourself if you need it on disk. For format='pdf',
        the response has `content_base64` (+ `encoding: "base64"`) instead of `content`,
        since PDF is binary — base64-decode it before writing. Returns an `error` key
        instead if nothing has been saved yet, the given scan_id isn't found, or (for
        pdf) the optional `pdf` extra isn't installed server-side."""
        fmt = (format or "markdown").lower()
        if fmt not in _VALID_REPORT_FORMATS:
            return {"error": f"unknown format {format!r} — valid values: "
                             f"{', '.join(sorted(_VALID_REPORT_FORMATS))}"}
        from ..core.report_store import ReportStore
        store = ReportStore(reports_dir)
        try:
            result = store.resolve(scan_id)
        except FileNotFoundError:
            return {"error": f"no stored report with scan-id {scan_id!r} in "
                             f"{reports_dir!r}"}
        if result is None:
            return {"error": f"no stored reports in {reports_dir!r} — call "
                             f"run_scan(save=True) first"}
        try:
            content = platform.reporting.render(result, fmt)
        except RuntimeError as exc:
            return {"error": str(exc)}
        return {"scan_id": result.scan_id, "format": fmt, **_encode_report(content)}

    # ================================================================== #
    # LAYER 4 — Platform: least-privilege RBAC generation
    # ================================================================== #
    def generate_rbac_manifest(service_account: str = "k8smatrixwarden-scanner",
                               namespace: str = "k8smatrixwarden-system",
                               create_namespace: bool = True,
                               bind: bool = True) -> dict:
        """Generate the least-privilege RBAC k8smatrixwarden needs to scan a real cluster — every
        verb is get/list/watch, never a write. bind=True returns a full deployable
        manifest (Namespace + ServiceAccount + per-shard ClusterRole/ClusterRoleBinding);
        bind=False returns just the bare ClusterRoles for review. Review before
        `kubectl apply` — this tool only generates the manifest, it never applies it."""
        if bind:
            return platform.loader.deployment_manifest(
                service_account=service_account, namespace=namespace,
                create_namespace=create_namespace)
        return {"cluster_roles": platform.loader.scoped_roles()}

    return {
        # 1. knowledge
        "list_rules": list_rules,
        "resolve_selector": resolve_selector,
        "get_kubectl_command": get_kubectl_command,
        "list_kubectl_commands": list_kubectl_commands,
        "get_tool_commands": get_tool_commands,
        "list_tool_commands": list_tool_commands,
        "get_playbook": get_playbook,
        "list_playbooks": list_playbooks,
        "lookup_cve": lookup_cve,
        "list_cves": list_cves,
        "get_compliance_ruleset": get_compliance_ruleset,
        "get_taxonomy": get_taxonomy,
        "mitre_coverage": mitre_coverage,
        "list_shards": list_shards,
        "list_namespaces": list_namespaces,
        "detect_cluster_provider": detect_cluster_provider,
        "validate_platform": validate_platform,
        # 2. scan / audit / runtime
        "preview_scan": preview_scan,
        "run_scan": run_scan,
        "interpret_query": interpret_query,
        "intelligent_scan": intelligent_scan,
        "run_cis_benchmark": run_cis_benchmark,
        "evaluate_runtime_events": evaluate_runtime_events,
        "correlate_runtime": correlate_runtime,
        "detect_drift": detect_drift,
        "list_runtime_detections": list_runtime_detections,
        "explain_remediation": explain_remediation,
        "build_threat_matrix": build_threat_matrix,
        "build_attack_path": build_attack_path,
        # 3. reports
        "list_reports": list_reports,
        "download_report": download_report,
        # 4. platform
        "generate_rbac_manifest": generate_rbac_manifest,
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
            "k8smatrixwarden.mcp.server.build_tools() without the SDK.")

    tools = build_tools(config_path)
    app = FastMCP("k8smatrixwarden-mcp")
    for name, fn in tools.items():
        app.tool(name=name)(fn)
    app.run()


if __name__ == "__main__":  # pragma: no cover
    serve()
