# K8sMatrixWarden-Dev-1 — Technical Analysis of the Architecture Specification

This document is the pre-implementation technical analysis of
`K8sMatrixWarden v1.0 - MITRE-Aligned Architecture.md`. It maps every architectural
concept in the spec to a concrete Python component before any code is written.

## 1. What the spec actually requires (extracted contracts)

| Spec concept (§) | Concrete obligation | Python realization |
|---|---|---|
| Domain-Sharded Execution (§3.3) | Rules grouped by data source; shard = execution/ownership boundary | `k8smatrixwarden/shards/*` each subclassing `DomainShard` |
| Rule model (§5.1) | Atomic check, self-declares MITRE/OWASP/CIS/NSA tags | `core/models.py::Rule` (+ `Finding`) |
| Rule/Technique Registry (§6.1) | Catalog of all rules; `resolve(selector) → rule_id set` | `core/registry.py::RuleRegistry` |
| MITRE Mapping Engine (§6) | Startup index tactic/technique/framework/alias → rule_ids; validate vs vendored taxonomy | `core/mapping_engine.py::MITREMappingEngine` |
| Scanner Registry (§6.1) | Plugin catalog: resource types + RBAC verbs | `core/registry.py::ScannerRegistry` + `core/plugin.py` |
| Evidence Collector (§6.1) | Scope-aware fetch/cache, **fetch once**, shared snapshot | `core/evidence.py::EvidenceCollector` (+ `Evidence`) |
| Detection Engine (§6.1) | Parallel rule executor over a common interface | `core/detection.py::DetectionEngine` (ThreadPool) |
| External Tool Adapters (§6.1, §22) | Normalize Trivy/kube-bench/… → internal Finding | `core/detection.py::ExternalToolAdapter` interface + hooks in shards |
| Result Aggregator (§6.1) | Dedupe same-object findings, merge tags | `core/aggregator.py::ResultAggregator` |
| Risk Scoring (§18.1) | severity × exploitability × blast_radius × path_multiplier | `core/scoring.py::RiskScoringEngine` |
| Reporting (§18.2) | terminal/md/json/sarif/html, tag-filterable | `core/reporting.py::ReportingEngine` |
| ScanRequest (§4.3) | scope × selector × mode × output | `core/models.py::ScanRequest/Scope/Selector` |
| Orchestrator (§4) | intent → scope → selector → confirm → route | `agents/orchestrator.py` |
| Scanner Agent (§5) | wire registry+evidence+detection+aggregate+score | `agents/scanner.py` |
| Runtime Agent (§8) | Falco/audit/drift rules, same registry pattern | `agents/runtime.py` |
| Remediation Agent (§9) | snapshot → diff → confirm → apply → health → rollback → audit | `agents/remediation.py` |
| MCP Server 6 datasets (§10) | kubectl cmds, tool cmds, playbooks, CVE KB, compliance, taxonomy | `mcp/datasets.py` + `mcp/server.py` |
| Config (§16) | shards/rules/aliases/overrides | `config/default_config.json` |
| Plugin model (§21) | register plugin, tag rule, scoped RBAC | `core/plugin.py` |

## 2. The single most important invariant to preserve

From §3.3/§6.2: **a rule lives in exactly one shard but carries many cross-cutting tags,
and every scan resolves through one registry index to a `rule_id` set.** Therefore:

- Rules must NOT be duplicated per tactic. `hostPath` is one `Rule` tagged with 3 tactics.
- Selector resolution is a set-union over index lookups, never per-request branching.
- Evidence is fetched **once** per scan for the union of the resolved rules' needs.

The code enforces this by making the registry the *only* thing that turns a request into
rules, and the `EvidenceCollector` the *only* thing that touches the cluster.

## 3. Key design decisions (and why)

1. **Pure-stdlib core.** No third-party package is installed in the target environment.
   The engine, rules, CLI, scoring, and reporting use only the standard library so
   `python -m k8smatrixwarden scan --mock` works with zero install. `kubernetes`, `rich`, and the
   `mcp` SDK are *optional* and imported lazily with graceful fallbacks.
2. **Rules as code, data as JSON.** Rules are `Rule` instances built in each shard (fast,
   type-checked, no YAML parser dependency). Taxonomy/config/fixtures are JSON.
3. **camelCase evidence everywhere.** Live mode reads raw K8s API JSON (camelCase) via
   `_preload_content=False`, matching the mock fixtures exactly, so a rule's field access
   (`spec.securityContext.privileged`) is identical in mock and live mode. (The k8s client's
   `to_dict()` would give snake_case and force per-mode branching — deliberately avoided.)
4. **Mock mode is first-class**, not a test hack: default when no kubeconfig is reachable,
   backed by a rich fixture that intentionally trips a wide spread of rules so the pipeline
   is demonstrable end-to-end.
5. **Rules return partial findings via `rule.finding(...)`** and the engine attaches the
   rule's taxonomy automatically — tags are authored once, on the rule (§6.2 anti-drift).

## 4. Scoring model made concrete (§18.1)

```
finding_score = severity_weight × exploitability × blast_radius × path_multiplier
path_multiplier = 1 + 0.25 × (distinct_tactics_on_rule − 1)          # attack-path bonus
cluster_risk (0–10) = 10 × raw / (raw + K)   where raw = Σ finding_score, K = saturation const
security_score (0–100) = round((1 − cluster_risk/10) × 100)
```
Saturation (`raw/(raw+K)`) is used instead of the spec's literal `/max_possible` because
`max_possible` is unbounded/undefined for an arbitrary cluster; saturation is monotonic,
deterministic, bounded to [0,10], and lets a handful of criticals dominate — matching the
rating bands in §18.1. This is called out in REVIEW.md as an intentional refinement.

## 5. Risk / edge cases identified up front

- **Registry must reject duplicate rule ids** and **unknown taxonomy ids** (CI-style
  validation at load, per §6.2) — implemented in `MITREMappingEngine.validate()`.
- **Selector with no matches** must be an explicit, friendly error, not an empty silent scan.
- **Scope+selector intersection**: selector resolves rules; scope constrains evidence and
  filters findings — both applied, never one or the other.
- **Parallel execution** must isolate rule failures (one bad rule can't crash the scan) —
  each rule runs in a guarded task; failures become INFO findings, not crashes (§ Option B
  critique in the redesign doc: a bug in one check must not take down the scan).
- **Cloud IAM shard** needs an external data source; in mock/live-without-cloud it degrades
  to advisory findings from annotations only.

## 6. Build order

models → registry/mapping → evidence → detection → aggregator → scoring → reporting →
plugin → shards → agents → mcp → cli → tests → run → review.
