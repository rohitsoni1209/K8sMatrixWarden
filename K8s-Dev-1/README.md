<h1 align="center">🛡️ k8ssec — K8s Security Tool v3.0</h1>

<p align="center">
  <strong>MITRE ATT&CK-aligned · Domain-Sharded Execution + Cross-Cutting Rule Registry</strong><br/>
  <em>A reference implementation of <code>K8s Security Tool v3.0 - MITRE-Aligned Architecture.md</code></em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue"/>
  <img src="https://img.shields.io/badge/deps-zero%20(stdlib%20core)-brightgreen"/>
  <img src="https://img.shields.io/badge/shards-10-blueviolet"/>
  <img src="https://img.shields.io/badge/rules-56-orange"/>
  <img src="https://img.shields.io/badge/tests-70%20passing-success"/>
</p>

---

## TL;DR

```bash
# no install, no dependencies — runs against a bundled insecure mock cluster
python -m k8ssec scan --mock

# scan by MITRE tactic  (resolves across shards through ONE registry index)
python -m k8ssec scan --tactic Persistence --mock

# scan by technique / outcome alias
python -m k8ssec scan --technique "Container Escape" --mock

# natural language (one-shot)
python -m k8ssec scan "scan production for Persistence" --mock

# interactive chat assistant (back-and-forth, confirm-then-run)
python -m k8ssec chat

# see what a request resolves to WITHOUT scanning
python -m k8ssec scan --module rbac_identity --dry-run
```

## Why this design

The whole tool turns on one idea from the spec (§3.3): **domain shards are the execution
boundary (vertical), MITRE tactics are cross-cutting tags (horizontal), and they are
orthogonal.** A rule like `hostPath mount` lives in **one** shard but is tagged with three
tactics (Persistence + Privilege Escalation + Lateral Movement). Every scan — by resource,
tactic, technique, module, rule, alias, or compliance framework — resolves through a single
registry index to a set of `rule_id`s, then runs against **one shared evidence fetch**.

```
Orchestrator (intent→scope→selector) → Registry.resolve(selector) → rule_id set
   → Evidence Collector (fetch once, scope-constrained) → Detection Engine (parallel)
   → Aggregator (dedupe+merge tags) → Risk Scoring (attack-path aware) → Reporting
```

## Install (optional extras)

The **core needs nothing**. Extras unlock live scanning / prettier output / MCP:

```bash
pip install -e .              # installs the `k8ssec` command
pip install -e ".[live]"      # + kubernetes client for real clusters
pip install -e ".[pretty]"    # + rich terminal tables
pip install -e ".[mcp]"       # + MCP protocol server
```

## Commands

| Command | What it does |
|---|---|
| `k8ssec chat` | **Interactive conversational assistant** (plain-English, confirm-then-run) |
| `k8ssec scan ...` | Run a scan by scope × selector, or a one-shot natural-language query |
| `k8ssec rules [--module M] [--tactic T]` | List the rule registry |
| `k8ssec coverage` | MITRE tactic coverage (rules per tactic) |
| `k8ssec cis ...` | Full **CIS Kubernetes Benchmark v1.8** (all 130 controls) |
| `k8ssec report list / download` | List & re-download saved scans in any format/filename (`scan --save`) |
| `k8ssec roles` | Per-plugin scoped RBAC ClusterRoles (§20/§21) |
| `k8ssec doctor` | Validate taxonomy, aliases, duplicate rule ids |
| `k8ssec mcp [--list-tools]` | Run the MCP server, or list its tools |

### Scan options

```
scope    : --namespace/-n · --pod · --workload KIND/name · --node · --image · --helm-release
selector : --tactic · --technique · --module · --rule · --alias · --framework · --severity-min
mode     : --mock (default) · --live · --fixture PATH · --kubeconfig PATH
output   : -o {terminal,text,markdown,json,sarif,html} · --output-file PATH
flow     : --dry-run · --yes · --fail-on {LOW,MEDIUM,HIGH,CRITICAL}   (CI mode)
```

Examples:

```bash
python -m k8ssec scan -n production --tactic "Credential Access" -o markdown --mock
python -m k8ssec scan --framework CIS -o json --mock
python -m k8ssec scan --technique "Exposed Secrets" --mock
python -m k8ssec scan --live --fail-on CRITICAL -o sarif --output-file results.sarif
```

### Full CIS Kubernetes Benchmark v1.8 (all 130 controls)

```bash
python -m k8ssec cis --mock                          # 130 controls, dashboard + failures
python -m k8ssec cis --kube-bench-json kb.json       # resolve the 31 node file controls
python -m k8ssec cis -o markdown --output-file cis.md
```

Every control gets a status — `PASS` / `FAIL` / `MANUAL` / `NA` / `NEEDS_NODE` — so nothing
is missed. **65 of 130 controls are evaluated straight from the K8s API** (25 native rules +
2 builtin + 38 control-plane/kubelet **process-flag** checks recovered from static-pod specs),
only **31** true file-permission controls need kube-bench (`--kube-bench-json`), and 34 are
CIS-designated manual reviews (surfaced, never auto-passed).

On managed clusters, `--profile eks|gke|aks` marks the provider-owned control plane (sections
1–3) as `NA` instead of grading controls you can't inspect. See the mitigation write-up in the
v3.0 doc §5.9.2. Catalog: `k8ssec/frameworks/cis_catalog.py`.

```bash
python -m k8ssec cis --mock                     # self-managed: NEEDS_NODE = 31 (file only)
python -m k8ssec cis --mock --profile eks        # managed: control plane → NA
python -m k8ssec cis --kube-bench-json kb.json   # + kube-bench → all 130 resolved, NEEDS_NODE 0
```

## Architecture map (code ↔ spec)

| Spec (§) | Code |
|---|---|
| Rule model §5.1 | `k8ssec/core/models.py` (`Rule`, `Finding`, `Scope`, `Selector`, `ScanRequest`) |
| Rule/Technique Registry §6.1 | `k8ssec/core/registry.py` |
| MITRE Mapping Engine §6 | `k8ssec/core/mapping_engine.py` |
| Evidence Collector §6.1 | `k8ssec/core/evidence.py` (mock + live, camelCase) |
| Detection Engine §6.1 | `k8ssec/core/detection.py` (parallel, per-rule isolation) |
| Result Aggregator §6.1 | `k8ssec/core/aggregator.py` |
| Risk Scoring §18.1 | `k8ssec/core/scoring.py` (attack-path bonus) |
| Reporting §18.2 | `k8ssec/core/reporting.py` (6 formats, tag-filterable) |
| Plugin model §21 | `k8ssec/core/plugin.py` |
| 10 Domain Shards §5 | `k8ssec/shards/*` |
| Orchestrator §4 | `k8ssec/agents/orchestrator.py` |
| Scanner Agent §5 | `k8ssec/agents/scanner.py` |
| Runtime Agent §8 | `k8ssec/agents/runtime.py` |
| Remediation Agent §9 | `k8ssec/agents/remediation.py` |
| MCP Server + 6 datasets §10 | `k8ssec/mcp/` |
| Taxonomy (Dataset 6) §6.2 | `k8ssec/taxonomy/*.json` |
| Config §16 | `k8ssec/config/default_config.json` |

## The 10 domain shards

`① cluster_control_plane · ② workload_pod_security · ③ rbac_identity · ④ network_security ·
⑤ image_supply_chain · ⑥ secrets · ⑦ compliance · ⑧ attack_surface · ⑨ admission_control (NEW) ·
⑩ cloud_iam (NEW)`

## Extending

Add a new scanner shard: drop a module in `k8ssec/shards/` exposing `SHARD = YourShard`
(subclass `DomainShard`, implement `rules()`). The Plugin Loader auto-discovers it, the
Mapping Engine auto-indexes its rules' tags, and a scoped RBAC role is generated from its
declared resource needs. **No engine change.** New MITRE technique? add its id to
`taxonomy/attack_for_containers.json` and tag rules with it. New framework? add a `cis:` /
`nsa_cisa:` / `owasp:` tag.

## Tests

```bash
python -m tests.run_tests          # bundled stdlib runner (no pytest needed)
python -m pytest tests/            # also works if pytest is installed
```

## Live scanning

`--live` reads the cluster as raw camelCase JSON via the `kubernetes` client (so rule code
is identical to mock mode). Control-plane flags (`ComponentConfig`) and cloud IAM
(`CloudIAM`) are synthetic buckets — populate them from kube-bench output / the cloud IAM
API respectively for full live coverage. See `REVIEW.md` for the roadmap of live-mode gaps.

## Safety

The Remediation Agent is **dry-run by default** and **never** applies a change without
explicit confirmation (§9 core rule). It snapshots before applying and rolls back on failure.

## Docs in this folder

- **`USAGE.md`** — full usage guide: every command, every flag, copy-paste workflows, CI recipes, troubleshooting
- `ANALYSIS.md` — pre-implementation technical analysis of the v3.0 spec
- `REVIEW.md` — post-implementation review, refinements made, and known limitations
