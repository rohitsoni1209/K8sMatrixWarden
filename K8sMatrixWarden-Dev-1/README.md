<h1 align="center">🛡️ k8smatrixwarden — K8sMatrixWarden v1.0</h1>

<p align="center">
  <strong>MITRE ATT&CK-aligned · Domain-Sharded Execution + Cross-Cutting Rule Registry</strong><br/>
  <em>A reference implementation of the K8sMatrixWarden MITRE-Aligned Architecture</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue"/>
  <img src="https://img.shields.io/badge/deps-zero%20(stdlib%20core)-brightgreen"/>
  <img src="https://img.shields.io/badge/shards-10-blueviolet"/>
  <img src="https://img.shields.io/badge/rules-56-orange"/>
  <img src="https://img.shields.io/badge/MCP%20tools-27-blueviolet"/>
  <img src="https://img.shields.io/badge/tests-196%20passing-success"/>
</p>

---

## TL;DR

```bash
# no install, no dependencies — runs against a bundled insecure mock cluster
python -m k8smatrixwarden scan --mock

# scan by MITRE tactic  (resolves across shards through ONE registry index)
python -m k8smatrixwarden scan --tactic Persistence --mock

# scan by technique / outcome alias
python -m k8smatrixwarden scan --technique "Container Escape" --mock

# natural language (one-shot)
python -m k8smatrixwarden scan "scan production for Persistence" --mock

# interactive chat assistant (back-and-forth, confirm-then-run)
python -m k8smatrixwarden chat

# see what a request resolves to WITHOUT scanning
python -m k8smatrixwarden scan --module rbac_identity --dry-run
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

The **core needs nothing**. Extras unlock live scanning / prettier output / MCP / PDF export:

```bash
pip install -e .              # installs the `k8smatrixwarden` command
pip install -e ".[live]"      # + kubernetes client for real clusters
pip install -e ".[pretty]"    # + rich terminal tables
pip install -e ".[mcp]"       # + MCP protocol server
pip install -e ".[pdf]"       # + fpdf2, for `-o pdf` report export
```

## Commands

| Command | What it does |
|---|---|
| `k8smatrixwarden chat` | **Interactive conversational assistant** (plain-English, confirm-then-run) |
| `k8smatrixwarden scan ...` | Run a scan by scope × selector, or a one-shot natural-language query |
| `k8smatrixwarden web [--port 8080]` | **Security Dashboard** web UI — browse scans, open reports, view the per-scan threat matrix, run a scan |
| `k8smatrixwarden matrix [--coverage]` | Print the **Kubernetes Threat Matrix** for a scan (or global detection coverage) |
| `k8smatrixwarden rules [--module M] [--tactic T]` | List the rule registry (each tagged `surface=scan`) |
| `k8smatrixwarden coverage` | MITRE tactic coverage (rules per tactic) |
| `k8smatrixwarden cis ...` | Full **CIS Kubernetes Benchmark v1.8** (all 130 controls) |
| `k8smatrixwarden report list / download` | List & re-download saved scans in any format/filename (`scan --save`) |
| `k8smatrixwarden roles` | Per-plugin scoped RBAC ClusterRoles (§20/§21) |
| `k8smatrixwarden doctor` | Validate taxonomy, aliases, duplicate rule ids |
| `k8smatrixwarden mcp [--list-tools]` | Run the MCP server, or list its 27 tools |

### Scan options

```
scope    : --namespace/-n · --pod · --workload KIND/name · --node · --image · --helm-release
selector : --tactic · --technique · --module · --rule · --alias · --framework · --severity-min
mode     : --mock (default) · --live · --fixture PATH · --kubeconfig PATH
output   : -o {terminal,text,markdown,json,sarif,html,pdf} · --output-file PATH
flow     : --dry-run · --yes · --fail-on {LOW,MEDIUM,HIGH,CRITICAL}   (CI mode)
```

Examples:

```bash
python -m k8smatrixwarden scan -n production --tactic "Credential Access" -o markdown --mock
python -m k8smatrixwarden scan --framework CIS -o json --mock
python -m k8smatrixwarden scan --technique "Exposed Secrets" --mock
python -m k8smatrixwarden scan --live --fail-on CRITICAL -o sarif --output-file results.sarif
```

### Full CIS Kubernetes Benchmark v1.8 (all 130 controls)

```bash
python -m k8smatrixwarden cis --mock                          # 130 controls, dashboard + failures
python -m k8smatrixwarden cis --kube-bench-json kb.json       # resolve the 31 node file controls
python -m k8smatrixwarden cis -o markdown --output-file cis.md
```

Every control gets a status — `PASS` / `FAIL` / `MANUAL` / `NA` / `NEEDS_NODE` — so nothing
is missed. **65 of 130 controls are evaluated straight from the K8s API** (25 native rules +
2 builtin + 38 control-plane/kubelet **process-flag** checks recovered from static-pod specs),
only **31** true file-permission controls need kube-bench (`--kube-bench-json`), and 34 are
CIS-designated manual reviews (surfaced, never auto-passed).

On managed clusters, `--profile eks|gke|aks` marks the provider-owned control plane (sections
1–3) as `NA` instead of grading controls you can't inspect. See the mitigation write-up in the
architecture doc §5.9.2. Catalog: `k8smatrixwarden/frameworks/cis_catalog.py`.

```bash
python -m k8smatrixwarden cis --mock                     # self-managed: NEEDS_NODE = 31 (file only)
python -m k8smatrixwarden cis --mock --profile eks        # managed: control plane → NA
python -m k8smatrixwarden cis --kube-bench-json kb.json   # + kube-bench → all 130 resolved, NEEDS_NODE 0
```

## Architecture map (code ↔ spec)

| Spec (§) | Code |
|---|---|
| Rule model §5.1 | `k8smatrixwarden/core/models.py` (`Rule`, `Finding`, `Scope`, `Selector`, `ScanRequest`) |
| Rule/Technique Registry §6.1 | `k8smatrixwarden/core/registry.py` |
| MITRE Mapping Engine §6 | `k8smatrixwarden/core/mapping_engine.py` |
| Evidence Collector §6.1 | `k8smatrixwarden/core/evidence.py` (mock + live, camelCase) |
| Detection Engine §6.1 | `k8smatrixwarden/core/detection.py` (parallel, per-rule isolation) |
| Result Aggregator §6.1 | `k8smatrixwarden/core/aggregator.py` |
| Risk Scoring §18.1 | `k8smatrixwarden/core/scoring.py` (attack-path bonus) |
| Reporting §18.2 | `k8smatrixwarden/core/reporting.py` (7 formats incl. PDF, tag-filterable, threat-matrix embedded) + `k8smatrixwarden/core/finding_context.py` (shared Summary/Standards/MITRE/Impact/Remediation/Validation content every format reads from) + `k8smatrixwarden/core/pdf_report.py` |
| Threat Matrix §12 | `k8smatrixwarden/core/threat_matrix.py` (projects findings onto the 9-tactic Kubernetes Threat Matrix) + `k8smatrixwarden/core/threat_matrix_render.py` (text/markdown/HTML heatmap) |
| Plugin model §21 | `k8smatrixwarden/core/plugin.py` |
| 10 Domain Shards §5 | `k8smatrixwarden/shards/*` |
| Orchestrator §4 | `k8smatrixwarden/agents/orchestrator.py` |
| Scanner Agent §5 | `k8smatrixwarden/agents/scanner.py` |
| Runtime Agent §8 | `k8smatrixwarden/agents/runtime.py` (Falco/audit/drift detections, all tagged `surface=runtime`) |
| Remediation Agent §9 | `k8smatrixwarden/agents/remediation.py` (snapshot→apply→health-check→rollback lifecycle) + `k8smatrixwarden/core/remediation_engine.py` (schema-aware, resource-aware command generation — resolves a Pod's owning controller and patches container fields by name via strategic merge, never a positional `containers[0]` json-add) |
| Web Dashboard §3.1/§19 | `k8smatrixwarden/web/` — stdlib `http.server` UI: saved-scan list, HTML reports, per-scan threat-matrix heatmap, in-browser scan, JSON API |
| MCP Server + 6 datasets §10 | `k8smatrixwarden/mcp/` — 27 tools across 4 layers: knowledge (16), scan/audit/runtime (8: `run_scan`, `preview_scan`, `interpret_query`, `run_cis_benchmark`, `evaluate_runtime_events`, `list_runtime_detections`, `explain_remediation`, `build_threat_matrix`), reports (2: `list_reports`, `download_report`), platform (1: `generate_rbac_manifest`). Full per-tool descriptions in `USAGE.md` §4.5. |
| Taxonomy (Dataset 6) §6.2 | `k8smatrixwarden/taxonomy/*.json` |
| Config §16 | `k8smatrixwarden/config/default_config.json` |

## The 10 domain shards

`① cluster_control_plane · ② workload_pod_security · ③ rbac_identity · ④ network_security ·
⑤ image_supply_chain · ⑥ secrets · ⑦ compliance · ⑧ attack_surface · ⑨ admission_control (NEW) ·
⑩ cloud_iam (NEW)`

## Extending

Add a new scanner shard: drop a module in `k8smatrixwarden/shards/` exposing `SHARD = YourShard`
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

Remediation is also **schema-aware**: a controller-owned Pod (the normal case — Deployment/
DaemonSet/StatefulSet/CronJob) is never patched directly, only its owning controller is,
using that kind's real patch path (`spec.template.spec.*`, or
`spec.jobTemplate.spec.template.spec.*` for a CronJob — a bare Pod has neither). A
standalone Pod's security-context fields are correctly treated as immutable-once-created
and get a recreate recommendation instead of a doomed-to-be-rejected patch. Helm/ArgoCD/
Flux-managed and `kube-system`/EKS-managed workloads get an explicit warning instead of a
silent live patch. See `k8smatrixwarden/core/remediation_engine.py` and `tests/test_remediation_engine.py`.

## Docs in this folder

- **`docs.html`** — the full reference site (open it directly in a browser): architecture,
  all 10 shards' rule catalogs, MITRE/OWASP/CIS coverage, the remediation engine, and the
  complete 25-tool MCP reference, in one self-contained page (dark/light aware)
- **`USAGE.md`** — full usage guide: every command, every flag, copy-paste workflows, CI recipes, troubleshooting
- `ANALYSIS.md` — pre-implementation technical analysis of the architecture spec
- `REVIEW.md` — post-implementation review, refinements made, and known limitations
