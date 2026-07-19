<h1 align="center">K8sMatrixWarden</h1>

<p align="center">
  <strong>MITRE ATT&CK-aligned · Domain-Sharded Execution + Cross-Cutting Rule Registry</strong><br/>
  <em>A reference implementation of the K8sMatrixWarden MITRE-Aligned Architecture</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue"/>
  <img src="https://img.shields.io/badge/deps-zero%20(stdlib%20core)-brightgreen"/>
  <img src="https://img.shields.io/badge/shards-11-blueviolet"/>
  <img src="https://img.shields.io/badge/rules-60-orange"/>
  <img src="https://img.shields.io/badge/MCP%20tools-30-blueviolet"/>
  <img src="https://img.shields.io/badge/tests-218%20passing-success"/>
  <img src="https://img.shields.io/badge/time-IST%20(UTC%2B05%3A30)-informational"/>
</p>

---

## Repository layout

This README lives at the repository root; the Python package and all project docs live in
the **`K8sMatrixWarden-Dev-1/`** subfolder. Run every command below from inside it (or
`pip install -e .` once from there to get the `k8smatrixwarden` command on your PATH):

```bash
cd K8sMatrixWarden-Dev-1
python -m k8smatrixwarden doctor        # sanity-check the install
```

## TL;DR

```bash
# no install, no dependencies — runs against a bundled insecure mock cluster
python -m k8smatrixwarden scan --mock

# name a scan — the saved report is "<name> + date + time" in the dashboard history
python -m k8smatrixwarden scan --mock --name "Prod nightly"

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

## The differentiator — scan × runtime correlation

Static scanning alone is table stakes (Trivy/kubescape/kube-bench all do it). The bet here is
**correlation + causality**: not "here's a weakness" but "**this** weakness is being **exploited
right now**, and here's the kill-chain." On top of the scanner, the platform adds:

- **Scan × runtime correlation** (`core/correlation.py`) — joins static findings to live
  Falco/audit runtime alerts by MITRE tactic (+ namespace): `confirmed` (same tactic + same
  namespace — actively exploited), `corroborated` (same tactic), `runtime-only` (behaviour the
  scan never predicted).
- **Drift detection** — flags runtime behaviour that **contradicts a Pod's declared posture**
  (uid 0 despite `runAsNonRoot`, writes despite `readOnlyRootFilesystem`) — the strongest signal,
  because it means a control the operator *thinks* is enforced is not.
- **Attack-path derivation** (`core/threat_matrix.py::attack_paths`) — chains the threat matrix's
  hit cells into a kill-chain (Initial Access → … → Impact) with entry points and a reaches-Impact flag.
- **Interactive dashboard** (`web/`) — a zero-dependency SPA with seven tabs (Overview, Findings,
  Threat Matrix, Attack Path, Attack Map, Runtime, Scan). A **report selector** switches the whole
  view to any saved scan, and every finding — in the Findings table, the Threat Matrix drill-downs,
  and the Attack Path / Attack Map stages — **deep-links straight to its card in the full report**.
  The **Scan** tab lets you name a scan and, for live scans, either type a **kubeconfig path** *or*
  **select the kubeconfig file from your system** (whichever is convenient). Live Falco ingestion
  feeds the Runtime tab. A **light/dark theme toggle** sits in the top bar of every page (remembered
  across sessions; follows the OS preference until you choose), and the layout uses the **full
  browser width** so the 9-column matrix and findings tables have room. All timestamps are shown
  in **IST**.
- **Honest evidence reporting** (`core/evidence.py`, `agents/scanner.py`) — a live scan that cannot
  authenticate **fails with the credential plugin's real error** (e.g. *"the AWS profile could not
  be found"*) instead of silently collecting nothing. Provider-agnostic: whatever `exec` command the
  kubeconfig declares is re-run, so EKS / GKE / AKS each surface their own error, and the legacy
  `auth-provider` mechanism is named too. A scan that reads no resource type at all is rated
  **`Unknown`**, never `Excellent` — zero findings only means "clean" when the cluster was actually
  read, and every surface (report, dashboard, PDF, JSON) says which it was.
- **Safe by default when exposed** (`web/server.py`) — the dashboard binds `127.0.0.1` and has no
  authentication. Loading a kubeconfig *executes its credential plugin*, so on any non-loopback bind
  a request-supplied kubeconfig is **refused** (`403`) rather than becoming remote code execution;
  startup warns, and `--allow-remote-kubeconfig` is the deliberate opt-in for people running their
  own auth in front.

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
| `k8smatrixwarden web [--port 8080]` | **Security Dashboard** web UI — browse scans, open reports, view the per-scan threat matrix, run a scan. Binds `127.0.0.1`; see USAGE §4.8 before exposing it |
| `k8smatrixwarden matrix [--coverage]` | Print the **Kubernetes Threat Matrix** for a scan (or global detection coverage) |
| `k8smatrixwarden rules [--module M] [--tactic T]` | List the rule registry (each tagged `surface=scan`) |
| `k8smatrixwarden coverage` | MITRE tactic coverage (rules per tactic) |
| `k8smatrixwarden cis ...` | Full **CIS Kubernetes Benchmark v1.8** (all 130 controls) |
| `k8smatrixwarden report list / download` | List & re-download saved scans in any format/filename (scans are saved automatically) |
| `k8smatrixwarden roles` | Per-plugin scoped RBAC ClusterRoles (§20/§21) |
| `k8smatrixwarden doctor` | Validate taxonomy, aliases, duplicate rule ids |
| `k8smatrixwarden mcp [--list-tools]` | Run the MCP server, or list its 30 tools |

### Scan options

```
scope    : --namespace/-n · --pod · --workload KIND/name · --node · --image · --helm-release
selector : --tactic · --technique · --module · --rule · --alias · --framework · --severity-min
mode     : --mock (default) · --live · --fixture PATH · --kubeconfig PATH · --context NAME
output   : -o {terminal,text,markdown,json,sarif,html,pdf} · --output-file PATH
naming   : --name "<scan name>"     report is named "<name> + date + time"
store    : (saved by default → web dashboard) · --no-save to skip · --reports-dir PATH
flow     : --dry-run · --yes · --fail-on {LOW,MEDIUM,HIGH,CRITICAL}   (CI mode)
```

> **Scans are saved by default.** Every `scan` (and every MCP `run_scan`/`intelligent_scan`)
> persists to the shared report store, so it shows up immediately in the web dashboard's
> **Scan history** — no `--save` needed. Use `--no-save` for a throwaway run.

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
| Reporting §18.2 | `k8smatrixwarden/core/reporting.py` (7 formats incl. PDF, tag-filterable, threat-matrix embedded) + `k8smatrixwarden/core/finding_context.py` (shared Summary/Standards/MITRE/Impact/Validation content every format reads from) + `k8smatrixwarden/core/pdf_report.py` |
| Threat Matrix §12 | `k8smatrixwarden/core/threat_matrix.py` (projects findings onto the 9-tactic Kubernetes Threat Matrix) + `k8smatrixwarden/core/threat_matrix_render.py` (text/markdown/HTML heatmap) |
| Plugin model §21 | `k8smatrixwarden/core/plugin.py` |
| 10 Domain Shards §5 | `k8smatrixwarden/shards/*` |
| Orchestrator §4 | `k8smatrixwarden/agents/orchestrator.py` |
| Scanner Agent §5 | `k8smatrixwarden/agents/scanner.py` |
| Runtime Agent §8 | `k8smatrixwarden/agents/runtime.py` (Falco/audit/drift detections, all tagged `surface=runtime`) |
| MCP Server + 5 datasets §10 | `k8smatrixwarden/mcp/` — **30 tools** across 4 layers: knowledge (14), scan/audit/runtime/analysis (12: `run_scan`, `preview_scan`, `interpret_query`, `intelligent_scan`, `detect_cluster_provider`, `run_cis_benchmark`, `build_threat_matrix`, `build_attack_path`, `evaluate_runtime_events`, `correlate_runtime`, `detect_drift`, `list_runtime_detections`), reports (2: `list_reports`, `download_report`), platform (2: `generate_rbac_manifest`, `deploy_falco`). **Every parameter of every tool carries a schema description** (via `Annotated[..., Field(description=…)]`) so the calling LLM sees fully documented arguments. Read-only: no remediation/apply tool is exposed. Full per-tool descriptions in `K8sMatrixWarden-Dev-1/USAGE.md` §4.5. |
| Scan × Runtime correlation §8 | `k8smatrixwarden/core/correlation.py` (`correlate()`, `detect_drift()`) — joins static findings to live Falco/audit alerts by MITRE tactic; drift flags declared-vs-observed posture contradictions |
| Attack-path derivation §12 | `k8smatrixwarden/core/threat_matrix.py::attack_paths()` — chains threat-matrix hit cells into a kill-chain |
| Interactive Dashboard §3.1/§19 | `k8smatrixwarden/web/` — zero-dependency SPA (7 tabs) with a report selector + finding deep-links to the report; `/api/dashboard[?scan_id=…]` · `/api/timeline` (MTTD/MTTR metrics) · `/api/runtime` (live Falco ingestion) |
| IST timestamps | `k8smatrixwarden/core/timeutil.py` — every generated timestamp (`generated_at`, scan ids) is Indian Standard Time (UTC+05:30); reports/dashboard render it as e.g. `19 Jul 2026, 01:13 IST` |
| Taxonomy (Dataset 6) §6.2 | `k8smatrixwarden/taxonomy/*.json` |
| Config §16 | `k8smatrixwarden/config/default_config.json` |

## The 11 domain shards

`① cluster_control_plane · ② workload_pod_security · ③ rbac_identity · ④ network_security ·
⑤ image_supply_chain · ⑥ secrets · ⑦ compliance · ⑧ attack_surface · ⑨ admission_control ·
⑩ cloud_iam · ⑪ log_analysis (NEW)`

⑪ **log_analysis** answers the question the other ten don't: *if an attacker got in, could
you tell?* The others ask whether a door is open; this one asks whether anyone is writing
down who walked through it — audit policy, retention, log rotation, and whether any
collector ships logs off-node at all. It is the scan-surface counterpart to the Runtime
Agent's MITRE T1070 detections: the Runtime Agent sees logs being cleared, this sees the
posture that makes clearing them unrecoverable.

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
API respectively for full live coverage. See `REVIEW.md` for the live-mode roadmap.

**Live scanning is fault-tolerant.** It preflights connectivity, so an unreachable cluster
(stopped, or a wrong endpoint) fails fast with one clear, actionable message — *"Cannot reach
the Kubernetes API server for context X … kubectl … cluster-info … or add --mock"* — instead
of a raw `urllib3` traceback. A resource type the scanning identity can't read (RBAC-forbidden)
or that an older cluster doesn't have (absent API group) is **skipped and recorded as a
warning**, never fatal — the scan completes with everything it *could* read and reports the
skipped types (CLI `warning:` lines; a `warnings[]` field on the web `/api/scan` and MCP
`run_scan`/`intelligent_scan` responses), so partial coverage is always visible.

All surfaces (CLI, MCP, web) also share **one report store** by default —
`~/.k8smatrixwarden/reports` (override with `$K8SMATRIXWARDEN_REPORTS_DIR`) — and **every scan
is persisted to it automatically** (CLI `scan`, MCP `run_scan`/`intelligent_scan`, and the web
scan button), so a scan run from the CLI or an LLM/MCP call appears in the web dashboard's
**Scan history** with no extra wiring. Give a scan a name (CLI `--name`, MCP `scan_name`, or
the dashboard's *Scan name* field) and its report is titled **"&lt;name&gt; + date + time"**
(e.g. `Prod nightly — 19 Jul 2026, 01:13 IST`) so it's easy to find later. See
`K8sMatrixWarden-Dev-1/USAGE.md` §4.5.

## Safety

**Detect-and-report only.** This tool never mutates the cluster from any surface — it has
no remediation/apply path. Scanning reads the cluster (get/list/watch only), and every
output (reports, threat matrix, MCP tools, web dashboard) is derived from that read-only
snapshot. The MCP surface exposes no write-capable tool, enforced by
`tests/test_mcp.py::test_no_remediation_or_apply_tool_is_exposed`.

## Docs

All project docs live in the **`K8sMatrixWarden-Dev-1/`** subfolder:

- **`K8sMatrixWarden-Dev-1/K8sMatrixWarden-doc.html`** — the full reference site (open it directly
  in a browser): architecture, all 11 shards' rule catalogs, MITRE/OWASP/CIS coverage,
  the runtime-correlation layer, and the complete 30-tool MCP reference, in one self-contained
  page (dark/light aware)
- **`K8sMatrixWarden-Dev-1/USAGE.md`** — full usage guide: every command, every flag, copy-paste workflows, CI recipes, troubleshooting
- `K8sMatrixWarden-Dev-1/ANALYSIS.md` — pre-implementation technical analysis of the architecture spec
- `K8sMatrixWarden-Dev-1/REVIEW.md` — post-implementation review, refinements made, and the forward roadmap
