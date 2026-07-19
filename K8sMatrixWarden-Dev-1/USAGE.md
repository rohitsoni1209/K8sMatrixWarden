<h1 align="center">k8smatrixwarden — Usage Guide</h1>

<p align="center">
  <em>Everything you need to actually <strong>use</strong> the tool — install, commands, examples, workflows.</em><br/>
  For architecture and design rationale, see <code>README.md</code>, <code>ANALYSIS.md</code>, and <code>REVIEW.md</code>.
</p>

---

## Table of Contents

1. [Requirements & Install](#1-requirements--install)
2. [Your First Scan (60 seconds)](#2-your-first-scan-60-seconds)
3. [The Four Ways to Use k8smatrixwarden](#3-the-four-ways-to-use-k8smatrixwarden)
4. [Command Reference](#4-command-reference)
   - [`scan`](#41-k8smatrixwarden-scan)
   - [`chat`](#42-k8smatrixwarden-chat)
   - [`cis`](#43-k8smatrixwarden-cis)
   - [`rules` / `coverage` / `roles` / `doctor`](#44-inspection-commands)
   - [`report`](#45-k8smatrixwarden-report--download-saved-reports-later)
   - [`mcp`](#45-k8smatrixwarden-mcp)
   - [`matrix`](#47-k8smatrixwarden-matrix--kubernetes-threat-matrix)
   - [`web`](#48-k8smatrixwarden-web--security-dashboard)
5. [Scoping a Scan — what to scan](#5-scoping-a-scan--what-to-scan)
6. [Selecting Rules — what kind of issue to look for](#6-selecting-rules--what-kind-of-issue-to-look-for)
7. [Natural-Language Queries](#7-natural-language-queries)
8. [Output Formats](#8-output-formats)
9. [Running Against a Real Cluster](#9-running-against-a-real-cluster)
11. [Common Workflows](#11-common-workflows)
12. [Configuration](#12-configuration)
13. [Understanding the Output](#13-understanding-the-output)
14. [Troubleshooting](#14-troubleshooting)
15. [Command Cheat Sheet](#15-command-cheat-sheet)

---

## 1. Requirements & Install

**Requirement:** Python 3.10+. That's it — the core engine has **zero required dependencies**.

```bash
cd K8sMatrixWarden-Dev-1

# Option A — run directly, no install (recommended for trying it out)
python -m k8smatrixwarden doctor

# Option B — install the `k8smatrixwarden` command onto your PATH
pip install -e .
k8smatrixwarden doctor
```

Everything below assumes `python -m k8smatrixwarden ...`; if you installed it, drop the `python -m` and just use `k8smatrixwarden ...`.

### Optional extras

| Extra | Unlocks | Install |
|---|---|---|
| `live` | Scanning a real cluster (`--live`) | `pip install -e ".[live]"` |
| `pretty` | Nicer colored terminal tables | `pip install -e ".[pretty]"` |
| `mcp` | Running the MCP protocol server for AI-agent integration | `pip install -e ".[mcp]"` |
| `pdf` | PDF report export (`-o pdf`) | `pip install -e ".[pdf]"` |
| `dev` | Running the test suite with real `pytest` | `pip install -e ".[dev]"` |

None of these are needed to use the tool — without them you get plain-text output and `--mock` scanning, which is fully functional.

### Sanity check

```bash
python -m k8smatrixwarden doctor
```

Expected output:
```
Shards loaded : 11 (admission_control, attack_surface, cloud_iam, cluster_control_plane, compliance, image_supply_chain, log_analysis, network_security, rbac_identity, secrets, workload_pod_security)
Rules loaded  : 60
Validation    : ✅ clean (taxonomy + aliases + no duplicate rule ids)
```

If you see that, everything is wired correctly and you're ready to scan.

---

## 2. Your First Scan (60 seconds)

The tool ships with a **bundled, deliberately-insecure mock cluster** so you can try every feature without a real Kubernetes cluster.

```bash
python -m k8smatrixwarden scan --mock
```

This runs all 56 rules against the mock cluster and prints a full terminal report: a risk score, a severity breakdown, and every finding with its MITRE ATT&CK mapping and a suggested fix.

Now try scanning for one specific kind of threat:

```bash
python -m k8smatrixwarden scan --tactic Persistence --mock
```

Or just talk to it:

```bash
python -m k8smatrixwarden chat
```

That's the whole tool in three commands. The rest of this guide covers every option in depth.

---

## 3. The Four Ways to Use k8smatrixwarden

| Mode | Command | Best for |
|---|---|---|
| **One-shot CLI** | `k8smatrixwarden scan --tactic Persistence -o markdown` | Scripts, CI pipelines, precise flag-driven scans |
| **One-shot natural language** | `k8smatrixwarden scan "scan production for Persistence"` | Quick ad-hoc questions without remembering flag names |
| **Interactive chat** | `k8smatrixwarden chat` | Exploring a cluster conversationally, multi-turn investigation |
| **Web Dashboard** | `k8smatrixwarden web` | Browsing saved scans, reports, and the threat matrix in a browser; running a scan by clicking |
| **MCP (AI agent)** | `k8smatrixwarden mcp` | Driving everything above from Claude/Cursor/any MCP client |

They all go through the exact same engine (Orchestrator → Registry → Evidence Collector → Detection Engine), so results are identical no matter which you use — pick whichever fits the moment.

---

## 4. Command Reference

```
k8smatrixwarden [--config PATH] <command> [options]
```

`--config PATH` (global, before the subcommand) overrides the default rule/shard/alias configuration — see [§12 Configuration](#12-configuration).

### 4.1 `k8smatrixwarden scan`

Run a security scan. Either flag-driven or natural language.

```bash
k8smatrixwarden scan [QUERY...] [scope flags] [selector flags] [output flags] [flow flags]
```

**Scope flags** — *what* to scan (pick at most one; default is the whole cluster):

| Flag | Example |
|---|---|
| `-n, --namespace NAME` | `-n production` |
| `--pod NAME` | `--pod payment-api` |
| `--workload KIND/NAME` | `--workload Deployment/api` |
| `--node NAME` | `--node worker-3` |
| `--image REF` | `--image nginx:latest` |
| `--helm-release NAME` | `--helm-release my-app` |

**Selector flags** — *which rules* to run (combine freely; default is all rules):

| Flag | Example |
|---|---|
| `--tactic TACTIC` | `--tactic "Privilege Escalation"` (repeatable) |
| `--technique NAME` | `--technique "Container Escape"` (composite alias or MITRE technique) |
| `--module SHARD` | `--module rbac_identity` |
| `--rule RULE_ID` | `--rule workload-privileged-container` |
| `--alias NAME` | `--alias "Exposed Secrets"` |
| `--framework NAME` | `--framework CIS` (CIS / NSA / OWASP) |
| `--severity-min LEVEL` | `--severity-min HIGH` |

**Output flags:**

| Flag | Values | Default |
|---|---|---|
| `-o, --output FORMAT` | `terminal, text, markdown, json, sarif, html, pdf` | `terminal` |
| `--output-file PATH` | write the rendered report to a file | — |

**Mode flags:**

| Flag | Meaning |
|---|---|
| `--mock` | use the bundled mock cluster (default when `--live` isn't given) |
| `--live` | scan a real cluster |
| `--fixture PATH` | use a custom mock cluster JSON instead of the bundled one |
| `--kubeconfig PATH` | kubeconfig file to use with `--live` (default: `~/.kube/config`) |
| `--context NAME` | kubeconfig context to use with `--live` (default: `current-context`) |

**Naming & report-store flags:**

| Flag | Meaning |
|---|---|
| `--name "TEXT"` | give the scan a human name; the saved report is titled **`<name> + date + time`** (e.g. `Prod nightly — 19 Jul 2026, 01:13 IST`) and is easy to find in the dashboard / `report list` |
| *(saved by default)* | every scan is persisted to the shared report store automatically, so it appears in the web dashboard's **Scan history** — no flag needed |
| `--no-save` | do **not** persist this scan (skips the dashboard / `report list`) — for a throwaway run |
| `--save` | **deprecated no-op** — scans are saved by default now; kept so old scripts don't break |
| `--reports-dir DIR` | override where this scan is saved (default: the shared store, see [§4.5](#45-k8smatrixwarden-report--download-saved-reports-later)) |

**Flow flags:**

| Flag | Meaning |
|---|---|
| `--dry-run` | show which rules *would* run, without scanning (nothing is saved) |
| `-y, --yes` | skip the confirmation prompt (natural-language mode) |
| `--fail-on LEVEL` | exit code `1` if any finding ≥ this severity (for CI) |

> **Scans save automatically.** Since scans are persisted by default, running
> `k8smatrixwarden scan --live` (or any scan) makes the result show up immediately in the web
> dashboard's **Scan history** — you no longer need `--save`. Add `--name "…"` to label it,
> or `--no-save` to skip persistence entirely.

### 4.2 `k8smatrixwarden chat`

Interactive conversational assistant.

```bash
k8smatrixwarden chat [--live] [--fixture PATH] [--kubeconfig PATH] [--context NAME]
```

Type plain English; it shows you the resolved plan and waits for confirmation before scanning. See [§7](#7-natural-language-queries) for example phrases, and the transcript in [§11](#11-common-workflows).

### 4.3 `k8smatrixwarden cis`

Run the **full CIS Kubernetes Benchmark v1.8** — all 130 controls.

```bash
k8smatrixwarden cis [--mock|--live] [--kubeconfig PATH] [--context NAME] [--kube-bench-json PATH] [--profile PROFILE] [-o FORMAT] [--show-all] [--fail-on-fail]
```

| Flag | Meaning |
|---|---|
| `--kubeconfig PATH` / `--context NAME` | same as `scan` — which cluster/context to read live |
| `--kube-bench-json PATH` | merge real `kube-bench --json` output to resolve node-level file-permission controls |
| `--profile PROFILE` | `self-managed` (default), `eks`, `gke`, `aks` — managed profiles mark the provider-owned control plane `N/A` instead of ungradeable |
| `-o, --output FORMAT` | `terminal, text, markdown, json` |
| `--show-all` | also list `MANUAL` / `NEEDS_NODE` / `NA` controls, not just failures |
| `--fail-on-fail` | exit code `1` if any control `FAIL`s (CI mode) |

See [§13.3](#133-cis-benchmark-statuses) for what each status (`PASS`/`FAIL`/`MANUAL`/`NA`/`NEEDS_NODE`) means.

### 4.4 Inspection commands

```bash
k8smatrixwarden rules [--module SHARD] [--tactic TACTIC]   # list the rule registry
k8smatrixwarden coverage                                    # rules per MITRE tactic (bar chart)
k8smatrixwarden roles [--bind] [--service-account NAME] [--sa-namespace NS] [--no-create-namespace] [--output-file PATH]
k8smatrixwarden doctor                                       # validate the whole platform wiring
```

`k8smatrixwarden roles` (no flags) prints the bare, per-shard `ClusterRole` JSON — useful for review. Add `--bind` to get a complete, `kubectl apply`-able manifest (Namespace + ServiceAccount + all `ClusterRole`/`ClusterRoleBinding` pairs) — see [§9.3](#93-step-3--least-privilege-rbac-recommended-before-scanning-anything-you-care-about).

Run `doctor` any time something seems off, or after editing `config/default_config.json` — it will tell you exactly what's broken (duplicate rule ids, unknown MITRE technique ids, dangling aliases).

### 4.5 `k8smatrixwarden report` — download saved reports later

Every scan is saved automatically, so you can list and re-download any result in any format,
to any filename — no `--save` needed:

```bash
k8smatrixwarden scan --live --name "Prod audit"                      # runs AND saves to the shared store
k8smatrixwarden report list                                          # what's stored (newest first)
k8smatrixwarden report download --scan-id prod-audit-… --format html --output audit.html
k8smatrixwarden report download --format markdown --output report.md   # (no --scan-id ⇒ latest)
```

| Command | Meaning |
|---|---|
| `report list [--limit N] [--reports-dir DIR]` | list stored scans — **name**, time, rating, risk, findings, and the scan id (the download key) |
| `report download [--scan-id ID] [--format FMT] [--output FILE] [--reports-dir DIR]` | re-render a stored scan; `--scan-id` defaults to the latest; `--output` picks the filename (omit ⇒ print to stdout) |

The scan id — the `--scan-id` download key — encodes the name, date, and time, e.g.
`prod-audit-20260719-011300-a1b2` (or `scan-20260719-011300-a1b2` when unnamed).

**Shared report store (one history across CLI, MCP, and web).** By default every surface
reads and writes the **same** store, resolved independently of the working directory, and
**every scan is persisted automatically** — so a scan you run from the CLI, or that an LLM
runs via the `run_scan` / `intelligent_scan` MCP tools, shows up in the web dashboard's
**Scan history** without anything having to run from the same folder:

- Default location: `~/.k8smatrixwarden/reports` (on Windows, `%USERPROFILE%\.k8smatrixwarden\reports`).
- Override for all surfaces at once with the `K8SMATRIXWARDEN_REPORTS_DIR` environment
  variable (point it at an absolute path), or per-command with `--reports-dir`.

> Earlier versions defaulted to a **relative** `./k8smatrixwarden-reports`, which resolved
> against each process's current directory — so a CLI/MCP scan silently landed somewhere the
> web server never read. The absolute per-user default fixes that.

Because the full result is stored, you can export it into a **different** format than you first viewed — scan once, download markdown for a PR *and* SARIF for CI *and* HTML for a stakeholder, all from the same saved scan. (CIS benchmark reports download via `k8smatrixwarden cis --output-file`.)

### 4.5 `k8smatrixwarden mcp`

Run the tool as an MCP (Model Context Protocol) server, so any MCP-compatible AI agent
(Claude, Cursor, VS Code, Windsurf, ...) can do everything the CLI can do, over the exact
same engine the CLI and chat use — including running real scans, a one-call
`intelligent_scan` (parse → detect cluster → scan → threat matrix → attack path), the full
CIS benchmark, projecting the Kubernetes Threat Matrix and kill-chain attack path,
correlating a live runtime event stream against static findings (`correlate_runtime`) plus
drift detection (`detect_drift`), and exporting saved reports in any format. It is
read-only: there is no remediation/apply tool.

```bash
k8smatrixwarden mcp --list-tools     # see what's exposed, without starting the server
k8smatrixwarden mcp                  # start the MCP server over stdio (requires: pip install -e ".[mcp]")
```

**30 tools, four layers.** Every tool's description below is verbatim its Python
docstring — that's exactly what the calling LLM sees, since FastMCP reads docstrings
directly as tool descriptions (`k8smatrixwarden/mcp/server.py`). In addition, **every
parameter of every tool carries its own schema description**, declared with
`Annotated[T, Field(description=…)]`, so an MCP client sees a fully documented argument list
(name, type, default, and a one-line description) for all 150 parameters across the 30 tools —
not just the tool-level summary. (The descriptions degrade gracefully to metadata-only when
the tool runs in-process without the MCP SDK.)

#### Layer 1 — Knowledge & introspection (14 tools · read-only, no scan execution)

| Tool | Description |
|---|---|
| `list_rules(shard?, tactic?)` | List rules in the registry (id, title, shard, severity, full taxonomy), optionally filtered by domain shard and/or MITRE tactic. Discovers valid `rule_ids` for scan selectors. |
| `resolve_selector(tactics?, techniques?, modules?, aliases?, frameworks?, rule_ids?)` | Resolve a raw selector to the rule ids it expands to, with no scope and no scan — lower-level than `preview_scan`. |
| `get_kubectl_command(name)` | Look up one named kubectl security one-liner (e.g. `list-privileged-pods`). |
| `list_kubectl_commands()` | List every named kubectl command in the dataset (9 total). |
| `get_tool_commands(tool)` | Look up example invocation(s) for one external tool (trivy, kube-bench, kubescape, cosign, ...). |
| `list_tool_commands()` | List every external tool the dataset knows, with its example invocation(s). |
| `lookup_cve(cve_id)` | Look up one CVE in the bundled K8s CVE knowledge base. |
| `list_cves()` | List every CVE in the bundled knowledge base (severity, affected range, description). |
| `get_compliance_ruleset(framework?)` | Get metadata for CIS / PSS / NSA_CISA (or all three) — summary only; use `run_cis_benchmark` for the full 130-control evaluation. |
| `get_taxonomy()` | Get the vendored MITRE ATT&CK-for-Containers technique catalog + current tactic coverage. |
| `mitre_coverage()` | Rule count per MITRE tactic (all 9). |
| `list_shards()` | List the 10 domain shards with titles and rule counts — valid values for the `modules` selector. |
| `list_namespaces(mock?, fixture?, kubeconfig?, context?)` | List namespace names in the target cluster — check before scoping a scan to one. |
| `validate_platform()` | Validate the install itself (`doctor` equivalent) — shard/rule counts, taxonomy/alias validation problems if any. |

#### Layer 2 — Scan · audit · runtime · analysis (12 tools · read-only cluster access)

| Tool | Description |
|---|---|
| `preview_scan(scope..., selector...)` | Resolve a scan's scope+selector to the exact rule set **without scanning** — the plan-before-you-run step. |
| `run_scan(scope..., selector..., mock?, output_format?, save?, scan_name?, max_findings?)` | Run a real scan. `output_format="json"` (default) returns structured findings + risk + the `threat_matrix` block + full per-finding context (summary/impact/standards/MITRE/validation); `"markdown"/"html"/"sarif"/"text"/"terminal"` instead returns the fully rendered report string. `"pdf"` returns base64-encoded PDF bytes (`content_base64` + `encoding: "base64"` instead of `content`) — requires the `pdf` extra server-side. **`save=True` by default**, so the scan lands in the shared store and the web dashboard's Scan history (pass `save=False` for a throwaway run); `scan_name` labels the saved report as `<name> + date + time`. |
| `interpret_query(text)` | Parse a natural-language request ("scan production for persistence") into scope/selector/resolved rules — no execution. |
| `intelligent_scan(query, scope..., include_attack_path?, mock?, save?, scan_name?)` | **One call, everything:** parse plain English → detect the cluster → run the read-only scan → return findings, risk, the threat matrix, **and** the kill-chain attack path. Composes `detect_cluster_provider` + `interpret_query` + `run_scan` + `build_threat_matrix` + `build_attack_path`. Also **saves by default** (`save=True`) so an LLM-driven scan appears in the dashboard; `scan_name` labels it. Use it to just ask and get the full analysis. |
| `detect_cluster_provider(mock?, fixture?, kubeconfig?, context?)` | Detect the cluster kind from its Node objects — `cloud` (gcp/aws/azure/local), `managed` (is the control plane GKE/EKS/AKS), and `profile` (feed straight into `run_cis_benchmark`). Reads Node `providerID` + managed-service labels only; no writes, no control-plane access. |
| `run_cis_benchmark(mock?, profile?, kube_bench_json?)` | Run the full CIS Kubernetes Benchmark v1.8 (130 controls, PASS/FAIL/MANUAL/NA/NEEDS_NODE). `profile="auto"` (default) auto-detects the provider via `detect_cluster_provider`. |
| `build_threat_matrix(scope..., selector..., scan_id?, coverage?, mock?)` | Project findings onto the 9-tactic **Kubernetes Threat Matrix** — from a fresh scan, a saved report (`scan_id`), or global detection coverage (`coverage=True`). Returns the same `{summary, columns[cells]}` structure the report/dashboard heatmap uses. Cells are `hit`/`covered`/`gap`. |
| `build_attack_path(scope..., selector..., scan_id?, mock?)` | Chain the threat matrix's **hit** cells into a kill-chain exploit path (Initial Access → … → Impact). Returns `chain`, per-tactic `steps` (techniques + exposing resources + worst severity), `entry_points`, and `reaches_impact`. From a fresh scan or a saved `scan_id`. |
| `evaluate_runtime_events(events)` | Evaluate a batch of Falco-style syscall or K8s audit events against the Runtime Agent's rule catalog; returns any alerts (each tagged `surface="runtime"` + its `source`). Detects shell-in-container, metadata-API access, network recon, crypto-miners, escape indicators, log tampering, new RoleBindings, secret enumeration, and more. |
| `correlate_runtime(events, scan_id?, scope..., selector..., mock?)` | **The "what's being exploited right now" view.** Evaluate `events` into runtime alerts, then join them to scan findings by MITRE tactic (+ namespace): `confirmed` (same tactic + namespace — actively exploited), `corroborated` (same tactic), `runtime-only` (never predicted). Correlates against a saved `scan_id` or a fresh read-only scan. |
| `detect_drift(events, namespace?, mock?)` | Detect runtime behaviour that **contradicts a Pod's declared security posture** — the strongest exploitation signal. Flags process-as-uid-0 despite `runAsNonRoot`, writes despite `readOnlyRootFilesystem`, and privileged-only ops from a non-privileged pod. Read-only; each drift finding is CRITICAL (declared vs observed vs pod). |
| `list_runtime_detections()` | List the Runtime Agent's detection catalog — every rule tagged `surface="runtime"` (source: falco/audit/drift). The counterpart to `list_rules`, whose Scanner rules are all `surface="scan"`. |

#### Layer 3 — Reports (persist a scan once, export in any format later)

| Tool | Description |
|---|---|
| `list_reports(reports_dir?, limit?)` | List previously saved scans (every `run_scan`/`intelligent_scan` is saved by default) — each with its name, time, rating, risk, findings, and scan id. |
| `download_report(scan_id?, format?, reports_dir?)` | Re-render a saved scan in any of the 7 formats without re-scanning; omit `scan_id` for the latest. Returns the rendered content — save it to a file yourself using your own file-write tool. `format="pdf"` returns base64-encoded bytes instead (same convention as `run_scan`). |

#### Layer 4 — Platform (2 tools)

| Tool | Description |
|---|---|
| `generate_rbac_manifest(service_account?, namespace?, create_namespace?, bind?)` | Generate the least-privilege RBAC (get/list/watch only) k8smatrixwarden needs against a real cluster. `bind=True` returns a full deployable manifest (Namespace + ServiceAccount + per-shard ClusterRole/ClusterRoleBinding); `bind=False` returns just the bare ClusterRoles for review. Only generates — never applies. |
| `deploy_falco(webhook_url, namespace?)` | One-click **Falco + falcosidekick** deploy: runs `helm install` to set up Falco with a webhook pointing at your K8sMatrixWarden runtime endpoint (e.g. `http://host.minikube.internal:8080/api/runtime`), so live syscall/audit events flow into `correlate_runtime`/`detect_drift`. Returns the install log + next steps. Requires `helm` on the system. |

`preview_scan` / `interpret_query` resolve a scope+selector (or a natural-language
request) to the exact rule set **without touching the cluster** — the same "show the
plan, then run it" pattern `k8smatrixwarden chat` uses. An agent should call one of those first,
then call `run_scan` with the same arguments to execute.

**Detect-and-report only — no remediation/apply tool.** Everything above is read-only:
scanning, the knowledge datasets, runtime-event evaluation, and report rendering never
mutate the cluster or write to disk on their own. There is no write/apply path anywhere in
the tool; `tests/test_mcp.py::test_no_remediation_or_apply_tool_is_exposed` enforces this
stays true as the tool surface grows.

### 4.7 `k8smatrixwarden matrix` — Kubernetes Threat Matrix

Project a scan's findings onto the 9-tactic [Kubernetes Threat Matrix](https://kubernetes-threat-matrix.redguard.ch/) (MITRE ATT&CK for Containers). Each technique cell is one of three states — **hit** (a finding fired, coloured by worst severity), **covered** (a rule exists, nothing found this scan), **gap** (no rule yet) — so the matrix reads as an honest coverage map, not just a hit list.

```bash
k8smatrixwarden matrix --mock                     # the matrix for a fresh cluster scan
k8smatrixwarden matrix -n production --mock        # scoped to a namespace
k8smatrixwarden matrix --tactic Persistence --mock # only rules for one tactic
k8smatrixwarden matrix --coverage                  # global "what can it detect" matrix (no scan)
k8smatrixwarden matrix --scan-id scan-… -o markdown --output-file matrix.md   # from a saved report
```

| Flag | Meaning |
|---|---|
| scope + selector flags | same as `scan` (`-n`, `--tactic`, `--module`, …) — builds the matrix from that scan |
| `--coverage` | show global detection coverage across **all** rules, with no scan overlaid |
| `--scan-id ID` | build the matrix from a previously saved report instead of scanning |
| `-o, --output FORMAT` | `text` (default), `markdown`, `json` |
| `--output-file PATH` | also write the rendered matrix to a file |

The same matrix is embedded in the markdown/JSON/HTML scan reports, shown as a heatmap on the web dashboard (§4.8), and available over MCP via `build_threat_matrix`.

**Coverage matrix vs. scan matrix.** The two are different questions and the web UI now reports different numbers for each:

| Page | Question it answers | Headline stats |
|---|---|---|
| `/matrix` (or `matrix --coverage`) | *What can K8sMatrixWarden detect?* | techniques with a detection rule (e.g. `30/56`), matrix coverage %, tactics with coverage, rules mapped to the matrix. Each column reads `5/6 with a rule`. |
| `/report/<scan_id>/matrix` | *What did this cluster expose?* | tactics implicated, techniques triggered, matrix coverage %, findings mapped. Cells are painted by worst finding severity. |

The coverage page has no scan overlaid, so every hit-derived number there is structurally zero. It used to display `0/9 tactics implicated · 0 findings mapped`, which read as a broken counter rather than an answer; it now reports the coverage axis instead, and states plainly that no scan is overlaid.

### 4.8 `k8smatrixwarden web` — Security Dashboard

Launch the **Security Dashboard**, a zero-dependency (stdlib `http.server` back end + a vanilla-JS single-page app, no framework/build step/CDN). The shell fetches `GET /api/dashboard` once and renders everything client-side across **seven tabs**: Overview, Findings, Threat Matrix, Attack Path, Attack Map, Runtime, and Scan.

A **report selector** at the top switches the entire dashboard to any saved scan (not just the latest), and **every finding is click-through** — in the Findings table, the Threat Matrix cell drill-downs, the Overview "fix first" list, and each Attack Path / Attack Map stage — opening straight to that finding's card in the full report (`/report/<scan_id>#<finding>`). The interface uses a clean, professional (low-emoji) visual style, and **all timestamps are shown in IST** (e.g. `19 Jul 2026, 01:13 IST`).

**Light / dark mode.** Every page (dashboard, coverage matrix, per-scan HTML report) carries a **theme button in the top bar**. It flips the page between light and dark, and the choice is remembered in `localStorage` across pages and sessions. With nothing chosen yet, the page follows your OS preference (`prefers-color-scheme`). All colours come from CSS variables, so the toggle re-themes the entire surface — heatmap, charts, tables — with no page reload.

**Full-width layout.** The dashboard and the HTML report use the width of the browser window (up to 1720px) rather than a narrow centred column, so the 9-column threat matrix, findings tables and the attack map get real room. Layouts still collapse cleanly on narrow/mobile viewports.

```bash
k8smatrixwarden web                              # serve on http://127.0.0.1:8080
k8smatrixwarden web --port 9000 --open           # custom port; open a browser at startup
k8smatrixwarden web --no-scan                    # serve saved reports read-only (disable the scan button)
k8smatrixwarden web --reports-dir ./my-reports   # where to read/write saved scans
```

| Flag | Default | Meaning |
|---|---|---|
| `--host HOST` | `127.0.0.1` | interface to bind (keep it on localhost unless you know what you're doing) |
| `--port PORT` | `8080` | port to listen on |
| `--reports-dir DIR` | `~/.k8smatrixwarden/reports` (shared; or `$K8SMATRIXWARDEN_REPORTS_DIR`) | directory the dashboard lists scans from and saves new ones to — the same shared store the CLI and MCP `run_scan` write to, so their saved scans appear here too |
| `--no-scan` | off | serve existing reports read-only; disable the in-browser *Run a scan* button and `POST /api/scan` |
| `--open` | off | open your default browser at the dashboard URL on startup |
| `--allow-remote-kubeconfig` | off | accept a kubeconfig in the request body even on a non-loopback bind — **only behind your own authentication**, see *Binding beyond localhost* below |

**The seven tabs:**

| Tab | What you see |
|---|---|
| **Overview** | A **scan-health banner** first if the scan could not fully read the cluster (see *Scan health*, below), then KPIs (risk / rating / high+ count / MITRE coverage), priority findings (each links to the report), risk-by-domain bars, an attack-surface heatmap whose **exposed tactics are clickable → jump to that stage in Attack Path**, a risk-trend sparkline, and runtime readiness (which tactics have detections armed). |
| **Findings** | Live search + severity chips (CRITICAL/HIGH/MEDIUM/LOW) + tactic filter + sortable columns across every finding. **Each row is clickable and opens that finding in the report.** |
| **Threat Matrix** | The 9×N interactive Kubernetes Threat Matrix heatmap; select a coloured cell to expand its findings inline — with enriched detail (resource, score, domain, MITRE technique, OWASP/CIS, message) and a **link per finding to its report card**. |
| **Attack Path** | The kill-chain flow (tactics → techniques), entry points, and a reaches-Impact flag. **Select any stage to list every finding under that tactic**, each linking to the report. |
| **Attack Map** | The kill-chain **with the vulnerable resources** (Pods/Deployments/…) grouped per tactic — an accordion; **expand a stage** to see its exposed resources and the findings at that stage (each linking to the report). |
| **Runtime** | Paste Falco events (or load a sample) → **correlate** them against the scan's findings + **detect drift**, rendered as confirmed/corroborated/runtime-only cards and drift findings. |
| **Scan** | A run-a-scan form and the saved-scan history table (each row can be opened in the dashboard, or as a report/matrix/JSON). The form takes an optional **Scan name**, a scope selector (with a namespace box that enables when you pick *namespace* scope), a **Selector dropdown** populated from the live registry vocabulary (tactics/modules/frameworks/aliases — so it never offers a term that doesn't exist), mock/live, and — for live scans — either a typed **kubeconfig path** *or* a **file picker to select the kubeconfig from your system** (whichever is convenient; the picked file's contents are read in-browser and materialised server-side into a short-lived temp file). Every scan run here is saved and titled `<name> + date + time`. |

**Scan health — an unread cluster is never shown as a clean one.** A scan that could not read the cluster produces zero findings *because nothing was inspected*, which would otherwise score as `Excellent`. The dashboard refuses to render that:

* the scan's rating becomes **`Unknown`** and the risk / high+ KPIs show **`—`**, not `0.0`;
* a red **"Scan incomplete — this cluster was not read"** banner sits above the tabs (so it is visible on every one) and lists each resource type that could not be read;
* Overview, Findings, Threat Matrix, Attack Path and Attack Map each repeat a short *"Not a result"* note, so no single view can be screenshotted out of context;
* the same story appears in the saved report in **every** format (HTML, markdown, text, terminal, PDF, JSON) and in `POST /api/scan`'s response (`evidence_ok`, `warnings[]`).

A *partially* readable cluster (some resource types forbidden, the rest fine) keeps its real rating but gets an amber **"Partial coverage"** banner naming the missing types — the findings are real, they are just not complete.

**Binding beyond localhost — the dashboard has no authentication.** It binds `127.0.0.1` by default and is meant to stay there. Two things change the moment you pass `--host 0.0.0.0`:

1. **Anyone who can reach the port can read every saved report** (and start scans, unless you pass `--no-scan`). There is no login. Put it behind your own reverse proxy / SSO if it must be reachable.
2. **A kubeconfig in the request body is arbitrary code.** Loading a kubeconfig *executes its credential plugin* — `aws eks get-token`, `gke-gcloud-auth-plugin`, `kubelogin` — as the user running the server. That is simply how cloud auth works, and the `kubernetes` client does the same. On loopback the only possible caller is you, so the *Scan* tab's kubeconfig path box and file picker are just a convenience. On a routable address it would be **remote code execution**.

So on a non-loopback bind the server **refuses a kubeconfig supplied in the request** — both `kubeconfig` (a path) and `kubeconfig_content` (an upload), since either one names a config whose plugin would run here. `POST /api/scan` returns `403` with an explanation, and the dashboard's *Scan* tab replaces the kubeconfig inputs with that explanation rather than offering a control that always fails. Everything else keeps working: mock scans, and live scans against the **server's own** kubeconfig/context.

Your options, in order of preference:

```bash
k8smatrixwarden web                                  # default: 127.0.0.1, kubeconfig upload allowed
k8smatrixwarden scan --live --kubeconfig ~/.kube/config   # scan from the CLI on the server itself
k8smatrixwarden web --host 0.0.0.0 --no-scan         # remote, read-only report browser
k8smatrixwarden web --host 0.0.0.0 --allow-remote-kubeconfig   # ONLY behind your own auth
```

Startup prints a warning naming which of these is in effect.

**HTTP API** — the same dashboard is a small read-mostly JSON API, scriptable with `curl`:

```bash
curl http://127.0.0.1:8080/api/dashboard                        # everything the SPA renders (latest scan)
curl "http://127.0.0.1:8080/api/dashboard?scan_id=scan-…"       # render a specific saved scan (report selector)
curl http://127.0.0.1:8080/api/reports                          # list saved scans
curl "http://127.0.0.1:8080/api/report/latest?format=markdown"  # a saved report, any format
curl http://127.0.0.1:8080/api/report/latest/matrix             # a scan's threat matrix (JSON)
curl http://127.0.0.1:8080/api/timeline                         # finding age / MTTD / MTTR metrics
curl -X POST http://127.0.0.1:8080/api/scan \
     -H 'Content-Type: application/json' \
     -d '{"scan_name":"Prod nightly","scope_level":"cluster","selector":"Persistence","mock":true}'   # run & save a named scan
# live scans may pass a kubeconfig by path ("kubeconfig":"/path") OR by value
# ("kubeconfig_content":"<file text>") — the latter is how the browser file-picker uploads it
curl -X POST http://127.0.0.1:8080/api/runtime \
     -H 'Content-Type: application/json' \
     -d '{"events":[ ... ]}'                                     # ingest Falco events → {correlation, drift}
```

The server binds `127.0.0.1` by default and is **read-mostly** — the only state-changing routes are `POST /api/scan` (a read-only scan that saves its result) and `POST /api/runtime` (ingests Falco/audit events and returns correlation + drift; it does not mutate the cluster). `POST /api/runtime` accepts a single falcosidekick event **or** a `{"events":[...]}` batch. The tool detects and reports only — no remediation/apply path is exposed from any surface. Saved-report lookups are path-traversal-guarded.

---

## 5. Scoping a Scan — what to scan

Scope answers **"where do I look?"** Only one scope applies at a time; if you don't specify one, the whole cluster is in scope.

```bash
k8smatrixwarden scan --mock                                    # entire cluster
k8smatrixwarden scan -n production --mock                       # one namespace
k8smatrixwarden scan --pod payment-api -n production --mock     # one pod
k8smatrixwarden scan --workload Deployment/user-service --mock  # one workload
k8smatrixwarden scan --image nginx:latest --mock                # anywhere this image runs
k8smatrixwarden scan --node worker-3 --mock                      # one node
k8smatrixwarden scan --helm-release my-app --mock                # one Helm release
```

Cluster-scoped resources (RBAC roles, admission webhooks) always stay visible even when you scope to a namespace — a namespace-scoped scan doesn't hide the ClusterRoleBinding that grants that namespace's pods `cluster-admin`.

---

## 6. Selecting Rules — what kind of issue to look for

Selector answers **"what am I looking for?"** You can combine axes freely (they combine as a union, then dedupe):

### By MITRE ATT&CK tactic
```bash
k8smatrixwarden scan --tactic Persistence --mock
k8smatrixwarden scan --tactic "Privilege Escalation" --tactic "Lateral Movement" --mock
```
Valid tactics: `Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Impact`

### By technique or composite/outcome alias
```bash
k8smatrixwarden scan --technique "Container Escape" --mock
k8smatrixwarden scan --technique "Exposed Secrets" --mock
k8smatrixwarden scan --technique "Privileged Pods" --mock
k8smatrixwarden scan --technique "Kubernetes API Exposure" --mock
```
These are curated bundles of rules mapped to a real-world attack outcome — see them all in `config/default_config.json` under `"aliases"`.

### By domain/module (a specific area of the platform)
```bash
k8smatrixwarden scan --module rbac_identity --mock
k8smatrixwarden scan --module network_security --mock
```
Module names match the shard names shown by `k8smatrixwarden doctor` — `cluster_control_plane, workload_pod_security, rbac_identity, network_security, image_supply_chain, secrets, compliance, attack_surface, admission_control, cloud_iam, log_analysis`.

### By exact rule
```bash
k8smatrixwarden rules --module workload_pod_security     # find the rule id you want
k8smatrixwarden scan --rule workload-privileged-container --mock
```

### By compliance framework
```bash
k8smatrixwarden scan --framework CIS --mock
k8smatrixwarden scan --framework OWASP --mock
k8smatrixwarden scan --framework NSA --mock
```
(For a *complete* CIS run including the checks that aren't mapped to a native rule, use `k8smatrixwarden cis` instead — see §4.3.)

### By minimum severity
```bash
k8smatrixwarden scan --severity-min CRITICAL --mock
```

### Combine them
```bash
k8smatrixwarden scan -n production --tactic "Credential Access" --severity-min HIGH -o markdown --mock
```

### Preview without scanning
Not sure what a selector resolves to? Use `--dry-run`:
```bash
k8smatrixwarden scan --tactic Persistence --dry-run
```
```
Scope=cluster-wide  Selector=tactic=Persistence
→ resolves to 6 rule(s): admission-malicious-webhook, cronjob-suspicious, compliance-psa-not-restricted, workload-writable-root-fs, workload-hostpath-root, workload-hostpath-writable
```

---

## 7. Natural-Language Queries

Every example below works both as a one-shot `k8smatrixwarden scan "..."` and typed directly into `k8smatrixwarden chat`:

```
scan production for Persistence
scan for Defense Evasion
scan only Container Escape
scan only Privileged Pods
scan everything related to RBAC
scan all Secret-related issues
scan only Kubernetes API exposure
is my cluster secure?
run the cis benchmark
map the attack surface
```

The Orchestrator parses these into the same `scope` + `selector` structure the flag-driven form uses — nothing is lost by phrasing it in English, and you always see the resolved rule plan before it runs.

One-shot usage requires confirmation by default (type `y`) unless you pass `--yes`:
```bash
k8smatrixwarden scan "scan production for Persistence" --yes --mock
```

### The chat is conversational (not just fixed phrases)

`k8smatrixwarden chat` understands **varied phrasing, synonyms, and typos** — you don't have to memorize exact wording:

```
scan for privesc                 →  Privilege Escalation
any leaked secrets?              →  Exposed Secrets + secrets domain
look for container breakout      →  Container Escape
check roles and permissions      →  RBAC domain
recon and exposure               →  Discovery + attack-surface
cryptomining or dos              →  Impact
```

It has **session memory**, so after a scan you can drill in with follow-ups:

```
you› scan production for credential access
     … (report) …
you› show criticals              # filter the last results by severity
you› details sec-etcd-not-encrypted   # deep-dive one finding
you› export markdown             # save the last report to a file
```

It answers questions and is namespace-aware, and it fails helpfully:

```
you› what can you do?            # capabilities
you› list tactics                # the 9 tactics + descriptions
you› explain lateral movement    # plain-English explanation
you› scan prod for rbac          → "I don't see a namespace 'prod'. Did you mean: production?"
you› scan the frobnicator        → "I couldn't turn that into a scan. Did you mean…?"  (not a silent full scan)
```

---

## 8. Output Formats

```bash
k8smatrixwarden scan --mock -o terminal      # rich terminal panels + per-severity tables (default)
k8smatrixwarden scan --mock -o text          # clean plain-text, zero dependencies
k8smatrixwarden scan --mock -o markdown      # the flagship report — see below
k8smatrixwarden scan --mock -o json          # structured data + summary + full per-finding context
k8smatrixwarden scan --mock -o sarif         # SARIF 2.1 for GitHub Code Scanning / IDE integration
k8smatrixwarden scan --mock -o html          # self-contained, filterable HTML report
k8smatrixwarden scan --mock -o pdf --output-file report.pdf   # audit-ready PDF (needs the `pdf` extra)
```

Every format is designed to be genuinely useful, not a flat dump. **Every finding, in
every format, carries the same report-grade sections** — Summary, Standards &
Benchmark Mapping (with a reference link per framework), MITRE ATT&CK Mapping (with a
reference link per technique), Impact, and Validation (exact steps to reproduce/verify) —
sourced from one shared content layer (`core/finding_context.py`) so no format can say
something different from another about what a finding means.

| Format | What you get |
|---|---|
| **terminal** | A risk panel and findings grouped by severity in colored tables (⚡ marks attack-path-amplified findings). Needs `rich` (`pip install -e ".[pretty]"`); falls back to `text` otherwise. |
| **text** | The same content as terminal in dependency-free plain text, plus a compact `standards` tag line, a real-world `why` (impact) line, and a `verify` command per finding. |
| **markdown** | YAML frontmatter · verdict · risk gauge · severity/tactic/OWASP dashboards · an **⚡ Attack-Path Amplified** section · a full report-grade card per finding (Summary, Standards & Benchmark Mapping table with links, MITRE ATT&CK Mapping table with links, Impact, Validation steps) · appendix. Renders beautifully on GitHub/GitLab. |
| **json** | The full finding data **plus** a `summary` block **plus**, per finding: `summary`, `impact`, `validation_steps`, `standards` (framework/control/title/url), and `mitre_mapping` (tactic/technique/url) — ready for dashboards/automation. |
| **sarif** | SARIF 2.1 with `security-severity`, rich `tags`, a `help.markdown` block (impact + standards + validation — what GitHub Code Scanning actually renders), and `partialFingerprints` for stable de-duplication. |
| **html** | One self-contained file (no external assets), dark/light aware: risk gauge, severity chips, a Summary + Standards & Benchmark table + MITRE ATT&CK table + Impact + Validation per card, and **interactive severity filter buttons**. |
| **pdf** | A print/share-ready audit document — title page with a colored risk score, executive summary, coverage tables, and the full per-finding write-up. Requires the optional `pdf` extra (`pip install -e ".[pdf]"`, pulls in `fpdf2` — pure Python, no system dependencies); without it you get a clear error telling you to install it or use another format. |

**Two ways to save a report to a file of your choosing:**

1. **Inline, at scan time** — `--output-file PATH` writes the report as you scan:
   ```bash
   k8smatrixwarden scan --mock -o markdown --output-file report.md
   k8smatrixwarden scan --mock -o html --output-file report.html
   k8smatrixwarden scan --mock -o sarif --output-file results.sarif
   k8smatrixwarden scan --mock -o pdf --output-file report.pdf
   ```
   For `-o pdf`, `--output-file` is optional — if you omit it, k8smatrixwarden writes
   `k8smatrixwarden-report-<scan_id>.pdf` in the current directory (PDF is binary, so
   unlike every other format it's never printed to the terminal).
2. **Later, from a saved scan** — every scan is saved automatically, so just download it in any format/filename afterwards (see [§4.5](#45-k8smatrixwarden-report--download-saved-reports-later)):
   ```bash
   k8smatrixwarden scan --mock --name "Prod nightly"
   k8smatrixwarden report download --format markdown --output my-report.md
   k8smatrixwarden report download --format pdf --output my-report.pdf
   ```
   `report download --format pdf` **requires** `--output PATH` for the same binary-content
   reason — it errors out with a clear message rather than dumping bytes to your terminal.

In `k8smatrixwarden chat`, just say **“export markdown to my-report.md”** (or `save html as findings.html`, or `export pdf`).

Each finding's card carries a **Validation** section with the exact commands to reproduce and verify the finding against your cluster, alongside its Summary, Standards, MITRE, and Impact sections, e.g.:

> ##### ✅ Validation — How to Reproduce / Verify
>
> ```bash
> kubectl get clusterrolebinding default-admin -o yaml
> ```

— so a report doubles as a cited, verifiable audit record.

---

## 9. Running Against a Real Cluster

This section is the complete path from "I only ever ran `--mock`" to a real scan against your cluster. Four steps: install the live extra → point at your cluster → (recommended) set up least-privilege access → scan.

### 9.1 Step 1 — install the live-scanning extra

```bash
pip install -e ".[live]"
# or, if you didn't install the package at all:
pip install kubernetes
```

Without this, `--live` fails immediately with a clear message telling you to install it or use `--mock` — it never half-runs.

### 9.2 Step 2 — point k8smatrixwarden at your cluster

k8smatrixwarden uses the same kubeconfig resolution `kubectl` does. If `kubectl get pods` already works in your shell, `k8smatrixwarden scan --live` will too, with no extra flags:

```bash
k8smatrixwarden scan --live
```

If you work with **multiple clusters/contexts** (the normal case — check `kubectl config get-contexts`), be explicit rather than relying on whatever happens to be `current-context`:

```bash
kubectl config get-contexts                 # see what's available
k8smatrixwarden scan --live --context prod-cluster    # target a specific one
k8smatrixwarden scan --live --kubeconfig /path/to/other-kubeconfig --context staging
```

`--context` (and `--kubeconfig`) are available on `scan`, `cis`, and `chat`. If a context name doesn't exist, k8smatrixwarden fails with an explicit error naming the bad context/file — it will **not** silently fall back to some other config.

### 9.3 Step 3 — least-privilege RBAC (recommended before scanning anything you care about)

By default, `k8smatrixwarden --live` scans using whatever your current kubeconfig identity can already see — for a first try on a personal/lab cluster that's usually fine. For anything real, don't hand the scanner your own admin credentials: generate the exact, minimal, **read-only** RBAC the tool actually needs and run as that instead.

```bash
# Generate a ready-to-apply manifest: 1 Namespace + 1 ServiceAccount +
# one scoped ClusterRole/ClusterRoleBinding PER shard (10 pairs).
k8smatrixwarden roles --bind --output-file k8smatrixwarden-rbac.json

# Inspect it before trusting it — every rule is get/list/watch only, nothing writes:
cat k8smatrixwarden-rbac.json

# Apply it (kubectl accepts the JSON `List` kind directly, no YAML conversion needed):
kubectl apply -f k8smatrixwarden-rbac.json
```

Options:

| Flag | Default | Meaning |
|---|---|---|
| `--service-account NAME` | `k8smatrixwarden-scanner` | the ServiceAccount the roles are bound to |
| `--sa-namespace NS` | `k8smatrixwarden-system` | namespace the ServiceAccount lives in |
| `--no-create-namespace` | off | assume `--sa-namespace` already exists, don't emit a `Namespace` object |
| `--bind` | off | emit the full deployable manifest instead of bare `ClusterRole` JSON (see below) |

Then get a kubeconfig for that ServiceAccount and scan with it — e.g. with a short-lived token:
```bash
TOKEN=$(kubectl -n k8smatrixwarden-system create token k8smatrixwarden-scanner)
kubectl config set-credentials k8smatrixwarden-scanner --token="$TOKEN"
kubectl config set-context k8smatrixwarden-scan --cluster="$(kubectl config current-context)" --user=k8smatrixwarden-scanner
k8smatrixwarden scan --live --context k8smatrixwarden-scan
```

Without `--bind`, `k8smatrixwarden roles` prints just the bare `ClusterRole` objects (useful to *review* what each shard needs without deploying anything):
```bash
k8smatrixwarden roles                       # inspect only — nothing to apply, no bindings/SA
```

### 9.4 Step 4 — scan

Same commands as mock mode, minus `--mock`, plus `--live`:

```bash
k8smatrixwarden scan --live                                  # whole cluster
k8smatrixwarden scan --live -n production                    # one namespace
k8smatrixwarden scan --live --tactic "Privilege Escalation"   # by tactic
k8smatrixwarden scan --live -o markdown --output-file report.md
```

`--live` reads the cluster via the same raw camelCase JSON shape as the mock fixtures, so every rule behaves identically in both modes — nothing is mock-only or live-only *except* two things:

1. **Control-plane process flags** (things like `--anonymous-auth`) are recovered automatically on self-managed clusters by reading the `kube-apiserver`/`etcd`/`kube-scheduler`/`kube-controller-manager` static pods in `kube-system` — no extra setup needed (the generated RBAC manifest in §9.3 already grants the `pods` read needed for this).
2. **Node file-permission checks** (file ownership/permissions on disk) genuinely cannot be read through the Kubernetes API. Run `kube-bench` on your nodes and feed its output in:
   ```bash
   kube-bench run --benchmark cis-1.8 --json > kb.json
   k8smatrixwarden cis --live --kube-bench-json kb.json
   ```

If you're on a managed cluster (EKS/GKE/AKS), tell the CIS engine so it doesn't grade infrastructure you don't own:
```bash
k8smatrixwarden cis --live --profile eks
```

### 9.5 Quick reference

```bash
pip install -e ".[live]"                                  # 1. install
kubectl config get-contexts                               # 2. find your cluster
k8smatrixwarden roles --bind --output-file k8smatrixwarden-rbac.json         # 3a. generate least-priv RBAC
kubectl apply -f k8smatrixwarden-rbac.json                          # 3b. apply it
k8smatrixwarden scan --live --context my-cluster                    # 4. scan
```

---

## 11. Common Workflows

**"Is this cluster secure at all?"**
```bash
k8smatrixwarden scan --live -o markdown --output-file security-report.md
```

**"What can go wrong in production specifically?"**
```bash
k8smatrixwarden scan -n production --live -o markdown
```

**"Show me every way someone could escalate privileges."**
```bash
k8smatrixwarden scan --tactic "Privilege Escalation" --live
```

**"Are my secrets handled safely?"**
```bash
k8smatrixwarden scan --technique "Exposed Secrets" --live
# or, for the whole secrets domain:
k8smatrixwarden scan --module secrets --live
```

**"Just check RBAC."**
```bash
k8smatrixwarden scan --module rbac_identity --live -o markdown
```

**"How compliant are we with CIS?"**
```bash
k8smatrixwarden cis --live --profile eks -o markdown --output-file cis-report.md
```

**"Only show me the scary stuff."**
```bash
k8smatrixwarden scan --live --severity-min CRITICAL
```

**"I don't remember flag names, just let me talk to it."**
```bash
k8smatrixwarden chat
```
```
k8smatrixwarden› scan production for Persistence
Intent=SCAN  Scope=namespace/production  Selector=tactic=Persistence
→ resolves to 6 rule(s) across 3 shard(s): admission_control, compliance, workload_pod_security
  rules: admission-malicious-webhook, cronjob-suspicious, compliance-psa-not-restricted, ...

Proceed with this scan? [Y/n]
k8smatrixwarden› y
[... full report ...]
```

**"I want a specific technique, not a whole tactic."**
```bash
k8smatrixwarden scan --technique "Container Escape" --live
```

---

## 12. Configuration

The default configuration lives at `k8smatrixwarden/config/default_config.json` and controls:

- which **shards** are enabled/disabled
- **severity overrides** for individual rules
- **composite aliases** (the "Container Escape"-style outcome bundles used by `--technique`)

Override it without editing the shipped file:
```bash
k8smatrixwarden scan --config my-config.json --mock
```
Your file is deep-merged over the defaults, so you only need to specify what you're changing:
```json
{
  "shards": { "cloud_iam": { "enabled": false } },
  "rule_overrides": { "workload-latest-tag": { "severity": "LOW" } },
  "aliases": { "My Custom Bundle": ["workload-privileged-container", "rbac-wildcard-verbs"] }
}
```
Always run `k8smatrixwarden doctor --config my-config.json` after editing — it validates your aliases and rule overrides before you scan with them.

---

## 13. Understanding the Output

### 13.1 The scan report

Every scan report has the same shape, regardless of output format:

- **Generated time & scan id** — in **Indian Standard Time (IST, UTC+05:30)**. `generated_at` is written as an ISO-8601 timestamp with the `+05:30` offset (e.g. `2026-07-19T01:13:00+05:30`) and shown in reports/dashboard as `19 Jul 2026, 01:13 IST`. The scan id encodes the (optional) **name, date, and time** in IST: `<name>-YYYYMMDD-HHMMSS-<hash>` when you pass `--name`/`scan_name` (e.g. `prod-nightly-20260719-011300-a1b2`), or `scan-YYYYMMDD-HHMMSS-<hash>` when unnamed. The report's human display name is `<name> + date + time` (falling back to the id when unnamed).
- **Risk score** — `0–10`, plus a rating (`Excellent → Critical`) and a `0–100` security score. A scan whose evidence collection failed is rated **`Unknown`** and carries a *Scan incomplete* banner instead — see §13.2.
- **Scan warnings** — present only when coverage was partial or absent (`warnings[]` + `evidence_ok` in the JSON).
- **Severity counts** — 🔴 CRITICAL · 🟠 HIGH · 🟡 MEDIUM · 🟢 LOW.
- **Findings**, each with:
  - the **rule id** that fired and which **shard** owns it
  - the **resource** affected (kind/name/namespace)
  - its **MITRE ATT&CK** tactic + technique, **OWASP** category, and **CIS** control (when applicable). Every reference is a **direct deep link**: a MITRE technique goes to `attack.mitre.org/techniques/T1610/` (sub-techniques use MITRE's own `T1552/007/` slash form), and an **OWASP Kubernetes Top 10 ID goes to that category's own page** — `K03` → `…/2025/en/src/K03-Secrets-Management-Failures.html`, not the project landing page. This holds in the markdown, HTML and PDF reports and in the dashboard's threat-matrix drill-down.
  - a plain-English **message**
  - report-grade context (impact, standards mapping, and validation steps to reproduce/verify)

Findings that touch *multiple* MITRE tactics (e.g. a writable hostPath mount, which enables Persistence, Privilege Escalation, *and* Lateral Movement) are scored higher — this is the "attack-path bonus," and it's why one finding can outweigh several single-tactic ones.

### 13.2 Risk rating bands

| Score | Rating |
|---|---|
| 0.0 – 2.0 | 🟢 Excellent |
| 2.1 – 4.0 | 🟢 Good |
| 4.1 – 6.0 | 🟡 Fair |
| 6.1 – 8.0 | 🟠 Poor |
| 8.1 – 10.0 | 🔴 Critical |
| *(n/a)* | ⚠️ **Unknown** — the scan could not read the cluster, so no rating is possible. Not a passing grade; see §14 *"Live scan reports 0 findings"*. |

### 13.3 CIS Benchmark statuses

`k8smatrixwarden cis` gives every one of the 130 CIS controls one of five statuses — never a silent guess:

| Status | Meaning |
|---|---|
| ✅ `PASS` | evaluated and compliant |
| ❌ `FAIL` | evaluated and non-compliant — resources listed |
| 🔶 `MANUAL` | CIS itself designates this a human policy review, not automatable |
| ➖ `NA` | not applicable — you're on a managed profile and this control belongs to the cloud provider |
| ⚙️ `NEEDS_NODE` | genuinely requires reading a file on a node's disk; supply `--kube-bench-json` to resolve it |

---

## 14. Troubleshooting

**"`ModuleNotFoundError` when I run `python -m k8smatrixwarden ...`"**
Make sure you're running it from inside the `K8sMatrixWarden-Dev-1` folder (or that it's installed via `pip install -e .`).

**"Emoji/box characters show up as `?` or garbled on Windows"**
The CLI already forces UTF-8 output; if you still see garbling, run `chcp 65001` in your terminal first, or use `-o text` for a plain-ASCII report.

**"My selector says 'matched no rules'"**
Selector terms are validated, not silently ignored — a typo in a tactic/module/framework name raises an error rather than quietly scanning nothing. Run `k8smatrixwarden rules` or `k8smatrixwarden coverage` to see valid values, or `k8smatrixwarden scan --dry-run` to check resolution before scanning.

**"`--live` fails with an import error"**
Install the optional live-scanning dependency: `pip install -e ".[live]"`.

**"`--live --context X` says it couldn't load the kubeconfig/context"**
The error names the exact file and context it tried. Run `kubectl config get-contexts` to see valid names — a typo'd `--context` fails loudly rather than silently falling back to some other cluster.

**"`--live` says *Cannot reach the Kubernetes API server*"**
The context is valid but the cluster isn't answering (it's stopped, or the endpoint is wrong). The tool preflights connectivity and fails fast with a clear message instead of a raw connection traceback — it even prints the `kubectl … cluster-info` command to verify, and reminds you that `--mock` scans the bundled sample cluster. Start the cluster (e.g. minikube/docker-desktop/kind) and retry. This is surfaced the same way everywhere: the CLI exits non-zero with the message, and the web `POST /api/scan` returns a clean `400 {"error": …}` (never a 500 stack trace).

**"The dashboard's kubeconfig picker is gone / `POST /api/scan` returns 403 about credential plugins"**
The server is not bound to localhost, so it refuses a kubeconfig from the request body — loading one would execute its credential plugin as the server's user. See *Binding beyond localhost* in §4.8 for why and what to do instead.

**"`--live` says *Kubernetes API authentication failed* / *the AWS profile is not configured*"**
Your kubeconfig authenticates through a **credential plugin** and that plugin could not produce a token — almost always because the cloud profile it names is not configured on *this* machine. This is **not AWS-specific**: the detection re-runs whatever `exec` command the kubeconfig declares, so `aws eks get-token` (EKS), `gke-gcloud-auth-plugin` (GKE) and `kubelogin` (AKS) all surface their own real error. Older kubeconfigs that use the pre-`exec` `auth-provider` mechanism (`gcp` / `azure` / `oidc`) fail the same way and are named too, with the command that fixes them. The error quotes the plugin's own output verbatim, e.g.:

```
error: Kubernetes API authentication failed for context 'arn:aws:eks:…:cluster/prod' — the
kubeconfig loaded, but no valid credentials could be obtained.
  → aws --region us-east-1 eks get-token --cluster-name prod --profile prod-admin failed
    (exit 253): The config profile (prod-admin) could not be found
The kubeconfig's credential plugin could not issue a token. Check the cloud profile it depends on:
  * AWS / EKS   — the AWS profile named in the kubeconfig is not configured on this machine.
                  Verify: aws configure list-profiles  ·  AWS_PROFILE=<name> aws sts get-caller-identity
  * GCP / GKE   — gcloud auth login, and install gke-gcloud-auth-plugin.
  * Azure / AKS — az login (kubelogin).
Refusing to save a scan of a cluster that could not be read — an empty result would look like a clean cluster.
```

Configure the profile (`aws configure --profile <name>`, `gcloud auth login`, `az login`) and re-run. The CLI exits non-zero, and the dashboard's *Run a scan* form shows the full message instead of saving anything.

> **Why this is fatal rather than a warning.** The Python `kubernetes` client only *logs* an exec-plugin failure and then continues with **no credentials at all**, so every API request comes back `401`. Before this was fixed, each resource type was skipped as a warning, the scan collected nothing, and a cluster nobody had read was reported as **0 findings / Excellent**. K8sMatrixWarden now runs the credential plugin itself to recover the real reason, and treats a `401` — at preflight or mid-scan — as fatal.

**"My live scan finished but shows 0 findings and rating `Unknown`"**
That is the safety net above, in its non-fatal form: the cluster answered, but **every** resource type was refused (typically `403` across the board from an identity with no read RBAC). Rather than score an empty result as `Excellent`, the scan is marked `evidence_ok: false`, rated `Unknown`, and every surface — report, dashboard Overview/Threat Matrix/Attack Path/Attack Map, PDF, JSON — carries a *"Scan incomplete — this cluster was not read"* banner listing what was unreadable. Fix the RBAC (§9.3) and re-scan. Zero findings is only ever a *good* result when `evidence_ok` is true.

**"Live scan gets `Forbidden`/403 errors"**
The identity you're scanning with can't read some resource types. **This no longer aborts the scan** — each inaccessible resource type (RBAC-forbidden, or an API group absent on that cluster) is *skipped and recorded as a warning*, and the scan completes with everything else. The skipped types are reported back everywhere: on the CLI as `warning: <Kind>: skipped (…)` lines, via `run_scan`/`intelligent_scan` (MCP) and `POST /api/scan` (web) in a `warnings[]` field, **and on the saved result itself** (`warnings[]` + `evidence_ok` in the JSON report) so every later re-render — report, dashboard, PDF — still shows an amber *"Partial coverage"* banner naming the missing types. Partial coverage is visible, never silently under-reported. If *every* type is refused, the scan is rated `Unknown` instead (see above). To get full coverage, scan with an identity that has broad read access, or generate and apply the tool's own least-privilege manifest: `k8smatrixwarden roles --bind --output-file k8smatrixwarden-rbac.json && kubectl apply -f k8smatrixwarden-rbac.json` (§9.3), then scan as that ServiceAccount.

**"CIS report shows a lot of `NEEDS_NODE`"**
That's expected and correct on a fresh run — those controls need on-node file reads that the Kubernetes API cannot provide. Run `kube-bench` on your nodes and pass `--kube-bench-json` (§9). If you're on a managed cluster, also pass `--profile eks|gke|aks` to correctly exclude the provider-owned control plane instead of marking it un-checkable.

**"How do I know the tool itself isn't over-privileged?"**
Run `k8smatrixwarden roles` — it prints the exact, minimal `ClusterRole` generated per shard (only the resource verbs each shard's rules actually declared needing; every verb is `get`/`list`/`watch`, never a write). `k8smatrixwarden roles --bind` shows exactly what would be deployed, including the ServiceAccount bindings, before you `kubectl apply` anything.

---

## 15. Command Cheat Sheet

```bash
# Getting started
python -m k8smatrixwarden doctor                                          # validate install
python -m k8smatrixwarden scan --mock                                     # full mock scan
python -m k8smatrixwarden chat                                             # talk to it

# Scoping
python -m k8smatrixwarden scan -n NAMESPACE --mock
python -m k8smatrixwarden scan --pod NAME -n NAMESPACE --mock
python -m k8smatrixwarden scan --workload Deployment/NAME --mock
python -m k8smatrixwarden scan --image REF --mock

# Selecting
python -m k8smatrixwarden scan --tactic "Persistence" --mock
python -m k8smatrixwarden scan --technique "Container Escape" --mock
python -m k8smatrixwarden scan --module rbac_identity --mock
python -m k8smatrixwarden scan --rule RULE_ID --mock
python -m k8smatrixwarden scan --framework CIS --mock
python -m k8smatrixwarden scan --severity-min CRITICAL --mock

# Output — name the file directly
python -m k8smatrixwarden scan --mock -o markdown --output-file report.md
python -m k8smatrixwarden scan --mock -o sarif --output-file results.sarif
python -m k8smatrixwarden scan --mock -o pdf --output-file report.pdf
python -m k8smatrixwarden scan --mock -o json

# Scans save automatically → name one, then download later in any format/filename
python -m k8smatrixwarden scan --mock --name "Prod nightly"       # runs AND saves
python -m k8smatrixwarden scan --mock --no-save                    # throwaway run (not saved)
python -m k8smatrixwarden report list
python -m k8smatrixwarden report download --format html --output audit.html
python -m k8smatrixwarden report download --scan-id prod-nightly-… --format markdown --output report.md

# Compliance
python -m k8smatrixwarden cis --mock
python -m k8smatrixwarden cis --live --profile eks
python -m k8smatrixwarden cis --live --kube-bench-json kb.json

# CI gates
python -m k8smatrixwarden scan --live --fail-on CRITICAL
python -m k8smatrixwarden cis --live --fail-on-fail

# Inspection
python -m k8smatrixwarden rules
python -m k8smatrixwarden rules --module workload_pod_security
python -m k8smatrixwarden coverage
python -m k8smatrixwarden roles                    # inspect only
python -m k8smatrixwarden roles --bind --output-file k8smatrixwarden-rbac.json   # deployable manifest

# Preview (no scan)
python -m k8smatrixwarden scan --tactic Persistence --dry-run

# Live cluster
pip install -e ".[live]"
kubectl apply -f k8smatrixwarden-rbac.json                    # least-privilege RBAC (once)
python -m k8smatrixwarden scan --live --context my-cluster
python -m k8smatrixwarden scan --live --kubeconfig ~/.kube/config --context my-cluster

# Threat matrix
python -m k8smatrixwarden matrix --mock                       # matrix for a scan
python -m k8smatrixwarden matrix --coverage                    # global detection coverage
python -m k8smatrixwarden matrix --scan-id scan-… -o markdown --output-file matrix.md

# Web dashboard (browse scans, reports, threat matrix; run a scan)
python -m k8smatrixwarden web                                  # http://127.0.0.1:8080
python -m k8smatrixwarden web --port 9000 --open
python -m k8smatrixwarden web --no-scan                        # read-only

# MCP (AI-agent integration)
python -m k8smatrixwarden mcp --list-tools                     # lists all 30 tools
python -m k8smatrixwarden mcp
```

---

<p align="center">
  Need the architecture rationale instead of usage? See <code>README.md</code>.<br/>
  Need the original design spec? See <code>K8sMatrixWarden v1.0 - MITRE-Aligned Architecture.md</code>.
</p>
