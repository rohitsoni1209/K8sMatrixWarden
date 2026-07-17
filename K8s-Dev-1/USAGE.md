<h1 align="center">📖 k8ssec — Usage Guide</h1>

<p align="center">
  <em>Everything you need to actually <strong>use</strong> the tool — install, commands, examples, workflows.</em><br/>
  For architecture and design rationale, see <code>README.md</code>, <code>ANALYSIS.md</code>, and <code>REVIEW.md</code>.
</p>

---

## Table of Contents

1. [Requirements & Install](#1-requirements--install)
2. [Your First Scan (60 seconds)](#2-your-first-scan-60-seconds)
3. [The Three Ways to Use k8ssec](#3-the-three-ways-to-use-k8ssec)
4. [Command Reference](#4-command-reference)
   - [`scan`](#41-k8ssec-scan)
   - [`chat`](#42-k8ssec-chat)
   - [`cis`](#43-k8ssec-cis)
   - [`rules` / `coverage` / `roles` / `doctor`](#44-inspection-commands)
   - [`mcp`](#45-k8ssec-mcp)
5. [Scoping a Scan — what to scan](#5-scoping-a-scan--what-to-scan)
6. [Selecting Rules — what kind of issue to look for](#6-selecting-rules--what-kind-of-issue-to-look-for)
7. [Natural-Language Queries](#7-natural-language-queries)
8. [Output Formats](#8-output-formats)
9. [Running Against a Real Cluster](#9-running-against-a-real-cluster)
10. [CI/CD Integration](#10-cicd-integration)
11. [Common Workflows (copy-paste recipes)](#11-common-workflows-copy-paste-recipes)
12. [Configuration](#12-configuration)
13. [Understanding the Output](#13-understanding-the-output)
14. [Troubleshooting](#14-troubleshooting)
15. [Command Cheat Sheet](#15-command-cheat-sheet)

---

## 1. Requirements & Install

**Requirement:** Python 3.10+. That's it — the core engine has **zero required dependencies**.

```bash
cd K8s-Dev-1

# Option A — run directly, no install (recommended for trying it out)
python -m k8ssec doctor

# Option B — install the `k8ssec` command onto your PATH
pip install -e .
k8ssec doctor
```

Everything below assumes `python -m k8ssec ...`; if you installed it, drop the `python -m` and just use `k8ssec ...`.

### Optional extras

| Extra | Unlocks | Install |
|---|---|---|
| `live` | Scanning a real cluster (`--live`) | `pip install -e ".[live]"` |
| `pretty` | Nicer colored terminal tables | `pip install -e ".[pretty]"` |
| `mcp` | Running the MCP protocol server for AI-agent integration | `pip install -e ".[mcp]"` |
| `dev` | Running the test suite with real `pytest` | `pip install -e ".[dev]"` |

None of these are needed to use the tool — without them you get plain-text output and `--mock` scanning, which is fully functional.

### Sanity check

```bash
python -m k8ssec doctor
```

Expected output:
```
Shards loaded : 10 (admission_control, attack_surface, cloud_iam, cluster_control_plane, compliance, image_supply_chain, network_security, rbac_identity, secrets, workload_pod_security)
Rules loaded  : 56
Validation    : ✅ clean (taxonomy + aliases + no duplicate rule ids)
```

If you see that, everything is wired correctly and you're ready to scan.

---

## 2. Your First Scan (60 seconds)

The tool ships with a **bundled, deliberately-insecure mock cluster** so you can try every feature without a real Kubernetes cluster.

```bash
python -m k8ssec scan --mock
```

This runs all 56 rules against the mock cluster and prints a full terminal report: a risk score, a severity breakdown, and every finding with its MITRE ATT&CK mapping and a suggested fix.

Now try scanning for one specific kind of threat:

```bash
python -m k8ssec scan --tactic Persistence --mock
```

Or just talk to it:

```bash
python -m k8ssec chat
```

That's the whole tool in three commands. The rest of this guide covers every option in depth.

---

## 3. The Three Ways to Use k8ssec

| Mode | Command | Best for |
|---|---|---|
| **One-shot CLI** | `k8ssec scan --tactic Persistence -o markdown` | Scripts, CI pipelines, precise flag-driven scans |
| **One-shot natural language** | `k8ssec scan "scan production for Persistence"` | Quick ad-hoc questions without remembering flag names |
| **Interactive chat** | `k8ssec chat` | Exploring a cluster conversationally, multi-turn investigation |

All three go through the exact same engine (Orchestrator → Registry → Evidence Collector → Detection Engine), so results are identical no matter which you use — pick whichever fits the moment.

---

## 4. Command Reference

```
k8ssec [--config PATH] <command> [options]
```

`--config PATH` (global, before the subcommand) overrides the default rule/shard/alias configuration — see [§12 Configuration](#12-configuration).

### 4.1 `k8ssec scan`

Run a security scan. Either flag-driven or natural language.

```bash
k8ssec scan [QUERY...] [scope flags] [selector flags] [output flags] [flow flags]
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
| `-o, --output FORMAT` | `terminal, text, markdown, json, sarif, html` | `terminal` |
| `--output-file PATH` | write the rendered report to a file | — |

**Mode flags:**

| Flag | Meaning |
|---|---|
| `--mock` | use the bundled mock cluster (default when `--live` isn't given) |
| `--live` | scan a real cluster |
| `--fixture PATH` | use a custom mock cluster JSON instead of the bundled one |
| `--kubeconfig PATH` | kubeconfig file to use with `--live` (default: `~/.kube/config`) |
| `--context NAME` | kubeconfig context to use with `--live` (default: `current-context`) |

**Flow flags:**

| Flag | Meaning |
|---|---|
| `--dry-run` | show which rules *would* run, without scanning |
| `-y, --yes` | skip the confirmation prompt (natural-language mode) |
| `--fail-on LEVEL` | exit code `1` if any finding ≥ this severity (for CI) |

### 4.2 `k8ssec chat`

Interactive conversational assistant.

```bash
k8ssec chat [--live] [--fixture PATH] [--kubeconfig PATH] [--context NAME]
```

Type plain English; it shows you the resolved plan and waits for confirmation before scanning. See [§7](#7-natural-language-queries) for example phrases, and the transcript in [§11](#11-common-workflows-copy-paste-recipes).

### 4.3 `k8ssec cis`

Run the **full CIS Kubernetes Benchmark v1.8** — all 130 controls.

```bash
k8ssec cis [--mock|--live] [--kubeconfig PATH] [--context NAME] [--kube-bench-json PATH] [--profile PROFILE] [-o FORMAT] [--show-all] [--fail-on-fail]
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
k8ssec rules [--module SHARD] [--tactic TACTIC]   # list the rule registry
k8ssec coverage                                    # rules per MITRE tactic (bar chart)
k8ssec roles [--bind] [--service-account NAME] [--sa-namespace NS] [--no-create-namespace] [--output-file PATH]
k8ssec doctor                                       # validate the whole platform wiring
```

`k8ssec roles` (no flags) prints the bare, per-shard `ClusterRole` JSON — useful for review. Add `--bind` to get a complete, `kubectl apply`-able manifest (Namespace + ServiceAccount + all `ClusterRole`/`ClusterRoleBinding` pairs) — see [§9.3](#93-step-3--least-privilege-rbac-recommended-before-scanning-anything-you-care-about).

Run `doctor` any time something seems off, or after editing `config/default_config.json` — it will tell you exactly what's broken (duplicate rule ids, unknown MITRE technique ids, dangling aliases).

### 4.5 `k8ssec report` — download saved reports later

Scan once with `--save`, then list and re-download the result in any format, to any filename:

```bash
k8ssec scan --live --save                                   # persist to ./k8ssec-reports/
k8ssec report list                                          # what's stored
k8ssec report download --scan-id scan-… --format html --output audit.html
k8ssec report download --format markdown --output report.md   # (no --scan-id ⇒ latest)
```

| Command | Meaning |
|---|---|
| `report list [--limit N] [--reports-dir DIR]` | list stored scans (id, time, rating, risk, findings, scope) |
| `report download [--scan-id ID] [--format FMT] [--output FILE] [--reports-dir DIR]` | re-render a stored scan; `--scan-id` defaults to the latest; `--output` picks the filename (omit ⇒ print to stdout) |

Because the full result is stored, you can export it into a **different** format than you first viewed — scan once, download markdown for a PR *and* SARIF for CI *and* HTML for a stakeholder, all from the same saved scan. (CIS benchmark reports download via `k8ssec cis --output-file`.)

### 4.5 `k8ssec mcp`

Run the tool as an MCP (Model Context Protocol) server, so an AI agent can query rules, resolve selectors, and look up remediation playbooks programmatically.

```bash
k8ssec mcp --list-tools     # see what's exposed, without starting the server
k8ssec mcp                  # start the MCP server over stdio (requires: pip install -e ".[mcp]")
```

---

## 5. Scoping a Scan — what to scan

Scope answers **"where do I look?"** Only one scope applies at a time; if you don't specify one, the whole cluster is in scope.

```bash
k8ssec scan --mock                                    # entire cluster
k8ssec scan -n production --mock                       # one namespace
k8ssec scan --pod payment-api -n production --mock     # one pod
k8ssec scan --workload Deployment/user-service --mock  # one workload
k8ssec scan --image nginx:latest --mock                # anywhere this image runs
k8ssec scan --node worker-3 --mock                      # one node
k8ssec scan --helm-release my-app --mock                # one Helm release
```

Cluster-scoped resources (RBAC roles, admission webhooks) always stay visible even when you scope to a namespace — a namespace-scoped scan doesn't hide the ClusterRoleBinding that grants that namespace's pods `cluster-admin`.

---

## 6. Selecting Rules — what kind of issue to look for

Selector answers **"what am I looking for?"** You can combine axes freely (they combine as a union, then dedupe):

### By MITRE ATT&CK tactic
```bash
k8ssec scan --tactic Persistence --mock
k8ssec scan --tactic "Privilege Escalation" --tactic "Lateral Movement" --mock
```
Valid tactics: `Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Impact`

### By technique or composite/outcome alias
```bash
k8ssec scan --technique "Container Escape" --mock
k8ssec scan --technique "Exposed Secrets" --mock
k8ssec scan --technique "Privileged Pods" --mock
k8ssec scan --technique "Kubernetes API Exposure" --mock
```
These are curated bundles of rules mapped to a real-world attack outcome — see them all in `config/default_config.json` under `"aliases"`.

### By domain/module (a specific area of the platform)
```bash
k8ssec scan --module rbac_identity --mock
k8ssec scan --module network_security --mock
```
Module names match the shard names shown by `k8ssec doctor` — `cluster_control_plane, workload_pod_security, rbac_identity, network_security, image_supply_chain, secrets, compliance, attack_surface, admission_control, cloud_iam`.

### By exact rule
```bash
k8ssec rules --module workload_pod_security     # find the rule id you want
k8ssec scan --rule workload-privileged-container --mock
```

### By compliance framework
```bash
k8ssec scan --framework CIS --mock
k8ssec scan --framework OWASP --mock
k8ssec scan --framework NSA --mock
```
(For a *complete* CIS run including the checks that aren't mapped to a native rule, use `k8ssec cis` instead — see §4.3.)

### By minimum severity
```bash
k8ssec scan --severity-min CRITICAL --mock
```

### Combine them
```bash
k8ssec scan -n production --tactic "Credential Access" --severity-min HIGH -o markdown --mock
```

### Preview without scanning
Not sure what a selector resolves to? Use `--dry-run`:
```bash
k8ssec scan --tactic Persistence --dry-run
```
```
Scope=cluster-wide  Selector=tactic=Persistence
→ resolves to 6 rule(s): admission-malicious-webhook, cronjob-suspicious, compliance-psa-not-restricted, workload-writable-root-fs, workload-hostpath-root, workload-hostpath-writable
```

---

## 7. Natural-Language Queries

Every example below works both as a one-shot `k8ssec scan "..."` and typed directly into `k8ssec chat`:

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
k8ssec scan "scan production for Persistence" --yes --mock
```

### The chat is conversational (not just fixed phrases)

`k8ssec chat` understands **varied phrasing, synonyms, and typos** — you don't have to memorize exact wording:

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
you› how do I fix the secret issue?   # exact kubectl remediation commands
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
k8ssec scan --mock -o terminal      # rich terminal panels + per-severity tables (default)
k8ssec scan --mock -o text          # clean plain-text, zero dependencies
k8ssec scan --mock -o markdown      # the flagship report — see below
k8ssec scan --mock -o json          # structured data + summary + per-finding fix commands
k8ssec scan --mock -o sarif         # SARIF 2.1 for GitHub Code Scanning / IDE integration
k8ssec scan --mock -o html          # self-contained, filterable HTML report
```

Every format is designed to be genuinely useful, not a flat dump:

| Format | What you get |
|---|---|
| **terminal** | A risk panel, findings grouped by severity in colored tables (⚡ marks attack-path-amplified findings), and a "Top Remediations" panel. Needs `rich` (`pip install -e ".[pretty]"`); falls back to `text` otherwise. |
| **markdown** | YAML frontmatter · verdict · risk gauge · severity/tactic/OWASP dashboards · an **⚡ Attack-Path Amplified** section · per-finding cards with full MITRE→technique mapping, OWASP/CIS/NSA tags, and a **collapsible `kubectl` fix command** · a **Prioritized Remediation Plan** table · appendix. Renders beautifully on GitHub/GitLab. |
| **json** | The full finding data **plus** a `summary` block (severity percentages, OWASP breakdown, attack-path count) **plus** concrete `remediation.commands` on every finding — ready for dashboards/automation. |
| **sarif** | SARIF 2.1 with `security-severity` (so GitHub sorts/gates correctly), rich `tags` (`owasp/…`, `mitre/…`, `cis/…`), help text with the fix, and `partialFingerprints` for stable de-duplication. |
| **html** | One self-contained file (no external assets), dark/light aware, with a risk gauge, severity chips, MITRE/OWASP tag chips, collapsible remediation, and **interactive severity filter buttons**. |
| **text** | The same content as terminal, in dependency-free plain text with box-drawing headers and severity bars. |

**Two ways to save a report to a file of your choosing:**

1. **Inline, at scan time** — `--output-file PATH` writes the report as you scan:
   ```bash
   k8ssec scan --mock -o markdown --output-file report.md
   k8ssec scan --mock -o html --output-file report.html
   k8ssec scan --mock -o sarif --output-file results.sarif
   ```
2. **Later, from a saved scan** — scan once with `--save`, then download in any format/filename (see [§4.5](#45-k8ssec-report--download-saved-reports-later)):
   ```bash
   k8ssec scan --mock --save
   k8ssec report download --format markdown --output my-report.md
   ```

In `k8ssec chat`, just say **“export markdown to my-report.md”** (or `save html as findings.html`).

The **markdown report embeds the actual remediation command** for each finding (formatted with the real resource name/namespace), e.g.:

> <details><summary>🛠️ Remediation — Remove cluster-admin from default SA</summary>
>
> ```bash
> kubectl delete clusterrolebinding default-admin
> ```
> </details>

— so a report doubles as a runnable fix checklist. (Destructive commands still require confirmation through the Remediation Agent; the report only *shows* them.)

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

### 9.2 Step 2 — point k8ssec at your cluster

k8ssec uses the same kubeconfig resolution `kubectl` does. If `kubectl get pods` already works in your shell, `k8ssec scan --live` will too, with no extra flags:

```bash
k8ssec scan --live
```

If you work with **multiple clusters/contexts** (the normal case — check `kubectl config get-contexts`), be explicit rather than relying on whatever happens to be `current-context`:

```bash
kubectl config get-contexts                 # see what's available
k8ssec scan --live --context prod-cluster    # target a specific one
k8ssec scan --live --kubeconfig /path/to/other-kubeconfig --context staging
```

`--context` (and `--kubeconfig`) are available on `scan`, `cis`, and `chat`. If a context name doesn't exist, k8ssec fails with an explicit error naming the bad context/file — it will **not** silently fall back to some other config.

### 9.3 Step 3 — least-privilege RBAC (recommended before scanning anything you care about)

By default, `k8ssec --live` scans using whatever your current kubeconfig identity can already see — for a first try on a personal/lab cluster that's usually fine. For anything real, don't hand the scanner your own admin credentials: generate the exact, minimal, **read-only** RBAC the tool actually needs and run as that instead.

```bash
# Generate a ready-to-apply manifest: 1 Namespace + 1 ServiceAccount +
# one scoped ClusterRole/ClusterRoleBinding PER shard (10 pairs).
k8ssec roles --bind --output-file k8ssec-rbac.json

# Inspect it before trusting it — every rule is get/list/watch only, nothing writes:
cat k8ssec-rbac.json

# Apply it (kubectl accepts the JSON `List` kind directly, no YAML conversion needed):
kubectl apply -f k8ssec-rbac.json
```

Options:

| Flag | Default | Meaning |
|---|---|---|
| `--service-account NAME` | `k8ssec-scanner` | the ServiceAccount the roles are bound to |
| `--sa-namespace NS` | `k8ssec-system` | namespace the ServiceAccount lives in |
| `--no-create-namespace` | off | assume `--sa-namespace` already exists, don't emit a `Namespace` object |
| `--bind` | off | emit the full deployable manifest instead of bare `ClusterRole` JSON (see below) |

Then get a kubeconfig for that ServiceAccount and scan with it — e.g. with a short-lived token:
```bash
TOKEN=$(kubectl -n k8ssec-system create token k8ssec-scanner)
kubectl config set-credentials k8ssec-scanner --token="$TOKEN"
kubectl config set-context k8ssec-scan --cluster="$(kubectl config current-context)" --user=k8ssec-scanner
k8ssec scan --live --context k8ssec-scan
```

Without `--bind`, `k8ssec roles` prints just the bare `ClusterRole` objects (useful to *review* what each shard needs without deploying anything):
```bash
k8ssec roles                       # inspect only — nothing to apply, no bindings/SA
```

### 9.4 Step 4 — scan

Same commands as mock mode, minus `--mock`, plus `--live`:

```bash
k8ssec scan --live                                  # whole cluster
k8ssec scan --live -n production                    # one namespace
k8ssec scan --live --tactic "Privilege Escalation"   # by tactic
k8ssec scan --live -o markdown --output-file report.md
```

`--live` reads the cluster via the same raw camelCase JSON shape as the mock fixtures, so every rule behaves identically in both modes — nothing is mock-only or live-only *except* two things:

1. **Control-plane process flags** (things like `--anonymous-auth`) are recovered automatically on self-managed clusters by reading the `kube-apiserver`/`etcd`/`kube-scheduler`/`kube-controller-manager` static pods in `kube-system` — no extra setup needed (the generated RBAC manifest in §9.3 already grants the `pods` read needed for this).
2. **Node file-permission checks** (file ownership/permissions on disk) genuinely cannot be read through the Kubernetes API. Run `kube-bench` on your nodes and feed its output in:
   ```bash
   kube-bench run --benchmark cis-1.8 --json > kb.json
   k8ssec cis --live --kube-bench-json kb.json
   ```

If you're on a managed cluster (EKS/GKE/AKS), tell the CIS engine so it doesn't grade infrastructure you don't own:
```bash
k8ssec cis --live --profile eks
```

### 9.5 Quick reference

```bash
pip install -e ".[live]"                                  # 1. install
kubectl config get-contexts                               # 2. find your cluster
k8ssec roles --bind --output-file k8ssec-rbac.json         # 3a. generate least-priv RBAC
kubectl apply -f k8ssec-rbac.json                          # 3b. apply it
k8ssec scan --live --context my-cluster                    # 4. scan
```

---

## 10. CI/CD Integration

Use `--fail-on` (scan) or `--fail-on-fail` (cis) to get a non-zero exit code when something bad is found — this is what makes the tool usable as a pipeline gate.

```bash
# Fail the build if any CRITICAL finding exists
k8ssec scan --live --fail-on CRITICAL -o sarif --output-file results.sarif

# Fail the build if any CIS control fails
k8ssec cis --live --fail-on-fail -o json --output-file cis-results.json
```

**Example GitHub Actions step:**
```yaml
- name: Kubernetes security scan
  run: |
    python -m k8ssec scan --live --fail-on CRITICAL -o sarif --output-file results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## 11. Common Workflows (copy-paste recipes)

**"Is this cluster secure at all?"**
```bash
k8ssec scan --live -o markdown --output-file security-report.md
```

**"What can go wrong in production specifically?"**
```bash
k8ssec scan -n production --live -o markdown
```

**"Show me every way someone could escalate privileges."**
```bash
k8ssec scan --tactic "Privilege Escalation" --live
```

**"Are my secrets handled safely?"**
```bash
k8ssec scan --technique "Exposed Secrets" --live
# or, for the whole secrets domain:
k8ssec scan --module secrets --live
```

**"Just check RBAC."**
```bash
k8ssec scan --module rbac_identity --live -o markdown
```

**"How compliant are we with CIS?"**
```bash
k8ssec cis --live --profile eks -o markdown --output-file cis-report.md
```

**"Only show me the scary stuff."**
```bash
k8ssec scan --live --severity-min CRITICAL
```

**"I don't remember flag names, just let me talk to it."**
```bash
k8ssec chat
```
```
k8ssec› scan production for Persistence
Intent=SCAN  Scope=namespace/production  Selector=tactic=Persistence
→ resolves to 6 rule(s) across 3 shard(s): admission_control, compliance, workload_pod_security
  rules: admission-malicious-webhook, cronjob-suspicious, compliance-psa-not-restricted, ...

Proceed with this scan? [Y/n]
k8ssec› y
[... full report ...]
```

**"I want a specific technique, not a whole tactic."**
```bash
k8ssec scan --technique "Container Escape" --live
```

---

## 12. Configuration

The default configuration lives at `k8ssec/config/default_config.json` and controls:

- which **shards** are enabled/disabled
- **severity overrides** for individual rules
- **composite aliases** (the "Container Escape"-style outcome bundles used by `--technique`)

Override it without editing the shipped file:
```bash
k8ssec scan --config my-config.json --mock
```
Your file is deep-merged over the defaults, so you only need to specify what you're changing:
```json
{
  "shards": { "cloud_iam": { "enabled": false } },
  "rule_overrides": { "workload-latest-tag": { "severity": "LOW" } },
  "aliases": { "My Custom Bundle": ["workload-privileged-container", "rbac-wildcard-verbs"] }
}
```
Always run `k8ssec doctor --config my-config.json` after editing — it validates your aliases and rule overrides before you scan with them.

---

## 13. Understanding the Output

### 13.1 The scan report

Every scan report has the same shape, regardless of output format:

- **Risk score** — `0–10`, plus a rating (`Excellent → Critical`) and a `0–100` security score.
- **Severity counts** — 🔴 CRITICAL · 🟠 HIGH · 🟡 MEDIUM · 🟢 LOW.
- **Findings**, each with:
  - the **rule id** that fired and which **shard** owns it
  - the **resource** affected (kind/name/namespace)
  - its **MITRE ATT&CK** tactic + technique, **OWASP** category, and **CIS** control (when applicable)
  - a plain-English **message**
  - a **remediation reference** pointing at a fix playbook, where one exists

Findings that touch *multiple* MITRE tactics (e.g. a writable hostPath mount, which enables Persistence, Privilege Escalation, *and* Lateral Movement) are scored higher — this is the "attack-path bonus," and it's why one finding can outweigh several single-tactic ones.

### 13.2 Risk rating bands

| Score | Rating |
|---|---|
| 0.0 – 2.0 | 🟢 Excellent |
| 2.1 – 4.0 | 🟢 Good |
| 4.1 – 6.0 | 🟡 Fair |
| 6.1 – 8.0 | 🟠 Poor |
| 8.1 – 10.0 | 🔴 Critical |

### 13.3 CIS Benchmark statuses

`k8ssec cis` gives every one of the 130 CIS controls one of five statuses — never a silent guess:

| Status | Meaning |
|---|---|
| ✅ `PASS` | evaluated and compliant |
| ❌ `FAIL` | evaluated and non-compliant — resources listed |
| 🔶 `MANUAL` | CIS itself designates this a human policy review, not automatable |
| ➖ `NA` | not applicable — you're on a managed profile and this control belongs to the cloud provider |
| ⚙️ `NEEDS_NODE` | genuinely requires reading a file on a node's disk; supply `--kube-bench-json` to resolve it |

---

## 14. Troubleshooting

**"`ModuleNotFoundError` when I run `python -m k8ssec ...`"**
Make sure you're running it from inside the `K8s-Dev-1` folder (or that it's installed via `pip install -e .`).

**"Emoji/box characters show up as `?` or garbled on Windows"**
The CLI already forces UTF-8 output; if you still see garbling, run `chcp 65001` in your terminal first, or use `-o text` for a plain-ASCII report.

**"My selector says 'matched no rules'"**
Selector terms are validated, not silently ignored — a typo in a tactic/module/framework name raises an error rather than quietly scanning nothing. Run `k8ssec rules` or `k8ssec coverage` to see valid values, or `k8ssec scan --dry-run` to check resolution before scanning.

**"`--live` fails with an import error"**
Install the optional live-scanning dependency: `pip install -e ".[live]"`.

**"`--live --context X` says it couldn't load the kubeconfig/context"**
The error names the exact file and context it tried. Run `kubectl config get-contexts` to see valid names — a typo'd `--context` fails loudly rather than silently falling back to some other cluster.

**"Live scan gets `Forbidden`/403 errors"**
The identity you're scanning with doesn't have enough read access. Either use an identity that already has broad read access (fine for a first personal-cluster test), or generate and apply the tool's own least-privilege manifest: `k8ssec roles --bind --output-file k8ssec-rbac.json && kubectl apply -f k8ssec-rbac.json` (§9.3), then scan as that ServiceAccount.

**"CIS report shows a lot of `NEEDS_NODE`"**
That's expected and correct on a fresh run — those controls need on-node file reads that the Kubernetes API cannot provide. Run `kube-bench` on your nodes and pass `--kube-bench-json` (§9). If you're on a managed cluster, also pass `--profile eks|gke|aks` to correctly exclude the provider-owned control plane instead of marking it un-checkable.

**"How do I know the tool itself isn't over-privileged?"**
Run `k8ssec roles` — it prints the exact, minimal `ClusterRole` generated per shard (only the resource verbs each shard's rules actually declared needing; every verb is `get`/`list`/`watch`, never a write). `k8ssec roles --bind` shows exactly what would be deployed, including the ServiceAccount bindings, before you `kubectl apply` anything.

---

## 15. Command Cheat Sheet

```bash
# Getting started
python -m k8ssec doctor                                          # validate install
python -m k8ssec scan --mock                                     # full mock scan
python -m k8ssec chat                                             # talk to it

# Scoping
python -m k8ssec scan -n NAMESPACE --mock
python -m k8ssec scan --pod NAME -n NAMESPACE --mock
python -m k8ssec scan --workload Deployment/NAME --mock
python -m k8ssec scan --image REF --mock

# Selecting
python -m k8ssec scan --tactic "Persistence" --mock
python -m k8ssec scan --technique "Container Escape" --mock
python -m k8ssec scan --module rbac_identity --mock
python -m k8ssec scan --rule RULE_ID --mock
python -m k8ssec scan --framework CIS --mock
python -m k8ssec scan --severity-min CRITICAL --mock

# Output — name the file directly
python -m k8ssec scan --mock -o markdown --output-file report.md
python -m k8ssec scan --mock -o sarif --output-file results.sarif
python -m k8ssec scan --mock -o json

# Save once, download later in any format/filename
python -m k8ssec scan --mock --save
python -m k8ssec report list
python -m k8ssec report download --format html --output audit.html
python -m k8ssec report download --scan-id scan-… --format markdown --output report.md

# Compliance
python -m k8ssec cis --mock
python -m k8ssec cis --live --profile eks
python -m k8ssec cis --live --kube-bench-json kb.json

# CI gates
python -m k8ssec scan --live --fail-on CRITICAL
python -m k8ssec cis --live --fail-on-fail

# Inspection
python -m k8ssec rules
python -m k8ssec rules --module workload_pod_security
python -m k8ssec coverage
python -m k8ssec roles                    # inspect only
python -m k8ssec roles --bind --output-file k8ssec-rbac.json   # deployable manifest

# Preview (no scan)
python -m k8ssec scan --tactic Persistence --dry-run

# Live cluster
pip install -e ".[live]"
kubectl apply -f k8ssec-rbac.json                    # least-privilege RBAC (once)
python -m k8ssec scan --live --context my-cluster
python -m k8ssec scan --live --kubeconfig ~/.kube/config --context my-cluster

# MCP (AI-agent integration)
python -m k8ssec mcp --list-tools
python -m k8ssec mcp
```

---

<p align="center">
  Need the architecture rationale instead of usage? See <code>README.md</code>.<br/>
  Need the original design spec? See <code>K8s Security Tool v3.0 - MITRE-Aligned Architecture.md</code>.
</p>
