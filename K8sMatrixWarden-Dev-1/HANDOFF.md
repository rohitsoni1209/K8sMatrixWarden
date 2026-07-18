# K8sMatrixWarden — Handoff & Roadmap

**Purpose:** everything that changed in this work session + a detailed, prioritized backlog
so anyone can pick up and keep building. Written for a developer who has *not* seen the
session — file paths, data shapes, and gotchas are spelled out.

- **Repo root:** `K8sMatrixWarden-Dev-1/`
- **Package:** `k8smatrixwarden/`
- **Tests:** `229 passing` (`python3 -m tests.run_tests`)
- **MCP tools:** `33` (was 27; +6 this session)
- **Web dashboard:** interactive SPA, live on `:8080`
- **Runtime target:** live **Kubernetes Goat** on a local **minikube** cluster

---

## 0. TL;DR of the direction

The tool started as a solid K8s **scanner** (config → findings → MITRE threat matrix).
The strategic bet is: *scanning alone is table stakes* (Trivy/kubescape/kube-bench all do it).
The differentiator is **scan × runtime correlation + causality**: not "here's a weakness"
but "**this** weakness is being **exploited right now**, and here's the kill-chain."

This session built the first half of that: the correlation engine, drift detection,
attack-path derivation, cloud auto-detection, a one-call `intelligent_scan`, and a rebuilt
**interactive dashboard**. It also pointed the whole thing at a real vulnerable cluster
(Kubernetes Goat) instead of only the bundled mock.

---

## 0.1 Follow-up hardening pass (after this handoff)

Three robustness/packaging fixes landed on top of the work above (tests `220 → 229`):

1. **Shared report store across surfaces.** Every surface (CLI, MCP, web) now defaults to
   one cwd-independent store — `~/.k8smatrixwarden/reports`, override with
   `$K8SMATRIXWARDEN_REPORTS_DIR` — via new `core/report_store.default_reports_dir()`. Before,
   the relative `k8smatrixwarden-reports` default resolved against each process's cwd, so a
   CLI/MCP `--save` scan never showed up in the web dashboard's history. Now it does.
2. **Fault-tolerant live scanning.** `core/evidence.py` `LiveEvidenceCollector` now preflights
   connectivity (fails fast with a clear "Cannot reach the API server … cluster-info … --mock"
   message instead of a `urllib3` traceback) and treats a per-resource `403`/`404` as a
   *skip-with-warning* rather than aborting the whole scan. Skipped types surface as
   `collector.warnings` → CLI `warning:` lines and a `warnings[]` field on web/MCP responses.
   Tests: `tests/test_live_resilience.py` (8).
3. **Editable install pointed at a stale copy.** `pip install -e .` was resolving to an older
   sibling checkout with only 27 MCP tools; re-running it from this repo restores all 33.

---

## 0.2 Remediation removal pass (detect-and-report only)

The **Remediation Agent and its whole subsystem were removed** in a later pass — the tool is
now strictly detect-and-report, with no write/apply path on any surface (tests `229 → 184`,
MCP tools `33 → 30`).

- **Deleted:** `agents/remediation.py` (the Agent), `core/remediation_engine.py` (schema-aware
  command generation / `FIELD_PATCHES` / `generate_remediation`), `tests/test_remediation_engine.py`.
- **MCP tools dropped (3):** `explain_remediation`, `get_playbook`, `list_playbooks`. The
  `PLAYBOOKS` dataset was removed from `mcp/datasets.py` (5 datasets now, not 6).
- **Data model:** `remediation_ref` removed from `Rule` and `Finding` (`core/models.py`) and
  from every rule across all 10 shards. `ResourceRef.owner_kind/owner_name/labels/annotations`
  are kept — they're neutral resource-identity metadata, not remediation.
- **Reports:** the per-finding "Remediation" section and the markdown "Prioritized Remediation
  Plan" are gone from all formats (terminal/text/markdown/json/sarif/html/pdf). Findings still
  carry Summary / Standards / MITRE / Impact / Validation via `core/finding_context.py`.
- **Chat/orchestrator:** the "how do I fix" intent and the `remediate` orchestrator intent were
  removed; a fix request now falls through to the normal did-you-mean handling.
- **Safety framing flipped:** it used to be "remediation exists but needs interactive
  confirmation"; it is now "no remediation path exists at all." `test_no_remediation_or_apply_tool_is_exposed`
  still guards the MCP surface.

---

## 1. What changed this session

### 1.1 Cloud/provider auto-detection
**Files:** `core/evidence.py` (new `detect_provider`), `mcp/server.py` (new `detect_cluster_provider` tool)

- `detect_provider(nodes: list[dict]) -> {cloud, managed, profile}` reads Node `providerID`
  + managed-service labels (`cloud.google.com/gke-nodepool`, `eks.amazonaws.com/nodegroup`,
  `kubernetes.azure.com/cluster`).
  - `cloud`: `gcp | aws | azure | local`
  - `managed`: is the control plane a managed offering (GKE/EKS/AKS)?
  - `profile`: `gke | eks | aks | self-managed` — feeds straight into CIS.
- **Why it matters:** CIS benchmark previously required the user to pass `--profile eks` by
  hand. Now `run_cis_benchmark(profile="auto")` (the new default) detects it. Managed control
  planes get sections 1–3 marked `NA` instead of ungradeable.
- **Gotcha:** a cloud VM running self-managed K8s (no managed label) maps to `cloud=aws` but
  `profile=self-managed` — the control plane is still inspectable. That distinction is
  deliberate; don't "simplify" it away.
- **Test:** `tests/test_provider.py`

### 1.2 Attack-path derivation
**Files:** `core/threat_matrix.py` (new `attack_paths`), `mcp/server.py` (new `build_attack_path` tool)

- `attack_paths(matrix: ThreatMatrix) -> dict` walks the matrix columns (already in
  kill-chain order, `TACTIC_ORDER`) and chains the **hit** cells into an exploit path.
- Returns: `chain` (tactic sequence string), `steps[]` (per tactic: techniques + resources
  + worst severity), `entry_points`, `reaches_impact`, `tactic_count`.
- **Design note / ceiling:** this is **kill-chain-order chaining** (the ATT&CK-navigator
  convention), *not* a per-finding causal graph. It answers "which tactics can an attacker
  string together here." Upgrade path is documented inline: true edge inference
  (pod-A's ServiceAccount can reach binding-B) when single-target blast-radius matters.

### 1.3 `intelligent_scan` — the one-call tool
**File:** `mcp/server.py`

- `intelligent_scan(query, ...)` = interpret NL → detect cluster → scan → findings + risk +
  threat matrix + attack path, in a single call. Composes `interpret_query` + `run_scan` +
  `build_threat_matrix` + `build_attack_path`.
- Returns top-level `intent`, `scope`, `selector`, `rule_count`, `cluster` (detected
  provider), plus the full scan JSON (`findings`, `risk`, `threat_matrix`) and `attack_path`.
- **Gotcha:** it calls `Orchestrator.run(...)` — NOT `Orchestrator.scan(...)` (that method
  doesn't exist; cost me a debugging cycle).

### 1.4 Scan × Runtime correlation + drift  ← **the differentiator**
**Files:** `core/correlation.py` (NEW), `mcp/server.py` (new `correlate_runtime` + `detect_drift` tools)

- **`correlate(findings, alerts) -> dict`** joins static scan findings to live runtime
  alerts by **MITRE tactic** (+ namespace when the event names one):
  - `confirmed` — same tactic + same namespace → the static weakness is being acted on
  - `corroborated` — same tactic → behaviour aligns with a known gap
  - `runtime-only` — live behaviour the scan never predicted (often the most interesting)
  - Headline counts: `confirmed_exploitation`, `correlated`, `runtime_only`.
- **`detect_drift(pods, events) -> dict`** flags runtime behaviour that **contradicts a
  Pod's declared security posture** — the strongest signal, because it means a control the
  operator thinks is enforced is not:
  - process as uid 0 despite `runAsNonRoot: true`
  - write outside tmp despite `readOnlyRootFilesystem: true`
  - a privileged-only op (`nsenter`/`mount`/`release_agent`) from a non-privileged pod
  - Reuses `Evidence` static helpers (`dig`, `containers`) to read the declared posture.
- **Gotcha:** drift needs events that name their pod (Falco `k8s.pod.name` enrichment).
  Un-attributable events are **skipped, not guessed** — deliberate, keeps false positives ~0.
- The runtime *detection* rules themselves already existed in `agents/runtime.py`
  (11 Falco/audit rules). This session added the **correlation layer** on top.
- **Test:** `tests/test_correlation.py`

### 1.5 Falco feed ingestion (normalizer)
**Files:** `agents/runtime.py` (new `normalize_falco_event`, `normalize_events`), `web/app.py`, `mcp/server.py`

- Falco/falcosidekick sends nested JSON (`output_fields` with dotted keys like `proc.name`, `k8s.pod.name`).
  Our `RuntimeAgent` matchers expect flat keys (`proc`, `pod`, `namespace`, etc).
- `normalize_falco_event(raw: dict) -> dict` bridges: parses both syscall (Falco) and k8s_audit
  sources, flattens to the internal shape.
- `normalize_events(raw)` wraps single or batch, accepts Falco-native OR already-flat.
- **Live Falco ready:** `POST /api/runtime` accepts raw falcosidekick POSTs one-at-a-time.
  `correlate_runtime` and `detect_drift` MCP tools also normalize on ingest.
- **Test:** `tests/test_correlation.py` (5 new tests for normalization)

### 1.6 Dashboard rebuilt → interactive SPA + Attack Map visualization
**Files:** `web/pages.py` (full rewrite), `web/app.py` (new endpoints)

- The old dashboard was server-rendered static HTML. It's now a **client-side SPA**
  (vanilla JS, zero dependencies, zero external hosts — same constraint the HTML report has).
- Serves a shell (`dashboard_page`) that fetches **`GET /api/dashboard`** once and renders
  everything client-side. Seven tabs:
  - **Overview** — KPIs (risk/rating/high+/coverage), priority findings, risk-by-domain
    bars, attack-surface heatmap, risk trend sparkline, **finding age (MTTD/MTTR)** panel,
    runtime readiness (which tactics have detections armed)
  - **Findings** — live search + severity chips (CRITICAL/HIGH/MEDIUM/LOW) + tactic filter
    + sortable columns (all 358 Goat findings; caps render at 400)
  - **Threat Matrix** — 9×N interactive heatmap; click red cell → inline finding list
  - **Attack Path** — kill-chain flow (tactics → techniques), reaches-Impact flag, entry points
  - **Attack Map** — kill-chain WITH vulnerable resources grouped per tactic (new) — shows
    which Pods/Deployments/etc are exposed at each stage of the chain
  - **Runtime** — paste/sample Falco events OR load sample → correlate + detect drift,
    rendered as correlation cards (confirmed/corroborated/runtime-only) + drift findings
  - **Scan** — run-a-scan form (defaults to **live** mode) + scan history table
- **New API endpoints** (`web/app.py`):
  - `GET /api/dashboard` — everything: scan meta, findings, threat_matrix, attack_path,
    runtime readiness (armed tripwires per tactic), trend (risk over time), timeline
    (open/resolved counts), history (saved scans list).
  - `GET /api/timeline` — standalone timeline endpoint (MTTD/MTTR metrics).
  - `POST /api/runtime` — ingest events `{events:[...]}` or bare Falco event →
    `{correlation, drift}`. Accepts single event (falcosidekick one-per-POST) or batch.
- **Animation polish:** spring easing on hover (KPIs, buttons, cells), smooth focus rings,
  responsive delays (.25s–.35s). No motion-reduce yet (add if needed).
- **Gotcha:** the web server does **not** hot-reload. After editing `pages.py`/`app.py`
  restart it (`pkill -f "k8smatrixwarden web"`).

### 1.7 Timeline / MTTD / MTTR
**Files:** `core/report_store.py` (new `_timeline.json` index, `timeline()` method), `web/app.py` (`/api/timeline`), `web/pages.py` (dashboard panel)

- `ReportStore.save()` diffs each scan against accumulated `_timeline.json` index
  (keyed by `rule_id|kind|name|namespace`). Tracks `first_seen`, `last_seen`, `resolved_at`.
- `timeline()` returns open/resolved counts, `oldest_open_days`, `median_open_days`,
  `oldest_critical` (the highest-priority unresolved finding), and per-finding `age_days`.
- Surface: `GET /api/timeline` + included in `/api/dashboard`; "⏱️ Finding age" panel in Overview.
- **Ceiling (inline):** granularity = scan cadence; timeline meaningful within same-scope scans.
  Index per scope if you run mixed scans (cluster vs namespace on one store).
- `list()` skips `_`-prefixed index files to avoid treating timeline as a report.
- **Next:** stamp `first_exploited_at` on correlation confirmations (needs live Falco feed).

### 1.8 Attack path in exported reports
**Files:** `core/reporting.py` (new `_attack_path_md()` helper + embedding in json/markdown),
`core/threat_matrix.py` (`attack_paths` already existed)

- JSON report embeds `attack_path` next to `threat_matrix` — full kill-chain struct.
- Markdown report renders "🎯 Kill-chain exploit path" section (chain string + per-tactic
  technique list). Re-uses `attack_paths()` function from `threat_matrix.py`.
- **Remaining:** HTML/PDF reports still link to web matrix instead of rendering chain inline.
  Add visual rendering there if user-facing reports need standalone chains.
- **Test:** `tests/test_report_store.py::test_attack_path_embedded_in_reports`

### 1.9 Deploy Falco MCP tool + one-click setup
**Files:** `mcp/server.py` (new `deploy_falco` tool)

- `deploy_falco(webhook_url, namespace="falco")` runs `helm repo add` + `helm install falco`
  with falcosidekick webhook pointing at your runtime endpoint.
- Returns status dict with install log steps + next steps (check pod status, tail logs,
  send events to `/api/runtime`).
- **Note:** helm must be installed on the system (not in the tool itself).
- **Integration:** falcosidekick posts raw Falco events to `/api/runtime` (normalized on ingest).

### 1.6 Live Kubernetes Goat integration
**No code change** — this already worked via `LiveEvidenceCollector`. To reproduce:

```bash
pip3 install kubernetes                 # the only missing piece
kubectl config current-context          # should be: minikube (where Goat runs)
python3 -m k8smatrixwarden scan --live --context minikube --save -o json
```

- **Important:** `http://127.0.0.1:1234/` is the Goat **web portal**, NOT the K8s API. The
  tool scans the **API** via kubeconfig (`--live --context minikube`), never an HTTP URL.
- Live Goat result: **9.8/10 Critical, 358 findings** (35 critical incl. cluster-admin on
  default SA, hostPath `/` mounts on health-check + system-monitor).

### 1.10 Tests
- New: `tests/test_provider.py`, `tests/test_correlation.py`, `tests/test_report_store.py` (timeline + attack-path)
- Updated: `tests/test_mcp.py` (tool-registry: +deploy_falco), `tests/test_web.py` (SPA contract + `/api/runtime`).
- All **229 pass** (includes the follow-up `tests/test_live_resilience.py`).

---

## 2. Files touched (quick map)

| File | Change |
|------|--------|
| `core/evidence.py` | + `detect_provider()` |
| `core/threat_matrix.py` | + `attack_paths()` |
| `core/correlation.py` | **NEW** — `correlate()`, `detect_drift()` |
| `core/reporting.py` | + `_attack_path_md()` + embed attack_path in json/markdown reports |
| `core/report_store.py` | + `_timeline.json` index, `timeline()` method, `_update_timeline()` |
| `agents/runtime.py` | + `normalize_falco_event()`, `normalize_events()` |
| `mcp/server.py` | + 6 tools: `detect_cluster_provider`, `intelligent_scan`, `build_attack_path`, `correlate_runtime`, `detect_drift`, `deploy_falco`; CIS `profile="auto"` |
| `web/app.py` | + `/api/dashboard`, `/api/timeline`, `/api/runtime`; `_dashboard_data()`; `_api_runtime()` |
| `web/pages.py` | full rewrite → SPA + Attack Map visualization; spring easing animations + focus rings |
| `tests/test_provider.py` | **NEW** |
| `tests/test_correlation.py` | **NEW** + 5 normalization tests |
| `tests/test_report_store.py` | **NEW** — timeline + attack-path-in-reports |
| `tests/test_mcp.py` | updated tool-set (added deploy_falco) |
| `tests/test_web.py` | SPA data-contract tests + `/api/runtime` endpoint |

---

## 3. How to run everything

```bash
cd K8sMatrixWarden-Dev-1

# tests
python3 -m tests.run_tests

# scan live Goat
python3 -m k8smatrixwarden scan --live --context minikube --save -o terminal

# one-call intelligent scan (mock)
python3 -c "from k8smatrixwarden.mcp.server import build_tools; \
  import json; print(json.dumps(build_tools()['intelligent_scan']('find privilege escalation', mock=True)['attack_path'], indent=2))"

# web dashboard (defaults to live scans in the form)
python3 -m k8smatrixwarden web --port 8080
# open http://127.0.0.1:8080

# MCP server (needs `pip install mcp`)
python3 -m k8smatrixwarden mcp --list-tools
```

**Dashboard demo:**
```bash
# Save a live Goat scan
python3 -m k8smatrixwarden scan --live --context minikube --save

# Start web server
python3 -m k8smatrixwarden web --port 8080
# open http://127.0.0.1:8080
# → Overview tab: KPIs, findings, risk trend, finding age (MTTD/MTTR), runtime readiness
# → Findings tab: search, filter, sort all 358 Goat findings
# → Threat Matrix tab: 9×N heatmap, click cells for findings
# → Attack Path tab: kill-chain (Initial Access → Impact)
# → Attack Map tab: kill-chain WITH vulnerable resources (Pods/Deployments/etc) grouped per tactic
# → Runtime tab: paste Falco events OR load sample → correlate + detect drift
```

**Runtime correlation demo (sample events, no real Falco needed):**
```bash
# Dashboard → Runtime tab → "Load sample attack" → "Correlate + detect drift"
# Against live Goat this shows ~4 confirmed exploitations (shell+privileged container,
# metadata API+exposed secret, new RoleBinding+hostPath, etc) tied to real pods.
```

**One-call intelligence (MCP / programmatic):**
```bash
# Natural language → scan + threat matrix + attack path
python3 -c "from k8smatrixwarden.mcp.server import build_tools; \
  import json; tools = build_tools(); \
  result = tools['intelligent_scan']('find privilege escalation and lateral movement', mock=True); \
  print(json.dumps({'chain': result['attack_path']['chain'], \
                    'findings': len(result['findings']), \
                    'tactics': result['attack_path']['tactic_count']}, indent=2))"

# Deploy Falco one-click (MCP tool)
tools['deploy_falco']('http://host.minikube.internal:8080/api/runtime')
```
exploitations tied to real pods.

---

## 4. Roadmap — what to build next (prioritized)

Ordered by ROI toward the "scan + runtime + causality" differentiator. Each item lists the
concrete files/shape so you can start immediately.

### P0 — Real Falco feed (closes the runtime loop for real)
**Ingestion side: DONE.** `agents/runtime.py` now has `normalize_falco_event` +
`normalize_events`, and `POST /api/runtime` accepts Falco-native JSON (nested
`output_fields`, dotted keys, `source: syscall|k8s_audit`) as a single event *or* a batch,
normalizing to the flat internal shape the matchers use. Verified end-to-end: a bare
falcosidekick shell event → confirmed exploitation against the live Goat scan. The MCP
`correlate_runtime` / `detect_drift` tools normalize too. Tests in `tests/test_correlation.py`.

**Remaining (infra, not code):** actually run Falco in the cluster.
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts && helm repo update
helm install falco falcosecurity/falco -n falco --create-namespace \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.webhook.address=http://<host-reachable-from-cluster>:8080/api/runtime
```
- falcosidekick posts **one event per request** → already handled (single-event POST).
- The webhook address must be reachable from inside minikube (use the host IP /
  `host.minikube.internal`, not `127.0.0.1`).
- **Optional next step:** buffer incoming events server-side (small in-memory ring per
  scan_id) so the dashboard Runtime tab can show a rolling live feed instead of one POST at a
  time. Needs the state store from P2.

### P0 — Timeline / MTTD / MTTR  ✅ DONE
"This finding was live for N days before it was fixed."
- `ReportStore` keeps a `_timeline.json` index keyed by `rule_id|kind|name|namespace`.
  `save()` diffs each scan: new → `first_seen`, disappeared → `resolved_at`, reappeared
  clears it. `timeline()` returns open/resolved counts, `oldest_open_days`,
  `median_open_days`, `oldest_critical`, per-finding `age_days`.
- Surface: `GET /api/timeline` + included in `/api/dashboard`; Overview "⏱️ Finding age"
  panel.
- **Ceilings (inline):** granularity = scan cadence; meaningful across scans of the **same
  scope** (mixed scopes falsely resolve/reappear — key the index per scope if needed).
  `list()` skips `_`-prefixed index files.
- **Next:** stamp `first_exploited_at` on correlation confirmations (needs P0 Falco feed).
- Test: `tests/test_report_store.py::test_timeline_tracks_open_and_resolved`.

### P1 — Attack path in the exported reports  ✅ DONE
- `core/reporting.py` `json()` now embeds `attack_path` next to `threat_matrix`; `markdown()`
  renders a "🎯 Kill-chain exploit path" section (chain + per-tactic techniques) via the new
  `_attack_path_md()` helper.
- **Remaining:** the HTML report (`_html` renderer) still only links to the web matrix — add
  a rendered chain there too if wanted. Same for PDF (`core/pdf_report.py`).
- Test: `tests/test_report_store.py::test_attack_path_embedded_in_reports`.

### P0.5 — Deploy Falco tool + Attack Map visualization  ✅ DONE
- **`deploy_falco` MCP tool:** one-click helm install with webhook auto-configured.
  Returns status + next steps. Requires helm on the system.
- **Attack Map tab:** new dashboard tab showing kill-chain WITH vulnerable K8s resources
  (Pods, Deployments, StatefulSets, etc.) grouped by tactic. Reuses scan findings data,
  no extra collection needed. Shows which resources are exposed at each stage of the attack.
- **UX polish:** spring easing on hover (KPIs, buttons, cells scale smoothly past target
  then settle). Smooth focus rings on inputs/textareas. Responsive delays (.25s–.35s).

### P1 — Drift as first-class runtime rules
`detect_drift` is a standalone function. The `RuntimeAgent` already reserves
`source="drift"` but has no drift rules. Consider unifying: drift checks that need the
declared spec can't be pure event matchers, so keep `detect_drift` separate but expose its
catalog in `list_runtime_detections` so "what we can catch" is complete.

### P1 — Resource-name-level correlation
`correlate()` joins on tactic + namespace. Once Falco enrichment gives `k8s.pod.name`
reliably (P0), tighten `confirmed` to require the **same resource**, not just namespace.
Bump namespace-only matches down to `corroborated`. One-line change in `core/correlation.py`
plus a test.

### P2 — Supply-chain / container mutation detection
Scan says "base image has CVE"; runtime says "new binary in /tmp after startup." New drift
class. Needs a runtime signal for image mutation (Falco `open+execve` of a path not in the
image layers, or a periodic hash check). Correlate with `image_supply_chain` shard findings.

### P2 — Dashboard: CIS compliance panel
Deliberately skipped (running 130 controls on every dashboard load is heavy). Add as a
**lazy-loaded** tab: `GET /api/cis` runs `run_cis_benchmark(profile="auto")` on demand,
client renders the section pass/fail heatmap.

### P2 — SIEM / alerting integrations
Prometheus exporter (`/metrics` with risk score, finding counts by severity/tactic) and a
Slack/webhook on new `confirmed_exploitation`. Kubescape ships these; needed for ops teams.

### P3 — Auth on the web dashboard
The web server is currently open (fine for localhost/demo). Before anyone exposes it, add a
token check in `web/server.py`'s handler. Keep it stdlib (a shared-secret header).

### P3 — Live-push runtime (WebSocket/SSE)
`/api/runtime` is POST-batch. For a real streaming Falco feed, add Server-Sent Events so the
Runtime tab updates without polling. Only worth it once P0 is real.

---

## 6. Session summary — what got shipped

**The core differentiator is now in place:** scan findings + live runtime correlation + drift
detection + kill-chain visualization. The tool answers "this weakness is being exploited
**right now**" — not "here's a list of static weaknesses."

**Major milestones this session:**
- ✅ Dashboard rebuilt as interactive SPA (7 tabs, search/filter/sort, no framework, no CDN)
- ✅ Attack path derivation (kill-chain sequence from threat matrix)
- ✅ Correlation engine (scan findings × runtime alerts by tactic + namespace)
- ✅ Drift detection (declared vs observed security posture)
- ✅ Falco feed normalization (accept native falcosidekick JSON, bridge to internal shape)
- ✅ Timeline / MTTD / MTTR (how long findings stay open, when resolved)
- ✅ Attack path in reports (embedded in JSON/Markdown exports)
- ✅ One-click Falco deploy (MCP tool, `helm install` with webhook)
- ✅ Attack Map visualization (kill-chain with vulnerable resources grouped per tactic)
- ✅ UX polish (spring easing, hover feedback, focus rings, semantic animations)
- ✅ Live Kubernetes Goat demo (9.8/10 Critical, 358 findings, real exploitation patterns)

**Test coverage:** 184 passing tests (this session added 7 test files/groups and the
follow-up added `test_live_resilience.py`; the remediation removal pass then dropped the
remediation-specific tests — see §0.2).

**MCP tools:** 30 tools. This session brought it to 33 (was 27, +6:
detect_cluster_provider, intelligent_scan, build_attack_path, correlate_runtime,
detect_drift, deploy_falco); the remediation removal pass (§0.2) then dropped 3
(explain_remediation, get_playbook, list_playbooks), leaving 30.

**Ready for next contributor:** all concrete file paths, data shapes, ceilings/tradeoffs
are documented inline. P1 and P2 items are clear next steps (resource-level correlation,
CIS panel, SIEM integrations, auth).

---

## 5. Architecture reminders (don't fight these)

- **Zero-dependency core.** The scanner/engine runs on stdlib only. Extras (`kubernetes`,
  `mcp`, `fpdf2`, `rich`) are optional. Don't add a hard dependency for something a few lines
  of stdlib can do. The web dashboard is inline HTML/CSS/JS for this reason — **no React,
  no build step, no CDN.**
- **One engine, many surfaces.** CLI, chat, web, MCP all compile to a `ScanRequest` and run
  through the same `Platform` (`bootstrap.build_platform`). Never re-implement scanning in a
  surface — call the engine.
- **Detect-and-report only — read-only everywhere.** The tool has no remediation/apply path
  on any surface (see §0.2); scanning is get/list/watch only and no output mutates the cluster.
  Keep it that way; `tests/test_mcp.py::test_no_remediation_or_apply_tool_is_exposed` enforces it.
- **Domain shards (vertical) × MITRE tactics (horizontal) are orthogonal.** A rule lives in
  one shard, is tagged with N tactics, and resolves through one registry index. This is the
  whole design; adding a shard = drop a file in `shards/`, no engine change.
- **Mock vs live is one flag.** `LiveEvidenceCollector` returns the same camelCase JSON shape
  as the mock fixture, so rule code is identical. Test against mock; demo against Goat.

---

## 6. Known gotchas (things that already bit us)

1. **Web server has no hot-reload** — restart after editing `web/*.py`.
2. **Stale server = empty dashboard** — if it started before a scan was saved, the
   `/api/reports` glob is fine but a *reused* process may serve stale; restart clean.
3. **`Orchestrator.run(...)` not `.scan(...)`** — the run method is `run`.
4. **`:1234` is the Goat portal, not the API** — scan via kubeconfig, not the URL.
5. **Python 3.9 works** despite README saying 3.10+ (`from __future__ import annotations`
   covers it), but target 3.10+ to be safe.
6. **f-strings with backslashes/nested same-quotes** break on 3.9 — build the string in a
   variable first (bit us in `pages.py`'s attack-surface cells).

---

## 7. Where to start (suggested first PR for a new contributor)

**Do P0 "Real Falco feed" first** — it's the highest-leverage, turns the sample-driven
Runtime tab into a live one, and the ingestion endpoint (`/api/runtime`) already exists. The
only real work is the falcosidekick → internal-event normalizer (~30 lines + a test) and
accepting single-event POSTs. That immediately makes the Goat demo show *real* live
exploitation instead of pasted samples.
