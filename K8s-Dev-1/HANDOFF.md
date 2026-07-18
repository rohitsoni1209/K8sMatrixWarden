# K8sMatrixWarden — Handoff & Roadmap

**Purpose:** everything that changed in this work session + a detailed, prioritized backlog
so anyone can pick up and keep building. Written for a developer who has *not* seen the
session — file paths, data shapes, and gotchas are spelled out.

- **Repo root:** `K8s-Dev-1/`
- **Package:** `k8smatrixwarden/`
- **Tests:** `213 passing` (`python3 -m tests.run_tests`)
- **MCP tools:** `32` (was 27; +5 this session)
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

### 1.5 Dashboard rebuilt → interactive SPA
**Files:** `web/pages.py` (full rewrite), `web/app.py` (new endpoints)

- The old dashboard was server-rendered static HTML. It's now a **client-side app**
  (vanilla JS, zero dependencies, zero external hosts — same constraint the HTML report has).
- Serves a shell (`dashboard_page`) that fetches **`GET /api/dashboard`** once and renders
  everything client-side. Six tabs:
  - **Overview** — KPIs, priority findings, risk-by-domain bars, attack-surface strip,
    risk trend, runtime readiness
  - **Findings** — live search + severity chips + tactic filter + sortable columns (handles
    all 358 Goat findings; caps table render at 400 rows)
  - **Threat Matrix** — interactive heatmap; click a red cell → its findings inline
  - **Attack Path** — kill-chain flow diagram, reaches-Impact flag
  - **Runtime** — paste/sample Falco events → correlate + drift, rendered as cards
  - **Scan** — run-a-scan form (defaults to **live**) + scan history table
- **New API endpoints** (`web/app.py`):
  - `GET /api/dashboard` — everything in one payload (`_dashboard_data()`): scan meta,
    findings, threat_matrix, attack_path, runtime readiness, trend, history.
  - `POST /api/runtime` — ingest events `{events:[...], scan_id?}` → `{correlation, drift}`.
    **This is the Falco ingestion point** — point falcosidekick here.
- **Gotcha:** the web server does **not** hot-reload. After editing `pages.py`/`app.py`
  you must restart it (`pkill -f "k8smatrixwarden web"` then relaunch). A stale server that
  started before a report was saved will serve an empty dashboard — this looked like a bug
  but wasn't.

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

### 1.7 Tests
- New: `tests/test_provider.py`, `tests/test_correlation.py`
- Updated: `tests/test_mcp.py` (tool-registry set), `tests/test_web.py` (dashboard is now a
  SPA — asserts the `/api/dashboard` data contract instead of scraping HTML).
- All **213 pass**.

---

## 2. Files touched (quick map)

| File | Change |
|------|--------|
| `core/evidence.py` | + `detect_provider()` + provider label/scheme maps |
| `core/threat_matrix.py` | + `attack_paths()` |
| `core/correlation.py` | **NEW** — `correlate()`, `detect_drift()` |
| `mcp/server.py` | + 5 tools: `detect_cluster_provider`, `intelligent_scan`, `build_attack_path`, `correlate_runtime`, `detect_drift`; CIS `profile="auto"` |
| `web/app.py` | + `/api/dashboard`, `/api/runtime`; `_dashboard` now serves SPA shell |
| `web/pages.py` | full rewrite → client-side SPA; deleted ~230 lines of server-render panels |
| `tests/test_provider.py` | **NEW** |
| `tests/test_correlation.py` | **NEW** |
| `tests/test_mcp.py` | tool-set assertions |
| `tests/test_web.py` | SPA data-contract tests |

---

## 3. How to run everything

```bash
cd K8s-Dev-1

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

**Runtime demo without real Falco:** open the dashboard → Runtime tab → "Load sample
attack" → "Correlate + detect drift". Against live Goat this shows ~4 confirmed
exploitations tied to real pods.

---

## 4. Roadmap — what to build next (prioritized)

Ordered by ROI toward the "scan + runtime + causality" differentiator. Each item lists the
concrete files/shape so you can start immediately.

### P0 — Real Falco feed (closes the runtime loop for real)
Right now runtime events are pasted/sampled. Make them real.
- Deploy Falco to the Goat minikube: `helm repo add falcosecurity https://falcosecurity.github.io/charts && helm install falco falcosecurity/falco --set falcosidekick.enabled=true`.
- Configure falcosidekick with a **webhook** output pointing at `POST /api/runtime`.
  - **Adapter needed:** falcosidekick posts one event per request in Falco's native JSON
    (`output_fields.proc.name`, `k8s.pod.name`, `k8s.ns.name`, …). Our `RuntimeAgent`
    matchers expect flat keys (`proc`, `pod`, `namespace`, `connect`, `file`, `op`, `verb`).
    Write a small normalizer `falco_event → internal event` in `agents/runtime.py` (or a new
    `core/falco_adapter.py`). ~30 lines.
- **Batching:** `/api/runtime` currently expects `{events:[...]}`. falcosidekick posts singly;
  either accept a single object too, or buffer server-side. Buffering needs a small in-memory
  ring per scan (state — see P2 for where state should live).

### P0 — Timeline / MTTD / MTTR (the metric leaders actually buy)
"This finding was live 7 days before it was fixed." Nobody else shows this well.
- **Needs persistent state:** a first-seen/last-seen store keyed by `finding.dedup_key()`
  (`rule_id, kind, name, namespace`). On each saved scan, diff against the previous scan:
  new findings get `first_seen=now`, disappeared ones get `resolved_at=now`.
- Storage: reuse `ReportStore`'s dir with a `_timeline.json` index (stdlib json, no DB).
- Surface: a `GET /api/timeline` endpoint + an Overview KPI ("median open age", "oldest
  critical"). Correlation events stamp `first_exploited_at`.
- **Ceiling to note:** scans are point-in-time, so MTTD granularity = scan cadence. Good
  enough; document it.

### P1 — Attack path & correlation in the exported reports
Currently attack-path lives only in MCP + the web SPA; the markdown/html/pdf reports don't
have it.
- `core/reporting.py` already embeds `threat_matrix` in `json()`/`html()`. Add an
  `attack_path` section the same way (call `attack_paths(build_threat_matrix(result, reg))`).
- `core/threat_matrix_render.py` is the place for a text/markdown/HTML renderer of the chain.

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

## 5. Architecture reminders (don't fight these)

- **Zero-dependency core.** The scanner/engine runs on stdlib only. Extras (`kubernetes`,
  `mcp`, `fpdf2`, `rich`) are optional. Don't add a hard dependency for something a few lines
  of stdlib can do. The web dashboard is inline HTML/CSS/JS for this reason — **no React,
  no build step, no CDN.**
- **One engine, many surfaces.** CLI, chat, web, MCP all compile to a `ScanRequest` and run
  through the same `Platform` (`bootstrap.build_platform`). Never re-implement scanning in a
  surface — call the engine.
- **Read-only everywhere the LLM/web can reach.** Remediation/apply is deliberately NOT
  exposed via MCP or web (§9.1 — every fix needs interactive confirmation). Keep it that way;
  `tests/test_mcp.py::test_no_remediation_or_apply_tool_is_exposed` enforces it.
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
