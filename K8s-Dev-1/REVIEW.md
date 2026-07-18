# K8s-Dev-1 — Post-Implementation Review & Optimization

This is the required review pass after the initial build. It records what was verified, the
refinements made to improve the code over a naive reading of the spec, the deliberate
deviations (with justification), and the known limitations / next steps.

**Status at review:** 10 shards, **56 rules**, **25/25 tests passing**, `doctor` validation
clean (no duplicate rule ids, every rule's technique id present in the vendored taxonomy,
all aliases resolve). End-to-end mock scan produces a Critical-rated report; tactic/technique/
module/framework slices, namespace scoping, all six report formats, and CI exit codes all
verified working.

---

## 1. What was verified end-to-end

| Capability | Evidence |
|---|---|
| Registry builds & validates | `k8smatrixwarden doctor` → 10 shards / 56 rules / ✅ clean |
| Every tactic covered | `k8smatrixwarden coverage` → all 9 tactics have ≥1 rule |
| Selector = single choke point | `--tactic Persistence` → 6 rules across 3 shards (matches spec §17 Workflow 2) |
| Composite alias | `--technique "Container Escape"` → 5 curated rules |
| Domain (row) slice | `--module rbac_identity` → 7 rules, single shard |
| Framework slice | `--framework CIS` → only `cis:`-tagged rules |
| Scope filtering | `-n staging` → only staging resources in findings |
| Attack-path scoring | hostPath rule (3 tactics) scores 1.5× a 1-tactic baseline (unit-tested) |
| Fetch-once evidence | one `EvidenceCollector.collect()` per scan, cached by kind |
| Report formats | terminal/text/markdown/json/sarif/html all render |
| CI mode | `--fail-on CRITICAL` → exit 1 with critical, 0 without |
| Runtime agent | Falco + audit events matched to tagged rules (unit-tested) |
| Remediation safety | dry-run default; declines without confirmation (unit-tested) |
| Zero-dependency core | platform builds & scans with no `kubernetes`/`rich`/`mcp`/`pyyaml`/`pytest` |

---

## 2. Refinements made during the build (improvements over a literal spec reading)

1. **Per-rule execution isolation.** The redesign doc's critique of a monolith (§ Option B)
   is that "a bug in one check must not take down the scan." Implemented literally: each
   rule runs in a guarded task in the Detection Engine; an exception becomes an `INFO`
   engine-error finding, never a crash. (`core/detection.py::_run_rule`.)

2. **camelCase-everywhere evidence.** The k8s client's `to_dict()` returns snake_case,
   which would force rules to branch between mock and live mode. Instead the live collector
   reads raw API JSON (`response_type="object"`), so `spec.securityContext.privileged`
   works identically in both modes. This removed an entire class of mock/live drift bugs.

3. **Anti-drift taxonomy validation is real, not decorative.** `doctor` fails if any rule
   references a technique id absent from the vendored `attack_for_containers.json`, or if an
   alias targets a nonexistent rule — the CI-style guard the spec calls for in §6.2.

4. **Selector never silently scans nothing.** An unmatched selector raises
   `SelectorResolutionError` rather than resolving to an empty set (a correctness trap the
   ANALYSIS flagged up front). Empty *selector* still means "all rules"; unmatched *terms*
   are an error.

5. **Union + dedup semantics** for multi-axis selectors (`--module secrets --tactic
   "Credential Access"`) with order preserved — matching the spec's "OR, then dedupe" (§4.3),
   unit-tested.

6. **Tag merging on aggregation.** When two rules flag the same object, the Aggregator
   merges their MITRE/CIS/NSA tags into one finding and keeps the worst severity (§6.1).

7. **Per-plugin scoped RBAC is generated, not hand-written.** Each shard's `rbac_verbs()`
   is derived from the resource kinds it declares, and the Plugin Loader emits a real
   `ClusterRole` per shard (`k8smatrixwarden roles`) — the least-privilege-below-the-agent model
   from §20/§21, made concrete.

8. **Control-plane finding naming** cleaned up so resources read `ControlPlane/apiServer`
   etc. instead of a raw path fragment (review nit, fixed).

---

## 3. Deliberate deviations from the spec (with justification)

| Deviation | Why | Where noted |
|---|---|---|
| **Saturating cluster-risk `10·raw/(raw+K)`** instead of the spec's literal `Σ/max_possible·10` | `max_possible` is undefined/unbounded for an arbitrary cluster. Saturation is monotonic, bounded to [0,10], deterministic, and lets a few criticals dominate — matching the §18.1 rating bands. | `core/scoring.py` docstring, `ANALYSIS.md §4` |
| **Rules authored as Python, data as JSON** (spec examples show YAML) | The target env has no `pyyaml`; Python rules are type-checked and dependency-free. Taxonomy/config/fixtures are JSON. Behavior is identical to the spec's YAML intent. | `ANALYSIS.md §3` |
| **Pure-stdlib core; kubernetes/rich/mcp optional** | None were installed; forcing them would make the tool un-runnable out of the box. Extras degrade gracefully. | `README`, `pyproject` extras |
| **Attack Surface shard focuses on genuinely cross-cutting analyses** (SA fan-out) rather than re-emitting other shards' findings | Avoids double-counting; the mapper's value is the cross-shard view, not duplication. | `shards/attack_surface.py` |

None of these change the architecture; they are implementation-level choices that keep the
tool runnable and honest.

---

## 4. Known limitations / live-mode gaps (roadmap)

1. **Synthetic evidence buckets in live mode.** `ComponentConfig` (control-plane flags) and
   `CloudIAM` (workload-identity bindings) have no direct K8s API. Live coverage of shards ①
   and ⑩ needs: kube-bench JSON ingestion for control-plane flags, and a cloud IAM adapter
   (read-only `iam:Get*`/`Describe*`) for cloud bindings. The rule logic is already written
   and works the moment those buckets are populated.
2. **Some external tool integrations are seams, not wired binaries.** The Trivy (image CVE)
   and kubescape adapters are defined (`core/detection.py::ExternalToolAdapter`) but their
   subprocess calls are stubs — the correct seam, work still to fill. (The **CIS engine is
   fully built** — 130 controls, §5.9/§6a/§6b — and kube-bench is wired via `--kube-bench-json`
   for the 31 file controls, so CIS is no longer a stub.)
3. **Runtime Agent is a rule catalog + matcher, not a live tail.** It evaluates an event
   stream (real or simulated). A production DaemonSet would feed it Falco/Tetragon gRPC and
   the audit webhook; the matching engine is ready.
4. **`seccomp` rule checks only the first container** (minor simplification, documented in
   `shards/workload_pod_security.py`).
5. **NL intent parsing is deterministic keyword/fuzzy matching**, sufficient for the spec's
   example phrases. §7.4's LLM layer would sit on top and resolve to the same registry index;
   the seam (`Orchestrator.interpret`) is where it plugs in.
6. **Remediation real-apply path** shells out to `kubectl` and is guarded behind
   `dry_run=False`; it is intentionally not exercised by default.

---

## 5. Performance characteristics

- **Evidence is fetched once per scan**, cached by kind, shared across all resolved rules
  (the efficiency property the whole architecture exists to guarantee). A tactic scan that
  touches Pods + webhooks fetches each list exactly once.
- **Rules execute in a thread pool** (`parallel_rules`, default 16). Rules are I/O-light in
  mock mode; in live mode the pool overlaps API-bound and CPU-bound rules. Image-CVE / cloud
  rules should move to a rate-limited pool when their adapters land (noted for scale, §10.8).
- **Registry resolution is O(1)** index lookups, not code scans — verified by design in
  `MITREMappingEngine`.

---

## 6. Security posture of the tool itself

- **Read-only by default**; the only write path is the Remediation Agent, gated by mandatory
  confirmation + snapshot + rollback.
- **Per-plugin least privilege**: `k8smatrixwarden roles` emits a scoped ClusterRole per shard so a
  compromised/buggy shard is limited to what it declared (§20). Cloud IAM's external
  credential is declared in its manifest, not granted globally.
- **No secret values are printed**: secret rules report *shape/location* (env name, key
  name), never decoded contents.

---

## 6a. CIS Benchmark full coverage (added post-initial-build)

The initial build had only ~26 CIS-tagged rules and flagged "full CIS" as a gap. That gap is
now closed with a dedicated **CIS Benchmark Engine** (`k8smatrixwarden/frameworks/`):

- **Authoritative catalog.** All **130** CIS Kubernetes Benchmark v1.8 controls were pulled
  verbatim from kube-bench's `cfg/cis-1.8/*.yaml` (not from memory). The original spec's
  "242 checks" was an **over-count** and is reflected in the architecture doc (§5.9) — the real
  benchmark is 130 controls (§1=60, §2=7, §3=5, §4=23, §5=35).
- **Every control gets a status** — `PASS` / `FAIL` / `MANUAL` / `NA` / `NEEDS_NODE` — so
  nothing is silently missed. Initial split was 25 native + 2 builtin + 69 kube-bench + 34
  manual; **§6b then mitigated the 69 down to 31** by recovering process flags from the API.
- **kube-bench delegation is real**: `k8smatrixwarden cis --kube-bench-json kb.json` merges kube-bench
  results, moving node controls out of NEEDS_NODE into PASS/FAIL (unit-tested).
- **Data-caught a real bug**: the tag-alignment test found `workload-hostpath-writable` was
  missing its `cis: 5.2.12` tag (fixed). Several native rules' CIS ids were also corrected to
  the true v1.8 numbering (e.g. privileged container 5.2.1 → 5.2.2, run-as-root 5.2.6 → 5.2.7).
- **6 new tests** (`tests/test_cis.py`); suite is now **31/31 passing**.

## 6b. Node-access limitation — mitigated (NEEDS_NODE 69 → 31)

The initial CIS engine marked all 69 non-policy control-plane/node controls `NEEDS_NODE`.
That was pessimistic: most are **process flags**, not file reads, and flags are recoverable
from the K8s API. Three mitigation layers (architecture doc §5.9.2) close the gap:

- **Layer 1 — static-pod flag recovery.** The live `ComponentConfig` collector
  (`core/evidence.py::build_component_config`) parses control-plane component `--flags` out of
  their `kube-system` static Pods. A new `component` evaluation method with per-control
  `(component, flag, op, value)` predicates checks 38 controls (§1.2/1.3/1.4/2 + kubelet §4.2)
  **entirely from the API, no node access**.
- **Layer 2 — kubelet config** feeds the same `component` mechanism (via `/configz` live).
- **Layer 4 — provider profiles** (`--profile eks|gke|aks`) mark the managed control plane
  (sections 1–3) as `NA` — a correctness fix (you can't and shouldn't grade a managed control
  plane) rather than reporting it as un-checkable.

**Measured result (mock cluster):**
| Mode | PASS | FAIL | MANUAL | NA | NEEDS_NODE | auto-coverage |
|---|---|---|---|---|---|---|
| self-managed | 14 | 51 | 34 | 0 | **31** | 50% |
| + kube-bench (all file controls) | 45 | 51 | 34 | 0 | **0** | 74% |
| eks/gke (managed) | 3 | 24 | 21 | 72 | 10 | 47% |

**Layer 3 (the last 31 file-permission controls) is deliberately NOT reimplemented** as an
on-node agent — that would duplicate kube-bench. They stay delegated via `--kube-bench-json`,
which resolves them to real PASS/FAIL (verified: feeding kube-bench output takes NEEDS_NODE to
0). Invariant preserved: **an unverifiable control is never silently marked PASS** — it is
`component`/`NEEDS_NODE`/`NA`/`MANUAL`, and the report always shows which.

## 6c. Remediation engine made schema-aware and resource-aware (bug fix + refactor)

**The bug:** remediation was generated by formatting one hardcoded command string per
playbook (`kubectl patch {kind} {name} -p '...{"spec":{"template":{"spec":{...`), always
assuming the `spec.template.spec` shape. That's correct for a Deployment/DaemonSet/
StatefulSet but **wrong for a bare Pod** (which has no `.spec.template` at all) and wrong
for a CronJob (which nests one level deeper, at `spec.jobTemplate.spec.template.spec`).
Since the overwhelmingly common real-world case is a controller-owned Pod (e.g. an EKS
`aws-node` DaemonSet pod), and findings are reported against the *Pod*, the tool was
generating `kubectl patch pod aws-node-64w2k -p '{"spec":{"template":...'` — syntactically
valid JSON, but a shape Kubernetes rejects outright for a Pod object.

**The fix — `k8smatrixwarden/core/remediation_engine.py`** (new module) replaces the flat
`{kind}`-templated command strings with a pipeline that mirrors the actual K8s object
model:

1. **Owner resolution.** A Pod's `ownerReferences` are resolved at finding-creation time
   (`shards/workload_pod_security.py::ref(ev, res)`, where `Evidence` is available) —
   including hopping *past* the immediate owner when it's not the real controller
   (ReplicaSet → Deployment, Job → CronJob), using ReplicaSet/Job objects already present
   in the scan's evidence. If that hop can't be confirmed (the intermediate object isn't
   in evidence), the engine does **not** guess a Deployment/CronJob name — it reports
   "cannot be safely automated" rather than fabricate a target.
2. **Resource-aware patch paths.** `POD_SPEC_PATH_PREFIX` maps each kind to where its Pod
   template actually lives (`Pod` → `spec`, `Deployment/DaemonSet/StatefulSet/ReplicaSet/
   Job` → `spec.template.spec`, `CronJob` → `spec.jobTemplate.spec.template.spec`) — one
   table, not one hardcoded string per playbook.
3. **Schema/mutability validation.** A field is only ever proposed as a live patch when
   the *target* is a controller (safe — triggers a normal rollout) or is explicitly
   marked mutable-on-a-live-Pod (a short, deliberately conservative allow-list; Pod specs
   are immutable after creation for almost everything, including all of
   `securityContext`/host-namespace flags). A genuinely standalone Pod gets a "delete +
   recreate" recommendation instead of a patch that Kubernetes would reject.
4. **Deployment-method + system-workload awareness (§6/§5 of the request).** Helm
   (`app.kubernetes.io/managed-by=Helm`) and ArgoCD/Flux markers are read from the
   *resolved owner's* own labels/annotations (fetched from evidence when the owner object
   is present, falling back to the Pod's own) and surface a drift/GitOps warning rather
   than silently proposing a live patch. `kube-system` namespace or known
   EKS/vendor-component name markers (`aws-node`, `coredns`, `kube-proxy`, `ebs-csi`,
   `efs-csi`, `metrics-server`, `cluster-autoscaler`, ...) get the literal warning text
   requested: *"This appears to be a Kubernetes/EKS managed component. Verify vendor
   documentation before changing its security context because the recommended hardening
   may break cluster functionality."*
5. **Output.** Every `RemediationResult` carries Finding / Affected Resource / Owner
   Resource / Root Cause / Risk / Remediation Steps / (validated) kubectl command /
   Alternative YAML / Validation commands / Rollback commands / Warnings / References —
   surfaced in the markdown report (owner row + collapsible warnings block), the JSON
   report (`remediation.*` per finding, additive — old `title`/`commands` keys kept for
   backward compat), and `RemediationAgent.show()`.

**Migration scope:** only the playbooks that actually had the Pod-template ambiguity
(`pod-security-context`, `run-as-non-root`, `drop-capabilities`, `read-only-root-fs`,
plus `disable-sa-automount`, which had a *different* bug — it patched a hardcoded `sa
{name}` using the *workload's* name, not the ServiceAccount's) moved to the new
`FIELD_PATCHES` registry. Playbooks that already targeted an unambiguous, non-Pod-shaped
kind directly (ClusterRoleBinding delete, NetworkPolicy apply, Namespace label, ...) or
were always a manual/policy note were left in `mcp/datasets.py::PLAYBOOKS` unchanged —
they were never affected by this bug. `workload-host-pid/-network/-ipc`, which previously
had **no** remediation at all, now get one.

**Known, documented limitation carried over from the original code:** the two
container-indexed JSON-patch fields (`drop-capabilities`, `read-only-root-fs`) still
target `containers[0]` positionally — the finding only captures the container's *name* in
`evidence`, not its array index. The engine now at least surfaces this as an explicit
warning (naming the actual flagged container) instead of silently patching the wrong
container when it isn't the first one; fully resolving it would mean carrying the
container index through to the Finding, which is a larger change left for later.

Mock fixture (`k8smatrixwarden/data/fixtures/mock_cluster.json`) was extended with a realistic
Deployment→ReplicaSet→Pod chain for `payment-api` and a `kube-system` DaemonSet-owned Pod
(`aws-node-64w2k`, matching the bug report's literal example) so the fix is exercised
end-to-end through the real scan pipeline, not just unit-level mocks. **12/12 requested
test scenarios covered** in `tests/test_remediation_engine.py` (31 tests): standalone /
Deployment / DaemonSet / StatefulSet / Job / CronJob-owned Pods, Helm-managed, ArgoCD-
managed, kube-system, immutable field, invalid patch path, missing ownerReference — plus a
regression guard asserting no `FIELD_PATCHES` × controller-kind combination ever produces
`kubectl patch pod ...` for a pod-template field. Full suite: **113/113 passing** (was
82/82 before this change).

## 6d. MCP tool surface audited for completeness (8 → 25 tools)

A capability audit compared every CLI/agent capability (`scan`, `chat`, `cis`, `rules`,
`coverage`, `roles`, `doctor`, `report list/download`, the Runtime Agent, the
remediation engine) against what the MCP server actually exposed. Gaps found and closed:

| Gap | Fix |
|---|---|
| No way to persist/export a scan report from an MCP client | `run_scan(..., save=True)` + new `list_reports`/`download_report` — full save → list → re-render-in-any-format lifecycle, matching `k8smatrixwarden report list/download` |
| `run_scan` only ever returned the JSON shape, never a real rendered report | Added `output_format` (`markdown`/`html`/`sarif`/`text`/`terminal`) to get the fully rendered string back directly, no save round-trip needed |
| `k8smatrixwarden doctor` (taxonomy/alias/duplicate-id validation) had no MCP equivalent | Added `validate_platform` |
| Dataset 5 (Compliance Rule Sets) was loaded but never exposed | Added `get_compliance_ruleset` |
| The Runtime Agent (§8 — Falco/audit event matching) was unreachable via MCP | Added `evaluate_runtime_events` |
| 4 of the 6 knowledge datasets (kubectl commands, tool commands, playbooks, CVEs) only supported "fetch by exact key you must already know" — no way to discover valid keys | Added `list_kubectl_commands`, `list_tool_commands`, `list_playbooks`, `list_cves` alongside the existing `get_*`/`lookup_*` |
| The schema-aware remediation engine (§6c) was only reachable indirectly, buried in a `run_scan` finding | Added `explain_remediation` — the full owner-resolved, schema-validated `RemediationResult` for a hypothetical resource, no scan required |

**Format-validation bug found and fixed during the review pass itself:** both the new
`run_scan(output_format=...)` and `download_report(format=...)` initially passed an
unvalidated format string straight to `ReportingEngine.render()`, which silently falls
back to `terminal` for any unrecognized value — so a typo like `"markdwn"` would render
as terminal text while the response's own `format` field echoed back `"markdwn"`,
looking successful. Both now validate against the 6 real formats and return a clear
`error` instead of a silently-wrong report. Caught by
`tests/test_mcp.py::test_run_scan_typoed_output_format_returns_error_not_silent_terminal`.

**Two genuinely dangling `remediation_ref`s found and fixed** while auditing the
registry for this pass (pre-existing, unrelated to §6c's Pod/controller bug):
`workload-missing-limits -> playbook/resource-limits` and `sec-env-var-secrets ->
playbook/secret-as-volume` both pointed at refs that resolved to nothing. The former is
now a proper schema-aware `FieldPatch` (same owner-resolution treatment as every other
Pod-template field); the latter is a genuine multi-step manifest change (move an env var
to a mounted volume), so it became a static manual-review playbook, like
`remove-hostpath`. `tests/test_registry.py::test_no_dangling_remediation_refs` guards
against this class of bug recurring.

**Dead code found and removed:** `remediation_engine.py::_CONTAINER_INDEXED_REFS` was
defined but never referenced — the actual container-index warning already keys off
`field.op == "json-add"` directly, which is more general and correctly covers the field
added by this same pass (`resource-limits`) without needing to be manually kept in sync.

Final: **25 MCP tools**, every one with a substantive docstring (FastMCP surfaces it
directly as the tool's description to the calling LLM — enforced by
`test_every_tool_has_a_nonempty_docstring`), full per-tool reference in `USAGE.md` §4.5.
Test suite: **137/137 passing** (was 113/113 before this pass).

## 6e. Report format made audit-grade + PDF export added

Every report format previously carried the minimum a scanner needs (rule id, severity,
message, MITRE/OWASP/CIS tags, a fix command). Brought up to what an industry-standard
tool report (Nessus/Qualys/Prisma-Cloud-style) actually includes: for **every finding, in
every format**, a full write-up with —

1. **Summary** — a plain-English explanation, not just the raw detection message
2. **Standards & Benchmark Mapping** — which named standard/framework (CIS Kubernetes
   Benchmark, OWASP Kubernetes Top 10, NSA/CISA Hardening Guide) the finding maps to,
   each with a real reference link
3. **MITRE ATT&CK Mapping** — tactic + technique, each with its exact, individually
   addressable `attack.mitre.org` link (including correct sub-technique slash-notation:
   `T1552.007` → `.../techniques/T1552/007/`, not the dot form)
4. **Impact** — the concrete, real-world consequence if left unaddressed (not a severity
   restatement — an actual explanation, e.g. what a container-escape primitive lets an
   attacker do next)
5. **Remediation** — the exact command (from the existing schema-aware remediation
   engine, §6c) plus a reference link, or, when it can't be automated, why not
6. **Validation** — exact steps/commands to reproduce and independently verify the
   finding, and to confirm it cleared after the fix

**New module — `k8smatrixwarden/core/finding_context.py`** is the single shared content
layer every renderer (markdown/html/json/sarif/pdf; terminal/text more lightly) reads
from, so no format can say something different from another about what a finding means.
It holds:
- `FINDING_CONTEXT`: hand-authored summary/impact/validation content for **all 56
  registered rules** (verified 1:1 against the live registry — a rule with no KB entry
  is a build-time-detectable gap, not a silent one), with a non-empty generated fallback
  for any future rule that hasn't been added to the KB yet
- `standards_for()` / `mitre_for()`: derive the Standards/MITRE tables directly from a
  rule's own `owasp`/`cis`/`nsa_cisa`/`mitre` tags (never hand-duplicated data that could
  drift) — CIS control titles are pulled from the **same vendored catalog**
  (`frameworks/cis_catalog.py`) the CIS Benchmark Engine itself evaluates against, not a
  generic "Control X.Y.Z" placeholder
- `mitre_technique_url()`: computes the real MITRE ATT&CK URL, correctly handling the
  sub-technique slash-vs-dot convention

**New format — PDF**, via the optional `pdf` extra (`fpdf2` — pure Python, no system
dependencies, consistent with how `live`/`pretty`/`mcp` are already optional). A title
page with a colored risk-score box, an executive summary, coverage tables, and the same
seven-section write-up per finding as markdown/html — `k8smatrixwarden/core/pdf_report.py`.
`ReportingEngine.render()` now returns `bytes` for `fmt="pdf"` and `str` for every other
format; every caller (CLI, chat, MCP) branches on this explicitly rather than assuming a
uniform return type, and PDF is written in binary mode / base64-encoded over MCP's JSON
transport as appropriate.

**Two real PDF-generation bugs found and fixed during development** (both now guarded by
tests):
1. `multi_cell(w=0, ...)` does **not** reset the cursor to the left margin by default in
   this fpdf2 version (it stays at the right edge of the text it just drew) — the second
   row of any two-column key/value table would silently overflow off the page width and
   raise `FPDFException: Not enough horizontal space to render a single character`. Fixed
   by passing `new_x="LMARGIN", new_y="NEXT"` explicitly on every `multi_cell` call.
2. The 3 built-in PDF core fonts (Helvetica/Courier) only support Latin-1 — the shared
   `finding_context.py` prose (correctly) uses real Unicode em-dashes, arrows, and curly
   quotes throughout, which crashed PDF rendering with `FPDFUnicodeEncodingException`.
   Fixed with a belt-and-suspenders sanitizer (`_ascii()`): overridden on the PDF
   subclass's own `cell()`/`multi_cell()` for every direct call, **and** applied
   explicitly at every `Table.row().cell()` call site, since fpdf2's table renderer
   batches and draws cells through an internal path that doesn't route back through the
   overridden methods. Rather than degrade the shared Unicode-rich KB content to
   accommodate one output format, the sanitization is PDF-local — markdown/html/json/
   sarif keep the real typography.

Verified: all 56 rules' generated content renders through the PDF pipeline with zero
exceptions (a full mock scan, 81 findings), plus the zero-finding and missing-fpdf2-extra
paths. Test suite: **163/163 passing** (was 137/137 before this pass) — 11 new
`test_finding_context.py`, 6 new `test_pdf_report.py`, plus new assertions in
`test_reporting.py` and `test_mcp.py`.

## 7. Suggested next steps (priority order)

1. Wire the **Trivy** and **kube-bench** adapters (highest coverage-per-effort; unlocks real
   CVE + full CIS).
2. Add the **cloud IAM adapter** (EKS/GKE/AKS) to populate the `CloudIAM` bucket live —
   closes the single highest-leverage gap from the redesign (§2).
3. Feed the **Runtime Agent** from a live Falco/audit source in-cluster (DaemonSet).
4. Add **trend/delta** storage (scan history) to power the "↑/↓ vs last scan" reporting the
   spec describes (§18.3).
5. Layer the **LLM intent parser** onto `Orchestrator.interpret` for free-form phrasing.
