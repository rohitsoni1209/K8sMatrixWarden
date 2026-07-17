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
| Registry builds & validates | `k8ssec doctor` → 10 shards / 56 rules / ✅ clean |
| Every tactic covered | `k8ssec coverage` → all 9 tactics have ≥1 rule |
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
   `ClusterRole` per shard (`k8ssec roles`) — the least-privilege-below-the-agent model
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
- **Per-plugin least privilege**: `k8ssec roles` emits a scoped ClusterRole per shard so a
  compromised/buggy shard is limited to what it declared (§20). Cloud IAM's external
  credential is declared in its manifest, not granted globally.
- **No secret values are printed**: secret rules report *shape/location* (env name, key
  name), never decoded contents.

---

## 6a. CIS Benchmark full coverage (added post-initial-build)

The initial build had only ~26 CIS-tagged rules and flagged "full CIS" as a gap. That gap is
now closed with a dedicated **CIS Benchmark Engine** (`k8ssec/frameworks/`):

- **Authoritative catalog.** All **130** CIS Kubernetes Benchmark v1.8 controls were pulled
  verbatim from kube-bench's `cfg/cis-1.8/*.yaml` (not from memory). The original spec's
  "242 checks" was an **over-count** and has been corrected in the v3.0 doc (§5.9) — the real
  benchmark is 130 controls (§1=60, §2=7, §3=5, §4=23, §5=35).
- **Every control gets a status** — `PASS` / `FAIL` / `MANUAL` / `NA` / `NEEDS_NODE` — so
  nothing is silently missed. Initial split was 25 native + 2 builtin + 69 kube-bench + 34
  manual; **§6b then mitigated the 69 down to 31** by recovering process flags from the API.
- **kube-bench delegation is real**: `k8ssec cis --kube-bench-json kb.json` merges kube-bench
  results, moving node controls out of NEEDS_NODE into PASS/FAIL (unit-tested).
- **Data-caught a real bug**: the tag-alignment test found `workload-hostpath-writable` was
  missing its `cis: 5.2.12` tag (fixed). Several native rules' CIS ids were also corrected to
  the true v1.8 numbering (e.g. privileged container 5.2.1 → 5.2.2, run-as-root 5.2.6 → 5.2.7).
- **6 new tests** (`tests/test_cis.py`); suite is now **31/31 passing**.

## 6b. Node-access limitation — mitigated (NEEDS_NODE 69 → 31)

The initial CIS engine marked all 69 non-policy control-plane/node controls `NEEDS_NODE`.
That was pessimistic: most are **process flags**, not file reads, and flags are recoverable
from the K8s API. Three mitigation layers (v3.0 doc §5.9.2) close the gap:

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

## 7. Suggested next steps (priority order)

1. Wire the **Trivy** and **kube-bench** adapters (highest coverage-per-effort; unlocks real
   CVE + full CIS).
2. Add the **cloud IAM adapter** (EKS/GKE/AKS) to populate the `CloudIAM` bucket live —
   closes the single highest-leverage gap from the redesign (§2).
3. Feed the **Runtime Agent** from a live Falco/audit source in-cluster (DaemonSet).
4. Add **trend/delta** storage (scan history) to power the "↑/↓ vs last scan" reporting the
   spec describes (§18.3).
5. Layer the **LLM intent parser** onto `Orchestrator.interpret` for free-form phrasing.
