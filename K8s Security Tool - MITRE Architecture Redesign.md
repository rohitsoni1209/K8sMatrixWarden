# K8s Security Tool — MITRE ATT&CK-Aligned Scanning Architecture Redesign

**Companion to:** `K8s security tool.md` (v2.0 Architecture & Design Document)
**Purpose:** Evaluate how the Scanner Agent should evolve to align with the Kubernetes Threat Matrix (https://kubernetes-threat-matrix.redguard.ch/), and recommend a production-grade scanning architecture.
**Scope:** Architecture and design only — no implementation.

---

## 0. Grounding — What the Kubernetes Threat Matrix Actually Contains

The Redguard matrix is an **extension of Microsoft's original 2020/2021 Kubernetes Threat Matrix**, not an independent taxonomy. Redguard's own site states it "extended the version of the Kubernetes Attack Matrix, especially by adding specific examples to simulate the techniques and references to learn even more about them." Structurally it has **9 tactics**, no technique IDs, no versioning, and no machine-readable schema — it's a human-readable reference page, not an API.

**The 9 tactics and their techniques (verified from the live site):**

| Tactic | Techniques |
|---|---|
| **Initial Access** | Using cloud credentials · Compromised images in registry · Kubeconfig file · Application vulnerability · Exposed sensitive interfaces |
| **Execution** | Exec into container · bash/cmd in container · New container · Application exploit (RCE) · SSH server running inside container · Sidecar injection |
| **Persistence** | Backdoor container · Writable hostPath mount · Kubernetes CronJob · Malicious admission controller |
| **Privilege Escalation** | Privileged container · Cluster-admin binding · hostPath mount · Access cloud resources · Disable namespacing (hostPID/hostNetwork/hostIPC) |
| **Defense Evasion** | Clear container logs · Delete K8s events · Pod/container name similarity · Connect from proxy server |
| **Credential Access** | List K8s secrets · Mount service principal · Access container service account · App credentials in config files · Access managed identity credentials · Malicious admission controller |
| **Discovery** | Access K8s API server · Access Kubelet API · Network mapping · Access Kubernetes dashboard · Instance metadata API |
| **Lateral Movement** | Access cloud resources · Container service account · Cluster internal networking · App credentials in config files · Writable volume mounts on host · CoreDNS poisoning · ARP poisoning/IP spoofing |
| **Impact** | Data destruction · Resource hijacking · Denial of service |

**Important correction to our existing doc:** Section 10.1 of `K8s security tool.md` lists a 10th column, **"Collection,"** with entries "Images from private registry" and "Collecting data from pod." **This tactic does not exist in the actual Redguard/Microsoft matrix.** It appears to have been invented or borrowed from the general MITRE Enterprise ATT&CK matrix (which does have a Collection tactic) rather than the Kubernetes-specific one. Recommend removing it from the existing doc or clearly labeling it as a custom extension, to avoid the tool's own documentation diverging from the reference it claims to implement.

**A second, sharper limitation worth flagging:** Redguard's matrix has **no stable technique IDs**. "Privileged Container" is just a string. MITRE's own **ATT&CK for Containers** (published inside the official Enterprise ATT&CK matrix since v10, maintained by the MITRE Center for Threat-Informed Defense) *does* have stable, versioned IDs — e.g. `T1610` Deploy Container, `T1611` Escape to Host, `T1613` Container and Resource Discovery, `T1552.007` Container API Credentials in Files. This matters architecturally (see §7): a production platform should not hard-code string-matching against a taxonomy that can be renamed without notice.

---

## 1. Detection-Method Classification per Technique

Every technique needs a different *kind* of evidence. Classifying this up front is what makes §3's architecture decision non-arbitrary — it's the reason a "one agent per tactic" split doesn't align with how the evidence is actually gathered.

| Detection Method | What it means | Data source |
|---|---|---|
| **Static/Config** | Inspect a resource manifest/spec at rest | K8s API (declarative objects) |
| **RBAC-based** | Analyze the permission graph | Roles/Bindings/`can-i` |
| **Image-based** | Inspect image layers/metadata | Registry, Trivy/Grype/Syft/Cosign |
| **Network-based** | Test reachability/exposure | Service/Ingress/NetworkPolicy objects + live probes |
| **Audit-log-based** | Pattern-match API server audit events | K8s audit log stream |
| **Runtime/Behavioral** | Kernel/syscall or process-level signal | Falco/Tetragon + baseline engine |
| **Cloud-IAM-based** | Inspect cloud-side identity bindings | Cloud provider API (IRSA, Workload Identity, Managed Identity) — outside the K8s API surface entirely |

| Tactic → Technique | Method(s) |
|---|---|
| Initial Access → Using cloud credentials | Cloud-IAM |
| Initial Access → Compromised images in registry | Image |
| Initial Access → Kubeconfig file | Static/Config + Image (grep) |
| Initial Access → Application vulnerability | Image (out of full scope — see §2) |
| Initial Access → Exposed sensitive interfaces | Network |
| Execution → Exec into container | Audit-log + Runtime |
| Execution → bash/cmd in container | Runtime |
| Execution → New container | Audit-log + Runtime (drift) |
| Execution → Application exploit (RCE) | Runtime (indirect) + Image |
| Execution → SSH server in container | Image + Runtime |
| Execution → Sidecar injection | Static/Config (webhook audit) + Runtime (drift) |
| Persistence → Backdoor container | Runtime (drift) + Audit-log |
| Persistence → Writable hostPath mount | Static/Config |
| Persistence → Kubernetes CronJob | Static/Config + Audit-log |
| Persistence → Malicious admission controller | Static/Config + Audit-log |
| Privilege Escalation → Privileged container | Static/Config |
| Privilege Escalation → Cluster-admin binding | RBAC |
| Privilege Escalation → hostPath mount | Static/Config |
| Privilege Escalation → Access cloud resources | Cloud-IAM |
| Privilege Escalation → Disable namespacing | Static/Config |
| Defense Evasion → Clear container logs | Runtime |
| Defense Evasion → Delete K8s events | Audit-log + RBAC |
| Defense Evasion → Pod/container name similarity | Static/Config (heuristic) |
| Defense Evasion → Connect from proxy server | Audit-log (source IP analysis) |
| Credential Access → List K8s secrets | RBAC + Audit-log |
| Credential Access → Mount service principal | Static/Config (volume scan) |
| Credential Access → Access container service account | Static/Config + RBAC |
| Credential Access → App credentials in config files | Static/Config (secrets scan) |
| Credential Access → Access managed identity credentials | Network (IMDS) + Cloud-IAM |
| Credential Access → Malicious admission controller | Static/Config + Audit-log |
| Discovery → Access K8s API server | RBAC + Audit-log |
| Discovery → Access Kubelet API | Network + Static/Config |
| Discovery → Network mapping | Runtime |
| Discovery → Access Kubernetes dashboard | Network |
| Discovery → Instance metadata API | Network + Runtime |
| Lateral Movement → Access cloud resources | Cloud-IAM |
| Lateral Movement → Container service account | RBAC (fan-out analysis) |
| Lateral Movement → Cluster internal networking | Network |
| Lateral Movement → App credentials in config files | Static/Config |
| Lateral Movement → Writable volume mounts on host | Static/Config |
| Lateral Movement → CoreDNS poisoning | RBAC + Runtime (drift) |
| Lateral Movement → ARP poisoning/IP spoofing | Network/CNI + Runtime |
| Impact → Data destruction | Audit-log + Runtime |
| Impact → Resource hijacking | Runtime |
| Impact → Denial of service | Static/Config + Runtime |

**Observation that drives the rest of this document:** techniques cluster far more tightly by *detection method / data source* than by *tactic*. `hostPath mount` is Static/Config whether it's serving Persistence, Privilege Escalation, or Lateral Movement. `Malicious admission controller` is the same evidence whether it's Persistence or Credential Access. This many-to-many relationship (a technique legitimately serves multiple tactics — that's how ATT&CK is designed) is the crux of the §3 architecture decision.

---

## 2. Coverage Matrix — Threat Matrix vs. Existing Scanner

Legend: 🟢 Full · 🟡 Partial · 🔴 None. Module references use the numbering from `K8s security tool.md` §5 (① Cluster & Control Plane, ② Workload & Pod Security, ③ RBAC & Identity, ④ Network, ⑤ Image & Supply Chain, ⑥ Secrets, ⑦ Compliance, ⑧ Attack Surface) plus the Runtime Agent (§6).

### Initial Access

| Technique | Existing Module | Status | Missing | Suggested Implementation |
|---|---|---|---|---|
| Using cloud credentials | — | 🔴 | No Cloud IAM scanner exists at all | New module: **Cloud IAM Scanner** — inspects IRSA/Workload Identity/AAD Pod Identity annotations on ServiceAccounts, cross-references attached cloud role policies for over-permission |
| Compromised images in registry | ⑤ Image & Supply Chain | 🟡 | CVE scan and signing exist, but no provenance/attestation (SLSA) verification, no known-malicious-hash feed | Add `cosign verify-attestation` check + integrate a malicious-image hash/IOC feed |
| Kubeconfig file | ⑥ Secrets (partial) | 🔴 | No pattern-matching for kubeconfig blocks in ConfigMaps/Secrets/image layers | Extend Module ⑥ + ⑤ with a `apiVersion: v1 / clusters:` / `.kube/config` path regex check |
| Application vulnerability | ⑤ Image & Supply Chain | 🟡 | Covers OS/library CVEs only; app-layer logic flaws (SASI/DAST) are explicitly out of scope for a K8s-focused tool | Document as an intentional boundary; expose an integration point (SARIF ingestion) rather than building SAST |
| Exposed sensitive interfaces | ④ Network Security | 🟢 | — | Already strong: dashboard, kubelet ports, etcd, NodePort/LB enumeration |

### Execution

| Technique | Existing Module | Status | Missing | Suggested Implementation |
|---|---|---|---|---|
| Exec into container | Runtime — Audit Event Analyzer | 🟡 | Rule only listed for `kube-system` exec; not generalized cluster-wide with RBAC correlation | Generalize the audit rule to all namespaces; join with "who has `pods/exec` verb" from Module ③ |
| bash/cmd in container | Runtime — Falco | 🟢 | — | "Shell spawned in container" rule already defined |
| New container | Runtime — Audit + Drift | 🟡 | Only "privileged:true" creation is flagged; no generic new-container-in-existing-workload diff | Extend Behavioral Baseline Engine to diff Pod template vs. running container set |
| Application exploit (RCE) | Runtime — Falco (indirect) | 🟡 | No explicit RCE signature; relies on downstream shell-spawn/recon rules | Acceptable as indirect coverage; document the inference chain |
| SSH server in container | — | 🔴 | No image-layer or runtime check for `sshd` | Add binary-presence check (`/usr/sbin/sshd`) to Module ⑤; add Falco rule for `sshd` process spawn / port 22 listen |
| Sidecar injection | — | 🔴 | No audit of MutatingWebhookConfigurations, no drift detection for unexpected sidecars | New checks under a **Admission Control** sub-module (see §2 Persistence row below — same gap) |

### Persistence

| Technique | Existing Module | Status | Missing | Suggested Implementation |
|---|---|---|---|---|
| Backdoor container | Runtime — Drift Detector | 🟡 | Detects new binaries inside a container, not a wholly new unauthorized container/workload | Audit-event rule for Pod/Deployment creation outside a known CI/CD image allowlist |
| Writable hostPath mount | ② Workload & Pod Security | 🟢 | — | Strong coverage (hostPath-to-root, docker.sock) |
| Kubernetes CronJob | — | 🔴 | No CronJob enumeration at all | New checks: enumerate CronJobs, flag suspicious schedules/images, alert on new CronJob creation via audit events |
| Malicious admission controller | — | 🔴 | No webhook configuration scanning | New **Admission Control Scanner** — validates `MutatingWebhookConfiguration`/`ValidatingWebhookConfiguration` (failurePolicy, namespaceSelector scope, endpoint reachability) + audit-event alert on new webhook registration |

### Privilege Escalation

| Technique | Existing Module | Status | Missing | Suggested Implementation |
|---|---|---|---|---|
| Privileged container | ② Workload | 🟢 | — | — |
| Cluster-admin binding | ③ RBAC | 🟢 | — | — |
| hostPath mount | ② Workload | 🟢 | — | — |
| Access cloud resources | — | 🔴 | Same Cloud IAM gap as Initial Access | Cloud IAM Scanner (shared with Initial Access / Lateral Movement) |
| Disable namespacing (hostPID/Network/IPC) | ② Workload | 🟢 | — | — |

### Defense Evasion

| Technique | Existing Module | Status | Missing | Suggested Implementation |
|---|---|---|---|---|
| Clear container logs | — | 🔴 | No detection for log truncation/deletion | Falco rule for writes/truncation on container log paths |
| Delete K8s events | Runtime — Audit Analyzer | 🟡 | Consumes audit events generally but doesn't explicitly flag `delete` verb on `events` | Add explicit audit-event rule + RBAC check for who can delete events (should be nobody by default) |
| Pod/container name similarity | ⑤ Image (typosquat, image names only) | 🟡 | Typosquat logic exists for image names, not pod/container names impersonating system components | Extend the same heuristic to `metadata.name` against a `kube-*`/`system:*` allowlist |
| Connect from proxy server | — | 🔴 | No source-IP anomaly analysis on API audit logs | New Runtime sub-component: audit log `sourceIPs` vs. known proxy/VPN/Tor ranges + geo/baseline deviation |

### Credential Access

| Technique | Existing Module | Status | Missing | Suggested Implementation |
|---|---|---|---|---|
| List K8s secrets | ③ RBAC + Runtime Audit | 🟢 | — | — |
| Mount service principal | — | 🔴 | No check for mounted cloud credential files (`.aws/credentials`, `azure.json`, GCP SA JSON) | Extend Module ② volume-mount scan + Module ⑥ secrets scan for these known filename/shape patterns |
| Access container service account | ② + ③ | 🟢 | — | — |
| App credentials in config files | ⑥ Secrets | 🟢 | — | — |
| Access managed identity credentials | ④ Network (generic IMDS reachability) | 🟡 | Doesn't distinguish IMDSv1 vs IMDSv2 enforcement or scope of attached identity | Enhance Module ④ to check IMDSv2-only enforcement (AWS) and flag identity scope breadth |
| Malicious admission controller | — | 🔴 | Duplicate of Persistence gap | Shared fix — Admission Control Scanner |

### Discovery

| Technique | Existing Module | Status | Missing | Suggested Implementation |
|---|---|---|---|---|
| Access K8s API server | ① + ③ | 🟢 | — | — |
| Access Kubelet API | ① + ④ | 🟢 | — | — |
| Network mapping | Runtime — Falco | 🟢 | — | — |
| Access Kubernetes dashboard | ④ Network | 🟢 | — | — |
| Instance metadata API | ④ + Runtime | 🟢 | — | — |

Discovery is the strongest-covered tactic in the current design — no gaps.

### Lateral Movement

| Technique | Existing Module | Status | Missing | Suggested Implementation |
|---|---|---|---|---|
| Access cloud resources | — | 🔴 | Duplicate Cloud IAM gap | Cloud IAM Scanner |
| Container service account | ③ RBAC (permission breadth only) | 🟡 | No "same SA reused across N pods/namespaces" blast-radius metric | Add SA fan-out metric to Module ⑧ Attack Surface Mapper |
| Cluster internal networking | ④ Network | 🟢 | — | — |
| App credentials in config files | ⑥ Secrets | 🟢 | — | — |
| Writable volume mounts on host | ② Workload | 🟢 | — | — |
| CoreDNS poisoning | — | 🔴 | No RBAC/config check on `kube-system/coredns` ConfigMap | New check: who can write the CoreDNS ConfigMap (RBAC) + Runtime drift rule on its modification |
| ARP poisoning / IP spoofing | ② (partial — NET_RAW cap) | 🟡 | No CNI-level anti-spoofing/L2-isolation verification | Extend Module ④ to verify CNI plugin enforces anti-ARP-spoofing (Calico WEP, Cilium L2 policy) |

### Impact

| Technique | Existing Module | Status | Missing | Suggested Implementation |
|---|---|---|---|---|
| Data destruction | Runtime — Audit Analyzer (generic) | 🟡 | No explicit bulk-`delete` spike detection on PV/PVC/StatefulSet | Add audit-event rule for mass-delete verb spikes |
| Resource hijacking | Runtime — Falco (crypto-miner signatures) | 🟢 | — | — |
| Denial of service | ② (resource limits) + Runtime | 🟢 | — | — |

### Coverage Summary

| Status | Count / 45 techniques |
|---|---|
| 🟢 Full | 22 (49%) |
| 🟡 Partial | 15 (33%) |
| 🔴 None | 8 (18%) |

**The 8 true gaps, ranked by how many tactics they touch (fix these first — they're cross-cutting):**

1. **Cloud IAM / workload identity scanning** — touches Initial Access, Privilege Escalation, Lateral Movement (highest leverage gap)
2. **Malicious/unaudited admission controllers** — touches Persistence, Credential Access, and enables Execution (sidecar injection)
3. **CoreDNS poisoning path** (RBAC on the ConfigMap)
4. **Kubernetes CronJob persistence**
5. **SSH server inside containers**
6. **Kubeconfig file exposure**
7. **Connect-from-proxy-server (audit log source-IP analysis)**
8. **ARP poisoning / IP spoofing (CNI-level enforcement check)**

Notably, **1 and 2 alone close gaps across five of nine tactics.** That reinforces §1's finding: the current 8 modules are already well-organized around *data sources*; what's missing isn't new tactic-shaped agents, it's two or three new *domain* modules (Cloud IAM, Admission Control) plus incremental rules inside existing modules.

---

## 3. Architecture Evaluation

### Option A — One Agent per MITRE Tactic

**Advantages**
- Marketing/reporting clarity: "Persistence Agent found 3 issues" reads well in a demo.
- Maps 1:1 to how a SOC analyst mentally organizes an incident.
- Superficially easy to reason about "what does this agent do."

**Disadvantages**
- **Techniques are not tactic-exclusive.** `hostPath mount` appears under Persistence *and* Privilege Escalation *and* Lateral Movement in the matrix itself. A literal per-tactic agent either (a) duplicates the check three times across three codebases, or (b) one agent owns it and the others have to call into it anyway — which quietly collapses back into a shared-library architecture while keeping the deployment overhead of 9 agents.
- **9x redundant Kubernetes API load.** Every tactic agent that touches Pods (at least 6 of the 9 do) independently lists/watches Pods across the cluster. On a large cluster this multiplies API server load and increases the chance of throttling — a real operational risk, not a hypothetical one.
- **RBAC and ops overhead multiply.** 9 Deployments, 9 sets of health checks, 9 log streams, 9 upgrade paths, 9 potential CVEs in the agent images themselves. The existing design already commits to least-privilege and read-only RBAC (§3.4, §18) — 9 agents means 9 more ClusterRoleBindings to audit rather than 1.
- **Team ownership misaligned.** Real security engineers specialize by domain (RBAC, network, image supply chain), not by MITRE tactic. A "Persistence Agent" owner would need to be simultaneously expert in CronJobs, hostPath, admission webhooks, and container drift — a much wider and shallower skill surface than "the RBAC person" or "the network person."
- **Taxonomy fragility.** MITRE matrices get revised (Microsoft's matrix has already been extended by Redguard; MITRE's own ATT&CK for Containers uses a different, more granular tactic/technique split). If tactics are baked into the process/deployment boundary, a taxonomy revision becomes an *infrastructure* change (add/remove/rename a Deployment), not a metadata change.
- **Scalability is the wrong shape.** You don't scale "Persistence scanning" independently in practice — you scale by *cluster size* (more pods/namespaces to fetch) or by *slow external tool calls* (image CVE scanning). Tactic is orthogonal to both real scaling axes.

**Verdict:** Intuitive on a slide, expensive and fragile in production. MITRE tactics are a **reporting/labeling dimension**, not a natural **execution boundary**.

### Option B — Single Monolithic Scanner

**Advantages**
- No duplicate data fetching — one pod list, one RBAC graph walk, shared in-memory cache per scan.
- Simplest possible deployment/ops footprint.
- Easiest to guarantee cross-check consistency (one codebase, one version).

**Disadvantages**
- Becomes a "God module": as gaps in §2 are closed (Cloud IAM, Admission Control, CoreDNS, CronJobs, SSH detection, proxy analysis, ARP/CNI checks) plus CIS/NSA/OWASP/custom-enterprise rules (§9), this one process accumulates hundreds to low-thousands of checks with no internal boundary.
- A bug or panic in one check (e.g., a malformed CronJob object crashing a naive parser) risks taking down the entire scan, including unrelated domains like RBAC.
- Cannot independently version or release a single new Trivy-based rule without redeploying (and re-risking) everything else.
- Cannot cleanly answer "scan only RBAC" or "scan only Persistence" *unless it already contains an internal router/filter* — at which point it has secretly reinvented a registry pattern, just without any module boundary to keep it maintainable. This is the tell that a pure monolith isn't really "simpler," it just hides the complexity that Option A/C make explicit.
- Cannot independently scale IO-bound checks (image CVE scans against a registry, network round-trips) separately from cheap in-memory config checks — one process means one scaling knob for very different cost profiles.

**Verdict:** Efficient at data-fetching, but doesn't survive growth. The moment it needs selective execution (which the user's §5 requirements explicitly demand), it has to build the exact registry/router machinery that Option C proposes as a first-class concept — just informally and without the module boundaries that make it maintainable.

---

## 4. Recommended Architecture — Domain-Sharded Execution + Cross-Cutting Rule Registry

**Neither A nor B.** The right decomposition axis is **data source / domain** (which the *existing* 8 modules already got right — Cluster, Workload, RBAC, Network, Image, Secrets, Compliance, Attack Surface) because that's what determines which K8s API objects need to be fetched and which external tool needs to be invoked. **MITRE tactic (and OWASP category, and CIS control ID) should be metadata layered on top, not a physical boundary.**

Concretely:

1. **Keep the macro architecture from `K8s security tool.md` §3 unchanged.** Orchestrator, Scanner Agent, Runtime Agent, Remediation Agent, MCP Server stay as-is. This redesign is internal to the Scanner Agent (and, to a lesser degree, the Runtime Agent's rule set).
2. **Refactor each of the 8 domain modules from a monolithic "module" into a plugin that owns a set of independent, self-describing Rules.** One rule = one technique-level check (e.g., `privileged-container`, `cluster-admin-default-sa`, `cronjob-suspicious-schedule`). A module is now a *namespace of rules that share a data-fetch pattern*, not a single scan function.
3. **Add a Rule/Technique Registry that indexes every rule by all of its taxonomy tags** (MITRE tactic + technique, OWASP K8s Top 10 ID, CIS control ID, NSA/CISA control, severity, resource scope) at process startup.
4. **A scan request resolves to a *set of rule IDs* via the registry**, regardless of which module those rules physically live in. "Scan for Persistence" doesn't invoke a Persistence *agent* — it queries the registry for `tactic == Persistence`, gets back rule IDs from Modules ①②④⑤(new: Admission Control), and executes exactly those, sharing one evidence-fetch pass.

This gets Option A's selective-execution UX and Option B's shared-data efficiency, while avoiding both of their failure modes. It is also not a novel idea invented for this project — it's the same pattern used by every mature policy/rule engine in this space: **OPA/Conftest and Kyverno** (declarative rules with metadata), **Checkov and Semgrep** (rules tagged with CWE/compliance IDs), **Trivy and Kubescape** (checks tagged with framework + control IDs). Re-deriving a bespoke alternative would be reinventing a solved problem; the existing tool's own MCP "Compliance Rule Sets" dataset (§8.1, Dataset 5) already implies this shape.

**Why this is superior, concretely:**

| Concern | Option A | Option B | Recommended (Domain + Registry) |
|---|---|---|---|
| Duplicate API calls | High (9x) | None | None (shared Evidence Collector) |
| "Scan for tactic X" | Native but wasteful | Requires informal internal router | Native — registry query |
| "Scan only technique Y" | Awkward (which agent owns it?) | Requires informal internal router | Native — registry query |
| Team ownership | Misaligned (tactic ≠ skill) | No boundaries at all | Aligned (domain = skill) |
| Blast radius of a bug | Contained to 1 tactic (but duplicated logic across others) | Whole scanner | Contained to 1 rule/module |
| Taxonomy revision (MITRE, OWASP, CIS all change independently) | Infra change | Code hunt across monolith | Metadata-only change |
| Independent scaling (slow image scans vs. cheap config checks) | No — scales by tactic, wrong axis | No — one process | Yes — scale by module/rule cost profile |
| New scanner/tool integration | Unclear which tactic-agent owns it | Bolt onto monolith | New plugin registers itself |

---

## 5. Ideal Scanning Workflow

### 5.1 Canonical scan request shape

Every entry point (CLI, chat, Web UI, REST API) should compile down to one internal object — this is what makes "scan a namespace," "scan for Persistence," and "scan only Container Escape" the *same code path* with different parameters, rather than three different features to build and maintain separately:

```
ScanRequest {
  scope: {
    cluster            |
    namespace: <ns>    |
    workload: <kind>/<name> in <ns>  |
    node: <name>       |
    pod: <name> in <ns> |
    image: <ref>        |
    helm_release: <name> in <ns>
  }
  selector (optional, combinable):
    tactic: <MITRE tactic>          # "Scan for Persistence"
    technique: <MITRE technique>    # "Scan only Container Escape"
    module: <domain>                # "Scan everything related to RBAC"
    rule_id: <specific rule>        # "Scan only Privileged Pods"
    severity_min: <LOW..CRITICAL>
    framework: <CIS | NSA | OWASP>  # audit-style requests
  mode: sync | async
  output: terminal | markdown | json | pdf | sarif | html
}
```

If `selector` is omitted, every rule whose `resource_scope` matches `scope` runs (today's "full scan" behavior). If `selector` is present, it's intersected with scope.

### 5.2 Execution flow (all request types share this path)

```
1. Orchestrator: Intent Classifier → SCAN/AUDIT/MAP + parses scope + selector → ScanRequest
2. Scanner Agent: Rule Registry.resolve(ScanRequest.selector) → concrete rule_id set
3. Scanner Agent: Evidence Collector.fetch(union of resource_scopes needed by resolved rules,
                                            constrained to ScanRequest.scope)
                  → one shared snapshot/cache (pods, roles, netpols, images, ... only what's needed)
4. Detection Engine: for each resolved rule → execute(rule, evidence) → raw findings
5. Result Aggregator: dedupe, attach full taxonomy tags (MITRE + OWASP + CIS + NSA) per finding
6. Risk Scoring Engine: severity × exploitability × blast_radius
7. Reporting Engine: render in requested format, filterable by any tag axis
```

Step 3 is the efficiency win over Option A: if a "Persistence" scan and an "RBAC" scan both need the Pod list, and both are requested (or both happen to overlap in resolved rules), the Evidence Collector fetches Pods once per scan session, not once per conceptual agent.

### 5.3 Worked examples

**"Scan the production namespace"**
`scope = {namespace: production}`, no selector → registry resolves to *all* rules whose scope includes `namespace`-level resources → full existing behavior, unchanged from today.

**"Scan for Persistence"**
`selector = {tactic: Persistence}` → registry returns rule IDs from Modules ②(hostPath), ①/new-Admission-Control(webhooks), new-CronJob-check, Runtime-drift(backdoor container) → only those execute, cluster-wide by default unless scope narrows it.

**"Scan only Container Escape"**
`Container Escape` isn't a single MITRE technique — it's a composite *outcome label* spanning several rules (privileged container, hostPath-to-root, docker.sock mount, dangerous capabilities like `SYS_ADMIN`). The registry needs a layer of **named composite selectors** (aliases that expand to a rule-ID set) in addition to raw tactic/technique lookup — see §8 for how these are authored and resolved.

**"Scan everything related to RBAC"**
`selector = {module: rbac_identity}` — this is a *domain* filter, not a MITRE filter, proving the selector needs 3 independent axes (tactic, technique/outcome, domain), not just MITRE.

**"Scan only Privileged Pods"**
`selector = {rule_id: workload-privileged-container}` — direct rule lookup, the finest-grained case.

---

## 6. Internal Architecture Components

| Component | Responsibility |
|---|---|
| **Scanner Registry** | Catalog of domain plugins (the 8+ modules). Tracks each plugin's name, version, K8s resource types it needs, and the RBAC verbs it requires (feeds least-privilege RoleBinding generation). |
| **Rule/Technique Registry** | Catalog of every individual rule: `id`, `title`, `owning_module`, `resource_scope`, `mitre[]`, `owasp`, `cis[]`, `nsa_cisa[]`, `severity`, `detection_method` (from §1's taxonomy), `remediation_ref`. Built once at startup from each plugin's declared rules. |
| **MITRE Mapping Engine** | A query layer over the Rule Registry, specialized for taxonomy lookups: tactic → rule IDs, technique → rule IDs, composite/outcome alias → rule IDs. Owns the versioned canonical taxonomy files (see §7) so rule tags can be validated against real technique IDs, not free-text strings. |
| **Evidence Collector** | Shared, scope-aware fetch/cache layer. Lists/watches only the resource types the resolved rule set actually needs, once per scan session, and hands typed objects to rules — this is what prevents Option A's 9x-refetch problem. |
| **Detection Engine (Rule Executor)** | Executes the resolved rule set against the evidence snapshot. Rule implementations can be native code, OPA/Rego policy, or a wrapped external tool invocation (Trivy, kube-bench, etc.) — the executor treats them uniformly via a common interface. |
| **External Tool Adapters** | Normalize third-party tool output (Trivy JSON, kube-bench JSON, kubescape results, Falco alerts) into the same internal Finding schema, attaching taxonomy tags via a per-tool mapping table. This is where MCP Dataset 2 (Scanning Tool Commands) and Dataset 4 (CVE KB) plug in. |
| **Result Aggregator** | Dedupes findings that multiple rules independently flag against the same underlying object, merges their taxonomy tags into one finding, and resolves finding identity across scans for trend deltas. |
| **Risk Scoring Engine** | Existing formula (severity × exploitability × blast radius) from §16.1, extended with an *attack-path-aware* bonus: a finding that closes off multiple tactics along a plausible chain (e.g., a `hostPath` mount that enables both Persistence and Privilege Escalation) should score higher than one that only closes a single, isolated tactic. |
| **Reporting Engine** | Existing 6 formats (§16.2), now with tag-based filtering as a first-class capability (`--tactic Persistence`, `--owasp K01`, `--cis 5.2.1`) because tags are finding metadata, not agent identity. |
| **Plugin Loader** | Discovers and loads domain plugins (built-in and custom/enterprise) at startup or hot-reload; validates each plugin's declared RBAC needs before granting a scoped RoleBinding (see §9). |

---

## 7. Mapping Strategy — Declarative-at-the-Rule, Indexed-at-Startup

**Should every scanner embed tactic_id/technique_id, or should mapping be centralized?**

**Recommendation: hybrid — authored at the rule, centralized for queries.**

Each rule carries its own taxonomy metadata, co-located with its detection logic:

```yaml
id: workload-privileged-container
title: Privileged container
resource_scope: [Pod]
severity: CRITICAL
detection_method: static_config
mitre:
  - tactic: "Privilege Escalation"
    technique_id: "T1610"          # ATT&CK for Containers canonical ID (see below)
    technique_name: "Deploy Container"
  - tactic: "Execution"
    technique_id: "T1610"
owasp: K01
cis: ["5.2.1"]
nsa_cisa: ["Pod Security"]
```

At process/plugin startup, the **MITRE Mapping Engine loads every rule's metadata into an in-memory index** (`tactic → [rule_id]`, `technique_id → [rule_id]`, `owasp → [rule_id]`, `cis → [rule_id]`) so runtime queries ("scan for Persistence") are O(1) lookups, not a scan across every module's source at request time.

**Why not pure centralized mapping** (a single, separate `mitre_mapping.yaml` disconnected from rule code)? Because it drifts: someone edits or adds a rule, forgets to touch the far-away mapping file, and the taxonomy silently goes stale — exactly the "same bug fixed in 9 places" maintainability problem identified in §3 for Option A, just relocated to a mapping file instead of a Deployment.

**Why not pure decentralized mapping with no index** (correct at the rule, but no registry)? Because every tactic/technique query becomes a full scan across every module's rule set at request time — fine at 50 rules, needlessly slow at 500+ once the gaps in §2 and the frameworks in §9 are all added.

**Canonical taxonomy source:** use **MITRE's official ATT&CK for Containers technique IDs** (`T16xx` series) as the machine-readable `technique_id`, not Redguard's free-text names. Redguard's matrix is valuable as a human-readable, example-rich reference (and its tactic names line up closely with ATT&CK for Containers), but it has no stable IDs or version history to build a formal contract on. Store Redguard's names as a `display_alias` for UX/reporting, and validate every rule's `technique_id` against a versioned, vendored copy of the canonical ATT&CK-for-Containers taxonomy in CI — a rule referencing a retired or nonexistent ID should fail the build. This is what makes the taxonomy layer swappable/upgradable (new MITRE revision = update one vendored file + re-run validation) instead of a hardcoded string-matching liability.

---

## 8. CLI / AI Agent Experience

The existing Orchestrator already has an Intent Classifier (§4.1–4.2 of the base doc) for `SCAN/AUDIT/MAP/...`. This redesign adds a second extraction stage that the Orchestrator feeds into the `ScanRequest.selector` from §5.1:

```
User text
   │
   ▼
[1] Coarse intent (existing) → SCAN | AUDIT | MAP | MONITOR | REMEDIATE | ...
   │
   ▼
[2] Scope extraction → cluster / namespace / workload / node / pod / image / helm_release
   │
   ▼
[3] Selector resolution against the Rule Registry's term index:
      - exact/fuzzy match against tactic names   → tactic filter
      - exact/fuzzy match against technique names → technique filter
      - exact/fuzzy match against module/domain names ("RBAC", "secrets", "network") → module filter
      - match against composite/outcome aliases ("Container Escape", "Exposed Secrets",
        "Privileged Container", "Anonymous API Access") → pre-expanded rule_id sets
   │
   ▼
[4] Ambiguous phrasing → LLM reasoning over the same term index (not a separate hand-maintained
    synonym table — generated FROM rule titles/tags so it never drifts from what actually exists)
   │
   ▼
[5] Confirmation step (reuses existing Human-in-the-Loop principle, §3.4/§4.3):
    "This resolves to N checks under Persistence: [hostPath mount, CronJob audit, ...]. Proceed?"
```

Step [5] matters: silently guessing the wrong rule set for "scan everything related to RBAC" is a correctness bug users won't notice until a finding is missing. Showing the resolved rule list before executing costs one confirmation and buys trust — consistent with the tool's existing non-negotiable confirmation-before-action rule for remediation.

**Worked interpretations:**

| User phrase | Resolves to | Selector kind |
|---|---|---|
| "Scan for Persistence" | All rules tagged `tactic: Persistence` | tactic |
| "Scan for Defense Evasion" | All rules tagged `tactic: Defense Evasion` | tactic |
| "Scan only Container Escape" | Composite alias → {privileged-container, hostpath-root, docker-socket, dangerous-caps} | composite alias |
| "Scan only Privileged Pods" | Single rule `workload-privileged-container` | rule_id |
| "Scan everything related to RBAC" | All rules in `module: rbac_identity` | module/domain |
| "Scan all Secret-related issues" | All rules in `module: secrets` ∪ rules tagged `tactic: Credential Access` | module ∪ tactic (union, deduped) |
| "Scan only Kubernetes API exposure" | Composite alias → {anonymous-auth, insecure-port, dashboard-exposed, kubelet-anon-auth} | composite alias |

The union case ("Secret-related issues") is why the selector needs to support combining axes with OR semantics, not just a single filter type.

---

## 9. Extensibility

The registry + declarative-metadata + plugin-loader model (§4, §6, §7) is what makes every item on the user's extensibility list an **additive, metadata-or-plugin-level change**, not a core rewrite:

| Requirement | How it's achieved without touching the engine |
|---|---|
| Add a new MITRE technique | Add the ID to the vendored canonical taxonomy file; tag relevant rules with it. Zero code change to the Detection Engine or Mapping Engine. |
| Add a new scanner (new domain) | Implement the Scanner Plugin interface (declares: rules it owns, resource types it needs, RBAC verbs required); register with the Scanner Registry. Auto-indexed by the Mapping Engine at load. |
| Add custom enterprise rules | Same plugin interface, loaded from a separate path/ConfigMap/PVC. Rules authored as OPA/Rego where possible so they're hot-reloadable policy-as-code, not compiled binary changes. |
| Support CIS Benchmarks | Already the shape of Module ⑦ — each kube-bench check gets a `cis: [...]` tag on the corresponding internal rule, or is ingested as a standalone External Tool Adapter finding if there's no 1:1 internal rule. |
| Support NSA/CISA Hardening Guide | Same pattern — `nsa_cisa: [...]` tag. |
| Support K8s Security Best Practices | Same pattern — a generic `best_practice: [...]` tag namespace for anything that isn't yet a formal framework. |
| Support Falco runtime detections | External Tool Adapter maps Falco rule names → internal rule IDs + tags; new custom Falco rules just need an adapter entry, not a new module. |
| Support Kubescape | External Tool Adapter; Kubescape already outputs MITRE + NSA + CIS control IDs natively, which is a near-direct feed into the Rule Registry's tag schema. |
| Support Trivy | Already Module ⑤'s primary engine; formalizing it as an External Tool Adapter just means its CVE IDs get the same tag treatment as native rules. |
| Support kube-bench | Same as CIS Benchmarks row above. |
| Support custom plugins generally | Versioned plugin interface (in-process for trusted/native rules; sandboxed — WASM or gRPC out-of-process — for third-party/community plugins) + a plugin manifest schema. Each plugin *declares* the K8s verbs/resources it needs, and the Plugin Loader mints a scoped RoleBinding covering only that — a genuine security improvement over today's single blanket `k8s-security-reader` role (§18), since a compromised or buggy plugin is now blast-radius-limited to what it declared, not to everything the whole Scanner Agent can read. |

This is the practical payoff of §4's decision: because the extension points are "register a plugin" and "tag a rule," none of these nine requirements force a change to the Orchestrator, the Evidence Collector, the Detection Engine, or the deployment topology.

---

## 10. Final Recommendation

### 10.1 Architecture name

**Domain-Sharded Execution with a Cross-Cutting Rule/Technique Registry** (Capability Registry + MITRE Mapping Engine hybrid). Macro-architecture from `K8s security tool.md` §3 is unchanged; this redesign is internal to the Scanner Agent, with a smaller analogous change to the Runtime Agent's rule set.

### 10.2 Folder structure

```
k8s-security-tool/
├── agents/
│   ├── orchestrator/
│   │   └── intent/                     # existing classifier + new scope/selector extraction (§8)
│   ├── scanner/
│   │   ├── registry/
│   │   │   ├── scanner_registry.*       # domain plugin catalog
│   │   │   ├── rule_registry.*          # per-rule metadata catalog
│   │   │   ├── mitre_mapping_engine.*   # tactic/technique/alias → rule_id index
│   │   │   └── taxonomy/                # versioned, vendored canonical references
│   │   │       ├── attck_for_containers_v16.json   # canonical MITRE technique IDs
│   │   │       ├── redguard_aliases.yaml           # display names (non-canonical)
│   │   │       ├── owasp_k8s_top10_2025.yaml
│   │   │       ├── cis_benchmark_v1.8.yaml
│   │   │       └── nsa_cisa.yaml
│   │   ├── modules/                     # domain plugins = existing 8, plugin-shaped, + 2 new
│   │   │   ├── cluster_control_plane/
│   │   │   ├── workload_pod_security/
│   │   │   │   ├── rules/
│   │   │   │   │   ├── privileged_container.yaml
│   │   │   │   │   ├── hostpath_root.yaml
│   │   │   │   │   └── ...
│   │   │   │   └── plugin.*
│   │   │   ├── rbac_identity/
│   │   │   ├── network_security/
│   │   │   ├── image_supply_chain/
│   │   │   ├── secrets/
│   │   │   ├── compliance/
│   │   │   ├── attack_surface/
│   │   │   ├── admission_control/       # NEW — closes Persistence/Credential Access gap
│   │   │   └── cloud_iam/               # NEW — closes Initial Access/PrivEsc/Lateral Movement gap
│   │   ├── evidence/                    # Evidence Collector (shared, scope-aware fetch/cache)
│   │   ├── engine/                      # Detection Engine / Rule Executor
│   │   ├── aggregator/                  # Result Aggregator + Risk Scoring
│   │   └── external_adapters/           # Trivy / kube-bench / kubescape / Falco normalizers
│   ├── runtime/                         # same registry pattern applied to Falco/Tetragon rule set
│   └── remediation/
├── mcp-server/                          # unchanged — 5 datasets, now includes taxonomy files as a 6th
├── cli/                                 # k8ssec CLI + shared NL intent-parsing lib
├── reporting/
└── deploy/                              # Helm charts, RBAC manifests (now includes per-plugin scoped roles)
```

### 10.3 Full Architecture Diagram

The recommended architecture has **two orthogonal axes**, and it takes three diagrams to show them properly:

- **Diagram A** — the *runtime pipeline* (top-to-bottom data flow), with each domain shard's internals exposed.
- **Diagram B** — the *orthogonality grid*: domain shards (vertical, the execution boundary) × cross-cutting taxonomy (horizontal, the labels). **This is the single most important picture in the whole redesign** — it's what "Domain-Sharded Execution + Cross-Cutting Rule Registry" literally means.
- **Diagram C** — a *worked resolution trace* showing how one request ("Scan for Persistence") slices through both axes.

Everything outside the dashed Scanner Agent box (Orchestrator, Runtime/Remediation Agents, MCP Server, target cluster) is unchanged from `K8s security tool.md` §3.

---

#### Diagram A — Runtime Pipeline (with domain-shard internals)

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                          👤 USER INTERFACES                                            │
│         ┌─────────┐   ┌─────────┐   ┌──────────┐   ┌──────────┐                        │
│         │   CLI   │   │  Chat   │   │  Web UI  │   │ REST API │                        │
│         │ k8ssec  │   │  (LLM)  │   │          │   │  / CI    │                        │
│         └────┬────┘   └────┬────┘   └────┬─────┘   └────┬─────┘                        │
│              └─────────────┴──────┬──────┴──────────────┘                              │
└─────────────────────────────────┼────────────────────────────────────────────────────┘
                                   ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                        🧠 ORCHESTRATOR AGENT                                           │
│   ┌──────────────────┐   ┌─────────────────────┐   ┌───────────────────────────────┐  │
│   │ [1] Intent       │──▶│ [2] Scope           │──▶│ [3] Selector Resolution        │  │
│   │     Classifier   │   │     Extraction      │   │  (tactic / technique / module  │  │
│   │ SCAN·AUDIT·MAP   │   │  cluster·ns·pod·    │   │   / rule_id / composite alias) │  │
│   │ MONITOR·REMEDIATE│   │  node·image·helm    │   │  ← queries Rule Registry index │  │
│   └──────────────────┘   └─────────────────────┘   └───────────────┬───────────────┘  │
│                              ┌──────────────────────────────────────▼───────────────┐ │
│                              │  ScanRequest { scope, selector[], mode, output }      │ │
│                              │  [5] Confirmation: "resolves to N rules — proceed?"   │ │
│                              └──────────────────────────────────────┬───────────────┘ │
└─────────────────────────────────────────────────────────────────────┼─────────────────┘
                                                                       ▼
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
   🔍 SCANNER AGENT
│                                                                                        │
│  ┌───────────────────────── ① REGISTRY LAYER (built once at startup) ──────────────┐  │
│  │                                                                                  │  │
│  │  ┌──────────────────┐   ┌────────────────────┐   ┌──────────────────────────┐   │  │
│  │  │ Scanner Registry │   │  Rule / Technique  │   │  MITRE Mapping Engine     │   │  │
│  │  │  plugin catalog: │◄─▶│  Registry          │◄─▶│  index (in-memory):       │   │  │
│  │  │  • resource types│   │  per rule:         │   │   tactic     → [rule_id]  │   │  │
│  │  │  • RBAC verbs    │   │   id·title·scope   │   │   technique  → [rule_id]  │   │  │
│  │  │  • plugin version│   │   ·severity·method │   │   owasp/cis  → [rule_id]  │   │  │
│  │  └────────┬─────────┘   │   ·mitre·owasp·cis │   │   alias      → [rule_id]  │   │  │
│  │           │ registers   │   ·nsa·remediation │   │  validates tags against ▼ │   │  │
│  │           │             └─────────▲──────────┘   │  ┌─────────────────────┐  │   │  │
│  │           │                       │ indexes tags │  │ taxonomy/ (vendored,│  │   │  │
│  │  ┌────────▼───────────────────────┴────────────┐ │  │ versioned, CI-check)│  │   │  │
│  │  │        DOMAIN SHARDS (self-describing plugins — the execution boundary) │ │  │  │
│  │  │  ┌───────────────────────┐ ┌───────────────────────┐ ┌────────────────┐│ │  │  │
│  │  │  │ ② Workload/Pod        │ │ ③ RBAC/Identity       │ │ ⑩ Cloud IAM(NEW)││ │  ATT&CK-
│  │  │  │ rules: privileged,    │ │ rules: cluster-admin, │ │ rules: IRSA over-││ │  Containers
│  │  │  │  hostPath-root,       │ │  wildcard-verbs,      │ │  perm, WI scope, ││ │  OWASP·CIS
│  │  │  │  docker-sock, caps... │ │  escalation-path...   │ │  managed-id...   ││ │  NSA·redguard
│  │  │  │ fetches: Pods,        │ │ fetches: Roles,       │ │ fetches: SA      ││ │  _aliases
│  │  │  │  Deployments          │ │  Bindings, ClusterR.  │ │  annotations +   ││ │  └──────────┘
│  │  │  │ RBAC needs: get/list  │ │ RBAC needs: get/list  │ │  cloud IAM API   ││ │           │
│  │  │  │  pods,deployments     │ │  rbac.authz.k8s.io    │ │ RBAC: get sa     ││ │           │
│  │  │  └───────────────────────┘ └───────────────────────┘ └────────────────┘│ │           │
│  │  │  ① Cluster/CtrlPlane  ④ Network  ⑤ Image/Supply  ⑥ Secrets              │ │           │
│  │  │  ⑦ Compliance  ⑧ Attack Surface  ⑨ Admission Control(NEW)  … same shape │ │           │
│  │  │  ◆ each shard declares (rules it owns · evidence it needs · RBAC verbs) │ │           │
│  │  │  ◆ Plugin Loader mints a SCOPED RoleBinding per shard from those verbs  │ │           │
│  │  └────────────────────────────────────────────────────────────────────────┘ │           │
│  └────────────────────────────────────┬─────────────────────────────────────────┘           │
│                    resolve(selector) → │ resolved rule_id set  (may span many shards)         │
│                                        ▼                                                      │
│  ┌───────────────────────── ② EXECUTION LAYER ────────────────────────────────────────────┐ │
│  │  ┌────────────────────┐   fetch ONCE, scope-constrained   ┌───────────────────┐         │ │
│  │  │ Evidence Collector │◄─────────────────────────────────▶│  ☸️ K8s API /      │         │ │
│  │  │ union of shards'   │   only resource types the resolved │  MCP Server /     │         │ │
│  │  │ evidence needs →   │   rules need — deduped across shards│  cloud IAM API    │         │ │
│  │  │ one shared snapshot│                                    └───────────────────┘         │ │
│  │  └─────────┬──────────┘                                                                  │ │
│  │            ▼                                                                              │ │
│  │  ┌────────────────────────────────────────────────────────────────────────────────┐    │ │
│  │  │ Detection Engine (Rule Executor) — worker pool, parallel, batched by resource   │    │ │
│  │  │  ┌───────────────┐  ┌───────────────┐  ┌──────────────────────────────────────┐│    │ │
│  │  │  │ native rules  │  │ OPA/Rego      │  │ External Tool Adapters                ││    │ │
│  │  │  │ (Go/Python)   │  │ policy rules  │  │ Trivy·kube-bench·kubescape·Falco →    ││    │ │
│  │  │  │               │  │ (hot-reload)  │  │ normalized to internal Finding schema ││    │ │
│  │  │  └───────────────┘  └───────────────┘  └──────────────────────────────────────┘│    │ │
│  │  └────────────────────────────────────┬─────────────────────────────────────────────┘    │ │
│  │                                        ▼ raw findings (each already carries its tags)     │ │
│  │  ┌────────────────────┐   ┌───────────────────────┐   ┌──────────────────────────┐       │ │
│  │  │ Result Aggregator  │──▶│ Risk Scoring Engine   │──▶│ Reporting Engine         │       │ │
│  │  │ dedupe same-object │   │ severity×exploit×     │   │ terminal·md·json·pdf·    │       │ │
│  │  │ findings + MERGE   │   │ blast_radius +        │   │ sarif·html               │       │ │
│  │  │ taxonomy tags      │   │ attack-path bonus     │   │ filterable by ANY tag ax.│       │ │
│  │  └────────────────────┘   └───────────────────────┘   └────────────┬─────────────┘       │ │
│  └────────────────────────────────────────────────────────────────────┼────────────────────┘ │
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
                                                                          ▼
                                    ┌─────────────────────────────────────────────────┐
                                    │  🧠 Orchestrator → aggregate → 📊 Report to User │
                                    └─────────────────────────────────────────────────┘

  Legend:  ◄─▶ bidirectional link/query   ──▶ data flow   ◆ per-shard contract
           ┌ ─ ┐ dashed box = the only component this redesign changes (Scanner Agent)
```

---

#### Diagram B — The Orthogonality Grid (domain-sharded × cross-cutting)

This grid **is** the recommended architecture. **Rows are domain shards** — the physical execution boundary, where rules actually live and where the code, the evidence-fetch pattern, and the scoped RBAC belong. **Columns are cross-cutting taxonomy** — MITRE tactics (and, on the right, compliance frameworks) — which are pure *metadata tags* on rules, owned by no single shard.

The whole point: **a rule sits in exactly one shard (its owner) but can carry many tags.** So a request slices the grid two different ways — down a column (tactic) or along a row (domain) — and both resolve through the *same* registry index to a set of `rule_id`s.

```
                              CROSS-CUTTING TAXONOMY  (tags — owned by no shard) ─────────▶
                      MITRE ATT&CK tactics                              compliance frameworks
                ┌────┬────┬────┬────┬────┬────┬────┬────┬────┐        ┌──────┬──────┬──────┐
 DOMAIN SHARDS  │ IA │ EX │ PE │ PV │ DE │ CA │ DI │ LM │ IM │        │ CIS  │ NSA  │OWASP │
 (exec boundary)├────┼────┼────┼────┼────┼────┼────┼────┼────┤        ├──────┼──────┼──────┤
 │  ① Ctrl Plane│ ●  │    │    │    │    │    │ ●  │    │    │        │  ●   │  ●   │  ●   │
 │  ② Workload  │    │ ●  │ ▓  │ ▓  │    │ ●  │    │ ▓  │ ●  │        │  ●   │  ●   │  ●   │
 │  ③ RBAC/Ident│    │    │    │ ●  │ ●  │ ●  │ ●  │ ●  │    │        │  ●   │  ●   │  ●   │
 ▼  ④ Network   │ ●  │    │    │    │    │ ●  │ ●  │ ●  │    │        │  ●   │  ●   │  ●   │
    ⑤ Image/Sup │ ●  │ ●  │    │    │ ●  │    │    │    │    │        │  ●   │      │  ●   │
    ⑥ Secrets   │    │    │    │    │    │ ●  │    │ ●  │    │        │      │  ●   │  ●   │
    ⑦ Compliance│    │    │    │    │    │    │    │    │    │  ◀── owns framework tags mostly
    ⑧ Atk Surf  │ ●  │    │    │ ●  │    │    │ ●  │ ●  │    │        │      │      │  ●   │
    ⑨ Admission │    │ ●  │ ▓  │    │    │ ●  │    │    │    │(NEW)   │  ●   │  ●   │  ●   │
    ⑩ Cloud IAM │ ●  │    │    │ ●  │    │ ●  │    │ ●  │    │(NEW)   │      │  ●   │  ●   │
                └────┴────┴─▲──┴─▲──┴────┴────┴────┴─▲──┴────┘        └──────┴──────┴──────┘
                            │    │                   │
   ● = rule(s) live here    └────┴─── the SAME rule (hostPath mount) is tagged PE + PV + LM
   ▓ = cells selected by the "Scan for Persistence" column-slice (see Diagram C)

  ── Two ways to slice the SAME registry, both returning a rule_id set ─────────────────────

   "Scan for Persistence"   → COLUMN slice  (PE) → rules from shards ② ⑨  (+ hostPath in ②)
   "Scan everything RBAC"   → ROW slice     (③) → every rule the RBAC shard owns
   "Scan only Priv Pods"    → single CELL   (rule_id: workload-privileged-container)
   "CIS audit"              → COLUMN slice  (CIS framework col) → rules across ①②③④⑤⑨…
   "Container Escape"       → composite alias → a hand-picked CELL SET spanning ② (priv,
                              hostPath-root, docker-sock, dangerous-caps)

  Key insight: tactic (column) and domain (row) are ORTHOGONAL. Option A tried to make
  columns the execution boundary → every column that touches Pods re-fetches Pods (⑨× load)
  and the shared "hostPath" rule gets duplicated into 3 columns. Here the rule lives ONCE
  in its shard (row) and the column is just an index lookup over its tags.
```

Tactic legend: IA Initial Access · EX Execution · PE Persistence · PV Privilege Escalation · DE Defense Evasion · CA Credential Access · DI Discovery · LM Lateral Movement · IM Impact. (● placement is illustrative of §2's coverage matrix, not an exhaustive rule census.)

---

#### Diagram C — Worked Resolution Trace: "Scan for Persistence" on the `production` namespace

```
 User: "Scan production for Persistence risks"
   │
   ▼
 Orchestrator →  ScanRequest { scope:{namespace: production},
                               selector:[{tactic: "Persistence"}],
                               output: markdown }
   │
   ▼
 ┌─ REGISTRY ─────────────────────────────────────────────────────────────────┐
 │ MITRE Mapping Engine.resolve(tactic="Persistence")                          │
 │   → index lookup, NOT a code scan                                           │
 │   → rule_ids = {                                                            │
 │        workload-hostpath-writable   (owner shard ②)   ← also tagged PV, LM  │
 │        workload-hostpath-root       (owner shard ②)                         │
 │        cronjob-suspicious           (owner shard ⑨/persistence checks)      │
 │        admission-malicious-webhook  (owner shard ⑨ Admission Control)       │
 │        runtime-backdoor-container   (owner Runtime Agent drift rule)        │
 │     }                                                                       │
 └───────────────────────────────┬─────────────────────────────────────────────┘
                                 │ 5 rules, spanning 2 scanner shards + 1 runtime rule
                                 ▼
 ┌─ EVIDENCE COLLECTOR ───────────────────────────────────────────────────────┐
 │ union of those rules' evidence needs, constrained to ns=production:         │
 │   Pods+volumes (②) · CronJobs (⑨) · Webhook configs (⑨, cluster-scoped)    │
 │   → fetched ONCE, shared snapshot   (no per-tactic re-fetch)                │
 └───────────────────────────────┬─────────────────────────────────────────────┘
                                 ▼
 ┌─ DETECTION ENGINE ─────────────────────────────────────────────────────────┐
 │ 5 rules run in parallel → raw findings, each already carrying MITRE/OWASP/  │
 │ CIS tags authored on the rule                                              │
 └───────────────────────────────┬─────────────────────────────────────────────┘
                                 ▼
 ┌─ AGGREGATE → SCORE → REPORT ───────────────────────────────────────────────┐
 │ dedupe (a pod flagged by both hostPath rules → one finding, merged tags) → │
 │ risk score (hostPath gets attack-path bonus: it ALSO enables PV+LM) →      │
 │ render markdown, filterable by tactic/owasp/cis                            │
 └────────────────────────────────────────────────────────────────────────────┘
```

**Reading all three together — the four things the architecture guarantees:**

1. **Registry Layer is built once at startup** (Diagram A ①): shards register their rules; the Mapping Engine indexes every rule's tags against vendored/versioned framework files. "Scan for Persistence" is therefore an O(1) index lookup (Diagram C), never a code scan.
2. **Domain = execution boundary, tactic = label** (Diagram B): rules live in exactly one shard (row) but carry many cross-cutting tags (columns). This is what kills Option A's duplication + N× API-load problem — `hostPath` exists once, not once per tactic.
3. **One choke point** — `resolve(selector) → rule_id set`. Every request shape (column-slice, row-slice, single cell, composite alias, framework audit) funnels through it. No per-request-type branching below the choke point.
4. **One shared, scope-constrained evidence fetch** feeds a parallel executor and a single dedupe → score → report pipeline where MITRE/OWASP/CIS are *finding metadata*, not agent identity — so the same scan is re-filterable by any axis after the fact without re-running.

### 10.4 Data flow

Same as `K8s security tool.md` §3.3, with one inserted step between "Route to agent(s)" and "Scanner Agent": **Rule Resolution** (registry query against the selector). Everything downstream — MCP Server queries, K8s cluster calls, result aggregation, MITRE/OWASP mapping, severity scoring, confirmation — is unchanged in shape, just now operating on a pre-resolved rule set instead of "run everything in this module."

### 10.5 Scanner execution flow

`resolve selector → registry query → scope-constrained evidence collection → rule execution → dedupe/aggregate → attach taxonomy tags → risk score → report`. This is the single path every scan type in §5.3 goes through — no special-cased code per request style.

### 10.6 MITRE mapping strategy (recap)

Declarative per-rule metadata, indexed centrally at startup, validated in CI against a vendored canonical **ATT&CK for Containers** ID set. Redguard's matrix supplies human-readable names/aliases and educational framing; it is not the machine-readable source of truth because it has no stable IDs.

### 10.7 Plugin strategy (recap)

Every scanner — built-in or third-party — is a plugin that self-declares its rules, resource needs, and RBAC verbs. The Plugin Loader mints scoped RoleBindings per plugin (least-privilege *below* the agent level, not just between agents), and external tools (Trivy, kube-bench, Kubescape, Falco) are integrated as adapters that normalize into the same Finding + tag schema rather than being reimplemented.

### 10.8 Future scalability considerations

- **Rule-level parallelism**, not tactic-agent-level: a worker pool can execute resolved rules in parallel batched by resource type, getting Option A's imagined elasticity without its duplication cost.
- **Multi-cluster becomes a `scope` extension** (`cluster: <id>` added to `ScanRequest.scope`), not a new architectural concept — the registry, evidence collector, and detection engine are already cluster-context-parametrized.
- **Multiple simultaneous taxonomy versions** are possible since taxonomies are vendored, versioned files — a customer pinned to an older MITRE revision or a different framework entirely doesn't require a fork.
- **IO-heavy vs. CPU-cheap rules can be scheduled differently** (e.g., image CVE scans queued against a rate-limited registry client pool, config checks run in-memory) because they're independent units in the registry, not lumped into one tactic-agent's runtime budget.

---

## Summary

- The Redguard/Microsoft Kubernetes Threat Matrix has **9 tactics, 45 techniques, no stable IDs** — treat it as a human-readable reference, not a machine-readable schema. Use MITRE's official **ATT&CK for Containers** IDs for the actual mapping contract. Also fix the existing doc's non-existent "Collection" tactic (§0).
- Current scanner coverage: **49% full, 33% partial, 18% missing** across the 45 techniques. The 8 real gaps cluster around two missing domains — **Cloud IAM/workload identity** and **Admission Controller auditing** — plus five smaller additions (CronJobs, SSH-in-container, kubeconfig exposure, CoreDNS RBAC, source-IP/proxy analysis, CNI anti-spoofing).
- **Neither Option A (one agent per tactic) nor Option B (one monolith) is correct.** Tactics are a many-to-many labeling dimension over techniques, not a natural execution boundary; a monolith without internal structure just reinvents a registry informally.
- **Recommended: keep the existing 8 domain modules as the execution boundary (add 2 new ones), and layer a Rule/Technique Registry + MITRE Mapping Engine on top** so any scan can be sliced by resource scope, tactic, technique, composite outcome label, or domain — all through one resolution path, one shared evidence fetch, and one reporting pipeline.
- This is not a novel pattern — it mirrors OPA/Kyverno, Checkov/Semgrep, Trivy/Kubescape, and is a natural extension of the existing MCP "Compliance Rule Sets" dataset the tool already designed for.

---

<p align="center">
  <strong>K8s Security Tool</strong> — MITRE ATT&CK-Aligned Scanning Architecture Redesign<br/>
  Companion Architecture Document · July 2026
</p>
