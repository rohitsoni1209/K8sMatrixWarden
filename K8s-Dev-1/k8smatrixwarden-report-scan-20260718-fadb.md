---
title: "K8s Security Report"
cluster: "target-cluster"
scan_id: "scan-20260718-fadb"
generated_at: "2026-07-18T02:48:28Z"
tool: "k8smatrixwarden 1.0"
mode: "mock"
scope: "cluster-wide"
selector: "all-rules"
rules_run: 56
risk_score: 9.7
security_score: 3
rating: "Critical"
critical: 16
high: 42
medium: 22
low: 1
tactics_covered: 9
---

# 🛡️ K8s Security Report

**Scan** `scan-20260718-fadb` · **Generated** 2026-07-18T02:48:28Z · **Mode** `mock`

🔴 **Risk 9.7/10 (Critical)** · **Security 3/100** · **81 findings** · **56 rules** · **scope** `cluster-wide`

> Critical risk. The cluster has severe, likely-exploitable exposures requiring emergency remediation.

<a id="top"></a>
## Contents

1. [Executive Summary](#summary)
2. [Kubernetes Threat Matrix](#matrix)
3. [Coverage & Exposure](#coverage)
4. [Findings](#findings) · [⚡ Attack-Path Amplified](#attackpaths)
5. [Prioritized Remediation Plan](#remediation)
6. [Appendix](#appendix)

---

<a id="summary"></a>
## 1. 📊 Executive Summary

**Overall risk:** 🔴 **9.7 / 10 (Critical)**  ·  **Security score:** 3 / 100

```
Risk  [█████████████████████████████░] 9.7/10
```

| Severity | Count | Share |
|:--|--:|:--|
| 🔴 CRITICAL | **16** | `████░░░░░░░░░░░░░░` 20% |
| 🟠 HIGH | **42** | `█████████░░░░░░░░░` 52% |
| 🟡 MEDIUM | **22** | `█████░░░░░░░░░░░░░` 27% |
| 🟢 LOW | **1** | `░░░░░░░░░░░░░░░░░░` 1% |
| **Total** | **81** | |

- **Findings:** 81 actionable (16 critical, 42 high, 22 medium, 1 low)
- **MITRE ATT&CK tactics implicated:** 9 / 9
- **Attack-path amplified findings:** 14 (one issue enabling multiple tactics)
- **Rules evaluated:** 56 across 10 domain(s)

[↑ top](#top)

---

<a id="matrix"></a>
## 2. 🗺️ Kubernetes Threat Matrix

Findings from this scan projected onto the [Kubernetes Threat Matrix](https://kubernetes-threat-matrix.redguard.ch/) (MITRE ATT&CK for Containers). **9 / 9** tactics implicated · **29 / 56** techniques triggered (**53.6%** of the matrix has detection coverage).

| Tactic | Techniques hit | Findings | Worst |
|:--|:--:|--:|:--:|
| **Initial Access** | 4 / 6 | 11 | 🔴 |
| **Execution** | 1 / 6 | 3 | 🔴 |
| **Persistence** | 3 / 5 | 9 | 🔴 |
| **Privilege Escalation** | 5 / 7 | 25 | 🔴 |
| **Defense Evasion** | 3 / 6 | 7 | 🟠 |
| **Credential Access** | 5 / 8 | 16 | 🔴 |
| **Discovery** | 2 / 5 | 8 | 🔴 |
| **Lateral Movement** | 5 / 10 | 14 | 🔴 |
| **Impact** | 1 / 3 | 3 | 🟡 |

#### Technique Detail

##### Initial Access

| State | Technique | ATT&CK | Findings | Resources |
|:--:|:--|:--|--:|:--|
| 🟠 | Using cloud credentials | [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/) | 1 | `CloudIAM/eks-node-role` |
| 🟡 | Compromised images in registry | [`T1525`](https://attack.mitre.org/techniques/T1525/) | 5 | `Pod/cache-redis (staging)`, `Pod/nignx-web (production)`, `Pod/payment-api (production)`, … (+2) |
| 🟦 | Kubeconfig file | [`T1552`](https://attack.mitre.org/techniques/T1552/) | — | — |
| ▫️ | Application vulnerability | — | — | — |
| 🟠 | Exposed sensitive interfaces | [`T1133`](https://attack.mitre.org/techniques/T1133/) | 4 | `Ingress/web-ingress (production)`, `Service/api-nodeport (production)`, `Service/kubernetes-dashboard (kubernetes-dashboard)`, … (+1) |
| 🔴 | Valid Accounts | [`T1078`](https://attack.mitre.org/techniques/T1078/) | 1 | `ControlPlane/apiServer` |

##### Execution

| State | Technique | ATT&CK | Findings | Resources |
|:--:|:--|:--|--:|:--|
| ▫️ | Exec into container | [`T1609`](https://attack.mitre.org/techniques/T1609/) | — | — |
| ▫️ | bash/cmd inside container | [`T1059`](https://attack.mitre.org/techniques/T1059/) | — | — |
| 🔴 | New container | [`T1610`](https://attack.mitre.org/techniques/T1610/) | 3 | `MutatingWebhookConfiguration/evil-webhook`, `Pod/aws-node-64w2k (kube-system)`, `Pod/payment-api (production)` |
| ▫️ | Application exploit (RCE) | — | — | — |
| ▫️ | SSH server running inside container | — | — | — |
| ▫️ | Sidecar injection | — | — | — |

##### Persistence

| State | Technique | ATT&CK | Findings | Resources |
|:--:|:--|:--|--:|:--|
| ▫️ | Backdoor container | [`T1525`](https://attack.mitre.org/techniques/T1525/) | — | — |
| ▫️ | Writable hostPath mount | — | — | — |
| 🟠 | Kubernetes CronJob | [`T1053.003`](https://attack.mitre.org/techniques/T1053/003/) | 1 | `CronJob/backup-cron (production)` |
| 🔴 | Malicious admission controller | [`T1554`](https://attack.mitre.org/techniques/T1554/) | 1 | `MutatingWebhookConfiguration/evil-webhook` |
| 🔴 | Deploy Container | [`T1610`](https://attack.mitre.org/techniques/T1610/) | 7 | `Namespace/production`, `Namespace/staging`, `Pod/aws-node-64w2k (kube-system)`, … (+4) |

##### Privilege Escalation

| State | Technique | ATT&CK | Findings | Resources |
|:--:|:--|:--|--:|:--|
| 🔴 | Privileged container | [`T1610`](https://attack.mitre.org/techniques/T1610/) | 14 | `Pod/aws-node-64w2k (kube-system)`, `Pod/cache-redis (staging)`, `Pod/payment-api (production)`, … (+11) |
| 🔴 | Cluster-admin binding | [`T1078`](https://attack.mitre.org/techniques/T1078/) | 4 | `ClusterRole/binder`, `ClusterRole/super-role`, `ClusterRoleBinding/default-admin`, … (+1) |
| ▫️ | hostPath mount | — | — | — |
| 🟠 | Access cloud resources | [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/) | 2 | `CloudIAM/?`, `CloudIAM/shared-sa (production)` |
| ▫️ | Disable namespacing (host PID/IPC/net) | — | — | — |
| 🟠 | Abuse Elevation Control | [`T1548`](https://attack.mitre.org/techniques/T1548/) | 3 | `Pod/aws-node-64w2k (kube-system)`, `Pod/cache-redis (staging)`, `Pod/payment-api (production)` |
| 🔴 | Escape to Host | [`T1611`](https://attack.mitre.org/techniques/T1611/) | 2 | `Pod/payment-api (production)` |

##### Defense Evasion

| State | Technique | ATT&CK | Findings | Resources |
|:--:|:--|:--|--:|:--|
| 🟠 | Clear container logs | [`T1070`](https://attack.mitre.org/techniques/T1070/) | 2 | `ClusterRole/cm-writer`, `ClusterRole/super-role` |
| ▫️ | Delete K8s events | — | — | — |
| ▫️ | Pod / container name similarity | — | — | — |
| ▫️ | Connect from proxy server | — | — | — |
| 🟠 | Impair Defenses | [`T1562`](https://attack.mitre.org/techniques/T1562/) | 2 | `ControlPlane/apiServer`, `MutatingWebhookConfiguration/evil-webhook` |
| 🟡 | Deploy Container | [`T1610`](https://attack.mitre.org/techniques/T1610/) | 3 | `Pod/aws-node-64w2k (kube-system)`, `Pod/cache-redis (staging)`, `Pod/payment-api (production)` |

##### Credential Access

| State | Technique | ATT&CK | Findings | Resources |
|:--:|:--|:--|--:|:--|
| 🟠 | List K8s secrets | [`T1552.007`](https://attack.mitre.org/techniques/T1552/007/) | 3 | `ClusterRole/secret-reader`, `ClusterRole/super-role`, `Pod/payment-api (production)` |
| ▫️ | Mount service principal | — | — | — |
| ▫️ | Access container service account | — | — | — |
| 🔴 | Application credentials in config files | [`T1552`](https://attack.mitre.org/techniques/T1552/) | 4 | `ConfigMap/app-config (production)`, `ControlPlane/apiServer`, `ControlPlane/etcd`, … (+1) |
| 🟠 | Access managed identity credential | [`T1552.005`](https://attack.mitre.org/techniques/T1552/005/) | 3 | `Namespace/production`, `Namespace/staging`, `ServiceAccount/shared-sa (production)` |
| ▫️ | Malicious admission controller | [`T1554`](https://attack.mitre.org/techniques/T1554/) | — | — |
| 🔴 | Adversary-in-the-Middle | [`T1557`](https://attack.mitre.org/techniques/T1557/) | 1 | `MutatingWebhookConfiguration/evil-webhook` |
| 🟡 | Steal Application Access Token | [`T1528`](https://attack.mitre.org/techniques/T1528/) | 5 | `Pod/aws-node-64w2k (kube-system)`, `Pod/cache-redis (staging)`, `Pod/nignx-web (production)`, … (+2) |

##### Discovery

| State | Technique | ATT&CK | Findings | Resources |
|:--:|:--|:--|--:|:--|
| 🔴 | Access the K8s API server | [`T1613`](https://attack.mitre.org/techniques/T1613/) | 6 | `ControlPlane/etcd`, `ControlPlane/kubelet`, `ControlPlane/version`, … (+3) |
| ▫️ | Access Kubelet API | — | — | — |
| 🟠 | Network mapping | [`T1046`](https://attack.mitre.org/techniques/T1046/) | 2 | `Pod/aws-node-64w2k (kube-system)`, `Pod/payment-api (production)` |
| ▫️ | Access Kubernetes dashboard | — | — | — |
| ▫️ | Instance Metadata API | [`T1552.005`](https://attack.mitre.org/techniques/T1552/005/) | — | — |

##### Lateral Movement

| State | Technique | ATT&CK | Findings | Resources |
|:--:|:--|:--|--:|:--|
| 🟠 | Access cloud resources | [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/) | 3 | `CloudIAM/?`, `CloudIAM/eks-node-role`, `CloudIAM/shared-sa (production)` |
| ▫️ | Container service account | [`T1552.007`](https://attack.mitre.org/techniques/T1552/007/) | — | — |
| ▫️ | Cluster internal networking | — | — | — |
| ▫️ | Applications credentials in config files | [`T1552`](https://attack.mitre.org/techniques/T1552/) | — | — |
| ▫️ | Writable volume mounts on host | — | — | — |
| 🟠 | CoreDNS poisoning | [`T1557`](https://attack.mitre.org/techniques/T1557/) | 2 | `ClusterRole/cm-writer`, `ClusterRole/super-role` |
| ▫️ | ARP poisoning / IP spoofing | — | — | — |
| 🟡 | Valid Accounts | [`T1078`](https://attack.mitre.org/techniques/T1078/) | 1 | `ServiceAccount/shared-sa` |
| 🔴 | Deploy Container | [`T1610`](https://attack.mitre.org/techniques/T1610/) | 6 | `Namespace/production`, `Namespace/staging`, `Pod/aws-node-64w2k (kube-system)`, … (+3) |
| 🟠 | Cloud Instance Metadata API | [`T1552.005`](https://attack.mitre.org/techniques/T1552/005/) | 2 | `Namespace/production`, `Namespace/staging` |

##### Impact

| State | Technique | ATT&CK | Findings | Resources |
|:--:|:--|:--|--:|:--|
| ▫️ | Data destruction | [`T1485`](https://attack.mitre.org/techniques/T1485/) | — | — |
| ▫️ | Resource hijacking | [`T1496`](https://attack.mitre.org/techniques/T1496/) | — | — |
| 🟡 | Denial of service | [`T1499`](https://attack.mitre.org/techniques/T1499/) | 3 | `Pod/aws-node-64w2k (kube-system)`, `Pod/cache-redis (staging)`, `Pod/payment-api (production)` |

> **Legend** — 🔴🟠🟡🟢 hit (painted by worst finding severity) · 🟦 covered (a rule exists, nothing found this scan) · ▫️ gap (no rule yet).

[↑ top](#top)

---

<a id="coverage"></a>
## 3. 🎯 Coverage & Exposure

### By MITRE ATT&CK Tactic

| Tactic | Findings | Distribution |
|:--|--:|:--|
| Privilege Escalation | 25 | `████████████████` |
| Credential Access | 16 | `██████████░░░░░░` |
| Lateral Movement | 14 | `█████████░░░░░░░` |
| Initial Access | 11 | `███████░░░░░░░░░` |
| Persistence | 9 | `██████░░░░░░░░░░` |
| Discovery | 8 | `█████░░░░░░░░░░░` |
| Defense Evasion | 7 | `████░░░░░░░░░░░░` |
| Execution | 3 | `██░░░░░░░░░░░░░░` |
| Impact | 3 | `██░░░░░░░░░░░░░░` |

### By Security Domain (shard)

| Domain | Findings |
|:--|--:|
| `workload_pod_security` | 37 |
| `rbac_identity` | 10 |
| `network_security` | 9 |
| `cluster_control_plane` | 8 |
| `admission_control` | 4 |
| `secrets` | 4 |
| `cloud_iam` | 4 |
| `compliance` | 2 |
| `image_supply_chain` | 2 |
| `attack_surface` | 1 |

### OWASP Kubernetes Top 10 (2025)

| ID | Category | Findings |
|:--|:--|--:|
| `K01` | Insecure Workload Configurations | 30 |
| `K02` | Overly Permissive Authorization | 5 |
| `K03` | Secrets Management Failures | 12 |
| `K04` | Lack of Cluster-Level Policy Enforcement | 5 |
| `K05` | Missing Network Segmentation | 4 |
| `K06` | Overly Exposed Components | 9 |
| `K07` | Misconfigured & Vulnerable Components | 6 |
| `K08` | Cluster-to-Cloud Lateral Movement | 6 |
| `K09` | Broken Authentication | 1 |
| `K10` | Inadequate Logging & Monitoring | 3 |

[↑ top](#top)

---

<a id="attackpaths"></a>
## ⚡ Attack-Path Amplified Findings

These single issues each enable **multiple** MITRE tactics, so an attacker can chain them — they are scored higher and should be fixed first.

| Finding | Resource | Tactics enabled |
|:--|:--|:--|
| **Over-permissive workload identity** | `CloudIAM/shared-sa (production)` | Privilege Escalation → Lateral Movement |
| **Over-permissive workload identity** | `CloudIAM/?` | Privilege Escalation → Lateral Movement |
| **Sensitive hostPath mount** | `Pod/payment-api (production)` | Persistence → Privilege Escalation → Lateral Movement |
| **Suspicious mutating webhook** | `MutatingWebhookConfiguration/evil-webhook` | Persistence → Credential Access |
| **Privileged container** | `Pod/payment-api (production)` | Privilege Escalation → Execution |
| **Privileged container** | `Pod/aws-node-64w2k (kube-system)` | Privilege Escalation → Execution |
| **Metadata API not blocked** | `Namespace/production` | Credential Access → Lateral Movement |
| **Metadata API not blocked** | `Namespace/staging` | Credential Access → Lateral Movement |
| **Broad node instance role** | `CloudIAM/eks-node-role` | Initial Access → Lateral Movement |
| **Host network shared** | `Pod/payment-api (production)` | Privilege Escalation → Discovery |
| **Host network shared** | `Pod/aws-node-64w2k (kube-system)` | Privilege Escalation → Discovery |
| **Writable hostPath mount** | `Pod/payment-api (production)` | Persistence → Lateral Movement |
| **Dangerous capabilities added** | `Pod/payment-api (production)` | Privilege Escalation → Lateral Movement |
| **Dangerous capabilities added** | `Pod/aws-node-64w2k (kube-system)` | Privilege Escalation → Lateral Movement |

---

<a id="findings"></a>
## 4. 🚨 Findings

<a id="sev-critical"></a>
### 🔴 CRITICAL — 16 finding(s)

#### 1. 🔴 etcd client cert auth disabled

`ControlPlane/etcd`

##### Summary

etcd — the cluster's entire state store, including every Secret in plaintext unless encryption-at-rest is separately enabled — does not require client certificate authentication.

> **Detected:** etcd --client-cert-auth is not true

| | |
|:--|:--|
| **Rule ID** | `etcd-client-cert-auth` |
| **Domain** | `cluster_control_plane` |
| **Exploitability** | Remote |
| **Blast radius** | Cluster-wide |
| **Risk score** | 90.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K06 — Overly Exposed Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 2.2 — --client-cert-auth argument set to true | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Discovery | Container and Resource Discovery (`T1613`) | [Reference](https://attack.mitre.org/techniques/T1613/) |

##### 💥 Impact

Anyone who can reach etcd's client port (2379) can read or write the raw cluster datastore directly, completely bypassing the Kubernetes API, RBAC, and admission control. This is a full cluster compromise path.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl -n kube-system get pod -l component=etcd -o jsonpath='{.items[0].spec.containers[0].command}' | tr ',' '\n' | grep client-cert-auth
```

<details><summary>🔎 Evidence</summary>

```json
{
  "spec.etcd.clientCertAuth": false
}
```
</details>

---

#### 2. 🔴 API server anonymous auth enabled

`ControlPlane/apiServer`

##### Summary

The API server accepts unauthenticated requests under the `system:anonymous` identity, so anyone who can reach it can act as a cluster user without presenting any credential.

> **Detected:** API server has --anonymous-auth=true

| | |
|:--|:--|
| **Rule ID** | `apiserver-anonymous-auth` |
| **Domain** | `cluster_control_plane` |
| **Exploitability** | Remote |
| **Blast radius** | Cluster-wide |
| **Risk score** | 90.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K09 — Broken Authentication | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 1.2.1 — --anonymous-auth argument is set to false | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |
| NSA/CISA Kubernetes Hardening Guide | Authentication — Authentication | [Reference](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Initial Access | Valid Accounts (`T1078`) | [Reference](https://attack.mitre.org/techniques/T1078/) |

##### 💥 Impact

An attacker who can route a request to the API server — from inside the network, a misconfigured LoadBalancer, or a leaked endpoint — gets whatever access the `system:unauthenticated` group's bindings grant, often enough to enumerate cluster state or, if that group is ever bound to anything permissive, escalate outright.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This finding's fix is a manual/policy action, not a single safe kubectl command.

Manual steps:

1. Fix insecure API server flags
2. # set --anonymous-auth=false, --insecure-port=0 on the API server

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get --raw /api -v=6 2>&1 | head -20  # an unauthenticated 200 instead of 401/403 confirms anonymous auth is on
```

<details><summary>🔎 Evidence</summary>

```json
{
  "spec.apiServer.anonymousAuth": true
}
```
</details>

---

#### 3. 🔴 Kubelet AlwaysAllow authz

`ControlPlane/kubelet`

##### Summary

The kubelet's authorization mode is `AlwaysAllow`, so even an authenticated caller's identity is never actually checked against RBAC before the kubelet honors the request.

> **Detected:** kubelet --authorization-mode=AlwaysAllow

| | |
|:--|:--|
| **Rule ID** | `kubelet-authz-always-allow` |
| **Domain** | `cluster_control_plane` |
| **Exploitability** | Remote |
| **Blast radius** | Cluster-wide |
| **Risk score** | 90.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K06 — Overly Exposed Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 4.2.2 — --authorization-mode not set to AlwaysAllow | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Discovery | Container and Resource Discovery (`T1613`) | [Reference](https://attack.mitre.org/techniques/T1613/) |

##### 💥 Impact

Any credential that can merely authenticate to the kubelet — not necessarily one with any RBAC grant — gets full kubelet API access: pod exec, log retrieval, and container lifecycle control on that node.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get --raw /api/v1/nodes/<node>/proxy/configz 2>/dev/null | jq '.kubeletconfig.authorization.mode'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "spec.kubelet.authorizationMode": "AlwaysAllow"
}
```
</details>

---

#### 4. 🔴 Kubelet anonymous auth enabled

`ControlPlane/kubelet`

##### Summary

A node's kubelet API accepts unauthenticated requests.

> **Detected:** kubelet --anonymous-auth=true

| | |
|:--|:--|
| **Rule ID** | `kubelet-anonymous-auth` |
| **Domain** | `cluster_control_plane` |
| **Exploitability** | Remote |
| **Blast radius** | Cluster-wide |
| **Risk score** | 90.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K06 — Overly Exposed Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 4.2.1 — --anonymous-auth argument set to false | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Discovery | Container and Resource Discovery (`T1613`) | [Reference](https://attack.mitre.org/techniques/T1613/) |

##### 💥 Impact

The kubelet API can list every pod's spec (including env-var secrets), exec into containers, and fetch logs. Anonymous access to it is a well-known, actively exploited path to full node and workload compromise.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
curl -sk https://<node-ip>:10250/pods  # a 200 with pod data instead of 401 confirms anonymous kubelet access
```

<details><summary>🔎 Evidence</summary>

```json
{
  "spec.kubelet.anonymousAuth": true
}
```
</details>

---

#### 5. 🔴 Kubernetes dashboard exposed

`Service/kubernetes-dashboard (kubernetes-dashboard)`

##### Summary

The Kubernetes Dashboard is reachable from outside the cluster.

> **Detected:** Kubernetes dashboard is externally exposed

| | |
|:--|:--|
| **Rule ID** | `net-dashboard-exposed` |
| **Domain** | `network_security` |
| **Exploitability** | Remote |
| **Blast radius** | Cluster-wide |
| **Risk score** | 90.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K06 — Overly Exposed Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Discovery | Container and Resource Discovery (`T1613`) | [Reference](https://attack.mitre.org/techniques/T1613/) |

##### 💥 Impact

The Dashboard is a well-documented, frequently targeted attack surface — multiple real-world breaches (including a widely reported Tesla cryptomining incident) started from an internet-reachable, under-authenticated Dashboard used to schedule an attacker-controlled pod.

##### 🛠️ Remediation

**Restrict or remove the dashboard**

```bash
kubectl -n kubernetes-dashboard patch svc kubernetes-dashboard -p '{"spec":{"type":"ClusterIP"}}'
```

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl -n kubernetes-dashboard get svc kubernetes-dashboard -o jsonpath='{.spec.type} {.status.loadBalancer.ingress}'
```

---

#### 6. 🔴 cluster-admin on default SA

`ClusterRoleBinding/default-admin`

##### Summary

The `cluster-admin` ClusterRole is bound to a namespace's `default` ServiceAccount — the identity every pod in that namespace gets automatically unless it explicitly requests a different one.

> **Detected:** cluster-admin bound to default ServiceAccount (kube-system/default)

| | |
|:--|:--|
| **Rule ID** | `rbac-cluster-admin-default-sa` |
| **Domain** | `rbac_identity` |
| **Exploitability** | Adjacent |
| **Blast radius** | Cluster-wide |
| **Risk score** | 60.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K02 — Overly Permissive Authorization | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.1.1 — cluster-admin role only used where required | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Valid Accounts (`T1078`) | [Reference](https://attack.mitre.org/techniques/T1078/) |

##### 💥 Impact

Every pod in that namespace, whether or not it was ever intended to have cluster-wide access, can act as `cluster-admin` simply by using its auto-mounted token — a single compromised pod anywhere in the namespace becomes full, unrestricted cluster compromise.

##### 🛠️ Remediation

**Remove cluster-admin from default SA**

```bash
kubectl delete clusterrolebinding default-admin
```

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get clusterrolebinding -o json | jq '.items[] | select(.roleRef.name=="cluster-admin") | select(.subjects[]?.name=="default")'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "subject": {
    "kind": "ServiceAccount",
    "name": "default",
    "namespace": "kube-system"
  }
}
```
</details>

---

#### 7. 🔴 Sensitive hostPath mount ⚡ Attack-Path Amplified

`Pod/payment-api (production)`

##### Summary

The pod mounts a sensitive host path (`/`, `/etc`, `/var/run`, or `/etc/kubernetes/manifests`) from the node's filesystem.

> **Detected:** mounts sensitive hostPath '/' — full/host-critical filesystem access

| | |
|:--|:--|
| **Rule ID** | `workload-hostpath-root` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 45.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.12 — Minimize the admission of HostPath volumes | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Persistence | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |
| Privilege Escalation | Escape to Host (`T1611`) | [Reference](https://attack.mitre.org/techniques/T1611/) |
| Lateral Movement | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Mounting `/etc/kubernetes/manifests` lets an attacker drop a new static pod manifest that the kubelet will run automatically, surviving pod restarts and even node reboots — a durable, host-level persistence and privilege-escalation mechanism. A root mount grants effectively unrestricted host filesystem access.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This finding's fix is a manual/policy action, not a single safe kubectl command.

Manual steps:

1. Remove hostPath / docker.sock mount
2. # manual review required: remove the hostPath volume + mount

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.volumes[*].hostPath.path}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "volume": "hostroot",
  "path": "/"
}
```
</details>

---

#### 8. 🔴 Suspicious mutating webhook ⚡ Attack-Path Amplified

`MutatingWebhookConfiguration/evil-webhook`

##### Summary

A Mutating or Validating webhook is configured with a suspiciously broad scope and/or an external endpoint outside the cluster.

> **Detected:** mutating webhook 'inject.evil.io' targets an external URL (https://attacker.example.com/mutate) with cluster-wide scope

| | |
|:--|:--|
| **Rule ID** | `admission-malicious-webhook` |
| **Domain** | `admission_control` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 37.5 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K04 — Lack of Cluster-Level Policy Enforcement | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Persistence | Compromise Host Software Binary (`T1554`) | [Reference](https://attack.mitre.org/techniques/T1554/) |
| Credential Access | Adversary-in-the-Middle (`T1557`) | [Reference](https://attack.mitre.org/techniques/T1557/) |

##### 💥 Impact

A mutating webhook can silently rewrite every matching object the API server processes — inject a sidecar, add a hostPath mount, alter securityContext — on every create/update, cluster-wide, invisibly to whoever submitted the original manifest. It's one of the stealthiest persistence mechanisms in Kubernetes.

##### 🛠️ Remediation

**Remove a malicious admission webhook**

```bash
kubectl delete mutatingwebhookconfiguration evil-webhook
```

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations -o json | jq '.items[] | {name: .metadata.name, webhooks: [.webhooks[] | {name, clientConfig, failurePolicy}]}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "url": "https://attacker.example.com/mutate"
}
```
</details>

---

#### 9. 🔴 Privileged container ⚡ Attack-Path Amplified

`Pod/payment-api (production)`

##### Summary

A container runs with `securityContext.privileged: true`, giving it essentially the same access to the host as a root process running directly on the node.

> **Detected:** container 'app' runs privileged (full host access)

| | |
|:--|:--|
| **Rule ID** | `workload-privileged-container` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 37.5 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.2 — Minimize the admission of privileged containers | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |
| NSA/CISA Kubernetes Hardening Guide | Pod Security — Pod Security | [Reference](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |
| Execution | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

A privileged container can load kernel modules, access every device on the host, and trivially break out to the underlying node — from there, an attacker controls every other workload scheduled on that node and can pivot across the cluster.

##### 🛠️ Remediation

**Harden pod securityContext (runAsNonRoot + seccompProfile)**

```bash
kubectl patch deployment payment-api -n production -p '{"spec": {"template": {"spec": {"securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}}}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo deployment/payment-api -n production
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tutorials/security/seccomp/) · [Kubernetes docs](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.containers[*].securityContext.privileged}'
```

_Post-remediation check:_

```bash
kubectl get deployment payment-api -n production -o yaml
kubectl rollout status deployment/payment-api -n production
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "app",
  "privileged": true
}
```
</details>

---

#### 10. 🔴 Privileged container ⚡ Attack-Path Amplified

`Pod/aws-node-64w2k (kube-system)`

##### Summary

A container runs with `securityContext.privileged: true`, giving it essentially the same access to the host as a root process running directly on the node.

> **Detected:** container 'aws-node' runs privileged (full host access)

| | |
|:--|:--|
| **Rule ID** | `workload-privileged-container` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `DaemonSet/aws-node (kube-system)` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 37.5 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.2 — Minimize the admission of privileged containers | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |
| NSA/CISA Kubernetes Hardening Guide | Pod Security — Pod Security | [Reference](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |
| Execution | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

A privileged container can load kernel modules, access every device on the host, and trivially break out to the underlying node — from there, an attacker controls every other workload scheduled on that node and can pivot across the cluster.

##### 🛠️ Remediation

**Harden pod securityContext (runAsNonRoot + seccompProfile)**

```bash
kubectl patch daemonset aws-node -n kube-system -p '{"spec": {"template": {"spec": {"securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}}}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo daemonset/aws-node -n kube-system
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tutorials/security/seccomp/) · [Kubernetes docs](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod aws-node-64w2k -n kube-system -o jsonpath='{.spec.containers[*].securityContext.privileged}'
```

_Post-remediation check:_

```bash
kubectl get daemonset aws-node -n kube-system -o yaml
kubectl rollout status daemonset/aws-node -n kube-system
```

<details><summary>⚠️ Warnings</summary>

- This appears to be a Kubernetes/EKS managed component. Verify vendor documentation before changing its security context because the recommended hardening may break cluster functionality.

</details>

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "aws-node",
  "privileged": true
}
```
</details>

---

#### 11. 🔴 bind/escalate/impersonate verbs

`ClusterRole/binder`

##### Summary

A Role/ClusterRole grants the `bind`, `escalate`, or `impersonate` verb — RBAC's own built-in privilege-escalation primitives.

> **Detected:** role can bind, escalate — privilege-escalation primitive

| | |
|:--|:--|
| **Rule ID** | `rbac-bind-escalate-verbs` |
| **Domain** | `rbac_identity` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 30.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K02 — Overly Permissive Authorization | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.1.8 — Limit use of Bind, Impersonate and Escalate permissions | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Valid Accounts (`T1078`) | [Reference](https://attack.mitre.org/techniques/T1078/) |

##### 💥 Impact

`escalate` lets the holder grant themselves permissions they don't already have; `bind` lets them attach any Role/ClusterRole (including `cluster-admin`) to a subject; `impersonate` lets them act as any other user or ServiceAccount. Any of the three is a direct, intended-by-Kubernetes escalation path, not a side effect — holding one of these verbs on a broad scope is equivalent to holding whatever it can grant.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get clusterrole,role -A -o json | jq '.items[] | select(.rules[]?.verbs[]? | IN("bind","escalate","impersonate")) | .metadata.name'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "verbs": [
    "bind",
    "escalate"
  ]
}
```
</details>

---

#### 12. 🔴 Wildcard verbs in role

`ClusterRole/super-role`

##### Summary

A Role/ClusterRole grants `verbs: ["*"]` — every possible action on the matched resources, present and future.

> **Detected:** role grants wildcard verbs (verbs: ['*'])

| | |
|:--|:--|
| **Rule ID** | `rbac-wildcard-verbs` |
| **Domain** | `rbac_identity` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 30.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K02 — Overly Permissive Authorization | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.1.3 — Minimize wildcard use in Roles and ClusterRoles | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Valid Accounts (`T1078`) | [Reference](https://attack.mitre.org/techniques/T1078/) |

##### 💥 Impact

A wildcard verb silently grants any verb the Kubernetes API ever adds in a future version too, not just today's. Combined with almost any resource grant, it typically includes `create`/`update`/`patch`/`delete` — full read-write control, not the narrow access the role was likely intended to provide.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This finding's fix is a manual/policy action, not a single safe kubectl command.

Manual steps:

1. Replace wildcard role with least-privilege
2. # generate a scoped Role from observed `auth can-i` usage; apply it

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get clusterrole,role -A -o json | jq '.items[] | select(.rules[]?.verbs[]?=="*") | .metadata.name'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "rule": {
    "apiGroups": [
      "*"
    ],
    "resources": [
      "*"
    ],
    "verbs": [
      "*"
    ]
  }
}
```
</details>

---

#### 13. 🔴 Wildcard resources in role

`ClusterRole/super-role`

##### Summary

A Role/ClusterRole grants `resources: ["*"]` — access to every resource type in every API group the rule's apiGroups cover.

> **Detected:** role grants wildcard resources (resources: ['*'])

| | |
|:--|:--|
| **Rule ID** | `rbac-wildcard-resources` |
| **Domain** | `rbac_identity` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 30.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K02 — Overly Permissive Authorization | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.1.3 — Minimize wildcard use in Roles and ClusterRoles | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Valid Accounts (`T1078`) | [Reference](https://attack.mitre.org/techniques/T1078/) |

##### 💥 Impact

This silently includes `secrets`, `pods/exec`, and RBAC objects themselves unless verbs are also tightly scoped — a wildcard resource grant is one of the most common accidental routes to a full privilege-escalation chain.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This finding's fix is a manual/policy action, not a single safe kubectl command.

Manual steps:

1. Replace wildcard role with least-privilege
2. # generate a scoped Role from observed `auth can-i` usage; apply it

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get clusterrole,role -A -o json | jq '.items[] | select(.rules[]?.resources[]?=="*") | .metadata.name'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "rule": {
    "apiGroups": [
      "*"
    ],
    "resources": [
      "*"
    ],
    "verbs": [
      "*"
    ]
  }
}
```
</details>

---

#### 14. 🔴 etcd not encrypted

`ControlPlane/etcd`

##### Summary

Secrets are stored in etcd without encryption at rest — the same underlying gap as `etcd-encryption-missing`, surfaced from the Secrets domain's perspective.

> **Detected:** etcd encryption at rest is not enabled — Secrets stored in plaintext

| | |
|:--|:--|
| **Rule ID** | `sec-etcd-not-encrypted` |
| **Domain** | `secrets` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 30.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K03 — Secrets Management Failures | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 1.2.28 — --encryption-provider-config argument set | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Unsecured Credentials (`T1552`) | [Reference](https://attack.mitre.org/techniques/T1552/) |

##### 💥 Impact

Every Secret in the cluster is recoverable in plaintext by anyone with read access to etcd's storage or backups, with no additional key or credential required.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This finding's fix is a manual/policy action, not a single safe kubectl command.

Manual steps:

1. Enable etcd encryption at rest
2. # configure --encryption-provider-config on the API server

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl -n kube-system get pod -l component=kube-apiserver -o jsonpath='{.spec.containers[0].command}' | tr ',' '\n' | grep encryption-provider-config
```

---

#### 15. 🔴 Docker socket mounted

`Pod/payment-api (production)`

##### Summary

The container mounts the Docker (or containerd) socket from the host, handing it direct control over the node's container runtime.

> **Detected:** mounts the Docker socket (/var/run/docker.sock) — container escape

| | |
|:--|:--|
| **Rule ID** | `workload-docker-socket` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 30.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| NSA/CISA Kubernetes Hardening Guide | Pod Security — Pod Security | [Reference](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Escape to Host (`T1611`) | [Reference](https://attack.mitre.org/techniques/T1611/) |

##### 💥 Impact

Access to the runtime socket is equivalent to root on the node: an attacker can launch a new privileged container, bind-mount the host filesystem into it, and read/write anything on the node — a textbook, one-command container escape.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This finding's fix is a manual/policy action, not a single safe kubectl command.

Manual steps:

1. Remove hostPath / docker.sock mount
2. # manual review required: remove the hostPath volume + mount

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.volumes[*].hostPath.path}' | grep -o '[^ ]*docker.sock'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "volume": "dockersock",
  "path": "/var/run/docker.sock"
}
```
</details>

---

#### 16. 🔴 Host PID namespace shared

`Pod/payment-api (production)`

##### Summary

The pod shares the host's PID namespace (`hostPID: true`), so its containers can see and interact with every process running on the node.

> **Detected:** workload shares host hostPID namespace

| | |
|:--|:--|
| **Rule ID** | `workload-host-pid` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Namespace |
| **Risk score** | 20.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.3 — Minimize admission of containers sharing host PID namespace | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

A container in this pod can see other containers' process environments (often containing secrets), send signals to host processes, and — combined with `/proc/<pid>/root`, reachable in this namespace — read another container's filesystem, a well-documented container-escape primitive.

##### 🛠️ Remediation

**Disable host PID namespace sharing**

```bash
kubectl patch deployment payment-api -n production -p '{"spec": {"template": {"spec": {"hostPID": false}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      hostPID: false
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo deployment/payment-api -n production
```
</details>

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.hostPID}'
```

_Post-remediation check:_

```bash
kubectl get deployment payment-api -n production -o yaml
kubectl rollout status deployment/payment-api -n production
```

<details><summary>🔎 Evidence</summary>

```json
{
  "hostPID": true
}
```
</details>

---

<a id="sev-high"></a>
### 🟠 HIGH — 42 finding(s)

#### 1. 🟠 Kubelet read-only port open

`ControlPlane/kubelet`

##### Summary

The kubelet's deprecated read-only port 10255 is open — an unauthenticated HTTP endpoint exposing pod and node state.

> **Detected:** kubelet read-only port 10255 is open

| | |
|:--|:--|
| **Rule ID** | `kubelet-read-only-port` |
| **Domain** | `cluster_control_plane` |
| **Exploitability** | Remote |
| **Blast radius** | Cluster-wide |
| **Risk score** | 63.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K06 — Overly Exposed Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 4.2.4 — --read-only-port argument set to 0 | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Discovery | Container and Resource Discovery (`T1613`) | [Reference](https://attack.mitre.org/techniques/T1613/) |

##### 💥 Impact

Anyone with network access to the node can enumerate every pod's spec, resource usage, and metadata on it with zero authentication — a reconnaissance foothold for planning further attacks.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
curl -s http://<node-ip>:10255/pods | head -5
```

<details><summary>🔎 Evidence</summary>

```json
{
  "spec.kubelet.readOnlyPort": 10255
}
```
</details>

---

#### 2. 🟠 API audit logging disabled

`ControlPlane/apiServer`

##### Summary

The API server has no `--audit-log-path` configured, so no record of who did what against the cluster is being kept.

> **Detected:** API server has no --audit-log-path (audit logging off)

| | |
|:--|:--|
| **Rule ID** | `apiserver-audit-logging` |
| **Domain** | `cluster_control_plane` |
| **Exploitability** | Remote |
| **Blast radius** | Cluster-wide |
| **Risk score** | 63.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K10 — Inadequate Logging & Monitoring | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 1.2.17 — --audit-log-path argument is set | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |
| NSA/CISA Kubernetes Hardening Guide | Audit Logging — Audit Logging | [Reference](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Defense Evasion | Impair Defenses (`T1562`) | [Reference](https://attack.mitre.org/techniques/T1562/) |

##### 💥 Impact

Without an audit trail, a compromise, a privilege-escalation attempt, or even ordinary operator error is unrecoverable after the fact — there is nothing to investigate, correlate, or use as evidence.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This finding's fix is a manual/policy action, not a single safe kubectl command.

Manual steps:

1. Enable API audit logging
2. # set --audit-log-path and --audit-policy-file on the API server

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl -n kube-system get pod -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' | tr ',' '\n' | grep audit-log-path
```

<details><summary>🔎 Evidence</summary>

```json
{
  "spec.apiServer.auditLogPath": ""
}
```
</details>

---

#### 3. 🟠 etcd encryption not configured

`ControlPlane/apiServer`

##### Summary

No `--encryption-provider-config` is set on the API server, so Secrets are stored in etcd as plaintext, not encrypted at rest.

> **Detected:** no --encryption-provider-config (secrets stored plaintext)

| | |
|:--|:--|
| **Rule ID** | `etcd-encryption-missing` |
| **Domain** | `cluster_control_plane` |
| **Exploitability** | Remote |
| **Blast radius** | Cluster-wide |
| **Risk score** | 63.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K03 — Secrets Management Failures | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 1.2.28 — --encryption-provider-config argument set | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Unsecured Credentials (`T1552`) | [Reference](https://attack.mitre.org/techniques/T1552/) |

##### 💥 Impact

Anyone with read access to etcd's data directory or its backups — a stolen disk snapshot, an exposed backup bucket, a compromised etcd node — can read every Secret in the cluster directly, with no additional key required.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This finding's fix is a manual/policy action, not a single safe kubectl command.

Manual steps:

1. Enable etcd encryption at rest
2. # configure --encryption-provider-config on the API server

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl -n kube-system get pod -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' | tr ',' '\n' | grep encryption-provider-config
```

<details><summary>🔎 Evidence</summary>

```json
{
  "spec.apiServer.encryptionProvider": ""
}
```
</details>

---

#### 4. 🟠 Deprecated/EOL Kubernetes version

`ControlPlane/version`

##### Summary

The cluster is running an end-of-life or otherwise outdated Kubernetes version with known, patched CVEs in supported releases.

> **Detected:** cluster runs an EOL/CVE-affected version (v1.24.0)

| | |
|:--|:--|
| **Rule ID** | `deprecated-k8s-version` |
| **Domain** | `cluster_control_plane` |
| **Exploitability** | Remote |
| **Blast radius** | Cluster-wide |
| **Risk score** | 63.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K07 — Misconfigured & Vulnerable Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Discovery | Container and Resource Discovery (`T1613`) | [Reference](https://attack.mitre.org/techniques/T1613/) |

##### 💥 Impact

Every disclosed CVE affecting that version — including any with public exploit code — remains exploitable indefinitely, since no further security patches are being backported to an EOL release.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl version --short 2>/dev/null || kubectl version
```

<details><summary>🔎 Evidence</summary>

```json
{
  "spec.version": "v1.24.0"
}
```
</details>

---

#### 5. 🟠 Over-permissive workload identity ⚡ Attack-Path Amplified

`CloudIAM/shared-sa (production)`

##### Summary

The AWS IAM role (IRSA) attached to this ServiceAccount grants permissions well beyond what the workload actually uses.

> **Detected:** workload identity for SA 'shared-sa' is over-permissive (binding: arn:aws:iam::111:role/shared)

| | |
|:--|:--|
| **Rule ID** | `iam-overpermissive` |
| **Domain** | `cloud_iam` |
| **Exploitability** | Adjacent |
| **Blast radius** | Cluster-wide |
| **Risk score** | 52.5 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K08 — Cluster-to-Cloud Lateral Movement | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Cloud Accounts (`T1078.004`) | [Reference](https://attack.mitre.org/techniques/T1078/004/) |
| Lateral Movement | Cloud Accounts (`T1078.004`) | [Reference](https://attack.mitre.org/techniques/T1078/004/) |

##### 💥 Impact

Any pod using this ServiceAccount inherits the role's full permission set for the lifetime of its token — a container compromise translates directly into whatever that over-broad IAM policy allows in the cloud account, not just what the application itself needed.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This finding's fix is a manual/policy action, not a single safe kubectl command.

Manual steps:

1. Scope cloud workload identity
2. # tighten the IAM policy attached to the workload identity (cloud-side)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get sa shared-sa -n production -o jsonpath='{.metadata.annotations.eks\.amazonaws\.com/role-arn}'  # then: aws iam list-attached-role-policies --role-name <role>
```

<details><summary>🔎 Evidence</summary>

```json
{
  "binding": {
    "kind": "WorkloadIdentity",
    "serviceAccount": "shared-sa",
    "namespace": "production",
    "role": "arn:aws:iam::111:role/shared",
    "actions": [
      "s3:*"
    ]
  }
}
```
</details>

---

#### 6. 🟠 Over-permissive workload identity ⚡ Attack-Path Amplified

`CloudIAM/?`

##### Summary

The AWS IAM role (IRSA) attached to this ServiceAccount grants permissions well beyond what the workload actually uses.

> **Detected:** workload identity for SA 'None' is over-permissive (binding: eks-node-role)

| | |
|:--|:--|
| **Rule ID** | `iam-overpermissive` |
| **Domain** | `cloud_iam` |
| **Exploitability** | Adjacent |
| **Blast radius** | Cluster-wide |
| **Risk score** | 52.5 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K08 — Cluster-to-Cloud Lateral Movement | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Cloud Accounts (`T1078.004`) | [Reference](https://attack.mitre.org/techniques/T1078/004/) |
| Lateral Movement | Cloud Accounts (`T1078.004`) | [Reference](https://attack.mitre.org/techniques/T1078/004/) |

##### 💥 Impact

Any pod using this ServiceAccount inherits the role's full permission set for the lifetime of its token — a container compromise translates directly into whatever that over-broad IAM policy allows in the cloud account, not just what the application itself needed.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This finding's fix is a manual/policy action, not a single safe kubectl command.

Manual steps:

1. Scope cloud workload identity
2. # tighten the IAM policy attached to the workload identity (cloud-side)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get sa ? -n default -o jsonpath='{.metadata.annotations.eks\.amazonaws\.com/role-arn}'  # then: aws iam list-attached-role-policies --role-name <role>
```

<details><summary>🔎 Evidence</summary>

```json
{
  "binding": {
    "kind": "NodeInstanceRole",
    "role": "eks-node-role",
    "actions": [
      "AdministratorAccess"
    ]
  }
}
```
</details>

---

#### 7. 🟠 LoadBalancer without source range

`Service/lb-public (production)`

##### Summary

A public-facing LoadBalancer Service has no `loadBalancerSourceRanges` set, so it accepts traffic from any source IP.

> **Detected:** LoadBalancer has no loadBalancerSourceRanges (open to the internet)

| | |
|:--|:--|
| **Rule ID** | `net-lb-no-source-range` |
| **Domain** | `network_security` |
| **Exploitability** | Remote |
| **Blast radius** | Namespace |
| **Risk score** | 42.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K06 — Overly Exposed Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Initial Access | External Remote Services (`T1133`) | [Reference](https://attack.mitre.org/techniques/T1133/) |

##### 💥 Impact

Without a source-IP allowlist, the service is reachable by anyone on the internet, not just intended clients — removing a cheap, effective layer of network-level access control for a service that may not need to be globally reachable at all.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get svc lb-public -n production -o jsonpath='{.spec.type} {.spec.loadBalancerSourceRanges}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "type": "LoadBalancer"
}
```
</details>

---

#### 8. 🟠 Metadata API not blocked ⚡ Attack-Path Amplified

`Namespace/production`

##### Summary

Pods in this environment can reach the cloud provider's instance metadata endpoint (`169.254.169.254`) with no egress restriction.

> **Detected:** namespace 'production' has no egress policy blocking the cloud metadata API (169.254.169.254)

| | |
|:--|:--|
| **Rule ID** | `net-metadata-api-open` |
| **Domain** | `network_security` |
| **Exploitability** | Adjacent |
| **Blast radius** | Namespace |
| **Risk score** | 35.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K08 — Cluster-to-Cloud Lateral Movement | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Cloud Instance Metadata API (`T1552.005`) | [Reference](https://attack.mitre.org/techniques/T1552/005/) |
| Lateral Movement | Cloud Instance Metadata API (`T1552.005`) | [Reference](https://attack.mitre.org/techniques/T1552/005/) |

##### 💥 Impact

The metadata API commonly serves the node's IAM role credentials. An attacker who achieves code execution in any pod on this node can request those credentials directly over HTTP and pivot from a container compromise straight into the cloud account — one of the most common real-world Kubernetes-to-cloud escalation chains (see the Capital One breach).

##### 🛠️ Remediation

**Block cloud metadata API egress**

```bash
kubectl apply -n default -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: block-metadata-api, namespace: default}
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
  - to: [{ipBlock: {cidr: 0.0.0.0/0, except: [169.254.169.254/32]}}]
EOF
```

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl exec -n default production -- curl -s -m 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null
```

<details><summary>🔎 Evidence</summary>

```json
{
  "namespace": "production"
}
```
</details>

---

#### 9. 🟠 Metadata API not blocked ⚡ Attack-Path Amplified

`Namespace/staging`

##### Summary

Pods in this environment can reach the cloud provider's instance metadata endpoint (`169.254.169.254`) with no egress restriction.

> **Detected:** namespace 'staging' has no egress policy blocking the cloud metadata API (169.254.169.254)

| | |
|:--|:--|
| **Rule ID** | `net-metadata-api-open` |
| **Domain** | `network_security` |
| **Exploitability** | Adjacent |
| **Blast radius** | Namespace |
| **Risk score** | 35.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K08 — Cluster-to-Cloud Lateral Movement | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Cloud Instance Metadata API (`T1552.005`) | [Reference](https://attack.mitre.org/techniques/T1552/005/) |
| Lateral Movement | Cloud Instance Metadata API (`T1552.005`) | [Reference](https://attack.mitre.org/techniques/T1552/005/) |

##### 💥 Impact

The metadata API commonly serves the node's IAM role credentials. An attacker who achieves code execution in any pod on this node can request those credentials directly over HTTP and pivot from a container compromise straight into the cloud account — one of the most common real-world Kubernetes-to-cloud escalation chains (see the Capital One breach).

##### 🛠️ Remediation

**Block cloud metadata API egress**

```bash
kubectl apply -n default -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: block-metadata-api, namespace: default}
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
  - to: [{ipBlock: {cidr: 0.0.0.0/0, except: [169.254.169.254/32]}}]
EOF
```

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl exec -n default staging -- curl -s -m 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null
```

<details><summary>🔎 Evidence</summary>

```json
{
  "namespace": "staging"
}
```
</details>

---

#### 10. 🟠 Broad node instance role ⚡ Attack-Path Amplified

`CloudIAM/eks-node-role`

##### Summary

The EC2/node instance role is broader than any pod actually scheduled on that node needs.

> **Detected:** node instance role is broader than the pods running on it require

| | |
|:--|:--|
| **Rule ID** | `iam-node-role-broad` |
| **Domain** | `cloud_iam` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 26.25 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K08 — Cluster-to-Cloud Lateral Movement | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Initial Access | Cloud Accounts (`T1078.004`) | [Reference](https://attack.mitre.org/techniques/T1078/004/) |
| Lateral Movement | Cloud Accounts (`T1078.004`) | [Reference](https://attack.mitre.org/techniques/T1078/004/) |

##### 💥 Impact

Before IRSA/Workload Identity was adopted (or for pods that don't use it), every pod on the node can reach the node's own instance role via the metadata API — an overly broad node role means every workload on that node, trusted or not, effectively holds that role's full permissions.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
aws ec2 describe-instances --instance-ids <id> --query 'Reservations[].Instances[].IamInstanceProfile'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "binding": {
    "kind": "NodeInstanceRole",
    "role": "eks-node-role",
    "actions": [
      "AdministratorAccess"
    ]
  }
}
```
</details>

---

#### 11. 🟠 Broad secret read access

`ClusterRole/super-role`

##### Summary

A ClusterRole grants `get`/`list` on `secrets` cluster-wide rather than scoped to a namespace or specific secret names.

> **Detected:** ClusterRole can read secrets cluster-wide (get/list on secrets)

| | |
|:--|:--|
| **Rule ID** | `rbac-secret-read-broad` |
| **Domain** | `rbac_identity` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 21.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K03 — Secrets Management Failures | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.1.2 — Minimize access to secrets | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Container API Credentials (`T1552.007`) | [Reference](https://attack.mitre.org/techniques/T1552/007/) |

##### 💥 Impact

Any subject bound to this role can read every Secret in every namespace — database credentials, TLS keys, cloud IAM tokens, other teams' application secrets — a single overly broad grant that effectively flattens Kubernetes' namespace isolation for credential material.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get clusterrole -o json | jq '.items[] | select(.rules[]? | select(.resources[]?=="secrets") | .verbs[]? | IN("get","list")) | .metadata.name'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "rule": {
    "apiGroups": [
      "*"
    ],
    "resources": [
      "*"
    ],
    "verbs": [
      "*"
    ]
  }
}
```
</details>

---

#### 12. 🟠 Broad secret read access

`ClusterRole/secret-reader`

##### Summary

A ClusterRole grants `get`/`list` on `secrets` cluster-wide rather than scoped to a namespace or specific secret names.

> **Detected:** ClusterRole can read secrets cluster-wide (get/list on secrets)

| | |
|:--|:--|
| **Rule ID** | `rbac-secret-read-broad` |
| **Domain** | `rbac_identity` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 21.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K03 — Secrets Management Failures | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.1.2 — Minimize access to secrets | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Container API Credentials (`T1552.007`) | [Reference](https://attack.mitre.org/techniques/T1552/007/) |

##### 💥 Impact

Any subject bound to this role can read every Secret in every namespace — database credentials, TLS keys, cloud IAM tokens, other teams' application secrets — a single overly broad grant that effectively flattens Kubernetes' namespace isolation for credential material.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get clusterrole -o json | jq '.items[] | select(.rules[]? | select(.resources[]?=="secrets") | .verbs[]? | IN("get","list")) | .metadata.name'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "rule": {
    "apiGroups": [
      ""
    ],
    "resources": [
      "secrets"
    ],
    "verbs": [
      "get",
      "list"
    ]
  }
}
```
</details>

---

#### 13. 🟠 Can write ConfigMaps (CoreDNS risk)

`ClusterRole/super-role`

##### Summary

A Role/ClusterRole grants `update`/`patch` on `configmaps` broadly enough to include (or not clearly exclude) the `kube-system/coredns` ConfigMap that drives cluster-internal DNS resolution.

> **Detected:** role can modify ConfigMaps (potential CoreDNS poisoning if kube-system CoreDNS CM is writable)

| | |
|:--|:--|
| **Rule ID** | `rbac-coredns-configmap-write` |
| **Domain** | `rbac_identity` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 21.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K05 — Missing Network Segmentation | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Lateral Movement | Adversary-in-the-Middle (`T1557`) | [Reference](https://attack.mitre.org/techniques/T1557/) |

##### 💥 Impact

Whoever can rewrite CoreDNS's Corefile controls DNS resolution for the entire cluster — a classic adversary-in-the-middle position, capable of redirecting any pod's traffic (including to internal services or the cloud metadata API) to an attacker-controlled endpoint.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get role,rolebinding -n kube-system -o json | jq '.items[] | select(.rules[]?.resources[]?=="configmaps")'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "rule": {
    "apiGroups": [
      "*"
    ],
    "resources": [
      "*"
    ],
    "verbs": [
      "*"
    ]
  }
}
```
</details>

---

#### 14. 🟠 Can write ConfigMaps (CoreDNS risk)

`ClusterRole/cm-writer`

##### Summary

A Role/ClusterRole grants `update`/`patch` on `configmaps` broadly enough to include (or not clearly exclude) the `kube-system/coredns` ConfigMap that drives cluster-internal DNS resolution.

> **Detected:** role can modify ConfigMaps (potential CoreDNS poisoning if kube-system CoreDNS CM is writable)

| | |
|:--|:--|
| **Rule ID** | `rbac-coredns-configmap-write` |
| **Domain** | `rbac_identity` |
| **Exploitability** | Local |
| **Blast radius** | Cluster-wide |
| **Risk score** | 21.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K05 — Missing Network Segmentation | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Lateral Movement | Adversary-in-the-Middle (`T1557`) | [Reference](https://attack.mitre.org/techniques/T1557/) |

##### 💥 Impact

Whoever can rewrite CoreDNS's Corefile controls DNS resolution for the entire cluster — a classic adversary-in-the-middle position, capable of redirecting any pod's traffic (including to internal services or the cloud metadata API) to an attacker-controlled endpoint.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get role,rolebinding -n kube-system -o json | jq '.items[] | select(.rules[]?.resources[]?=="configmaps")'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "rule": {
    "apiGroups": [
      ""
    ],
    "resources": [
      "configmaps",
      "events"
    ],
    "verbs": [
      "update",
      "patch",
      "delete"
    ]
  }
}
```
</details>

---

#### 15. 🟠 Ingress without TLS

`Ingress/web-ingress (production)`

##### Summary

An Ingress resource serves traffic over plain HTTP with no TLS configuration.

> **Detected:** Ingress serves traffic without TLS

| | |
|:--|:--|
| **Rule ID** | `net-ingress-no-tls` |
| **Domain** | `network_security` |
| **Exploitability** | Remote |
| **Blast radius** | Pod |
| **Risk score** | 21.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K06 — Overly Exposed Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Initial Access | External Remote Services (`T1133`) | [Reference](https://attack.mitre.org/techniques/T1133/) |

##### 💥 Impact

Any credential, session token, or sensitive payload sent to this endpoint travels in cleartext and can be intercepted by anyone with network visibility along the path — a straightforward, passive eavesdropping exposure.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get ingress web-ingress -n production -o jsonpath='{.spec.tls}'
```

---

#### 16. 🟠 Host network shared ⚡ Attack-Path Amplified

`Pod/payment-api (production)`

##### Summary

The pod shares the host's network namespace (`hostNetwork: true`), binding directly to the node's own network interfaces.

> **Detected:** workload shares host hostNetwork namespace

| | |
|:--|:--|
| **Rule ID** | `workload-host-network` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Namespace |
| **Risk score** | 17.5 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.5 — Minimize admission of containers sharing host network namespace | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |
| Discovery | Network Service Discovery (`T1046`) | [Reference](https://attack.mitre.org/techniques/T1046/) |

##### 💥 Impact

The pod can see and bind to every port on the node, sniff traffic on the host's interfaces, and reach any service the node itself can reach (including cloud metadata endpoints that may otherwise be firewalled from pod IPs) — a significant discovery and lateral-movement advantage.

##### 🛠️ Remediation

**Disable host network namespace sharing**

```bash
kubectl patch deployment payment-api -n production -p '{"spec": {"template": {"spec": {"hostNetwork": false}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      hostNetwork: false
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo deployment/payment-api -n production
```
</details>

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.hostNetwork}'
```

_Post-remediation check:_

```bash
kubectl get deployment payment-api -n production -o yaml
kubectl rollout status deployment/payment-api -n production
```

<details><summary>🔎 Evidence</summary>

```json
{
  "hostNetwork": true
}
```
</details>

---

#### 17. 🟠 Host network shared ⚡ Attack-Path Amplified

`Pod/aws-node-64w2k (kube-system)`

##### Summary

The pod shares the host's network namespace (`hostNetwork: true`), binding directly to the node's own network interfaces.

> **Detected:** workload shares host hostNetwork namespace

| | |
|:--|:--|
| **Rule ID** | `workload-host-network` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `DaemonSet/aws-node (kube-system)` |
| **Exploitability** | Local |
| **Blast radius** | Namespace |
| **Risk score** | 17.5 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.5 — Minimize admission of containers sharing host network namespace | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |
| Discovery | Network Service Discovery (`T1046`) | [Reference](https://attack.mitre.org/techniques/T1046/) |

##### 💥 Impact

The pod can see and bind to every port on the node, sniff traffic on the host's interfaces, and reach any service the node itself can reach (including cloud metadata endpoints that may otherwise be firewalled from pod IPs) — a significant discovery and lateral-movement advantage.

##### 🛠️ Remediation

**Disable host network namespace sharing**

```bash
kubectl patch daemonset aws-node -n kube-system -p '{"spec": {"template": {"spec": {"hostNetwork": false}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      hostNetwork: false
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo daemonset/aws-node -n kube-system
```
</details>

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod aws-node-64w2k -n kube-system -o jsonpath='{.spec.hostNetwork}'
```

_Post-remediation check:_

```bash
kubectl get daemonset aws-node -n kube-system -o yaml
kubectl rollout status daemonset/aws-node -n kube-system
```

<details><summary>⚠️ Warnings</summary>

- This appears to be a Kubernetes/EKS managed component. Verify vendor documentation before changing its security context because the recommended hardening may break cluster functionality.

</details>

<details><summary>🔎 Evidence</summary>

```json
{
  "hostNetwork": true
}
```
</details>

---

#### 18. 🟠 Writable hostPath mount ⚡ Attack-Path Amplified

`Pod/payment-api (production)`

##### Summary

The pod mounts a writable hostPath volume outside the small set of already-flagged critical system paths.

> **Detected:** mounts a writable hostPath '/var/run/docker.sock' (persistence / lateral movement vector)

| | |
|:--|:--|
| **Rule ID** | `workload-hostpath-writable` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Namespace |
| **Risk score** | 17.5 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.12 — Minimize the admission of HostPath volumes | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Persistence | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |
| Lateral Movement | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

A writable path on the node's filesystem that survives the pod's own lifecycle is a persistence mechanism — an attacker who compromises this pod can drop a payload on the node that a different, later workload (or the node itself) may execute, and it can be used to move data between pods that shouldn't otherwise be able to communicate.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This finding's fix is a manual/policy action, not a single safe kubectl command.

Manual steps:

1. Remove hostPath / docker.sock mount
2. # manual review required: remove the hostPath volume + mount

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.volumes[*].hostPath.path}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "volume": "dockersock",
  "path": "/var/run/docker.sock"
}
```
</details>

---

#### 19. 🟠 Host IPC namespace shared

`Pod/payment-api (production)`

##### Summary

The pod shares the host's IPC namespace (`hostIPC: true`), exposing shared memory segments and semaphores used by host processes.

> **Detected:** workload shares host hostIPC namespace

| | |
|:--|:--|
| **Rule ID** | `workload-host-ipc` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Namespace |
| **Risk score** | 14.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.4 — Minimize admission of containers sharing host IPC namespace | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

A container in this pod can read or write shared memory used by other processes on the node, including, in some configurations, information leaked by unrelated host services — an information-disclosure and cross-process-influence vector.

##### 🛠️ Remediation

**Disable host IPC namespace sharing**

```bash
kubectl patch deployment payment-api -n production -p '{"spec": {"template": {"spec": {"hostIPC": false}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      hostIPC: false
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo deployment/payment-api -n production
```
</details>

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.hostIPC}'
```

_Post-remediation check:_

```bash
kubectl get deployment payment-api -n production -o yaml
kubectl rollout status deployment/payment-api -n production
```

<details><summary>🔎 Evidence</summary>

```json
{
  "hostIPC": true
}
```
</details>

---

#### 20. 🟠 PSA not enforcing 'restricted'

`Namespace/production`

##### Summary

The namespace does not enforce the `restricted` Pod Security Standard — Kubernetes' own built-in, opt-in baseline for hardened pod specs.

> **Detected:** namespace 'production' does not enforce Pod Security Standard 'restricted' (current: none)

| | |
|:--|:--|
| **Rule ID** | `compliance-psa-not-restricted` |
| **Domain** | `compliance` |
| **Exploitability** | Local |
| **Blast radius** | Namespace |
| **Risk score** | 14.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K04 — Lack of Cluster-Level Policy Enforcement | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.1 — Cluster has at least one active policy control mechanism | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |
| NSA/CISA Kubernetes Hardening Guide | Pod Security — Pod Security | [Reference](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) |
| NSA/CISA Kubernetes Hardening Guide | Policy Enforcement — Policy Enforcement | [Reference](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Persistence | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Without PSA enforcement, nothing prevents any future pod deployed into this namespace from being privileged, root, or host-namespace-sharing, regardless of how well-intentioned today's workloads are — it's a namespace-wide guardrail, not a one-time check.

##### 🛠️ Remediation

**Enforce Pod Security Standard 'restricted'**

```bash
kubectl label ns production pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/warn=restricted --overwrite
```

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get ns production -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "namespace": "production",
  "enforce": null
}
```
</details>

---

#### 21. 🟠 PSA not enforcing 'restricted'

`Namespace/staging`

##### Summary

The namespace does not enforce the `restricted` Pod Security Standard — Kubernetes' own built-in, opt-in baseline for hardened pod specs.

> **Detected:** namespace 'staging' does not enforce Pod Security Standard 'restricted' (current: privileged)

| | |
|:--|:--|
| **Rule ID** | `compliance-psa-not-restricted` |
| **Domain** | `compliance` |
| **Exploitability** | Local |
| **Blast radius** | Namespace |
| **Risk score** | 14.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K04 — Lack of Cluster-Level Policy Enforcement | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.1 — Cluster has at least one active policy control mechanism | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |
| NSA/CISA Kubernetes Hardening Guide | Pod Security — Pod Security | [Reference](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) |
| NSA/CISA Kubernetes Hardening Guide | Policy Enforcement — Policy Enforcement | [Reference](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Persistence | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Without PSA enforcement, nothing prevents any future pod deployed into this namespace from being privileged, root, or host-namespace-sharing, regardless of how well-intentioned today's workloads are — it's a namespace-wide guardrail, not a one-time check.

##### 🛠️ Remediation

**Enforce Pod Security Standard 'restricted'**

```bash
kubectl label ns staging pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/warn=restricted --overwrite
```

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get ns staging -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "namespace": "staging",
  "enforce": "privileged"
}
```
</details>

---

#### 22. 🟠 Namespace without NetworkPolicy

`Namespace/production`

##### Summary

The namespace has zero NetworkPolicies applied, so every pod in it can send and receive traffic from every other pod in the cluster by default.

> **Detected:** namespace 'production' has no NetworkPolicy (flat network)

| | |
|:--|:--|
| **Rule ID** | `net-no-networkpolicy` |
| **Domain** | `network_security` |
| **Exploitability** | Local |
| **Blast radius** | Namespace |
| **Risk score** | 14.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K05 — Missing Network Segmentation | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.3.2 — All Namespaces have NetworkPolicies defined | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |
| NSA/CISA Kubernetes Hardening Guide | Network Policy — Network Policy | [Reference](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Lateral Movement | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

A flat, unsegmented pod network means a single compromised pod — anywhere in the cluster — can immediately probe and reach every other workload with no additional lateral-movement step required. NetworkPolicy is Kubernetes' primary built-in segmentation control, and it is opt-in.

##### 🛠️ Remediation

**Apply default-deny NetworkPolicy**

```bash
kubectl apply -n default -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny-ingress, namespace: default}
spec: {podSelector: {}, policyTypes: [Ingress]}
EOF
```

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get networkpolicy -n default
```

<details><summary>🔎 Evidence</summary>

```json
{
  "namespace": "production"
}
```
</details>

---

#### 23. 🟠 Namespace without NetworkPolicy

`Namespace/staging`

##### Summary

The namespace has zero NetworkPolicies applied, so every pod in it can send and receive traffic from every other pod in the cluster by default.

> **Detected:** namespace 'staging' has no NetworkPolicy (flat network)

| | |
|:--|:--|
| **Rule ID** | `net-no-networkpolicy` |
| **Domain** | `network_security` |
| **Exploitability** | Local |
| **Blast radius** | Namespace |
| **Risk score** | 14.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K05 — Missing Network Segmentation | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.3.2 — All Namespaces have NetworkPolicies defined | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |
| NSA/CISA Kubernetes Hardening Guide | Network Policy — Network Policy | [Reference](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Lateral Movement | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

A flat, unsegmented pod network means a single compromised pod — anywhere in the cluster — can immediately probe and reach every other workload with no additional lateral-movement step required. NetworkPolicy is Kubernetes' primary built-in segmentation control, and it is opt-in.

##### 🛠️ Remediation

**Apply default-deny NetworkPolicy**

```bash
kubectl apply -n default -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny-ingress, namespace: default}
spec: {podSelector: {}, policyTypes: [Ingress]}
EOF
```

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get networkpolicy -n default
```

<details><summary>🔎 Evidence</summary>

```json
{
  "namespace": "staging"
}
```
</details>

---

#### 24. 🟠 Suspicious CronJob

`CronJob/backup-cron (production)`

##### Summary

A CronJob has a suspicious schedule, image, or command — the pattern used by backdoors that need to survive pod restarts and even node reboots.

> **Detected:** CronJob 'backup-cron' looks suspicious (schedule='* * * * *', images=['curlimages/curl:latest'])

| | |
|:--|:--|
| **Rule ID** | `cronjob-suspicious` |
| **Domain** | `admission_control` |
| **Exploitability** | Local |
| **Blast radius** | Namespace |
| **Risk score** | 14.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Persistence | Scheduled Task/Job: Cron (`T1053.003`) | [Reference](https://attack.mitre.org/techniques/T1053/003/) |

##### 💥 Impact

A CronJob is a durable, self-reinstating persistence mechanism: even if the malicious pod it spawns is found and killed, the CronJob simply creates another one on its next scheduled tick, with no further attacker action required.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get cronjob backup-cron -n production -o jsonpath='{.spec.schedule} {.spec.jobTemplate.spec.template.spec.containers[*].image} {.spec.jobTemplate.spec.template.spec.containers[*].command}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "schedule": "* * * * *",
  "images": [
    "curlimages/curl:latest"
  ]
}
```
</details>

---

#### 25. 🟠 Dangerous capabilities added ⚡ Attack-Path Amplified

`Pod/payment-api (production)`

##### Summary

The container adds a Linux capability from a high-risk set (`SYS_ADMIN`, `SYS_PTRACE`, `NET_RAW`, `NET_ADMIN`, `SYS_MODULE`, `BPF`, `DAC_OVERRIDE`) beyond the container-runtime default.

> **Detected:** container 'app' adds dangerous capabilities: NET_RAW, SYS_ADMIN

| | |
|:--|:--|
| **Rule ID** | `workload-dangerous-caps` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 8.75 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.8 — Minimize the admission of containers with NET_RAW capability | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |
| CIS Kubernetes Benchmark v1.8 | 5.2.9 — Minimize the admission of containers with added capabilities | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |
| Lateral Movement | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Each of these capabilities maps to a documented container-escape or lateral-movement technique — `SYS_ADMIN` alone is close to full root, `NET_RAW` enables ARP/IP spoofing for on-path attacks against other pods on the same node, and `SYS_PTRACE` allows inspecting/injecting into other processes' memory.

##### 🛠️ Remediation

**Drop ALL capabilities**

```bash
kubectl patch deployment payment-api -n production -p '{"spec": {"template": {"spec": {"containers": [{"securityContext": {"capabilities": {"drop": ["ALL"]}}, "name": "app"}]}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      containers:
        - securityContext:
            capabilities:
              drop:
                - ALL
          name: app
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo deployment/payment-api -n production
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.containers[*].securityContext.capabilities.add}'
```

_Post-remediation check:_

```bash
kubectl get deployment payment-api -n production -o yaml
kubectl rollout status deployment/payment-api -n production
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "app",
  "capabilities": [
    "NET_RAW",
    "SYS_ADMIN"
  ]
}
```
</details>

---

#### 26. 🟠 Dangerous capabilities added ⚡ Attack-Path Amplified

`Pod/aws-node-64w2k (kube-system)`

##### Summary

The container adds a Linux capability from a high-risk set (`SYS_ADMIN`, `SYS_PTRACE`, `NET_RAW`, `NET_ADMIN`, `SYS_MODULE`, `BPF`, `DAC_OVERRIDE`) beyond the container-runtime default.

> **Detected:** container 'aws-node' adds dangerous capabilities: NET_ADMIN

| | |
|:--|:--|
| **Rule ID** | `workload-dangerous-caps` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `DaemonSet/aws-node (kube-system)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 8.75 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.8 — Minimize the admission of containers with NET_RAW capability | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |
| CIS Kubernetes Benchmark v1.8 | 5.2.9 — Minimize the admission of containers with added capabilities | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |
| Lateral Movement | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Each of these capabilities maps to a documented container-escape or lateral-movement technique — `SYS_ADMIN` alone is close to full root, `NET_RAW` enables ARP/IP spoofing for on-path attacks against other pods on the same node, and `SYS_PTRACE` allows inspecting/injecting into other processes' memory.

##### 🛠️ Remediation

**Drop ALL capabilities**

```bash
kubectl patch daemonset aws-node -n kube-system -p '{"spec": {"template": {"spec": {"containers": [{"securityContext": {"capabilities": {"drop": ["ALL"]}}, "name": "aws-node"}]}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      containers:
        - securityContext:
            capabilities:
              drop:
                - ALL
          name: aws-node
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo daemonset/aws-node -n kube-system
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod aws-node-64w2k -n kube-system -o jsonpath='{.spec.containers[*].securityContext.capabilities.add}'
```

_Post-remediation check:_

```bash
kubectl get daemonset aws-node -n kube-system -o yaml
kubectl rollout status daemonset/aws-node -n kube-system
```

<details><summary>⚠️ Warnings</summary>

- This appears to be a Kubernetes/EKS managed component. Verify vendor documentation before changing its security context because the recommended hardening may break cluster functionality.

</details>

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "aws-node",
  "capabilities": [
    "NET_ADMIN"
  ]
}
```
</details>

---

#### 27. 🟠 Webhook failurePolicy=Ignore

`MutatingWebhookConfiguration/evil-webhook`

##### Summary

A security-relevant admission webhook has `failurePolicy: Ignore`.

> **Detected:** webhook 'inject.evil.io' has failurePolicy=Ignore (security control can be bypassed by breaking it)

| | |
|:--|:--|
| **Rule ID** | `admission-webhook-failurepolicy` |
| **Domain** | `admission_control` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K04 — Lack of Cluster-Level Policy Enforcement | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Defense Evasion | Impair Defenses (`T1562`) | [Reference](https://attack.mitre.org/techniques/T1562/) |

##### 💥 Impact

If the webhook is ever unreachable — network issue, the webhook pod itself crashing, or an attacker deliberately taking it offline — every object it was supposed to validate or mutate is admitted anyway, silently. An attacker who can make a policy webhook unavailable can bypass it entirely rather than needing to defeat its logic.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations -o json | jq '.items[].webhooks[] | select(.failurePolicy=="Ignore") | .name'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "webhook": "inject.evil.io"
}
```
</details>

---

#### 28. 🟠 Capabilities not dropped (ALL)

`Pod/payment-api (production)`

##### Summary

The container does not drop the full Linux capability set (`capabilities.drop: [ALL]`) before adding back only what it needs.

> **Detected:** container 'app' does not drop ALL capabilities

| | |
|:--|:--|
| **Rule ID** | `workload-caps-not-dropped` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.9 — Minimize the admission of containers with added capabilities | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Leaving the container-runtime default capability set intact (which already includes things like `NET_RAW` and `CHOWN`) means the container carries more ambient privilege than most application workloads ever legitimately need — unnecessary attack surface with no functional benefit.

##### 🛠️ Remediation

**Drop ALL capabilities**

```bash
kubectl patch deployment payment-api -n production -p '{"spec": {"template": {"spec": {"containers": [{"securityContext": {"capabilities": {"drop": ["ALL"]}}, "name": "app"}]}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      containers:
        - securityContext:
            capabilities:
              drop:
                - ALL
          name: app
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo deployment/payment-api -n production
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.containers[*].securityContext.capabilities.drop}'
```

_Post-remediation check:_

```bash
kubectl get deployment payment-api -n production -o yaml
kubectl rollout status deployment/payment-api -n production
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "app",
  "dropped": []
}
```
</details>

---

#### 29. 🟠 Capabilities not dropped (ALL)

`Pod/cache-redis (staging)`

##### Summary

The container does not drop the full Linux capability set (`capabilities.drop: [ALL]`) before adding back only what it needs.

> **Detected:** container 'redis' does not drop ALL capabilities

| | |
|:--|:--|
| **Rule ID** | `workload-caps-not-dropped` |
| **Domain** | `workload_pod_security` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.9 — Minimize the admission of containers with added capabilities | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Leaving the container-runtime default capability set intact (which already includes things like `NET_RAW` and `CHOWN`) means the container carries more ambient privilege than most application workloads ever legitimately need — unnecessary attack surface with no functional benefit.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** 'securityContext.capabilities.drop' is part of the Pod spec, which is immutable once the Pod is created — Kubernetes rejects patches to this field on a live Pod. This Pod has no owning controller, so it must be recreated directly (there is no Deployment/DaemonSet/etc. to roll out instead).

Manual steps:

1. 'securityContext.capabilities.drop' cannot be patched on a live, standalone Pod.
2. kubectl get pod cache-redis -n staging -o yaml > pod.yaml
3. Edit pod.yaml to set the corrected value, then:
4. kubectl delete pod cache-redis -n staging
5. kubectl apply -f pod.yaml

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod cache-redis -n staging -o jsonpath='{.spec.containers[*].securityContext.capabilities.drop}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "redis",
  "dropped": []
}
```
</details>

---

#### 30. 🟠 Capabilities not dropped (ALL)

`Pod/aws-node-64w2k (kube-system)`

##### Summary

The container does not drop the full Linux capability set (`capabilities.drop: [ALL]`) before adding back only what it needs.

> **Detected:** container 'aws-node' does not drop ALL capabilities

| | |
|:--|:--|
| **Rule ID** | `workload-caps-not-dropped` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `DaemonSet/aws-node (kube-system)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.9 — Minimize the admission of containers with added capabilities | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Leaving the container-runtime default capability set intact (which already includes things like `NET_RAW` and `CHOWN`) means the container carries more ambient privilege than most application workloads ever legitimately need — unnecessary attack surface with no functional benefit.

##### 🛠️ Remediation

**Drop ALL capabilities**

```bash
kubectl patch daemonset aws-node -n kube-system -p '{"spec": {"template": {"spec": {"containers": [{"securityContext": {"capabilities": {"drop": ["ALL"]}}, "name": "aws-node"}]}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      containers:
        - securityContext:
            capabilities:
              drop:
                - ALL
          name: aws-node
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo daemonset/aws-node -n kube-system
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod aws-node-64w2k -n kube-system -o jsonpath='{.spec.containers[*].securityContext.capabilities.drop}'
```

_Post-remediation check:_

```bash
kubectl get daemonset aws-node -n kube-system -o yaml
kubectl rollout status daemonset/aws-node -n kube-system
```

<details><summary>⚠️ Warnings</summary>

- This appears to be a Kubernetes/EKS managed component. Verify vendor documentation before changing its security context because the recommended hardening may break cluster functionality.

</details>

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "aws-node",
  "dropped": []
}
```
</details>

---

#### 31. 🟠 Unrecognized sidecar injection

`MutatingWebhookConfiguration/evil-webhook`

##### Summary

A mutating webhook injects a sidecar container into pods it processes.

> **Detected:** mutating webhook 'inject.evil.io' injects sidecars (verify it is a trusted mesh/agent)

| | |
|:--|:--|
| **Rule ID** | `admission-sidecar-injection` |
| **Domain** | `admission_control` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K04 — Lack of Cluster-Level Policy Enforcement | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Execution | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Sidecar injection is legitimate for service meshes and observability agents, but it is also a documented technique for smuggling an attacker-controlled container into every pod cluster-wide via a single webhook compromise — reviewing exactly what gets injected and by whom is necessary to distinguish the two.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get mutatingwebhookconfigurations -o json | jq '.items[].webhooks[] | {name, rules}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "webhook": "inject.evil.io"
}
```
</details>

---

#### 32. 🟠 Privilege escalation allowed

`Pod/payment-api (production)`

##### Summary

`allowPrivilegeEscalation` is not explicitly set to `false`, so a process in the container can gain more privileges than its parent (e.g. via a setuid binary) at runtime.

> **Detected:** container 'app' allows privilege escalation (allowPrivilegeEscalation not false)

| | |
|:--|:--|
| **Rule ID** | `workload-allow-priv-escalation` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.6 — Minimize admission of containers with allowPrivilegeEscalation | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Abuse Elevation Control (`T1548`) | [Reference](https://attack.mitre.org/techniques/T1548/) |

##### 💥 Impact

Combined with any writable, attacker-influenced binary in the image, this allows in-container privilege escalation even when the container itself doesn't start as root — widening the blast radius of an application-level compromise.

##### 🛠️ Remediation

**Harden pod securityContext (runAsNonRoot + seccompProfile)**

```bash
kubectl patch deployment payment-api -n production -p '{"spec": {"template": {"spec": {"securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}}}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo deployment/payment-api -n production
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tutorials/security/seccomp/) · [Kubernetes docs](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}'
```

_Post-remediation check:_

```bash
kubectl get deployment payment-api -n production -o yaml
kubectl rollout status deployment/payment-api -n production
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "app"
}
```
</details>

---

#### 33. 🟠 Privilege escalation allowed

`Pod/cache-redis (staging)`

##### Summary

`allowPrivilegeEscalation` is not explicitly set to `false`, so a process in the container can gain more privileges than its parent (e.g. via a setuid binary) at runtime.

> **Detected:** container 'redis' allows privilege escalation (allowPrivilegeEscalation not false)

| | |
|:--|:--|
| **Rule ID** | `workload-allow-priv-escalation` |
| **Domain** | `workload_pod_security` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.6 — Minimize admission of containers with allowPrivilegeEscalation | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Abuse Elevation Control (`T1548`) | [Reference](https://attack.mitre.org/techniques/T1548/) |

##### 💥 Impact

Combined with any writable, attacker-influenced binary in the image, this allows in-container privilege escalation even when the container itself doesn't start as root — widening the blast radius of an application-level compromise.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** 'securityContext' is part of the Pod spec, which is immutable once the Pod is created — Kubernetes rejects patches to this field on a live Pod. This Pod has no owning controller, so it must be recreated directly (there is no Deployment/DaemonSet/etc. to roll out instead).

Manual steps:

1. 'securityContext' cannot be patched on a live, standalone Pod.
2. kubectl get pod cache-redis -n staging -o yaml > pod.yaml
3. Edit pod.yaml to set the corrected value, then:
4. kubectl delete pod cache-redis -n staging
5. kubectl apply -f pod.yaml

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tutorials/security/seccomp/) · [Kubernetes docs](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod cache-redis -n staging -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "redis"
}
```
</details>

---

#### 34. 🟠 Privilege escalation allowed

`Pod/aws-node-64w2k (kube-system)`

##### Summary

`allowPrivilegeEscalation` is not explicitly set to `false`, so a process in the container can gain more privileges than its parent (e.g. via a setuid binary) at runtime.

> **Detected:** container 'aws-node' allows privilege escalation (allowPrivilegeEscalation not false)

| | |
|:--|:--|
| **Rule ID** | `workload-allow-priv-escalation` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `DaemonSet/aws-node (kube-system)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.6 — Minimize admission of containers with allowPrivilegeEscalation | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Abuse Elevation Control (`T1548`) | [Reference](https://attack.mitre.org/techniques/T1548/) |

##### 💥 Impact

Combined with any writable, attacker-influenced binary in the image, this allows in-container privilege escalation even when the container itself doesn't start as root — widening the blast radius of an application-level compromise.

##### 🛠️ Remediation

**Harden pod securityContext (runAsNonRoot + seccompProfile)**

```bash
kubectl patch daemonset aws-node -n kube-system -p '{"spec": {"template": {"spec": {"securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}}}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo daemonset/aws-node -n kube-system
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tutorials/security/seccomp/) · [Kubernetes docs](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod aws-node-64w2k -n kube-system -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}'
```

_Post-remediation check:_

```bash
kubectl get daemonset aws-node -n kube-system -o yaml
kubectl rollout status daemonset/aws-node -n kube-system
```

<details><summary>⚠️ Warnings</summary>

- This appears to be a Kubernetes/EKS managed component. Verify vendor documentation before changing its security context because the recommended hardening may break cluster functionality.

</details>

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "aws-node"
}
```
</details>

---

#### 35. 🟠 Can delete Kubernetes events

`ClusterRole/super-role`

##### Summary

A Role/ClusterRole grants `delete` on `events`.

> **Detected:** role can delete events (defense evasion / covering tracks)

| | |
|:--|:--|
| **Rule ID** | `rbac-can-delete-events` |
| **Domain** | `rbac_identity` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K10 — Inadequate Logging & Monitoring | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Defense Evasion | Indicator Removal (`T1070`) | [Reference](https://attack.mitre.org/techniques/T1070/) |

##### 💥 Impact

Kubernetes events are one of the first places an operator looks during incident response. A subject that can delete them can erase evidence of its own suspicious activity (pod creation, exec, image pulls) as it happens — a defense-evasion primitive specifically flagged in the Kubernetes threat matrix.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get clusterrole,role -A -o json | jq '.items[] | select(.rules[]? | select(.resources[]?=="events") | .verbs[]?=="delete") | .metadata.name'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "rule": {
    "apiGroups": [
      "*"
    ],
    "resources": [
      "*"
    ],
    "verbs": [
      "*"
    ]
  }
}
```
</details>

---

#### 36. 🟠 Can delete Kubernetes events

`ClusterRole/cm-writer`

##### Summary

A Role/ClusterRole grants `delete` on `events`.

> **Detected:** role can delete events (defense evasion / covering tracks)

| | |
|:--|:--|
| **Rule ID** | `rbac-can-delete-events` |
| **Domain** | `rbac_identity` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K10 — Inadequate Logging & Monitoring | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Defense Evasion | Indicator Removal (`T1070`) | [Reference](https://attack.mitre.org/techniques/T1070/) |

##### 💥 Impact

Kubernetes events are one of the first places an operator looks during incident response. A subject that can delete them can erase evidence of its own suspicious activity (pod creation, exec, image pulls) as it happens — a defense-evasion primitive specifically flagged in the Kubernetes threat matrix.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get clusterrole,role -A -o json | jq '.items[] | select(.rules[]? | select(.resources[]?=="events") | .verbs[]?=="delete") | .metadata.name'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "rule": {
    "apiGroups": [
      ""
    ],
    "resources": [
      "configmaps",
      "events"
    ],
    "verbs": [
      "update",
      "patch",
      "delete"
    ]
  }
}
```
</details>

---

#### 37. 🟠 Container runs as root

`Pod/payment-api (production)`

##### Summary

The container has no enforced non-root user — it may run as UID 0 inside the container.

> **Detected:** container 'app' may run as root (runAsNonRoot not enforced)

| | |
|:--|:--|
| **Rule ID** | `workload-run-as-root` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.7 — Minimize the admission of root containers | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Running as root inside the container removes a key defense-in-depth layer: if any other misconfiguration (a writable filesystem, a capability, a kernel vulnerability) is also present, root privileges inside the container make exploiting it materially easier, and any container-escape primitive lands the attacker as root on the host too.

##### 🛠️ Remediation

**Force runAsNonRoot**

```bash
kubectl patch deployment payment-api -n production -p '{"spec": {"template": {"spec": {"securityContext": {"runAsNonRoot": true}}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo deployment/payment-api -n production
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.containers[*].securityContext.runAsUser} {.spec.securityContext.runAsNonRoot}'
```

_Post-remediation check:_

```bash
kubectl get deployment payment-api -n production -o yaml
kubectl rollout status deployment/payment-api -n production
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "app",
  "runAsUser": 0
}
```
</details>

---

#### 38. 🟠 Container runs as root

`Pod/cache-redis (staging)`

##### Summary

The container has no enforced non-root user — it may run as UID 0 inside the container.

> **Detected:** container 'redis' may run as root (runAsNonRoot not enforced)

| | |
|:--|:--|
| **Rule ID** | `workload-run-as-root` |
| **Domain** | `workload_pod_security` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.7 — Minimize the admission of root containers | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Running as root inside the container removes a key defense-in-depth layer: if any other misconfiguration (a writable filesystem, a capability, a kernel vulnerability) is also present, root privileges inside the container make exploiting it materially easier, and any container-escape primitive lands the attacker as root on the host too.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** 'securityContext' is part of the Pod spec, which is immutable once the Pod is created — Kubernetes rejects patches to this field on a live Pod. This Pod has no owning controller, so it must be recreated directly (there is no Deployment/DaemonSet/etc. to roll out instead).

Manual steps:

1. 'securityContext' cannot be patched on a live, standalone Pod.
2. kubectl get pod cache-redis -n staging -o yaml > pod.yaml
3. Edit pod.yaml to set the corrected value, then:
4. kubectl delete pod cache-redis -n staging
5. kubectl apply -f pod.yaml

_References:_ [Kubernetes docs](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod cache-redis -n staging -o jsonpath='{.spec.containers[*].securityContext.runAsUser} {.spec.securityContext.runAsNonRoot}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "redis",
  "runAsUser": null
}
```
</details>

---

#### 39. 🟠 Container runs as root

`Pod/aws-node-64w2k (kube-system)`

##### Summary

The container has no enforced non-root user — it may run as UID 0 inside the container.

> **Detected:** container 'aws-node' may run as root (runAsNonRoot not enforced)

| | |
|:--|:--|
| **Rule ID** | `workload-run-as-root` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `DaemonSet/aws-node (kube-system)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.2.7 — Minimize the admission of root containers | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Privilege Escalation | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Running as root inside the container removes a key defense-in-depth layer: if any other misconfiguration (a writable filesystem, a capability, a kernel vulnerability) is also present, root privileges inside the container make exploiting it materially easier, and any container-escape primitive lands the attacker as root on the host too.

##### 🛠️ Remediation

**Force runAsNonRoot**

```bash
kubectl patch daemonset aws-node -n kube-system -p '{"spec": {"template": {"spec": {"securityContext": {"runAsNonRoot": true}}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo daemonset/aws-node -n kube-system
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod aws-node-64w2k -n kube-system -o jsonpath='{.spec.containers[*].securityContext.runAsUser} {.spec.securityContext.runAsNonRoot}'
```

_Post-remediation check:_

```bash
kubectl get daemonset aws-node -n kube-system -o yaml
kubectl rollout status daemonset/aws-node -n kube-system
```

<details><summary>⚠️ Warnings</summary>

- This appears to be a Kubernetes/EKS managed component. Verify vendor documentation before changing its security context because the recommended hardening may break cluster functionality.

</details>

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "aws-node",
  "runAsUser": null
}
```
</details>

---

#### 40. 🟠 Credentials in ConfigMap

`ConfigMap/app-config (production)`

##### Summary

A ConfigMap key or value looks like a hardcoded credential (password, token, API key, private key).

> **Detected:** ConfigMap key 'admin_password' looks like a hardcoded credential

| | |
|:--|:--|
| **Rule ID** | `sec-configmap-credentials` |
| **Domain** | `secrets` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K03 — Secrets Management Failures | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Unsecured Credentials (`T1552`) | [Reference](https://attack.mitre.org/techniques/T1552/) |

##### 💥 Impact

Unlike Secrets, ConfigMaps are not treated as sensitive by Kubernetes — they're readable by any identity with generic `get`/`list` on ConfigMaps (a far more common grant than secret access), and their contents are shown in plaintext by `kubectl get configmap -o yaml` with no redaction.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get configmap app-config -n production -o yaml
```

<details><summary>🔎 Evidence</summary>

```json
{
  "key": "admin_password"
}
```
</details>

---

#### 41. 🟠 Secret exposed as env var

`Pod/payment-api (production)`

##### Summary

A container injects a Secret's value via an environment variable (`env[].valueFrom.secretKeyRef`) rather than a mounted file.

> **Detected:** container 'app' injects a Secret via env var 'DB_PASSWORD' (exposed in logs/crash dumps)

| | |
|:--|:--|
| **Rule ID** | `sec-env-var-secrets` |
| **Domain** | `secrets` |
| **Owner resource** | `ReplicaSet/payment-api-7d9f8c9d76 (production)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K03 — Secrets Management Failures | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.4.1 — Prefer Secrets as files over Secrets as environment variables | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Container API Credentials (`T1552.007`) | [Reference](https://attack.mitre.org/techniques/T1552/007/) |

##### 💥 Impact

Environment variables are captured whole in `kubectl describe pod`, crash dumps, core dumps, child-process environments, and many APM/logging agents that snapshot process environment by default — each an independent way the secret value can leak outside the one process that actually needs it.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This finding's fix is a manual/policy action, not a single safe kubectl command.

Manual steps:

1. Mount the Secret as a volume instead of an env var
2. # manual review required: env vars sourced from a Secret are visible in `kubectl describe pod`, crash dumps, and child-process environments. Replace the env.valueFrom.secretKeyRef with a projected volume mount (add a `volumes[].secret` + matching `volumeMounts[]` on the container, then update the app to read the value from the mounted file instead).

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.containers[*].env[?(@.valueFrom.secretKeyRef)].name}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "env": "DB_PASSWORD"
}
```
</details>

---

#### 42. 🟠 Mounted cloud credentials

`Pod/cache-redis (staging)`

##### Summary

A volume mount path matches a well-known cloud credential file location (`.aws/credentials`, `azure.json`, a GCP service-account JSON, or a `.kube/config`).

> **Detected:** mounts a cloud credential path (/root/.aws/credentials) — service principal / managed identity exposure

| | |
|:--|:--|
| **Rule ID** | `sec-mounted-cloud-creds` |
| **Domain** | `secrets` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 7.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K03 — Secrets Management Failures | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Unsecured Credentials (`T1552`) | [Reference](https://attack.mitre.org/techniques/T1552/) |

##### 💥 Impact

These files typically grant standing, long-lived cloud or cluster credentials with whatever scope was provisioned for them — often far broader than the single pod needs — turning a container compromise directly into a cloud-account or cross-cluster compromise.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod cache-redis -n staging -o jsonpath='{.spec.containers[*].volumeMounts[*].mountPath}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "mountPath": "/root/.aws/credentials"
}
```
</details>

---

<a id="sev-medium"></a>
### 🟡 MEDIUM — 22 finding(s)

#### 1. 🟡 ServiceAccount fan-out

`ServiceAccount/shared-sa`

##### Summary

The same ServiceAccount is mounted into a large number of workloads spread across multiple namespaces.

> **Detected:** ServiceAccount 'shared-sa' is reused by 3 workloads across 2 namespaces (production, staging) — wide lateral-movement blast radius

| | |
|:--|:--|
| **Rule ID** | `as-sa-fanout` |
| **Domain** | `attack_surface` |
| **Exploitability** | Adjacent |
| **Blast radius** | Cluster-wide |
| **Risk score** | 24.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K02 — Overly Permissive Authorization | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Lateral Movement | Valid Accounts (`T1078`) | [Reference](https://attack.mitre.org/techniques/T1078/) |

##### 💥 Impact

A single compromised pod anywhere this ServiceAccount is used can act as it everywhere else it's used too — the SA's effective blast radius is the union of every namespace it appears in, not just the one where the compromise happened. This is exactly how a low-value workload becomes an unintended pivot point into higher-value ones sharing the same identity.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.serviceAccountName=="shared-sa") | "\(.metadata.namespace)/\(.metadata.name)"'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "pods": 3,
  "namespaces": [
    "production",
    "staging"
  ]
}
```
</details>

---

#### 2. 🟡 NodePort service exposed

`Service/api-nodeport (production)`

##### Summary

A Service of type `NodePort` opens a port in the 30000–32767 range directly on every node in the cluster.

> **Detected:** NodePort service exposes ports [31000]

| | |
|:--|:--|
| **Rule ID** | `net-nodeport-service` |
| **Domain** | `network_security` |
| **Exploitability** | Remote |
| **Blast radius** | Pod |
| **Risk score** | 12.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K06 — Overly Exposed Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Initial Access | External Remote Services (`T1133`) | [Reference](https://attack.mitre.org/techniques/T1133/) |

##### 💥 Impact

NodePort exposure bypasses any Ingress-level access control and is reachable on every node's IP, widening the effective attack surface well beyond what a ClusterIP + Ingress topology would expose, especially if nodes themselves have public IPs.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get svc api-nodeport -n production -o jsonpath='{.spec.type} {.spec.ports[*].nodePort}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "nodePorts": [
    31000
  ]
}
```
</details>

---

#### 3. 🟡 NodePort service exposed

`Service/kubernetes-dashboard (kubernetes-dashboard)`

##### Summary

A Service of type `NodePort` opens a port in the 30000–32767 range directly on every node in the cluster.

> **Detected:** NodePort service exposes ports [30443]

| | |
|:--|:--|
| **Rule ID** | `net-nodeport-service` |
| **Domain** | `network_security` |
| **Exploitability** | Remote |
| **Blast radius** | Pod |
| **Risk score** | 12.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K06 — Overly Exposed Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Initial Access | External Remote Services (`T1133`) | [Reference](https://attack.mitre.org/techniques/T1133/) |

##### 💥 Impact

NodePort exposure bypasses any Ingress-level access control and is reachable on every node's IP, widening the effective attack surface well beyond what a ClusterIP + Ingress topology would expose, especially if nodes themselves have public IPs.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get svc kubernetes-dashboard -n kubernetes-dashboard -o jsonpath='{.spec.type} {.spec.ports[*].nodePort}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "nodePorts": [
    30443
  ]
}
```
</details>

---

#### 4. 🟡 Mutable :latest image tag

`Pod/payment-api (production)`

##### Summary

The container references a mutable image tag (`:latest`, or no tag/digest at all) instead of an immutable content digest.

> **Detected:** container 'app' uses a mutable/unpinned image tag: nginx:latest

| | |
|:--|:--|
| **Rule ID** | `workload-latest-tag` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K07 — Misconfigured & Vulnerable Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Initial Access | Implant Internal Image (`T1525`) | [Reference](https://attack.mitre.org/techniques/T1525/) |

##### 💥 Impact

The exact code running in production can silently change on the next pod restart or node reschedule without any deployment event — breaking reproducibility, complicating incident response ('which image was actually running?'), and opening a supply-chain window if the tag is ever repointed to a malicious image at the registry.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This fix needs a value you must supply before running it (shown as <...> in the template below) — e.g. the image digest, which requires resolving the tag against the registry first.

Manual steps:

1. Pin image to a digest
2. kubectl set image pod/payment-api -n production <container>=<image>@sha256:<digest>

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.containers[*].image}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "app",
  "image": "nginx:latest"
}
```
</details>

---

#### 5. 🟡 Mutable :latest image tag

`Pod/cache-redis (staging)`

##### Summary

The container references a mutable image tag (`:latest`, or no tag/digest at all) instead of an immutable content digest.

> **Detected:** container 'redis' uses a mutable/unpinned image tag: redis:latest

| | |
|:--|:--|
| **Rule ID** | `workload-latest-tag` |
| **Domain** | `workload_pod_security` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K07 — Misconfigured & Vulnerable Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Initial Access | Implant Internal Image (`T1525`) | [Reference](https://attack.mitre.org/techniques/T1525/) |

##### 💥 Impact

The exact code running in production can silently change on the next pod restart or node reschedule without any deployment event — breaking reproducibility, complicating incident response ('which image was actually running?'), and opening a supply-chain window if the tag is ever repointed to a malicious image at the registry.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This fix needs a value you must supply before running it (shown as <...> in the template below) — e.g. the image digest, which requires resolving the tag against the registry first.

Manual steps:

1. Pin image to a digest
2. kubectl set image pod/cache-redis -n staging <container>=<image>@sha256:<digest>

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod cache-redis -n staging -o jsonpath='{.spec.containers[*].image}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "redis",
  "image": "redis:latest"
}
```
</details>

---

#### 6. 🟡 Mutable :latest image tag

`Pod/nignx-web (production)`

##### Summary

The container references a mutable image tag (`:latest`, or no tag/digest at all) instead of an immutable content digest.

> **Detected:** container 'web' uses a mutable/unpinned image tag: nignx:latest

| | |
|:--|:--|
| **Rule ID** | `workload-latest-tag` |
| **Domain** | `workload_pod_security` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K07 — Misconfigured & Vulnerable Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Initial Access | Implant Internal Image (`T1525`) | [Reference](https://attack.mitre.org/techniques/T1525/) |

##### 💥 Impact

The exact code running in production can silently change on the next pod restart or node reschedule without any deployment event — breaking reproducibility, complicating incident response ('which image was actually running?'), and opening a supply-chain window if the tag is ever repointed to a malicious image at the registry.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This fix needs a value you must supply before running it (shown as <...> in the template below) — e.g. the image digest, which requires resolving the tag against the registry first.

Manual steps:

1. Pin image to a digest
2. kubectl set image pod/nignx-web -n production <container>=<image>@sha256:<digest>

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod nignx-web -n production -o jsonpath='{.spec.containers[*].image}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "web",
  "image": "nignx:latest"
}
```
</details>

---

#### 7. 🟡 SA token auto-mounted

`Pod/payment-api (production)`

##### Summary

This workload's ServiceAccount token is automatically mounted into the pod, even though most application containers never call the Kubernetes API.

> **Detected:** service-account token is auto-mounted (automountServiceAccountToken not false)

| | |
|:--|:--|
| **Rule ID** | `workload-sa-token-automount` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K03 — Secrets Management Failures | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.1.6 — Service Account Tokens only mounted where necessary | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Steal Application Access Token (`T1528`) | [Reference](https://attack.mitre.org/techniques/T1528/) |

##### 💥 Impact

If the container is compromised, the mounted token is immediately usable by the attacker to call the Kubernetes API as that ServiceAccount — credential theft that requires no further exploitation step, and one of the most common real-world Kubernetes attack-chain pivots.

##### 🛠️ Remediation

**Disable service-account token automount**

```bash
kubectl patch deployment payment-api -n production -p '{"spec": {"template": {"spec": {"automountServiceAccountToken": false}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      automountServiceAccountToken: false
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo deployment/payment-api -n production
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.automountServiceAccountToken}'
```

_Post-remediation check:_

```bash
kubectl get deployment payment-api -n production -o yaml
kubectl rollout status deployment/payment-api -n production
```

<details><summary>🔎 Evidence</summary>

```json
{
  "automount": null
}
```
</details>

---

#### 8. 🟡 SA token auto-mounted

`Pod/cache-redis (staging)`

##### Summary

This workload's ServiceAccount token is automatically mounted into the pod, even though most application containers never call the Kubernetes API.

> **Detected:** service-account token is auto-mounted (automountServiceAccountToken not false)

| | |
|:--|:--|
| **Rule ID** | `workload-sa-token-automount` |
| **Domain** | `workload_pod_security` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K03 — Secrets Management Failures | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.1.6 — Service Account Tokens only mounted where necessary | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Steal Application Access Token (`T1528`) | [Reference](https://attack.mitre.org/techniques/T1528/) |

##### 💥 Impact

If the container is compromised, the mounted token is immediately usable by the attacker to call the Kubernetes API as that ServiceAccount — credential theft that requires no further exploitation step, and one of the most common real-world Kubernetes attack-chain pivots.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** 'automountServiceAccountToken' is part of the Pod spec, which is immutable once the Pod is created — Kubernetes rejects patches to this field on a live Pod. This Pod has no owning controller, so it must be recreated directly (there is no Deployment/DaemonSet/etc. to roll out instead).

Manual steps:

1. 'automountServiceAccountToken' cannot be patched on a live, standalone Pod.
2. kubectl get pod cache-redis -n staging -o yaml > pod.yaml
3. Edit pod.yaml to set the corrected value, then:
4. kubectl delete pod cache-redis -n staging
5. kubectl apply -f pod.yaml

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod cache-redis -n staging -o jsonpath='{.spec.automountServiceAccountToken}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "automount": null
}
```
</details>

---

#### 9. 🟡 SA token auto-mounted

`Pod/nignx-web (production)`

##### Summary

This workload's ServiceAccount token is automatically mounted into the pod, even though most application containers never call the Kubernetes API.

> **Detected:** service-account token is auto-mounted (automountServiceAccountToken not false)

| | |
|:--|:--|
| **Rule ID** | `workload-sa-token-automount` |
| **Domain** | `workload_pod_security` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K03 — Secrets Management Failures | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.1.6 — Service Account Tokens only mounted where necessary | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Steal Application Access Token (`T1528`) | [Reference](https://attack.mitre.org/techniques/T1528/) |

##### 💥 Impact

If the container is compromised, the mounted token is immediately usable by the attacker to call the Kubernetes API as that ServiceAccount — credential theft that requires no further exploitation step, and one of the most common real-world Kubernetes attack-chain pivots.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** 'automountServiceAccountToken' is part of the Pod spec, which is immutable once the Pod is created — Kubernetes rejects patches to this field on a live Pod. This Pod has no owning controller, so it must be recreated directly (there is no Deployment/DaemonSet/etc. to roll out instead).

Manual steps:

1. 'automountServiceAccountToken' cannot be patched on a live, standalone Pod.
2. kubectl get pod nignx-web -n production -o yaml > pod.yaml
3. Edit pod.yaml to set the corrected value, then:
4. kubectl delete pod nignx-web -n production
5. kubectl apply -f pod.yaml

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod nignx-web -n production -o jsonpath='{.spec.automountServiceAccountToken}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "automount": null
}
```
</details>

---

#### 10. 🟡 SA token auto-mounted

`Pod/aws-node-64w2k (kube-system)`

##### Summary

This workload's ServiceAccount token is automatically mounted into the pod, even though most application containers never call the Kubernetes API.

> **Detected:** service-account token is auto-mounted (automountServiceAccountToken not false)

| | |
|:--|:--|
| **Rule ID** | `workload-sa-token-automount` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `DaemonSet/aws-node (kube-system)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K03 — Secrets Management Failures | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.1.6 — Service Account Tokens only mounted where necessary | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Steal Application Access Token (`T1528`) | [Reference](https://attack.mitre.org/techniques/T1528/) |

##### 💥 Impact

If the container is compromised, the mounted token is immediately usable by the attacker to call the Kubernetes API as that ServiceAccount — credential theft that requires no further exploitation step, and one of the most common real-world Kubernetes attack-chain pivots.

##### 🛠️ Remediation

**Disable service-account token automount**

```bash
kubectl patch daemonset aws-node -n kube-system -p '{"spec": {"template": {"spec": {"automountServiceAccountToken": false}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      automountServiceAccountToken: false
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo daemonset/aws-node -n kube-system
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod aws-node-64w2k -n kube-system -o jsonpath='{.spec.automountServiceAccountToken}'
```

_Post-remediation check:_

```bash
kubectl get daemonset aws-node -n kube-system -o yaml
kubectl rollout status daemonset/aws-node -n kube-system
```

<details><summary>⚠️ Warnings</summary>

- This appears to be a Kubernetes/EKS managed component. Verify vendor documentation before changing its security context because the recommended hardening may break cluster functionality.

</details>

<details><summary>🔎 Evidence</summary>

```json
{
  "automount": null
}
```
</details>

---

#### 11. 🟡 SA token auto-mounted

`ReplicaSet/payment-api-7d9f8c9d76 (production)`

##### Summary

This workload's ServiceAccount token is automatically mounted into the pod, even though most application containers never call the Kubernetes API.

> **Detected:** service-account token is auto-mounted (automountServiceAccountToken not false)

| | |
|:--|:--|
| **Rule ID** | `workload-sa-token-automount` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K03 — Secrets Management Failures | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.1.6 — Service Account Tokens only mounted where necessary | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Steal Application Access Token (`T1528`) | [Reference](https://attack.mitre.org/techniques/T1528/) |

##### 💥 Impact

If the container is compromised, the mounted token is immediately usable by the attacker to call the Kubernetes API as that ServiceAccount — credential theft that requires no further exploitation step, and one of the most common real-world Kubernetes attack-chain pivots.

##### 🛠️ Remediation

**Disable service-account token automount**

```bash
kubectl patch replicaset payment-api-7d9f8c9d76 -n production -p '{"spec": {"template": {"spec": {"automountServiceAccountToken": false}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      automountServiceAccountToken: false
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
# snapshot BEFORE applying: kubectl get replicaset payment-api-7d9f8c9d76 -n production -o yaml > /snapshots/ReplicaSet-payment-api-7d9f8c9d76.yaml
kubectl apply -f /snapshots/ReplicaSet-payment-api-7d9f8c9d76.yaml
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get replicaset payment-api-7d9f8c9d76 -n production -o jsonpath='{.spec.automountServiceAccountToken}'
```

_Post-remediation check:_

```bash
kubectl get replicaset payment-api-7d9f8c9d76 -n production -o yaml
```

<details><summary>🔎 Evidence</summary>

```json
{
  "automount": null
}
```
</details>

---

#### 12. 🟡 Writable root filesystem

`Pod/payment-api (production)`

##### Summary

The container's root filesystem is writable (`readOnlyRootFilesystem` is not `true`).

> **Detected:** container 'app' has a writable root filesystem (readOnlyRootFilesystem not true)

| | |
|:--|:--|
| **Rule ID** | `workload-writable-root-fs` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Persistence | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

A writable root filesystem lets an attacker who achieves code execution in the container persist a backdoor binary or modify application code in place, surviving until the pod is next restarted — an unnecessary window for most stateless application workloads.

##### 🛠️ Remediation

**Set readOnlyRootFilesystem**

```bash
kubectl patch deployment payment-api -n production -p '{"spec": {"template": {"spec": {"containers": [{"securityContext": {"readOnlyRootFilesystem": true}, "name": "app"}]}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      containers:
        - securityContext:
            readOnlyRootFilesystem: true
          name: app
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo deployment/payment-api -n production
```
</details>

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.containers[*].securityContext.readOnlyRootFilesystem}'
```

_Post-remediation check:_

```bash
kubectl get deployment payment-api -n production -o yaml
kubectl rollout status deployment/payment-api -n production
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "app"
}
```
</details>

---

#### 13. 🟡 Writable root filesystem

`Pod/cache-redis (staging)`

##### Summary

The container's root filesystem is writable (`readOnlyRootFilesystem` is not `true`).

> **Detected:** container 'redis' has a writable root filesystem (readOnlyRootFilesystem not true)

| | |
|:--|:--|
| **Rule ID** | `workload-writable-root-fs` |
| **Domain** | `workload_pod_security` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Persistence | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

A writable root filesystem lets an attacker who achieves code execution in the container persist a backdoor binary or modify application code in place, surviving until the pod is next restarted — an unnecessary window for most stateless application workloads.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** 'securityContext.readOnlyRootFilesystem' is part of the Pod spec, which is immutable once the Pod is created — Kubernetes rejects patches to this field on a live Pod. This Pod has no owning controller, so it must be recreated directly (there is no Deployment/DaemonSet/etc. to roll out instead).

Manual steps:

1. 'securityContext.readOnlyRootFilesystem' cannot be patched on a live, standalone Pod.
2. kubectl get pod cache-redis -n staging -o yaml > pod.yaml
3. Edit pod.yaml to set the corrected value, then:
4. kubectl delete pod cache-redis -n staging
5. kubectl apply -f pod.yaml

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod cache-redis -n staging -o jsonpath='{.spec.containers[*].securityContext.readOnlyRootFilesystem}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "redis"
}
```
</details>

---

#### 14. 🟡 Writable root filesystem

`Pod/aws-node-64w2k (kube-system)`

##### Summary

The container's root filesystem is writable (`readOnlyRootFilesystem` is not `true`).

> **Detected:** container 'aws-node' has a writable root filesystem (readOnlyRootFilesystem not true)

| | |
|:--|:--|
| **Rule ID** | `workload-writable-root-fs` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `DaemonSet/aws-node (kube-system)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Persistence | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

A writable root filesystem lets an attacker who achieves code execution in the container persist a backdoor binary or modify application code in place, surviving until the pod is next restarted — an unnecessary window for most stateless application workloads.

##### 🛠️ Remediation

**Set readOnlyRootFilesystem**

```bash
kubectl patch daemonset aws-node -n kube-system -p '{"spec": {"template": {"spec": {"containers": [{"securityContext": {"readOnlyRootFilesystem": true}, "name": "aws-node"}]}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      containers:
        - securityContext:
            readOnlyRootFilesystem: true
          name: aws-node
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo daemonset/aws-node -n kube-system
```
</details>

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod aws-node-64w2k -n kube-system -o jsonpath='{.spec.containers[*].securityContext.readOnlyRootFilesystem}'
```

_Post-remediation check:_

```bash
kubectl get daemonset aws-node -n kube-system -o yaml
kubectl rollout status daemonset/aws-node -n kube-system
```

<details><summary>⚠️ Warnings</summary>

- This appears to be a Kubernetes/EKS managed component. Verify vendor documentation before changing its security context because the recommended hardening may break cluster functionality.

</details>

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "aws-node"
}
```
</details>

---

#### 15. 🟡 No seccomp profile

`Pod/payment-api (production)`

##### Summary

The container has no seccomp profile applied — every syscall the kernel exposes is available to it by default.

> **Detected:** container 'app' has no seccomp profile

| | |
|:--|:--|
| **Rule ID** | `workload-no-seccomp` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.7.2 — Ensure seccomp profile is set to docker/default in Pod definitions | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Defense Evasion | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Seccomp is one of the cheapest, highest-value hardening layers available: applying `RuntimeDefault` alone blocks dozens of syscalls with no legitimate use in a typical application container, meaningfully shrinking what a post-exploitation payload can actually do even after achieving code execution.

##### 🛠️ Remediation

**Harden pod securityContext (runAsNonRoot + seccompProfile)**

```bash
kubectl patch deployment payment-api -n production -p '{"spec": {"template": {"spec": {"securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}}}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo deployment/payment-api -n production
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tutorials/security/seccomp/) · [Kubernetes docs](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.securityContext.seccompProfile.type} {.spec.containers[*].securityContext.seccompProfile.type}'
```

_Post-remediation check:_

```bash
kubectl get deployment payment-api -n production -o yaml
kubectl rollout status deployment/payment-api -n production
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "app"
}
```
</details>

---

#### 16. 🟡 No seccomp profile

`Pod/cache-redis (staging)`

##### Summary

The container has no seccomp profile applied — every syscall the kernel exposes is available to it by default.

> **Detected:** container 'redis' has no seccomp profile

| | |
|:--|:--|
| **Rule ID** | `workload-no-seccomp` |
| **Domain** | `workload_pod_security` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.7.2 — Ensure seccomp profile is set to docker/default in Pod definitions | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Defense Evasion | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Seccomp is one of the cheapest, highest-value hardening layers available: applying `RuntimeDefault` alone blocks dozens of syscalls with no legitimate use in a typical application container, meaningfully shrinking what a post-exploitation payload can actually do even after achieving code execution.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** 'securityContext' is part of the Pod spec, which is immutable once the Pod is created — Kubernetes rejects patches to this field on a live Pod. This Pod has no owning controller, so it must be recreated directly (there is no Deployment/DaemonSet/etc. to roll out instead).

Manual steps:

1. 'securityContext' cannot be patched on a live, standalone Pod.
2. kubectl get pod cache-redis -n staging -o yaml > pod.yaml
3. Edit pod.yaml to set the corrected value, then:
4. kubectl delete pod cache-redis -n staging
5. kubectl apply -f pod.yaml

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tutorials/security/seccomp/) · [Kubernetes docs](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod cache-redis -n staging -o jsonpath='{.spec.securityContext.seccompProfile.type} {.spec.containers[*].securityContext.seccompProfile.type}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "redis"
}
```
</details>

---

#### 17. 🟡 No seccomp profile

`Pod/aws-node-64w2k (kube-system)`

##### Summary

The container has no seccomp profile applied — every syscall the kernel exposes is available to it by default.

> **Detected:** container 'aws-node' has no seccomp profile

| | |
|:--|:--|
| **Rule ID** | `workload-no-seccomp` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `DaemonSet/aws-node (kube-system)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |
| CIS Kubernetes Benchmark v1.8 | 5.7.2 — Ensure seccomp profile is set to docker/default in Pod definitions | [Reference](https://www.cisecurity.org/benchmark/kubernetes) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Defense Evasion | Deploy Container (`T1610`) | [Reference](https://attack.mitre.org/techniques/T1610/) |

##### 💥 Impact

Seccomp is one of the cheapest, highest-value hardening layers available: applying `RuntimeDefault` alone blocks dozens of syscalls with no legitimate use in a typical application container, meaningfully shrinking what a post-exploitation payload can actually do even after achieving code execution.

##### 🛠️ Remediation

**Harden pod securityContext (runAsNonRoot + seccompProfile)**

```bash
kubectl patch daemonset aws-node -n kube-system -p '{"spec": {"template": {"spec": {"securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}}}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo daemonset/aws-node -n kube-system
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/tutorials/security/seccomp/) · [Kubernetes docs](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod aws-node-64w2k -n kube-system -o jsonpath='{.spec.securityContext.seccompProfile.type} {.spec.containers[*].securityContext.seccompProfile.type}'
```

_Post-remediation check:_

```bash
kubectl get daemonset aws-node -n kube-system -o yaml
kubectl rollout status daemonset/aws-node -n kube-system
```

<details><summary>⚠️ Warnings</summary>

- This appears to be a Kubernetes/EKS managed component. Verify vendor documentation before changing its security context because the recommended hardening may break cluster functionality.

</details>

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "aws-node"
}
```
</details>

---

#### 18. 🟡 Missing resource limits

`Pod/payment-api (production)`

##### Summary

The container has no `resources.limits` set for CPU or memory.

> **Detected:** container 'app' has no resource limits (DoS amplification)

| | |
|:--|:--|
| **Rule ID** | `workload-missing-limits` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `Deployment/payment-api (production)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Impact | Endpoint Denial of Service (`T1499`) | [Reference](https://attack.mitre.org/techniques/T1499/) |

##### 💥 Impact

A single misbehaving or compromised container without limits can consume all available CPU/memory on its node, starving every other workload scheduled there — a self-inflicted or attacker-triggered denial-of-service that has no per-container blast-radius boundary.

##### 🛠️ Remediation

**Set container resource limits (adjust values for the workload)**

```bash
kubectl patch deployment payment-api -n production -p '{"spec": {"template": {"spec": {"containers": [{"resources": {"limits": {"cpu": "500m", "memory": "512Mi"}}, "name": "app"}]}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      containers:
        - resources:
            limits:
              cpu: 500m
              memory: 512Mi
          name: app
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo deployment/payment-api -n production
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.containers[*].resources.limits}'
```

_Post-remediation check:_

```bash
kubectl get deployment payment-api -n production -o yaml
kubectl rollout status deployment/payment-api -n production
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "app"
}
```
</details>

---

#### 19. 🟡 Missing resource limits

`Pod/cache-redis (staging)`

##### Summary

The container has no `resources.limits` set for CPU or memory.

> **Detected:** container 'redis' has no resource limits (DoS amplification)

| | |
|:--|:--|
| **Rule ID** | `workload-missing-limits` |
| **Domain** | `workload_pod_security` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Impact | Endpoint Denial of Service (`T1499`) | [Reference](https://attack.mitre.org/techniques/T1499/) |

##### 💥 Impact

A single misbehaving or compromised container without limits can consume all available CPU/memory on its node, starving every other workload scheduled there — a self-inflicted or attacker-triggered denial-of-service that has no per-container blast-radius boundary.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** 'resources.limits' is part of the Pod spec, which is immutable once the Pod is created — Kubernetes rejects patches to this field on a live Pod. This Pod has no owning controller, so it must be recreated directly (there is no Deployment/DaemonSet/etc. to roll out instead).

Manual steps:

1. 'resources.limits' cannot be patched on a live, standalone Pod.
2. kubectl get pod cache-redis -n staging -o yaml > pod.yaml
3. Edit pod.yaml to set the corrected value, then:
4. kubectl delete pod cache-redis -n staging
5. kubectl apply -f pod.yaml

_References:_ [Kubernetes docs](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod cache-redis -n staging -o jsonpath='{.spec.containers[*].resources.limits}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "redis"
}
```
</details>

---

#### 20. 🟡 Missing resource limits

`Pod/aws-node-64w2k (kube-system)`

##### Summary

The container has no `resources.limits` set for CPU or memory.

> **Detected:** container 'aws-node' has no resource limits (DoS amplification)

| | |
|:--|:--|
| **Rule ID** | `workload-missing-limits` |
| **Domain** | `workload_pod_security` |
| **Owner resource** | `DaemonSet/aws-node (kube-system)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K01 — Insecure Workload Configurations | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Impact | Endpoint Denial of Service (`T1499`) | [Reference](https://attack.mitre.org/techniques/T1499/) |

##### 💥 Impact

A single misbehaving or compromised container without limits can consume all available CPU/memory on its node, starving every other workload scheduled there — a self-inflicted or attacker-triggered denial-of-service that has no per-container blast-radius boundary.

##### 🛠️ Remediation

**Set container resource limits (adjust values for the workload)**

```bash
kubectl patch daemonset aws-node -n kube-system -p '{"spec": {"template": {"spec": {"containers": [{"resources": {"limits": {"cpu": "500m", "memory": "512Mi"}}, "name": "aws-node"}]}}}}'
```

<details><summary>Alternative — apply via YAML</summary>

```yaml
spec:
  template:
    spec:
      containers:
        - resources:
            limits:
              cpu: 500m
              memory: 512Mi
          name: aws-node
```

</details>

<details><summary>Rollback (if the fix causes issues)</summary>

```bash
kubectl rollout undo daemonset/aws-node -n kube-system
```
</details>

_References:_ [Kubernetes docs](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod aws-node-64w2k -n kube-system -o jsonpath='{.spec.containers[*].resources.limits}'
```

_Post-remediation check:_

```bash
kubectl get daemonset aws-node -n kube-system -o yaml
kubectl rollout status daemonset/aws-node -n kube-system
```

<details><summary>⚠️ Warnings</summary>

- This appears to be a Kubernetes/EKS managed component. Verify vendor documentation before changing its security context because the recommended hardening may break cluster functionality.

</details>

<details><summary>🔎 Evidence</summary>

```json
{
  "container": "aws-node"
}
```
</details>

---

#### 21. 🟡 Managed identity reachable

`ServiceAccount/shared-sa (production)`

##### Summary

A managed cloud identity's credentials are reachable from within a pod on this node.

> **Detected:** ServiceAccount is bound to a cloud managed identity; ensure metadata API egress is restricted and the identity is least-privilege

| | |
|:--|:--|
| **Rule ID** | `iam-managed-identity-reachable` |
| **Domain** | `cloud_iam` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K08 — Cluster-to-Cloud Lateral Movement | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Credential Access | Cloud Instance Metadata API (`T1552.005`) | [Reference](https://attack.mitre.org/techniques/T1552/005/) |

##### 💥 Impact

Combined with an open path to the metadata API (see `net-metadata-api-open`), this is the concrete mechanism by which a container compromise becomes a cloud-account compromise — the credential is sitting one unauthenticated HTTP request away.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl exec -n production shared-sa -- curl -s -m 2 -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01' 2>/dev/null
```

<details><summary>🔎 Evidence</summary>

```json
{
  "annotations": {
    "eks.amazonaws.com/role-arn": "arn:aws:iam::111:role/shared"
  }
}
```
</details>

---

#### 22. 🟡 Image not signed

`Pod/payment-api (production)`

##### Summary

The container image has no cosign/notary signature verifying its provenance.

> **Detected:** image 'nginx:latest' has no cosign/notary signature annotation

| | |
|:--|:--|
| **Rule ID** | `img-not-signed` |
| **Domain** | `image_supply_chain` |
| **Owner resource** | `ReplicaSet/payment-api-7d9f8c9d76 (production)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 4.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K07 — Misconfigured & Vulnerable Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Initial Access | Implant Internal Image (`T1525`) | [Reference](https://attack.mitre.org/techniques/T1525/) |

##### 💥 Impact

Without signature verification, the cluster cannot distinguish between the image the team actually built and one substituted at the registry (via a compromised CI pipeline, a registry-level compromise, or a man-in-the-middle) — image signing is the control that closes that gap.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** This finding's fix is a manual/policy action, not a single safe kubectl command.

Manual steps:

1. Require signed images (policy)
2. # deploy a Kyverno/cosign verifyImages policy

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
cosign verify payment-api 2>&1 | head -5
```

<details><summary>🔎 Evidence</summary>

```json
{
  "image": "nginx:latest"
}
```
</details>

---

<a id="sev-low"></a>
### 🟢 LOW — 1 finding(s)

#### 1. 🟢 Stale-image pull policy

`Pod/payment-api (production)`

##### Summary

The container's `imagePullPolicy` is `IfNotPresent` against a tag that isn't pinned to an immutable digest.

> **Detected:** container 'app' may run a stale cached image (IfNotPresent + :latest)

| | |
|:--|:--|
| **Rule ID** | `img-pull-policy` |
| **Domain** | `image_supply_chain` |
| **Owner resource** | `ReplicaSet/payment-api-7d9f8c9d76 (production)` |
| **Exploitability** | Local |
| **Blast radius** | Pod |
| **Risk score** | 1.0 |

##### 📚 Standards & Benchmark Mapping

| Framework | Control | Reference |
|:--|:--|:--|
| OWASP Kubernetes Top 10 (2025) | K07 — Misconfigured & Vulnerable Components | [Reference](https://owasp.org/www-project-kubernetes-top-ten/) |

##### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Reference |
|:--|:--|:--|
| Initial Access | Implant Internal Image (`T1525`) | [Reference](https://attack.mitre.org/techniques/T1525/) |

##### 💥 Impact

A node that already has a stale cached copy of the tag will keep running it even after a fix has been pushed to the registry under the same tag — a patched vulnerability can remain exploitable on some nodes well after the image was 'fixed'.

##### 🛠️ Remediation

⚠️ **This remediation cannot be safely automated.** No remediation playbook is registered for this rule.

Manual steps:

1. No remediation is registered for this rule.

##### ✅ Validation — How to Reproduce / Verify

Run before remediating to confirm the finding, and again afterward to confirm it cleared:

```bash
kubectl get pod payment-api -n production -o jsonpath='{.spec.containers[*].imagePullPolicy}'
```

<details><summary>🔎 Evidence</summary>

```json
{
  "image": "nginx:latest"
}
```
</details>

---

[↑ top](#top)

---

<a id="remediation"></a>
## 5. 🛠️ Prioritized Remediation Plan

Fixes ordered by risk (highest first). Every command is shown exactly as it would run — **review before applying**; destructive actions require confirmation through the Remediation Agent.

| # | Priority | Finding | Resource | Fix |
|--:|:--|:--|:--|:--|
| 1 | 🔴 CRITICAL | Kubernetes dashboard exposed | `Service/kubernetes-dashboard (kubernetes-dashboard)` | `kubectl -n kubernetes-dashboard patch svc kubernetes-dashboard -p '…` |
| 2 | 🔴 CRITICAL | cluster-admin on default SA | `ClusterRoleBinding/default-admin` | `kubectl delete clusterrolebinding default-admin` |
| 3 | 🔴 CRITICAL | Suspicious mutating webhook | `MutatingWebhookConfiguration/evil-webhook` | `kubectl delete mutatingwebhookconfiguration evil-webhook` |
| 4 | 🔴 CRITICAL | Privileged container | `Pod/payment-api (production)` | `kubectl patch deployment payment-api -n production -p '{"spec": {"t…` |
| 5 | 🔴 CRITICAL | Privileged container | `Pod/aws-node-64w2k (kube-system)` | `kubectl patch daemonset aws-node -n kube-system -p '{"spec": {"temp…` |
| 6 | 🔴 CRITICAL | Host PID namespace shared | `Pod/payment-api (production)` | `kubectl patch deployment payment-api -n production -p '{"spec": {"t…` |
| 7 | 🟠 HIGH | Metadata API not blocked | `Namespace/production` | `kubectl apply -n default -f - <<'EOF' apiVersion: networking.k8s.io…` |
| 8 | 🟠 HIGH | Metadata API not blocked | `Namespace/staging` | `kubectl apply -n default -f - <<'EOF' apiVersion: networking.k8s.io…` |
| 9 | 🟠 HIGH | Host network shared | `Pod/payment-api (production)` | `kubectl patch deployment payment-api -n production -p '{"spec": {"t…` |
| 10 | 🟠 HIGH | Host network shared | `Pod/aws-node-64w2k (kube-system)` | `kubectl patch daemonset aws-node -n kube-system -p '{"spec": {"temp…` |
| 11 | 🟠 HIGH | Host IPC namespace shared | `Pod/payment-api (production)` | `kubectl patch deployment payment-api -n production -p '{"spec": {"t…` |
| 12 | 🟠 HIGH | PSA not enforcing 'restricted' | `Namespace/production` | `kubectl label ns production pod-security.kubernetes.io/enforce=rest…` |
| 13 | 🟠 HIGH | PSA not enforcing 'restricted' | `Namespace/staging` | `kubectl label ns staging pod-security.kubernetes.io/enforce=restric…` |
| 14 | 🟠 HIGH | Namespace without NetworkPolicy | `Namespace/production` | `kubectl apply -n default -f - <<'EOF' apiVersion: networking.k8s.io…` |
| 15 | 🟠 HIGH | Namespace without NetworkPolicy | `Namespace/staging` | `kubectl apply -n default -f - <<'EOF' apiVersion: networking.k8s.io…` |

[↑ top](#top)

---

<a id="appendix"></a>
## 6. 📎 Appendix

<details><summary><strong>Scan metadata</strong></summary>

| Key | Value |
|:--|:--|
| Scan ID | `scan-20260718-fadb` |
| Generated | 2026-07-18T02:48:28Z |
| Tool version | k8smatrixwarden 1.0 |
| Mode | mock |
| Scope | cluster-wide |
| Selector | all-rules |
| Rules evaluated | 56 |

</details>

<details><summary><strong>Rules evaluated in this scan</strong></summary>

```
admission-malicious-webhook, admission-webhook-failurepolicy, admission-sidecar-injection, cronjob-suspicious
as-sa-fanout, iam-overpermissive, iam-node-role-broad, iam-managed-identity-reachable
apiserver-anonymous-auth, apiserver-insecure-port, apiserver-audit-logging, etcd-encryption-missing
etcd-client-cert-auth, kubelet-anonymous-auth, kubelet-read-only-port, kubelet-authz-always-allow
deprecated-k8s-version, compliance-psa-not-restricted, img-pull-policy, img-not-signed
img-typosquat, img-kubeconfig-embedded, net-nodeport-service, net-lb-no-source-range
net-dashboard-exposed, net-ingress-no-tls, net-no-networkpolicy, net-metadata-api-open
rbac-wildcard-verbs, rbac-wildcard-resources, rbac-cluster-admin-default-sa, rbac-bind-escalate-verbs
rbac-secret-read-broad, rbac-can-delete-events, rbac-coredns-configmap-write, sec-env-var-secrets
sec-configmap-credentials, sec-mounted-cloud-creds, sec-etcd-not-encrypted, workload-privileged-container
workload-run-as-root, workload-allow-priv-escalation, workload-writable-root-fs, workload-dangerous-caps
workload-caps-not-dropped, workload-host-pid, workload-host-network, workload-host-ipc
workload-docker-socket, workload-hostpath-root, workload-hostpath-writable, workload-missing-limits
workload-no-seccomp, workload-sa-token-automount, workload-latest-tag, workload-sshd-present
```

</details>

---
<sub>Generated by 🛡️ k8smatrixwarden 1.0 — MITRE ATT&CK-aligned Kubernetes security scanner.</sub>