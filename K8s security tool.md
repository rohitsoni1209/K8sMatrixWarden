<p align="center">
  <img src="https://kubernetes.io/images/kubernetes-horizontal-color.png" width="300"/>
</p>

<h1 align="center">🛡️ K8s Security Tool</h1>

<p align="center">
  <strong>AI-Powered Kubernetes Security Platform</strong><br/>
  <em>Automated Attack Surface Mapping · Vulnerability Detection · Runtime Protection · Intelligent Remediation</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white"/>
  <img src="https://img.shields.io/badge/Version-2.0-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Status-Design%20Phase-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Reports-Downloadable-blue?style=for-the-badge&logo=markdown&logoColor=white"/>
</p>

---

## 📑 Table of Contents

<details>
<summary><strong>Click to expand full table of contents</strong></summary>

| # | Section | Description |
|---|---------|-------------|
| 1 | [Executive Summary](#1-executive-summary) | High-level overview and value proposition |
| 2 | [Problem Statement](#2-problem-statement) | Why this tool exists |
| 3 | [Architecture](#3-architecture) | System design, agents, data flow |
| 4 | [Orchestrator Agent](#4-orchestrator-agent) | Intent classification, routing, safety controls |
| 5 | [Scanner Agent](#5-scanner-agent) | 8 scanning modules in detail |
| 6 | [Runtime Agent](#6-runtime-agent) | Real-time threat detection & monitoring |
| 7 | [Remediation Agent](#7-remediation-agent) | Auto-fix engine with rollback |
| 8 | [K8s Security MCP Server](#8-k8s-security-mcp-server) | Knowledge layer — datasets & commands |
| 9 | [Kubernetes Attack Surface Map](#9-kubernetes-attack-surface-map) | 5-layer attack surface breakdown |
| 10 | [MITRE ATT&CK for Kubernetes](#10-mitre-attck-for-kubernetes) | Full threat matrix & detection mapping |
| 11 | [OWASP Kubernetes Top 10 (2025)](#11-owasp-kubernetes-top-10-2025) | Complete coverage with detection & remediation |
| 12 | [Kubernetes Goat — Vulnerability Scenarios](#12-kubernetes-goat--vulnerability-scenarios) | All 22 scenarios mapped |
| 13 | [Real-World CVEs & Attack Patterns](#13-real-world-cves--attack-patterns) | 15+ CVEs and 10+ attack writeups |
| 14 | [Scanner Configuration Spec](#14-scanner-configuration-spec) | YAML-based scan rule definitions |
| 15 | [End-to-End Workflows](#15-end-to-end-workflows) | 5 real-world usage scenarios |
| 16 | [Security Scoring & Reporting](#16-security-scoring--reporting) | Risk scoring model & report formats |
| 16.4 | [Report Download System](#164-report-download-system) | CLI, API, and web-based report download |
| 17 | [Deployment Architecture](#17-deployment-architecture) | How the tool runs inside K8s |
| 18 | [RBAC Configuration](#18-rbac-configuration) | Least-privilege roles for the tool itself |
| 19 | [Open-Source Tool Integrations](#19-open-source-tool-integrations) | 15+ integrated tools |
| 20 | [Alerting & Notification](#20-alerting--notification) | Alert routing & escalation |
| 21 | [Roadmap](#21-roadmap) | 4-phase delivery plan |
| 22 | [Glossary](#22-glossary) | Key terms & acronyms |
| 23 | [References](#23-references) | Standards, frameworks, learning resources |

</details>

---

## 1. Executive Summary

### What

**K8s Security Tool** is an AI-powered, Kubernetes-native security platform that continuously scans, monitors, and secures Kubernetes clusters. It uses a **multi-agent architecture** where specialized agents collaborate to detect vulnerabilities, map attack surfaces, enforce compliance, and auto-remediate security issues — all within the Kubernetes ecosystem.

### Why

Kubernetes clusters are complex, dynamic, and present a massive attack surface. Misconfigurations are the #1 cause of K8s breaches. Manual security reviews don't scale. Existing tools scan but don't remediate. This tool closes the loop: **Detect → Analyze → Fix → Verify**.

### How

```
┌──────────────┐     ┌─────────────────┐     ┌────────────────┐     ┌──────────────┐
│              │     │                 │     │                │     │              │
│   DETECT     │────▶│    ANALYZE      │────▶│   REMEDIATE    │────▶│   VERIFY     │
│              │     │                 │     │  (with user    │     │              │
│  Scan pods,  │     │  Map to MITRE,  │     │   approval)    │     │  Re-scan to  │
│  RBAC, net,  │     │  OWASP, CIS.   │     │                │     │  confirm fix │
│  images,     │     │  Score risk.    │     │  Apply patches,│     │              │
│  secrets     │     │  Prioritize.    │     │  generate      │     │  Score       │
│              │     │                 │     │  policies      │     │  improved?   │
└──────────────┘     └─────────────────┘     └────────────────┘     └──────────────┘
```

### Key Capabilities

| Capability | Description |
|---|---|
| 🗺️ **Attack Surface Mapping** | Enumerates every external entry point, container escape vector, privilege escalation path, and lateral movement route in the cluster |
| 🔍 **Deep Vulnerability Scanning** | 8 scanning modules covering control plane, workloads, RBAC, network, images, secrets, compliance, and attack surface |
| 🛡️ **Runtime Threat Detection** | Real-time syscall monitoring (Falco/Tetragon), behavioral baselines, container drift detection, K8s audit event analysis |
| 🔧 **Intelligent Remediation** | AI-generated fixes with exact `kubectl` commands shown before execution, rollback on failure, audit trail for every change |
| 📊 **Compliance Enforcement** | Continuous CIS Kubernetes Benchmark, Pod Security Standards, NSA/CISA hardening checks with drift alerting |
| 🎯 **Threat Classification** | Every finding mapped to MITRE ATT&CK techniques and OWASP K8s Top 10 categories |

---

## 2. Problem Statement

### The Kubernetes Security Challenge

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   "67% of companies have delayed or slowed deployment of Kubernetes     │
│    due to security concerns"  — Red Hat State of K8s Security 2024     │
│                                                                         │
│   "Nearly 90% of containers run on Kubernetes, yet most organizations  │
│    lack visibility into K8s-specific threats"  — Sysdig 2024 Report    │
│                                                                         │
│   "Misconfigurations account for over 40% of K8s security incidents"   │
│    — NSA/CISA Kubernetes Hardening Guidance                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### What Existing Tools Lack

| Gap | How K8s Security Tool Solves It |
|---|---|
| **Scan-only, no remediation** — tools report issues but don't fix them | Auto-remediation engine with human-in-the-loop approval |
| **Point-in-time scans** — no continuous monitoring | Runtime Agent provides 24/7 syscall + audit event monitoring |
| **Siloed tools** — separate tools for images, RBAC, network, compliance | Single platform with 8 integrated scanning modules |
| **No threat context** — findings lack attack chain mapping | Every finding mapped to MITRE ATT&CK + OWASP K8s Top 10 |
| **No prioritization** — hundreds of findings with no risk ranking | AI-driven risk scoring with severity + exploitability + blast radius |
| **Cloud-coupled** — many tools only work with specific cloud providers | Cloud-agnostic — works on EKS, AKS, GKE, bare-metal, k3s, kind |

---

## 3. Architecture

### 3.1 System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│   ┌─────────────────────────────────┐                                           │
│   │   👤 Security Engineer           │                                           │
│   │   ┌───────┐ ┌──────┐ ┌───────┐  │                                           │
│   │   │  CLI  │ │ Chat │ │ Web   │  │                                           │
│   │   │       │ │      │ │ UI    │  │                                           │
│   │   └───┬───┘ └──┬───┘ └───┬───┘  │                                           │
│   └───────┼────────┼─────────┼──────┘                                           │
│           └────────┼─────────┘                                                  │
│                    ▼                                                            │
│   ┌────────────────────────────────────────────────────────────┐                │
│   │                  🧠 ORCHESTRATOR AGENT                      │                │
│   │                                                            │                │
│   │   ┌──────────────┐ ┌─────────────┐ ┌───────────────────┐  │                │
│   │   │    Intent     │ │   Request   │ │    Response       │  │                │
│   │   │  Classifier   │ │   Router    │ │    Aggregator     │  │                │
│   │   └──────────────┘ └─────────────┘ └───────────────────┘  │                │
│   │                                                            │                │
│   │   ┌──────────────┐ ┌─────────────┐ ┌───────────────────┐  │                │
│   │   │   Severity    │ │   MITRE     │ │   Confirmation    │  │                │
│   │   │   Scorer      │ │   Mapper    │ │   Controller      │  │                │
│   │   └──────────────┘ └─────────────┘ └───────────────────┘  │                │
│   └────────┬───────────────────┬───────────────────┬───────────┘                │
│            │                   │                   │                             │
│            ▼                   ▼                   ▼                             │
│   ┌────────────────┐ ┌────────────────┐ ┌──────────────────┐                    │
│   │  🔍 SCANNER     │ │  🛡️ RUNTIME    │ │  🔧 REMEDIATION   │                    │
│   │     AGENT       │ │     AGENT     │ │     AGENT        │                    │
│   │                 │ │               │ │                  │                    │
│   │ ┌─────────────┐│ │ ┌───────────┐ │ │ ┌──────────────┐ │                    │
│   │ │ Cluster &   ││ │ │ Syscall   │ │ │ │ Auto-Fix     │ │                    │
│   │ │ Control     ││ │ │ Monitor   │ │ │ │ Engine       │ │                    │
│   │ │ Plane       ││ │ │ (Falco/   │ │ │ │              │ │                    │
│   │ ├─────────────┤│ │ │ Tetragon) │ │ │ ├──────────────┤ │                    │
│   │ │ Workload &  ││ │ ├───────────┤ │ │ │ Policy       │ │                    │
│   │ │ Pod Security││ │ │ K8s Audit │ │ │ │ Generator    │ │                    │
│   │ ├─────────────┤│ │ │ Event     │ │ │ │              │ │                    │
│   │ │ RBAC &      ││ │ │ Analyzer  │ │ │ ├──────────────┤ │                    │
│   │ │ Identity    ││ │ ├───────────┤ │ │ │ Rollback     │ │                    │
│   │ ├─────────────┤│ │ │ Container │ │ │ │ Controller   │ │                    │
│   │ │ Network     ││ │ │ Drift     │ │ │ │              │ │                    │
│   │ │ Security    ││ │ │ Detector  │ │ │ ├──────────────┤ │                    │
│   │ ├─────────────┤│ │ ├───────────┤ │ │ │ Audit        │ │                    │
│   │ │ Image &     ││ │ │ Behavioral│ │ │ │ Trail        │ │                    │
│   │ │ Supply Chain││ │ │ Baseline  │ │ │ │ Logger       │ │                    │
│   │ ├─────────────┤│ │ │ Engine    │ │ │ └──────────────┘ │                    │
│   │ │ Secrets     ││ │ └───────────┘ │ │                  │                    │
│   │ ├─────────────┤│ │               │ │                  │                    │
│   │ │ CIS Bench & ││ │               │ │                  │                    │
│   │ │ Compliance  ││ │               │ │                  │                    │
│   │ ├─────────────┤│ │               │ │                  │                    │
│   │ │ Attack      ││ │               │ │                  │                    │
│   │ │ Surface Map ││ │               │ │                  │                    │
│   │ └─────────────┘│ │               │ │                  │                    │
│   └────────┬───────┘ └───────┬───────┘ └────────┬─────────┘                    │
│            │                 │                   │                              │
│            └─────────────────┼───────────────────┘                              │
│                              ▼                                                  │
│   ┌──────────────────────────────────────────────────────────────────┐          │
│   │                 📦 K8s SECURITY MCP SERVER                       │          │
│   │                                                                  │          │
│   │   ┌──────────────────┐ ┌──────────────────┐ ┌────────────────┐  │          │
│   │   │ 📘 Dataset 1:    │ │ 📗 Dataset 2:    │ │ 📙 Dataset 3:  │  │          │
│   │   │ kubectl Security │ │ Scanning Tool    │ │ Remediation    │  │          │
│   │   │ Commands         │ │ Commands         │ │ Playbooks      │  │          │
│   │   └──────────────────┘ └──────────────────┘ └────────────────┘  │          │
│   │                                                                  │          │
│   │   ┌──────────────────┐ ┌──────────────────┐                     │          │
│   │   │ 📕 Dataset 4:    │ │ 📒 Dataset 5:    │                     │          │
│   │   │ CVE Knowledge    │ │ Compliance       │                     │          │
│   │   │ Base             │ │ Rule Sets        │                     │          │
│   │   └──────────────────┘ └──────────────────┘                     │          │
│   └────────────────────────────────┬─────────────────────────────────┘          │
│                                    ▼                                            │
│   ┌──────────────────────────────────────────────────────────────────┐          │
│   │                 ☸️ TARGET KUBERNETES CLUSTER                      │          │
│   │                                                                  │          │
│   │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌─────────────┐  │          │
│   │  │  Control   │ │  Worker    │ │  Pods &    │ │  Network,   │  │          │
│   │  │  Plane     │ │  Nodes     │ │  Workloads │ │  RBAC &     │  │          │
│   │  │            │ │            │ │            │ │  Secrets    │  │          │
│   │  └────────────┘ └────────────┘ └────────────┘ └─────────────┘  │          │
│   └──────────────────────────────────────────────────────────────────┘          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Agent Summary

| Agent | Purpose | Runs As | Replicas |
|---|---|---|---|
| **🧠 Orchestrator** | Receives all requests, classifies intent, routes to agents, aggregates results, manages confirmations | Deployment | 1 |
| **🔍 Scanner** | All vulnerability scanning — 8 modules covering every K8s layer | Deployment (HPA) | 1–3 |
| **🛡️ Runtime** | Real-time monitoring — syscall, audit events, drift, behavioral anomalies | DaemonSet | 1 per node |
| **🔧 Remediation** | Executes fixes after user approval — patches, policies, rollbacks | Deployment | 1 |

### 3.3 Data Flow

```
                         ┌───────────────┐
                         │  User Request │
                         └───────┬───────┘
                                 │
                    ┌────────────▼────────────┐
                    │   🧠 Orchestrator Agent  │
                    │                          │
                    │  1. Classify intent      │
                    │  2. Extract scope         │
                    │  3. Route to agent(s)     │
                    └──┬──────────┬──────────┬─┘
                       │          │          │
            ┌──────────▼──┐  ┌───▼────┐  ┌──▼──────────┐
            │ 🔍 Scanner   │  │🛡️ Run- │  │🔧 Remediate │
            │    Agent     │  │  time  │  │   Agent     │
            └──────┬───────┘  └───┬────┘  └──┬──────────┘
                   │              │           │
            ┌──────▼──────────────▼───────────▼──────┐
            │        📦 K8s Security MCP Server       │
            │                                         │
            │  kubectl cmds · scan tools · fix cmds   │
            │  CVE database · compliance rules        │
            └──────────────────┬──────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  ☸️ K8s Cluster      │
                    │  (API Server, Pods,  │
                    │   Nodes, Network)    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Results returned    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼────────────┐
                    │   🧠 Orchestrator      │
                    │                        │
                    │  4. Aggregate results  │
                    │  5. Map → MITRE/OWASP  │
                    │  6. Score severity      │
                    │  7. Suggest fix         │
                    │  8. Ask confirmation    │
                    └──────────┬─────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   📊 Report to User  │
                    └─────────────────────┘
```

### 3.4 Design Principles

| # | Principle | Detail |
|---|---|---|
| 1 | **Kubernetes-Native** | Deployed as pods inside K8s. Scans K8s. Speaks K8s API. |
| 2 | **Agent-Based** | Specialized agents — each owns a domain. Orchestrator coordinates. |
| 3 | **MCP-Driven** | Agents don't hardcode commands — they query the MCP Server's trained datasets |
| 4 | **Human-in-the-Loop** | All destructive actions require explicit user confirmation |
| 5 | **Least Privilege** | Tool's own RBAC is read-only by default; write access scoped to Remediation Agent only |
| 6 | **Cloud-Agnostic** | Works on any K8s distribution — EKS, AKS, GKE, bare-metal, k3s, kind, minikube |
| 7 | **Extensible** | Pluggable scanning modules, custom rules, additional tool integrations |
| 8 | **Idempotent** | Running the same scan twice produces the same result; fixes are safe to re-apply |

---

## 4. Orchestrator Agent

### 4.1 Responsibilities

The Orchestrator is the **single entry point** for all user interactions. It never scans or fixes anything directly — it delegates to specialized agents.

```
                              User Request
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │     INTENT CLASSIFICATION     │
                    │                               │
                    │  "Scan pods in production"    │
                    │     → Intent: SCAN            │
                    │     → Scope: ns=production    │
                    │     → Resource: pods          │
                    │                               │
                    │  "Is my cluster secure?"      │
                    │     → Intent: AUDIT           │
                    │     → Scope: cluster-wide     │
                    │                               │
                    │  "Fix the RBAC issue"         │
                    │     → Intent: REMEDIATE       │
                    │     → Scope: specific finding │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │       REQUEST ROUTING         │
                    │                               │
                    │  SCAN / AUDIT / MAP ──▶ 🔍    │
                    │  MONITOR ────────────▶ 🛡️     │
                    │  REMEDIATE ──────────▶ 🔍 + 🔧 │
                    │  REPORT ────────────▶ 🔍 + 📊 │
                    │  INVESTIGATE ────────▶ 🔍 + 🛡️ │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │     RESPONSE ASSEMBLY         │
                    │                               │
                    │  • Collect agent results      │
                    │  • Map → MITRE ATT&CK ID      │
                    │  • Map → OWASP K8s Top 10     │
                    │  • Calculate risk score        │
                    │  • Rank by severity            │
                    │  • Generate fix suggestions    │
                    │  • Ask user confirmation       │
                    └──────────────────────────────┘
```

### 4.2 Supported Intents

| Intent | Description | Agent(s) Invoked |
|---|---|---|
| `SCAN` | Run vulnerability / config scan on specified scope | Scanner |
| `AUDIT` | Run compliance benchmark (CIS, PSS, NSA) | Scanner (Compliance module) |
| `MAP` | Map the cluster's complete attack surface | Scanner (Attack Surface module) |
| `MONITOR` | Enable or check real-time runtime monitoring | Runtime |
| `INVESTIGATE` | Deep-dive into a specific finding or suspicious activity | Scanner + Runtime |
| `REMEDIATE` | Fix an identified vulnerability | Scanner (analyze) → Remediation (fix) |
| `REPORT` | Generate a security report (PDF/JSON/Markdown/SARIF) | Scanner → Orchestrator (compile) |
| `DOWNLOAD` | Download a generated report in a specified format | Orchestrator → Report Store |

### 4.3 Safety Controls

> **⚠️ These rules are non-negotiable and cannot be overridden.**

| Rule | Enforcement |
|---|---|
| No auto-remediation without confirmation | Orchestrator blocks Remediation Agent until user types `Y` / confirms |
| Show exact changes before applying | Remediation Agent must output the exact `kubectl patch` / YAML diff before execution |
| Rollback on failure | Remediation Agent snapshots state before change; auto-rollbacks if health check fails |
| Audit trail for every action | Every scan, finding, and remediation logged with timestamp, user, and agent ID |
| Read-only by default | Scanner and Runtime Agents use `k8s-security-reader` ClusterRole — no write access |
| Scoped write access | Only Remediation Agent uses `k8s-security-remediator` ClusterRole — and only when triggered |

---

## 5. Scanner Agent

The Scanner Agent contains **8 specialized modules**. Each module can run independently or as part of a full cluster scan.

### 5.1 Module Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     🔍 SCANNER AGENT — 8 MODULES                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ① Cluster & Control Plane   ② Workload & Pod Security          │
│  ③ RBAC & Identity           ④ Network Security                 │
│  ⑤ Image & Supply Chain      ⑥ Secrets                         │
│  ⑦ CIS Benchmark & Compliance ⑧ Attack Surface Mapper           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Module ① — Cluster & Control Plane Scanner

Scans the Kubernetes control plane components for misconfigurations and insecure defaults.

| Check | What It Detects | Severity | Tool Used |
|---|---|---|---|
| Anonymous auth enabled | `--anonymous-auth=true` on API server | 🔴 CRITICAL | kubectl + kube-bench |
| Insecure port open | `--insecure-port` not set to 0 | 🔴 CRITICAL | kubectl |
| Audit logging disabled | Missing `--audit-log-path` flag | 🟠 HIGH | kube-bench |
| etcd encryption missing | No `--encryption-provider-config` | 🟠 HIGH | kubectl |
| etcd no client cert auth | `--client-cert-auth` not true | 🔴 CRITICAL | kube-bench |
| Kubelet anon auth | `--anonymous-auth=true` on kubelet | 🔴 CRITICAL | kube-bench |
| Kubelet read-only port | Port 10255 open | 🟠 HIGH | kube-bench |
| Kubelet AlwaysAllow | `--authorization-mode=AlwaysAllow` | 🔴 CRITICAL | kube-bench |
| Missing admission controllers | NodeRestriction, PSA, LimitRanger not enabled | 🟠 HIGH | kubectl |
| Profiling enabled | `--profiling=true` on scheduler/controller-manager | 🟡 MEDIUM | kube-bench |
| Deprecated K8s version | Running EOL or CVE-affected version | 🟠 HIGH | version check |
| TLS certificates expiring | Certs expiring within 30 days | 🟠 HIGH | openssl / kubeadm |

### 5.3 Module ② — Workload & Pod Security Scanner

Scans every pod across all namespaces for insecure configurations.

| Check | What It Detects | Severity | Pod Spec Field |
|---|---|---|---|
| Privileged container | Container runs with full host privileges | 🔴 CRITICAL | `securityContext.privileged` |
| Running as root | Container runs as UID 0 | 🟠 HIGH | `securityContext.runAsUser` / `runAsNonRoot` |
| Privilege escalation allowed | Child process can gain more privileges | 🟠 HIGH | `securityContext.allowPrivilegeEscalation` |
| Writable root filesystem | Container can modify its own filesystem | 🟡 MEDIUM | `securityContext.readOnlyRootFilesystem` |
| Dangerous capabilities | SYS_ADMIN, SYS_PTRACE, NET_RAW, DAC_OVERRIDE, NET_ADMIN | 🟠 HIGH | `securityContext.capabilities.add` |
| Capabilities not dropped | ALL not dropped | 🟠 HIGH | `securityContext.capabilities.drop` |
| Host PID sharing | Container shares host PID namespace | 🔴 CRITICAL | `spec.hostPID` |
| Host Network sharing | Container shares host network stack | 🟠 HIGH | `spec.hostNetwork` |
| Host IPC sharing | Container shares host IPC namespace | 🟠 HIGH | `spec.hostIPC` |
| Docker socket mounted | `/var/run/docker.sock` exposed | 🔴 CRITICAL | `volumes[].hostPath.path` |
| hostPath to root | `hostPath: /` gives full host filesystem access | 🔴 CRITICAL | `volumes[].hostPath.path` |
| Missing resource limits | No CPU/memory limits → DoS risk | 🟡 MEDIUM | `resources.limits` |
| Missing resource requests | No CPU/memory requests → scheduling issues | 🟡 MEDIUM | `resources.requests` |
| No seccomp profile | Missing kernel syscall restrictions | 🟡 MEDIUM | `securityContext.seccompProfile` |
| No AppArmor profile | Missing mandatory access control | 🟡 MEDIUM | annotations |
| SA token auto-mounted | Service account token accessible inside pod | 🟡 MEDIUM | `automountServiceAccountToken` |
| `:latest` image tag | Mutable tag — unpinned version | 🟡 MEDIUM | `containers[].image` |
| `imagePullPolicy: IfNotPresent` | May run stale cached image | 🟡 LOW | `containers[].imagePullPolicy` |

### 5.4 Module ③ — RBAC & Identity Scanner

Analyzes the full RBAC graph for overly permissive roles and privilege escalation paths.

| Check | What It Detects | Severity |
|---|---|---|
| Wildcard verbs | Roles with `verbs: ["*"]` — can do anything | 🔴 CRITICAL |
| Wildcard resources | Roles with `resources: ["*"]` — applies to everything | 🔴 CRITICAL |
| Cluster-admin binding on default SA | Default service account bound to `cluster-admin` | 🔴 CRITICAL |
| Privilege escalation paths | SA → Role → ClusterRole → cluster-admin chain | 🔴 CRITICAL |
| Pod creation + SA impersonation | Role can create pods + impersonate other SAs | 🟠 HIGH |
| Secret list/get access | Role can read secrets across namespaces | 🟠 HIGH |
| Unused roles & bindings | Roles with no subjects bound → cleanup opportunity | 🟡 LOW |
| Cross-namespace access | RoleBinding grants access outside its own namespace | 🟠 HIGH |
| Default SA with non-default perms | Default SA in namespace has extra permissions | 🟠 HIGH |
| `bind` / `escalate` verbs | Role can create bindings to higher-privilege roles | 🔴 CRITICAL |

**Privilege Escalation Path Detection:**

```
                    ┌─────────────────────────────────────┐
                    │   RBAC ESCALATION PATH EXAMPLE      │
                    │                                     │
                    │   default SA (ns: staging)           │
                    │        │                             │
                    │        ▼                             │
                    │   RoleBinding: dev-binding           │
                    │        │                             │
                    │        ▼                             │
                    │   ClusterRole: pod-manager           │
                    │   (verbs: create,delete on pods)     │
                    │        │                             │
                    │        ▼                             │
                    │   Can create pod with:               │
                    │   serviceAccountName: admin-sa       │
                    │        │                             │
                    │        ▼                             │
                    │   admin-sa has cluster-admin! 🔴      │
                    │                                     │
                    │   ⚠️ Effective: staging SA → admin   │
                    └─────────────────────────────────────┘
```

### 5.5 Module ④ — Network Security Scanner

Maps network exposure and validates segmentation policies.

| Check | What It Detects | Severity |
|---|---|---|
| No NetworkPolicy in namespace | Namespace has zero network policies → flat network | 🟠 HIGH |
| No default-deny ingress | Missing catch-all deny ingress policy | 🟠 HIGH |
| No default-deny egress | Missing catch-all deny egress policy | 🟡 MEDIUM |
| Cross-namespace unrestricted | Pods in ns-A can freely reach pods in ns-B | 🟠 HIGH |
| NodePort services | Services exposed on node ports (30000-32767) | 🟡 MEDIUM |
| LoadBalancer without source restriction | Public LB with no `loadBalancerSourceRanges` | 🟠 HIGH |
| Ingress without TLS | Ingress endpoint serving unencrypted HTTP | 🟠 HIGH |
| Dashboard exposed | `kubernetes-dashboard` accessible externally | 🔴 CRITICAL |
| Metadata API reachable | Pods can curl `169.254.169.254` | 🟠 HIGH |
| ExternalIP usage | Services using `externalIPs` — potential for CVE-2020-8554 | 🟡 MEDIUM |
| No mTLS / service mesh | Inter-service traffic is unencrypted | 🟡 MEDIUM |

### 5.6 Module ⑤ — Image & Supply Chain Scanner

Scans container images for vulnerabilities and supply chain risks.

| Check | What It Detects | Severity | Tool |
|---|---|---|---|
| Image CVE scan | Known vulnerabilities in OS packages and libraries | Variable | Trivy / Grype |
| `:latest` tag | Mutable, unpinned image version | 🟡 MEDIUM | kubectl |
| Image pull policy | `IfNotPresent` may use stale cached image | 🟡 LOW | kubectl |
| Private registry auth | Registry pull secrets missing or misconfigured | 🟠 HIGH | kubectl |
| Secrets in image layers | API keys, passwords, certs baked into image layers | 🔴 CRITICAL | TruffleHog / Trivy |
| Image not signed | No cosign/notary signature on image | 🟡 MEDIUM | Cosign |
| No SBOM | Unknown dependencies — can't audit supply chain | 🟡 LOW | Syft |
| Base image outdated | Base image (e.g., alpine:3.14) has known CVEs | 🟠 HIGH | Trivy |
| Typosquatting risk | Image name similar to popular image (e.g., `nignx`) | 🟠 HIGH | Image name analysis |

### 5.7 Module ⑥ — Secrets Scanner

Detects insecure secret storage and usage patterns.

| Check | What It Detects | Severity |
|---|---|---|
| Secrets as env vars | `env[].valueFrom.secretKeyRef` — exposed in logs/crash dumps | 🟠 HIGH |
| etcd not encrypted | Secrets stored in plaintext in etcd | 🔴 CRITICAL |
| Hardcoded credentials in ConfigMaps | Passwords, tokens in ConfigMap data | 🟠 HIGH |
| Secret readable by many SAs | RBAC grants secret `get`/`list` to broad audience | 🟠 HIGH |
| Secret not rotated | Secret older than rotation threshold (e.g., 90 days) | 🟡 MEDIUM |
| No external secret store | Not using Vault, AWS Secrets Manager, or ESO | 🟡 MEDIUM |
| Default token not disabled | `automountServiceAccountToken` not set to `false` | 🟡 MEDIUM |

### 5.8 Module ⑦ — CIS Benchmark & Compliance Scanner

Automated compliance checks against industry standards.

| Standard | Tool | Checks |
|---|---|---|
| **CIS Kubernetes Benchmark v1.8** | kube-bench | 242 checks across master, node, etcd, policies |
| **CIS Docker Benchmark** | docker-bench-security | Host config, daemon config, images, runtime |
| **Pod Security Standards** | kubectl + PSA | Privileged / Baseline / Restricted level per namespace |
| **NSA/CISA Hardening Guide** | kubescape | Pod security, network policies, auth, audit, upgrades |
| **MITRE ATT&CK for K8s** | kubescape | Framework-based scan mapping to MITRE techniques |

**Compliance Score Output:**

```
┌─────────────────────────────────────────────────────┐
│              COMPLIANCE DASHBOARD                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  CIS Kubernetes Benchmark v1.8                      │
│  ████████████████████░░░░░░░░  72% PASS             │
│  Passed: 174 / 242                                  │
│  Failed: 52  |  Warning: 16                         │
│                                                     │
│  Pod Security Standards                             │
│  ┌─────────────┬────────────┬──────────────────┐   │
│  │  Namespace   │  Current   │  Required        │   │
│  ├─────────────┼────────────┼──────────────────┤   │
│  │  production  │  Baseline  │  Restricted ⚠️    │   │
│  │  staging     │  Privileged│  Baseline ⚠️      │   │
│  │  kube-system │  Privileged│  Baseline ⚠️      │   │
│  │  monitoring  │  Restricted│  Restricted ✅    │   │
│  └─────────────┴────────────┴──────────────────┘   │
│                                                     │
│  NSA/CISA Hardening                                 │
│  ████████████████░░░░░░░░░░░░  60% COMPLIANT        │
│                                                     │
│  Trend: ↑ 5% improvement from last scan             │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### 5.9 Module ⑧ — Attack Surface Mapper

Builds a complete view of all attack vectors in the cluster.

**Output Categories:**

| Category | What It Maps | Example Output |
|---|---|---|
| **External Entry Points** | All services reachable from outside the cluster | "8 services exposed: 3 NodePort, 2 LB, 2 Ingress, 1 Dashboard" |
| **Container Escape Vectors** | Configurations that allow breaking out of a container | "5 vectors: 2 privileged, 1 hostPath, 1 docker.sock, 1 SYS_ADMIN" |
| **Privilege Escalation Paths** | RBAC chains from low-priv SA to cluster-admin | "4 paths: default-SA→pod-creator→admin-SA→cluster-admin" |
| **Lateral Movement Routes** | How an attacker moves between pods/namespaces | "6 routes: 4 ns without NetworkPolicy, metadata API open, no mTLS" |
| **Data Exfiltration Vectors** | Paths to leak sensitive data out of the cluster | "3 vectors: no egress policy, secrets in env vars, ConfigMap creds" |
| **MITRE Coverage** | How many MITRE techniques the cluster is vulnerable to | "26 / 40 techniques applicable" |
| **Risk Score** | Composite score 0-10 | "Cluster Risk: 7.8 / 10 (HIGH)" |

---

## 6. Runtime Agent

The Runtime Agent provides **continuous, real-time** security monitoring. Unlike the Scanner Agent (which runs on-demand), the Runtime Agent runs as a **DaemonSet on every node** 24/7.

### 6.1 Syscall Monitoring

Integrates with **Falco** and **Cilium Tetragon** for kernel-level monitoring.

| Detection Rule | What It Catches | Severity | Example |
|---|---|---|---|
| Shell spawned in container | bash, sh, zsh exec'd inside a running container | 🟠 HIGH | Attacker got RCE and opened a shell |
| Sensitive file access | Reads to `/etc/shadow`, `/etc/passwd`, `/proc/1/environ` | 🟠 HIGH | Credential harvesting |
| Network recon tools | nmap, netcat, masscan, nslookup to internal ranges | 🟠 HIGH | Attacker mapping internal network |
| Metadata API access | curl/wget to `169.254.169.254` | 🔴 CRITICAL | Cloud credential theft |
| Package manager in prod | apt-get, yum, apk install in production container | 🟡 MEDIUM | Attacker installing tools |
| Binary from /tmp | Executable run from `/tmp`, `/dev/shm`, `/var/tmp` | 🟠 HIGH | Malware execution |
| Kernel module load | `insmod`, `modprobe` inside container | 🔴 CRITICAL | Kernel exploit attempt |
| Privilege change syscall | `setuid`, `setgid` calls | 🟠 HIGH | Privilege escalation |
| Container escape indicators | Access to cgroup `release_agent`, `nsenter`, `chroot` | 🔴 CRITICAL | Container breakout |
| Crypto miner signatures | xmrig, minerd, cpuminer process names | 🟠 HIGH | Cryptojacking |

### 6.2 Kubernetes Audit Event Analysis

> **No external log agent needed** — the Runtime Agent directly consumes K8s API server audit events.

| Event Pattern | Threat Detected | Severity |
|---|---|---|
| 403 Forbidden responses spike | Unauthorized access attempts / brute force | 🟠 HIGH |
| Secret `get` / `list` events | Credential harvesting via K8s API | 🟠 HIGH |
| New RoleBinding / ClusterRoleBinding creation | Privilege escalation attempt | 🔴 CRITICAL |
| `kubectl exec` into kube-system pods | Attacker in sensitive namespace | 🔴 CRITICAL |
| Pod created with `privileged: true` | Container escape preparation | 🔴 CRITICAL |
| ServiceAccount token used from unexpected IP | Stolen token usage | 🟠 HIGH |
| Admission webhook bypass attempt | Trying to circumvent policy enforcement | 🟠 HIGH |

### 6.3 Container Drift Detection

| What Changed | Threat | Severity |
|---|---|---|
| New binary appeared | Malware downloaded into running container | 🟠 HIGH |
| Config file modified | Configuration tampering | 🟡 MEDIUM |
| New listening port opened | Backdoor / reverse shell | 🟠 HIGH |
| Package installed at runtime | Attack tool installation | 🟡 MEDIUM |

### 6.4 Behavioral Baseline Engine

```
  Training Phase (first 48h):              Detection Phase (ongoing):
  ┌───────────────────────────┐           ┌───────────────────────────┐
  │ Pod: payment-api           │           │ Pod: payment-api           │
  │                           │           │                           │
  │ Normal processes:          │           │ ANOMALY DETECTED:         │
  │ • node                    │           │ • node ✅                   │
  │ • npm                     │           │ • npm ✅                    │
  │                           │           │ • curl ❌ (not in baseline) │
  │ Normal connections:        │           │ • nc ❌ (not in baseline)   │
  │ • → postgres:5432         │           │                           │
  │ • → redis:6379            │           │ New connection:            │
  │                           │           │ • → 169.254.169.254 ❌      │
  │ Normal CPU: 10-30%        │           │                           │
  │ Normal MEM: 128-256Mi     │           │ CPU spike: 95% ❌           │
  └───────────────────────────┘           └───────────────────────────┘
```

---

## 7. Remediation Agent

### 7.1 Core Rule

> **⚠️ Every remediation action requires explicit user confirmation. No exceptions. No bypass. No auto-mode.**

### 7.2 Fix Categories

| Category | Fixes Available | Example Fix Command |
|---|---|---|
| **Pod Security** | Add securityContext, drop capabilities, disable privilege escalation, set readOnlyFS, add seccomp | `kubectl patch deploy <name> -p '{"spec":{"template":{"spec":{"securityContext":{"runAsNonRoot":true}}}}}'` |
| **RBAC** | Replace wildcards, downgrade ClusterRole→Role, remove unused bindings, disable SA auto-mount | `kubectl patch sa default -n <ns> -p '{"automountServiceAccountToken":false}'` |
| **Network Policy** | Generate default-deny, create allow-list, isolate namespaces, block metadata API | `kubectl apply -f default-deny-ingress.yaml` |
| **Secrets** | Rotate compromised secrets, migrate env→volume, enable etcd encryption | `kubectl create secret generic <name> --from-literal=key=<new-value> --dry-run=client -o yaml | kubectl apply -f -` |
| **Images** | Pin to digest, set imagePullPolicy: Always, block CRITICAL CVE images | `kubectl set image deploy/<name> <container>=<image>@sha256:<digest>` |
| **Compliance** | Apply PSA labels, enable audit logging, configure admission controllers | `kubectl label ns <ns> pod-security.kubernetes.io/enforce=restricted` |

### 7.3 Rollback Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    REMEDIATION LIFECYCLE                      │
│                                                              │
│  ① SNAPSHOT                                                  │
│     └── kubectl get deploy <name> -o yaml > /snapshots/      │
│                                                              │
│  ② SHOW PROPOSED CHANGE                                      │
│     └── Display exact diff to user                           │
│                                                              │
│  ③ USER CONFIRMS (Y/N)                                       │
│     └── If N → abort, no changes made                        │
│                                                              │
│  ④ APPLY FIX                                                 │
│     └── kubectl patch / apply                                │
│                                                              │
│  ⑤ HEALTH CHECK                                              │
│     └── Wait for rollout, verify pod Running + Ready         │
│                                                              │
│  ⑥ IF FAILURE                                                │
│     └── kubectl apply -f /snapshots/<snapshot>.yaml           │
│     └── "Fix rolled back — pods restored to previous state"  │
│                                                              │
│  ⑦ AUDIT LOG                                                 │
│     └── Log: timestamp, user, finding, fix applied, result   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 8. K8s Security MCP Server

The MCP Server is the **knowledge layer**. All agents query it for the right commands, scan logic, and fix procedures. It has **5 trained datasets**:

### 8.1 Datasets

| # | Dataset | Contents | Used By |
|---|---------|----------|---------|
| 📘 1 | **kubectl Security Commands** | 60+ kubectl commands for inspecting pods, RBAC, secrets, network, events | Scanner Agent |
| 📗 2 | **Scanning Tool Commands** | Trivy, kube-bench, kubeaudit, kubesec, kubescape, popeye CLI invocations | Scanner Agent |
| 📙 3 | **Remediation Playbooks** | kubectl patch templates, YAML fix specs, policy templates | Remediation Agent |
| 📕 4 | **CVE Knowledge Base** | 200+ K8s-related CVEs with affected versions, detection logic, fix versions | Scanner + Orchestrator |
| 📒 5 | **Compliance Rule Sets** | CIS Benchmark rules, PSS definitions, NSA/CISA controls | Scanner Agent |

### 8.2 Sample Commands per Dataset

<details>
<summary><strong>📘 Dataset 1 — kubectl Security Commands (click to expand)</strong></summary>

```bash
# ── Pod & Workload Inspection ──
kubectl get pods -A -o wide
kubectl get pods -A -o json | jq '.items[] | select(.spec.securityContext.privileged==true) | .metadata.name'
kubectl get pods -A -o json | jq '.items[] | select(.spec.hostNetwork==true) | .metadata.namespace + "/" + .metadata.name'
kubectl get pod <name> -n <ns> -o jsonpath='{.spec.containers[*].securityContext}'
kubectl get pods --field-selector=status.phase!=Running -A

# ── RBAC Analysis ──
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
kubectl auth can-i create pods --as=system:serviceaccount:<ns>:<sa>
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'
kubectl get clusterroles -o json | jq '.items[] | select(.rules[].verbs[] == "*")'
kubectl get rolebindings -A -o wide

# ── Secrets ──
kubectl get secrets -A --field-selector type=Opaque
kubectl get pods -A -o json | jq '.items[].spec.containers[].env[]? | select(.valueFrom.secretKeyRef)'
kubectl get configmaps -A -o json | jq '.items[] | select(.data | to_entries[] | .value | test("password|secret|token|key"; "i"))'

# ── Network ──
kubectl get networkpolicies -A
kubectl get svc -A -o json | jq '.items[] | select(.spec.type=="NodePort") | .metadata.namespace + "/" + .metadata.name + ":" + (.spec.ports[].nodePort|tostring)'
kubectl get ingress -A
kubectl get endpoints -A

# ── Events & Audit ──
kubectl get events -A --sort-by='.lastTimestamp' --field-selector type=Warning
kubectl get events -A --field-selector reason=FailedCreate
kubectl logs <pod> --previous -n <ns>
```

</details>

<details>
<summary><strong>📗 Dataset 2 — Scanning Tool Commands (click to expand)</strong></summary>

```bash
# ── Trivy ──
trivy image <image>
trivy image --severity CRITICAL,HIGH <image>
trivy k8s --report summary cluster
trivy k8s --namespace <ns> --report all
trivy fs --scanners secret /path

# ── kube-bench ──
kube-bench run
kube-bench run --targets master
kube-bench run --targets node
kube-bench run --targets etcd
kube-bench run --json

# ── kubeaudit ──
kubeaudit all
kubeaudit privesc
kubeaudit rootfs
kubeaudit nonroot
kubeaudit caps
kubeaudit netpols

# ── kubesec ──
kubesec scan pod.yaml
curl -sSX POST --data-binary @pod.yaml https://v2.kubesec.io/scan

# ── kubescape ──
kubescape scan framework cis-v1.23-t1.0.1
kubescape scan framework nsa
kubescape scan framework mitre
kubescape scan workload Deployment/<name> -n <ns>

# ── popeye ──
popeye
popeye -n <namespace>
popeye --save --output-file report.html
```

</details>

<details>
<summary><strong>📙 Dataset 3 — Remediation Playbooks (click to expand)</strong></summary>

```yaml
# ── Pod Security Fix ──
kubectl patch deployment <name> -n <ns> -p '
{"spec":{"template":{"spec":{
  "securityContext":{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}},
  "containers":[{"name":"<container>","securityContext":{
    "privileged":false,
    "allowPrivilegeEscalation":false,
    "readOnlyRootFilesystem":true,
    "capabilities":{"drop":["ALL"]}
  }}]
}}}}'

# ── Disable SA Token Auto-mount ──
kubectl patch sa default -n <ns> -p '{"automountServiceAccountToken":false}'

# ── Default-Deny Ingress NetworkPolicy ──
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: <ns>
spec:
  podSelector: {}
  policyTypes:
    - Ingress

# ── Default-Deny Egress NetworkPolicy ──
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: <ns>
spec:
  podSelector: {}
  policyTypes:
    - Egress

# ── Block Metadata API ──
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-metadata-api
  namespace: <ns>
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32

# ── PSA Label Enforcement ──
kubectl label ns <ns> \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

# ── Resource Limits (LimitRange) ──
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: <ns>
spec:
  limits:
    - default:
        cpu: "500m"
        memory: "256Mi"
      defaultRequest:
        cpu: "100m"
        memory: "128Mi"
      type: Container
```

</details>

---

## 9. Kubernetes Attack Surface Map

The Attack Surface Mapper builds a **5-layer map** of every exploitable path in the cluster:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   ╔══════════════════════════════════════════════════════════════════════╗  │
│   ║  LAYER 1 — EXTERNAL EXPOSURE                                        ║  │
│   ║                                                                      ║  │
│   ║  "What can an attacker reach from the internet?"                     ║  │
│   ║                                                                      ║  │
│   ║  ┌────────────────────────────────────────────────────────────────┐  ║  │
│   ║  │ • NodePort services (30000-32767)                              │  ║  │
│   ║  │ • LoadBalancer services with public IPs                        │  ║  │
│   ║  │ • Ingress endpoints (HTTP/HTTPS)                               │  ║  │
│   ║  │ • API Server (if externally accessible)                        │  ║  │
│   ║  │ • Kubernetes Dashboard (if deployed & exposed)                 │  ║  │
│   ║  │ • Kubelet API (10250 unauthenticated / 10255 read-only)        │  ║  │
│   ║  │ • etcd (2379 if reachable)                                     │  ║  │
│   ║  └────────────────────────────────────────────────────────────────┘  ║  │
│   ╚══════════════════════════════════════════════════════════════════════╝  │
│                                     │                                      │
│                                     ▼                                      │
│   ╔══════════════════════════════════════════════════════════════════════╗  │
│   ║  LAYER 2 — CONTROL PLANE                                            ║  │
│   ║                                                                      ║  │
│   ║  "Can an attacker compromise the cluster's brain?"                   ║  │
│   ║                                                                      ║  │
│   ║  ┌────────────────────────────────────────────────────────────────┐  ║  │
│   ║  │ • API Server: anonymous auth, insecure port, weak TLS          │  ║  │
│   ║  │ • etcd: no encryption, no client certs, exposed                │  ║  │
│   ║  │ • Kubelet: anonymous auth, AlwaysAllow authz, read-only port   │  ║  │
│   ║  │ • Scheduler/Controller Manager: profiling, insecure bind       │  ║  │
│   ║  │ • Missing admission controllers                                │  ║  │
│   ║  │ • Outdated/CVE-affected K8s version                            │  ║  │
│   ║  └────────────────────────────────────────────────────────────────┘  ║  │
│   ╚══════════════════════════════════════════════════════════════════════╝  │
│                                     │                                      │
│                                     ▼                                      │
│   ╔══════════════════════════════════════════════════════════════════════╗  │
│   ║  LAYER 3 — WORKLOADS                                                ║  │
│   ║                                                                      ║  │
│   ║  "Can an attacker escape a container or escalate privileges?"        ║  │
│   ║                                                                      ║  │
│   ║  ┌────────────────────────────────────────────────────────────────┐  ║  │
│   ║  │ • Privileged containers                                        │  ║  │
│   ║  │ • Root-running containers                                      │  ║  │
│   ║  │ • Dangerous capabilities (SYS_ADMIN, NET_RAW, SYS_PTRACE)     │  ║  │
│   ║  │ • Host namespace sharing (PID, IPC, Network)                   │  ║  │
│   ║  │ • hostPath / docker.sock mounts                                │  ║  │
│   ║  │ • No resource limits (DoS amplification)                       │  ║  │
│   ║  │ • Writable root filesystem                                     │  ║  │
│   ║  │ • Overly permissive service accounts                           │  ║  │
│   ║  └────────────────────────────────────────────────────────────────┘  ║  │
│   ╚══════════════════════════════════════════════════════════════════════╝  │
│                                     │                                      │
│                                     ▼                                      │
│   ╔══════════════════════════════════════════════════════════════════════╗  │
│   ║  LAYER 4 — NETWORK & IDENTITY                                       ║  │
│   ║                                                                      ║  │
│   ║  "Can an attacker move laterally inside the cluster?"                ║  │
│   ║                                                                      ║  │
│   ║  ┌────────────────────────────────────────────────────────────────┐  ║  │
│   ║  │ • No Network Policies (flat network — all pods talk to all)    │  ║  │
│   ║  │ • Cross-namespace access unrestricted                          │  ║  │
│   ║  │ • No mTLS between services                                     │  ║  │
│   ║  │ • RBAC wildcard permissions                                    │  ║  │
│   ║  │ • Cluster-admin on default service accounts                    │  ║  │
│   ║  │ • CoreDNS poisoning potential                                  │  ║  │
│   ║  │ • Metadata API reachable (169.254.169.254)                     │  ║  │
│   ║  └────────────────────────────────────────────────────────────────┘  ║  │
│   ╚══════════════════════════════════════════════════════════════════════╝  │
│                                     │                                      │
│                                     ▼                                      │
│   ╔══════════════════════════════════════════════════════════════════════╗  │
│   ║  LAYER 5 — IMAGES & SUPPLY CHAIN                                    ║  │
│   ║                                                                      ║  │
│   ║  "Are the container images and dependencies trustworthy?"            ║  │
│   ║                                                                      ║  │
│   ║  ┌────────────────────────────────────────────────────────────────┐  ║  │
│   ║  │ • Vulnerable base images (OS package CVEs)                     │  ║  │
│   ║  │ • `:latest` tag usage (mutable, unpinned)                      │  ║  │
│   ║  │ • No image signing or verification                             │  ║  │
│   ║  │ • Secrets baked into image layers                              │  ║  │
│   ║  │ • Private registry without authentication                     │  ║  │
│   ║  │ • Typosquatted / malicious images                              │  ║  │
│   ║  │ • No SBOM — unknown transitive dependencies                    │  ║  │
│   ║  └────────────────────────────────────────────────────────────────┘  ║  │
│   ╚══════════════════════════════════════════════════════════════════════╝  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. MITRE ATT&CK for Kubernetes

Every finding is classified using the **Microsoft Threat Matrix for Kubernetes** (MITRE ATT&CK adapted for K8s containers).

### 10.1 Full Threat Matrix

| Initial Access | Execution | Persistence | Priv Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Impact |
|---|---|---|---|---|---|---|---|---|---|
| Using cloud credentials | Exec into container | Backdoor container | Privileged container | Clear container logs | List K8s secrets | Access K8s API server | Access cloud resources | Images from private registry | Data destruction |
| Compromised image in registry | bash/cmd inside container | Writable hostPath mount | Cluster-admin binding | Delete K8s events | Mount service principal | Access Kubelet API | Container service account | Collecting data from pod | Resource hijacking |
| Kubeconfig file | New container | Kubernetes CronJob | hostPath mount | Pod/container name similarity | Container service account | Network mapping | Cluster internal networking | | Denial of service |
| Application vulnerability | Application exploit (RCE) | Malicious admission controller | Access cloud resources | Connect from proxy server | App credentials in config | Exposed sensitive interfaces | App credentials in config | | |
| Exposed sensitive interfaces | SSH server in container | Container service account | | | Managed identity credentials | Instance Metadata API | Writable hostPath mount | | |
| | Sidecar injection | Static pods | | | Malicious admission controller | | CoreDNS poisoning | | |
| | | | | | | | ARP poisoning / IP spoofing | | |

### 10.2 Detection Coverage

| Tactic | Tool Detection Method | Agent |
|---|---|---|
| **Initial Access** | Service exposure scan, registry audit, kubeconfig check | Scanner |
| **Execution** | Syscall monitoring, `kubectl exec` audit events, new container alerts | Runtime |
| **Persistence** | Config drift detection, CronJob audit, admission controller review, static pod check | Scanner + Runtime |
| **Privilege Escalation** | Pod securityContext scan, RBAC analysis, hostPath mount detection | Scanner |
| **Defense Evasion** | Audit log integrity monitoring, event stream analysis, container naming anomalies | Runtime |
| **Credential Access** | Secret access audit, RBAC review, config scanning, SA token analysis | Scanner |
| **Discovery** | API access audit, kubelet port scan, network recon detection, metadata API check | Scanner + Runtime |
| **Lateral Movement** | NetworkPolicy enforcement check, DNS config audit, cross-namespace traffic analysis | Scanner |
| **Collection** | Registry access audit, pod data access monitoring | Scanner + Runtime |
| **Impact** | Resource usage anomaly (cryptomining), DoS detection (no limits), data deletion alerts | Runtime |

---

## 11. OWASP Kubernetes Top 10 (2025)

Complete coverage of all 10 risks with detection logic and remediation actions.

---

### K01 — Insecure Workload Configurations

| | |
|---|---|
| **Severity** | 🔴 CRITICAL |
| **Description** | Pods running as root, privileged containers, missing security contexts, writable filesystems, dangerous capabilities |
| **Detection** | Scanner Module ② — scans every pod for `privileged: true`, `runAsUser: 0`, `allowPrivilegeEscalation: true`, missing `securityContext`, capabilities not dropped |
| **Remediation** | Patch deployments with `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, drop ALL caps, add seccomp profile |
| **K8s Goat** | #4 Container escape, #12 Gaining env info, #13 DoS resources |
| **MITRE** | Privilege Escalation → Privileged Container |

---

### K02 — Overly Permissive Authorization

| | |
|---|---|
| **Severity** | 🔴 CRITICAL |
| **Description** | Wildcard RBAC permissions, cluster-admin bound to default SAs, overly broad roles |
| **Detection** | Scanner Module ③ — `kubectl auth can-i --list` per SA, `verbs: ["*"]` detection, cluster-admin binding audit, escalation path analysis |
| **Remediation** | Generate least-privilege Roles, downgrade ClusterRoleBindings → namespaced RoleBindings, remove unused bindings |
| **K8s Goat** | #16 RBAC misconfiguration |
| **MITRE** | Privilege Escalation → Cluster-admin Binding |

---

### K03 — Secrets Management Failures

| | |
|---|---|
| **Severity** | 🟠 HIGH |
| **Description** | Secrets in env vars (exposed in logs/crash dumps), unencrypted etcd, hardcoded credentials, secrets in image layers |
| **Detection** | Scanner Module ⑥ — checks all pod envs for `secretKeyRef`, scans ConfigMaps for plaintext secrets, verifies etcd encryption, image layer scan |
| **Remediation** | Migrate env secrets → mounted volumes, enable etcd encryption, flag images with embedded secrets |
| **K8s Goat** | #1 Sensitive keys in codebases, #15 Hidden in layers |
| **MITRE** | Credential Access → List K8s Secrets |

---

### K04 — Lack of Cluster-Level Policy Enforcement

| | |
|---|---|
| **Severity** | 🟠 HIGH |
| **Description** | No admission controllers, no policy engine (Kyverno/OPA), Pod Security Admission not configured |
| **Detection** | Scanner Module ⑦ — checks PSA labels on namespaces, Kyverno ClusterPolicies, OPA constraints, required admission controllers |
| **Remediation** | Apply PSA labels (`pod-security.kubernetes.io/enforce: restricted`), deploy baseline Kyverno policies |
| **K8s Goat** | #22 Kyverno Policy Engine, #17 KubeAudit |
| **MITRE** | Persistence → Malicious Admission Controller |

---

### K05 — Missing Network Segmentation

| | |
|---|---|
| **Severity** | 🟠 HIGH |
| **Description** | No Network Policies, flat network, no egress restrictions, cross-namespace access |
| **Detection** | Scanner Module ④ — checks every namespace for NetworkPolicies, tests cross-namespace reachability, default-deny check |
| **Remediation** | Generate default-deny NetworkPolicies per namespace, create allow-list rules for known service communication |
| **K8s Goat** | #11 Namespace bypass, #20 Network Security Policy |
| **MITRE** | Lateral Movement → Cluster Internal Networking |

---

### K06 — Overly Exposed Components

| | |
|---|---|
| **Severity** | 🟠 HIGH |
| **Description** | API server publicly accessible, dashboard exposed without auth, kubelet ports open, NodePort services |
| **Detection** | Scanner Module ④ — enumerates NodePort/LB/ExternalIP, checks API server bind address & anon auth, detects dashboard |
| **Remediation** | Restrict services to ClusterIP, apply API server firewall, secure/delete exposed dashboards |
| **K8s Goat** | #8 NodePort exposed services |
| **MITRE** | Initial Access → Exposed Sensitive Interfaces |

---

### K07 — Misconfigured & Vulnerable Components

| | |
|---|---|
| **Severity** | 🟡 MEDIUM |
| **Description** | Outdated K8s version with known CVEs, misconfigured kubelet/API server, deprecated APIs |
| **Detection** | Scanner Module ① + ⑦ — kube-bench CIS checks, version vs CVE database, deprecated API detection |
| **Remediation** | Generate upgrade plan, flag deprecated APIs, apply CIS benchmark fixes |
| **K8s Goat** | #5 Docker CIS, #6 K8s CIS, #19 Popeye |
| **MITRE** | Discovery → Access K8s API Server |

---

### K08 — Cluster-to-Cloud Lateral Movement

| | |
|---|---|
| **Severity** | 🟠 HIGH |
| **Description** | Pods can reach cloud metadata API (169.254.169.254), overly permissive IAM roles |
| **Detection** | Scanner Module ④ — metadata API reachability test, IMDS v2 check, workload identity audit |
| **Remediation** | Create NetworkPolicy blocking 169.254.169.254, recommend workload identity scoping |
| **K8s Goat** | #3 SSRF in K8s world |
| **MITRE** | Lateral Movement → Access Cloud Resources |

---

### K09 — Broken Authentication

| | |
|---|---|
| **Severity** | 🔴 CRITICAL |
| **Description** | Anonymous auth enabled, weak/expired certificates, no OIDC, default credentials |
| **Detection** | Scanner Module ① — API server flags (`--anonymous-auth`, `--token-auth-file`), cert expiry, OIDC config |
| **Remediation** | Disable anonymous auth, configure cert rotation, recommend OIDC |
| **K8s Goat** | #7 Attacking private registry |
| **MITRE** | Initial Access → Using Cloud Credentials |

---

### K10 — Inadequate Logging & Monitoring

| | |
|---|---|
| **Severity** | 🟡 MEDIUM |
| **Description** | No API audit logging, missing audit policy, no security monitoring/alerting |
| **Detection** | Scanner Module ⑦ — checks audit policy file, audit log backend, Falco/Tetragon deployment |
| **Remediation** | Deploy audit policy, generate Falco custom rules |
| **K8s Goat** | #18 Falco runtime monitoring, #21 Cilium Tetragon |
| **MITRE** | Defense Evasion → Clear Container Logs |

---

## 12. Kubernetes Goat — Vulnerability Scenarios

All **22 Kubernetes Goat** scenarios mapped to scanner modules:

| # | Scenario | Risk Category | Scanner Module | Detection Summary |
|---|----------|---------------|----------------|-------------------|
| 1 | Sensitive keys in codebases | Credential Exposure | ⑤ Image & Supply Chain | Scans image layers for hardcoded API keys, passwords, tokens |
| 2 | DIND exploitation | Container Escape | ② Workload Security | Detects Docker socket mount, DinD sidecars |
| 3 | SSRF in K8s world | Lateral Movement | ④ Network Security | Tests metadata API reachability from pods |
| 4 | Container escape to host | Privilege Escalation | ② Workload Security | Detects `privileged: true`, hostPath mounts, host namespaces |
| 5 | Docker CIS benchmarks | Compliance | ⑦ CIS Benchmark | Runs docker-bench-security |
| 6 | K8s CIS benchmarks | Compliance | ⑦ CIS Benchmark | Runs kube-bench |
| 7 | Attacking private registry | Initial Access | ⑤ Image & Supply Chain | Audits registry auth, pull secret exposure |
| 8 | NodePort exposed services | External Exposure | ④ Network Security | Enumerates all NodePort services |
| 9 | Helm v2 tiller PwN | Privilege Escalation | ① Cluster & Control Plane | Detects legacy tiller with cluster-admin |
| 10 | Crypto miner container | Impact | 🛡️ Runtime Agent | CPU anomaly + crypto process signature matching |
| 11 | Namespace bypass | Lateral Movement | ④ Network Security | Tests cross-namespace communication |
| 12 | Gaining environment info | Info Disclosure | ② Workload Security | Checks sensitive env vars, mounted configs |
| 13 | DoS resources | Denial of Service | ② Workload Security | Detects missing resource limits/requests |
| 14 | Hacker container preview | Execution | 🛡️ Runtime Agent | Detects known attack tool images (kali, nmap, etc.) |
| 15 | Hidden in layers | Credential Exposure | ⑤ Image & Supply Chain | Deep image layer scan for removed secrets |
| 16 | RBAC misconfiguration | Privilege Escalation | ③ RBAC & Identity | Full RBAC audit — wildcards, escalation paths |
| 17 | KubeAudit | Audit | ⑦ CIS Benchmark | Integrates kubeaudit |
| 18 | Falco runtime monitoring | Runtime | 🛡️ Runtime Agent | Integrates Falco syscall rules |
| 19 | Popeye sanitizer | Best Practices | ⑦ CIS Benchmark | Integrates Popeye |
| 20 | Network Security Policies | Network | ④ Network Security | Validates NSP presence & enforcement |
| 21 | Cilium Tetragon eBPF | Runtime | 🛡️ Runtime Agent | Integrates Tetragon for eBPF enforcement |
| 22 | Kyverno Policy Engine | Policy | ⑦ CIS Benchmark | Checks Kyverno policy deployment & coverage |

---

## 13. Real-World CVEs & Attack Patterns

### 13.1 Critical Kubernetes CVEs

| CVE | Severity | Description | Detection |
|-----|----------|-------------|-----------|
| CVE-2018-1002105 | 🔴 CRITICAL | API server websocket upgrade → unauthenticated cluster-admin | K8s version check + API config audit |
| CVE-2019-11253 | 🟠 HIGH | XML/JSON parsing DoS (billion laughs) on API server | Version check |
| CVE-2019-11247 | 🟠 HIGH | Cluster-scoped resources via namespaced API calls | API access audit |
| CVE-2019-11249 | 🟠 HIGH | kubectl cp path traversal | kubectl version check |
| CVE-2020-8554 | 🟡 MEDIUM | MitM via LoadBalancer/ExternalIP | Service config audit |
| CVE-2020-8558 | 🟡 MEDIUM | Node-local services reachable from host network | kubelet config check |
| CVE-2020-8559 | 🟠 HIGH | Compromised node escalation via API redirect | Node security audit |
| CVE-2021-25741 | 🟠 HIGH | Symlink exchange → hostPath escape via subPath | Volume mount analysis |
| CVE-2021-25740 | 🟡 MEDIUM | EndpointSlice confused deputy | Service/endpoint audit |
| CVE-2022-3162 | 🟡 MEDIUM | Unauthorized custom resource read | RBAC audit |
| CVE-2022-3294 | 🟠 HIGH | Node IP change → API server proxy access | Node config monitoring |
| CVE-2023-3676 | 🟠 HIGH | Windows node command injection via annotations | Pod annotation audit |
| CVE-2023-5528 | 🟠 HIGH | Windows node command injection via volume paths | Volume mount analysis |
| CVE-2024-3177 | 🟠 HIGH | Bypass mountable secrets via ephemeral containers | Ephemeral container + RBAC audit |
| CVE-2024-9486 | 🔴 CRITICAL | K8s Image Builder VMs with default credentials | Image provenance scan |

### 13.2 Real-World Attack Patterns

| # | Attack | Kill Chain | Tool Detection |
|---|--------|-----------|----------------|
| 1 | **Cryptojacking via Kubelet** | Exposed kubelet → deploy miner → resource hijack | Scanner: kubelet port → Runtime: CPU anomaly |
| 2 | **Dashboard Takeover** | Unauthenticated dashboard → create pod → cluster-admin | Scanner: dashboard exposure + auth audit |
| 3 | **Metadata SSRF** | SSRF in pod → curl 169.254.169.254 → steal IAM creds | Scanner: metadata reachability test |
| 4 | **Container Escape (cgroups)** | Privileged container → cgroup release_agent → host exec | Scanner: privileged detection → Runtime: cgroup writes |
| 5 | **SA Token Theft** | Auto-mounted token → auth can-i → escalate if over-permissive | Scanner: SA mount audit + RBAC analysis |
| 6 | **Registry Typosquatting** | Publish `nignx` (typo) → unsuspecting pull → malware | Scanner: image name analysis + registry whitelist |
| 7 | **CoreDNS Poisoning** | Compromised pod → modify CoreDNS ConfigMap → redirect traffic | Scanner: CoreDNS RBAC → Runtime: DNS config change |
| 8 | **etcd Theft** | Exposed etcd (2379) no TLS → dump secrets | Scanner: etcd exposure + TLS audit |
| 9 | **CronJob Persistence** | Create CronJob with backdoor → survives restarts | Scanner: CronJob audit → Runtime: new CronJob alert |
| 10 | **Static Pod Injection** | Write manifest to /etc/kubernetes/manifests/ → kubelet runs it | Scanner: hostPath to manifests → Runtime: static pod alert |
| 11 | **ARP Poisoning** | L2 attack within pod network → traffic interception | Scanner: CNI security check → Runtime: ARP anomaly |
| 12 | **Admission Webhook Backdoor** | Install malicious MutatingWebhook → inject sidecar into all pods | Scanner: webhook audit → Runtime: new webhook alert |

---

## 14. Scanner Configuration Spec

```yaml
# ═══════════════════════════════════════════════════
# K8s Security Tool — Scanner Configuration v2.0
# ═══════════════════════════════════════════════════

version: "2.0"
scanner:

  # ── Global Settings ──
  global:
    severity_threshold: MEDIUM     # Minimum severity to report (LOW | MEDIUM | HIGH | CRITICAL)
    scan_namespaces: all           # "all" or list: [production, staging, kube-system]
    exclude_namespaces: []         # Namespaces to skip
    scan_interval: "0 */6 * * *"  # Cron schedule for recurring scans
    parallel_scans: 3              # Max concurrent module scans
    report_format: [json, markdown]

  # ── Module 1: Control Plane ──
  cluster:
    enabled: true
    checks:
      api_server:
        anonymous_auth: { must_be: false, severity: CRITICAL }
        insecure_port: { must_be: 0, severity: CRITICAL }
        audit_logging: { required: true, severity: HIGH }
        encryption_provider: { required: true, severity: HIGH }
        admission_controllers:
          required: [NodeRestriction, PodSecurity, LimitRanger, ResourceQuota, ServiceAccount]
          severity: HIGH
      etcd:
        client_cert_auth: { must_be: true, severity: CRITICAL }
        peer_auto_tls: { must_be: false, severity: HIGH }
      kubelet:
        anonymous_auth: { must_be: false, severity: CRITICAL }
        read_only_port: { must_be: 0, severity: HIGH }
        authorization_mode: { must_be: Webhook, severity: HIGH }

  # ── Module 2: Workloads ──
  workloads:
    enabled: true
    checks:
      privileged: { must_be: false, severity: CRITICAL }
      run_as_non_root: { must_be: true, severity: HIGH }
      read_only_root_fs: { must_be: true, severity: MEDIUM }
      allow_privilege_escalation: { must_be: false, severity: HIGH }
      capabilities_drop_all: { required: true, severity: HIGH }
      host_pid: { must_be: false, severity: CRITICAL }
      host_network: { must_be: false, severity: HIGH }
      host_ipc: { must_be: false, severity: HIGH }
      docker_socket: { must_not_exist: true, severity: CRITICAL }
      resource_limits: { required: true, severity: MEDIUM }
      latest_tag: { must_not_use: true, severity: MEDIUM }
      seccomp_profile: { required: true, severity: MEDIUM }
      sa_token_automount: { must_be: false, severity: MEDIUM }

  # ── Module 3: RBAC ──
  rbac:
    enabled: true
    checks:
      wildcard_verbs: { severity: CRITICAL }
      wildcard_resources: { severity: CRITICAL }
      cluster_admin_default_sa: { severity: CRITICAL }
      escalation_path_detection: { enabled: true, severity: CRITICAL }
      bind_escalate_verbs: { severity: CRITICAL }
      unused_bindings: { severity: LOW }

  # ── Module 4: Network ──
  network:
    enabled: true
    checks:
      network_policy_coverage: { required: true, severity: HIGH }
      default_deny_ingress: { required: true, severity: HIGH }
      default_deny_egress: { required: false, severity: MEDIUM }
      metadata_api_blocked: { required: true, severity: HIGH }
      nodeport_detection: { severity: MEDIUM }
      ingress_tls: { required: true, severity: HIGH }
      dashboard_exposure: { severity: CRITICAL }

  # ── Module 5: Images ──
  images:
    enabled: true
    scan_tool: trivy
    severity_threshold: HIGH
    checks:
      signing_required: false
      sbom_generation: true
      registry_whitelist: []   # Empty = all allowed. Set to ["gcr.io", "docker.io"] to restrict.

  # ── Module 6: Secrets ──
  secrets:
    enabled: true
    checks:
      env_var_secrets: { severity: HIGH }
      etcd_encryption: { severity: CRITICAL }
      configmap_credentials: { severity: HIGH }
      rotation_max_age_days: 90

  # ── Module 7: Compliance ──
  compliance:
    enabled: true
    frameworks:
      cis_kubernetes: { version: "1.8", tool: kube-bench, pass_threshold: 80 }
      pod_security_standards: { enforce_level: restricted }
      nsa_cisa: { enabled: true, tool: kubescape }

  # ── Module 8: Attack Surface ──
  attack_surface:
    enabled: true
    output: [report, risk_score, mitre_mapping]
```

---

## 15. End-to-End Workflows

### Workflow 1 — Full Cluster Security Scan

```
👤 "Run a full security scan on my cluster"

🧠 Orchestrator: Intent=SCAN, Scope=cluster-wide → routes to Scanner Agent (all 8 modules)

🔍 Scanner Agent runs all modules in parallel:
   ① Control Plane    → 4 CRITICAL, 2 HIGH
   ② Workload         → 8 CRITICAL, 15 HIGH, 22 MEDIUM
   ③ RBAC             → 2 CRITICAL, 5 HIGH
   ④ Network          → 1 CRITICAL, 6 HIGH
   ⑤ Images           → 3 CRITICAL, 12 HIGH
   ⑥ Secrets          → 1 CRITICAL, 4 HIGH
   ⑦ Compliance       → CIS: 68% | PSS: 3 ns non-compliant | NSA: 55%
   ⑧ Attack Surface   → Risk Score: 8.1/10 (HIGH)

📊 Report:
   ┌────────────────────────────────────────────────┐
   │  CLUSTER SECURITY REPORT                        │
   │                                                 │
   │  🔴 CRITICAL: 19   🟠 HIGH: 44   🟡 MEDIUM: 22 │
   │                                                 │
   │  Top 3 Critical:                                │
   │  1. 5 privileged containers in production       │
   │  2. cluster-admin bound to 3 default SAs        │
   │  3. etcd encryption not enabled                 │
   │                                                 │
   │  Security Score: 31 / 100 (CRITICAL)            │
   │  MITRE Techniques: 28 / 40 applicable           │
   │                                                 │
   │  Auto-remediate CRITICAL findings? (Y/N)        │
   └────────────────────────────────────────────────┘
```

### Workflow 2 — Scan Specific Namespace

```
👤 "Scan the production namespace for pod security issues"

🧠 Orchestrator: Intent=SCAN, Scope=ns:production, Module=② → Scanner Agent

🔍 Scanner scans all pods in production:
   • payment-api: privileged=true 🔴, running as root 🟠
   • user-service: image CVE-2021-22931 🔴, no resource limits 🟡
   • cache-redis: no seccomp 🟡, `:latest` tag 🟡

📊 "3 pods scanned, 2 CRITICAL, 1 HIGH, 3 MEDIUM findings.
    Fix CRITICAL issues? I'll show exact changes first."
```

### Workflow 3 — Attack Surface Mapping

```
👤 "Map the attack surface"

🧠 Orchestrator: Intent=MAP → Scanner Agent (Module ⑧)

📊 Report:
   External Entry Points: 8  (3 NodePort, 2 LB, 2 Ingress, 1 Dashboard 🔴)
   Container Escape Vectors: 5
   Privilege Escalation Paths: 4
   Lateral Movement Routes: 6
   Data Exfiltration Vectors: 3
   Risk Score: 7.8 / 10 (HIGH)
   MITRE Techniques Applicable: 26
```

### Workflow 4 — Runtime Threat Response

```
🛡️ Runtime Agent auto-alert:
   "Falco: shell spawned in web-app (production). Process: curl 169.254.169.254"

🧠 Orchestrator: auto-routes to Scanner (investigate) + Runtime (details)

📊 CRITICAL ALERT:
   • Shell in container + metadata API accessed = credential theft
   • MITRE: Execution → bash | Credential Access → Metadata API
   • Recommended: Kill pod, apply NetworkPolicy, rotate SA token
   • Execute emergency response? (Y/N)

👤 "Y"

🔧 Remediation Agent:
   ✅ Pod killed
   ✅ NetworkPolicy blocking 169.254.169.254 applied
   ✅ SA token rotated
   ✅ Audit log entry created
```

### Workflow 6 — Download Enriched Markdown Report

```
👤 "Download the latest security report as markdown"

🧠 Orchestrator: Intent=DOWNLOAD, Format=markdown → Report Store

📄 Report Generator:
   • Fetches latest scan results from PVC /reports/
   • Renders enriched .md with:
     - YAML frontmatter (scan metadata)
     - Executive dashboard table
     - Per-finding collapsible fix blocks
     - MITRE + OWASP tags on every finding
     - Compliance tables (CIS / PSS / NSA)
     - Attack surface ASCII diagrams
     - Trend delta vs previous scan

✅ Output:
   File: k8s-security-report-20260707.md
   Size: ~85 KB
   Sections: 8
   Findings: 5 CRITICAL · 18 HIGH · 32 MEDIUM · 14 LOW

   Download options:
   • CLI:    k8ssec report download --format markdown
   • API:    GET /api/v1/reports/latest/download?format=markdown
   • Web UI: http://localhost:8080/reports → Download ↓
   • kubectl: kubectl cp report-store-0:/reports/latest.md ./report.md
```

### Workflow 5 — Compliance Audit

```
👤 "Run CIS benchmark audit"

🧠 Orchestrator: Intent=AUDIT → Scanner Agent (Module ⑦)

📊 CIS Kubernetes Benchmark v1.8:
   ████████████████████░░░░░░░░  72% PASS
   Passed: 174 / 242
   Failed: 52 (12 CRITICAL, 18 HIGH, 22 MEDIUM)
   Trend: ↑ 5% from last scan

   Top failures:
   1. [1.2.1] API server --anonymous-auth not false
   2. [1.2.6] API server --kubelet-certificate-authority not set
   3. [4.2.1] Kubelet --anonymous-auth not false

   Auto-fix the 12 CRITICAL CIS failures? (Y/N)
```

---

## 16. Security Scoring & Reporting

### 16.1 Risk Scoring Model

```
Risk Score = Σ (finding_severity × exploitability × blast_radius) / max_possible_score × 10

Where:
  severity:       CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1
  exploitability: Remote=3, Adjacent=2, Local=1
  blast_radius:   Cluster-wide=3, Namespace=2, Pod=1
```

**Score Ranges:**

| Score | Rating | Color | Action |
|---|---|---|---|
| 0.0 – 2.0 | Excellent | 🟢 | Maintain current posture |
| 2.1 – 4.0 | Good | 🟢 | Address medium findings |
| 4.1 – 6.0 | Fair | 🟡 | Prioritize high findings |
| 6.1 – 8.0 | Poor | 🟠 | Immediate action on critical findings |
| 8.1 – 10.0 | Critical | 🔴 | Emergency remediation required |

### 16.2 Report Formats

| Format | Content | Download Method | Use Case |
|---|---|---|---|
| **Terminal Output** | Colored severity findings with inline fix suggestions | `k8ssec report show` | Quick interactive scans |
| **Markdown (.md)** | Rich formatted report with tables, severity badges, collapsible sections, embedded MITRE/OWASP mappings | `k8ssec report download --format markdown` | Documentation, GitHub wikis, sharing |
| **JSON** | Machine-readable structured findings with full metadata | `k8ssec report download --format json` | CI/CD pipeline integration, SIEM ingest |
| **PDF** | Executive summary + detailed findings, branded layout | `k8ssec report download --format pdf` | Management / audit reporting |
| **SARIF** | Static Analysis Results Interchange Format | `k8ssec report download --format sarif` | IDE / GitHub Advanced Security integration |
| **HTML** | Self-contained interactive HTML with charts and severity filters | `k8ssec report download --format html` | Offline sharing, browser-based viewing |

### 16.3 Enriched Markdown Report — Content Spec

Every downloaded `.md` report follows this enriched structure:

```markdown
# 🛡️ K8s Security Report — [Cluster Name]
**Generated:** 2026-07-07 14:30 UTC  |  **Scan ID:** `scan-20260707-a3f2`  |  **Score:** 4.2/10 (Fair)

---

## 📊 Executive Dashboard

| Metric | Value |
|---|---|
| 🔴 Critical | 5 |
| 🟠 High | 18 |
| 🟡 Medium | 32 |
| 🟢 Low | 14 |
| 📈 Trend | ↑ Improved from 5.8 (last month) |
| 🎯 MITRE Coverage | 28 / 40 techniques |
| ✅ CIS Benchmark | 72% PASS |

---

## 🔴 Critical Findings

### 1. Privileged Container — payment-api (production)
- **OWASP:** K01 — Insecure Workload Configuration
- **MITRE:** Privilege Escalation → Privileged Container
- **Exploitability:** Remote · Blast Radius: Cluster-wide

<details>
<summary>Fix Command (click to expand)</summary>

```bash
kubectl patch deploy payment-api -n production -p \
  '{"spec":{"template":{"spec":{"containers":[{"name":"payment-api",
    "securityContext":{"privileged":false,"allowPrivilegeEscalation":false}}]}}}}'
```
</details>
```

---

### 16.4 Report Download System

#### Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                       REPORT DOWNLOAD FLOW                           │
│                                                                      │
│  ┌─────────────┐    ┌─────────────────────┐    ┌─────────────────┐  │
│  │  User/CI    │    │  🧠 Orchestrator     │    │  Report Store   │  │
│  │  ──────     │    │  ─────────────────  │    │  (PVC /reports) │  │
│  │  CLI        │──▶ │  Intent: DOWNLOAD   │──▶ │                 │  │
│  │  Web UI     │    │  format, scan_id    │    │  • .md files    │  │
│  │  API        │    │  namespace filter   │    │  • .json files  │  │
│  └─────────────┘    └──────────┬──────────┘    │  • .pdf files   │  │
│                                │               │  • .sarif files │  │
│                                ▼               │  • .html files  │  │
│                    ┌───────────────────────┐   └────────┬────────┘  │
│                    │  Report Generator     │            │           │
│                    │                       │◀───────────┘           │
│                    │  • Markdown renderer  │                        │
│                    │  • PDF converter      │                        │
│                    │  • SARIF builder      │                        │
│                    │  • HTML builder       │                        │
│                    └───────────┬───────────┘                        │
│                                │                                    │
│                                ▼                                    │
│                    ┌───────────────────────┐                        │
│                    │  Served to User       │                        │
│                    │  • File download      │                        │
│                    │  • kubectl cp         │                        │
│                    │  • REST API stream    │                        │
│                    └───────────────────────┘                        │
└──────────────────────────────────────────────────────────────────────┘
```

#### CLI Download Commands

```bash
# ── List all available reports ──
k8ssec report list
k8ssec report list --last 10
k8ssec report list --namespace production

# ── Download latest report (Enriched Markdown — default) ──
k8ssec report download
k8ssec report download --format markdown          # enriched .md (default)
k8ssec report download --format json
k8ssec report download --format pdf
k8ssec report download --format sarif
k8ssec report download --format html

# ── Download a specific scan by ID ──
k8ssec report download --scan-id scan-20260707-a3f2 --format markdown

# ── Filter report scope before downloading ──
k8ssec report download --namespace production --severity CRITICAL,HIGH --format markdown
k8ssec report download --module rbac --format json
k8ssec report download --since 7d --format pdf

# ── Output to specific path ──
k8ssec report download --format markdown --output ./reports/k8s-security-$(date +%Y%m%d).md
k8ssec report download --format pdf --output /tmp/audit-report.pdf

# ── CI/CD mode (no prompts, exit code 1 if CRITICAL found) ──
k8ssec report download --format sarif --output results.sarif --ci
k8ssec report download --format json --fail-on CRITICAL
```

#### REST API Endpoints

```http
# List available reports
GET  /api/v1/reports
GET  /api/v1/reports?namespace=production&last=5

# Download report in specified format
GET  /api/v1/reports/{scan-id}/download?format=markdown
GET  /api/v1/reports/{scan-id}/download?format=json
GET  /api/v1/reports/{scan-id}/download?format=pdf
GET  /api/v1/reports/{scan-id}/download?format=sarif
GET  /api/v1/reports/{scan-id}/download?format=html

# Download latest report
GET  /api/v1/reports/latest/download?format=markdown

# Download filtered report
GET  /api/v1/reports/latest/download?format=markdown&severity=CRITICAL,HIGH&namespace=production

# Trigger scan + download in one call (async)
POST /api/v1/scan
Body: { "scope": "cluster", "format": "markdown", "download": true }
```

#### kubectl-based Download (no CLI plugin required)

```bash
# Copy latest markdown report from the report store pod to local
kubectl cp k8s-security-tool/report-store-0:/reports/latest.md ./k8s-report.md

# Port-forward the dashboard and download via browser
kubectl port-forward svc/security-dashboard 8080:80 -n k8s-security-tool
# Then open: http://localhost:8080/reports  → click Download ↓

# Stream report via kubectl exec
kubectl exec -n k8s-security-tool deploy/orchestrator-agent -- \
  k8ssec report download --format markdown --stdout > k8s-report-$(date +%Y%m%d).md
```

#### Enriched Markdown Report — Special Formatting Features

| Feature | Description |
|---|---|
| **Severity Badges** | `![CRITICAL](badge)` inline badges next to each finding |
| **Collapsible Fix Blocks** | `<details><summary>Fix Command</summary>` blocks for all remediations |
| **MITRE + OWASP Tags** | Every finding tagged with MITRE technique ID and OWASP K8s Top 10 number |
| **Compliance Tables** | CIS / PSS / NSA scores rendered as markdown tables with pass/fail icons |
| **Attack Path Diagrams** | ASCII privilege escalation chains embedded in report |
| **Trend Delta** | Score change vs previous scan shown inline (`↑ +5%`, `↓ -2%`) |
| **Scan Metadata Header** | Cluster name, scan ID, timestamp, tool version in frontmatter |
| **YAML frontmatter** | Machine-readable metadata block for tooling integration |

**Sample Markdown Frontmatter:**

```yaml
---
title: "K8s Security Report"
cluster: "prod-cluster-eu-west-1"
scan_id: "scan-20260707-a3f2"
generated_at: "2026-07-07T14:30:00Z"
tool_version: "2.0"
score: 4.2
rating: "Fair"
critical: 5
high: 18
medium: 32
low: 14
cis_pass_pct: 72
mitre_techniques: 28
---
```

---

### 16.5 Sample Report Structure

```
┌──────────────────────────────────────────────────┐
│           SECURITY REPORT — July 2026            │
├──────────────────────────────────────────────────┤
│                                                  │
│  [YAML Frontmatter — scan metadata]              │
│                                                  │
│  1. EXECUTIVE SUMMARY                            │
│     • Score: 4.2/10 (Fair)                       │
│     • Findings: 5 Critical, 18 High, 32 Medium   │
│     • Trend: ↑ Improved from 5.8 (last month)   │
│                                                  │
│  2. CRITICAL FINDINGS (top 5)                    │
│     • Detail, MITRE mapping, fix command         │
│     • Collapsible fix blocks per finding         │
│                                                  │
│  3. COMPLIANCE STATUS                            │
│     • CIS: 72% | PSS: Partial | NSA: 60%        │
│                                                  │
│  4. ATTACK SURFACE SUMMARY                       │
│     • 8 entry points, 5 escape vectors           │
│                                                  │
│  5. REMEDIATION PLAN                             │
│     • Prioritized fix list with commands         │
│                                                  │
│  6. TREND ANALYSIS                               │
│     • Score chart over last 30 days              │
│                                                  │
│  7. DOWNLOAD OPTIONS                             │
│     • k8ssec report download --format <fmt>      │
│     • GET /api/v1/reports/latest/download        │
│     • Web UI → Reports → Download ↓              │
│                                                  │
│  8. APPENDIX                                     │
│     • Full finding list (all severities)         │
│                                                  │
└──────────────────────────────────────────────────┘
```

---

## 17. Deployment Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                    TARGET KUBERNETES CLUSTER                        │
│                                                                    │
│  Namespace: k8s-security-tool                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                                                              │  │
│  │  ┌─────────────────────┐  ┌───────────────────────────────┐ │  │
│  │  │ orchestrator-agent  │  │ scanner-agent                 │ │  │
│  │  │ Deployment (1)      │  │ Deployment (1-3, HPA)         │ │  │
│  │  └─────────────────────┘  └───────────────────────────────┘ │  │
│  │                                                              │  │
│  │  ┌─────────────────────┐  ┌───────────────────────────────┐ │  │
│  │  │ remediation-agent   │  │ k8s-security-mcp-server       │ │  │
│  │  │ Deployment (1)      │  │ StatefulSet (1)               │ │  │
│  │  └─────────────────────┘  └───────────────────────────────┘ │  │
│  │                                                              │  │
│  │  ┌─────────────────────┐                                    │  │
│  │  │ security-dashboard  │                                    │  │
│  │  │ Deployment (1)      │                                    │  │
│  │  └─────────────────────┘                                    │  │
│  │                                                              │  │
│  │  ┌──────────────────────────────────────────────────────┐   │  │
│  │  │ runtime-agent (DaemonSet — 1 per node)               │   │  │
│  │  │ Falco + Cilium Tetragon sidecars                     │   │  │
│  │  └──────────────────────────────────────────────────────┘   │  │
│  │                                                              │  │
│  │  ┌──────────────────────────────────────────────────────┐   │  │
│  │  ┌──────────────────────────────────────────────────────┐   │  │
│  │  │ report-store (StatefulSet + PVC /reports)            │   │  │
│  │  │ Serves: CLI · REST API · Web UI downloads            │   │  │
│  │  └──────────────────────────────────────────────────────┘   │  │
│  │                                                              │  │
│  │  ┌──────────────────────────────────────────────────────┐   │  │
│  │  │ security-data (PVC)                                  │   │  │
│  │  │ • Scan results & history                             │   │  │
│  │  │ • CVE knowledge base                                 │   │  │
│  │  │ • Compliance trends                                  │   │  │
│  │  │ • Remediation audit trail                            │   │  │
│  │  │ • Behavioral baselines                               │   │  │
│  │  │ • Generated reports (.md · .json · .pdf · .sarif)    │   │  │
│  │  └──────────────────────────────────────────────────────┘   │  │
│  │                                                              │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

**Resource Requirements:**

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
|---|---|---|---|---|
| orchestrator-agent | 100m | 500m | 128Mi | 512Mi |
| scanner-agent | 200m | 1000m | 256Mi | 1Gi |
| runtime-agent (per node) | 100m | 500m | 128Mi | 512Mi |
| remediation-agent | 100m | 500m | 128Mi | 256Mi |
| mcp-server | 200m | 1000m | 512Mi | 2Gi |
| security-dashboard | 50m | 200m | 64Mi | 256Mi |
| report-store | 100m | 500m | 256Mi | 1Gi |

---

## 18. RBAC Configuration

```yaml
# ══════════════════════════════════════════
# Role 1: Read-Only (Scanner + Runtime)
# ══════════════════════════════════════════
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: k8s-security-reader
rules:
  - apiGroups: [""]
    resources: [pods, services, secrets, configmaps, namespaces, nodes,
                serviceaccounts, persistentvolumes, persistentvolumeclaims, events]
    verbs: [get, list, watch]
  - apiGroups: [apps]
    resources: [deployments, daemonsets, statefulsets, replicasets]
    verbs: [get, list, watch]
  - apiGroups: [batch]
    resources: [jobs, cronjobs]
    verbs: [get, list, watch]
  - apiGroups: [networking.k8s.io]
    resources: [networkpolicies, ingresses]
    verbs: [get, list, watch]
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [roles, rolebindings, clusterroles, clusterrolebindings]
    verbs: [get, list, watch]
  - apiGroups: [admissionregistration.k8s.io]
    resources: [mutatingwebhookconfigurations, validatingwebhookconfigurations]
    verbs: [get, list, watch]
  - apiGroups: [policy]
    resources: [podsecuritypolicies]
    verbs: [get, list, watch]

---
# ══════════════════════════════════════════════
# Role 2: Write (Remediation Agent Only)
# ══════════════════════════════════════════════
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: k8s-security-remediator
rules:
  - apiGroups: [""]
    resources: [pods, services, secrets, configmaps, serviceaccounts]
    verbs: [get, list, watch, update, patch, delete]
  - apiGroups: [apps]
    resources: [deployments, daemonsets, statefulsets]
    verbs: [get, list, watch, update, patch]
  - apiGroups: [networking.k8s.io]
    resources: [networkpolicies]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [roles, rolebindings]
    verbs: [get, list, watch, create, update, patch, delete]
```

---

## 19. Open-Source Tool Integrations

| Category | Tool | Purpose | Integration Point |
|---|---|---|---|
| **Image Scanning** | [Trivy](https://github.com/aquasecurity/trivy) | CVE scanning for images, filesystems, IaC | Scanner Module ⑤ |
| **Image Scanning** | [Grype](https://github.com/anchore/grype) | Supplementary image vulnerability scanner | Scanner Module ⑤ |
| **CIS Benchmark** | [kube-bench](https://github.com/aquasecurity/kube-bench) | CIS K8s Benchmark automation | Scanner Module ⑦ |
| **Cluster Audit** | [KubeAudit](https://github.com/Shopify/kubeaudit) | Security best practice audit | Scanner Module ⑦ |
| **Workload Scoring** | [kubesec](https://github.com/controlplaneio/kubesec) | Risk scoring for K8s resources | Scanner Module ② |
| **Cluster Sanitizer** | [Popeye](https://github.com/derailed/popeye) | Best practice violations & dead resources | Scanner Module ⑦ |
| **Security Posture** | [Kubescape](https://github.com/kubescape/kubescape) | Multi-framework scanning (CIS, NSA, MITRE) | Scanner Module ⑦ |
| **Runtime Monitoring** | [Falco](https://github.com/falcosecurity/falco) | Syscall-level threat detection | Runtime Agent |
| **eBPF Enforcement** | [Cilium Tetragon](https://github.com/cilium/tetragon) | eBPF security observability & enforcement | Runtime Agent |
| **Policy Engine** | [Kyverno](https://github.com/kyverno/kyverno) | K8s-native policy management | Scanner Module ⑦ + Remediation |
| **Policy Engine** | [OPA Gatekeeper](https://github.com/open-policy-agent/gatekeeper) | Policy-as-code admission webhooks | Scanner Module ⑦ |
| **Secret Detection** | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Scan images & repos for leaked secrets | Scanner Module ⑤ + ⑥ |
| **Image Signing** | [Cosign](https://github.com/sigstore/cosign) | Container image signing & verification | Scanner Module ⑤ |
| **SBOM** | [Syft](https://github.com/anchore/syft) | Software Bill of Materials generation | Scanner Module ⑤ |
| **Network Policy** | [Cilium](https://github.com/cilium/cilium) / [Calico](https://github.com/projectcalico/calico) | Network policy enforcement | Scanner Module ④ |

---

## 20. Alerting & Notification

### 20.1 Alert Severity Routing

| Severity | Channel | Response SLA | Example |
|---|---|---|---|
| 🔴 CRITICAL | Slack #security-critical + PagerDuty on-call | Immediate | Privileged container deployed in prod, active exploit detected |
| 🟠 HIGH | Slack #security-alerts | < 4 hours | New cluster-admin binding, secret exposed as env var |
| 🟡 MEDIUM | Slack #security-findings | < 24 hours | Missing resource limits, `:latest` tag, no seccomp |
| 🟢 LOW/INFO | Dashboard only | Next sprint | Unused role bindings, compliance improvement suggestions |

### 20.2 Alert Format

```
┌──────────────────────────────────────────────────────────┐
│  🔴 CRITICAL SECURITY ALERT                              │
│                                                          │
│  Finding:  Privileged container deployed                 │
│  Pod:      payment-api (namespace: production)           │
│  OWASP:    K01 — Insecure Workload Configuration         │
│  MITRE:    Privilege Escalation → Privileged Container   │
│  Detected: 2026-07-07 14:23:18 UTC                       │
│                                                          │
│  Suggested Fix:                                          │
│  kubectl patch deploy payment-api -n production -p       │
│  '{"spec":{"template":{"spec":{"containers":[{"name":   │
│  "payment-api","securityContext":{"privileged":false}}]}}}'│
│                                                          │
│  [Fix Now] [Investigate] [Suppress] [View Report]        │
└──────────────────────────────────────────────────────────┘
```

### 20.3 Supported Integrations

| Platform | Integration Type |
|---|---|
| **Slack** | Webhook — alerts to channels by severity |
| **Microsoft Teams** | Webhook — alert cards with action buttons |
| **PagerDuty** | Events API v2 — critical alert escalation |
| **OpsGenie** | Alert API — on-call routing |
| **Email** | SMTP — daily/weekly digest reports |
| **Webhook (generic)** | HTTP POST — custom integrations |

---

## 21. Roadmap

### Phase 1 — Core Scanning Engine (Weeks 1–4)

| Deliverable | Status |
|---|---|
| Orchestrator Agent — intent classification + request routing | 🔲 |
| Scanner Agent — Module ② Workload & Pod Security | 🔲 |
| Scanner Agent — Module ③ RBAC & Identity | 🔲 |
| Scanner Agent — Module ⑥ Secrets | 🔲 |
| MCP Server — Dataset 1 (kubectl commands) | 🔲 |
| CLI interface | 🔲 |

### Phase 2 — Full Coverage (Weeks 5–8)

| Deliverable | Status |
|---|---|
| Scanner Agent — Module ① Cluster & Control Plane | 🔲 |
| Scanner Agent — Module ④ Network Security | 🔲 |
| Scanner Agent — Module ⑤ Image & Supply Chain (Trivy) | 🔲 |
| Scanner Agent — Module ⑦ CIS Benchmark (kube-bench) | 🔲 |
| Scanner Agent — Module ⑧ Attack Surface Mapper | 🔲 |
| MCP Server — Dataset 2 (scanning tools) + Dataset 4 (CVEs) + Dataset 5 (compliance rules) | 🔲 |
| MITRE ATT&CK + OWASP K8s Top 10 mapping | 🔲 |

### Phase 3 — Runtime & Remediation (Weeks 9–12)

| Deliverable | Status |
|---|---|
| Runtime Agent — Falco integration | 🔲 |
| Runtime Agent — K8s audit event analysis | 🔲 |
| Runtime Agent — Container drift + behavioral baseline | 🔲 |
| Remediation Agent — Auto-fix with confirmation + rollback | 🔲 |
| MCP Server — Dataset 3 (remediation playbooks) | 🔲 |
| Security Dashboard (web UI) with report download UI | 🔲 |
| Risk Scoring Engine | 🔲 |
| Report Download System — CLI + REST API + web UI | 🔲 |
| Enriched Markdown report renderer | 🔲 |

### Phase 4 — Production Readiness (Weeks 13–16)

| Deliverable | Status |
|---|---|
| Scheduled recurring scans (cron-based) | 🔲 |
| Compliance drift alerts | 🔲 |
| Report generation & download (Markdown, JSON, PDF, SARIF, HTML) | 🔲 |
| CI/CD mode — `--ci` flag + `--fail-on CRITICAL` exit codes | 🔲 |
| Alerting integration (Slack, Teams, PagerDuty) | 🔲 |
| Multi-cluster support | 🔲 |
| Trend analysis & historical dashboards | 🔲 |
| Helm chart for deployment | 🔲 |

---

## 22. Glossary

| Term | Definition |
|---|---|
| **PSA** | Pod Security Admission — K8s built-in admission controller enforcing Pod Security Standards |
| **PSS** | Pod Security Standards — three levels (Privileged, Baseline, Restricted) |
| **CIS** | Center for Internet Security — publishes K8s security benchmarks |
| **RBAC** | Role-Based Access Control — K8s authorization model |
| **SA** | ServiceAccount — K8s identity for pods |
| **MCP** | Model Context Protocol — knowledge-serving layer for AI agents |
| **MITRE ATT&CK** | Adversarial Tactics, Techniques & Common Knowledge — threat classification framework |
| **SBOM** | Software Bill of Materials — inventory of all software components |
| **CVE** | Common Vulnerabilities and Exposures — standardized vulnerability IDs |
| **eBPF** | Extended Berkeley Packet Filter — kernel-level monitoring technology |
| **mTLS** | Mutual TLS — bidirectional TLS authentication between services |
| **CNI** | Container Network Interface — K8s networking plugin standard |
| **IMDS** | Instance Metadata Service — cloud provider metadata endpoint (169.254.169.254) |
| **HPA** | Horizontal Pod Autoscaler — auto-scales pod replicas |
| **SARIF** | Static Analysis Results Interchange Format — standardized vulnerability report format for IDE / GitHub Security integration |
| **report-store** | StatefulSet component that persists and serves generated reports via CLI, REST API, and Web UI |
| **Enriched Markdown** | `.md` report format with YAML frontmatter, severity badges, collapsible fix blocks, MITRE/OWASP tags, and embedded diagrams |

---

## 23. References

### Standards & Frameworks

| Resource | URL |
|---|---|
| OWASP Kubernetes Top 10 (2025) | https://owasp.org/www-project-kubernetes-top-ten/ |
| Microsoft Threat Matrix for Kubernetes | https://microsoft.github.io/Threat-Matrix-for-Kubernetes/ |
| MITRE ATT&CK | https://attack.mitre.org/ |
| CIS Kubernetes Benchmark | https://www.cisecurity.org/benchmark/kubernetes |
| NSA/CISA K8s Hardening Guide | https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF |
| K8s Pod Security Standards | https://kubernetes.io/docs/concepts/security/pod-security-standards/ |
| NIST SP 800-190 (Containers) | https://csrc.nist.gov/publications/detail/sp/800-190/final |

### Learning & Research

| Resource | URL |
|---|---|
| Kubernetes Goat | https://madhuakula.com/kubernetes-goat/ |
| OWASP K8s Security Cheatsheet | https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html |
| OWASP Docker Security Cheatsheet | https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html |
| K8s Security Documentation | https://kubernetes.io/docs/concepts/security/ |
| K8s Security Testing Guide | https://github.com/owasp/www-project-kubernetes-security-testing-guide |

---

<p align="center">
  <strong>K8s Security Tool</strong> — v2.0<br/>
  Architecture & Design Document<br/>
  July 2026
</p>


