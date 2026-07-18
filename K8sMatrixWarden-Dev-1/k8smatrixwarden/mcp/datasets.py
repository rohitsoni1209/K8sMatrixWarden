"""
K8s Security MCP Server — the 6 knowledge datasets (§10).

  1. kubectl Security Commands
  2. Scanning Tool Commands
  3. Remediation Playbooks
  4. CVE Knowledge Base
  5. Compliance Rule Sets
  6. Taxonomy Files  (loaded from k8smatrixwarden/taxonomy via bootstrap)

These are plain Python/JSON so the agents and CLI can query them with or without the MCP
protocol layer. `mcp/server.py` exposes them over MCP when the SDK is installed.
"""
from __future__ import annotations

# --- Dataset 1: kubectl Security Commands -------------------------------- #
KUBECTL_COMMANDS = {
    "list-privileged-pods":
        "kubectl get pods -A -o json | jq '.items[] | "
        "select(.spec.containers[].securityContext.privileged==true) | .metadata.name'",
    "list-hostnetwork-pods":
        "kubectl get pods -A -o json | jq '.items[] | select(.spec.hostNetwork==true) | "
        ".metadata.namespace + \"/\" + .metadata.name'",
    "cluster-admin-bindings":
        "kubectl get clusterrolebindings -o json | jq '.items[] | "
        "select(.roleRef.name==\"cluster-admin\") | .subjects'",
    "wildcard-clusterroles":
        "kubectl get clusterroles -o json | jq '.items[] | select(.rules[].verbs[]==\"*\")'",
    "can-i-list":
        "kubectl auth can-i --list --as=system:serviceaccount:{namespace}:{sa}",
    "networkpolicies":
        "kubectl get networkpolicies -A",
    "nodeport-services":
        "kubectl get svc -A -o json | jq '.items[] | select(.spec.type==\"NodePort\")'",
    "mutating-webhooks":
        "kubectl get mutatingwebhookconfigurations -o json | jq '.items[].webhooks[] | "
        "{name, clientConfig, failurePolicy}'",
    "cronjobs":
        "kubectl get cronjobs -A -o wide",
}

# --- Dataset 2: Scanning Tool Commands ----------------------------------- #
TOOL_COMMANDS = {
    "trivy": [
        "trivy image --severity CRITICAL,HIGH {image}",
        "trivy k8s --report summary cluster",
    ],
    "kube-bench": ["kube-bench run --targets master,node,etcd,policies --json"],
    "kubeaudit": ["kubeaudit all"],
    "kubesec": ["kubesec scan {manifest}"],
    "kubescape": ["kubescape scan framework nsa,mitre,cis-v1.23"],
    "popeye": ["popeye -A --out json"],
    "trufflehog": ["trufflehog docker --image {image}"],
    "cosign": ["cosign verify {image}", "cosign verify-attestation {image}"],
}

# --- Dataset 3: Remediation Playbooks ------------------------------------ #
# Referenced by rule.remediation_ref. {name},{namespace},{kind} are format placeholders.
#
# NOTE: fixes that touch a Pod-template field (securityContext, host namespaces,
# automountServiceAccountToken, ...) are NOT here — they moved to
# `core/remediation_engine.py::FIELD_PATCHES`, which is schema-aware: it knows a bare
# Pod's field lives at `spec.*` while a Deployment/DaemonSet/StatefulSet's lives at
# `spec.template.spec.*` and a CronJob's at `spec.jobTemplate.spec.template.spec.*`, and
# it resolves controller-owned Pods to their owner before ever proposing a patch. A
# single hardcoded command string here can't express any of that — see the module
# docstring in remediation_engine.py for why. This dict now only holds playbooks that
# target an unambiguous, non-Pod-shaped kind directly (ServiceAccount deletion aside,
# a ClusterRoleBinding/NetworkPolicy/etc. IS the object to patch, regardless of what
# owns what), or that were always a manual/policy note rather than a real command.
PLAYBOOKS = {
    "playbook/remove-hostpath": {
        "title": "Remove hostPath / docker.sock mount",
        "commands": ["# manual review required: remove the hostPath volume + mount"],
    },
    "playbook/secret-as-volume": {
        "title": "Mount the Secret as a volume instead of an env var",
        "commands": [
            "# manual review required: env vars sourced from a Secret are visible in "
            "`kubectl describe pod`, crash dumps, and child-process environments. "
            "Replace the env.valueFrom.secretKeyRef with a projected volume mount "
            "(add a `volumes[].secret` + matching `volumeMounts[]` on the container, "
            "then update the app to read the value from the mounted file instead)."
        ],
    },
    "playbook/pin-image-digest": {
        "title": "Pin image to a digest",
        "commands": ["kubectl set image {kind}/{name} -n {namespace} "
                     "<container>=<image>@sha256:<digest>"],
    },
    "playbook/least-privilege-role": {
        "title": "Replace wildcard role with least-privilege",
        "commands": ["# generate a scoped Role from observed `auth can-i` usage; apply it"],
    },
    "playbook/downgrade-binding": {
        "title": "Remove cluster-admin from default SA",
        "commands": ["kubectl delete clusterrolebinding {name}"],
    },
    "playbook/default-deny-netpol": {
        "title": "Apply default-deny NetworkPolicy",
        "commands": [
            "kubectl apply -n {namespace} -f - <<'EOF'\n"
            "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n"
            "metadata: {{name: default-deny-ingress, namespace: {namespace}}}\n"
            "spec: {{podSelector: {{}}, policyTypes: [Ingress]}}\nEOF",
        ],
    },
    "playbook/block-metadata-api": {
        "title": "Block cloud metadata API egress",
        "commands": [
            "kubectl apply -n {namespace} -f - <<'EOF'\n"
            "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n"
            "metadata: {{name: block-metadata-api, namespace: {namespace}}}\n"
            "spec:\n  podSelector: {{}}\n  policyTypes: [Egress]\n  egress:\n"
            "  - to: [{{ipBlock: {{cidr: 0.0.0.0/0, except: [169.254.169.254/32]}}}}]\nEOF",
        ],
    },
    "playbook/psa-enforce-restricted": {
        "title": "Enforce Pod Security Standard 'restricted'",
        "commands": [
            "kubectl label ns {name} "
            "pod-security.kubernetes.io/enforce=restricted "
            "pod-security.kubernetes.io/warn=restricted --overwrite",
        ],
    },
    "playbook/etcd-encryption": {
        "title": "Enable etcd encryption at rest",
        "commands": ["# configure --encryption-provider-config on the API server"],
    },
    "playbook/enable-audit": {
        "title": "Enable API audit logging",
        "commands": ["# set --audit-log-path and --audit-policy-file on the API server"],
    },
    "playbook/apiserver-flags": {
        "title": "Fix insecure API server flags",
        "commands": ["# set --anonymous-auth=false, --insecure-port=0 on the API server"],
    },
    "playbook/restrict-dashboard": {
        "title": "Restrict or remove the dashboard",
        "commands": ["kubectl -n kubernetes-dashboard patch svc kubernetes-dashboard "
                     "-p '{{\"spec\":{{\"type\":\"ClusterIP\"}}}}'"],
    },
    "playbook/remove-webhook": {
        "title": "Remove a malicious admission webhook",
        "commands": ["kubectl delete mutatingwebhookconfiguration {name}"],
    },
    "playbook/require-image-signature": {
        "title": "Require signed images (policy)",
        "commands": ["# deploy a Kyverno/cosign verifyImages policy"],
    },
    "playbook/scope-workload-identity": {
        "title": "Scope cloud workload identity",
        "commands": ["# tighten the IAM policy attached to the workload identity (cloud-side)"],
    },
}

# --- Dataset 4: CVE Knowledge Base (subset, §15.1) ----------------------- #
CVE_KB = {
    "CVE-2018-1002105": {"severity": "CRITICAL", "affects": "<1.10.11",
                         "desc": "API server websocket upgrade -> unauth cluster-admin"},
    "CVE-2020-8554": {"severity": "MEDIUM", "affects": "all",
                      "desc": "MitM via LoadBalancer/ExternalIP"},
    "CVE-2021-25741": {"severity": "HIGH", "affects": "<1.22.1",
                       "desc": "Symlink -> hostPath escape via subPath"},
    "CVE-2024-3177": {"severity": "HIGH", "affects": "<1.30",
                      "desc": "Bypass mountable secrets via ephemeral containers"},
    "CVE-2024-9486": {"severity": "CRITICAL", "affects": "image-builder",
                      "desc": "K8s Image Builder VMs with default credentials"},
}

# --- Dataset 5: Compliance Rule Sets (pointers) -------------------------- #
COMPLIANCE_RULES = {
    "CIS": {"version": "1.8", "tool": "kube-bench", "pass_threshold": 80},
    "PSS": {"levels": ["Privileged", "Baseline", "Restricted"], "enforce": "restricted"},
    "NSA_CISA": {"tool": "kubescape", "sections": ["Pod Security", "Network Policy",
                                                   "Authentication", "Audit Logging",
                                                   "Upgrading"]},
}
