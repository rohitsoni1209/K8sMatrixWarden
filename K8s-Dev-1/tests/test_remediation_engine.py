"""
Schema-aware, resource-aware remediation engine (core/remediation_engine.py).

Covers the exact bug report this engine was built to fix — a Pod owned by a controller
(Deployment/DaemonSet/StatefulSet/CronJob) must NEVER get a `kubectl patch pod ...`
command for a field that lives at `spec.template.spec` on the controller but doesn't
exist at all on a bare Pod (Pods have no `.spec.template`) — plus the full scenario
matrix requested: standalone / Deployment / DaemonSet / StatefulSet / Job / CronJob
Pods, Helm-managed, ArgoCD-managed, kube-system, immutable fields, invalid patch paths,
and missing ownerReferences.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.evidence import Evidence
from k8smatrixwarden.core.models import (BlastRadius, DetectionMethod, Exploitability, Finding,
                                ResourceRef, Scope, ScopeLevel, Severity)
from k8smatrixwarden.core.remediation_engine import (CONTROLLER_KINDS_PATCHABLE, FIELD_PATCHES,
                                            POD_SPEC_PATH_PREFIX, FieldPatch,
                                            RemediationEngine, detect_deployment_method,
                                            generate_remediation, is_system_workload)
from k8smatrixwarden.shards.base import ref as base_ref
from k8smatrixwarden.shards.workload_pod_security import ref as owner_resolving_ref

ENGINE = RemediationEngine()


def _finding(*, remediation_ref="playbook/pod-security-context", kind="Pod",
            name="mypod", namespace="production", owner_kind=None, owner_name=None,
            labels=None, annotations=None, evidence=None,
            severity=Severity.MEDIUM) -> Finding:
    res = ResourceRef(kind=kind, name=name, namespace=namespace, owner_kind=owner_kind,
                      owner_name=owner_name, labels=labels or {},
                      annotations=annotations or {})
    return Finding(
        rule_id="workload-no-seccomp", title="No seccomp profile", severity=severity,
        resource=res, message=f"container 'app' has no seccomp profile",
        owning_shard="workload_pod_security", detection_method=DetectionMethod.STATIC_CONFIG,
        exploitability=Exploitability.LOCAL, blast_radius=BlastRadius.POD,
        remediation_ref=remediation_ref, evidence=evidence or {},
    )


# ===================================================================================
# 1. Standalone Pod
# ===================================================================================
def test_standalone_pod_is_never_patched_directly():
    f = _finding(kind="Pod", name="cache-redis", namespace="staging")  # no owner at all
    r = generate_remediation(f)
    assert r.automatable is False
    assert r.kubectl_command is None
    assert "immutable" in r.reason_not_automated.lower()
    # must recommend recreate, never a live patch of the immutable field
    assert any("delete pod" in s for s in r.remediation_steps)
    assert any("apply -f" in s for s in r.remediation_steps)


# ===================================================================================
# 2. Deployment-owned Pod
# ===================================================================================
def test_deployment_owned_pod_targets_the_deployment():
    f = _finding(kind="Pod", name="payment-api-7d9f8-abcde", namespace="production",
                owner_kind="Deployment", owner_name="payment-api")
    r = generate_remediation(f)
    assert r.automatable is True
    assert r.target_kind == "Deployment" and r.target_name == "payment-api"
    assert r.kubectl_command.startswith("kubectl patch deployment payment-api "
                                        "-n production")
    assert '"spec":{"template":{"spec"' in r.kubectl_command.replace(" ", "")
    assert "kubectl rollout status deployment/payment-api" in r.validation_commands[0] \
        or any("rollout status" in c for c in r.validation_commands)
    assert any("rollout undo deployment/payment-api" in c for c in r.rollback_commands)


# ===================================================================================
# 3. DaemonSet-owned Pod — the LITERAL bug report scenario
# ===================================================================================
def test_daemonset_owned_pod_targets_the_daemonset_not_the_pod():
    f = _finding(kind="Pod", name="aws-node-64w2k", namespace="kube-system",
                owner_kind="DaemonSet", owner_name="aws-node",
                labels={"k8s-app": "aws-node"})
    r = generate_remediation(f)
    assert r.automatable is True
    assert r.target_kind == "DaemonSet" and r.target_name == "aws-node"
    # THE regression this whole engine exists for:
    assert "patch pod aws-node-64w2k" not in r.kubectl_command
    assert r.kubectl_command.startswith("kubectl patch daemonset aws-node -n kube-system")
    assert '"spec":{"template":{"spec":' in r.kubectl_command.replace(" ", "")
    # a bare Pod never has spec.template — must never appear when the target is a Pod
    assert "kubectl patch pod " not in r.kubectl_command


def test_daemonset_owned_pod_in_kube_system_warns_about_system_component():
    f = _finding(kind="Pod", name="aws-node-64w2k", namespace="kube-system",
                owner_kind="DaemonSet", owner_name="aws-node")
    r = generate_remediation(f)
    assert any("Kubernetes/EKS managed component" in w for w in r.warnings)
    assert any("vendor documentation" in w for w in r.warnings)


# ===================================================================================
# 4. StatefulSet-owned Pod
# ===================================================================================
def test_statefulset_owned_pod_targets_the_statefulset():
    f = _finding(kind="Pod", name="postgres-0", namespace="production",
                owner_kind="StatefulSet", owner_name="postgres")
    r = generate_remediation(f)
    assert r.automatable is True
    assert r.target_kind == "StatefulSet" and r.target_name == "postgres"
    assert r.kubectl_command.startswith("kubectl patch statefulset postgres "
                                        "-n production")


# ===================================================================================
# 5. Job-owned Pod (standalone Job, no CronJob) — must NOT be treated as automatable
# ===================================================================================
def test_job_owned_pod_without_cronjob_is_not_automated():
    f = _finding(kind="Pod", name="migrate-abcde", namespace="production",
                owner_kind="Job", owner_name="migrate-job")
    r = generate_remediation(f)
    assert r.automatable is False
    assert r.kubectl_command is None
    assert "migrate-job" in r.reason_not_automated
    assert any("kubectl get job migrate-job" in s for s in r.remediation_steps)


# ===================================================================================
# 6. CronJob-owned Pod (Job resolved up to its CronJob)
# ===================================================================================
def test_cronjob_owned_pod_targets_cronjob_with_jobtemplate_path():
    f = _finding(kind="Pod", name="backup-cron-1234567-xyz", namespace="production",
                owner_kind="CronJob", owner_name="backup-cron")
    r = generate_remediation(f)
    assert r.automatable is True
    assert r.target_kind == "CronJob" and r.target_name == "backup-cron"
    assert r.kubectl_command.startswith("kubectl patch cronjob backup-cron -n production")
    # CronJob nests one level deeper than Deployment/DaemonSet/StatefulSet
    assert '"spec":{"jobTemplate":{"spec":{"template":{"spec":' in \
        r.kubectl_command.replace(" ", "")
    assert any("future scheduled runs" in s.lower() for s in r.remediation_steps)


# ===================================================================================
# 7. Helm-managed Deployment
# ===================================================================================
def test_helm_managed_deployment_recommends_helm_upgrade_not_live_patch():
    f = _finding(kind="Pod", name="web-abc123", namespace="production",
                owner_kind="Deployment", owner_name="web",
                labels={"app.kubernetes.io/managed-by": "Helm",
                       "app.kubernetes.io/instance": "web"})
    r = generate_remediation(f)
    assert r.deployment_method == "helm"
    assert any("Helm-managed" in w and "helm upgrade" in w for w in r.warnings)
    # still automatable (the command IS correct) — Helm just gets a drift warning, not a block
    assert r.automatable is True


def test_detect_deployment_method_helm():
    assert detect_deployment_method({"app.kubernetes.io/managed-by": "Helm"}, {}) == "helm"


# ===================================================================================
# 8. ArgoCD-managed Deployment
# ===================================================================================
def test_argocd_managed_deployment_recommends_gitops_update():
    f = _finding(kind="Pod", name="api-def456", namespace="production",
                owner_kind="Deployment", owner_name="api",
                labels={"argocd.argoproj.io/instance": "api-app"})
    r = generate_remediation(f)
    assert r.deployment_method == "argocd"
    assert any("GitOps" in w and "ArgoCD" in w for w in r.warnings)


def test_flux_managed_deployment_recommends_gitops_update():
    assert detect_deployment_method({}, {"fluxcd.io/sync-checksum": "abc"}) == "flux"


# ===================================================================================
# 9. kube-system DaemonSet / system workload detection
# ===================================================================================
def test_is_system_workload_by_namespace():
    assert is_system_workload("kube-system", "anything") is True


def test_is_system_workload_by_name_marker_outside_kube_system():
    # some managed components run outside kube-system too (e.g. a dedicated namespace)
    assert is_system_workload("monitoring", "metrics-server-abc123") is True


def test_is_system_workload_false_for_ordinary_app():
    assert is_system_workload("production", "payment-api") is False


# ===================================================================================
# 10. Immutable field handling
# ===================================================================================
def test_immutable_field_on_bare_pod_is_blocked():
    field = FieldPatch(path="securityContext", value={"runAsNonRoot": True},
                       title="x", mutable_on_live_pod=False)
    patchable, reason = ENGINE._validate(field, "Pod", "mypod", "standalone")
    assert patchable is False
    assert "immutable" in reason.lower()


def test_a_field_explicitly_marked_mutable_on_live_pod_would_be_allowed():
    # proves the gate is a real check, not a hardcoded "Pod always blocked"
    field = FieldPatch(path="activeDeadlineSeconds", value=300, title="x",
                       mutable_on_live_pod=True)
    patchable, reason = ENGINE._validate(field, "Pod", "mypod", "standalone")
    assert patchable is True and reason is None


def test_controller_target_is_always_mutable_regardless_of_flag():
    field = FieldPatch(path="securityContext", value={"runAsNonRoot": True}, title="x",
                       mutable_on_live_pod=False)
    for kind in CONTROLLER_KINDS_PATCHABLE:
        patchable, reason = ENGINE._validate(field, kind, "name", "controller")
        assert patchable is True, kind


# ===================================================================================
# 11. Invalid / unsupported patch path
# ===================================================================================
def test_unsupported_target_kind_never_generates_a_command():
    field = FIELD_PATCHES["playbook/pod-security-context"]
    patchable, reason = ENGINE._validate(field, "Ingress", "some-ingress", "direct")
    assert patchable is False
    assert "no known pod-template schema path" in reason.lower()


def test_unresolved_replicaset_owner_never_generates_a_command():
    f = _finding(kind="Pod", name="nginx-7d9f8-abc", namespace="production",
                owner_kind="ReplicaSet", owner_name="nginx-7d9f8c9d76")
    r = generate_remediation(f)
    assert r.automatable is False
    assert r.kubectl_command is None
    assert "nginx-7d9f8c9d76" in r.reason_not_automated
    assert "not update already-running pods" in r.reason_not_automated.lower()


def test_every_field_patch_has_a_known_pod_spec_prefix():
    # a data-integrity guard: every registered field must resolve on every patchable kind
    for ref, field in FIELD_PATCHES.items():
        if field.scope == "object-root":
            continue
        for kind in CONTROLLER_KINDS_PATCHABLE | {"Pod"}:
            assert kind in POD_SPEC_PATH_PREFIX, f"{ref} / {kind}"


# ===================================================================================
# 12. Missing ownerReferences
# ===================================================================================
def test_missing_ownerreferences_resolves_to_no_owner():
    ref = base_ref({"kind": "Pod", "metadata": {"name": "lonely", "namespace": "default"}})
    assert ref.owner_kind is None and ref.owner_name is None


def test_empty_ownerreferences_list_resolves_to_no_owner():
    ref = base_ref({"kind": "Pod",
                    "metadata": {"name": "lonely", "namespace": "default",
                                "ownerReferences": []}})
    assert ref.owner_kind is None and ref.owner_name is None


def test_missing_ownerreference_finding_recommends_manual_recreate():
    f = _finding(kind="Pod", name="lonely", namespace="default", owner_kind=None)
    r = generate_remediation(f)
    assert r.automatable is False
    assert r.owner_resource is None
    assert "no owning controller" in r.reason_not_automated.lower()


# ===================================================================================
# Owner-chain resolution (workload_pod_security.py's evidence-aware ref()) — proves the
# ReplicaSet->Deployment and Job->CronJob hops actually work against real Evidence, not
# just the Finding-level unit tests above which assert on an already-resolved owner.
# ===================================================================================
def _evidence(**buckets) -> Evidence:
    return Evidence(buckets, Scope(ScopeLevel.CLUSTER))


def test_owner_resolving_ref_hops_replicaset_to_deployment():
    pod = {"kind": "Pod", "metadata": {"name": "nginx-7d9f8-abc", "namespace": "production",
          "ownerReferences": [{"kind": "ReplicaSet", "name": "nginx-7d9f8c9d76",
                               "controller": True}]}}
    rs = {"kind": "ReplicaSet", "metadata": {"name": "nginx-7d9f8c9d76",
         "namespace": "production",
         "ownerReferences": [{"kind": "Deployment", "name": "nginx", "controller": True}]}}
    ev = _evidence(replicasets=[rs])
    r = owner_resolving_ref(ev, pod)
    assert r.owner_kind == "Deployment" and r.owner_name == "nginx"


def test_owner_resolving_ref_hops_job_to_cronjob():
    pod = {"kind": "Pod", "metadata": {"name": "backup-1700000000-abc",
          "namespace": "production",
          "ownerReferences": [{"kind": "Job", "name": "backup-1700000000",
                               "controller": True}]}}
    job = {"kind": "Job", "metadata": {"name": "backup-1700000000", "namespace": "production",
          "ownerReferences": [{"kind": "CronJob", "name": "backup", "controller": True}]}}
    ev = _evidence(jobs=[job])
    r = owner_resolving_ref(ev, pod)
    assert r.owner_kind == "CronJob" and r.owner_name == "backup"


def test_owner_resolving_ref_falls_back_when_replicaset_not_in_evidence():
    pod = {"kind": "Pod", "metadata": {"name": "nginx-abc", "namespace": "production",
          "ownerReferences": [{"kind": "ReplicaSet", "name": "nginx-missing",
                               "controller": True}]}}
    ev = _evidence(replicasets=[])   # RS genuinely not present in this scan's evidence
    r = owner_resolving_ref(ev, pod)
    # conservative: stays at ReplicaSet, does NOT guess a Deployment name
    assert r.owner_kind == "ReplicaSet" and r.owner_name == "nginx-missing"


def test_owner_resolving_ref_prefers_owner_object_labels_over_pod_labels():
    pod = {"kind": "Pod", "metadata": {"name": "web-abc", "namespace": "production",
          "labels": {},  # pod template didn't copy the release label down
          "ownerReferences": [{"kind": "DaemonSet", "name": "web", "controller": True}]}}
    ds = {"kind": "DaemonSet", "metadata": {"name": "web", "namespace": "production",
         "labels": {"app.kubernetes.io/managed-by": "Helm"}}}
    ev = _evidence(daemonsets=[ds])
    r = owner_resolving_ref(ev, pod)
    assert r.labels.get("app.kubernetes.io/managed-by") == "Helm"


# ===================================================================================
# Container-level fixes target the right container BY NAME via strategic merge —
# never a positional containers[0] json-add (which also fails on missing intermediates).
# ===================================================================================
def test_container_scoped_patch_targets_container_by_name_strategic_merge():
    f = _finding(remediation_ref="playbook/drop-capabilities", kind="Pod",
                name="web-abc", namespace="production", owner_kind="Deployment",
                owner_name="web", evidence={"container": "sidecar"})
    r = generate_remediation(f)
    assert r.automatable is True
    cmd = r.kubectl_command
    assert cmd.startswith("kubectl patch deployment web -n production -p")
    assert "--type=json" not in cmd and "containers[0]" not in cmd
    flat = cmd.replace(" ", "")
    assert '"name":"sidecar"' in flat                 # merge key → the right container
    assert '"drop":["ALL"]' in flat


def test_container_scoped_alternative_yaml_is_well_formed():
    # the alt-YAML shown to users must have valid nesting: capabilities UNDER
    # securityContext, and `name` as a SIBLING of securityContext (not a stray key).
    f = _finding(remediation_ref="playbook/drop-capabilities", kind="Pod", name="p",
                namespace="prod", owner_kind="Deployment", owner_name="web",
                evidence={"container": "app"})
    y = generate_remediation(f).alternative_yaml
    lines = [ln for ln in y.splitlines() if ln.strip() and "```" not in ln]

    sc_col = next(l for l in lines if "securityContext:" in l).index("securityContext")
    caps_col = next(l for l in lines if "capabilities:" in l).index("capabilities")
    name_col = next(l for l in lines if "name:" in l).index("name")
    assert caps_col > sc_col          # capabilities nested inside securityContext
    assert name_col == sc_col         # name is a sibling key of the same container


def test_container_scoped_patch_without_container_name_is_not_automatable():
    # no evidence['container'] → we must not guess a positional index
    f = _finding(remediation_ref="playbook/drop-capabilities", kind="Pod",
                name="web-abc", namespace="production", owner_kind="Deployment",
                owner_name="web", evidence={})
    r = generate_remediation(f)
    assert r.automatable is False
    assert r.kubectl_command is None


# ===================================================================================
# Previously-dangling refs (found during MCP-tool review, fixed alongside it)
# ===================================================================================
def test_resource_limits_ref_is_no_longer_dangling():
    f = _finding(remediation_ref="playbook/resource-limits", kind="Pod", name="x",
                namespace="production", owner_kind="Deployment", owner_name="x",
                evidence={"container": "app"})
    r = generate_remediation(f)
    assert r.automatable is True
    cmd = r.kubectl_command
    assert cmd.startswith("kubectl patch deployment x -n production -p")
    assert "--type=json" not in cmd
    flat = cmd.replace(" ", "")
    assert '"name":"app"' in flat
    assert '"limits":{"cpu":"500m","memory":"512Mi"}' in flat


def test_pin_image_digest_template_is_not_presented_as_runnable():
    # the command still carries <image>@sha256:<digest> placeholders the operator must
    # fill (a registry lookup) — it must NOT be offered as a copy-paste-ready command.
    f = _finding(remediation_ref="playbook/pin-image-digest", kind="Deployment",
                name="web", namespace="production")
    r = generate_remediation(f)
    assert r.automatable is False
    assert r.kubectl_command is None
    assert "digest" in (r.reason_not_automated or "").lower()
    # the template is still shown in the steps so the operator knows what to run
    assert any("sha256" in s for s in r.remediation_steps)


def test_secret_as_volume_ref_is_no_longer_dangling():
    from k8smatrixwarden.mcp.datasets import PLAYBOOKS
    assert "playbook/secret-as-volume" in PLAYBOOKS
    f = _finding(remediation_ref="playbook/secret-as-volume", kind="Pod", name="x",
                namespace="production", owner_kind="Deployment", owner_name="x")
    r = generate_remediation(f)
    # a manual/comment-only playbook — never claim it's an automated fix
    assert r.automatable is False


# ===================================================================================
# Output completeness (§8 required fields)
# ===================================================================================
def test_result_as_dict_has_every_required_section():
    f = _finding(kind="Pod", name="aws-node-64w2k", namespace="kube-system",
                owner_kind="DaemonSet", owner_name="aws-node")
    d = generate_remediation(f).as_dict()
    for key in ("finding", "affected_resource", "owner_resource", "root_cause", "risk",
               "remediation_steps", "kubectl_command", "alternative_yaml",
               "validation_commands", "rollback_commands", "warnings", "references"):
        assert key in d, key


def test_render_text_shows_manual_required_when_not_automatable():
    f = _finding(kind="Pod", name="cache-redis", namespace="staging")
    text = generate_remediation(f).render_text()
    assert "cannot be safely automated" in text


# ===================================================================================
# The core regression guard: across every registered field patch, no combination of
# target kind ever produces the literal broken pattern from the bug report.
# ===================================================================================
def test_never_generates_pod_scoped_template_patch():
    for pb_ref, field in FIELD_PATCHES.items():
        for owner_kind in CONTROLLER_KINDS_PATCHABLE:
            f = _finding(remediation_ref=pb_ref, kind="Pod", name="x", namespace="ns",
                        owner_kind=owner_kind, owner_name="owner-name",
                        evidence={"container": "app"})
            r = generate_remediation(f)
            if r.kubectl_command:
                assert "patch pod " not in r.kubectl_command, (pb_ref, owner_kind)
        # a standalone pod must never get a patch command for a pod-template field either
        f = _finding(remediation_ref=pb_ref, kind="Pod", name="x", namespace="ns",
                    evidence={"container": "app"})
        r = generate_remediation(f)
        if field.scope == "pod-template" and not field.mutable_on_live_pod:
            assert r.kubectl_command is None, pb_ref
