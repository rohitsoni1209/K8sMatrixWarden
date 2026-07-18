"""
Evidence Collector (§6.1).

The ONLY component that touches the cluster. It fetches the union of the resolved rules'
evidence needs, ONCE, constrained to the scan scope, and hands rules a shared, cached,
read-only snapshot. This is the efficiency win over per-tactic agents (redesign §3/§4).

Two backends:
  * MockEvidenceCollector  — loads a JSON fixture (default; zero dependencies).
  * LiveEvidenceCollector  — reads the K8s API as raw camelCase JSON (matches the fixture
                             exactly) via the optional `kubernetes` client.

`Evidence` is the object passed to every rule. Fields are accessed with dotted paths so
rule code is identical in mock and live mode.
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

from .models import Scope


# Logical kind -> the fixture/list bucket key.
KIND_ALIASES = {
    "Pod": "pods",
    "Deployment": "deployments",
    "DaemonSet": "daemonsets",
    "StatefulSet": "statefulsets",
    "ReplicaSet": "replicasets",
    "Job": "jobs",
    "CronJob": "cronjobs",
    "Service": "services",
    "Ingress": "ingresses",
    "NetworkPolicy": "networkpolicies",
    "Namespace": "namespaces",
    "Node": "nodes",
    "ServiceAccount": "serviceaccounts",
    "Secret": "secrets",
    "ConfigMap": "configmaps",
    "Role": "roles",
    "RoleBinding": "rolebindings",
    "ClusterRole": "clusterroles",
    "ClusterRoleBinding": "clusterrolebindings",
    "MutatingWebhookConfiguration": "mutatingwebhookconfigurations",
    "ValidatingWebhookConfiguration": "validatingwebhookconfigurations",
    "ComponentConfig": "componentconfig",     # synthetic: control-plane flags
    "CloudIAM": "cloudiam",                    # synthetic: cloud identity bindings
}


class Evidence:
    """A read-only, scope-filterable snapshot of cluster resources."""

    def __init__(self, buckets: dict[str, list[dict]], scope: Scope):
        self._buckets = buckets
        self._scope = scope

    def get(self, kind: str, *, all_scopes: bool = False) -> list[dict]:
        """Return resources of `kind`, scope-filtered unless all_scopes=True."""
        bucket = KIND_ALIASES.get(kind, kind.lower())
        items = self._buckets.get(bucket, []) or []
        if all_scopes:
            return list(items)
        return [r for r in items if self._scope.matches(r)]

    def raw(self, bucket: str) -> Any:
        return self._buckets.get(bucket)

    def namespaces(self) -> list[str]:
        return [ (n.get("metadata", {}) or {}).get("name")
                 for n in self.get("Namespace", all_scopes=True) ]

    @staticmethod
    def dig(obj: dict, path: str, default: Any = None) -> Any:
        """Dotted-path getter, e.g. dig(pod, 'spec.securityContext.privileged')."""
        cur: Any = obj
        for part in path.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return default
            if cur is None:
                return default
        return cur

    @staticmethod
    def containers(resource: dict) -> list[dict]:
        """All containers (regular + init + ephemeral) of a pod/workload."""
        spec = resource.get("spec", {}) or {}
        if "template" in spec:
            spec = (spec.get("template", {}) or {}).get("spec", {}) or {}
        out = []
        out.extend(spec.get("containers", []) or [])
        out.extend(spec.get("initContainers", []) or [])
        out.extend(spec.get("ephemeralContainers", []) or [])
        return out

    @staticmethod
    def pod_spec(resource: dict) -> dict:
        spec = resource.get("spec", {}) or {}
        if "template" in spec:
            return (spec.get("template", {}) or {}).get("spec", {}) or {}
        return spec


class EvidenceCollector:
    """Base collector: caches fetched buckets so each kind is fetched at most once."""

    def __init__(self) -> None:
        self._cache: dict[str, list[dict]] = {}
        #: Non-fatal problems hit while collecting (e.g. a resource type the scanner's
        #: RBAC can't read, or an API group absent on this cluster). The scan proceeds
        #: with whatever it could read; surfaces make partial coverage visible instead of
        #: silently under-reporting. Empty on the mock backend.
        self.warnings: list[str] = []

    def collect(self, needs: set[str], scope: Scope) -> Evidence:
        for kind in needs:
            bucket = KIND_ALIASES.get(kind, kind.lower())
            if bucket not in self._cache:
                self._cache[bucket] = self._fetch(kind, bucket)
        return Evidence(self._cache, scope)

    def _fetch(self, kind: str, bucket: str) -> list[dict]:  # pragma: no cover - overridden
        raise NotImplementedError


class MockEvidenceCollector(EvidenceCollector):
    """Loads all resources from a single JSON fixture (default backend)."""

    def __init__(self, fixture_path: str):
        super().__init__()
        with open(fixture_path, "r", encoding="utf-8") as fh:
            self._data = json.load(fh)

    def _fetch(self, kind: str, bucket: str) -> list[dict]:
        items = self._data.get(bucket, [])
        # Tag items with their kind if the fixture omitted it.
        for it in items:
            it.setdefault("kind", kind)
        return list(items)


def _api_exception_type() -> tuple:
    """The kubernetes client's ApiException, or an empty tuple if the package is absent
    (isinstance(x, ()) is always False, so callers stay safe either way)."""
    try:
        from kubernetes.client.exceptions import ApiException  # type: ignore
        return (ApiException,)
    except Exception:
        return ()


def _is_connection_error(exc: BaseException) -> bool:
    """True when `exc` is a transport/reachability failure — the cluster is down, the
    endpoint is wrong, DNS fails, the connection is refused, or a request times out —
    as opposed to an HTTP response like 403/404. A connection failure means nothing on
    the cluster is scannable (fatal, one clean message); an HTTP error affects only one
    resource type (skip it, keep scanning)."""
    api_exc = _api_exception_type()
    if api_exc and isinstance(exc, api_exc):
        # status 0/None => the client never received an HTTP response = transport failure.
        return not getattr(exc, "status", None)
    try:
        import urllib3
        if isinstance(exc, urllib3.exceptions.HTTPError):
            return True
    except Exception:
        pass
    return isinstance(exc, (ConnectionError, TimeoutError, OSError))


def _short_api_error(exc: BaseException) -> str:
    """A one-line, human reason for skipping a resource type (used in scan warnings)."""
    for api_exc in _api_exception_type():
        if isinstance(exc, api_exc):
            status = getattr(exc, "status", None)
            if status == 403:
                return "HTTP 403 Forbidden — scanner ServiceAccount lacks read RBAC for it"
            if status == 404:
                return "HTTP 404 — API group/resource not present on this cluster"
            reason = (getattr(exc, "reason", "") or "").strip()
            return f"HTTP {status} {reason}".strip()
    first = (str(exc).splitlines() or [""])[0][:120]
    return f"{type(exc).__name__}: {first}" if first else type(exc).__name__


class LiveEvidenceCollector(EvidenceCollector):
    """
    Reads the live cluster as raw camelCase JSON via the optional `kubernetes` client.
    Imported lazily so the tool runs without the dependency.

    Resilient by design: a connection failure (cluster down / wrong endpoint) fails fast
    with one clear, actionable message instead of a urllib3 traceback, and a per-resource
    HTTP error (RBAC-forbidden secret, absent API group) is recorded as a warning and
    skipped rather than aborting the whole scan.
    """

    #: Per-request cap (seconds) so an unreachable/slow API server can't hang a scan.
    _REQUEST_TIMEOUT = 15
    _PREFLIGHT_TIMEOUT = 6

    def __init__(self, kubeconfig: Optional[str] = None, context: Optional[str] = None):
        super().__init__()
        try:
            from kubernetes import client, config  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "Live scanning requires the 'kubernetes' package. "
                "Install it (`pip install kubernetes`) or use --mock."
            ) from exc
        if kubeconfig or context:
            # User explicitly pointed us at a kubeconfig/context — a failure here is a
            # real, specific problem (bad path, unknown context) and must not be masked
            # by a confusing in-cluster-config fallback error.
            try:
                config.load_kube_config(config_file=kubeconfig, context=context)
            except Exception as exc:
                raise RuntimeError(
                    f"Could not load kubeconfig (file={kubeconfig!r}, "
                    f"context={context!r}): {exc}\n"
                    f"Run `kubectl config get-contexts` to see valid context names."
                ) from exc
        else:
            try:
                config.load_kube_config()
            except Exception:
                config.load_incluster_config()
        self._client = client
        self._api = client.ApiClient()
        self._context = context
        self._preflight()

    def _unreachable(self, exc: BaseException) -> RuntimeError:
        """A clear, actionable error for 'the API server can't be reached' — the common
        live-scan failure (cluster stopped, wrong endpoint) — instead of a raw traceback."""
        ctx = self._context or "(current-context)"
        detail = (str(exc).splitlines() or [""])[0][:200] or type(exc).__name__
        hint_ctx = self._context or "<name>"
        return RuntimeError(
            f"Cannot reach the Kubernetes API server for context {ctx!r}.\n"
            f"  → {type(exc).__name__}: {detail}\n"
            f"The cluster may be stopped, or the context may point at the wrong endpoint.\n"
            f"Verify it is running:  kubectl --context {hint_ctx} cluster-info\n"
            f"Or scan the bundled sample cluster instead:  add --mock")

    def _preflight(self) -> None:
        """Probe the API server once up front so an unreachable cluster fails fast with a
        clear message. Only a *connection* failure is fatal here — a 401/403/etc on
        /version (some clusters gate it) is fine; real resource fetches handle their own
        auth per type."""
        try:
            self._api.call_api("/version", "GET", auth_settings=["BearerToken"],
                               _preload_content=False,
                               _request_timeout=self._PREFLIGHT_TIMEOUT)
        except Exception as exc:
            if _is_connection_error(exc):
                raise self._unreachable(exc) from exc

    def _get_json(self, path: str) -> list[dict]:
        """Call the REST path and parse the raw JSON body ourselves (camelCase preserved).

        `_preload_content=False` returns the underlying HTTP response without the client
        trying to deserialize it into a typed model, so this stays compatible across
        kubernetes-client versions — the older `response_type=` kwarg was removed in v33+
        (renamed to `response_types_map`), which otherwise breaks live scanning on a
        modern client even though pyproject only requires `kubernetes>=28`.
        """
        resp = self._api.call_api(
            path, "GET", auth_settings=["BearerToken"],
            _preload_content=False, _request_timeout=self._REQUEST_TIMEOUT,
        )
        raw = resp[0] if isinstance(resp, tuple) else resp
        body = getattr(raw, "data", raw)
        if isinstance(body, (bytes, bytearray)):
            body = body.decode("utf-8")
        data = json.loads(body) if body else {}
        return data.get("items", []) if isinstance(data, dict) else []

    _PATHS = {
        "pods": "/api/v1/pods",
        "services": "/api/v1/services",
        "secrets": "/api/v1/secrets",
        "configmaps": "/api/v1/configmaps",
        "namespaces": "/api/v1/namespaces",
        "nodes": "/api/v1/nodes",
        "serviceaccounts": "/api/v1/serviceaccounts",
        "deployments": "/apis/apps/v1/deployments",
        "daemonsets": "/apis/apps/v1/daemonsets",
        "statefulsets": "/apis/apps/v1/statefulsets",
        "replicasets": "/apis/apps/v1/replicasets",
        "jobs": "/apis/batch/v1/jobs",
        "cronjobs": "/apis/batch/v1/cronjobs",
        "networkpolicies": "/apis/networking.k8s.io/v1/networkpolicies",
        "ingresses": "/apis/networking.k8s.io/v1/ingresses",
        "roles": "/apis/rbac.authorization.k8s.io/v1/roles",
        "rolebindings": "/apis/rbac.authorization.k8s.io/v1/rolebindings",
        "clusterroles": "/apis/rbac.authorization.k8s.io/v1/clusterroles",
        "clusterrolebindings": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        "mutatingwebhookconfigurations":
            "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations",
        "validatingwebhookconfigurations":
            "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
    }

    def _fetch(self, kind: str, bucket: str) -> list[dict]:
        if bucket == "componentconfig":
            # Mitigation Layer 1/2: build ComponentConfig from kube-system static-pod specs.
            return self._build_component_config()
        path = self._PATHS.get(bucket)
        if not path:
            return []   # synthetic buckets (cloudiam) unavailable without an adapter
        try:
            items = self._get_json(path)
        except Exception as exc:
            if _is_connection_error(exc):
                # The cluster went unreachable mid-scan — nothing more is scannable.
                raise self._unreachable(exc) from exc
            # RBAC-forbidden, missing API group, or a transient error for THIS resource
            # type only: skip it, record why, and keep scanning everything else. Honest
            # partial coverage beats aborting the whole scan over one resource type.
            self.warnings.append(f"{kind}: skipped ({_short_api_error(exc)})")
            return []
        for it in items:
            it.setdefault("kind", kind)
        return items

    def _build_component_config(self) -> list[dict]:
        """Parse control-plane component flags from their kube-system static Pods.

        On self-managed (kubeadm/k3s) clusters the API server, controller-manager,
        scheduler and etcd run as static Pods whose --flags are visible in the Pod spec.
        This recovers ~38 CIS 'process flag' controls with NO node access.
        """
        try:
            pods = self._get_json("/api/v1/namespaces/kube-system/pods")
        except Exception:
            return []
        return [build_component_config(pods)]


def build_component_config(pods: list[dict]) -> dict:
    """Turn kube-system control-plane Pods into a ComponentConfig evidence object."""
    name_to_comp = {
        "kube-apiserver": "apiServer",
        "kube-controller-manager": "controllerManager",
        "kube-scheduler": "scheduler",
        "etcd": "etcd",
    }
    spec: dict = {"version": None}
    for pod in pods:
        pname = (pod.get("metadata", {}) or {}).get("name", "")
        comp = next((c for prefix, c in name_to_comp.items()
                     if pname.startswith(prefix)), None)
        if not comp:
            continue
        containers = (pod.get("spec", {}) or {}).get("containers", []) or []
        tokens: list[str] = []
        for c in containers:
            tokens += (c.get("command", []) or []) + (c.get("args", []) or [])
        flags = _parse_flags(tokens)
        entry = spec.setdefault(comp, {})
        entry["flags"] = flags
        if comp == "apiServer":
            entry["anonymousAuth"] = flags.get("anonymous-auth") == "true"
            entry["insecurePort"] = int(flags.get("insecure-port", 0) or 0)
            entry["auditLogPath"] = flags.get("audit-log-path", "")
            entry["encryptionProvider"] = flags.get("encryption-provider-config", "")
        elif comp == "etcd":
            entry["clientCertAuth"] = flags.get("client-cert-auth") == "true"
    return {"kind": "ComponentConfig", "metadata": {"name": "control-plane"}, "spec": spec}


def _parse_flags(tokens: list[str]) -> dict:
    """Parse ['--k=v', '--flag', 'value'] into {k: v}."""
    flags: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if isinstance(tok, str) and tok.startswith("--"):
            body = tok[2:]
            if "=" in body:
                k, v = body.split("=", 1)
                flags[k] = v
            else:
                nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
                if isinstance(nxt, str) and not nxt.startswith("--"):
                    flags[body] = nxt
                    i += 1
                else:
                    flags[body] = "true"
        i += 1
    return flags


# --------------------------------------------------------------------------- #
# Provider detection — which cloud/distro, so callers pick the right CIS profile
# (and, later, the right cloud-IAM API). Core K8s API paths are identical across
# providers, so scanning itself needs no per-cloud branch; only the managed-control-
# plane question (CIS sections 1-3) and cloud-IAM evidence do.
# --------------------------------------------------------------------------- #
#: A managed-service node label is authoritative for "this is GKE/EKS/AKS" — its
#: presence means the control plane is provider-owned (CIS profile => NA sections 1-3).
_MANAGED_NODE_LABELS = {
    "cloud.google.com/gke-nodepool": "gke",
    "eks.amazonaws.com/nodegroup": "eks",
    "kubernetes.azure.com/cluster": "aks",
}
#: providerID scheme names the IaaS. A cloud VM WITHOUT a managed label is
#: self-managed K8s on that cloud — control plane is still inspectable, so its CIS
#: profile stays 'self-managed'; only `cloud` reflects the IaaS (for cloud-IAM APIs).
_PROVIDERID_CLOUD = {"gce": "gcp", "aws": "aws", "azure": "azure"}


def detect_provider(nodes: list[dict]) -> dict:
    """Best-effort cluster provider from Node objects. Returns:
        cloud   — 'gcp' | 'aws' | 'azure' | 'local'   (which IaaS; picks cloud-IAM API)
        managed — True if a managed offering owns the control plane (GKE/EKS/AKS)
        profile — 'gke' | 'eks' | 'aks' | 'self-managed'   (feed straight to CIS)
    Managed-service node labels are authoritative for `managed`/`profile`; providerID
    only names the cloud. Empty/kind/k3s nodes => local, self-managed."""
    cloud = "local"
    for node in nodes:
        pid = (node.get("spec", {}) or {}).get("providerID", "") or ""
        scheme = pid.split(":", 1)[0].lower()
        if scheme in _PROVIDERID_CLOUD:
            cloud = _PROVIDERID_CLOUD[scheme]
            break
    profile = None
    for node in nodes:
        labels = (node.get("metadata", {}) or {}).get("labels", {}) or {}
        profile = next((p for lbl, p in _MANAGED_NODE_LABELS.items() if lbl in labels), None)
        if profile:
            break
    return {"cloud": cloud, "managed": profile is not None,
            "profile": profile or "self-managed"}


def default_fixture_path() -> str:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, "data", "fixtures", "mock_cluster.json")
