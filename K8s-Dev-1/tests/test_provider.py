"""detect_provider: Node providerID + managed labels -> cloud/profile."""
from k8smatrixwarden.core.evidence import detect_provider


def _node(provider_id="", labels=None):
    return {"spec": {"providerID": provider_id},
            "metadata": {"labels": labels or {}}}


def test_gke():
    got = detect_provider([_node("gce://proj/zone/vm",
                                 {"cloud.google.com/gke-nodepool": "pool-1"})])
    assert got == {"cloud": "gcp", "managed": True, "profile": "gke"}


def test_eks():
    got = detect_provider([_node("aws:///us-east-1a/i-abc",
                                 {"eks.amazonaws.com/nodegroup": "ng"})])
    assert got == {"cloud": "aws", "managed": True, "profile": "eks"}


def test_aks():
    got = detect_provider([_node("azure:///subscriptions/x/vm",
                                 {"kubernetes.azure.com/cluster": "mc"})])
    assert got == {"cloud": "azure", "managed": True, "profile": "aks"}


def test_local_empty():
    assert detect_provider([_node()]) == {
        "cloud": "local", "managed": False, "profile": "self-managed"}


def test_self_managed_on_cloud_vm():
    # AWS VM, no EKS label -> cloud reflects IaaS, but control plane is self-managed
    # (inspectable), so CIS profile must stay self-managed, not eks.
    got = detect_provider([_node("aws:///us-east-1a/i-xyz")])
    assert got == {"cloud": "aws", "managed": False, "profile": "self-managed"}


if __name__ == "__main__":
    for fn in (test_gke, test_eks, test_aks, test_local_empty,
               test_self_managed_on_cloud_vm):
        fn()
    print("ok")
