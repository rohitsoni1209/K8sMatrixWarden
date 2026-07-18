"""
Live-scan robustness (no real cluster needed).

Covers the resilience layer added so live scanning fails cleanly instead of leaking a
urllib3 traceback, and degrades gracefully when one resource type is inaccessible:
  * `_is_connection_error` classifies transport failures vs HTTP responses
  * a per-resource HTTP 403/404 is recorded as a warning and skipped, not fatal
  * a connection failure raises one clear, actionable RuntimeError

Uses the zero-dependency runner's calling convention (no fixtures): collectors are built
via __new__ to skip network I/O, and `_get_json` is replaced with a plain instance
attribute (instance attrs aren't bound, so the stub receives just `path`).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from k8smatrixwarden.core.evidence import (
    EvidenceCollector, LiveEvidenceCollector, _is_connection_error, _short_api_error)
from k8smatrixwarden.core.models import Scope, ScopeLevel


class _FakeApiException(Exception):
    """Mimics kubernetes.client.exceptions.ApiException (has .status/.reason). The
    classifier duck-types on .status, so it need not be the real class."""
    def __init__(self, status, reason=""):
        super().__init__(f"({status})\nReason: {reason}")
        self.status = status
        self.reason = reason


def _raise(exc):
    def _stub(_path):
        raise exc
    return _stub


def _collector():
    """A LiveEvidenceCollector with no kube config and no preflight — built via __new__
    so we can unit-test _fetch/collect against a stubbed API with no real cluster."""
    coll = LiveEvidenceCollector.__new__(LiveEvidenceCollector)
    EvidenceCollector.__init__(coll)
    coll._context = "unit-test"
    return coll


# --------------------------------------------------------------------------- #
# classifier
# --------------------------------------------------------------------------- #
def test_connection_error_classifier_true_for_transport_failures():
    assert _is_connection_error(ConnectionRefusedError("refused"))
    assert _is_connection_error(TimeoutError("timed out"))
    assert _is_connection_error(OSError("no route to host"))


def test_connection_error_classifier_false_for_http_responses():
    # A 403/404 IS an HTTP response — the cluster is reachable, just guarded/missing.
    assert not _is_connection_error(_FakeApiException(403, "Forbidden"))
    assert not _is_connection_error(_FakeApiException(404, "Not Found"))


def test_short_api_error_is_human_readable():
    assert "403" in _short_api_error(_FakeApiException(403, "Forbidden"))
    assert "404" in _short_api_error(_FakeApiException(404, "Not Found"))


# --------------------------------------------------------------------------- #
# per-resource fault tolerance
# --------------------------------------------------------------------------- #
def test_forbidden_resource_is_skipped_not_fatal():
    coll = _collector()
    coll._get_json = _raise(_FakeApiException(403, "Forbidden"))
    out = coll._fetch("Secret", "secrets")
    assert out == []                      # skipped, not raised
    assert coll.warnings                  # and recorded
    assert "Secret" in coll.warnings[0]


def test_missing_api_group_is_skipped():
    coll = _collector()
    coll._get_json = _raise(_FakeApiException(404, "NotFound"))
    assert coll._fetch("Ingress", "ingresses") == []
    assert any("Ingress" in w for w in coll.warnings)


def test_partial_scan_collects_what_it_can():
    """One resource type forbidden, another readable → scan proceeds with the readable
    one and warns about the other (never aborts)."""
    coll = _collector()

    def selective(path):
        if "secrets" in path:
            raise _FakeApiException(403, "Forbidden")
        return [{"metadata": {"name": "p1"}}]

    coll._get_json = selective
    ev = coll.collect({"Pod", "Secret"}, Scope(ScopeLevel.CLUSTER))
    assert len(ev.get("Pod", all_scopes=True)) == 1     # readable type came through
    assert ev.get("Secret", all_scopes=True) == []      # forbidden type empty
    assert any("Secret" in w for w in coll.warnings)


# --------------------------------------------------------------------------- #
# connection failure -> one clean, actionable error
# --------------------------------------------------------------------------- #
def test_connection_failure_midscan_raises_clean_runtimeerror():
    coll = _collector()
    coll._get_json = _raise(ConnectionRefusedError("refused"))
    with pytest.raises(RuntimeError):
        coll._fetch("Pod", "pods")


def test_unreachable_message_is_actionable():
    coll = _collector()
    err = coll._unreachable(ConnectionRefusedError("Max retries exceeded"))
    msg = str(err)
    assert "Cannot reach the Kubernetes API server" in msg
    assert "cluster-info" in msg          # tells the user how to verify
    assert "--mock" in msg                # and the fallback
