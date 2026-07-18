"""
Report Store (§16.4) — persists scan results so they can be listed and re-downloaded
later in any format.

A scan result is saved as `<dir>/<scan_id>.json` (its `as_dict()` form). `download` loads a
stored result and re-renders it via the ReportingEngine into whatever format is asked for —
so you scan once and can export markdown / json / html / sarif afterwards, to any filename.

Pure stdlib; the store is just a directory of JSON files (default `./k8smatrixwarden-reports`).
"""
from __future__ import annotations

import datetime as _dt
import glob
import json
import os
import re
from dataclasses import dataclass
from typing import Optional

from .results import ScanResult

DEFAULT_DIR = "k8smatrixwarden-reports"
#: Timeline index: finding-identity -> first/last seen + resolved. Lets the tool answer
#: "how long has this been open" (MTTD proxy) and "when was it fixed" (MTTR), which a
#: point-in-time scan alone can't. Granularity == scan cadence.
_TIMELINE_FILE = "_timeline.json"

#: A scan id is `scan-YYYYMMDD-xxxx` (or synthetic ids like `coverage`). Anything with a
#: path separator, `..`, or other filesystem-significant character is rejected before it is
#: ever joined into a path — otherwise a caller-supplied id (a web route param, an
#: LLM-provided argument) could traverse out of the store dir and read arbitrary `*.json`.
_SAFE_SCAN_ID = re.compile(r"[A-Za-z0-9._-]+")


@dataclass
class StoredReport:
    scan_id: str
    path: str
    generated_at: str
    rating: str
    risk_score: float
    total: int
    scope: str


class ReportStore:
    def __init__(self, directory: str = DEFAULT_DIR):
        self.dir = directory

    # -- save ------------------------------------------------------------- #
    def save(self, result: ScanResult) -> str:
        os.makedirs(self.dir, exist_ok=True)
        path = os.path.join(self.dir, f"{result.scan_id}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(result.as_dict(), fh, indent=2, default=str)
        self._update_timeline(result)
        return path

    # -- timeline (MTTD/MTTR) --------------------------------------------- #
    # ponytail: diffs each scan against an accumulated index. Meaningful across scans of
    # the SAME scope (e.g. a scheduled cluster-wide scan); mixing scopes/selectors makes
    # findings falsely "resolve" and reappear. Upgrade: key the index per scope if you
    # run mixed scans on one store.
    @staticmethod
    def _fkey(rule_id, kind, name, namespace) -> str:
        return "|".join([rule_id or "", kind or "", name or "", namespace or ""])

    def _timeline_path(self) -> str:
        return os.path.join(self.dir, _TIMELINE_FILE)

    def _load_timeline(self) -> dict:
        try:
            with open(self._timeline_path(), encoding="utf-8") as fh:
                return json.load(fh)
        except (FileNotFoundError, ValueError):
            return {}

    def _update_timeline(self, result: ScanResult) -> None:
        tl = self._load_timeline()
        ts = result.generated_at
        current = {}
        for f in result.findings:
            if f.severity.weight == 0:      # skip INFO/engine-error
                continue
            r = f.resource
            current[self._fkey(f.rule_id, r.kind, r.name, r.namespace)] = f
        for k, f in current.items():
            e = tl.get(k)
            if e is None:
                tl[k] = {"rule_id": f.rule_id, "title": f.title,
                         "severity": f.severity.label, "resource": str(f.resource),
                         "first_seen": ts, "last_seen": ts, "resolved_at": None}
            else:
                e.update(last_seen=ts, resolved_at=None,
                         severity=f.severity.label)   # reappeared / refresh
        for k, e in tl.items():
            if k not in current and not e.get("resolved_at"):
                e["resolved_at"] = ts               # gone this scan == fixed
        with open(self._timeline_path(), "w", encoding="utf-8") as fh:
            json.dump(tl, fh, indent=2)

    def timeline(self) -> dict:
        """Open/resolved finding ages against the latest scan. `age_days` is a
        scan-cadence-granular MTTD proxy; `resolved` with a `resolved_at` gives MTTR."""
        tl = self._load_timeline()
        if not tl:
            return {"open": 0, "resolved": 0, "oldest_open_days": 0,
                    "median_open_days": 0, "oldest_critical": None, "entries": []}
        latest = self.list(limit=1)
        now = latest[0].generated_at if latest else max(e["last_seen"] for e in tl.values())
        open_e, resolved = [], 0
        for e in tl.values():
            if e.get("resolved_at"):
                resolved += 1
                continue
            open_e.append({**e, "age_days": _days_between(e["first_seen"], now)})
        open_e.sort(key=lambda x: x["age_days"], reverse=True)
        ages = [e["age_days"] for e in open_e]
        crit = next((e for e in open_e if e["severity"] == "CRITICAL"), None)
        return {"open": len(open_e), "resolved": resolved,
                "oldest_open_days": max(ages) if ages else 0,
                "median_open_days": _median(ages),
                "oldest_critical": crit, "entries": open_e[:100]}

    # -- list ------------------------------------------------------------- #
    def list(self, limit: Optional[int] = None) -> list[StoredReport]:
        out: list[StoredReport] = []
        for p in glob.glob(os.path.join(self.dir, "*.json")):
            if os.path.basename(p).startswith("_"):
                continue        # internal index (e.g. _timeline.json), not a report
            try:
                with open(p, encoding="utf-8") as fh:
                    d = json.load(fh)
            except Exception:
                continue
            risk = d.get("risk", {}) or {}
            counts = d.get("counts", {}) or {}
            total = sum(v for k, v in counts.items() if k != "INFO")
            out.append(StoredReport(
                scan_id=d.get("scan_id", os.path.basename(p)[:-5]),
                path=p,
                generated_at=d.get("generated_at", ""),
                rating=risk.get("rating", "?"),
                risk_score=risk.get("cluster_risk", 0.0),
                total=total,
                scope=d.get("scope", "")))
        out.sort(key=lambda r: r.generated_at, reverse=True)
        return out[:limit] if limit else out

    # -- load ------------------------------------------------------------- #
    def load(self, scan_id: str) -> ScanResult:
        if not scan_id or not _SAFE_SCAN_ID.fullmatch(scan_id):
            raise FileNotFoundError(f"invalid scan id: {scan_id!r}")
        path = os.path.join(self.dir, f"{scan_id}.json")
        with open(path, encoding="utf-8") as fh:
            return ScanResult.from_dict(json.load(fh))

    def load_latest(self) -> Optional[ScanResult]:
        reports = self.list(limit=1)
        return self.load(reports[0].scan_id) if reports else None

    def resolve(self, scan_id: Optional[str]) -> Optional[ScanResult]:
        """Load an explicit scan id, or the latest if scan_id is None/'latest'."""
        if not scan_id or scan_id == "latest":
            return self.load_latest()
        return self.load(scan_id)


def _parse_ts(s: str) -> Optional[_dt.datetime]:
    try:
        return _dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _days_between(start: str, end: str) -> float:
    a, b = _parse_ts(start), _parse_ts(end)
    if not a or not b:
        return 0.0
    return round((b - a).total_seconds() / 86400, 1)


def _median(xs: list) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else round((s[mid - 1] + s[mid]) / 2, 1)
