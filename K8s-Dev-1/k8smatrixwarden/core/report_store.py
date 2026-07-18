"""
Report Store (§16.4) — persists scan results so they can be listed and re-downloaded
later in any format.

A scan result is saved as `<dir>/<scan_id>.json` (its `as_dict()` form). `download` loads a
stored result and re-renders it via the ReportingEngine into whatever format is asked for —
so you scan once and can export markdown / json / html / sarif afterwards, to any filename.

Pure stdlib; the store is just a directory of JSON files (default `./k8smatrixwarden-reports`).
"""
from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass
from typing import Optional

from .results import ScanResult

DEFAULT_DIR = "k8smatrixwarden-reports"

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
        return path

    # -- list ------------------------------------------------------------- #
    def list(self, limit: Optional[int] = None) -> list[StoredReport]:
        out: list[StoredReport] = []
        for p in glob.glob(os.path.join(self.dir, "*.json")):
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
