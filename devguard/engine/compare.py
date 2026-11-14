"""Scan comparison: new / persistent / resolved, per comparable category only."""

from __future__ import annotations

from typing import Any

from ..models import CATEGORIES


def _reason(run: dict[str, Any] | None, scan_id: int, category: str) -> str:
    if run is None:
        return f"no {category} scanner run recorded in scan #{scan_id}"
    if run["status"] == "skipped":
        return f"{run['scanner']} was skipped in scan #{scan_id} ({run.get('skip_reason') or 'no input'})"
    return f"{run['scanner']} did not complete in scan #{scan_id} ({run['status']})"


def compare_scans(base: dict[str, Any], head: dict[str, Any],
                  base_runs: list[dict[str, Any]], head_runs: list[dict[str, Any]],
                  base_findings: list[dict[str, Any]], head_findings: list[dict[str, Any]]) -> dict[str, Any]:
    """A category is compared only when its scanner run is `success` in BOTH scans.

    Missing data is never treated as "resolved": findings of a non-comparable
    category appear in none of the three lists.
    """
    b_runs = {r["category"]: r for r in base_runs}
    h_runs = {r["category"]: r for r in head_runs}
    lists: dict[str, list[dict[str, Any]]] = {"new": [], "resolved": [], "persistent": []}
    categories = []

    for category in CATEGORIES:
        entry: dict[str, Any] = {"category": category, "comparable": True, "reason": None,
                                 "new": None, "resolved": None, "persistent": None}
        for run, scan in ((b_runs.get(category), base), (h_runs.get(category), head)):
            if run is None or run["status"] != "success":
                entry.update(comparable=False, reason=_reason(run, scan["id"], category))
                break
        if entry["comparable"]:
            b = {f["fingerprint"]: f for f in base_findings if f["category"] == category}
            h = {f["fingerprint"]: f for f in head_findings if f["category"] == category}
            parts = {
                "new": [f for fp, f in h.items() if fp not in b],
                "resolved": [f for fp, f in b.items() if fp not in h],
                "persistent": [f for fp, f in h.items() if fp in b],
            }
            for key, items in parts.items():
                entry[key] = len(items)
                lists[key].extend(items)
        categories.append(entry)

    b_score, h_score = base.get("risk_score"), head.get("risk_score")
    brief = lambda s: {k: s.get(k) for k in ("id", "target_path", "label", "status", "started_at", "risk_score")}
    return {
        "base": brief(base),
        "head": brief(head),
        "targets_differ": base["target_path"] != head["target_path"],
        "fully_comparable": all(c["comparable"] for c in categories),
        "categories": categories,
        "totals": {k: len(v) for k, v in lists.items()},
        "risk": {"base": b_score, "head": h_score,
                 "delta": h_score - b_score if b_score is not None and h_score is not None else None},
        **lists,
    }
