"""Mitigation mapper and risk scorer.

The reasoner attaches a KB mitigation, control ids and base likelihood/impact to
each threat. This stage:

* enriches each control id with its real title + paraphrased requirement text
  from ``frameworks/`` (so the register is actionable and traceable), and
* computes a triaged risk score (likelihood x impact -> 1..25) and a risk level,
  so the register is prioritized rather than a flat list.

Risk scoring is intentionally transparent (a simple product with documented
band thresholds) because a human reviews and may override it.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from ..reason.threat import Threat

_FRAMEWORKS_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "frameworks"
)


@dataclass
class Control:
    id: str
    framework: str
    title: str
    requirement: str


def load_controls(frameworks_dir: str | None = None) -> dict[str, Control]:
    path = os.path.join(frameworks_dir or _FRAMEWORKS_DIR, "controls.json")
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return {
        c["id"]: Control(
            id=c["id"],
            framework=c["framework"],
            title=c["title"],
            requirement=c["requirement"],
        )
        for c in raw["controls"]
    }


def load_owasp_top10(frameworks_dir: str | None = None) -> dict:
    """Load the CWE -> OWASP Top 10:2021 category mapping."""
    path = os.path.join(frameworks_dir or _FRAMEWORKS_DIR, "owasp_top10.json")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def risk_level(score: int) -> str:
    """Band a 1..25 risk score. Documented, overridable thresholds."""
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


class MitigationMapper:
    def __init__(self, controls: dict[str, Control] | None = None,
                 owasp: dict | None = None):
        self.controls = controls if controls is not None else load_controls()
        self.owasp = owasp if owasp is not None else load_owasp_top10()

    def _owasp_for(self, cwe: str) -> str:
        cat = self.owasp.get("cwe_to_category", {}).get(cwe)
        return self.owasp.get("categories", {}).get(cat, "") if cat else ""

    def enrich(self, threats: list[Threat]) -> list[Threat]:
        for t in threats:
            t.risk = max(1, min(25, t.likelihood * t.impact))
            t.risk_level = risk_level(t.risk)
            t.owasp_top10 = self._owasp_for(t.cwe)
            # Normalize/validate control ids against the loaded frameworks.
            valid = [c for c in t.controls if c in self.controls]
            t.controls = valid
        # Highest risk first for a triaged register.
        threats.sort(key=lambda t: (-t.risk, t.component, t.stride))
        return threats

    def control_detail(self, control_id: str) -> Control | None:
        return self.controls.get(control_id)

    def mitigation_table(self, threats: list[Threat]) -> list[dict]:
        """Flattened threat -> control -> fix -> priority rows for reporting."""
        rows = []
        for t in threats:
            control_titles = []
            for cid in t.controls:
                c = self.controls.get(cid)
                control_titles.append(f"{cid} ({c.title})" if c else cid)
            rows.append(
                {
                    "threat_id": t.id,
                    "component": t.component,
                    "stride": t.stride_name,
                    "threat": t.title,
                    "controls": control_titles,
                    "cwe": t.cwe,
                    "mitigation": t.mitigation,
                    "risk": t.risk,
                    "priority": t.risk_level,
                }
            )
        return rows
