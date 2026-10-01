"""Threat-model diff and baseline gating.

Two features teams actually adopt:

* **Diff** - compare an old threat model against a new one and report which
  threats were *added*, *removed*, or had their *risk changed*. Answers "what new
  threats did this change introduce?" - the question a reviewer asks on every PR.

* **Baseline** - a `.threatforge.baseline.json` file of accepted threat keys.
  `gate()` fails only on threats **not** in the baseline, exactly like a linter's
  accepted-warnings file. This lets a team adopt ThreatForge in CI without being
  blocked by the backlog of already-known threats - they gate on *new* risk only.

Threat identity for diffing/baselining is the stable key
``(component, stride, source_pattern)`` so wording changes don't create churn.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..reason.threat import Threat


def threat_key(t: Threat) -> str:
    return f"{t.component}::{t.stride}::{t.source_pattern or t.title}"


@dataclass
class DiffResult:
    added: list[Threat] = field(default_factory=list)
    removed: list[dict] = field(default_factory=list)
    risk_changed: list[dict] = field(default_factory=list)
    unchanged: int = 0

    def to_dict(self) -> dict:
        return {
            "added": [t.to_dict() for t in self.added],
            "removed": self.removed,
            "risk_changed": self.risk_changed,
            "unchanged": self.unchanged,
            "summary": {
                "added": len(self.added),
                "removed": len(self.removed),
                "risk_changed": len(self.risk_changed),
                "unchanged": self.unchanged,
            },
        }

    def to_markdown(self) -> str:
        out = ["### ThreatForge diff", ""]
        s = self.to_dict()["summary"]
        out.append(f"- **{s['added']}** new threats, **{s['removed']}** resolved, "
                   f"**{s['risk_changed']}** changed risk, {s['unchanged']} unchanged.")
        out.append("")
        if self.added:
            out.append("**New threats introduced:**")
            out.append("")
            out.append("| Component | STRIDE | Threat | Risk |")
            out.append("| --- | --- | --- | --- |")
            for t in self.added:
                out.append(f"| {t.component} | {t.stride_name} | {t.title} | "
                           f"{t.risk} ({t.risk_level}) |")
            out.append("")
        if self.removed:
            out.append("**Resolved threats:**")
            out.append("")
            for r in self.removed:
                out.append(f"- {r['component']} / {r['stride']} - {r['title']}")
            out.append("")
        if self.risk_changed:
            out.append("**Risk changed:**")
            out.append("")
            for r in self.risk_changed:
                out.append(f"- {r['component']} / {r['stride']}: "
                           f"{r['old_risk']} → {r['new_risk']}")
            out.append("")
        return "\n".join(out)


def diff_threats(old: list[Threat], new: list[Threat]) -> DiffResult:
    old_map = {threat_key(t): t for t in old}
    new_map = {threat_key(t): t for t in new}
    res = DiffResult()
    for k, t in new_map.items():
        if k not in old_map:
            res.added.append(t)
        else:
            if t.risk != old_map[k].risk:
                res.risk_changed.append({
                    "component": t.component, "stride": t.stride_name,
                    "old_risk": old_map[k].risk, "new_risk": t.risk,
                })
            else:
                res.unchanged += 1
    for k, t in old_map.items():
        if k not in new_map:
            res.removed.append({"component": t.component, "stride": t.stride_name,
                                "title": t.title})
    return res


# -- baseline ---------------------------------------------------------------
def write_baseline(threats: list[Threat], path: str) -> str:
    keys = sorted(threat_key(t) for t in threats)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"_about": "Accepted threats. `threatforge gate` fails only on "
                             "threats NOT listed here. Regenerate with `threatforge "
                             "baseline`.", "accepted": keys}, fh, indent=2)
    return path


def load_baseline(path: str) -> set[str]:
    with open(path, encoding="utf-8") as fh:
        return set(json.load(fh).get("accepted", []))


@dataclass
class GateResult:
    passed: bool
    new_threats: list[Threat]
    fail_level: str

    def to_markdown(self) -> str:
        if self.passed:
            return (f"### ThreatForge gate: PASS\n\nNo new threats at or above "
                    f"`{self.fail_level}` beyond the accepted baseline.")
        out = [f"### ThreatForge gate: FAIL", "",
               f"{len(self.new_threats)} new threat(s) at or above `{self.fail_level}` "
               f"not in the baseline:", "",
               "| Component | STRIDE | Threat | Risk |", "| --- | --- | --- | --- |"]
        for t in self.new_threats:
            out.append(f"| {t.component} | {t.stride_name} | {t.title} | "
                       f"{t.risk} ({t.risk_level}) |")
        out.append("")
        out.append("_Accept these (if intended) with `make baseline`, or mitigate them._")
        return "\n".join(out)


_LEVEL_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def gate(threats: list[Threat], baseline: set[str], fail_level: str = "High") -> GateResult:
    """Fail on threats not in the baseline whose risk level >= fail_level."""
    threshold = _LEVEL_RANK.get(fail_level, 3)
    offenders = [
        t for t in threats
        if threat_key(t) not in baseline
        and _LEVEL_RANK.get(t.risk_level, 0) >= threshold
    ]
    return GateResult(passed=not offenders, new_threats=offenders, fail_level=fail_level)
