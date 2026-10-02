"""Attack-path chaining: turn a flat threat list into multi-step attack paths.

Every other open tool emits a flat, per-component list. ThreatForge chains
threats along the *real* data-flow graph into plausible multi-step paths - e.g.
"spoof the public auth -> reach the app over an unauthenticated hop -> read PII
from the unencrypted data store" - and maps each step to a MITRE ATT&CK
technique. This is the reasoning a senior reviewer does by hand.

Grounding discipline (so we don't emit implausible paths):

* A path only follows edges that exist in the recovered DFD.
* It must start at an **entry** (a public external entity or an internet-facing
  process) and end at a **high-value target** (a sensitive data store, or an
  element in the DATA/TRUSTED zone).
* Every step on the path must carry at least one real threat from the register -
  an attacker needs a foothold at each hop. Paths with ungrounded hops are
  discarded, not invented.
* Each path gets a confidence (the product of its steps' threat confidences) and
  is flagged ``needs_review`` when that drops below a threshold. Paths are ranked
  by total severity, de-duplicated, and capped - an attack graph full of
  implausible paths loses trust faster than no graph at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..model.schema import ElementType, SystemModel, TrustZone
from ..reason.threat import Threat


@dataclass
class AttackStep:
    component: str
    component_id: str
    threat_id: str
    stride: str
    title: str
    risk: int
    attack_technique: str
    tactic: str


@dataclass
class AttackPath:
    id: str
    entry: str
    target: str
    steps: list[AttackStep] = field(default_factory=list)
    total_risk: int = 0
    confidence: float = 1.0
    needs_review: bool = False

    def tactic_chain(self) -> list[str]:
        return [s.tactic for s in self.steps if s.tactic]

    def narrative(self) -> str:
        return " -> ".join(f"{s.component} [{s.stride}]" for s in self.steps)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "entry": self.entry, "target": self.target,
            "total_risk": self.total_risk, "confidence": round(self.confidence, 2),
            "needs_review": self.needs_review, "narrative": self.narrative(),
            "tactics": self.tactic_chain(),
            "steps": [vars(s) for s in self.steps],
        }


class AttackGraphBuilder:
    def __init__(self, attack_map: dict, max_depth: int = 6, max_paths: int = 12,
                 confidence_floor: float = 0.4):
        self.attack_map = attack_map
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.confidence_floor = confidence_floor

    def _tactic_rank(self, tactic: str) -> int:
        order = self.attack_map.get("tactic_order", [])
        return order.index(tactic) if tactic in order else len(order)

    def _attack_for(self, t: Threat) -> tuple[str, str]:
        by_pattern = self.attack_map.get("by_pattern", {})
        by_stride = self.attack_map.get("by_stride", {})
        m = by_pattern.get(t.source_pattern) or by_stride.get(t.stride)
        if not m:
            return "", ""
        return f"{m['technique']} {m['technique_name']}", m["tactic"]

    def build(self, model: SystemModel, threats: list[Threat]) -> list[AttackPath]:
        # Index threats by element; keep the highest-risk threat per element as
        # the representative step, but remember all for tactic selection.
        by_elem: dict[str, list[Threat]] = {}
        for t in threats:
            by_elem.setdefault(t.component_id, []).append(t)
        for v in by_elem.values():
            v.sort(key=lambda t: -t.risk)

        adj: dict[str, list[str]] = {}
        for fl in model.flows:
            adj.setdefault(fl.source, []).append(fl.dest)

        entries = [
            e for e in model.elements
            if (e.type == ElementType.EXTERNAL_ENTITY and e.zone == TrustZone.PUBLIC)
            or (e.type == ElementType.PROCESS and e.attributes.get("internet_facing"))
        ]

        def is_target(eid: str) -> bool:
            el = model.element(eid)
            if not el:
                return False
            if el.type == ElementType.DATA_STORE and (
                el.attributes.get("handles_sensitive") or el.attributes.get("handles_pii")
            ):
                return True
            return el.zone in (TrustZone.DATA, TrustZone.TRUSTED)

        raw_paths: list[list[str]] = []

        def dfs(node: str, path: list[str], seen: set[str]):
            if len(path) > self.max_depth:
                return
            if len(path) >= 2 and is_target(node):
                raw_paths.append(list(path))
                # keep exploring for deeper targets too, but cap total work
            for nxt in adj.get(node, []):
                if nxt in seen:
                    continue
                dfs(nxt, path + [nxt], seen | {nxt})

        for e in entries:
            dfs(e.id, [e.id], {e.id})

        paths: list[AttackPath] = []
        seen_narratives: set[str] = set()
        counter = 1
        for nodes in raw_paths:
            steps: list[AttackStep] = []
            conf = 1.0
            ok = True
            for eid in nodes:
                reps = by_elem.get(eid)
                if not reps:
                    ok = False  # ungrounded hop -> discard the path
                    break
                t = reps[0]
                tech, tactic = self._attack_for(t)
                steps.append(AttackStep(
                    component=t.component, component_id=eid, threat_id=t.id,
                    stride=t.stride, title=t.title, risk=t.risk,
                    attack_technique=tech, tactic=tactic,
                ))
                conf *= max(0.1, t.confidence)
            if not ok or len(steps) < 2:
                continue
            narrative = " -> ".join(s.component_id for s in steps)
            if narrative in seen_narratives:
                continue
            seen_narratives.add(narrative)
            path = AttackPath(
                id=f"AP-{counter:03d}",
                entry=steps[0].component,
                target=steps[-1].component,
                steps=steps,
                total_risk=sum(s.risk for s in steps),
                confidence=round(conf, 2),
                needs_review=conf < self.confidence_floor,
            )
            paths.append(path)
            counter += 1

        paths.sort(key=lambda p: (-p.total_risk, -p.confidence))
        return paths[: self.max_paths]
