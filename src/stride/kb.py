"""Loader and evaluator for the STRIDE knowledge base.

The KB (``stride_kb.yaml``) encodes two things: which STRIDE categories apply to
which DFD element type, and a set of reusable *threat patterns* whose ``when``
conditions are matched against the extracted system model. This module loads the
KB and evaluates those conditions, producing the grounded candidate space that
the reasoner draws from. Keeping condition evaluation here (deterministic, data
driven) is what constrains the LLM to relevant, model-supported threats.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import yaml

from ..model.schema import DataFlow, Element, ElementType, SystemModel, TrustZone

_KB_PATH = os.path.join(os.path.dirname(__file__), "stride_kb.yaml")

# Tokens we treat as "sensitive" when they appear in flow data or store contents.
SENSITIVE_TOKENS = {
    "credentials", "password", "passwords", "secret", "secrets", "token",
    "tokens", "session", "pii", "ssn", "card", "payment", "financial",
    "personal", "email", "api_key", "apikey", "health", "private",
}


@dataclass
class ThreatPattern:
    id: str
    category: str
    applies_to: str
    title: str
    rationale: str
    when: list[str]
    controls: list[str]
    cwe: str
    base_likelihood: int
    base_impact: int
    mitigation: str


class StrideKB:
    def __init__(self, data: dict[str, Any]):
        self.categories: dict[str, str] = data["categories"]
        self.applicability: dict[str, list[str]] = data["applicability"]
        self.patterns: list[ThreatPattern] = [
            ThreatPattern(**p) for p in data["patterns"]
        ]

    @classmethod
    def load(cls, path: str | None = None) -> "StrideKB":
        with open(path or _KB_PATH, "r", encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh))

    def category_name(self, code: str) -> str:
        return self.categories.get(code, code)

    def applicable_categories(self, element_type: ElementType) -> list[str]:
        return self.applicability.get(element_type.value, [])

    # -- condition evaluation ------------------------------------------------
    def _sensitive_data(self, tokens: list[str]) -> bool:
        return any(_norm_token(t) in SENSITIVE_TOKENS for t in tokens)

    def _eval_condition(
        self, cond: str, model: SystemModel, el: Element, fl: DataFlow | None
    ) -> bool:
        cond = cond.strip()

        # Flow-topology shorthands.
        if cond == "flow.crosses_boundary":
            if fl is None:
                return False
            s, d = model.element(fl.source), model.element(fl.dest)
            return bool(s and d and s.zone != d.zone)
        if cond == "flow.carries_sensitive":
            return bool(fl and self._sensitive_data(fl.data))
        if cond.startswith("flow.carries:"):
            tok = cond.split(":", 1)[1]
            return bool(fl and _norm_token(tok) in {_norm_token(x) for x in fl.data})

        # Element shorthands.
        if cond == "element.internet_facing":
            return bool(el.attributes.get("internet_facing") or el.zone == TrustZone.PUBLIC)
        if cond == "element.handles_sensitive":
            return bool(
                el.attributes.get("handles_sensitive")
                or el.attributes.get("handles_pii")
                or self._sensitive_data(el.attributes.get("data", []))
            )
        if cond == "element.reaches_trusted":
            return _reaches_zone(model, el, TrustZone.TRUSTED) or _reaches_zone(
                model, el, TrustZone.DATA
            )

        # Generic "<scope>.<attr> is true|false".
        m = cond.split()
        if len(m) == 3 and m[1] == "is" and m[2] in ("true", "false"):
            scope_attr, _, want = m
            want_bool = want == "true"
            return self._get_attr(scope_attr, el, fl) is want_bool

        # Generic "<scope>.<attr> == <value>".
        if "==" in cond:
            lhs, rhs = (x.strip() for x in cond.split("==", 1))
            return str(self._get_attr(lhs, el, fl)) == rhs
        if "!=" in cond:
            lhs, rhs = (x.strip() for x in cond.split("!=", 1))
            return str(self._get_attr(lhs, el, fl)) != rhs

        return False

    def _get_attr(self, scope_attr: str, el: Element, fl: DataFlow | None) -> Any:
        scope, _, attr = scope_attr.partition(".")
        if scope == "element":
            if attr == "zone":
                return el.zone.value
            return el.attributes.get(attr, False)
        if scope == "flow" and fl is not None:
            if attr in ("authenticated", "encrypted", "protocol"):
                return getattr(fl, attr)
            return fl.attributes.get(attr, False)
        return False

    def match(
        self, model: SystemModel, el: Element, fl: DataFlow | None, pattern: ThreatPattern
    ) -> bool:
        """True if every ``when`` condition of the pattern holds for this target."""
        return all(self._eval_condition(c, model, el, fl) for c in pattern.when)


def _norm_token(t: str) -> str:
    return "".join(ch for ch in t.lower() if ch.isalnum())


def _reaches_zone(model: SystemModel, start: Element, zone: TrustZone) -> bool:
    """BFS over flows: can we reach an element in ``zone`` from ``start``?"""
    seen = {start.id}
    frontier = [start.id]
    while frontier:
        nxt = []
        for eid in frontier:
            for fl in model.flows:
                if fl.source == eid and fl.dest not in seen:
                    tgt = model.element(fl.dest)
                    if tgt and tgt.zone == zone:
                        return True
                    seen.add(fl.dest)
                    nxt.append(fl.dest)
        frontier = nxt
    return False
