"""The grounded STRIDE threat reasoner - the heart of ThreatForge.

Given the extracted :class:`SystemModel` and the :class:`StrideKB`, the reasoner
performs a *per-component STRIDE sweep*:

1. For each element, take the STRIDE categories that apply to its type.
2. For each applicable category, find KB threat patterns whose ``when``
   conditions match the extracted model (this is the grounding step - only
   model-supported candidates survive).
3. Hand each surviving candidate to the pluggable backend to confirm relevance
   and phrase the rationale.
4. Emit a :class:`Threat` per accepted candidate, tagged with the boundary it
   crosses and the KB pattern that produced it (for auditability).

Flows are swept too: a data-flow threat is attributed to the flow but reported
against the destination process/store it feeds, which is how a reviewer expects
to read it.

The *ungrounded* mode (used only by the ablation experiment) bypasses step 2 and
emits the textbook STRIDE threats for each element type regardless of model
support - letting us measure how much grounding cuts irrelevant threats.
"""

from __future__ import annotations

from ..model.schema import DataFlow, Element, ElementType, SystemModel
from ..stride.kb import StrideKB
from .backends import Candidate, ReasonerBackend, StubBackend, UngroundedStubBackend
from .threat import Threat


class GroundedReasoner:
    def __init__(self, kb: StrideKB, backend: ReasonerBackend | None = None):
        self.kb = kb
        self.backend = backend or StubBackend()

    # -- helpers -------------------------------------------------------------
    def _boundary_for_flow(self, model: SystemModel, fl: DataFlow) -> str:
        s, d = model.element(fl.source), model.element(fl.dest)
        if not s or not d or s.zone == d.zone:
            return ""
        for b in model.boundaries:
            if {b.zone_a, b.zone_b} == {s.zone, d.zone}:
                return b.name
        return ""

    def _render(self, text: str, el: Element, fl: DataFlow | None) -> str:
        data = ", ".join((fl.data if fl else el.attributes.get("data", [])) or []) or "data"
        return text.replace("{name}", el.name).replace("{data}", data)

    def _candidate(
        self, model: SystemModel, el: Element, fl: DataFlow | None, pattern
    ) -> Candidate:
        evidence = {
            "zone": el.zone.value,
            "attributes": {k: el.attributes.get(k) for k in el.attributes},
        }
        if fl is not None:
            evidence["flow"] = {
                "encrypted": fl.encrypted,
                "authenticated": fl.authenticated,
                "data": fl.data,
                "crosses_boundary": self._boundary_for_flow(model, fl) != "",
            }
        return Candidate(
            component=el.name,
            component_type=el.type.value,
            stride_code=pattern.category,
            stride_name=self.kb.category_name(pattern.category),
            pattern_id=pattern.id,
            title=pattern.title,
            rationale=self._render(pattern.rationale, el, fl),
            evidence=evidence,
        )

    # -- main sweep ----------------------------------------------------------
    def analyze(self, model: SystemModel) -> list[Threat]:
        threats: list[Threat] = []
        counter = 1

        # Element-targeted patterns (process, data_store, external_entity).
        for el in model.elements:
            if el.type == ElementType.DATA_FLOW:
                continue
            applicable = set(self.kb.applicable_categories(el.type))
            for pattern in self.kb.patterns:
                if pattern.applies_to != el.type.value:
                    continue
                if pattern.category not in applicable:
                    continue
                if not self.kb.match(model, el, None, pattern):
                    continue
                cand = self._candidate(model, el, None, pattern)
                judgment = self.backend.judge(cand)
                if not judgment.accept:
                    continue
                threats.append(
                    self._make_threat(counter, el, None, pattern, judgment, model)
                )
                counter += 1

        # Flow-targeted patterns (data_flow): report against the destination.
        flow_applicable = set(self.kb.applicable_categories(ElementType.DATA_FLOW))
        for fl in model.flows:
            dst = model.element(fl.dest)
            if dst is None:
                continue
            for pattern in self.kb.patterns:
                if pattern.applies_to != ElementType.DATA_FLOW.value:
                    continue
                if pattern.category not in flow_applicable:
                    continue
                if not self.kb.match(model, dst, fl, pattern):
                    continue
                cand = self._candidate(model, dst, fl, pattern)
                judgment = self.backend.judge(cand)
                if not judgment.accept:
                    continue
                threats.append(
                    self._make_threat(counter, dst, fl, pattern, judgment, model)
                )
                counter += 1

        return threats

    def _make_threat(
        self, n: int, el: Element, fl: DataFlow | None, pattern, judgment, model
    ) -> Threat:
        boundary = self._boundary_for_flow(model, fl) if fl is not None else ""
        if not boundary and el.attributes.get("internet_facing"):
            boundary = "Internet -> Application"
        return Threat(
            id=f"TF-{n:03d}",
            component=el.name,
            component_id=el.id,
            stride=pattern.category,
            stride_name=self.kb.category_name(pattern.category),
            title=pattern.title,
            rationale=judgment.rationale,
            mitigation=pattern.mitigation,
            controls=list(pattern.controls),
            cwe=pattern.cwe,
            likelihood=pattern.base_likelihood,
            impact=pattern.base_impact,
            boundary=boundary,
            source_pattern=pattern.id,
        )


class UngroundedReasoner:
    """Ablation baseline: emit textbook STRIDE threats per element *type*.

    Ignores the extracted model's attributes and topology entirely. For every
    element it proposes the canonical threats for the element's type, using
    generic rationale. This mimics prompting an LLM for a STRIDE model without
    grounding it in recovered structure; many of these threats will be
    irrelevant to the actual system, which is exactly what the ablation measures.
    """

    def __init__(self, kb: StrideKB):
        self.kb = kb
        self.backend = UngroundedStubBackend()

    def analyze(self, model: SystemModel) -> list[Threat]:
        threats: list[Threat] = []
        counter = 1
        for el in model.elements:
            if el.type == ElementType.DATA_FLOW:
                continue
            for code in self.kb.applicable_categories(el.type):
                # Emit one generic threat per applicable category, model-blind.
                pattern = _first_pattern_for(self.kb, el.type.value, code)
                cand = Candidate(
                    component=el.name,
                    component_type=el.type.value,
                    stride_code=code,
                    stride_name=self.kb.category_name(code),
                    pattern_id="ungrounded",
                    title=pattern.title if pattern else f"{self.kb.category_name(code)} of {el.name}",
                    rationale="",
                    evidence={},
                )
                judgment = self.backend.judge(cand)
                threats.append(
                    Threat(
                        id=f"UG-{counter:03d}",
                        component=el.name,
                        component_id=el.id,
                        stride=code,
                        stride_name=self.kb.category_name(code),
                        title=cand.title,
                        rationale=judgment.rationale,
                        likelihood=pattern.base_likelihood if pattern else 3,
                        impact=pattern.base_impact if pattern else 3,
                        source_pattern="llm",
                    )
                )
                counter += 1
        return threats


def _first_pattern_for(kb: StrideKB, element_type: str, code: str):
    for p in kb.patterns:
        if p.applies_to == element_type and p.category == code:
            return p
    return None
