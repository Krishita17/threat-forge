"""Evaluation harness: coverage, precision, structure recovery, and ablation.

All metrics are computed against ground truth that is *independent* of the KB
evaluator (synthetic systems carry an injected-weakness oracle; real systems
carry hand-authored reference models), so the numbers are meaningful rather than
self-confirming. We report the honest false-positive/noise rate alongside
coverage, because a threat-model drafter that floods reviewers with spurious
threats gets abandoned.

Matching is by ``(component, stride_code)`` key, which does not depend on the
exact wording of either the proposed threat or the reference.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..model.schema import ElementType, SystemModel
from ..reason.threat import Threat
from .synthetic import SyntheticSystem


@dataclass
class CoverageResult:
    expected: int
    found: int           # expected threats that were surfaced (true positives)
    missed: int          # expected threats not surfaced (false negatives)
    extra: int           # surfaced threats not in ground truth (false positives)
    proposed: int        # total proposed

    @property
    def coverage(self) -> float:
        return self.found / self.expected if self.expected else 1.0

    @property
    def precision(self) -> float:
        return self.found / self.proposed if self.proposed else 0.0

    @property
    def noise_rate(self) -> float:
        return self.extra / self.proposed if self.proposed else 0.0

    def to_dict(self) -> dict:
        return {
            "expected": self.expected,
            "proposed": self.proposed,
            "true_positives": self.found,
            "false_negatives": self.missed,
            "false_positives": self.extra,
            "coverage": round(self.coverage, 3),
            "precision": round(self.precision, 3),
            "noise_rate": round(self.noise_rate, 3),
        }


def score_threats(expected_keys: set[tuple[str, str]], threats: list[Threat]) -> CoverageResult:
    proposed_keys = {(t.component, t.stride) for t in threats}
    found = expected_keys & proposed_keys
    missed = expected_keys - proposed_keys
    extra = proposed_keys - expected_keys
    return CoverageResult(
        expected=len(expected_keys),
        found=len(found),
        missed=len(missed),
        extra=len(extra),
        proposed=len(proposed_keys),
    )


# -- structure recovery -------------------------------------------------------
@dataclass
class StructureResult:
    element_type: str
    expected: int
    recovered: int
    correct: int

    @property
    def precision(self) -> float:
        return self.correct / self.recovered if self.recovered else 0.0

    @property
    def recall(self) -> float:
        return self.correct / self.expected if self.expected else 1.0


def _norm(s: str) -> str:
    return "".join(ch for ch in s.lower() if ch.isalnum())


def score_structure(reference: SystemModel, recovered: SystemModel) -> dict[str, StructureResult]:
    """Per-element-type precision/recall of recovered structure vs a reference."""
    out: dict[str, StructureResult] = {}
    for et in (ElementType.PROCESS, ElementType.DATA_STORE, ElementType.EXTERNAL_ENTITY):
        ref_names = {_norm(e.name) for e in reference.elements_of(et)}
        rec_names = {_norm(e.name) for e in recovered.elements_of(et)}
        correct = len(ref_names & rec_names)
        out[et.value] = StructureResult(
            element_type=et.value,
            expected=len(ref_names),
            recovered=len(rec_names),
            correct=correct,
        )
    # Trust boundaries as their own "type".
    ref_b = {frozenset({b.zone_a, b.zone_b}) for b in reference.boundaries}
    rec_b = {frozenset({b.zone_a, b.zone_b}) for b in recovered.boundaries}
    out["trust_boundary"] = StructureResult(
        element_type="trust_boundary",
        expected=len(ref_b),
        recovered=len(rec_b),
        correct=len(ref_b & rec_b),
    )
    return out
