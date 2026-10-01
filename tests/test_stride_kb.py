"""STRIDE applicability + grounded-reasoning tests."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.data.evaluation import score_threats
from src.data.synthetic import PRESETS, generate_system
from src.model.schema import (
    DataFlow,
    Element,
    ElementType,
    SystemModel,
    TrustZone,
)
from src.model.builder import infer_trust_boundaries
from src.reason.reasoner import GroundedReasoner, UngroundedReasoner
from src.stride.kb import StrideKB


def test_applicability_matches_methodology():
    kb = StrideKB.load()
    assert set(kb.applicable_categories(ElementType.EXTERNAL_ENTITY)) == {"S", "R"}
    assert set(kb.applicable_categories(ElementType.DATA_FLOW)) == {"T", "I", "D"}
    assert set(kb.applicable_categories(ElementType.DATA_STORE)) == {"T", "R", "I", "D"}
    assert set(kb.applicable_categories(ElementType.PROCESS)) == {"S", "T", "R", "I", "D", "E"}


def test_every_pattern_category_is_applicable_to_its_target():
    """No pattern may fire a STRIDE category that is not valid for its element type."""
    kb = StrideKB.load()
    for p in kb.patterns:
        et = ElementType(p.applies_to)
        assert p.category in kb.applicable_categories(et), p.id


def test_grounded_reasoner_covers_injected_weaknesses():
    """Grounded reasoner should surface all injected ground-truth threats."""
    kb = StrideKB.load()
    reasoner = GroundedReasoner(kb)
    for name, knobs in PRESETS.items():
        sysm = generate_system(name, knobs, seed=3)
        threats = reasoner.analyze(sysm.model)
        res = score_threats(sysm.expected_keys(), threats)
        assert res.coverage == 1.0, (name, res.to_dict())


def test_grounding_beats_ungrounded_on_precision():
    """The whole point: grounding should be more precise than the baseline."""
    kb = StrideKB.load()
    grounded = GroundedReasoner(kb)
    ungrounded = UngroundedReasoner(kb)
    g_tp = g_prop = u_tp = u_prop = 0
    for name, knobs in PRESETS.items():
        sysm = generate_system(name, knobs, seed=5)
        gt = sysm.expected_keys()
        g = score_threats(gt, grounded.analyze(sysm.model))
        u = score_threats(gt, ungrounded.analyze(sysm.model))
        g_tp += g.found; g_prop += g.proposed
        u_tp += u.found; u_prop += u.proposed
    g_prec = g_tp / g_prop
    u_prec = u_tp / u_prop
    assert g_prec > u_prec


def test_secure_system_yields_fewer_threats_than_insecure():
    kb = StrideKB.load()
    reasoner = GroundedReasoner(kb)
    secure = generate_system("s", PRESETS["secure_baseline"], seed=1)
    insecure = generate_system("i", PRESETS["insecure_startup"], seed=1)
    assert len(reasoner.analyze(secure.model)) < len(reasoner.analyze(insecure.model))


def test_no_tls_flow_triggers_tampering_and_disclosure():
    """A sensitive, boundary-crossing, unencrypted flow -> T + I on destination."""
    m = SystemModel(name="t")
    user = Element("u", "User", ElementType.EXTERNAL_ENTITY, TrustZone.PUBLIC,
                   {"authenticated": True})
    proc = Element("p", "App", ElementType.PROCESS, TrustZone.APPLICATION,
                   {"internet_facing": True, "authenticated": True, "authorization": True,
                    "validates_input": True, "rate_limited": True, "audit_logging": True})
    m.add_element(user)
    m.add_element(proc)
    m.add_flow(DataFlow("f", "u", "p", data=["credentials"], protocol="http",
                        encrypted=False, authenticated=True))
    infer_trust_boundaries(m)
    threats = GroundedReasoner(StrideKB.load()).analyze(m)
    codes = {(t.component, t.stride) for t in threats}
    assert ("App", "T") in codes
    assert ("App", "I") in codes
