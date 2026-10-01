"""Structure-recovery tests against synthetic ground truth."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.analyze_code.python_analyzer import analyze_python_repo
from src.analyze_diagram.mermaid import parse_mermaid
from src.data.diagram_gen import to_mermaid
from src.data.evaluation import score_structure
from src.data.synthetic import generate_catalog, generate_system, PRESETS
from src.model.builder import build_system_model, infer_trust_boundaries
from src.model.schema import ElementType, TrustZone


def test_diagram_roundtrip_recovers_structure():
    """A generated diagram should parse back to the same elements + boundaries."""
    for name, sysm in generate_catalog().items():
        mermaid = to_mermaid(sysm.model)
        recovered = parse_mermaid(mermaid, name=name)
        recovered = infer_trust_boundaries(recovered)
        scores = score_structure(sysm.model, recovered)
        for et in ("process", "data_store", "external_entity"):
            assert scores[et].recall == 1.0, (name, et, scores[et])
        # Trust boundaries recovered exactly from the round-tripped diagram.
        assert scores["trust_boundary"].recall == 1.0, (name, scores["trust_boundary"])


def test_trust_boundary_inference_counts():
    """The secure baseline has the expected set of trust boundaries."""
    sysm = generate_system("t", PRESETS["secure_baseline"], seed=1)
    model = infer_trust_boundaries(sysm.model)
    pairs = {frozenset({b.zone_a, b.zone_b}) for b in model.boundaries}
    assert frozenset({TrustZone.PUBLIC, TrustZone.DMZ}) in pairs
    assert frozenset({TrustZone.APPLICATION, TrustZone.DATA}) in pairs
    assert frozenset({TrustZone.APPLICATION, TrustZone.THIRD_PARTY}) in pairs


def test_code_analyzer_recovers_sample_structure():
    """The code analyzer should find the app, a data store and a third party."""
    sample = os.path.join(os.path.dirname(__file__), "..", "samples", "py_webapp")
    model = analyze_python_repo(sample, name="Sample Web App")
    types = {e.type for e in model.elements}
    assert ElementType.PROCESS in types
    assert ElementType.DATA_STORE in types       # sqlite3 import
    assert ElementType.EXTERNAL_ENTITY in types  # requests import / end user
    # The app process should be internet-facing (flask + routes).
    app = next(e for e in model.elements if e.type == ElementType.PROCESS)
    assert app.attributes.get("internet_facing") is True


def test_code_and_diagram_corroborate():
    """Fusing code + diagram yields one model with trust boundaries."""
    sample = os.path.join(os.path.dirname(__file__), "..", "samples", "py_webapp")
    diagram = os.path.join(os.path.dirname(__file__), "..", "samples", "diagrams", "py_webapp.mmd")
    code_frag = analyze_python_repo(sample, name="Sample Web App")
    with open(diagram, encoding="utf-8") as fh:
        diag_frag = parse_mermaid(fh.read(), name="Sample Web App")
    fused = build_system_model("Sample Web App", code_frag, diag_frag)
    assert len(fused.boundaries) >= 2
    assert fused.metadata.get("sources")
