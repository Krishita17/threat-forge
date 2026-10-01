"""Export-schema validity tests (native JSON, pytm, Threat Dragon)."""

import ast
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.model.schema import SystemModel
from src.pipeline import run_pipeline
from src.report import exports
from src.mitigate.mapper import MitigationMapper, load_controls


def _sample():
    sample = os.path.join(os.path.dirname(__file__), "..", "samples", "py_webapp")
    diagram = os.path.join(os.path.dirname(__file__), "..", "samples", "diagrams", "py_webapp.mmd")
    return run_pipeline("Sample Web App", repo_path=sample, diagram_path=diagram,
                        backend_config={"backend": "stub"})


def test_native_json_roundtrips():
    model, threats = _sample()
    text = exports.to_native_json(model, threats)
    data = json.loads(text)
    assert data["tool"] == "ThreatForge"
    restored = SystemModel.from_dict(data["model"])
    assert len(restored.elements) == len(model.elements)
    assert len(restored.boundaries) == len(model.boundaries)


def test_pytm_export_is_valid_python():
    model, threats = _sample()
    code = exports.to_pytm(model, threats)
    ast.parse(code)  # must be syntactically valid
    assert "from pytm import" in code
    assert "tm.process()" in code


def test_threat_dragon_export_schema():
    model, threats = _sample()
    doc = json.loads(exports.to_threat_dragon(model, threats))
    assert "summary" in doc and "detail" in doc
    diagrams = doc["detail"]["diagrams"]
    assert diagrams and diagrams[0]["diagramType"] == "STRIDE"
    assert any(c["type"].startswith("tm.") for c in diagrams[0]["cells"])


def test_all_controls_referenced_by_kb_exist():
    """Every control id used by a KB pattern must resolve in frameworks/."""
    from src.stride.kb import StrideKB

    controls = load_controls()
    kb = StrideKB.load()
    for p in kb.patterns:
        for cid in p.controls:
            assert cid in controls, f"{p.id} references unknown control {cid}"


def test_risk_scoring_bands():
    mapper = MitigationMapper()
    model, threats = _sample()
    enriched = mapper.enrich(threats)
    for t in enriched:
        assert 1 <= t.risk <= 25
        assert t.risk_level in ("Low", "Medium", "High", "Critical")
    # Register is sorted highest-risk first.
    risks = [t.risk for t in enriched]
    assert risks == sorted(risks, reverse=True)
