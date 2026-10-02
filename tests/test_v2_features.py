"""Tests for v2 differentiators: attack paths, ATT&CK, verification, LINDDUN,
IaC, confidence/review flags, compliance crosswalk."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.analyze_iac.iac_analyzer import analyze_kubernetes, analyze_terraform
from src.model.schema import ElementType, TrustZone
from src.pipeline import build_attack_paths, run_pipeline
from src.verify.generate import generate_pytest, generate_sigma

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "py_webapp")
DIAGRAM = os.path.join(os.path.dirname(__file__), "..", "samples", "diagrams", "py_webapp.mmd")


def _run(privacy=False):
    return run_pipeline("Sample Web App", repo_path=SAMPLE, diagram_path=DIAGRAM,
                        backend_config={"backend": "stub"}, privacy=privacy)


def test_attack_paths_are_grounded_and_ordered():
    model, threats = _run()
    paths = build_attack_paths(model, threats)
    assert paths, "expected at least one attack path"
    # Ranked by total risk descending.
    risks = [p.total_risk for p in paths]
    assert risks == sorted(risks, reverse=True)
    for p in paths:
        assert len(p.steps) >= 2
        # Every step must map to a threat that exists in the register (grounding).
        ids = {t.id for t in threats}
        assert all(s.threat_id in ids for s in p.steps)
        # Steps carry ATT&CK techniques/tactics.
        assert all(s.tactic for s in p.steps)


def test_attack_technique_and_compliance_attached():
    _, threats = _run()
    assert any(t.attack_technique for t in threats)
    assert any(t.compliance for t in threats)
    # Compliance refs look like FRAMEWORK:control.
    for t in threats:
        for ref in t.compliance:
            assert ":" in ref and ref.split(":")[0] in ("SOC2", "ISO27001", "PCIDSS")


def test_confidence_and_needs_review_flags():
    _, threats = _run()
    for t in threats:
        assert 0.0 <= t.confidence <= 1.0
    # High-risk threats must be flagged for review.
    assert all(t.needs_review for t in threats if t.risk_level in ("High", "Critical"))
    # Low-confidence patterns exist and are flagged.
    low = [t for t in threats if t.confidence < 0.7]
    assert low and all(t.needs_review for t in low)


def test_traceability_evidence_present():
    _, threats = _run()
    # At least one threat should trace to a file:line in the sample app.
    assert any(".py:" in t.evidence for t in threats)


def test_privacy_linddun_sweep():
    _, threats = _run(privacy=True)
    priv = [t for t in threats if t.framework == "LINDDUN"]
    assert priv, "expected LINDDUN privacy threats"
    assert all(t.stride in {"L", "I", "NR", "DT", "DD", "U", "NC"} for t in priv)


def test_verification_outputs():
    _, threats = _run()
    code = generate_pytest(threats)
    import ast
    ast.parse(code)  # generated pytest must be valid Python
    assert "pytest.mark.skip" in code  # stubs start skipped (honesty)
    rules = generate_sigma(threats)
    assert rules and all("detection" in r and "logsource" in r for r in rules)


def test_terraform_analyzer_flags_public_resources():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "main.tf"), "w") as fh:
            fh.write('resource "aws_s3_bucket" "b" { acl = "public-read" }\n'
                     'resource "aws_db_instance" "db" { publicly_accessible = true }\n')
        model = analyze_terraform(d, name="tf")
        stores = model.elements_of(ElementType.DATA_STORE)
        assert stores
        # A public bucket should land in the PUBLIC zone (exposed).
        assert any(e.zone == TrustZone.PUBLIC for e in stores)


def test_kubernetes_analyzer_detects_loadbalancer():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "svc.yaml"), "w") as fh:
            fh.write("apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n"
                     "spec:\n  type: LoadBalancer\n")
        model = analyze_kubernetes(d, name="k8s")
        procs = model.elements_of(ElementType.PROCESS)
        assert any(e.attributes.get("internet_facing") for e in procs)
