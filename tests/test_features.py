"""Tests for the community features: SARIF, OWASP map, diff/baseline/gate, JS, HTML."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.analyze_code.js_analyzer import analyze_js_repo
from src.model.schema import ElementType
from src.pipeline import detect_language, run_pipeline
from src.report import exports
from src.report.diff import (
    diff_threats,
    gate,
    load_baseline,
    threat_key,
    write_baseline,
)
from src.report.html_report import render_html


def _sample():
    sample = os.path.join(os.path.dirname(__file__), "..", "samples", "py_webapp")
    diagram = os.path.join(os.path.dirname(__file__), "..", "samples", "diagrams", "py_webapp.mmd")
    return run_pipeline("Sample Web App", repo_path=sample, diagram_path=diagram,
                        backend_config={"backend": "stub"})


def test_owasp_top10_mapping_attached():
    _, threats = _sample()
    mapped = [t for t in threats if t.owasp_top10]
    assert mapped, "expected some threats mapped to an OWASP Top 10 category"
    assert any(t.owasp_top10.startswith("A0") for t in mapped)


def test_sarif_schema():
    model, threats = _sample()
    doc = json.loads(exports.to_sarif(model, threats))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "ThreatForge"
    assert len(run["results"]) == len(threats)
    # Every result references a declared rule and a valid level.
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for r in run["results"]:
        assert r["ruleId"] in rule_ids
        assert r["level"] in ("error", "warning", "note")


def test_shields_badge_shape():
    _, threats = _sample()
    badge = json.loads(exports.to_shields_badge(threats))
    assert badge["schemaVersion"] == 1
    assert badge["label"] == "threats"
    assert badge["color"] in ("red", "orange", "yellow", "brightgreen")


def test_mermaid_dfd_export():
    model, threats = _sample()
    mmd = exports.to_mermaid_dfd(model)
    assert mmd.startswith("flowchart")
    assert "subgraph" in mmd


def test_html_report_is_self_contained():
    model, threats = _sample()
    doc = render_html(model, threats)
    assert "<svg" in doc  # embedded DFD
    assert "localStorage" in doc  # client-side review state
    # No external script/style/link references.
    assert "http://" not in doc.replace("http://www.w3.org/2000/svg", "")
    assert "<script src" not in doc


def test_diff_detects_added_and_removed():
    _, threats = _sample()
    old = threats[2:]          # pretend two threats are new
    new = threats
    result = diff_threats(old, new)
    assert len(result.added) == 2
    assert result.unchanged == len(old)


def test_baseline_gate_roundtrip():
    _, threats = _sample()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "baseline.json")
        write_baseline(threats, path)
        baseline = load_baseline(path)
        # All current threats accepted -> gate passes.
        assert gate(threats, baseline, fail_level="Low").passed
        # Empty baseline -> high-risk threats fail the gate.
        res = gate(threats, set(), fail_level="High")
        assert not res.passed
        assert all(t.risk_level in ("High", "Critical") for t in res.new_threats)


def test_threat_key_is_stable_to_wording():
    _, threats = _sample()
    t = threats[0]
    k1 = threat_key(t)
    t.title = "completely different wording"  # title not part of key when pattern set
    t.rationale = "changed"
    assert threat_key(t) == k1 or t.source_pattern == ""


def test_js_analyzer_recovers_structure():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "package.json"), "w") as fh:
            json.dump({"dependencies": {"express": "^4", "pg": "^8", "axios": "^1"}}, fh)
        with open(os.path.join(d, "server.js"), "w") as fh:
            fh.write('const app=require("express")();\napp.get("/u",(r,s)=>s.send("ok"));\n')
        model = analyze_js_repo(d, name="JS App")
        types = {e.type for e in model.elements}
        assert ElementType.PROCESS in types
        assert ElementType.DATA_STORE in types
        assert ElementType.EXTERNAL_ENTITY in types
        assert detect_language(d) == "javascript"
