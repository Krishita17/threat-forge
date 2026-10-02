"""End-to-end pipeline orchestration.

Wires the stages together: analyze (code and/or diagram) -> build system model ->
ground STRIDE reasoner -> mitigation mapper + risk scorer -> report. Every stage
is individually callable (see the CLI subcommands); this module is the
convenience path used by ``make`` targets and the sample run.
"""

from __future__ import annotations

from typing import Any

import os

from .analyze_code.js_analyzer import analyze_js_repo
from .analyze_code.python_analyzer import analyze_python_repo
from .analyze_diagram.mermaid import parse_mermaid_file
from .analyze_iac.iac_analyzer import analyze_iac
from .mitigate.mapper import MitigationMapper
from .model.builder import build_system_model
from .model.schema import SystemModel
from .reason.backends import get_backend
from .reason.reasoner import GroundedReasoner
from .reason.threat import Threat
from .stride.kb import StrideKB


def detect_language(repo_path: str) -> str:
    """Pick a code analyzer by inspecting the repo (python | javascript)."""
    if os.path.exists(os.path.join(repo_path, "package.json")):
        return "javascript"
    py = js = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {".venv", "venv", "node_modules", ".git"}]
        for fn in files:
            if fn.endswith(".py"):
                py += 1
            elif fn.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
                js += 1
    return "javascript" if js > py else "python"


def analyze_code_repo(repo_path: str, name: str, language: str | None = None) -> SystemModel:
    language = language or detect_language(repo_path)
    if language == "javascript":
        return analyze_js_repo(repo_path, name=name)
    return analyze_python_repo(repo_path, name=name)


def analyze_inputs(
    name: str,
    repo_path: str | None = None,
    diagram_path: str | None = None,
    language: str | None = None,
    iac_path: str | None = None,
) -> SystemModel:
    """Analyze code, a diagram and/or infrastructure-as-code and fuse into one model."""
    fragments: list[SystemModel] = []
    if repo_path:
        fragments.append(analyze_code_repo(repo_path, name, language=language))
    if diagram_path:
        fragments.append(parse_mermaid_file(diagram_path, name=name))
    if iac_path:
        fragments.append(analyze_iac(iac_path, name=name))
    if not fragments:
        raise ValueError("Provide at least one of repo_path, diagram_path or iac_path")
    return build_system_model(name, *fragments)


import os.path

_LINDDUN_KB = os.path.join(os.path.dirname(__file__), "..", "frameworks", "linddun_kb.yaml")


def reason_over_model(
    model: SystemModel,
    kb: StrideKB | None = None,
    backend_config: dict[str, Any] | None = None,
    privacy: bool = False,
) -> list[Threat]:
    kb = kb or StrideKB.load()
    backend = get_backend(backend_config)
    threats = GroundedReasoner(kb, backend=backend, id_prefix="TF").analyze(model)
    if privacy:
        # Run the LINDDUN privacy sweep with the same grounded reasoner.
        priv_kb = StrideKB.load(_LINDDUN_KB)
        threats += GroundedReasoner(priv_kb, backend=backend, id_prefix="PRIV").analyze(model)
    return threats


def map_and_score(threats: list[Threat], mapper: MitigationMapper | None = None) -> list[Threat]:
    mapper = mapper or MitigationMapper()
    return mapper.enrich(threats)


def run_pipeline(
    name: str,
    repo_path: str | None = None,
    diagram_path: str | None = None,
    kb: StrideKB | None = None,
    backend_config: dict[str, Any] | None = None,
    language: str | None = None,
    iac_path: str | None = None,
    privacy: bool = False,
) -> tuple[SystemModel, list[Threat]]:
    """Full pipeline from inputs to a scored threat register."""
    kb = kb or StrideKB.load()
    model = analyze_inputs(name, repo_path=repo_path, diagram_path=diagram_path,
                           language=language, iac_path=iac_path)
    threats = reason_over_model(model, kb=kb, backend_config=backend_config,
                                privacy=privacy)
    threats = map_and_score(threats)
    return model, threats


def build_attack_paths(model: SystemModel, threats: list[Threat]):
    """Build grounded multi-step attack paths with ATT&CK mapping."""
    from .attack.attack_graph import AttackGraphBuilder
    from .mitigate.mapper import load_attack

    return AttackGraphBuilder(load_attack()).build(model, threats)


def run_on_model(
    model: SystemModel,
    kb: StrideKB | None = None,
    backend_config: dict[str, Any] | None = None,
    privacy: bool = False,
) -> list[Threat]:
    """Pipeline from an already-built model (used for synthetic systems)."""
    kb = kb or StrideKB.load()
    threats = reason_over_model(model, kb=kb, backend_config=backend_config,
                                privacy=privacy)
    return map_and_score(threats)
