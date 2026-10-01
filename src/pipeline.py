"""End-to-end pipeline orchestration.

Wires the stages together: analyze (code and/or diagram) -> build system model ->
ground STRIDE reasoner -> mitigation mapper + risk scorer -> report. Every stage
is individually callable (see the CLI subcommands); this module is the
convenience path used by ``make`` targets and the sample run.
"""

from __future__ import annotations

from typing import Any

from .analyze_code.python_analyzer import analyze_python_repo
from .analyze_diagram.mermaid import parse_mermaid_file
from .mitigate.mapper import MitigationMapper
from .model.builder import build_system_model
from .model.schema import SystemModel
from .reason.backends import get_backend
from .reason.reasoner import GroundedReasoner
from .reason.threat import Threat
from .stride.kb import StrideKB


def analyze_inputs(
    name: str,
    repo_path: str | None = None,
    diagram_path: str | None = None,
) -> SystemModel:
    """Analyze code and/or a diagram and fuse into one system model."""
    fragments: list[SystemModel] = []
    if repo_path:
        fragments.append(analyze_python_repo(repo_path, name=name))
    if diagram_path:
        fragments.append(parse_mermaid_file(diagram_path, name=name))
    if not fragments:
        raise ValueError("Provide at least one of repo_path or diagram_path")
    return build_system_model(name, *fragments)


def reason_over_model(
    model: SystemModel,
    kb: StrideKB | None = None,
    backend_config: dict[str, Any] | None = None,
) -> list[Threat]:
    kb = kb or StrideKB.load()
    reasoner = GroundedReasoner(kb, backend=get_backend(backend_config))
    return reasoner.analyze(model)


def map_and_score(threats: list[Threat], mapper: MitigationMapper | None = None) -> list[Threat]:
    mapper = mapper or MitigationMapper()
    return mapper.enrich(threats)


def run_pipeline(
    name: str,
    repo_path: str | None = None,
    diagram_path: str | None = None,
    kb: StrideKB | None = None,
    backend_config: dict[str, Any] | None = None,
) -> tuple[SystemModel, list[Threat]]:
    """Full pipeline from inputs to a scored threat register."""
    kb = kb or StrideKB.load()
    model = analyze_inputs(name, repo_path=repo_path, diagram_path=diagram_path)
    threats = reason_over_model(model, kb=kb, backend_config=backend_config)
    threats = map_and_score(threats)
    return model, threats


def run_on_model(
    model: SystemModel,
    kb: StrideKB | None = None,
    backend_config: dict[str, Any] | None = None,
) -> list[Threat]:
    """Pipeline from an already-built model (used for synthetic systems)."""
    kb = kb or StrideKB.load()
    threats = reason_over_model(model, kb=kb, backend_config=backend_config)
    return map_and_score(threats)
