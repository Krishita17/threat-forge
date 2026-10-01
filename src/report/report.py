"""Threat-model report generator.

Assembles the reviewable deliverable in Markdown: the rendered DFD, the trust
boundaries, the triaged threat register, a per-STRIDE summary, the risk heatmap
reference, and the mitigation table. Every table here is generated from the
model + register, never hand-written, so the report regenerates deterministically.
The human-in-the-loop framing is stated at the top of every report.
"""

from __future__ import annotations

import os

from ..mitigate.mapper import MitigationMapper
from ..model.schema import ElementType, SystemModel
from ..reason.threat import Threat
from . import exports
from .dfd_render import render_svg_file

_STRIDE_ORDER = ["S", "T", "R", "I", "D", "E"]
_STRIDE_FULL = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
    "I": "Information disclosure", "D": "Denial of service",
    "E": "Elevation of privilege",
}


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |")
    return "\n".join(out)


def generate_report(
    model: SystemModel,
    threats: list[Threat],
    out_dir: str,
    mapper: MitigationMapper | None = None,
    slug: str | None = None,
) -> dict[str, str]:
    """Write the full report + exports. Returns a dict of artifact paths."""
    os.makedirs(out_dir, exist_ok=True)
    mapper = mapper or MitigationMapper()
    slug = slug or "".join(c if c.isalnum() else "_" for c in model.name.lower())

    svg_path = os.path.join(out_dir, f"{slug}_dfd.svg")
    render_svg_file(model, svg_path)

    # Counts.
    counts = {c: 0 for c in _STRIDE_ORDER}
    for t in threats:
        counts[t.stride] = counts.get(t.stride, 0) + 1
    n_elem = len([e for e in model.elements if e.type != ElementType.DATA_FLOW])

    lines: list[str] = []
    lines.append(f"# Threat Model: {model.name}")
    lines.append("")
    lines.append(
        "> **Draft for review - not a security sign-off.** ThreatForge produces a "
        "candidate STRIDE threat model from recovered structure. It can miss real "
        "threats and propose spurious ones. A competent human must review, edit, "
        "accept or reject every item below. Author: Krishita Sanjay Choksi."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(_md_table(
        ["Metric", "Value"],
        [
            ["Components", str(n_elem)],
            ["Data flows", str(len(model.flows))],
            ["Trust boundaries", str(len(model.boundaries))],
            ["Threats identified", str(len(threats))],
            ["Critical / High", str(sum(1 for t in threats if t.risk_level in ("Critical", "High")))],
        ],
    ))
    lines.append("")

    # DFD.
    lines.append("## Data-Flow Diagram")
    lines.append("")
    lines.append(f"![DFD]({os.path.basename(svg_path)})")
    lines.append("")

    # Trust boundaries.
    lines.append("## Trust Boundaries (inferred)")
    lines.append("")
    if model.boundaries:
        rows = [[b.name, str(len(b.crossing_flows))] for b in model.boundaries]
        lines.append(_md_table(["Boundary", "Crossing flows"], rows))
    else:
        lines.append("_No trust boundaries inferred (single-zone system)._")
    lines.append("")

    # STRIDE distribution.
    lines.append("## Threats by STRIDE Category")
    lines.append("")
    lines.append(_md_table(
        ["Category", "Count"],
        [[_STRIDE_FULL[c], str(counts[c])] for c in _STRIDE_ORDER],
    ))
    lines.append("")

    # Threat register.
    lines.append("## Threat Register")
    lines.append("")
    reg_rows = []
    for t in threats:
        reg_rows.append([
            t.id, t.component, _STRIDE_FULL.get(t.stride, t.stride), t.title,
            t.boundary or "-", f"{t.risk} ({t.risk_level})", t.review_status,
        ])
    lines.append(_md_table(
        ["ID", "Component", "STRIDE", "Threat", "Boundary", "Risk", "Review"],
        reg_rows,
    ))
    lines.append("")

    # Mitigation table.
    lines.append("## Mitigations and Mapped Controls")
    lines.append("")
    mit_rows = []
    for row in mapper.mitigation_table(threats):
        mit_rows.append([
            row["threat_id"],
            row["threat"],
            ", ".join(row["controls"]) or "-",
            row["cwe"] or "-",
            row["mitigation"],
            row["priority"],
        ])
    lines.append(_md_table(
        ["ID", "Threat", "Mapped controls", "CWE", "Recommended fix", "Priority"],
        mit_rows,
    ))
    lines.append("")

    # Detailed rationale.
    lines.append("## Threat Detail")
    lines.append("")
    for t in threats:
        lines.append(f"### {t.id} - {t.title}")
        lines.append("")
        lines.append(f"- **Component:** {t.component}")
        lines.append(f"- **STRIDE:** {_STRIDE_FULL.get(t.stride, t.stride)}")
        if t.boundary:
            lines.append(f"- **Trust boundary:** {t.boundary}")
        lines.append(f"- **Rationale:** {t.rationale}")
        lines.append(f"- **Mitigation:** {t.mitigation}")
        lines.append(f"- **Controls:** {', '.join(t.controls) or '-'} | **CWE:** {t.cwe or '-'}")
        lines.append(f"- **Risk:** likelihood {t.likelihood} x impact {t.impact} = "
                     f"{t.risk} ({t.risk_level})")
        lines.append(f"- **Source:** KB pattern `{t.source_pattern}`")
        lines.append("")

    md = "\n".join(lines)
    md_path = os.path.join(out_dir, f"{slug}_threat_model.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md)

    # Exports.
    paths = {"markdown": md_path, "dfd_svg": svg_path}
    json_path = os.path.join(out_dir, f"{slug}.threatforge.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(exports.to_native_json(model, threats))
    paths["json"] = json_path

    pytm_path = os.path.join(out_dir, f"{slug}.pytm.py")
    with open(pytm_path, "w", encoding="utf-8") as fh:
        fh.write(exports.to_pytm(model, threats))
    paths["pytm"] = pytm_path

    td_path = os.path.join(out_dir, f"{slug}.threatdragon.json")
    with open(td_path, "w", encoding="utf-8") as fh:
        fh.write(exports.to_threat_dragon(model, threats))
    paths["threat_dragon"] = td_path

    return paths
