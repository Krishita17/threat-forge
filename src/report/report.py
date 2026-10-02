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
from .html_report import render_html_file

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
        cat = _STRIDE_FULL.get(t.stride, t.stride) if t.framework == "STRIDE" else t.stride_name
        reg_rows.append([
            t.id, t.component, cat, t.title,
            t.boundary or "-", f"{t.risk} ({t.risk_level})",
            f"{t.confidence:.2f}", "yes" if t.needs_review else "no",
        ])
    lines.append(_md_table(
        ["ID", "Component", "Category", "Threat", "Boundary", "Risk", "Conf.", "Review?"],
        reg_rows,
    ))
    lines.append("")
    lines.append("_`Conf.` is calibrated confidence; `Review? = yes` flags threats a "
                 "human must confirm (high-risk or low-confidence)._")
    lines.append("")

    # Attack paths.
    from ..pipeline import build_attack_paths  # local import to avoid cycle
    paths = build_attack_paths(model, threats)
    if paths:
        lines.append("## Attack Paths (chained, with MITRE ATT&CK)")
        lines.append("")
        lines.append("Multi-step paths an attacker could follow along the data-flow "
                     "graph, each step mapped to a MITRE ATT&CK technique. Grounded: "
                     "every hop carries a real threat from the register.")
        lines.append("")
        for p in paths:
            flag = " _(needs review - low confidence)_" if p.needs_review else ""
            lines.append(f"### {p.id}: {p.entry} → {p.target} "
                         f"(risk {p.total_risk}, confidence {p.confidence:.2f}){flag}")
            lines.append("")
            lines.append("| # | Component | STRIDE | Threat | ATT&CK technique | Tactic |")
            lines.append("| --- | --- | --- | --- | --- | --- |")
            for i, s in enumerate(p.steps, 1):
                lines.append(f"| {i} | {s.component} | {_STRIDE_FULL.get(s.stride, s.stride)} "
                             f"| {s.title} | {s.attack_technique or '-'} | {s.tactic or '-'} |")
            lines.append("")

    # Mitigation table.
    lines.append("## Mitigations and Mapped Controls")
    lines.append("")
    mit_rows = []
    for t in threats:
        control_titles = []
        for cid in t.controls:
            c = mapper.control_detail(cid)
            control_titles.append(f"{cid} ({c.title})" if c else cid)
        mit_rows.append([
            t.id,
            t.title,
            ", ".join(control_titles) or "-",
            t.cwe or "-",
            t.owasp_top10.split(" - ")[0] if t.owasp_top10 else "-",
            ", ".join(t.compliance) or "-",
            t.mitigation,
            t.risk_level,
        ])
    lines.append(_md_table(
        ["ID", "Threat", "Mapped controls", "CWE", "OWASP", "Compliance (SOC2/ISO/PCI)",
         "Recommended fix", "Priority"],
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

    # SARIF for GitHub code-scanning / Security tab.
    sarif_path = os.path.join(out_dir, f"{slug}.sarif")
    with open(sarif_path, "w", encoding="utf-8") as fh:
        fh.write(exports.to_sarif(model, threats,
                                  anchor_file=os.path.basename(md_path)))
    paths["sarif"] = sarif_path

    # GitHub-native Mermaid DFD (embeddable in Markdown).
    mmd_path = os.path.join(out_dir, f"{slug}_dfd.mmd")
    with open(mmd_path, "w", encoding="utf-8") as fh:
        fh.write(exports.to_mermaid_dfd(model))
    paths["mermaid"] = mmd_path

    # Interactive, self-contained HTML report.
    html_path = os.path.join(out_dir, f"{slug}_threat_model.html")
    render_html_file(model, threats, html_path)
    paths["html"] = html_path

    # shields.io badge endpoint.
    badge_path = os.path.join(out_dir, f"{slug}_badge.json")
    with open(badge_path, "w", encoding="utf-8") as fh:
        fh.write(exports.to_shields_badge(threats))
    paths["badge"] = badge_path

    # Attack-path graph (grounded, ATT&CK-mapped).
    import json as _json

    from ..pipeline import build_attack_paths
    ap = build_attack_paths(model, threats)
    ap_path = os.path.join(out_dir, f"{slug}_attack_paths.json")
    with open(ap_path, "w", encoding="utf-8") as fh:
        _json.dump([p.to_dict() for p in ap], fh, indent=2)
    paths["attack_paths"] = ap_path

    # Threat -> verification: pytest security tests + Sigma detection rules.
    from ..verify.generate import generate_pytest, generate_sigma_yaml
    tests_path = os.path.join(out_dir, f"test_{slug}_security.py")
    with open(tests_path, "w", encoding="utf-8") as fh:
        fh.write(generate_pytest(threats))
    paths["pytest"] = tests_path
    sigma_path = os.path.join(out_dir, f"{slug}.sigma.yml")
    with open(sigma_path, "w", encoding="utf-8") as fh:
        fh.write(generate_sigma_yaml(threats))
    paths["sigma"] = sigma_path

    return paths
