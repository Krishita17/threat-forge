"""Render a SystemModel as a data-flow diagram (SVG) with trust boundaries.

Pure-Python SVG generation (no external dependencies) so it works from a clean
clone. Elements are laid out in columns by trust zone (least trusted on the
left), data flows are drawn as arrows, and trust boundaries are drawn as dashed
separators between adjacent zone columns - the visual proof that the tool
recovered real structure and inferred where trust changes.
"""

from __future__ import annotations

from ..model.schema import ElementType, SystemModel, TrustZone

_ZONE_ORDER = [
    TrustZone.PUBLIC,
    TrustZone.THIRD_PARTY,
    TrustZone.DMZ,
    TrustZone.APPLICATION,
    TrustZone.DATA,
    TrustZone.TRUSTED,
]
_ZONE_LABEL = {
    TrustZone.PUBLIC: "Public / Internet",
    TrustZone.THIRD_PARTY: "Third-party",
    TrustZone.DMZ: "Edge / DMZ",
    TrustZone.APPLICATION: "Application",
    TrustZone.DATA: "Data",
    TrustZone.TRUSTED: "Trusted / Admin",
}
_ZONE_FILL = {
    TrustZone.PUBLIC: "#fdecea",
    TrustZone.THIRD_PARTY: "#fef7e0",
    TrustZone.DMZ: "#e8f0fe",
    TrustZone.APPLICATION: "#e6f4ea",
    TrustZone.DATA: "#f3e8fd",
    TrustZone.TRUSTED: "#e0f7fa",
}

_COL_W = 210
_COL_GAP = 40
_NODE_W = 160
_NODE_H = 54
_NODE_GAP = 34
_TOP = 80
_MARGIN = 30


def _esc(s: str) -> str:
    return (
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def render_svg(model: SystemModel) -> str:
    # Group non-flow elements by zone, in canonical order; drop empty zones.
    by_zone: dict[TrustZone, list] = {}
    for el in model.elements:
        if el.type == ElementType.DATA_FLOW:
            continue
        by_zone.setdefault(el.zone, []).append(el)
    zones = [z for z in _ZONE_ORDER if by_zone.get(z)]

    # Compute positions.
    pos: dict[str, tuple[float, float]] = {}
    col_x: dict[TrustZone, float] = {}
    max_rows = max((len(by_zone[z]) for z in zones), default=1)
    for ci, z in enumerate(zones):
        x = _MARGIN + ci * (_COL_W + _COL_GAP)
        col_x[z] = x
        for ri, el in enumerate(by_zone[z]):
            y = _TOP + ri * (_NODE_H + _NODE_GAP)
            cx = x + (_COL_W - _NODE_W) / 2
            pos[el.id] = (cx, y)

    width = _MARGIN * 2 + len(zones) * _COL_W + (len(zones) - 1) * _COL_GAP
    height = _TOP + max_rows * (_NODE_H + _NODE_GAP) + 60

    out: list[str] = []
    out.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="Helvetica,Arial,sans-serif">'
    )
    out.append(
        '<defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" '
        'orient="auto" markerUnits="strokeWidth">'
        '<path d="M0,0 L9,3 L0,6 Z" fill="#555"/></marker></defs>'
    )
    out.append(f'<rect width="{width}" height="{height}" fill="#ffffff"/>')
    out.append(
        f'<text x="{width/2}" y="34" text-anchor="middle" font-size="20" '
        f'font-weight="bold" fill="#222">{_esc(model.name)} - Data-Flow Diagram</text>'
    )

    # Zone background columns + labels.
    for z in zones:
        x = col_x[z]
        out.append(
            f'<rect x="{x}" y="{_TOP-28}" width="{_COL_W}" height="{height-_TOP-10}" '
            f'rx="10" fill="{_ZONE_FILL[z]}" stroke="#d0d0d0"/>'
        )
        out.append(
            f'<text x="{x+_COL_W/2}" y="{_TOP-10}" text-anchor="middle" font-size="13" '
            f'font-weight="bold" fill="#555">{_esc(_ZONE_LABEL[z])}</text>'
        )

    # Trust boundaries: dashed vertical lines between adjacent populated zones
    # that actually have a crossing flow.
    crossing_pairs = set()
    for b in model.boundaries:
        crossing_pairs.add(frozenset({b.zone_a, b.zone_b}))
    for i in range(len(zones) - 1):
        za, zb = zones[i], zones[i + 1]
        boundary = next(
            (b for b in model.boundaries if {b.zone_a, b.zone_b} == {za, zb}), None
        )
        if not boundary:
            continue
        bx = col_x[zb] - _COL_GAP / 2
        out.append(
            f'<line x1="{bx}" y1="{_TOP-34}" x2="{bx}" y2="{height-20}" '
            f'stroke="#d93025" stroke-width="2" stroke-dasharray="7,5"/>'
        )
        out.append(
            f'<text x="{bx}" y="{height-6}" text-anchor="middle" font-size="10" '
            f'fill="#d93025">trust boundary</text>'
        )

    # Flows (draw before nodes so nodes sit on top).
    for fl in model.flows:
        if fl.source not in pos or fl.dest not in pos:
            continue
        sx, sy = pos[fl.source]
        dx, dy = pos[fl.dest]
        x1, y1 = sx + _NODE_W, sy + _NODE_H / 2
        x2, y2 = dx, dy + _NODE_H / 2
        if dx < sx:  # right-to-left edge: exit left, enter right
            x1, x2 = sx, dx + _NODE_W
        color = "#d93025" if (not fl.encrypted and _crosses(model, fl)) else "#888"
        out.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" '
            f'stroke-width="1.5" marker-end="url(#arrow)"/>'
        )
        midx, midy = (x1 + x2) / 2, (y1 + y2) / 2 - 4
        lbl = (",".join(fl.data)[:18] or "data") + (" 🔒" if fl.encrypted else "")
        out.append(
            f'<text x="{midx}" y="{midy}" text-anchor="middle" font-size="9" '
            f'fill="#666">{_esc(lbl)}</text>'
        )

    # Nodes.
    for el in model.elements:
        if el.type == ElementType.DATA_FLOW or el.id not in pos:
            continue
        x, y = pos[el.id]
        out.append(_node_shape(el, x, y))

    out.append("</svg>")
    return "\n".join(out)


def _crosses(model: SystemModel, fl) -> bool:
    s, d = model.element(fl.source), model.element(fl.dest)
    return bool(s and d and s.zone != d.zone)


def _node_shape(el, x: float, y: float) -> str:
    label = _esc(el.name)
    cx = x + _NODE_W / 2
    ty = y + _NODE_H / 2 + 4
    if el.type == ElementType.PROCESS:
        shape = (
            f'<rect x="{x}" y="{y}" width="{_NODE_W}" height="{_NODE_H}" rx="27" '
            f'fill="#ffffff" stroke="#1a73e8" stroke-width="2"/>'
        )
    elif el.type == ElementType.DATA_STORE:
        shape = (
            f'<path d="M{x},{y+8} a{_NODE_W/2},8 0 0 1 {_NODE_W},0 v{_NODE_H-16} '
            f'a{_NODE_W/2},8 0 0 1 {-_NODE_W},0 Z" fill="#ffffff" '
            f'stroke="#8430ce" stroke-width="2"/>'
        )
    else:  # external entity
        shape = (
            f'<rect x="{x}" y="{y}" width="{_NODE_W}" height="{_NODE_H}" '
            f'fill="#ffffff" stroke="#b06000" stroke-width="2"/>'
        )
    return (
        f"{shape}"
        f'<text x="{cx}" y="{ty}" text-anchor="middle" font-size="12" '
        f'fill="#222">{label}</text>'
    )


def render_svg_file(model: SystemModel, path: str) -> str:
    svg = render_svg(model)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(svg)
    return path
