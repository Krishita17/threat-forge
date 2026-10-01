"""Emit a Mermaid flowchart for a SystemModel.

Produces a diagram that the diagram analyzer can parse back, so the diagram
input path is evaluable against the same ground truth as the code path. Zones
become ``subgraph`` blocks; element type and a few security attributes are
encoded in a pipe-delimited label so the round trip preserves grounding, while
remaining a perfectly readable Mermaid diagram for a human.
"""

from __future__ import annotations

from ..model.schema import ElementType, SystemModel, TrustZone

_SHAPE = {
    ElementType.PROCESS: ("([", "])"),        # stadium = process
    ElementType.DATA_STORE: ("[(", ")]"),     # cylinder = data store
    ElementType.EXTERNAL_ENTITY: ("[", "]"),  # rectangle = external entity
}

_ZONE_TITLE = {
    TrustZone.PUBLIC: "Public / Internet",
    TrustZone.DMZ: "Edge / DMZ",
    TrustZone.APPLICATION: "Application",
    TrustZone.DATA: "Data",
    TrustZone.THIRD_PARTY: "Third-party",
    TrustZone.TRUSTED: "Trusted / Admin",
}


def _attr_tags(el) -> str:
    a = el.attributes
    tags = []
    if "authenticated" in a:
        tags.append(f"auth={'yes' if a['authenticated'] else 'no'}")
    if a.get("internet_facing"):
        tags.append("internet=yes")
    if "encrypted" in a:
        tags.append(f"enc={'yes' if a['encrypted'] else 'no'}")
    if a.get("handles_sensitive") or a.get("handles_pii"):
        tags.append("sens=yes")
    if "authorization" in a:
        tags.append(f"authz={'yes' if a['authorization'] else 'no'}")
    if "rate_limited" in a:
        tags.append(f"ratelimit={'yes' if a['rate_limited'] else 'no'}")
    if "validates_input" in a:
        tags.append(f"validate={'yes' if a['validates_input'] else 'no'}")
    if "audit_logging" in a:
        tags.append(f"audit={'yes' if a['audit_logging'] else 'no'}")
    return ";".join(tags)


def to_mermaid(model: SystemModel) -> str:
    lines = ["flowchart LR"]
    # Group elements by zone.
    by_zone: dict[TrustZone, list] = {}
    for el in model.elements:
        if el.type == ElementType.DATA_FLOW:
            continue
        by_zone.setdefault(el.zone, []).append(el)

    for zone in TrustZone:
        els = by_zone.get(zone)
        if not els:
            continue
        lines.append(f"  subgraph {zone.value}[{_ZONE_TITLE[zone]}]")
        for el in els:
            open_s, close_s = _SHAPE[el.type]
            label = f"{el.name}|{el.type.value}"
            tags = _attr_tags(el)
            if tags:
                label += f"|{tags}"
            lines.append(f'    {el.id}{open_s}"{label}"{close_s}')
        lines.append("  end")

    for fl in model.flows:
        data = ",".join(fl.data) or "data"
        proto = fl.protocol or ("https" if fl.encrypted else "http")
        lines.append(f"  {fl.source} -->|{data} / {proto}| {fl.dest}")

    return "\n".join(lines) + "\n"
