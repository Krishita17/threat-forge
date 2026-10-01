"""System-model builder: the grounding layer.

Takes one or more partial :class:`SystemModel` fragments (from the code analyzer
and/or the diagram analyzer), fuses them into a single normalized model, and -
the key contribution - *infers trust boundaries* from the trust zones assigned
to elements. Trust boundaries are where data crosses between zones of differing
trust, and they are where threats concentrate, so inferring them well is half
the value of the tool.

Fusion strategy (deliberately simple and auditable, since a human reviews it):

* Elements are merged by normalized name. When the same component appears in
  both the code and the diagram, the fragments corroborate and we keep the union
  of their attributes (code-derived attributes win on conflict, because static
  analysis sees the real wiring).
* Flows are merged by (source, dest) endpoint pair after element merging.
* Trust boundaries are derived last, purely from the final zone assignment.
"""

from __future__ import annotations

import re

from .schema import (
    DataFlow,
    Element,
    SystemModel,
    TrustBoundary,
    TrustZone,
)


def _norm(name: str) -> str:
    """Normalize a name for cross-source matching: lowercase, alnum only."""
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def merge_models(name: str, *fragments: SystemModel) -> SystemModel:
    """Fuse model fragments into one normalized model (boundaries not yet set)."""
    merged = SystemModel(name=name)
    # id remap: a fragment's local element id -> the merged element id.
    id_map: dict[tuple[int, str], str] = {}
    by_key: dict[str, Element] = {}  # normalized-name -> merged element

    for frag_idx, frag in enumerate(fragments):
        for el in frag.elements:
            key = _norm(el.name) or el.id
            existing = by_key.get(key)
            if existing is None:
                new_el = Element(
                    id=el.id,
                    name=el.name,
                    type=el.type,
                    zone=el.zone,
                    attributes=dict(el.attributes),
                    source=el.source,
                )
                merged.add_element(new_el)
                by_key[key] = new_el
                id_map[(frag_idx, el.id)] = new_el.id
            else:
                # Corroboration: union attributes, keep the more-trusted/known zone.
                for k, v in el.attributes.items():
                    existing.attributes.setdefault(k, v)
                if existing.source and el.source and el.source not in existing.source:
                    existing.source = f"{existing.source}; {el.source}"
                elif not existing.source:
                    existing.source = el.source
                id_map[(frag_idx, el.id)] = existing.id

    # Merge flows using the remapped element ids.
    flow_keys: dict[tuple[str, str], DataFlow] = {}
    for frag_idx, frag in enumerate(fragments):
        for fl in frag.flows:
            src = id_map.get((frag_idx, fl.source))
            dst = id_map.get((frag_idx, fl.dest))
            if not src or not dst:
                continue
            key = (src, dst)
            existing = flow_keys.get(key)
            if existing is None:
                new_fl = DataFlow(
                    id=fl.id,
                    source=src,
                    dest=dst,
                    name=fl.name,
                    data=list(fl.data),
                    protocol=fl.protocol,
                    authenticated=fl.authenticated,
                    encrypted=fl.encrypted,
                    attributes=dict(fl.attributes),
                )
                merged.add_flow(new_fl)
                flow_keys[key] = new_fl
            else:
                existing.data = sorted(set(existing.data) | set(fl.data))
                existing.authenticated = existing.authenticated or fl.authenticated
                existing.encrypted = existing.encrypted or fl.encrypted
                if not existing.protocol:
                    existing.protocol = fl.protocol

    merged.metadata["sources"] = [f.name for f in fragments]
    return merged


# Human-readable labels for a boundary between two zones.
_BOUNDARY_NAMES = {
    frozenset({TrustZone.PUBLIC, TrustZone.DMZ}): "Internet -> Edge",
    frozenset({TrustZone.PUBLIC, TrustZone.APPLICATION}): "Internet -> Application",
    frozenset({TrustZone.DMZ, TrustZone.APPLICATION}): "Edge -> Application",
    frozenset({TrustZone.APPLICATION, TrustZone.DATA}): "Application -> Data",
    frozenset({TrustZone.APPLICATION, TrustZone.THIRD_PARTY}): "Application -> Third-party",
    frozenset({TrustZone.APPLICATION, TrustZone.TRUSTED}): "Application -> Trusted/Admin",
    frozenset({TrustZone.PUBLIC, TrustZone.THIRD_PARTY}): "Internet -> Third-party",
    frozenset({TrustZone.DATA, TrustZone.TRUSTED}): "Data -> Trusted/Admin",
}


def infer_trust_boundaries(model: SystemModel) -> SystemModel:
    """Derive trust boundaries from the model's zone assignment.

    A boundary exists between any two zones that are connected by at least one
    data flow. Each boundary records the flows that cross it. This is pure,
    deterministic inference over the fused model - no LLM involved - so that the
    grounding layer stays auditable.
    """
    model.boundaries = []
    seen: dict[frozenset[TrustZone], TrustBoundary] = {}

    for fl in model.flows:
        src, dst = model.element(fl.source), model.element(fl.dest)
        if not src or not dst or src.zone == dst.zone:
            continue
        pair = frozenset({src.zone, dst.zone})
        boundary = seen.get(pair)
        if boundary is None:
            za, zb = sorted((src.zone, dst.zone), key=lambda z: z.rank)
            name = _BOUNDARY_NAMES.get(pair, f"{za.value} -> {zb.value}")
            boundary = TrustBoundary(
                id=f"tb_{za.value}_{zb.value}",
                name=name,
                zone_a=za,
                zone_b=zb,
            )
            seen[pair] = boundary
            model.boundaries.append(boundary)
        if fl.id not in boundary.crossing_flows:
            boundary.crossing_flows.append(fl.id)

    model.boundaries.sort(key=lambda b: (b.zone_a.rank, b.zone_b.rank))
    return model


def build_system_model(name: str, *fragments: SystemModel) -> SystemModel:
    """End-to-end: merge fragments then infer trust boundaries."""
    merged = merge_models(name, *fragments)
    return infer_trust_boundaries(merged)
