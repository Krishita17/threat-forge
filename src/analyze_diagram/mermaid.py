"""Diagram analyzer: Mermaid flowchart -> SystemModel fragment.

Parses a Mermaid ``flowchart`` into the shared element/connector vocabulary so a
team that has an architecture diagram but no clean code (or vice-versa) can still
get a model. The parser handles:

* ``subgraph <id>[<Title>]`` blocks -> trust zones (by title/id keyword).
* node declarations with shapes:
    ``id([...])`` stadium   -> process
    ``id[(...)]`` cylinder  -> data store
    ``id[...]``   rectangle -> external entity (or process if labelled so)
* an optional pipe-delimited label ``Name|type|k=v;k=v`` carrying type + attrs.
* edges ``a -->|label| b`` where the label may encode ``data / protocol``.

When metadata is absent (a hand-drawn diagram), type is inferred from shape and
zone from the enclosing subgraph, so plain diagrams still work.
"""

from __future__ import annotations

import re

from ..model.schema import (
    DataFlow,
    Element,
    ElementType,
    SystemModel,
    TrustZone,
)

_ZONE_KEYWORDS = [
    (("public", "internet", "external", "untrusted"), TrustZone.PUBLIC),
    (("dmz", "edge", "gateway", "proxy", "lb", "load"), TrustZone.DMZ),
    (("third", "3rd", "partner", "vendor", "payment", "external service"), TrustZone.THIRD_PARTY),
    (("data", "database", "storage", "persistence", "db"), TrustZone.DATA),
    (("trusted", "admin", "internal", "privileged", "mgmt"), TrustZone.TRUSTED),
    (("app", "application", "service", "backend", "api"), TrustZone.APPLICATION),
]

_NODE_RE = re.compile(
    r'^\s*([A-Za-z0-9_]+)\s*(\[\(|\(\[|\{\{|\[|\()\s*"?(.*?)"?\s*(\)\]|\]\)|\}\}|\]|\))\s*$'
)
_SUBGRAPH_RE = re.compile(r'^\s*subgraph\s+([A-Za-z0-9_]+)\s*(?:\[\s*"?(.*?)"?\s*\])?\s*$')
_EDGE_RE = re.compile(
    r'^\s*([A-Za-z0-9_]+)\s*(?:-->|---|-\.->|==>)\s*(?:\|\s*"?(.*?)"?\s*\|)?\s*([A-Za-z0-9_]+)\s*$'
)


def _zone_from_text(text: str, default: TrustZone = TrustZone.APPLICATION) -> TrustZone:
    low = text.lower()
    for keywords, zone in _ZONE_KEYWORDS:
        if any(k in low for k in keywords):
            return zone
    return default


def _type_from_shape(open_s: str) -> ElementType:
    if open_s == "[(" or open_s == "([" and False:
        return ElementType.DATA_STORE
    if open_s == "[(":
        return ElementType.DATA_STORE
    if open_s == "([":
        return ElementType.PROCESS
    if open_s == "{{":
        return ElementType.EXTERNAL_ENTITY
    if open_s == "(":
        return ElementType.PROCESS
    return ElementType.EXTERNAL_ENTITY  # bare rectangle default


_BOOL = {"yes": True, "no": False, "true": True, "false": False}


def _parse_label(raw: str, shape_type: ElementType):
    """Return (display_name, element_type, attributes) from a node label."""
    parts = [p.strip() for p in raw.split("|")]
    name = parts[0] or "node"
    el_type = shape_type
    attrs: dict = {}
    if len(parts) >= 2 and parts[1]:
        try:
            el_type = ElementType(parts[1])
        except ValueError:
            pass
    if len(parts) >= 3 and parts[2]:
        for kv in parts[2].split(";"):
            if "=" not in kv:
                continue
            k, v = (x.strip() for x in kv.split("=", 1))
            attrs[_ATTR_ALIAS.get(k, k)] = _BOOL.get(v.lower(), v)
    return name, el_type, attrs


_ATTR_ALIAS = {
    "auth": "authenticated",
    "internet": "internet_facing",
    "enc": "encrypted",
    "sens": "handles_sensitive",
    "authz": "authorization",
    "ratelimit": "rate_limited",
    "validate": "validates_input",
    "audit": "audit_logging",
}


def parse_mermaid(text: str, name: str = "diagram") -> SystemModel:
    model = SystemModel(name=name)
    model.metadata["input"] = "diagram"
    current_zone = TrustZone.APPLICATION
    zone_stack: list[TrustZone] = []
    flow_counter = 0

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("%%") or stripped.startswith("flowchart") or stripped.startswith("graph"):
            continue

        sg = _SUBGRAPH_RE.match(line)
        if sg:
            gid, title = sg.group(1), sg.group(2) or sg.group(1)
            current_zone = _zone_from_text(f"{gid} {title}")
            zone_stack.append(current_zone)
            continue
        if stripped == "end":
            if zone_stack:
                zone_stack.pop()
            current_zone = zone_stack[-1] if zone_stack else TrustZone.APPLICATION
            continue

        edge = _EDGE_RE.match(line)
        node = _NODE_RE.match(line)
        # Edge lines can also match node regex loosely; prefer edge if it has an arrow.
        if ("-->" in stripped or "---" in stripped or "==>" in stripped or "-.->" in stripped) and edge:
            src, label, dst = edge.group(1), edge.group(2) or "", edge.group(3)
            data: list[str] = []
            protocol = ""
            if label:
                if "/" in label:
                    dpart, ppart = label.rsplit("/", 1)
                    data = [d.strip() for d in dpart.split(",") if d.strip()]
                    protocol = ppart.strip()
                else:
                    data = [d.strip() for d in label.split(",") if d.strip()]
            flow_counter += 1
            model.add_flow(
                DataFlow(
                    id=f"df_{flow_counter}",
                    source=src,
                    dest=dst,
                    name=label,
                    data=data,
                    protocol=protocol,
                    encrypted=protocol.lower() in ("https", "tls", "mtls"),
                    authenticated=False,
                )
            )
            continue

        if node:
            nid, open_s, raw, _close = node.group(1), node.group(2), node.group(3), node.group(4)
            shape_type = _type_from_shape(open_s)
            disp, el_type, attrs = _parse_label(raw, shape_type)
            model.add_element(
                Element(
                    id=nid,
                    name=disp,
                    type=el_type,
                    zone=current_zone,
                    attributes=attrs,
                    source=f"diagram:{nid}",
                )
            )

    return model


def parse_mermaid_file(path: str, name: str | None = None) -> SystemModel:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    return parse_mermaid(text, name=name or path)
