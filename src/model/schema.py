"""Core data-flow-diagram (DFD) schema shared across the whole pipeline.

Every stage of ThreatForge speaks this one vocabulary. The code analyzer and the
diagram analyzer both emit :class:`SystemModel` instances; the trust-boundary
inference, STRIDE reasoner, mitigation mapper, and report generator all consume
them. Keeping a single normalized schema is what lets the two input paths
(code / diagram) corroborate one another and what keeps the LLM grounded.

The vocabulary follows the classic Microsoft DFD element taxonomy used by STRIDE:

* ``PROCESS``          - code that acts on data (a service, handler, worker).
* ``DATA_STORE``       - where data rests (database, cache, queue, file, bucket).
* ``EXTERNAL_ENTITY``  - an actor outside the system boundary (user, 3rd-party API).
* ``DATA_FLOW``        - data moving between two elements (modelled as an edge).

Trust boundaries are *zones*; each element is assigned to exactly one zone, and a
data flow that connects elements in different zones is a boundary-crossing flow -
which is where threats concentrate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


SCHEMA_VERSION = "1.0"


class ElementType(str, Enum):
    """The four DFD element kinds recognized by STRIDE."""

    PROCESS = "process"
    DATA_STORE = "data_store"
    EXTERNAL_ENTITY = "external_entity"
    DATA_FLOW = "data_flow"


class TrustZone(str, Enum):
    """Trust zones, ordered loosely from least to most trusted.

    The ordering matters for boundary inference: a flow between two different
    zones crosses a trust boundary, and the larger the trust gap the more
    interesting the crossing.
    """

    PUBLIC = "public"            # the open internet / untrusted callers
    DMZ = "dmz"                  # edge: load balancers, gateways, reverse proxies
    APPLICATION = "application"  # the app's own processes
    DATA = "data"               # persistence tier (databases, queues, buckets)
    THIRD_PARTY = "third_party"  # external services the app calls out to
    TRUSTED = "trusted"          # internal admin / privileged tooling

    @property
    def rank(self) -> int:
        order = [
            TrustZone.PUBLIC,
            TrustZone.THIRD_PARTY,
            TrustZone.DMZ,
            TrustZone.APPLICATION,
            TrustZone.DATA,
            TrustZone.TRUSTED,
        ]
        return order.index(self)


@dataclass
class Element:
    """A node in the DFD: a process, data store, or external entity."""

    id: str
    name: str
    type: ElementType
    zone: TrustZone = TrustZone.APPLICATION
    # Free-form, analyzer-supplied attributes used by the reasoner as grounding,
    # e.g. {"authenticated": False, "encrypted": False, "handles_pii": True,
    #       "technology": "flask", "internet_facing": True}.
    attributes: dict[str, Any] = field(default_factory=dict)
    # Where this element came from, for human review (file path, diagram node id).
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        d["zone"] = self.zone.value
        return d


@dataclass
class DataFlow:
    """A directed edge: data travelling from ``source`` to ``dest``."""

    id: str
    source: str  # Element.id
    dest: str    # Element.id
    name: str = ""
    # What travels: used by the reasoner (e.g. "credentials", "pii", "session").
    data: list[str] = field(default_factory=list)
    protocol: str = ""           # "https", "http", "tcp", "amqp", ...
    authenticated: bool = False
    encrypted: bool = False
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TrustBoundary:
    """An inferred seam between two trust zones.

    A boundary is identified by the pair of zones it separates and carries the
    set of data-flow ids that cross it. Boundaries are *inferred* by the model
    builder, not supplied by the user - that inference is a core contribution.
    """

    id: str
    name: str
    zone_a: TrustZone
    zone_b: TrustZone
    crossing_flows: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["zone_a"] = self.zone_a.value
        d["zone_b"] = self.zone_b.value
        return d


@dataclass
class SystemModel:
    """The normalized DFD: the single grounding artifact for the whole pipeline."""

    name: str
    elements: list[Element] = field(default_factory=list)
    flows: list[DataFlow] = field(default_factory=list)
    boundaries: list[TrustBoundary] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    # -- lookups -------------------------------------------------------------
    def element(self, element_id: str) -> Element | None:
        for e in self.elements:
            if e.id == element_id:
                return e
        return None

    def flow(self, flow_id: str) -> DataFlow | None:
        for f in self.flows:
            if f.id == flow_id:
                return f
        return None

    def elements_of(self, element_type: ElementType) -> list[Element]:
        return [e for e in self.elements if e.type == element_type]

    def crossing_flows(self) -> list[DataFlow]:
        """Flows whose endpoints live in different trust zones."""
        out = []
        for f in self.flows:
            src, dst = self.element(f.source), self.element(f.dest)
            if src and dst and src.zone != dst.zone:
                out.append(f)
        return out

    def add_element(self, element: Element) -> Element:
        if self.element(element.id) is None:
            self.elements.append(element)
        return element

    def add_flow(self, flow: DataFlow) -> DataFlow:
        if self.flow(flow.id) is None:
            self.flows.append(flow)
        return flow

    # -- serialization -------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "schema_version": self.schema_version,
            "metadata": self.metadata,
            "elements": [e.to_dict() for e in self.elements],
            "flows": [f.to_dict() for f in self.flows],
            "boundaries": [b.to_dict() for b in self.boundaries],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SystemModel":
        elements = [
            Element(
                id=e["id"],
                name=e["name"],
                type=ElementType(e["type"]),
                zone=TrustZone(e.get("zone", "application")),
                attributes=e.get("attributes", {}),
                source=e.get("source", ""),
            )
            for e in d.get("elements", [])
        ]
        flows = [
            DataFlow(
                id=f["id"],
                source=f["source"],
                dest=f["dest"],
                name=f.get("name", ""),
                data=f.get("data", []),
                protocol=f.get("protocol", ""),
                authenticated=f.get("authenticated", False),
                encrypted=f.get("encrypted", False),
                attributes=f.get("attributes", {}),
            )
            for f in d.get("flows", [])
        ]
        boundaries = [
            TrustBoundary(
                id=b["id"],
                name=b["name"],
                zone_a=TrustZone(b["zone_a"]),
                zone_b=TrustZone(b["zone_b"]),
                crossing_flows=b.get("crossing_flows", []),
            )
            for b in d.get("boundaries", [])
        ]
        return cls(
            name=d["name"],
            elements=elements,
            flows=flows,
            boundaries=boundaries,
            metadata=d.get("metadata", {}),
            schema_version=d.get("schema_version", SCHEMA_VERSION),
        )

    @classmethod
    def from_json(cls, text: str) -> "SystemModel":
        return cls.from_dict(json.loads(text))
