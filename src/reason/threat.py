"""The Threat record - the unit of the threat register."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Threat:
    id: str
    component: str          # element name the threat is against
    component_id: str
    stride: str             # single-letter STRIDE code (S/T/R/I/D/E)
    stride_name: str
    title: str
    rationale: str
    # Filled by the mitigation mapper:
    mitigation: str = ""
    controls: list[str] = field(default_factory=list)
    cwe: str = ""
    owasp_top10: str = ""   # OWASP Top 10:2021 category, e.g. "A01:2021 - ..."
    likelihood: int = 0     # 1-5
    impact: int = 0         # 1-5
    risk: int = 0           # likelihood * impact (1-25)
    risk_level: str = ""    # Low / Medium / High / Critical
    boundary: str = ""      # name of the trust boundary involved, if any
    source_pattern: str = ""  # KB pattern id or "llm" for ungrounded baseline
    # Human-in-the-loop review state: accepted / edited / rejected / proposed.
    review_status: str = "proposed"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Threat":
        return cls(**d)


def threats_to_json(threats: list[Threat], indent: int = 2) -> str:
    return json.dumps([t.to_dict() for t in threats], indent=indent)
