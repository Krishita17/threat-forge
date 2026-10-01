"""Synthetic architecture generator with independent ground-truth threat sets.

Produces plausible :class:`SystemModel` instances with tunable knobs (number of
trust boundaries, presence of authn/crypto, data sensitivity, exposure). Each
system ships with a *ground-truth expected threat set* so the pipeline can be
evaluated reproducibly without needing real codebases.

Important for honest evaluation: the ground truth is derived from the *weaknesses
the generator deliberately injects*, via an independent mapping table
(:data:`WEAKNESS_THREATS`) - NOT by running the STRIDE KB evaluator. The reasoner
reaches its threats through a separate code path (KB ``when`` conditions), so
coverage and precision measured against this ground truth are meaningful: the
reasoner can both miss expected threats and surface unexpected ones.

A ground-truth key is ``(component_name, stride_code)``. Matching at eval time is
by this key, so the comparison does not depend on either side's wording.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from ..model.schema import (
    DataFlow,
    Element,
    ElementType,
    SystemModel,
    TrustZone,
)

# Independent mapping: an injected weakness -> the (element-role, STRIDE code)
# threats a competent reviewer would expect it to produce. This is the oracle.
# Keyed by weakness tag; value is a list of STRIDE codes expected on the element
# that carries the weakness.
WEAKNESS_THREATS: dict[str, list[str]] = {
    "unauthenticated_entity": ["S"],          # spoofing of the external actor
    "unauthenticated_endpoint": ["S"],        # spoofed caller to the process
    "no_input_validation": ["T"],             # tampering/injection
    "no_authorization": ["E"],                # privilege escalation
    "no_rate_limit": ["D"],                   # DoS of the internet-facing process
    "no_audit_logging_proc": ["R"],           # repudiation at the process
    "verbose_errors": ["I"],                  # info disclosure via errors
    "plaintext_transport": ["T", "I"],        # tampering + disclosure in transit
    "no_encryption_at_rest": ["I"],           # disclosure of data at rest
    "no_store_integrity": ["T"],              # tampering of stored data
    "no_store_audit": ["R"],                  # repudiation of store writes
    "admin_on_public_path": ["E"],            # elevation toward admin
}


@dataclass
class GroundTruthThreat:
    component: str
    stride: str
    weakness: str


@dataclass
class SyntheticSystem:
    model: SystemModel
    expected: list[GroundTruthThreat] = field(default_factory=list)

    def expected_keys(self) -> set[tuple[str, str]]:
        return {(g.component, g.stride) for g in self.expected}


@dataclass
class GenKnobs:
    """Tunable generation parameters."""

    n_services: int = 2
    has_authn: bool = True
    has_crypto: bool = True            # TLS in transit + encryption at rest
    has_authz: bool = True
    has_rate_limit: bool = True
    has_audit_logging: bool = True
    has_input_validation: bool = True
    data_sensitivity: str = "high"      # "low" | "high"
    use_third_party: bool = True
    use_admin_tier: bool = True


def _add(system: SyntheticSystem, component: str, codes: list[str], weakness: str):
    for c in codes:
        system.expected.append(GroundTruthThreat(component, c, weakness))


def generate_system(name: str, knobs: GenKnobs, seed: int = 0) -> SyntheticSystem:
    """Build one synthetic system + its ground-truth expected threats."""
    rng = random.Random(seed)
    m = SystemModel(name=name)
    sys = SyntheticSystem(model=m)
    sensitive = knobs.data_sensitivity == "high"
    sens_data = ["credentials", "pii"] if sensitive else ["config"]

    # --- External user (public zone) ---------------------------------------
    user = Element(
        id="ext_user",
        name="End User",
        type=ElementType.EXTERNAL_ENTITY,
        zone=TrustZone.PUBLIC,
        attributes={"authenticated": knobs.has_authn},
    )
    m.add_element(user)
    if not knobs.has_authn:
        _add(sys, user.name, WEAKNESS_THREATS["unauthenticated_entity"], "unauthenticated_entity")

    # --- Edge gateway (DMZ) -------------------------------------------------
    gateway = Element(
        id="gateway",
        name="API Gateway",
        type=ElementType.PROCESS,
        zone=TrustZone.DMZ,
        attributes={
            "internet_facing": True,
            "authenticated": knobs.has_authn,
            "rate_limited": knobs.has_rate_limit,
            "validates_input": knobs.has_input_validation,
            "authorization": knobs.has_authz,
            "audit_logging": knobs.has_audit_logging,
        },
    )
    m.add_element(gateway)
    if not knobs.has_rate_limit:
        _add(sys, gateway.name, WEAKNESS_THREATS["no_rate_limit"], "no_rate_limit")
    if not knobs.has_authn:
        _add(sys, gateway.name, WEAKNESS_THREATS["unauthenticated_endpoint"], "unauthenticated_endpoint")
    _add(sys, gateway.name, ["I"], "verbose_errors")  # internet-facing always risks I-PROC-ERRORS

    # --- Application services (application zone) ----------------------------
    services: list[Element] = []
    for i in range(max(1, knobs.n_services)):
        svc = Element(
            id=f"svc_{i}",
            name=f"Service {chr(ord('A') + i)}",
            type=ElementType.PROCESS,
            zone=TrustZone.APPLICATION,
            attributes={
                "internet_facing": False,
                "authenticated": knobs.has_authn,
                "authorization": knobs.has_authz,
                "validates_input": knobs.has_input_validation,
                "audit_logging": knobs.has_audit_logging,
                "handles_sensitive": sensitive,
            },
        )
        m.add_element(svc)
        services.append(svc)
        if not knobs.has_input_validation:
            _add(sys, svc.name, WEAKNESS_THREATS["no_input_validation"], "no_input_validation")
        if not knobs.has_authz:
            _add(sys, svc.name, WEAKNESS_THREATS["no_authorization"], "no_authorization")
        if not knobs.has_audit_logging:
            _add(sys, svc.name, WEAKNESS_THREATS["no_audit_logging_proc"], "no_audit_logging_proc")

    # --- Primary datastore (data zone) --------------------------------------
    db = Element(
        id="db",
        name="Primary Database",
        type=ElementType.DATA_STORE,
        zone=TrustZone.DATA,
        attributes={
            "handles_sensitive": sensitive,
            "encrypted": knobs.has_crypto,
            "integrity_protected": knobs.has_audit_logging,
            "audit_logging": knobs.has_audit_logging,
            "data": sens_data,
        },
    )
    m.add_element(db)
    if sensitive and not knobs.has_crypto:
        _add(sys, db.name, WEAKNESS_THREATS["no_encryption_at_rest"], "no_encryption_at_rest")
    if not knobs.has_audit_logging:
        _add(sys, db.name, WEAKNESS_THREATS["no_store_integrity"], "no_store_integrity")
        _add(sys, db.name, WEAKNESS_THREATS["no_store_audit"], "no_store_audit")

    # --- Optional third-party service --------------------------------------
    third = None
    if knobs.use_third_party:
        third = Element(
            id="third_party",
            name="Payment Provider",
            type=ElementType.EXTERNAL_ENTITY,
            zone=TrustZone.THIRD_PARTY,
            attributes={"authenticated": True},
        )
        m.add_element(third)

    # --- Optional admin tier ------------------------------------------------
    admin = None
    if knobs.use_admin_tier:
        admin = Element(
            id="admin_console",
            name="Admin Console",
            type=ElementType.PROCESS,
            zone=TrustZone.TRUSTED,
            attributes={
                "internet_facing": False,
                "authenticated": True,
                "authorization": knobs.has_authz,
                "audit_logging": knobs.has_audit_logging,
            },
        )
        m.add_element(admin)

    # --- Flows --------------------------------------------------------------
    def flow(fid, src, dst, data, proto="https"):
        enc = knobs.has_crypto and proto == "https"
        m.add_flow(
            DataFlow(
                id=fid,
                source=src,
                dest=dst,
                name=fid,
                data=data,
                protocol=proto if knobs.has_crypto else "http",
                authenticated=knobs.has_authn,
                encrypted=enc,
            )
        )

    flow("f_user_gw", user.id, gateway.id, sens_data)
    for i, svc in enumerate(services):
        flow(f"f_gw_svc{i}", gateway.id, svc.id, sens_data)
        flow(f"f_svc{i}_db", svc.id, db.id, sens_data)
        if third is not None and i == 0:
            flow(f"f_svc{i}_tp", svc.id, third.id, ["payment"])
    if admin is not None:
        flow("f_admin_db", admin.id, db.id, sens_data)
        # If authz is missing and a public path can reach admin via gateway,
        # flag elevation toward admin on the gateway.
        if not knobs.has_authz:
            gateway.attributes["reaches_trusted"] = True
            _add(sys, gateway.name, WEAKNESS_THREATS["admin_on_public_path"], "admin_on_public_path")

    # Ground-truth transport threats: for every boundary-crossing flow without
    # encryption that carries sensitive data, expect T + I on the destination.
    if not knobs.has_crypto:
        for fl in m.flows:
            s, d = m.element(fl.source), m.element(fl.dest)
            if s and d and s.zone != d.zone:
                _add(sys, d.name, ["T"], "plaintext_transport")
                if any(tok in {"credentials", "pii", "payment"} for tok in fl.data):
                    _add(sys, d.name, ["I"], "plaintext_transport")

    # De-duplicate ground-truth keys (a component may collect the same code once).
    seen = set()
    deduped = []
    for g in sys.expected:
        k = (g.component, g.stride)
        if k not in seen:
            seen.add(k)
            deduped.append(g)
    sys.expected = deduped
    return sys


# -- Preset catalog ----------------------------------------------------------
PRESETS: dict[str, GenKnobs] = {
    "secure_baseline": GenKnobs(
        n_services=2, has_authn=True, has_crypto=True, has_authz=True,
        has_rate_limit=True, has_audit_logging=True, has_input_validation=True,
        data_sensitivity="high", use_third_party=True, use_admin_tier=True,
    ),
    "insecure_startup": GenKnobs(
        n_services=2, has_authn=False, has_crypto=False, has_authz=False,
        has_rate_limit=False, has_audit_logging=False, has_input_validation=False,
        data_sensitivity="high", use_third_party=True, use_admin_tier=True,
    ),
    "partial_hardening": GenKnobs(
        n_services=3, has_authn=True, has_crypto=False, has_authz=True,
        has_rate_limit=False, has_audit_logging=True, has_input_validation=False,
        data_sensitivity="high", use_third_party=False, use_admin_tier=True,
    ),
    "internal_tool": GenKnobs(
        n_services=1, has_authn=True, has_crypto=True, has_authz=False,
        has_rate_limit=True, has_audit_logging=False, has_input_validation=True,
        data_sensitivity="low", use_third_party=False, use_admin_tier=False,
    ),
}


def generate_catalog(seed: int = 7) -> dict[str, SyntheticSystem]:
    """Generate the full preset catalog, each with ground truth."""
    out = {}
    for i, (preset_name, knobs) in enumerate(PRESETS.items()):
        out[preset_name] = generate_system(preset_name, knobs, seed=seed + i)
    return out
