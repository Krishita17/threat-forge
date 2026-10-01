# STRIDE taxonomy (reference)

STRIDE is Microsoft's threat-classification methodology. Each letter names a
category of threat and pairs with the security property it violates:

| Code | Threat | Property violated | Typical question |
| --- | --- | --- | --- |
| S | Spoofing | Authentication | Can someone pretend to be someone/something else? |
| T | Tampering | Integrity | Can data or code be modified without authorization? |
| R | Repudiation | Non-repudiation | Can an actor deny having performed an action? |
| I | Information disclosure | Confidentiality | Can data be exposed to those not authorized? |
| D | Denial of service | Availability | Can the system be made unavailable? |
| E | Elevation of privilege | Authorization | Can an actor gain capabilities they should not have? |

Threat modeling with STRIDE typically proceeds by:

1. drawing a **data-flow diagram** of the system (processes, data stores,
   external entities, data flows);
2. identifying **trust boundaries** where data crosses between zones of differing
   trust;
3. sweeping each element for the STRIDE categories that apply to its type
   (see the per-element table in this directory's README); and
4. recording threats, mitigations and residual risk for human review.

ThreatForge automates steps 1–3 to produce a *draft* and leaves step 4's
judgment to a human reviewer. Requirement text referenced elsewhere in this repo
is paraphrased; see the official Microsoft, OWASP, NIST and MITRE sources for
authoritative definitions.

Author: Krishita Sanjay Choksi.
