# Framework reference data

This directory holds the recognized security frameworks ThreatForge maps to.
All identifiers and titles are the **genuine** ones published by each framework;
all requirement/summary text is **paraphrased** (my own short summaries), never
reproduced verbatim. Consult the official sources for authoritative wording.

| File | Framework | Version referenced |
| --- | --- | --- |
| `controls.json` | OWASP ASVS, NIST SP 800-53, MITRE CWE | ASVS 4.0.3; NIST 800-53 Rev. 5; CWE 4.x |
| `stride.md` | Microsoft STRIDE methodology | per-element applicability |

## STRIDE per-element applicability

The core of the STRIDE knowledge base (`src/stride/stride_kb.yaml`) is the
mapping from DFD element type to the STRIDE categories that can apply to it. This
is the long-standing Microsoft STRIDE-per-element convention:

| DFD element | S | T | R | I | D | E |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| External entity | ✓ |  | ✓ |  |  |  |
| Process | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data store |  | ✓ | ✓ | ✓ | ✓ |  |
| Data flow |  | ✓ |  | ✓ | ✓ |  |

S = Spoofing, T = Tampering, R = Repudiation, I = Information disclosure,
D = Denial of service, E = Elevation of privilege.

Author: Krishita Sanjay Choksi.
