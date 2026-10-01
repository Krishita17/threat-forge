# Scope, responsible use, and ethics

Author: Krishita Sanjay Choksi

## Purpose

ThreatForge is a **defensive security design-support tool**. Its deliverable is a
*draft threat model* — the same kind of artifact a security architect produces in
a design review — intended to improve a system's security posture. It is not an
attack tool, and it produces no exploits, payloads, or offensive tradecraft.

## Human-in-the-loop is mandatory

ThreatForge produces a **draft, never a verdict**. Every stage emits a reviewable
artifact (recovered model, inferred trust boundaries, candidate threats,
mitigations) that a competent human is expected to accept, edit, or reject. Each
threat in the register carries a `review_status` (`proposed` by default) precisely
so that review is an explicit, tracked step.

Treating an unreviewed ThreatForge output as a finished threat model is an
**explicit misuse** and is out of scope for what the tool claims to do.

## Honesty about accuracy

The tool can fail in both directions, and we report both:

- **False negatives** — it can miss real threats. Structure it cannot recover
  (undocumented components, dynamic wiring, business-logic flaws) will not be
  modelled, and the STRIDE knowledge base is finite.
- **False positives / noise** — it can propose threats that are not relevant to
  the specific system. The code analyzer is deliberately conservative (it assumes
  a control is absent unless it sees evidence of it), which surfaces more
  candidates for a human to prune. On the synthetic benchmark the grounded
  pipeline's noise rate is reported honestly alongside coverage, and it is higher
  on already-hardened systems where few genuine threats remain.

ThreatForge **reduces the cost of starting** a threat model. It does not guarantee
completeness and must never be treated as a security sign-off.

## Scope limits

- Analyze only code and diagrams that you own or are explicitly authorized to
  assess.
- This repository ships **synthetic systems** and a **permissively-licensed
  sample app** only. It contains no proprietary architecture and no client
  systems, and none should be committed to it.
- Control-framework content (STRIDE, OWASP ASVS, NIST SP 800-53, CWE) is included
  as reference data using genuine identifiers and titles with **paraphrased**
  requirement text; consult the official sources for authoritative wording.

## Responsible-use notice

A generated threat model informs human security decisions; it does not replace
professional security review. Use ThreatForge to get past the blank page faster,
then apply human judgment.
