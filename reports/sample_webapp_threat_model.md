# Threat Model: Sample Web App

> **Draft for review - not a security sign-off.** ThreatForge produces a candidate STRIDE threat model from recovered structure. It can miss real threats and propose spurious ones. A competent human must review, edit, accept or reject every item below. Author: Krishita Sanjay Choksi.

## Summary

| Metric | Value |
| --- | --- |
| Components | 4 |
| Data flows | 3 |
| Trust boundaries | 3 |
| Threats identified | 14 |
| Critical / High | 7 |

## Data-Flow Diagram

![DFD](sample_webapp_dfd.svg)

## Trust Boundaries (inferred)

| Boundary | Crossing flows |
| --- | --- |
| Internet -> Application | 1 |
| Application -> Third-party | 1 |
| Application -> Data | 1 |

## Threats by STRIDE Category

| Category | Count |
| --- | --- |
| Spoofing | 2 |
| Tampering | 3 |
| Repudiation | 2 |
| Information disclosure | 3 |
| Denial of service | 2 |
| Elevation of privilege | 2 |

## Threat Register

| ID | Component | STRIDE | Threat | Boundary | Risk | Review |
| --- | --- | --- | --- | --- | --- | --- |
| TF-008 | End User | Spoofing | Unauthenticated external actor can impersonate a legitimate user | - | 16 (High) | proposed |
| TF-001 | Sample Web App Service | Spoofing | Process accepts requests without verifying caller identity | Internet -> Application | 16 (High) | proposed |
| TF-011 | SQLite Database | Information disclosure | Sensitive data at rest is not encrypted | - | 15 (High) | proposed |
| TF-014 | SQLite Database | Information disclosure | Sensitive data is exposed in transit | Application -> Data | 15 (High) | proposed |
| TF-006 | Sample Web App Service | Elevation of privilege | Missing or weak authorization enables privilege escalation | Internet -> Application | 15 (High) | proposed |
| TF-013 | SQLite Database | Tampering | Data in transit can be tampered with across a trust boundary | Application -> Data | 12 (High) | proposed |
| TF-002 | Sample Web App Service | Tampering | Untrusted input reaches the process without validation | Internet -> Application | 12 (High) | proposed |
| TF-007 | Sample Web App Service | Elevation of privilege | Internet-facing path can reach privileged/admin functionality | Internet -> Application | 10 (Medium) | proposed |
| TF-005 | Sample Web App Service | Denial of service | No rate limiting on an internet-facing process | Internet -> Application | 9 (Medium) | proposed |
| TF-003 | Sample Web App Service | Repudiation | Security-relevant actions are not auditable | Internet -> Application | 9 (Medium) | proposed |
| TF-009 | SQLite Database | Tampering | Stored data can be modified without detection | - | 8 (Medium) | proposed |
| TF-012 | SQLite Database | Denial of service | Unbounded growth or connection exhaustion in the store | - | 6 (Medium) | proposed |
| TF-010 | SQLite Database | Repudiation | Writes to the store are not attributable | - | 6 (Medium) | proposed |
| TF-004 | Sample Web App Service | Information disclosure | Verbose errors or responses leak internal detail | Internet -> Application | 6 (Medium) | proposed |

## Mitigations and Mapped Controls

| ID | Threat | Mapped controls | CWE | Recommended fix | Priority |
| --- | --- | --- | --- | --- | --- |
| TF-008 | Unauthenticated external actor can impersonate a legitimate user | ASVS-2.1.1 (Password security), NIST-IA-2 (Identification and Authentication (Organizational Users)), NIST-IA-5 (Authenticator Management) | CWE-287 | Require strong authentication for this actor (MFA where feasible), enforce password/credential policy, and rate-limit/lock out credential-stuffing attempts. | High |
| TF-001 | Process accepts requests without verifying caller identity | ASVS-2.1.1 (Password security), NIST-IA-2 (Identification and Authentication (Organizational Users)) | CWE-306 | Authenticate every request to this process; reject or challenge unauthenticated callers at the trust boundary. | High |
| TF-011 | Sensitive data at rest is not encrypted | ASVS-8.3.4 (Protect data at rest), NIST-SC-28 (Protection of Information at Rest) | CWE-311 | Encrypt sensitive data at rest, manage keys separately from data, and restrict decrypt access to least privilege. | High |
| TF-014 | Sensitive data is exposed in transit | ASVS-9.1.1 (Transport security), ASVS-8.3.1 (Sensitive data in requests), NIST-SC-8 (Transmission Confidentiality and Integrity) | CWE-319 | Encrypt the channel end-to-end; minimize sensitive fields in transit and avoid placing them in URLs or logs. | High |
| TF-006 | Missing or weak authorization enables privilege escalation | ASVS-4.1.1 (General access control design), ASVS-4.1.3 (Least-privilege access control), NIST-AC-3 (Access Enforcement), NIST-AC-6 (Least Privilege) | CWE-285 | Enforce server-side, deny-by-default authorization on every privileged action; apply least privilege and verify object-level access. | High |
| TF-013 | Data in transit can be tampered with across a trust boundary | ASVS-9.1.1 (Transport security), NIST-SC-8 (Transmission Confidentiality and Integrity) | CWE-319 | Encrypt and integrity-protect the channel (TLS 1.2+); reject plaintext transport for any boundary-crossing flow. | High |
| TF-002 | Untrusted input reaches the process without validation | ASVS-5.1.3 (Input validation), ASVS-5.3.4 (Injection prevention) | CWE-20 | Validate and canonicalize all input at the boundary; use parameterized queries and context-aware output encoding. | High |
| TF-007 | Internet-facing path can reach privileged/admin functionality | ASVS-4.1.1 (General access control design), NIST-AC-6 (Least Privilege) | CWE-269 | Segment admin functionality behind separate authentication and network controls; never expose privileged operations on the public path. | Medium |
| TF-005 | No rate limiting on an internet-facing process | ASVS-11.1.4 (Anti-automation / rate limiting), NIST-SC-5 (Denial-of-Service Protection) | CWE-770 | Apply rate limiting, request quotas, timeouts and resource caps; place the service behind an edge/DoS-protection layer. | Medium |
| TF-003 | Security-relevant actions are not auditable | ASVS-7.1.3 (Security event logging), NIST-AU-2 (Event Logging), NIST-AU-9 (Protection of Audit Information) | CWE-778 | Log security-relevant events with user identity, timestamp and outcome to an append-only, access-controlled store. | Medium |
| TF-009 | Stored data can be modified without detection | ASVS-1.9.2 (Data integrity in transit/storage), NIST-SI-7 (Software, Firmware, and Information Integrity) | CWE-345 | Apply write authorization, integrity checks (hashing/signing) and tamper-evident audit logging to the store. | Medium |
| TF-012 | Unbounded growth or connection exhaustion in the store | NIST-SC-5 (Denial-of-Service Protection) | CWE-770 | Enforce connection pooling limits, quotas and input size caps upstream; monitor capacity and set alerts. | Medium |
| TF-010 | Writes to the store are not attributable | ASVS-7.1.3 (Security event logging), NIST-AU-2 (Event Logging) | CWE-778 | Record attributable, append-only change history for the store and protect it from the accounts that can write data. | Medium |
| TF-004 | Verbose errors or responses leak internal detail | ASVS-7.4.1 (Safe error handling), ASVS-14.3.2 (Disable debug in production) | CWE-209 | Return generic error responses to clients; log detail server-side only; disable debug mode in production. | Medium |

## Threat Detail

### TF-008 - Unauthenticated external actor can impersonate a legitimate user

- **Component:** End User
- **STRIDE:** Spoofing
- **Rationale:** End User is an external entity whose requests are not strongly authenticated, so an attacker can impersonate it (e.g. credential stuffing, forged identity).
- **Mitigation:** Require strong authentication for this actor (MFA where feasible), enforce password/credential policy, and rate-limit/lock out credential-stuffing attempts.
- **Controls:** ASVS-2.1.1, NIST-IA-2, NIST-IA-5 | **CWE:** CWE-287
- **Risk:** likelihood 4 x impact 4 = 16 (High)
- **Source:** KB pattern `S-EXT-AUTHN`

### TF-001 - Process accepts requests without verifying caller identity

- **Component:** Sample Web App Service
- **STRIDE:** Spoofing
- **Trust boundary:** Internet -> Application
- **Rationale:** Sample Web App Service handles requests but does not authenticate its caller, allowing a spoofed client to act as a trusted one.
- **Mitigation:** Authenticate every request to this process; reject or challenge unauthenticated callers at the trust boundary.
- **Controls:** ASVS-2.1.1, NIST-IA-2 | **CWE:** CWE-306
- **Risk:** likelihood 4 x impact 4 = 16 (High)
- **Source:** KB pattern `S-PROC-WEAKAUTH`

### TF-011 - Sensitive data at rest is not encrypted

- **Component:** SQLite Database
- **STRIDE:** Information disclosure
- **Rationale:** SQLite Database stores sensitive data (credentials, pii) without encryption at rest, exposing it if the store is compromised.
- **Mitigation:** Encrypt sensitive data at rest, manage keys separately from data, and restrict decrypt access to least privilege.
- **Controls:** ASVS-8.3.4, NIST-SC-28 | **CWE:** CWE-311
- **Risk:** likelihood 3 x impact 5 = 15 (High)
- **Source:** KB pattern `I-STORE-ATREST`

### TF-014 - Sensitive data is exposed in transit

- **Component:** SQLite Database
- **STRIDE:** Information disclosure
- **Trust boundary:** Application -> Data
- **Rationale:** SQLite Database carries sensitive data (credentials, pii) across a boundary without encryption, so it can be intercepted.
- **Mitigation:** Encrypt the channel end-to-end; minimize sensitive fields in transit and avoid placing them in URLs or logs.
- **Controls:** ASVS-9.1.1, ASVS-8.3.1, NIST-SC-8 | **CWE:** CWE-319
- **Risk:** likelihood 3 x impact 5 = 15 (High)
- **Source:** KB pattern `I-FLOW-PLAINTEXT`

### TF-006 - Missing or weak authorization enables privilege escalation

- **Component:** Sample Web App Service
- **STRIDE:** Elevation of privilege
- **Trust boundary:** Internet -> Application
- **Rationale:** Sample Web App Service does not enforce authorization checks per action, so an authenticated low-privilege actor may perform privileged operations.
- **Mitigation:** Enforce server-side, deny-by-default authorization on every privileged action; apply least privilege and verify object-level access.
- **Controls:** ASVS-4.1.1, ASVS-4.1.3, NIST-AC-3, NIST-AC-6 | **CWE:** CWE-285
- **Risk:** likelihood 3 x impact 5 = 15 (High)
- **Source:** KB pattern `E-PROC-AUTHZ`

### TF-013 - Data in transit can be tampered with across a trust boundary

- **Component:** SQLite Database
- **STRIDE:** Tampering
- **Trust boundary:** Application -> Data
- **Rationale:** SQLite Database crosses a trust boundary without transport integrity (no TLS/encryption), so an on-path attacker can modify the data.
- **Mitigation:** Encrypt and integrity-protect the channel (TLS 1.2+); reject plaintext transport for any boundary-crossing flow.
- **Controls:** ASVS-9.1.1, NIST-SC-8 | **CWE:** CWE-319
- **Risk:** likelihood 3 x impact 4 = 12 (High)
- **Source:** KB pattern `T-FLOW-NOTLS`

### TF-002 - Untrusted input reaches the process without validation

- **Component:** Sample Web App Service
- **STRIDE:** Tampering
- **Trust boundary:** Internet -> Application
- **Rationale:** Sample Web App Service receives data from a less-trusted zone and may process it without validation, enabling injection or state corruption.
- **Mitigation:** Validate and canonicalize all input at the boundary; use parameterized queries and context-aware output encoding.
- **Controls:** ASVS-5.1.3, ASVS-5.3.4 | **CWE:** CWE-20
- **Risk:** likelihood 3 x impact 4 = 12 (High)
- **Source:** KB pattern `T-PROC-INPUT`

### TF-007 - Internet-facing path can reach privileged/admin functionality

- **Component:** Sample Web App Service
- **STRIDE:** Elevation of privilege
- **Trust boundary:** Internet -> Application
- **Rationale:** Sample Web App Service is internet-facing and sits on a path toward trusted/admin functions; a flaw here can be leveraged to reach privileged operations.
- **Mitigation:** Segment admin functionality behind separate authentication and network controls; never expose privileged operations on the public path.
- **Controls:** ASVS-4.1.1, NIST-AC-6 | **CWE:** CWE-269
- **Risk:** likelihood 2 x impact 5 = 10 (Medium)
- **Source:** KB pattern `E-PROC-ADMIN`

### TF-005 - No rate limiting on an internet-facing process

- **Component:** Sample Web App Service
- **STRIDE:** Denial of service
- **Trust boundary:** Internet -> Application
- **Rationale:** Sample Web App Service is internet-facing without rate limiting or quotas, so it can be overwhelmed by request floods.
- **Mitigation:** Apply rate limiting, request quotas, timeouts and resource caps; place the service behind an edge/DoS-protection layer.
- **Controls:** ASVS-11.1.4, NIST-SC-5 | **CWE:** CWE-770
- **Risk:** likelihood 3 x impact 3 = 9 (Medium)
- **Source:** KB pattern `D-PROC-RATELIMIT`

### TF-003 - Security-relevant actions are not auditable

- **Component:** Sample Web App Service
- **STRIDE:** Repudiation
- **Trust boundary:** Internet -> Application
- **Rationale:** Sample Web App Service performs security-relevant actions but does not emit tamper-resistant audit logs, so actors can deny having acted.
- **Mitigation:** Log security-relevant events with user identity, timestamp and outcome to an append-only, access-controlled store.
- **Controls:** ASVS-7.1.3, NIST-AU-2, NIST-AU-9 | **CWE:** CWE-778
- **Risk:** likelihood 3 x impact 3 = 9 (Medium)
- **Source:** KB pattern `R-PROC-LOG`

### TF-009 - Stored data can be modified without detection

- **Component:** SQLite Database
- **STRIDE:** Tampering
- **Rationale:** SQLite Database persists data without integrity controls or change auditing, so unauthorized modification may go unnoticed.
- **Mitigation:** Apply write authorization, integrity checks (hashing/signing) and tamper-evident audit logging to the store.
- **Controls:** ASVS-1.9.2, NIST-SI-7 | **CWE:** CWE-345
- **Risk:** likelihood 2 x impact 4 = 8 (Medium)
- **Source:** KB pattern `T-STORE-INTEGRITY`

### TF-012 - Unbounded growth or connection exhaustion in the store

- **Component:** SQLite Database
- **STRIDE:** Denial of service
- **Rationale:** SQLite Database can be driven to resource exhaustion (storage, connections) by unbounded writes from upstream processes.
- **Mitigation:** Enforce connection pooling limits, quotas and input size caps upstream; monitor capacity and set alerts.
- **Controls:** NIST-SC-5 | **CWE:** CWE-770
- **Risk:** likelihood 2 x impact 3 = 6 (Medium)
- **Source:** KB pattern `D-STORE-EXHAUST`

### TF-010 - Writes to the store are not attributable

- **Component:** SQLite Database
- **STRIDE:** Repudiation
- **Rationale:** SQLite Database does not record who changed what, so repudiation of data changes is possible.
- **Mitigation:** Record attributable, append-only change history for the store and protect it from the accounts that can write data.
- **Controls:** ASVS-7.1.3, NIST-AU-2 | **CWE:** CWE-778
- **Risk:** likelihood 2 x impact 3 = 6 (Medium)
- **Source:** KB pattern `R-STORE-LOG`

### TF-004 - Verbose errors or responses leak internal detail

- **Component:** Sample Web App Service
- **STRIDE:** Information disclosure
- **Trust boundary:** Internet -> Application
- **Rationale:** Sample Web App Service is internet-facing and may return verbose errors/stack traces that disclose internal structure to attackers.
- **Mitigation:** Return generic error responses to clients; log detail server-side only; disable debug mode in production.
- **Controls:** ASVS-7.4.1, ASVS-14.3.2 | **CWE:** CWE-209
- **Risk:** likelihood 3 x impact 2 = 6 (Medium)
- **Source:** KB pattern `I-PROC-ERRORS`
