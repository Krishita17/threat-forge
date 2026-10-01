# Sample web app (ThreatForge input fixture)

A tiny, deliberately-imperfect Flask service used as a **sample input** for
ThreatForge's code analyzer. It has:

- a public HTTP API (`/login`, `/profile/<id>`, `/pay`),
- a SQLite data store (`users.db`),
- an outbound call to a third-party payment provider.

It omits some controls on purpose (no rate limiting, no per-object authorization
on `/profile`) so the generated threat model has realistic findings to review.

This fixture is permissively licensed along with the rest of the repository and
is not intended to be deployed. Author: Krishita Sanjay Choksi.
