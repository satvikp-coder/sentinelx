# Threat Model

## Trust boundaries

| Element | Trust level |
|---|---|
| User task | Intent (trusted source of goals) |
| Page DOM / tool result / HTTP response / logs / retrieved text | UNTRUSTED data |
| LLM output | Proposal only |
| Deterministic policy gateway | Authority |
| Investigator prose | Hypothesis (must cite evidence; INFERRED) |
| Fixture | Disposable, resettable |
| Scanner | Only against verified-owned targets |
| Shield | Narrow, temporary rules only; never edits code |

## Policy order
infrastructure deny > explicit user restrictions > scenario permissions > human confirmation > safe allowlist > default deny.

## Abuse cases against Sentinel X itself

| Abuse case | Planned mitigation (not yet implemented) |
|---|---|
| SSRF through scan targets | Ownership-token verification; resolve and pin IPs; deny private/link-local/metadata ranges unless target is a verified localhost lab; no redirects off-target |
| Prompt injection of the investigator | Evidence treated as data; investigator output is a hypothesis validated by strict schema and citation checks; never grants permission |
| Scanner pointed at a site the user does not own | Ownership token enforced in code before any request; refuse otherwise; audit-logged |
| Shield rule too broad | Rules are narrow, scoped, expiring, human-reviewable, with a kill switch and a deny-by-default blast-radius check |
| Secret leakage to model or into the public repo | Redaction before storage and model calls; `.env` ignored; commit scanning; no secrets in fixtures |
| Tampered evidence | Hash-chained, append-only evidence records; verifier checks chain integrity |

All mitigations are PLANNED. This document is a design, not proof of working controls.
