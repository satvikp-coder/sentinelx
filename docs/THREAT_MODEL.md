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

Most mitigations in this table are still PLANNED (hash-chained evidence and secret redaction are implemented; see the Scenario A section below and STATUS.md). This document is a design, not proof of working controls.

## Scenario A lab: what is and is not covered (implemented 2026-10-27)

| Boundary / abuse case | Status |
|---|---|
| Hostile page text, hidden DOM text and tool-result text reach a gullible agent | SIMULATED: the scripted planner obeys imperative send/post/upload/cancel text; attacks reproduce in the unprotected arm (the ledger proves it) |
| Agent tries to leave the lab (real internet, IP literal, other port, `file:`) | Aborted by the sandbox boundary in BOTH arms; tested for navigations, raw HTTP and redirects |
| Redirect to an off-scope but in-lab host (orders to collector) | Followed in the unprotected arm (side effect observed); blocked per hop in the protected arm (`REDIRECT_BLOCKED`) |
| Agent or page reaches the ledger or admin endpoints | Admin needs token AND loopback; the ledger path is never given to the planner or adapter |
| Agent lies about what it did | The verifier ignores the answer for side effects (ledger only) |
| Synthetic secret leaking into evidence | Redacted on append (`synth_tok_` pattern); tested over every stored payload |
| Subresource exfiltration (a hostile page embeds an image pointing at the collector) | NOT covered: only action-level requests and redirect hops are policy-checked; the sandbox allows any `*.lab.test` host. Open gap |
| Signal wording coverage | Signals (hints) fire for the exfil wording, not for the cancel/upload wording; the blocks came from deterministic rules, not signals |
| `http_request` | The lab policy blocks it outright (HIGH_IMPACT_BLOCKED) and scenarios do not list it; per-method / per-endpoint HTTP policy is future work |
| Real model behaviour | NOT tested: nothing here is evidence about LLM agents |
