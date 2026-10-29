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
| Redirect to an off-scope but in-lab host (orders to collector) | Followed in the unprotected arm (side effect observed); blocked per hop in the protected arm (`EGRESS_BLOCKED`, channel `redirect_hop`) |
| Agent or page reaches the ledger or admin endpoints | Admin needs token AND loopback; the ledger path is never given to the planner or adapter |
| Agent lies about what it did | The verifier ignores the answer for side effects (ledger only) |
| Synthetic secret leaking into evidence | Redacted on append (`synth_tok_` pattern); tested over every stored payload |
| Subresource exfiltration (a hostile page embeds an image pointing at the collector) | CLOSED for the protected arm in Prompt 4: every browser request is checked by the versioned page-request policy (see below). The unprotected arm still leaks, by design |
| Signal wording coverage | Signals (hints) fire for the exfil wording, not for the cancel/upload wording; the blocks came from deterministic rules, not signals |
| `http_request` | Allowed for reads (GET/HEAD) when the scenario lists it; POST/PUT/PATCH/DELETE are CONFIRM (high-impact). Per-endpoint HTTP policy is still future work |
| Real model behaviour | NOT tested: nothing here is evidence about LLM agents |

## Page-initiated egress: what is closed and what remains (Prompt 4)

Closed (tested in both arms, one test per vector): img, script, iframe, stylesheet, `link rel=prefetch`, fetch, XHR, CSS `url()`, `sendBeacon`, form POST, meta refresh, 302 redirect hops, WebSocket. In the unprotected arm each one reaches the ledger (or is closed as unsupported); in the protected arm each is aborted as `EGRESS_BLOCKED` and the ledger stays empty. A secret in a page request's URL or body is also blocked when the destination IS allowed (`SECRET_EGRESS`).

Still open, stated precisely:
- **Non-secret data to an allowed host.** The page-request policy allows any request to an allowed host. A hostile page can send non-secret information to an endpoint on that host (and an allowed host that stores attacker-controlled content is a covert channel). Only secrets are scanned.
- **Pattern-based secret detection.** Obfuscated secrets (split, base64, hex, character substitution) evade the detectors.
- **Transports that are not HTTP routes.** WebRTC, DNS prefetch and similar are not intercepted; the only backstops are the sandbox host-resolver rules (`*.lab.test` -> 127.0.0.1, everything else NXDOMAIN) and the fact that every lab host is the local lab server. Not exercised by any test.
- **Same-origin attacker-controlled state** (e.g. stored XSS on an allowed host) is out of scope of this prototype.
- **Policy coverage was authored together with the cases.** The case set shows how the controls behave on these 30 cases, not on unseen attacks.
- Response bodies, cookies and storage are not inspected; only requests are.


## Abuse case: Sentinel X's scanner pointed at a stranger's site (Part 2, implemented controls)
| Threat | Control (implemented and tested) |
|---|---|
| A user (or a prompt) registers a site they do not own | Non-lab targets are OFF by default; need `ALLOW_NON_LAB_TARGETS`, a token served at the site's exact origin (`/.well-known/sentinelx-verify.txt`), the owner's acknowledgement phrase, and expire after 24 h; only a hash of the token is stored |
| `lab=true` used to smuggle a real host | Registration rejects it unless every host is loopback or `*.lab.test` |
| Scope tricks: `http://good@evil/`, `good.evil`, other port/scheme, IP literals, IDN/dot tricks | Strict normalizer plus exact scheme/host/port match; any `@` in the authority is refused (USERINFO_IN_URL) |
| Redirect from an allowed site to an internal or foreign address | Every hop is re-checked against scope; off-scope hops are never requested |
| SSRF to private/metadata addresses (non-lab) | One resolution, all answers must be public, connection pinned to the checked IP (IPv4, IPv6, IPv4-mapped); metadata hosts blocked by name and address |
| DNS rebinding | The resolved address is pinned for the life of the scan; the resolver is called once per host |
| State-changing requests | GET/HEAD/OPTIONS only by default; writes only on lab targets, declared in the scan profile, with a reason and a synthetic account; operator-only switch |
| Runaway or noisy scan | Request budget (500), rate limit, per-host concurrency, wall-clock, body/response caps; each stop is explicit |
| Cannot stop a scan | Kill switch (flag or file) checked before every request |
| Scanner code bypasses the gate | A static test fails if scanner code imports httpx/requests/urllib.request/socket/etc. anywhere except `GuardedClient` |
| Secrets leak into evidence | URLs are redacted (secret-looking query values masked), only header NAMES and sizes are stored, no bodies |
| A model or scanned page changes the rules | Config and profile are frozen objects set by the operator; recorded in the evidence at scan start |

Still open: the ownership proof trusts whoever controls the origin at that moment; TLS certificate validation of non-lab hosts relies on the HTTP client defaults; the gate is only as complete as the code that uses `GuardedClient` (future scanner code must keep using it). Not exercised against the real internet: non-lab targets were tested only against local stub servers.

## Hard safety rules for the Site Guard scanner (Prompt 9, enforced and tested)
1. **Every request goes through `sentinelx.scanner.http.GuardedClient`.** No other HTTP, socket or subprocess use exists in `packages/scanner` (static AST test: `test_scanner_code_never_reaches_the_network_except_through_guardedclient`), and `GuardedClient` itself runs every request through the authorization gate (`sentinelx.scanner.authz`).
2. **Non-destructive by design.** Probes use harmless marker strings (`sx_mark_...` for reflected XSS; a single trailing quote and an ordinary value for SQL injection) and read-only observation. The only write the catalog ever performs is `weak_upload_validation`'s single inert, double-extension text file, uploaded as a declared, reasoned, lab-only step; it is cleaned up only by a lab reset, never by a delete through the app. `missing_rate_limit` never sends more than `HARD_CAP = 15` failed logins, for a NONEXISTENT synthetic username, regardless of what any profile or model says (`SiteScanProfile.login_burst` is itself bounded `<= 15`). No file-system or shell payloads, no exploit frameworks, no payload designed to extract real data; confirmation always relies on a harmless observable difference (an error signature, an unencoded marker, identical cross-persona content, a reachable path) that an ordinary user could also see.
3. **The scanner never reads ground truth.** It never imports or opens `labs/*/PLANTED.json` or any `*_reference` directory (static test: `test_scanner_never_imports_or_opens_planted_or_reference_paths`). Scoring against ground truth lives entirely in `sentinelx.evaluation.scan_scoring`, which runs only AFTER a scan, on its already-produced report.
4. **Model output can never add a request, a URL, a header or a payload.** The model (`sentinelx.scanner.model_assist`) may only (a) order/narrow the FIXED check-id catalog (an unknown id, or any other failure, falls back to the full default plan with a visible note) and (b) write a plain-language explanation of an ALREADY-INDEPENDENTLY-CONFIRMED finding, labelled `"MODEL-GENERATED"` and never read by anything that decides a finding's state. At most 2 model calls per scan.
5. **Every scan has a versioned profile.** `configs/scan/lab_default.yaml` (checks, request budget, rate limit, whether declared state-changing steps are permitted, personas); its SHA-256 (`SiteScanProfile.sha256`) is recorded in every report's provenance and in the `SCAN_CONFIG` evidence event.

## Hard spend guard for a paid model profile (Prompt 9 Part 0.6, enforced and tested)
A budgeted profile (currently `baseten_spark_open`; NVIDIA's free tier has no published price to guard) is checked BEFORE every call, never after: `sentinelx.model_clients.profiles.check_budget()` sums the real cumulative cost already recorded in `usage` and compares it to the configured hard cap. Reaching the cap returns the explicit `ModelCallStatus.BUDGET_EXHAUSTED` and refuses the call outright - never a retry, never a silent fallback to a cheaper profile mid-call (a fallback only happens at routing time, BEFORE any call is attempted, and is always labelled in the result). The dry-run batch estimator (`scripts/estimate_cost.py`) is intentionally MORE conservative than the real-time guard: it refuses a planned batch whose worst case would eat into a configured reserve below the hard cap, as a margin against its own estimate being wrong. Neither the guard nor the estimator is a substitute for checking the real bill on the Baseten dashboard.

