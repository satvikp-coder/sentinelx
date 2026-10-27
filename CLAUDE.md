# Sentinel X - Agent Security Digital Twin (project rules)

Meta Global AI Developer Hackathon 2026, Indie track ("Push the Frontier"). Solo developer.
Building period Oct 27 - Nov 4, 2026. Final submission Nov 4, 9 PM ET (Nov 5, 7:30 AM IST).
We are scope-disciplined and evidence-driven. These rules persist across sessions.

## Product (one shared evidence and verification core)
- **Side 1 - Agent Guard:** isolated lab where a browser agent does a legitimate task while attacker-controlled synthetic content tries to redirect it. Instrument every proposed/executed action, deterministic policy gateway, tamper-evident evidence, paired unprotected/protected experiments, Meta open-weight models for bounded scenario generation and evidence-cited investigation, IncidentTwin containment branches (EVCS) in resettable fixtures, independent verifier.
- **Side 2 - Site Guard:** red-team scanner, fix engine and live reverse-proxy shield for sites the user owns. Safe non-destructive scans, fixes proposed and independently verified, human escalation, narrow temporary shield rules ("TEMPORARY SHIELD, NOT A FIX").
- Deliverables: Agent Guard SDK, Site Guard CLI, dashboard on real backend data, reproducible benchmark.

## Stack
Python 3.11+, FastAPI, Pydantic 2, SQLite (WAL) with versioned migrations, pytest, httpx, Playwright, React + Vite + TypeScript, provider-agnostic server-side model adapter (OpenAI-compatible Chat Completions). Modular monolith.

## Rules
1. Models propose; the protected gateway enforces; independent assertions score. An LLM never grants permission, scores itself, validates a patch, or picks URLs, payloads or shell commands.
2. Page DOM, tool results, HTTP responses, logs, retrieved text and ALL model output are untrusted data. Validate with strict Pydantic (`extra="forbid"`).
3. Synthetic data and lab hosts only (`*.lab.test` mapped to local services; lab services bind to 127.0.0.1). No public targets, real credentials, real transactions, or outbound internet from the lab.
4. Always label OBSERVED vs INFERRED vs SIMULATED (and PROPOSED, VERIFIED, APPLIED). ATTEMPTED forbidden action is not EXECUTED forbidden action. A generated patch is not a verified fix. A shield rule is not a fix. A recorded replay is not a re-executed branch.
5. No fabricated metrics, canned successes, or mock model text presented as live. A failed model call is an explicit `MODEL_UNAVAILABLE` state. Dashboards show backend-derived data only. Every reported result names the provider, model and mode (LIVE / RECORDED).
6. No secrets in git. `.env` ignored, `.env.example` placeholders only. Redact secrets before storing or sending anything to a model. The repo will be PUBLIC: check every commit for secrets.
7. Clean-room: do not import code from the old `satvikp-coder/sentinel` repo. Reference repos (Claude-Red, Strix, Cloudflare security-audit-skill, ECC, Tracecat, PentAGI) are inspiration or optional lab tools only, each logged in `docs/THIRD_PARTY_INVENTORY.md` before any use. No code copied from Tracecat (AGPL).
8. Authorization: scan and attack-test ONLY localhost labs or targets verified as owned by the user (ownership token enforced in code). Non-destructive by default.
9. Modular monolith. No Kubernetes, queues or extra infrastructure unless a tested requirement forces it.
10. Safe defaults: monitor-only mode, no auto-apply, human approval for anything that changes code, the shield never edits code live, a kill switch always exists.
11. `STATUS.md` records real commits, tests run with results, failures, blockers and the next step. A design is not proof that code exists or works. Never mark anything done without showing test output.
12. Hackathon honesty: everything in this repo is new work built during the hackathon; `docs/HACKATHON_SCOPE.md` lists what was built when and every third-party component.

## Policy order (deterministic gateway)
infrastructure deny > explicit user restrictions > scenario permissions > human confirmation > safe allowlist > default deny.

## Hackathon facts (from the official participant guide; do not invent others)
- Building period Oct 27 - Nov 4, 2026. New work only; demo may show only what was built during the hackathon. Repo must be public. Max team 4, solo allowed.
- Three-minute demo video required. Submission on Cerebral Valley by Nov 4, 9 PM ET; late submissions not considered.
- Must reasonably use Meta's models. Organizers confirmed Meta open-weight models (Muse Glimmer, Muse Spark Open) on own hardware or via partner inference are allowed; $10K Best Build on Meta Open Weight Models bonus prize.
- Model plan: NO credit card, NO paid Meta Model API. Default: Muse Glimmer 30B on NVIDIA's free hosted endpoint (`meta/muse-glimmer-30b`, base URL `https://integrate.api.nvidia.com/v1`). Optional: Muse Spark Open via a partner using credits. **All model API details are UNVERIFIED until Prompt 5 re-reads the docs. Do not guess parameters.**

## Working conventions
- Inspect before modifying; preserve user changes. Never commit, push, deploy or do destructive actions unless asked.
- Run relevant tests and report actual output; never claim a pass without running.
- Prompt 0 (setup) writes no feature code. Do not start the next prompt until the user says so.
- Cost-aware routing follows the user's global CLAUDE.md.
