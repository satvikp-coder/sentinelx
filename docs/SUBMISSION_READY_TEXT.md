# Submission-ready text — owner review required

Copy the fields below into the actual event form after resolving the handoff
gates. Field lengths and exact required fields must be checked in the portal.

## Project title

Sentinel X

## Tagline

Test hostile AI-agent inputs and protect authorized local apps with deterministic
policy, independent verification and temporary, human-approved shields.

## Problem

AI agents encounter untrusted pages and tool results that can redirect their
actions. Meanwhile, developers of small applications need a practical way to
validate vulnerabilities and mitigate exposure without confusing an AI-generated
claim with proof. Logs, blocked attempts and generated patches alone do not tell
us whether an attack executed or whether a fix works.

## What we built

Sentinel X combines Agent Guard and Site Guard around one principle:
**Models propose; deterministic code and independent verification decide.**

Agent Guard checks proposed tool actions before execution, applies scenario and
session restrictions, records tamper-evident evidence and compares controlled
protected/unprotected experiments. Python and TypeScript SDKs expose the guard;
independent assertions distinguish attempted actions from executed outcomes.

Site Guard provides an authorization-gated local-lab scanner, evidence-backed
findings and a patch proposal/verification workflow. A generated patch is not
automatically accepted or deployed. The React dashboard and FastAPI backend expose
actual workflow state instead of fabricated success metrics.

Shield is a temporary reverse-proxy mitigation, not a source-code fix. The local
operator proposes a scoped rule, explicitly approves its exact content, and passes
a compiler/representative benign replay gate. The API and proxy share a private
SQLite runtime authority. Activation and required evidence are committed together;
TTL/removal stop enforcement and API restart restores rule-management visibility.
The real HTTP demo shows a blocked request never reaching the upstream, a benign
request forwarded, then removed-rule traffic passing again.

## Meta model use and provenance

Historical stored traces record NVIDIA-hosted `meta/muse-glimmer-30b` planning and
investigation. The 10-case, two-arm historical subset contains 20 runs, 16 valid
and 4 invalid, with model-unavailable outcomes retained. There is also a small
Baseten `meta-models/muse-spark-open-1026` usage record and model-profile attribution
in a historical fix report. These are previous recorded artifacts; this submission
preparation/demo makes no provider calls. The baseline scripted agent is explicitly
SIMULATED. A full 30-case live comparison and model-performance improvement are
not claimed. See `docs/SUBMISSION_MODEL_EVIDENCE.md` for evidence strength and gaps.

## Technical implementation and independent verification

Python/FastAPI, strict Pydantic schemas, SQLite/WAL evidence/runtime stores,
deterministic policy and verification, a real ASGI reverse proxy, React/Vite/
TypeScript dashboard, and Python/TypeScript SDKs. Approval decisions do not grant
a model authority to authorize tools or validate its own fixes. Hash chains detect
certain tampering; they do not authenticate a malicious database writer.

## Executed engineering checks

Release `d855c4ece913775306295a8fec54254e7c2181d1` passed Python and web jobs in
[Actions run 41845409978](https://github.com/satvikp-coder/sentinelx/actions/runs/41845409978):
**1,591 tests passed, 1 skipped**. Twelve Docker-dependent and 136 browser tests
executed successfully within that total. The skipped test needed live-model
credentials. These are engineering-test counts, not security effectiveness rates.

The completion review also exercised separate API/proxy/upstream processes,
public approvals, real HTTP blocking/upstream counters, benign forwarding,
expiry/removal, restarts and persistent evidence. An earlier real Node lab scan
used 122 requests, reported 12 findings and independently confirmed 10. Those
counts describe that run, not universal recall or precision. A historical clean
reference report contains a false-positive public-settings finding; do not present
it as a genuine vulnerability or hide it. The final-check report explains it.

## Limitations and responsible use

This is a local single-operator prototype using synthetic lab targets. Shared
demo authentication is not production multi-user authorization. Runtime storage
must be private to trusted operator processes. Representative replay does not
guarantee zero benign blocks. Shield is temporary mitigation. External scanners
remain disabled without separate approval. We do not claim universal prompt-
injection prevention, production deployment, a completed live benchmark or model
superiority. Model/provider availability and pricing require owner verification.

## Setup

From a clean clone with Python 3.11+ and Node 22:

```text
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
.venv\Scripts\python.exe -m pip install -e sdk/python
.venv\Scripts\python.exe examples/agent_guard_basic.py enforce
.venv\Scripts\python.exe scripts/demo_evidence_chain.py
```

No provider credentials are required for those demos. For the genuine public API +
proxy workflow, follow `docs/SUBMISSION_RECORDING_GUIDE.md`. Browser/Docker tests
need their stated prerequisites; do not silently count unexecuted tests as passed.

## Links and owner fields

- GitHub: https://github.com/satvikp-coder/sentinelx — currently PRIVATE; owner must resolve judge access and actual event visibility rules.
- Verified code SHA: `d855c4ece913775306295a8fec54254e7c2181d1`.
- Video: **[OWNER: INSERT ACCESSIBLE DEMO VIDEO URL AFTER RECORDING]**.
- Team/contributors: **[OWNER: CONFIRM REGISTERED TEAM AND NAMES]**.
- Proposed track/theme: Indie / Push the Frontier — owner confirms registration.
- License: **[OWNER DECISION REQUIRED; NO LICENSE SELECTED]**.
- AI coding assistance: OpenCode and Codex contributed to implementation, repair,
  testing and documentation; owner verifies permitted assistance and accurate attribution.
- Eligibility, source chronology and accepted rules: **[OWNER CONFIRMATION REQUIRED]**.

Do not paste bracketed placeholders into a final submission. Replace them only
with genuine owner-supplied information. No video, portal submission or receipt
has been created by this documentation task.
