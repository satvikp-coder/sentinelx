# Sentinel X: submission draft requiring owner review

Sentinel X combines Agent Guard and Site Guard around one rule:
**Models propose; deterministic code and independent verification decide.**

Agent Guard checks proposed tool actions against scenario-specific policy before
execution and records evidence. Site Guard includes a lab-scoped scanner, a patch
proposal/verification workflow, and a temporary reverse-proxy Shield. The local
FastAPI backend and React dashboard expose these workflows.

## Demonstrated in the completion review

- Separate localhost API, proxy and synthetic upstream processes.
- Public proposal and exact-content/session-scoped approval.
- Real HTTP 403 enforcement without forwarding the blocked request upstream.
- Benign pass-through, monitor-mode separation, client scope, expiration/removal,
  restart discovery and durable hash-chain evidence.
- Chromium dashboard proposal, approval, activation and removal; all ten screens opened.
- SDK runtime tests with a local sidecar and a wrapped-tool execution counter.

Commands, exact test totals and remaining gates are recorded in
[tasks/CODEX_COMPLETION_AND_SUBMISSION.md](../tasks/CODEX_COMPLETION_AND_SUBMISSION.md).
Test totals are engineering verification, not attack-protection benchmark rates.
Do not reuse old evaluation numbers as new measurements.

## Model use and limitations

Provider adapters and an offline benchmark harness exist. This completion review
made no paid provider calls and ran no live Meta-model comparison. Do not claim a
model name, live result, measured improvement, or hackathon eligibility without
corresponding run provenance and organizer confirmation. The default scripted
agent must remain labeled SIMULATED. External scanner operation was not authorized.

The approval model is a shared local demo principal. The runtime database must be
private to trusted operator processes; a checksum is not writer authentication.
Shield is temporary mitigation, not a source-code fix or general injection defense.
Representative benign replay does not prove zero false positives for other apps.

## Owner release gates

Confirm current organizer requirements, model-use eligibility, deadline, license,
third-party attribution and source chronology. Review the actual CI run, Docker/PHP
coverage and submission assets. Repository visibility, video publication and final
submission remain owner actions. No release or submission was performed here.
