# Sentinel X: three-minute submission demo

Release being demonstrated: `d855c4ece913775306295a8fec54254e7c2181d1`.
Audience: hackathon judges. Scope: a single trusted local operator, synthetic
traffic, no provider calls. Preparation, installation and long tests happen before
recording. This is a three-minute editorial plan, not a claim that the portal's
video-length rule was independently accessible. Confirm that rule with the owner.

Use [the recording guide](SUBMISSION_RECORDING_GUIDE.md) for exact setup, public
API requests, expected checks and cleanup. Never substitute a changed label for
observed enforcement. If a check fails, stop and record the failure; do not narrate
the planned result as an observation.

| Time | Screen / action | Narration |
|---|---|---|
| 0:00–0:15 | Title and one architecture sketch: proposed action → policy → tool; evidence → verifier | “Sentinel X helps developers test hostile inputs against AI agents and authorized local applications. Models propose; deterministic code and independent verification decide.” |
| 0:15–0:35 | Run the offline Agent Guard example in enforce mode; show the actual BLOCK and completed legitimate read | “This is a scripted synthetic agent, not a live model. A hostile page asks it to send a fake token. The SDK blocks the off-scope tool call while the legitimate read completes. ATTEMPTED is different from EXECUTED.” |
| 0:35–0:50 | Run the disposable evidence-chain demo; show clean verification and detected tampering | “The independent verifier checks stored evidence. This deliberate change to a disposable database is detected. Hash chains are tamper-evident; they do not authenticate a malicious database administrator.” |
| 0:50–1:10 | Show an actual lab scan report, target, timestamp, confirmed/candidate counts and request budget | “Site Guard scans authorized local labs and independently rechecks candidates. These are observed findings from this run, not a universal detection rate. A generated patch would still require verification and approval.” |
| 1:10–1:25 | Public proposal request; display returned PROPOSED; send matching traffic before activation | “Shield is temporary mitigation, not a fix. A proposal does not enforce anything.” |
| 1:25–1:45 | Public approval request followed by public activation request | “The trusted local operator approves this exact rule. The compiler and representative benign replay must pass before activation. Approval and durable activation evidence are part of the workflow.” |
| 1:45–2:05 | Actual proxy request: HTTP 403; compare upstream counter before/after | “The running proxy blocked this request. The upstream counter did not change, so this is enforcement, not just an ACTIVE badge.” |
| 2:05–2:20 | Actual `/health` request through proxy: HTTP 200 and upstream counter increment | “A non-matching legitimate request is forwarded. This does not prove zero false positives for other applications.” |
| 2:20–2:35 | Public remove request; repeat matching request: HTTP 200, upstream counter increments | “The operator removes the rule, and the request reaches the upstream again. Rules also have bounded lifetimes.” |
| 2:35–2:50 | Public durable Shield evidence endpoint; actual chain status and activation/removal records | “Evidence is persisted, not merely broadcast to a dashboard. The API and proxy share one private runtime database.” |
| 2:50–3:00 | Exact CI run plus limitations card | “This revision passed Python and web CI. Historical Meta-model traces exist; this demo makes no model calls. The system is a local prototype, not production multi-user security.” |

## Results that may be shown, with their provenance

- CI [41845409978](https://github.com/satvikp-coder/sentinelx/actions/runs/41845409978)
  at the release SHA: **1,591 passed, 1 skipped**; 12 Docker-dependent and 136
  browser tests executed successfully. These categories overlap the total.
- The CI live-provider test was skipped. Do not call it passed or a live benchmark.
- The earlier completion review's actual Node scan: 122 requests, 12 reported
  findings, 10 verifier-confirmed. This is historical captured evidence. If using
  a fresh scan, display its own numbers instead. Do not imply they must match.
- Separate-process enforcement, benign forwarding, expiry, removal, restarts,
  scope and mode tests are executable at
  `tests/integration/test_shield_public_processes.py`. Run them before recording;
  their full runtime is not part of the three-minute clip.
- Historical model evidence is classified in
  [SUBMISSION_MODEL_EVIDENCE.md](SUBMISSION_MODEL_EVIDENCE.md). A stored LIVE label
  is not a new invocation; a scripted 30-case replay is not a live 30-case benchmark.

## Recording discipline

Show actual terminals/API output at readable size. Cut installation/waiting time,
but disclose cuts and prerecorded evidence. Keep rule IDs consistent across takes.
Use the synthetic upstream, an external scratch directory and loopback listeners.
Do not show provider dashboards, credentials, unreviewed historical source excerpts,
or an actual credential file. Do not use real customer data.

## Do not claim

“Production ready,” “all prompt injection prevented,” “zero false positives,”
“guaranteed secure,” “live 30-case benchmark completed,” “edits outperform diff,”
or “hackathon eligibility confirmed.” Do not imply a video was recorded/published,
that judges can access a private repository, or that the owner selected a license.
