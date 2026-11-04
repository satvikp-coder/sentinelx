# Sentinel X completion and submission gates

Date: 2026-11-04. Starting main/origin: `e035f379b246a0d5dbcb7ae57ffc2ab642718052`.
Starting worker: `2e2d5a8d874958a8876e289233367ac64d3ccf98`.
This supersedes historical worker summaries and the earlier repair prompt.

## Repairs

- Durable SQLite rule authority; publication and required activation evidence share
  one transaction. Staging lifecycle rules are never served before commit.
- Process death or failed activation evidence leaves a proposal inert. Readers
  cannot observe an uncommitted activation. No compensating-write assumption.
- Durable, monotonic approval acceptance order, with exact session/content binding
  and a revocation recheck inside the publication transaction.
- Restart discovery recovers valid proposals and active/terminal rules. Operators
  can discover and remove existing enforcement after restarting only the API.
- Versioned runtime digest binds target, client scope, action, mode and expiry.
  Old runtime hashes fail closed; legacy rules require new proposal/approval.
- Global and per-rule monitor/recommend remain non-enforcing. A stale or corrupt
  durable row cannot fall back to a cached API ACTIVE projection.
- Compiler carries mode correctly; API TTL matches the compiler's 24-hour maximum.
  Client-scoped benign replay uses the scoped identity, including legitimate traffic.
- Request IDs are hashed. Request telemetry retains a fixed route vocabulary,
  masks unknown segments, drops query/fragment contents and normalizes methods.
  This does not promise detection of arbitrary secrets intentionally placed in
  trusted rule definitions; never place credentials in route matchers.
- SSE subscribes before replay and deduplicates by sequence; body middleware no
  longer breaks stream disconnects. Redaction occurs before event-buffer retention.
- Public authenticated `/api/v1/shield/evidence` exposes actual durable lifecycle
  records and chain verification, rather than treating an SSE buffer as evidence.
- Dashboard exposes proposal, explicit approval/activation, expiry/removal and
  durable evidence. Default rule mode remains monitor. SDK has real runtime tests.
- Missing Python subpackages are included in packaging; clean installation installs
  the Python SDK. The clean-install check uses a real local Git clone.

## Genuine execution evidence before final integration

Interpreter: `C:/Users/satvi/Desktop/sentinelx-ds/.venv/Scripts/python.exe`.
All pytest runs use a new external `--basetemp` and `-p no:cacheprovider`.
Review launcher blocks real credential-file access and redirects generated evidence
away from existing project evaluations. No providers or external targets are called.

- Initial new regressions: **6 failed, 1 passed** on the starting implementation.
- First full fast suite after repairs: **1423 passed, 150 deselected, exit 0**.
- Subsequent unit run: **1181 passed, exit 0**; later added regressions run separately.
- New recovery/atomicity/redaction regressions and separate-process E2E are in
  `tests/unit/test_shield_completion_regressions.py` and
  `tests/integration/test_shield_public_processes.py`.
- Expanded separate-process group: **17 passed, exit 0**, including real natural TTL,
  expiry/removal, kill switch, upstream counters, client isolation, SSE and restarts.
- SDK: `npm test --workspace sdk/typescript`: **6 passed, 0 failed, exit 0**.
- `npm run build`: TypeScript SDK and React production build passed.
- Chromium: all ten screens opened, Shield proposal/approval/activation/removal
  completed, **0 page errors**. This is not exhaustive browser coverage of all screens.
- Final-run dry-run: exit 0; no stage executed. Estimates are not billed spend.
- Wheel build passed; agent_test, external_scanner and scanner.checks packages present.
- Project Ruff and `git diff --check`: exit 0.
- Initial clean-copy smoke failed because it lacked Git metadata, not because the
  secret assertion found a leak. The replacement is a genuine local-clone gate.
- Genuine clean clone, new venv, core smoke tests and CLI import subsequently
  passed (exit 0). This smoke mode does not replace the full fast suite.
- Final worker full fast suite: **1429 passed, 150 deselected, exit 0**,
  581.30 seconds. Separate clean-clone smoke: **234 passed, exit 0**.
- Project-wide Ruff, SDK/runtime tests, dashboard build/Chromium workflow and
  forbidden-path audit passed. npm audit reported **0 vulnerabilities**.
- Post-merge main: **1429 passed, 150 deselected, exit 0**, 541.62 seconds.
  The first attempt had 2 failures caused by the reviewer's network guard blocking
  the machine's own lab-binding probes; those 2 tests passed after correcting only
  that external guard, followed by the complete successful rerun. No product test
  was weakened and no application change was needed for that retry.
- Completed the missing scanner dashboard start/status/cancel/findings controls.
  Chromium exercised the actual Node application using a disposable database:
  scan COMPLETED with **12 reported findings** rendered. This is a finding count,
  not a recall/accuracy measurement. The lab must already be running.
- Compiled SDK against the actual main API: **2 authorized tool calls executed,
  0 external tool calls executed**; default execution arguments matched policy.

Final premerge/postmerge test summaries, exact integrated SHA and remote/CI status
must be checked in the final reviewer output/workflow; no earlier count is a
substitute for execution against the final revision.

## Reproduce the gates

```powershell
python -m ruff check .
python -m pytest -m "not slow" --basetemp="$env:TEMP/sentinelx-NEW-UNIQUE-ROOT" -p no:cacheprovider
python -m pytest tests/integration/test_shield_public_processes.py --basetemp="$env:TEMP/sentinelx-ANOTHER-NEW-ROOT" -p no:cacheprovider
npm run build
npm test --workspace sdk/typescript
python scripts/fresh_clone_check.py
git diff --check
```

Use the actual reviewed interpreter and replace both temp names each run. Do not
run two suites using the fixed Node lab ports simultaneously. The clean-clone gate
requires committed source and creates a disposable virtual environment; it does
not copy working-tree credentials. Run the final-run dry-run with `--evaluations`
and `--manifest-out` pointing outside existing evaluation evidence.

## Supported demo deployment and migration

Use **one local API control-plane worker** and one or more loopback-bound proxy
readers. All must share the same private `SHIELD_RUNTIME_DB` and configured
`SHIELD_UPSTREAM`. The writer's filesystem access is authority; plain content
hashes detect corruption and are not authentication against a malicious DB writer.
Keep the directory private to the trusted operator. Do not expose proxy control
statistics or the shared-demo-token API publicly.

General API sessions and SSE replay remain process-local: restart invalidates
unbound sessions and requires a new approval session; it must not fabricate
permissions. Durable Shield rules remain discoverable/removable. Runtime v1 hashes
are deliberately rejected; repropose/reapprove instead of automatically upgrading
old enforcement. Unreadable runtime authority follows documented fail-open proxy
semantics and does not claim continued protection. Monitor is the default.

Benign replay is representative local-app coverage, not proof of zero collateral
blocks for arbitrary apps. Validate the intended app's routes before using rules.
Rules are temporary mitigation, not source-code fixes or universal injection defense.

## Submission and owner-only gates

- Docker/PHP: local daemon unavailable; do not claim fresh Docker coverage here.
- Live Meta-model benchmark: NOT RUN; no credentials accessed or paid calls made.
- External scanners: NOT RUN; remain disabled without separate approval.
- CI workflow exists; require the actual result for the pushed SHA, not push success.
- History scanner reports candidates without printing values. Generic base64 hits
  include dependency integrity hashes and synthetic fixtures; exit 1 is REVIEW
  REQUIRED, not proof of a genuine leak. Credential files are never opened.
  Do not claim historic credential rotation without owner evidence.
- License, organizer rules/eligibility/deadline, attribution and source chronology:
  owner must confirm. Live model use must be supported by run provenance.
- Repository visibility, video recording/publication and hackathon submission are
  owner actions. None are performed by this task. No winning outcome is guaranteed.

## OpenCode follow-up method

Do not restart features or weaken guards to improve a ledger. For any failing gate:
reproduce with a disposable fixture; add a regression exercising production logic;
fix the smallest confirmed root cause; rerun affected tests, full fast suite, builds,
real separate-process workflow and the clean-clone gate. Preserve all historical
evaluation evidence, source provenance and forbidden security paths. Report actual
exit codes and counts. Never manufacture a live/model/CI success or ACTIVE state.
