# CURRENT REQUIRED REPAIR — independent recheck of 2e2d5a8

Read this update FIRST. The earlier prompt below is preserved as historical context. Use the current observations here when an earlier reproduction has improved.

Current reviewed worker:2e2d5a8d874958a8876e289233367ac64d3ccf98.
Main/origin/main:e035f379b246a0d5dbcb7ae57ffc2ab642718052.
Actual ahead/behind:21/0, not16/0. The only existing untracked file is this reviewer-requested prompt; preserve it. No application source changes, merge or push were made by the reviewer.

Current evidence directory:
C:\Users\satvi\AppData\Local\Temp\sentinelx-final-recheck-3911e0f1e7554981a529de21b5b8fde1
Read REVIEW.md, separate-process-results.json, root-causes.json and sdk-sse-digest.json. Reuse the disposable scripts after inspecting their isolation/fault hooks. The normal E2E uses public HTTP and actual API/proxy subprocesses without private approval injection or mocked matching.

## Current verdict: FAIL — focused tests are green but safety failures remain

Fresh verification:499focused tests passed,0failed/errors,exit0; project Ruff and branch diff check exit0. SDK compile/runtime passed. Full fast suite was NOT rerun for this commit after confirmed blockers. The previous1411passed measurement belongs to ef4b982 and must not be represented as fresh2e2d5a8 execution.

### P1: restart reconciliation still never succeeds
Location:apps/api/routes.py:_reconcile_runtime_to_api(), around319–355.
Root cause:it executes `with store.lock`, but store.lock is asyncio.Lock. Actual TypeError:'Lock' object does not support the context manager protocol. list_shield_rules catches and hides the exception.
Public actual-process result:after API-only restart, GET rules200[] while the proxy still enforces. Removal by a known old rule ID now works200 and stops traffic—retain that improvement. Discovery/recovery is still broken.
Method:use the correct asynchronous locking contract and await reconciliation, or choose an appropriately thread-safe projection strategy throughout. Do not merely suppress this failure. Load trusted durable rule data; report unavailable recovery rather than an apparently authoritative empty list. Preserve evidence/ownership, modes and immutable revisions.
Test:activate via public endpoints, restart API, list and identify existing enforced rule, remove via public endpoint, verify actual upstream delivery. No private store seeding.

### P1: sequence ordering was added to the wrong approval record
Locations:submit_approval(), _record_approval(), _next_approval_seq(), approve_shield_rule().
Root cause:submit_approval appends records WITHOUTseq into _SESSION_STATE[sid]['approvals']; activation reads that list. seq exists only in the separate _APPROVALS record. Both authoritative candidates still use defaultseq0.
Confirmed root-causes.json:authoritative_approval_records_have_sequence=[false,false];parallel_global_record_has_sequence=true.
Controlled-time public approve then revoke still activates200ACTIVE and returns403 through the real proxy.
Method:assign a trusted monotonic acceptance sequence to the actual authoritative record under the correct lock/transaction. Keep strict ApprovalRecord validation and SessionContext compatibility; do not blindly add forbidden extra fields. Prefer sequence ordering independent of wall-clock changes; persist ordering needed for restart. Keep exact session/content binding.
Test:equal timestamps, backward clock, duplicate/replayed decisions, concurrent revoke/activation and restart. The later accepted revoke must win.

### P1: permanent rollback failure still leaves enforcement active
Location:activation compensation around2002–2033.
Three retries do not fix a permanently failed status write. Current response still says rolled back even when shared statusACTIVE and actual traffic403. The private runtime_reconciliation_failed marker is not an exposed durable operator recovery state.
Method:retain a truthful authoritative outcome, durable reconciliation task and supported operator management. A local cache deactivation is not shared data-plane rollback. If confirmation fails, do not claim it succeeded or projectPROPOSED as if no enforcement exists. Preserve required evidence and scope.
Test:combined evidence+rollback failure, sustained real SQLite contention, partial runtime commit and recovery after failures clear. Assert response wording/status, API view, shared row and actual traffic together.
Improvement to retain:busy/failed removal now returns503 rather than false200/stopped=true. Do not regress it. Verify already-terminal/idempotent removal truthfully rather than relying on a simpleAND of operation return values.

### P1: crash publication is still not crash-safe
Real API process terminated after sharedACTIVE commit and before evidence/response. ClientReadError; proxy403; restart list remains empty. Known-ID removal now succeeds and stops traffic, but a restarted operator still cannot discover the interrupted rule.
Method:implement a documented durable transition/publication/reconciliation protocol, not additional exception catches. Test process death at each deterministic boundary and recovery with actual HTTP. Do not claim atomically published activation evidence across two SQLite files without an actual protocol.

### P1/P2: the mode enum is not propagated into runtime rules
A public mode=monitor proposal creates an internal ShieldRule with mode=enforce. API creation and activation omit mode, so the new model's enforce default applies. Public monitor-mode rule still blocks403 under an enforce proxy.
Method:carry the intended mode through compiler, API creation, activation reconstruction, runtime storage, recovery and response. Keep global monitor/recommend non-enforcing. Define safe compatible handling of old rows, rather than relying on a default that silently upgrades behavior.
Also canonical_rule_hash does NOT change when ShieldRule.mode changes. Include every supported enforcement field in the canonical runtime hash and version/migrate the contract safely. A plain hash is still not writer authentication.
Test:public monitor/recommend/enforce rules across publication and both process restarts; changing mode invalidates approval/hash as appropriate; legacy rows have documented safe behavior. Use actual upstream counters.

### P2: sensitive metadata is still retained
No change was made to proxy log redaction or runtime metadata sanitization in2e2d5a8. Actual credential-shaped X-Request-ID remains in /__shield/stats; recognized sensitive intent is masked in API output but stored raw in runtime payload reason after legitimate public activation.
Method:structured allowlisted/hashing/redaction of ALL retained metadata and exports, preserving exact matcher semantics. Do not patch just the example marker or only path. Check response, stats, runtimeDB, evidence, logs, SSE and report sinks with synthetic markers; print booleans, never marker values.

### Digest improvement and remaining scope
Expiry changes now invalidate the approval digest:verified. Retain this fix. Configured target/client namespace still is not bound by the helper; do not claim multi-user or cross-target authorization from a shared demo Bearer and constant shield-api target. Define the supported local-demo scope honestly and test any added target/client binding.

### Coverage and handoff correction
No tests were added/changed in2e2d5a8. Existing green tests therefore cannot prove these new repairs. The handoff names test_shield_approve_modified_rule_invalidates_approval, which does not exist under that name; the actual existing case is test_e2e_modified_rule_invalidates_approval.
Commit meaningful regression tests for each current failure before fixing it, capture the pre-fix failure, then prove the post-fix behavior.

The supplemental SSE diagnostic received200 and3data records without correlating the expected Shield event. Treat this as an unverified acceptance condition, not as a proven clean stream or a diagnosed new vulnerability. A real SSE test must first receive the exact event/rule ID before checking redaction/reconnect.

## Completion contract
Implement the repairs above first, then follow the release/test/human-action gates in the original prompt below. Do not claim final submission readiness from499focused passes or a historical full-suite count. Finish locally feasible work, record remaining owner/provider/Docker/CI actions honestly, make focused local commits, and stop for independent review.

NO MERGE. NO PUSH. NO DEPLOY. NO REAL PROVIDER CALLS. NO REAL .ENV ACCESS.

---
# Preserved earlier repair prompt and acceptance matrix
# OpenCode repair prompt — final Shield recovery and submission gates

Prepared by independent review on 2026-11-04. This file authorizes no integration or publication.

## Role and outcome
You are the implementation engineer. Repair the confirmed failures below, preserve the verified behavior, complete locally feasible release checks, and produce an honest handoff for independent review. Do not stop at documentation or existing green tests.

Worker: C:\Users\satvi\Desktop\sentinelx-ds, branch work/ds.
Reviewed HEAD: ef4b982814a8f9cd743e07183a048c211cf2e360.
Main/origin/main: e035f379b246a0d5dbcb7ae57ffc2ab642718052.
At review: worker20ahead0behind; both worktrees were clean before this new prompt was added.

Read applicable instructions, this entire file, and the independent artifacts:
C:\Users\satvi\AppData\Local\Temp\sentinelx-recovery-audit-5fb8423db8ec4c72afcee58c84c4930a

Useful files there:
- separate_process_e2e.py and FINAL separate-process-results.json
- review_api.py and review_proxy.py (disposable evidence/config/fault wrappers)
- runtime_tamper.py and runtime-tamper.json
- sdk_sse_digest.py and sdk-sse-digest.json
- full.log, full.xml, full.exit
- node-repeat.log, node-repeat.xml, node-repeat.exit
- SHIELD_RECOVERY_REVIEW.md (written by the independent reviewer)

Do not use initial-separate-process-results.json as final crash evidence: its first crash setup had an old-session fixture reference; the corrected final reproduction observed the commit, killed only its own API process, and reproduced orphaned enforcement.

## Boundaries
- Implement and test on work/ds; make focused local commits after checks pass.
- NO merge, push, reset, rebase, history rewrite, production deployment, package publication, repository visibility change or hackathon submission.
- Never read/display/copy real .env files or credentials.
- No real provider calls, model spending or external-site scans.
- Use synthetic loopback services and disposable databases/processes only.
- Do not kill unrelated processes or delete repository lab data.
- Preserve policy gateway order, approvals, ownership, evidence redaction, kill switches, limits and safe monitor defaults.
- Do not modify protected policy/scanner authorization files, planted truth/reference labs or immutable evaluation manifests.
- Preserve historical measurements. Do not turn old results into new evidence.
- This prompt file is reviewer-authored input; preserve it or explicitly identify its inclusion in your handoff. Do not treat it as an unexplained user change to discard.

## Fresh independent evidence — what already works
- Full fast pytest:1411passed,150deselected,0failed/errors/skips,exit0,540.09seconds.
- Repeat Node lab/scanner subset:28passed,12deselected,exit0,335.47seconds.
- Project Ruff, SDK compilation, frontend typecheck and Vite build:exit0.
- Actual SDK wrapper against a real local API preserves checked arguments and blocks the tested external URL without executing it.
- Fully separate API and proxy Uvicorn processes plus a real upstream: proposal200, approval200, activation200ACTIVE, matching403 with unchanged upstream counter, benign200 with upstream increment.
- Normal manual removal/expiry stop shared enforcement; proxy restart recovers ACTIVE rows and keeps removed rows inactive.
- Natural TTL stops enforcement without a maintenance call; global monitor/recommend do not block, enforce does.
- Ordinary evidence/upsert failure compensation returns503 and stops enforcement when rollback succeeds.
- Missing approval, wrong-session lookup, normal approve-then-revoke, over24h approval age, unauthenticated caller and benign-matching rule are denied in tested cases.

These successes do NOT make the remaining failures acceptable.

## P1-01 — API restart loses visibility and control of enforced rules
Location: apps/api/routes.py, in-memory store.shield_rules/session/approval handling and public list/remove/expire routes; packages/shield/runtime.py.

Confirmed public-process reproduction:
1. Start separate API/proxy processes with the same disposable SHIELD_RUNTIME_DB.
2. Propose/approve/activate a rule through public authenticated HTTP.
3. Matching request403; upstream counter unchanged.
4. Restart only the API process.
5. Rule list200 but empty; detail/status unavailable (405 in tested route).
6. Authorized DELETE old rule404.
7. Proxy still403; runtime rowACTIVE.

Impact: an operator loses normal control of active enforcement after a routine restart.

Method:
- Define one durable authority for rules and lifecycle state.
- Persist enough trusted metadata to reconstruct public records and authorized management after restart.
- List/status/removal/expiry must resolve durable rules, not depend solely on process memory.
- Preserve native runtime/evidence identifiers and ownership bindings.
- Rehydrate only trusted persisted authorization; do not fabricate generic scenarios, sessions or default permissions.
- Explicitly support one API writer process if that is the chosen model; document unsupported deployment shapes.
- Distinguish configured/installed/enforcing/reconciliation-pending status accurately.

Regression:
Actual API+proxy subprocesses, public workflow, restart API, list old rule, remove old rule, observe actual HTTP200 and upstream counter increment. Restart again and prove removed rule stays removed. Restart proxy and prove only valid unexpired ACTIVE rules recover.

## P1-02 — rollback failure and SQLite contention produce false safety claims
Locations: apps/api/routes.py activation compensation around1911–1925; remove/expire around1672–1725.

Confirmed failure A:
- Inject activation-evidence append failure AND runtime set_status rollback failure.
- API503 explicitly says installation was rolled back.
- Runtime row remainsACTIVE; proxy still403.
- Subsequent remove returns200 and runtime_enforcement_stopped=true while the shared rule still enforces.

Confirmed failure B (actual SQLite resource, no fake matching):
- Hold BEGIN IMMEDIATE on disposable runtime DB after legitimate activation.
- Public DELETE waits for busy timeout then returns200/REMOVED/stopped=true.
- Shared row remainsACTIVE; separate proxy still403.

Root cause:
Rollback errors are swallowed. Local removal success is ORed with shared-store success, even though separate readers continue enforcing the shared ACTIVE row. API state is updated before authoritative removal is confirmed.

Method:
- Treat shared-state transition failure as unresolved enforcement, never successful removal/rollback.
- Return a truthful failure/degraded state with a durable reconciliation/operator path.
- Do not claim runtime_enforcement_stopped from local-cache success alone.
- Handle already-terminal rows idempotently by reading authoritative state.
- Keep authoritative/API/local state consistent across remove, expire, activate and compensate.
- Bound SQLite busy handling; avoid silently freezing the ASGI loop for unbounded waits.
- Preserve real evidence of attempted/failed/confirmed transitions.

Regressions:
Single and combined evidence/runtime/rollback failures; real SQLite lock; repeated removal/expiry; fault recovery followed by authorized cleanup; verify API response, durable row, actual403/200 and upstream counts at every stage.

## P1-03 — crash after runtime commit creates unmanageable orphan enforcement
Locations: activation order in apps/api/routes.py; shared runtime persistence; restart recovery.

Confirmed reproduction using only public approval and an explicit post-commit pause hook:
- Real upsert commitsACTIVE.
- Kill only the disposable API process before evidence/API completion.
- Client gets ReadError; proxy403 and runtimeACTIVE.
- Restart API: list empty, removal404, proxy still403.

Method:
- Define a crash-safe publication/transaction protocol.
- A proxy must not enforce an uncommitted/unsupported activation outcome.
- Use an appropriate durable state machine, transaction/outbox, activation receipt or recoverable pending state. Choose the smallest design that meets the invariant; document its guarantees.
- Make interrupted transitions discoverable and resolvable by the restarted control plane.
- Do not promise atomicity across separate SQLite databases merely because WAL is enabled.
- Do not append fabricated successful activation evidence before enforcement exists.
- Do not suppress the final evidence write to hide the failure.

Regression:
Terminate the API at deterministic boundaries: before install, after runtime commit, before evidence, after evidence and before response. Restart; reconcile; verify real traffic, rules, approval linkage and evidence. Retain raw observed statuses, not hardcoded expected outcomes.

## P1-04 — equal timestamps let an older approval defeat revocation
Location: apps/api/routes.py around1804, latest=max(candidates,key=timestamp).

Confirmed controlled-time public reproduction:
- Freeze server approval timestamps to one valid instant.
- POST approve, then POST revoke, using public endpoints.
- Unfreeze time; activate.
- API200ACTIVE and actual403 enforcement: max() selected the first record at the tied timestamp.

Method:
- Define latest by trusted acceptance order, preferably a durable monotonic sequence/revision.
- Do not depend on wall-clock timestamps alone for revocation precedence.
- Keep timestamps for audit/age checks; define safe handling of clock rollback/future timestamps.
- Serialize approval/revocation selection with activation commit so a newer accepted revocation cannot be bypassed.
- Never restore cross-session searching or prefix matching.

Regressions:
Identical timestamps; backward clock step; approve/revoke ordering; repeated revoke; concurrent approval/revocation; stale approval replay; restart ordering; normal authorized approval. All through public workflow where possible; time control must not fabricate private approval records.

## P2-05 — sensitive strings still reach proxy stats and runtime metadata
Locations: packages/shield/proxy.py:_log()/stats(); packages/shield/runtime.py:upsert(); API ShieldRule construction.

Confirmed:
- Synthetic credential-shaped X-Request-ID is retained in proxy.request_log and exposed by /__shield/stats.
- A recognized credential-shaped intent is masked in the public rule response, but after legitimate activation it appears raw in the runtime DB payload reason field.
- No real credential was used. This is not a claim of theft of a server-side key.

Method:
- Redact or hash sensitive correlation identifiers before retaining/exporting them.
- Apply structured allowlists/redaction to ALL retained metadata, not only path.
- Sanitize non-enforcement metadata before runtime persistence. Preserve exact trusted matcher semantics; do not silently change what a rule matches by blanket-redacting its scope.
- Validate intent against its actual supported taxonomy where appropriate.
- Avoid copying arbitrary request/header/source values into safe-looking fields.
- Do not add a regex that only recognizes the review marker.

Regressions:
Recognizable key-shaped and arbitrary synthetic sensitive values in request ID/header/path/query/intent/nested fields/error metadata. Check API, stats/logs, runtime DB, evidence, SSE and report/export sinks. Never print marker values.

## P2-06 — approval digest does not bind all enforcement content
Location: apps/api/routes.py:_shield_rule_digest().

Independent function checks:
- Route change changes digest:yes.
- TTL/expires_at change changes digest:no.
- Target field change changes digest:no.

This is a content-binding gap; no public rule-update exploit was claimed because no such update route exists. Current API is a single shared demo Bearer principal and one configured upstream, not multi-user production authorization.

Method:
- Define a versioned canonical approval subject over every supported enforcement-relevant field: identity, target/upstream namespace, matcher/client scope, action, mode and TTL/expiry.
- Bind proposals, approval, gate, runtime row and evidence to the same immutable revision.
- Require reapproval after any enforcement-relevant modification.
- Preserve exact session lookup, trusted principal semantics and24h age bound.
- Clearly separate display-only reviewer text from authenticated identity.
- Explicitly scope runtime DBs/readers to their intended target; do not claim cross-target isolation from a constant shield-api target ID.

Regression:
Modify each supported enforcement field after approval and require denial/new approval. Test wrong target/namespace, wrong session, wrong rule and wrong digest. Do not fabricate generic authorization fallback for recovered rules.

## P2-07 — mode/client and streaming claims need precise contracts
Observed:
- Global monitor/recommend200; global enforce403:verified.
- A rule submitted with mode=monitor still blocks under an enforce proxy.
- API global-route rules have client=None; both synthetic clients are blocked. A client-scoped proposal is not currently expressible through the public schema.
- A separate SSE diagnostic got200 and three data events, but did not correlate the expected Shield proposal event. No marker in an uncorrelated stream is NOT proof of redaction. Treat this as unverified until a targeted test explains it; do not call it a confirmed new SSE defect from this observation alone.

Method:
- Make per-rule and global mode semantics explicit and enforce the advertised API contract.
- Expose supported scope selectors or honestly label global rules; do not claim unrelated-client isolation without an actual scoped test.
- For SSE tests, first require receipt of the exact rule/event, then assert redaction, ordering and reconnection.
- Test real API and proxy subprocesses, not only TestClient/direct ASGI calls.

## Runtime database authenticity — required deployment condition
A reviewer inserted an unapproved ACTIVE row into a disposable DB with a recomputed plain hash. The real proxy blocked403. Tampering without updating the hash forwarded200; recomputing the hash blocked403 again.

This requires filesystem write access. No remote/API exploit was demonstrated. The implementation explicitly treats DB write access as control-plane authority. A plain hash proves consistency, not authorized authorship.

Required method:
- Keep that trust boundary honest.
- Use a private configured runtime directory and verify/document supported permissions for the local demo.
- Do not expose the DB as a download or accept its path from untrusted request data.
- If untrusted writers must be supported, add genuine authenticated authorization/receipts rather than another plain checksum.
- Test malformed payload, wrong hash, mismatched identity/status, missing DB, unreadable DB and wrong configured path. Document fail-open behavior and stale-state handling.

## Regression-first implementation sequence
1. Verify actual Git state and preserve this reviewer-created prompt.
2. Read/run the independent scripts in disposable locations. Inspect test wrappers; use normal public paths for positive E2E.
3. Add committed failing regressions for P1-01 through P1-04 and P2-05 before fixes. Capture actual failures.
4. Implement durable authority/recovery and transaction semantics together.
5. Fix approval ordering/content binding and redaction.
6. Add mode/scope and actual SSE correlation tests.
7. Run focused tests, then full matrix below.
8. Make focused local commits; record what each fixes.
9. Stop for independent review. Do not integrate automatically.

Fault hooks belong only to disposable test processes/fixtures. Do not add public debug endpoints or production bypass flags. Do not mock matching or activation in the positive HTTP acceptance test. Failure-injection tests must be clearly distinguished.

## Mandatory real acceptance workflow
Three actual loopback services: API Uvicorn process, standalone proxy Uvicorn process and synthetic upstream HTTP server. Use free ports and disposable DBs. Use synthetic private demo authentication.

Propose200PROPOSED -> no block -> public approval200 -> activate200ACTIVE -> matching403 with upstream counter unchanged -> benign200 with counter increment -> unrelated client unaffected WHEN client-scoped -> expiry/removal200 -> matching200 -> proxy restart preserves valid active/terminal rules -> API restart lists and manages existing rules -> fault/crash recovery remains truthful -> evidence chain and redaction validated -> clean process shutdown.

Use persistent evidence to verify the actual rule revision, approval reference, gate reference, target, timestamps and lifecycle outcome. A structurally valid hash chain alone is insufficient proof of those claims.

## Verification commands and evidence
Known interpreter:
C:\Users\satvi\Desktop\sentinelx-ds\.venv\Scripts\python.exe

Use fresh unique --basetemp outside both worktrees and -p no:cacheprovider.
Run:
- All new recovery/failure/approval/redaction tests.
- Shield unit/API/runtime-store/real HTTP tests.
- Policy, evidence, SSE, scanner, fixer, Agent Guard and CLI regressions.
- Full fast pytest: -m "not slow".
- Repeat Node lab/scanner subset to detect leaked processes/data locks.
- Project-wide Ruff and git diff --check.
- Forbidden-path and credential-file change audit.
- TypeScript SDK compile plus real wrapped-tool/API runtime checks.
- React typecheck/build and meaningful frontend contract tests.
- Browser workflows using an existing installed browser environment where available.
- Disposable clean-install/fresh-clone smoke without copying .env or an existing venv.

Record exact command/cwd/exit/pass/fail/error/skip/deselected counts. Collected is not passed. Do not downgrade failing assertions or relabel failures pre-existing without baseline evidence. Do not rerun only green selections and hide failures.

## Submission-readiness phase after critical repairs
Inspect the whole current feature matrix against production paths. Complete locally actionable packaging/CI/dashboard/API workflow gaps and update docs from actual results. Do not equate a Shield-only pass with full Sentinel X completion.

Prepare an honest local demo using only the verified configuration. Distinguish:
- actual HTTP enforcement vs direct evaluator tests;
- proposed/installed/enforcing/removed/recovery-pending;
- attempted vs executed actions;
- real scan findings vs unexecuted states;
- live model results vs scripted/recorded results;
- verified patches vs generated proposals;
- temporary shield vs a fix;
- actual cost vs estimate/unknown.

Hosted CI on unpushed commits is NOT_RUN. You may repair/test workflow configuration locally; no push is authorized here. Docker/PHP, unavailable browser flows, clean install and live-model benchmark must remain honestly unverified until executed.

Owner-only checklist: authorize any live/provider benchmark under existing budgets; choose license/visibility as required; confirm current submission rules/deadline; record approved demo; publish/submit only under separate explicit authorization. Do not invent evidence or claim these human actions occurred.

## Final handoff and exit criteria
Return:
- Starting/final SHA, ancestry and clean-state details (identify this input file).
- Focused commits/files and before/after reproductions.
- Every critical fault's API response, durable row, actual traffic and recovery outcome.
- Actual public separate-process E2E results and upstream counters.
- Canonical approval/digest/ordering/revocation tests.
- Persistent evidence and all redaction sinks.
- Full test/build/Node-repeat results and exact exits.
- Feature-by-feature PASS/PARTIAL/FAIL/BLOCKED/NOT_RUN.
- Remaining unverified/human actions.
- Updated demo/submission claims that match evidence.

Do not say final-submission-ready while P1 defects, required validation or owner-only submission actions remain. If one item is blocked, continue other safe independent work and report the exact dependency.

MERGED:NO. PUSHED:NO. DEPLOYED:NO. PUBLISHED:NO.
Stop for independent review.
