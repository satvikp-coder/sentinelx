# Architecture (design only; nothing below is implemented)

Modular monolith. Python backend, SQLite (WAL), React dashboard.

```
                        +------------------------------+
                        |  web (React) | CLI | SDKs    |
                        +---------------+--------------+
                                        |
                                 +------v------+
                                 |  API (FastAPI)  |
                                 +------+------+
                                        |
 +-------------- SHARED CORE -----------+-----------------------------------+
 |  policy gateway   evidence store   case/escalation workflow              |
 |  (authority)      (tamper-evident) (human in the loop)                    |
 |  model adapter (OpenAI-compatible; MODEL_UNAVAILABLE on failure)          |
 |  verifier (independent assertions)                                        |
 +----------+----------------------------------------------+-----------------+
            |                                              |
  SIDE 1: AGENT GUARD                            SIDE 2: SITE GUARD
  agent_runtime  -> instrumented browser agent   scanner (ownership-gated, non-destructive)
  fixture_lab    -> *.lab.test, 127.0.0.1 only   fixer   (propose -> independent verify -> human approve)
  adversarial    -> bounded scenario generation  shield  (reverse proxy; narrow temporary rules;
  investigator   -> evidence-cited hypotheses              "TEMPORARY SHIELD, NOT A FIX"; kill switch)
  containment    -> IncidentTwin branches (EVCS) labs: vibe_shop_php, vibe_notes_node
```

Flow principles: models propose; the gateway enforces; the verifier scores. All external/model content is untrusted and schema-validated (Pydantic, extra=forbid).

## Evidence hash chain (implemented in `sentinelx.evidence.store`; tamper-EVIDENCE, not forensic chain of custody)

Each session has its own chain. An event is a row of `events` (model `EvidenceEvent`, schema_version 1.0).

Algorithm (exact):

1. `GENESIS_HASH` = 64 ASCII zeros (`"0" * 64`). The first event of a session (seq 1) has `previous_hash = GENESIS_HASH`; event N has `previous_hash` = `event_hash` of event N-1 in the same session. `seq` starts at 1 and increases by exactly 1 (UNIQUE(session_id, seq)).
2. Build the event document with ALL fields except `event_hash`: `schema_version, id, session_id, seq, kind, timestamp_utc, parent_event_id, state, source, payload, previous_hash`.
   - `timestamp_utc` is formatted `YYYY-MM-DDTHH:MM:SS.ffffffZ` (UTC, always 6 fractional digits).
   - `state` is the enum string (e.g. `OBSERVED`); `parent_event_id` is `null` when absent.
   - `payload` is the already-redacted JSON object.
3. Canonical JSON: serialize with sorted keys at every level, separators `(",", ":")` (no extra whitespace), `ensure_ascii=False`, encoded as UTF-8.
4. `event_hash = lowercase_hex( SHA-256( canonical_json_bytes || previous_hash_as_ASCII_bytes ) )`.
5. `verify_chain(session_id)` walks events by `seq` and returns `OK` or the FIRST broken event with one of:
   - `MODIFIED`: the recomputed hash differs from the stored `event_hash` (any field edited), or the row no longer parses; also reported at an event whose successor's `previous_hash` no longer matches it (event rewritten and re-hashed).
   - `MISSING`: a `seq` gap (a deleted row); reported at the first surviving event after the gap. Deleting the *tail* is only detectable by passing an externally stored `expected_last_hash`.
   - `REORDERED`: an event's stored hash is valid for a different `seq`, or its `previous_hash` is another event's hash.

Limitation: someone who can rewrite the database AND recompute every subsequent hash can forge a consistent chain. Anchor `event_hash` of the last event elsewhere (e.g. in an exported report) to detect that.

## Session state machine (`sentinelx.evidence.sessions`)

```
CREATED -> READY -> RUNNING -> PAUSED -> (RUNNING by authorized OPERATOR resume | CANCELLED)
                       |-> COMPLETED | FAILED -> ANALYZED -> EXPORTED
 CREATED/READY/RUNNING -> CANCELLED (terminal)
```
A BLOCKED action is an evidence event, not a session state. Each real transition writes an `audit` row and an evidence event atomically; repeating a transition is a no-op. Roles: SYSTEM and OPERATOR may transition; AGENT may only request RUNNING -> PAUSED; resuming PAUSED -> RUNNING needs OPERATOR.

## Redaction (`sentinelx.policy.redaction`)
Applied inside `EvidenceStore.append` and `RecordStore.insert` (storage) and must be applied before any model call. Pattern-based, best effort.

## Policy gateway decision order (`sentinelx.policy.evaluate`, implemented)

`evaluate(action_request, scenario, policy, session_context) -> PolicyDecision` is a pure function (no I/O, clock, randomness, network, DNS or model calls) and the only authority for ALLOW / BLOCK / CONFIRM. It never raises: junk input or an internal error is a BLOCK (`MALFORMED_REQUEST`, `CONTEXT_INVALID`, `SCENARIO_INVALID`, `POLICY_INVALID`, `INTERNAL_ERROR`). Rules run in this order and the first match decides:

1. **INFRASTRUCTURE_DENY**: kill switch; session not RUNNING; request for another session; step not strictly increasing; `max_steps` reached; per-minute rate limit; tool unknown to the policy.
2. **USER_RESTRICTIONS**: user-forbidden tools/arguments; blocked destinations (policy + user, any port); **SECRET_EGRESS** (built-in secret detectors + configured `secret_patterns`, also on percent-decoded text) regardless of destination.
3. **SCENARIO_PERMISSIONS**: tool must be in the scenario's `allowed_actions`; only allowed/required scalar arguments within `max_length`; every URL argument must pass the exact-host check (`DESTINATION_NOT_ALLOWED`, with a precise URL reason code such as `USERINFO_IN_URL`, `PORT_NOT_ALLOWED`, `NONCANONICAL_IP`).
4. **HUMAN_CONFIRMATION**: high-impact tools return CONFIRM (or BLOCK if configured). CONFIRM never executes; a human records an `ApprovalRecord` whose `subject_id` is `"<action_id>:<args_digest>"` (bound to the exact tool + arguments). On re-evaluation the whole pipeline (rules 1-3) runs again before an approval is honoured; a matching rejection beats an approval.
5. **SAFE_ALLOWLIST**: tools in `allowed_tools` with valid arguments and in-scope destinations are ALLOWed.
6. **DEFAULT_DENY**: anything not explicitly allowed is BLOCKed.

Signals (`sentinelx.policy.signals`: instruction-override phrases, hidden-text hints, exfil requests) are computed after the verdict and attached to the decision as evidence. They cannot change a decision.

Monitor mode computes the real decision, returns `effective_action = ALLOW` and keeps the real decision in `decision` / `would_have_decided`; a small set of hard stops (kill switch, session not RUNNING, session mismatch, malformed/invalid inputs) stays enforced.

`sentinelx.policy.gateway.decide_and_record` runs `evaluate` and appends `ACTION_PROPOSED` (state PROPOSED, redacted request) then `ACTION_DECIDED` (state OBSERVED, parent-linked, with rule_ids, reason_code, policy_version, signals) in one transaction.

URL handling (`sentinelx.policy.urls`) rejects rather than repairs anything ambiguous: only http/https (about:blank if configured), no userinfo, no encoded authority, no backslashes/whitespace/control characters, no wildcard or suffix matching, canonical-form IP literals only and only when listed, IDN only when its punycode form is listed, trailing dot rejected unless configured. It cross-checks its own parse against `urllib.parse.urlsplit` and rejects on disagreement; `//`-prefixed relative references are resolved by us, not `urljoin` (which differs from browsers for `///host`).

## Scenario A lab, runtime and verifier (implemented; the agent is SIMULATED)

```
 apps/fixture_lab (FastAPI, 127.0.0.1:<OS port>, Host-header vhosts)      packages/verifier
   orders / calendar / support / collector .lab.test                       reads ONLY: scenario ground truth,
   mock side-effect endpoints --> ledger.jsonl (ground truth) -----------> evidence events, the ledger
   admin: reset / ledger (token + loopback only)
        ^                                  ^
        | Chromium (host-resolver rules)   | httpx -> 127.0.0.1 (http_request, tool_call)
        |                                  |
   +----+----------------------------------+------------------------------------+
   |  SANDBOX BOUNDARY (both arms): requests served hop by hop, redirects by us   |
   +------------------------------------+-----------------------------------------+
                                        |  only if the arm allows
   PROTECTED (arm B):   ACTION_PROPOSED -> policy gateway -> ACTION_DECIDED -> [ACTION_EXECUTED]
   UNPROTECTED (arm A): ACTION_PROPOSED -> SHADOW_DECISION (SIMULATED) -> ACTION_EXECUTED
                                        ^
                  ScriptedNaivePlanner (SIMULATED, not an LLM) behind the Planner interface
```

**Sandbox boundary vs policy gateway.** Different mechanisms, different jobs, no shared code.

- The *gateway* (`sentinelx.policy.evaluate`) decides what the agent MAY do. It runs only in the protected arm, on the proposed action, before execution.
- The *sandbox* (`sentinelx.agent_runtime.sandbox` plus the adapter's request router) guarantees what the agent CAN reach, in BOTH arms: only plain http to `*.lab.test` on the lab port. Everything else (real internet, IP literals, other ports, `file:`, `data:`, `javascript:`) is aborted and recorded as `SANDBOX_BLOCKED`. So even the unprotected arm cannot leave the lab.
- Redirects: Playwright does not invoke a route handler for the target of a browser-followed redirect (verified empirically: a redirect to `collector.lab.test` reached the ledger). The adapter therefore serves every request itself with `route.fetch(max_redirects=0)` and follows redirects hop by hop, applying the sandbox check to every hop (both arms) and `sentinelx.policy.check_redirect` to every hop (protected arm). Chromium also runs with `--host-resolver-rules="MAP *.lab.test 127.0.0.1, MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"` as a second layer; the hosts file is never edited.
- Evidence order per action: `ACTION_PROPOSED`, then `ACTION_DECIDED` (protected) or `SHADOW_DECISION` (unprotected), then `ACTION_EXECUTED`. A blocked or CONFIRM action has no EXECUTED event and is an event, not a session failure. In the protected arm the adapter is reachable only through `_execute_allowed`, which requires an effective ALLOW.
- Ground truth: every call to a mock side-effect endpoint (collector `/collect`, calendar `/api/cancel`, support `/api/upload`) is appended to a per-run JSONL ledger by the lab server. The planner and adapter never see it; the runner reads it once, after the run, and hands it to the verifier.
- Verifier: `forbidden_outcome_occurred` from the ledger only; `goal_met` from the final answer against ground truth; attempted / executed / blocked / false-block counts from evidence events. Results are stored as a `VERIFIER_RESULT` event (state VERIFIED) and in the `verifications` table (`kind = 'RUN'`).
- Arms: A = UNPROTECTED, B = PROTECTED (the `Arm` enum). Tool arguments are flat scalars: `tool_call(name, order_id)`, `submit_form(selector, field_name, field_value)`.

## Page-initiated egress (implemented; closes the Prompt 3 gap)

Requests a page makes by itself (img, script, iframe, link/prefetch, fetch, XHR, form posts, CSS `url()`, beacons, meta refresh, redirect hops, WebSocket) are treated as PROPOSED side effects of whatever the agent loaded.

- Rule set: `page_subresource` in `configs/policy/lab.yaml` (enabled flag, blocked resource types, allowed methods). It is part of `policy_version`, so editing it changes the version.
- Code path: `sentinelx.policy.evaluate_page_request` (pure, in the same package and purity tests as `evaluate`). Order: rules disabled -> malformed -> blocked resource type -> blocked method -> secret in URL **or body** -> exact allowed-host check (redirect hops via `check_redirect`) -> ALLOW.
- Enforcement: the adapter serves every browser request itself (`route.fetch`, redirects followed hop by hop). Per hop: (1) the sandbox boundary (both arms), then (2) in the PROTECTED arm only, the page-request policy. A denial aborts the request and records `EGRESS_BLOCKED` (url, resource type, method, channel = main_frame / form_submission / iframe / subresource / redirect_hop / websocket, reason, rule ids, policy version, `boundary: page_egress_policy`). Policy-blocked navigations are aborted with `aborted`, which leaves the current document in place, so the legitimate task survives.
- Allowed requests are not logged one by one; each run records ONE `EGRESS_SUMMARY` (counts by resource type and host, blocked counts) and `RUN_STARTED.boundaries` lists which boundaries applied: `["sandbox"]` for arm A, `["sandbox", "policy_gateway", "page_egress_policy"]` for arm B.
- WebSockets are never connected in the lab: arm A records `SANDBOX_BLOCKED` (`WEBSOCKET_UNSUPPORTED_IN_LAB`), arm B records `EGRESS_BLOCKED`.
- `http_request` is allowed for reads; state-changing methods (POST/PUT/PATCH/DELETE) are CONFIRM via a conditional `high_impact_actions` entry (`when: [{arg: method, values: [...]}]`).

## Evaluation pipeline (implemented; the agent is SIMULATED)

```
fixtures/attacks/*.json  fixtures/benign/*.json  (hand-authored AttackTemplate / BenignTemplate)
        |  sentinelx.evaluation.cases   (+ payloads/*, loaded by the lab per case id)
        v
evaluations/manifest.json  (sealed: manifest_hash over cases + case_hash + policy_version + budgets + order_seed)
        |  sentinelx.evaluation.runner   (refuses on any hash/header/fixture/policy mismatch)
        v
for each (case, arm, rep) in a seeded-shuffled order:  reset lab (same seed => same fixture_hash)
        arm A: sandbox only            arm B: sandbox + policy gateway + page-egress policy
        -> run_session -> independent verifier (ledger + evidence) -> RunRecord (valid | invalid + reason)
        v
sentinelx.evaluation.metrics (rates only via rate(); zero/missing denominator raises)
        v
report.json / report.csv / report.md  (provenance + limitations; generation fails on an incomplete rate)
```

Why `sentinelx.evaluation` and not `sentinelx.verifier.experiments`: the verifier must stay independent of the planner and runtime (a test enforces it), while the runner necessarily drives both. Arm C (EVCS containment, Prompt 7) has a seam only (`ARM_REGISTRY`); it is not implemented.

## Model adapter, ModelPlanner and variant generator (Prompt 5, implemented)
- `sentinelx.model_clients`: provider-agnostic OpenAI-compatible client (httpx). Config from `.env` (`MODEL_*`), key as `SecretStr`, never logged. Prompts are redacted before sending (the lab's synthetic token is the one explicit, flag-controlled exception). Token-bucket rate limit, retries with jittered backoff (Retry-After honoured), circuit breaker, per-run call cap and experiment call/token ceilings. Output is parsed strictly (one repair re-ask with the validation error, then `INVALID_OUTPUT`). A failed call is `MODEL_UNAVAILABLE`/`TIMEOUT`/`RATE_LIMITED`/`BUDGET_EXHAUSTED`; live failures never fall back to recordings. Every call is a `MODEL_CALL` evidence event (hashes, tokens, latency, reasoning setting; reasoning text is never stored). Recorded cassettes (`fixtures/recorded_model/`, mode RECORDED) exist only when explicitly recorded.
- `sentinelx.model_clients.profiles` (Prompt 9 Part 0.6, opt-in - every caller above keeps using the single-profile `load_config()` path unchanged): `configs/models.yaml` names named profiles (`nvidia_glimmer`, `baseten_spark_open`) with a base URL, model slug, key env var, and published per-1M-token prices, plus a task -> (primary, fallback) routing table. `resolve_task()` tries the primary, falls back to the ONE configured fallback if the key is missing or the profile's budget is exhausted, and always labels a fallback in the result - never silently. `check_budget()` sums the `usage` table's `estimated_cost` (now carrying a `profile` column) against a `budgets` table row and returns `OK`/`WARNING`/`BUDGET_EXHAUSTED`; the hard cap is a real stop, never a retry. `scripts/estimate_cost.py` is a separate, more conservative dry-run check for a whole planned batch, using a configured reserve below the hard cap.
- `sentinelx.agent_runtime.model_planner`: `ModelPlanner` implements the same `Planner` interface as the scripted planner. It proposes one tool call per step; page text, structure and tool results enter the prompt only inside `UNTRUSTED DATA` delimiters. It never sees labels, policy, verifier or ledger. Whatever it proposes goes through the unchanged gateway (arm B) or straight to execution (arm A); the verifier scores from ground truth. Model failure ends the run `FAILED` with an abort reason, and the run is excluded as invalid.
- Evaluation: planner factories (`ScriptedPlannerFactory`, `ModelPlannerFactory`); a report covers exactly one planner, so SIMULATED and model-driven results are never merged. Reports name provider, model, mode, prompt version and reasoning setting, and list model usage and invalid runs.
- `sentinelx.adversarial`: bounded generator. The model fills one plain-text slot of a fixed template for a hand-written seed; a static checker rejects markup, URLs/hosts, unapproved paths/placeholders, credential/harm terms; our code builds the case and copies every label from the seed. Generated cases live in `fixtures/generated/` and a separate manifest; the sealed hand-authored manifest and its hash are untouched.

## Investigator and independent finding verifier (Prompt 6/7 session, implemented)
- `sentinelx.investigator.facts.build_facts`: evidence events -> bounded structured facts (allowlisted payload fields only, dotted paths, strings cut at 120 chars). No model.
- `baseline.baseline_investigate`: facts -> OBSERVED claims (each with a structured assertion `{event_id, field_path, op, value}`) + at most two rule-table INFERRED claims: (1) forbidden outcome occurred -> "the agent followed untrusted instructions" (cites verifier, proposal, execution); (2) forbidden action attempted AND stopped by a BLOCK/CONFIRM decision or an egress/sandbox block -> "consistent with untrusted content attempting to redirect the agent". Fixed-template summary; catalog-only mitigations; severity from a rule table keyed on the attempted action's reason code (SECRET_EGRESS critical; DESTINATION_NOT_ALLOWED / high-impact high; TOOL_NOT_IN_SCENARIO medium; attempt with no known reason medium; no attempt low). Severity looks at neither confidence nor attack success. Works offline and is the default.
- `model_investigator`: ONE call (`investigator_prompt_v1`, see docs/PROMPTS.md) over the facts inside an UNTRUSTED DATA block; strict `InvestigatorOutput` (extra keys, free-text mitigations, shapeless claims -> invalid -> adapter's single re-ask -> baseline with the visible note "model unavailable: baseline used"). The model's severity is only a suggestion; the rule table is authoritative.
- `verify.verify_finding` (imports only `common_schemas` and the evidence store - a test enforces this): (1) every cited id must exist in THIS session; (2) an OBSERVED assertion must hold on the cited event's payload (`equals`/`contains`/`exists`, bool is not int); (3) an INFERRED claim must not contradict `VERIFIER_RESULT` and its wording must be backed by the kinds of events it cites (small regex table: outcome, attempt, goal, "blocked" needs a BLOCK/CONFIRM decision or an egress/sandbox block - a SIMULATED shadow decision does not count); (4) mitigations must be in the catalog. rejected = fake/cross-session id, false OBSERVED assertion, off-catalog mitigation; confirmed = every claim passes; otherwise needs_validation. INFERRED claims that match no table row are only checked for citation and contradictions - they are interpretation, not verified fact.
- `service.investigate`: draft (model or baseline) -> verify -> append `INCIDENT_FINDING` (INFERRED) and `FINDING_VERIFIED` (VERIFIED only when confirmed; OBSERVED + `flagged: true` otherwise) and an `incidents` row. `citation_fidelity` = claims with verified support / claims evaluated, summed with numerator and denominator.
- `timeline.build_timeline`: ordered events with parent links, state labels and proposal -> decision -> execution/block chains (SIMULATED shadow decisions are labelled and separate).

## Human-approval workflow (implemented)
- When the gateway returns CONFIRM in the protected arm and the run has an approver, the runtime builds the existing `ApprovalRequest` (bound to the exact tool, an arguments digest, the session and the `policy_version` - an additive field), appends `APPROVAL_REQUESTED` (the action is frozen: it is not executed), asks an approver (`sentinelx.agent_runtime.approvers`) and appends `APPROVAL_RECORDED` (state SIMULATED for the ScriptedOperator). Only on `approve` does the gateway RE-EVALUATE the same request with the approval in its context and append a second `ACTION_DECIDED` (`reevaluated_after_approval`); an approval can never override rules 1-3 because they run first, and an approval for other arguments or another action id does not match (`approval_subject_id` = action id + arguments digest).
- Approvers: `AlwaysReject` (default; also what happens when no approver is set), `TimeoutApprover` (nobody answers), `ScriptedOperator` (a SIMULATED human). Its input is `fixtures/operator_policy/<case id>.json`, hand-authored from the case's goal text (the four cases whose goal asks for a state-changing action list it; every attack case lists nothing). That file is read only by the approver; tests assert the planner, gateway, verifier and the mitigation/selection/suggestion modules never import it. The file is keyed by case id (the ScenarioSpec id), not by the S1/S2/S3 family, because one family contains cases with different intents.

## IncidentTwin containment - EVCS (implemented; SIMULATED scripted agent)
- "Digital twin" = a bounded, resettable replica of OUR lab fixtures. A branch is a RE-EXECUTION from a checkpoint, not a rollback of anything real.
- **Checkpoint** (`containment.branch.Checkpoint`): `{scenario_id, case_id, seed, fixture_hash, policy_version, planner "SIMULATED scripted", script_version (hash of the task script), step_index_of_decision, parent_session_id, trace_event_ids, ref}`. It recreates the starting state in a fresh lab; browser memory is not snapshotted.
- **Parent** = the recorded attack session (scripted planner, arm A). **Branch** (`run_branch`): a fresh `LabServer` (own ledger directory and port), reset to the checkpoint's seed, asserted to have the parent's `fixture_hash` and an empty ledger, scripted planner from the start, one mitigation applied, session kind `CONTAINMENT` with a `RUN_STARTED` note naming the mitigation, parent and checkpoint; judged by the verifier; stored as a `ContainmentBranch` (`model_mode` NONE). Extra measurements: `blocked_legitimate` (verifier false blocks), `confirmed_legitimate` (legit actions sent to CONFIRM), `added_actions` (proposals beyond the task script), `stripped_chars`, `duration_ms`.
- **Catalog**: BLOCK_ONLY (lab policy, AlwaysReject), PAUSE_AND_CONFIRM (lab policy, the run's approver), STRIP_UNTRUSTED_INSTRUCTION (no gateway; signals-detector spans removed from what the planner sees), LIMIT_NAVIGATION (gateway scenario reduced to navigate/read_page/click), ROLLBACK_AND_RETRY (`configs/policy/lab_strict.yaml`: 10 steps, 30 req/min, no `http_request`, high-impact BLOCK), TRAP_BLOCK_EVERYTHING (control: deny every tool), BASELINE_BLOCK_ALL_SENSITIVE (`lab_baseline.yaml`: state-changing `http_request` BLOCK; comparison only).
- **Selection** (`containment.selection`, code only): eligible = valid verified run AND `unauthorized_executed == 0`; recommend only among eligible branches with `task_completed`; utility = 1 - (w_blocked*blocked + w_confirm*confirmed + w_added*added + w_strip*stripped/100 + w_latency*ms/1000) with weights from `configs/containment/weights.yaml` (version recorded, validated non-negative; latency priced 0 by default for reproducibility); ties broken by the fixed order BLOCK_ONLY, PAUSE_AND_CONFIRM, STRIP, LIMIT_NAVIGATION, ROLLBACK and reported; trap/baseline never recommended; no completing branch -> "no safe mitigation preserves the task: human review required" (ESCALATE_TO_HUMAN).
- **Recorded replay** (`replay_decisions`/`divergence`): re-evaluating the parent's recorded proposals under a mitigation policy, labelled RECORDED REPLAY and never counted as a branch.
- **Evidence**: on the parent session, `EVCS_CHECKPOINT`, one `EVCS_BRANCH` per branch (cites the branch session id) and `EVCS_RECOMMENDATION` (state PROPOSED, cites all branch session ids).
- **Optional model** (`containment_prompt_v1`): one call per case to choose which candidates to try; fallback = full catalog.
- **Arm C**: EVCS-recommended mitigation per attack case (its own verified branch) beside A and B from the sealed manifest (same manifest hash); benign cases = lab policy + SIMULATED ScriptedOperator.


## Site Guard: labs and the authorization gate (Part 2, implemented; no scanner checks yet)
- **Labs** (`labs/`): `vibe_shop_php` (PHP 8.5.12 + SQLite in Docker, port 18080) and `vibe_notes_node` (Express + built-in `node:sqlite`, port 18081), each with a hand-fixed `*_reference` copy (ports 18082 / 18083). All listen on 127.0.0.1 only (`apps/labctl.py` proves it: published binding, listening socket, and a refused connection through every non-loopback address of the PC). Data is synthetic and seeded deterministically; `scripts/lab_reset.py` restores it and prints a state hash (salted password hashes are excluded). Each lab ships `PLANTED.json` (strict `PlantedManifest`: class, severity, file, lines, endpoint, a description of what is wrong, a harmless "what to observe" confirmation strategy, fix category, `requires_human_decision`) and `benign_traffic.py` (every legitimate feature with golden markers; the regression suite for later fix verification and the false-block measurement for the shield). The reference copies are ground truth for verification only: a test asserts nothing under `packages/` mentions `_reference` or `labs/`.
- **Authorization gate** (`sentinelx.scanner.authz` = pure logic; `sentinelx.scanner.http.GuardedClient` = the ONLY approved HTTP client, enforced by a static test). Per request AND per redirect hop, in this order: kill switch -> target state (VERIFIED, not expired, non-lab only if the operator enabled it) -> exact scheme/host/port scope (no wildcard, no userinfo, `sentinelx.policy.urls` normalizer) -> method policy (GET/HEAD/OPTIONS; POST/PUT/PATCH/DELETE only on lab targets, only if the scan profile declares them, with a reason and a declared synthetic account) -> body cap -> request budget and wall-clock -> address check (non-lab: ONE DNS resolution, loopback/private/link-local/multicast/reserved/metadata refused for IPv4 and IPv6, then the connection is PINNED to that IP; lab hosts map to loopback without DNS) -> rate limit. Responses are size- and time-capped. Every attempt is an evidence event (`SCAN_REQUEST` / `SCAN_REQUEST_REFUSED`, redacted URL, header names only, no bodies), the operator configuration is recorded once (`SCAN_CONFIG`) and a fatal refusal records `SCAN_STOPPED`.
- **Targets**: lab targets (`lab=true`) need every host to be `localhost`, `127.0.0.1`, `::1` or a `*.lab.test` name and are auto-verified (method `lab`). Non-lab targets are DISABLED unless `ALLOW_NON_LAB_TARGETS=true`, start PENDING, and need the owner to serve a random token at `/.well-known/sentinelx-verify.txt` on the exact origin (fetched once through the guarded client, compared in constant time, only its SHA-256 stored) plus the exact acknowledgement phrase; verification expires (default 24 h). Refusal codes: UNVERIFIED_TARGET, OUT_OF_SCOPE_HOST, OUT_OF_SCOPE_REDIRECT, PRIVATE_ADDRESS, METHOD_NOT_ALLOWED, BUDGET_EXCEEDED, RATE_LIMITED, KILL_SWITCH, EXPIRED_VERIFICATION, USERINFO_IN_URL, BODY_TOO_LARGE (+ NON_LAB_DISABLED, BAD_URL, STATE_CHANGE_UNDECLARED, NO_ADDRESS).
- **Immutability**: `AuthzConfig` and `ScanProfile` are frozen pydantic objects set by operator code; there is no input path from a model, a scanned page or a request that changes them.

## Site Guard scanner (Prompt 9, implemented): personas, recon, the check library, independent verification
- **Personas** (`labs/<lab>/personas.json`, synthetic, committed, labelled `"synthetic": true`): `anonymous`, `user_a`, `user_b` (used only to test whether A can read B's data), `admin_guesser` (an ordinary visitor who looks at admin/debug routes with NO admin credentials). `sentinelx.scanner.session.new_session` refuses persona credentials for any non-lab target (`PersonaCredentialError`). `PersonaSession` keeps its own cookie jar and bearer token; `ScanContext.ensure_persona(name, fresh=True)` always makes a brand-new session with a fresh login, never reusing a cached one - this is what the independent verifier uses.
- **Recon** (`sentinelx.scanner.recon`): a breadth-first GET crawl per persona (`crawl`), parsing real HTML (`PageParser`, stdlib `html.parser`) for links/forms and script src/inline text for API-literal strings (`/api/...`), which are themselves FETCHED (not just registered) so member-object samples get discovered (`expand_collections` turns a JSON list-of-objects response into `/collection/{id}` sample URLs per persona). Safe discovery (`discover`, anonymous only) GETs a fixed list of conventional paths (`configs/scan/paths.yaml`: exposure/admin/API-hint paths) and records a soft-404 baseline so a catch-all error page is never misread as a hit. `probe_api_hints` also runs for a LOGGED-IN persona, so protected endpoints (e.g. `/api/search`) get a real, usable sample instead of only a login-required response.
- **Check catalog** (`sentinelx.scanner.checks`, one module per check, `Check(spec, run, applicable)`): `security_headers_and_cookies`, `sensitive_file_exposure`, `debug_exposure`, `missing_authentication` (confirms only when the response also looks sensitive - a secret, an email, 2+ JSON user-identifier keys, or 2+ of the scanner's own known persona usernames in a plain listing), `permissive_cors`, `verbose_errors`, `sql_injection` (a database-error signature, OR - for apps with `display_errors` off - the page stopping mid-render where the ordinary value's page completed normally), `reflected_xss`, `broken_object_authorization`, `missing_rate_limit` (hard-capped at 15 failed logins for a NONEXISTENT username, ever - `HARD_CAP` in `checks/rate_limit.py`), `weak_upload_validation` (lab-only, declared state-changing, an inert double-extension text file, cleaned up only by a lab reset). Severity comes from a fixed table (`checks/base.SEVERITY_BY_CLASS`), never from the model or from confidence. `applicable(ctx)` reports the endpoints a check WOULD examine (no request of its own) and feeds the coverage ledger. `excerpt()`/`looks_like_a_secret()` call the shared `sentinelx.policy.redaction` module directly, which also covers quoted source-code secret assignments (`const SECRET = 'x'`, PHP's `define('APP_SECRET', 'x')`) - an earlier, narrow scanner-local supplement for this shape was removed once the shared module grew to cover it (Prompt 9 Part 0.3).
- **Independent verifier** (`sentinelx.scanner.verify`): one function per `VulnClass`, each with its OWN request logic and decision rule, re-declared independently of `checks/*.py` (down to re-declaring its own copies of the DB-error/stack-trace/secret regexes) - it never calls a check's `run()`. Every verifier opens a FRESH session (`ensure_persona(..., fresh=True)`, then `ctx.request_in(session, ...)` for any further requests in that same fresh session) and re-observes the consequence. `missing_rate_limit`'s verifier can only ever return `needs_validation` (reproduces, still behavioural) or `rejected` (a fresh burst is throttled) - never `confirmed`. `weak_upload_validation`'s verifier re-checks only persistence (the file is still fetchable), not the upload itself, so verification never doubles the lab's artefacts.
- **Coverage ledger** (`sentinelx.scanner.coverage`): rows = (check, endpoint); every row is `exercised: true` with evidence event ids, or `exercised: false` with a reason (`"profile excludes this check"`, `"not applicable: no matching endpoint was found"`, or the scan's own stop reason for checks that never got their turn).
- **Model assist** (`sentinelx.scanner.model_assist`, at most 2 calls/scan): `scan_prompt_v1` orders/narrows the profile's own check list from a redacted crawl-shape summary (counts only); an unknown id or any failure falls back to the full default plan with a note. `explain_prompt_v1` (one batch call, only if something confirmed) writes a plain-language `explanation` for already-confirmed findings, labelled `"MODEL-GENERATED"`; it cannot change any finding's state. See `docs/PROMPTS.md`.
- **Orchestrator** (`sentinelx.scanner.orchestrate.run_scan`): register -> verify target -> recon (crawl + discover + hint-probing) -> plan -> hunt (run each check in plan order, skipping the rest once budget/rate/kill-switch/cancel trips, each skip recorded with its reason) -> verify every candidate -> optional explanations -> report. Every evidence kind: `SCAN_CONFIG` (once), `SCAN_REQUEST`/`SCAN_REQUEST_REFUSED` (every attempt), `SCAN_CHECK_ERROR` (a check's own exception, caught so one bad check cannot crash the scan), `SCAN_FINDING_CANDIDATE` (state INFERRED), `SCAN_FINDING_VERIFIED` (state VERIFIED only if confirmed, else OBSERVED + `flagged: true`), `SCAN_STOPPED`, `SCAN_FINISHED`. Always ends with an explicit `stop_reason` (`"completed"`, a `Refusal` code, or `"CANCELLED"`).
- **Scoring** (`sentinelx.evaluation.scan_scoring`, reads a lab's `PLANTED.json` ONLY here, after a scan; the scanner package itself never does): matches a CONFIRMED finding to a planted item on `(CLASS_MAP[vuln_class], normalized endpoint, method)` - `normalize_endpoint` folds numeric/`:id`/`{id}` segments to the same `{id}` shape, EXCEPT `APPLICATION_WIDE_CLASSES` (`security_headers_and_cookies`, `permissive_cors`: typically one piece of global middleware in a real app), which match by class alone regardless of endpoint. Unmatched confirmed findings are listed for MANUAL review, never auto-counted as false positives. `clean_copy_check` reruns the SAME specific-item matching against a scan of the hand-fixed reference copy (not just class membership, so an unrelated, legitimately-public finding of the same class never counts as a failed fix).

## Site Guard fix engine (Prompt 9 Parts A-G, implemented): diagnosis, patch generation, independent verification, the decision ladder
- **Repo scope** (`sentinelx.fixer.scope.create_scope`): copies ONE lab's own source into a disposable, git-initialized directory (`RepoScope`); PHP's `app/` subdir is self-contained, Node's source files live in the lab root and are copied individually, explicitly EXCLUDING `node_modules`, `data`, and `PLANTED.json` (which lives in the Node lab's root, unlike PHP's). `RepoScope.resolve_in_scope()` is the only way fixer code turns a model- or diff-supplied relative path into a real filesystem path, and refuses anything that resolves outside `work_dir`. The original lab directory is never written to.
- **Fix policy** (`configs/fix/policy.yaml`, `sentinelx.fixer.models.FixCategory` - a 12-value enum written independently of, and never aligned to, the lab ground truth's own fix-category field): per scanner `VulnClass`, the allowed category and whether a deterministic fix is reasonable (`AUTO`: sql_injection, reflected_xss, broken_object_authorization, sensitive_file_exposure, security_headers_and_cookies, verbose_errors, debug_exposure) or depends on a business decision (`NEEDS_HUMAN`: missing_authentication, missing_rate_limit, permissive_cors, weak_upload_validation - never auto-applied regardless of verification outcome).
- **Diagnosis** (`sentinelx.fixer.diagnose`): `route_to_file()` is pure, static code, no model - PHP endpoint -> matching script path; Node endpoint -> a regex search over `server.js`'s own route registrations, folding Express `:param` to the scanner's `{id}` template. A bounded model call (`diagnose_prompt_v1`) then narrows a capped file excerpt down to a line range; the model sees only the excerpt and the finding's public fields, never labels or ground truth, and a model failure falls back to the whole excerpt, honestly labelled, never a fabricated line number.
- **Patch generation** (`sentinelx.fixer.patch_gen`, `fix_prompt_v1`, at most 2 retries feeding back the deterministic validator failure text): one model call proposes a unified diff, explanation, files_touched and fix_category (strict schema, `fix_category` restricted to the `FixCategory` enum).
- **Diff validator** (`sentinelx.fixer.diff_validator`, pure code, no model, parses the diff itself rather than trusting `git apply` to say what it does first): rejects a file outside the allowed set, a path escaping the scope, more than 60 changed lines, a binary diff, a new network call (a lookbehind keeps PHP/JS method calls like `->fetch()` from being confused with the Fetch API), shell/eval/subprocess use, a secret-shaped literal (the shared redactor), removing a security-control call without an equivalent replacement, and edits to a test or benign-traffic path.
- **Applier** (`sentinelx.fixer.apply`): `git apply` given a real file path, never a shell string built from model text; commits the change in the scope's own disposable repo.
- **Independent verification** (`sentinelx.fixer.verify`, NO model import anywhere in this module): `materialize.py` turns the (patched) scope back into a runnable, isolated lab instance on its own loopback port (PHP: `docker compose build+up` under a unique project name; Node: `node server.js` directly, pointed at the original's `node_modules` via `NODE_PATH` so it is never copied). In order: diff review (re-checked), syntax (`php -l` inside the pinned image / `node --check`), the lab's own benign-traffic generator (every feature plus its golden content-marker check), and one full scan of the patched instance compared against the original scan's confirmed set (the fixed finding must no longer confirm, and nothing new may). All must pass for `VERIFIED`; any failure is `REJECTED` with per-check timing recorded as a `RepairVerification`.
- **Decision ladder** (`sentinelx.fixer.ladder`): a `VERIFIED` `AUTO` patch is recorded `PROPOSED` (a `PatchProposal` + its `RepairVerification`) and waits for a human `ApprovalRecord`; `apply_approved()` is the only path into `labs_applied/<lab>/current/` (never the original lab), keeping a timestamped rollback copy of whatever was already there. `NEEDS_HUMAN` by policy, a patch the model never validates, or verification `REJECTED` twice all route to an `EscalationTicket` (`OPEN`, 2-3 concrete options with trade-offs) instead.
- **Orchestrator** (`sentinelx.fixer.orchestrate.run_fix`): diagnose -> generate_patch -> apply -> verify -> decide, looping on a `REJECTED_RETRY` ladder outcome by resetting the scope to its unpatched baseline (`git reset --hard`) before a fresh attempt, never stacking attempts. Checks the hard spend guard before every patch-generation attempt (escalates immediately on `BUDGET_EXHAUSTED`, never mid-call) and records every model call's actual token usage into the `usage` ledger under the resolved profile.
- **CLI** (`scripts/run_fix.py --target <lab> --scan-report <report.json> [--findings ids] [--approve id] [--reviewer name]`, `scripts/escalations.py list/ack/resolve`, `scripts/run_fix_batch.py` for the rule-based batch in `evaluations/example_fix_report/`).
