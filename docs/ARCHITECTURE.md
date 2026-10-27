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
