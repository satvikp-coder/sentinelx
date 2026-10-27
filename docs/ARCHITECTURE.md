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
