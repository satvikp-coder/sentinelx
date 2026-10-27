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
