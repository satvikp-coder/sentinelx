# Sentinel X - Agent Security Digital Twin

Built for the Meta Global AI Developer Hackathon 2026 (Indie track, "Push the Frontier").

Two sides on one shared evidence and verification core:
- **Agent Guard** - an isolated lab where an autonomous browser agent is attacked through synthetic page/tool content; deterministic policy gateway, tamper-evident evidence, paired unprotected/protected runs, independent verifier, IncidentTwin containment branches.
- **Site Guard** - a red-team scanner, fix engine and live reverse-proxy shield for sites you own.

## Protect your AI agent in 5 minutes

Lab targets only in this version. The SDK is offline: no network, no model calls.

1. Install:
```
pip install -e .
pip install -e sdk/python
```

2. Wrap a tool with the guard. The policy file has exactly four keys - `allowed_hosts`,
`allowed_tools`, `high_impact_actions`, `secret_patterns` (unknown keys are rejected):

```python
from sentinelx_agent_guard import Guard, GuardBlocked

guard = Guard("examples/agent_guard_policy.yaml", mode="enforce")

@guard.tool("fetch_page")
def fetch_page(url: str) -> str:
    return "page text"

try:
    fetch_page("http://orders.lab.test/cart")
except GuardBlocked as exc:
    print("BLOCKED:", exc.reason_code)
```

3. Run the offline demo: a naive agent follows a hostile page instruction and the guard
blocks the send while the legitimate task still completes:
```
python examples/agent_guard_basic.py
```

4. Check one action with the real policy gateway (action.json holds `tool`, `arguments`,
optional `allowed_hosts`):
```
sentinelx agent check --policy configs/policy/default.yaml --action action.json
```

## Harden your site in 10 minutes (lab demo)

Lab targets only in this version; non-lab scanning is DISABLED. The demo needs Node.js and
runs against the local `vibe_notes_node` lab.

```
python scripts/lab_up.py vibe_notes_node
python scripts/lab_reset.py vibe_notes_node
sentinelx init
sentinelx site add http://127.0.0.1:18081 --lab
sentinelx site verify vibe_notes_node
sentinelx site scan vibe_notes_node
python scripts/lab_up.py vibe_notes_node
sentinelx site guard --upstream http://127.0.0.1:18081 --listen 127.0.0.1:18090 --mode monitor
#   in another terminal, one benign request through the shield:
#   curl http://127.0.0.1:18090/health
sentinelx site report vibe_notes_node
sentinelx shield list
python scripts/lab_down.py vibe_notes_node
```

`site scan` stops the lab when it finishes, so bring it back up before the guard demo.
The shield is a TEMPORARY SHIELD, NOT A FIX; monitor mode never blocks. This exact
sequence (with the benign request sent by httpx) is run by `python scripts/readme_smoke.py`.

## Honest status
**Local security prototype.** Agent Guard, the lab-only scanner/fixer, a FastAPI
backend, TypeScript/Python SDKs, and a React dashboard are implemented. The default
agent evaluation is SIMULATED; no live model benchmark was run in this completion
review. Shield was exercised through separate local API/proxy/upstream processes,
including approval, real HTTP blocking, restart recovery and removal. The dashboard
Shield workflow was exercised in Chromium. This is a single-operator local demo,
not production multi-user authorization. See
[completion and submission gates](tasks/CODEX_COMPLETION_AND_SUBMISSION.md).

## Planned vs implemented

| Component | Status |
|---|---|
| Common schemas (strict Pydantic) | implemented (local) |
| Model adapter (OpenAI-compatible, Meta open-weight) | implemented (local; no live credentials) |
| Policy gateway | implemented (local; no model calls) |
| Evidence store (SQLite WAL, tamper-evident) | implemented (local) |
| Agent runtime + fixture lab | implemented for Scenarios A/B with SIMULATED scripted agent |
| Hand-authored attack + benign case set (15 + 15), sealed manifest | implemented |
| Paired experiment runner, metrics, reports | implemented (scripted agent only; no model) |
| Adversarial scenario generation (model-driven) | planned |
| Verifier (independent assertions) | implemented for Scenario A/B (ledger-based) |
| Investigator (evidence-cited) | implemented (model + baseline) |
| IncidentTwin containment (EVCS) | implemented (15 attack cases) |
| Scanner (Site Guard) | authorization gate + GuardedClient + 11-check catalog + independent verifier + coverage ledger; stored XSS + POST authz checks added |
| Fixer | implemented (structured edits + unified diff; secret-safe retry diagnostics) |
| Shield (reverse proxy) | implemented (deterministic narrow rules, human approval, representative benign replay,
SQLite runtime/evidence, TTL and kill switch; no blanket injection-protection claim) |
| Agent Guard SDK (Python / TypeScript) | Python SDK implemented; TypeScript SDK implemented |
| Site Guard CLI | implemented (local; lab targets only) |
| API (FastAPI) | implemented (/api/v1, event streaming, SSE) |
| Dashboard (React) | implemented (React + Vite + TypeScript, 10 screens) |
| Lab 1: vibe_shop_php (+ reference, PLANTED ground truth, benign traffic) | implemented (local; Docker required) |
| Lab 2: vibe_notes_node (+ reference, PLANTED ground truth, benign traffic) | implemented (local) |
| Reproducible benchmark | implemented (30-case sealed manifest; harness ready) |
| Final-run orchestrator | implemented (scripts/final_run.py --dry-run) |
| External scanner QA harness (Strix/PentAGI) | implemented (disabled by default; dry-run only) |

## Responsible use
Scan only systems you own or are authorized to test. See [SECURITY.md](SECURITY.md).

## Development
```
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && pytest
npm install && npm run build
```
