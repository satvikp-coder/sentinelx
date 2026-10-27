# Sentinel X - Agent Security Digital Twin

Built for the Meta Global AI Developer Hackathon 2026 (Indie track, "Push the Frontier").

Two sides on one shared evidence and verification core:
- **Agent Guard** - an isolated lab where an autonomous browser agent is attacked through synthetic page/tool content; deterministic policy gateway, tamper-evident evidence, paired unprotected/protected runs, independent verifier, IncidentTwin containment branches.
- **Site Guard** - a red-team scanner, fix engine and live reverse-proxy shield for sites you own.

## Honest status
**Early prototype.** The typed contracts, evidence store, policy gateway, a synthetic attack lab and an independent verifier exist locally and are tested; the agent in the lab is a SIMULATED scripted program, not an LLM. No model integration, scanner, fixer, shield, SDK, CLI, API or dashboard exists yet. See [STATUS.md](STATUS.md) for real test output and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design (a design is not proof of working code).

## Planned vs implemented

| Component | Status |
|---|---|
| Common schemas (strict Pydantic) | implemented (local) |
| Model adapter (OpenAI-compatible, Meta open-weight) | planned |
| Policy gateway | implemented (local; no model calls) |
| Evidence store (SQLite WAL, tamper-evident) | implemented (local) |
| Agent runtime + fixture lab | implemented for Scenario A with a SIMULATED scripted agent (no LLM yet) |
| Adversarial scenario generation | planned |
| Verifier (independent assertions) | implemented for Scenario A (ledger-based) |
| Investigator (evidence-cited) | planned |
| IncidentTwin containment (EVCS) | planned |
| Scanner (Site Guard) | planned |
| Fixer | planned |
| Shield (reverse proxy) | planned |
| Agent Guard SDK (Python / TypeScript) | planned |
| Site Guard CLI | planned |
| API (FastAPI) | planned |
| Dashboard (React) | planned |
| Reproducible benchmark | planned |

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
