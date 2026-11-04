# Hackathon scope and source chronology

Sentinel X was developed as new project work for the stated **October 27–November 4,
2026** build period. This is the contributor's scope declaration, supported by the
repository history below; Git timestamps alone do not independently prove when an
idea/code was authored or certify eligibility. Owner must confirm the accepted
event rules, timezone, source chronology and any organizer permission.

## Recorded implementation milestones

Dates are the commits' recorded local timestamps (IST), not invented build dates.

| Component | Recorded milestone | Commit |
|---|---|---|
| Initial source scaffold | October 27, 05:32 IST; October 26, 20:02 ET | `865823f` |
| Hash-chained evidence | October 27 | `6a17ca4` |
| Agent runtime and controlled browser lab | October 27 | `30c9ed5` |
| Model adapter | October 27 | `5c0d837` |
| Site Guard request authorization | October 27 | `67cbb19` |
| Fix engine | October 29 | `98a36af` |
| Shield reverse proxy | October 30 | `f6ac3e7` |
| Python SDK | October 31 | `f0ccd23` |
| FastAPI backend / TypeScript SDK / dashboard | November 2 | `125d29a`, `b3d4f95`, `3dcd430` |
| Recovery, independent checks, licensing and cost honesty | Through November 4 | `8803fb6`, `dae6eff`, `b7af191` |

Subsequent README/publication preparation is release documentation and metadata,
not a newly claimed model experiment. Its actual commit timestamps remain visible;
do not relabel later work as having occurred earlier to satisfy a cutoff.
Earlier compliance notes assumed a different official start date; resolve that
with genuine accepted-participant material rather than inventing permission.

## What is demonstrated and what is not

Agent Guard is demonstrated with deterministic policy and synthetic/scripted
fixtures; historical Meta-provider examples retain their original LIVE provenance
and failures. Site Guard's scanner/fixer operate against local synthetic labs.
Shield uses explicit approval, representative benign replay, real loopback proxy
traffic and durable evidence. A rule is temporary mitigation, not a code fix.

No current live-model benchmark, universal protection, real-site scan, production
deployment, external-scanner operation or published video is claimed. The full
live comparison was not completed. New documentation reuses historical metrics
only with links, denominators and caveats; it does not manufacture new results.

## Original and third-party work

The contributor's recorded clean-room declaration says no source was imported from
the earlier `satvikp-coder/sentinel` repository. This release review did not compare
that separate repository, so it is an attestation rather than an independently
established source-origin guarantee.

- Runtime/build dependencies include Python, FastAPI, Pydantic, httpx, PyYAML,
  Uvicorn, psutil, SQLite, React, Vite and TypeScript. Test tools include pytest,
  Hypothesis and Playwright. Exact declarations are in `pyproject.toml`, the SDK
  manifests and `package-lock.json`; dependencies retain their own licenses.
- NVIDIA and Baseten are historical inference providers, not original project
  model weights. Provider/model provenance and evidence limits are recorded in
  [SUBMISSION_MODEL_EVIDENCE.md](SUBMISSION_MODEL_EVIDENCE.md).
- Claude-Red, Strix, Cloudflare security-audit-skill, ECC, Tracecat and PentAGI were
  identified as inspiration or optional lab tooling. The inventory records their
  claimed usage/status; it is not a claim that each tool was run or copied.
- OpenCode and Codex assisted implementation, repair, testing and documentation,
  with human developer direction/review. No formal third-party certification or
  human line-by-line audit is claimed.

See [THIRD_PARTY_INVENTORY.md](THIRD_PARTY_INVENTORY.md) and
[RULES_COMPLIANCE.md](RULES_COMPLIANCE.md). The project license is MIT,
copyright 2026 Satvik Patel; this does not replace third-party terms.
