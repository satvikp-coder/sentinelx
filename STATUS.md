# STATUS

Last updated: 2026-10-27 (Prompt 0: project setup only; no feature code).

## Environment report (observed 2026-10-27, Windows 11)

| Tool | Result |
|---|---|
| git | 2.53.0.windows.2 |
| python / python3 | 3.13.14 (`py` launcher: 3.13.5); stdlib sqlite3 library 3.50.4 |
| pip | 26.1.2 |
| node / npm | v24.12.0 / 11.6.2 |
| docker | CLI 29.7.2 installed, **daemon NOT running** (Docker Desktop engine pipe not found). Start Docker Desktop before any container work. |
| php | **MISSING**. Needed for labs/vibe_shop_php. Install via `winget install PHP.PHP` (or from windows.php.net), or run that lab in Docker once the daemon is up. |
| sqlite3 CLI | **MISSING** (optional; Python's sqlite3 module works). `winget install SQLite.SQLite` if wanted. |
| ruff | not global; installed in project `.venv` |
| Playwright | `pip install --dry-run playwright` resolves; npm registry has 1.64.1. **Browsers not downloaded or tested** (`playwright install chromium` is a later step; needs a large download). |
| gh | logged in as satvikp-coder |

No system packages were installed.

## Verified results (Prompt 3, 2026-10-27)
- `ruff check .` -> All checks passed!
- `pytest -rs` -> **597 passed, 0 skipped** in 86 s. **58 browser (Chromium) tests actually ran**, 0 failed, 0 skipped.
- Chromium installed with `python scripts/setup_browsers.py` (Playwright cache, no system packages). Browser tests skip with a clear message locally if Chromium is missing and FAIL when `SENTINELX_CI=1`.
- `python scripts/demo_agent_lab.py` runs 6 scenarios x 2 arms and prints the comparison table.
- The lifecycle/cleanup browser tests were run 5 times in a row (17/17 each) after the fixes below.
- Local commits only; not pushed. CI has not run these commits on GitHub (Linux CI needs `playwright install --with-deps`; the workflow now does that, untested).

## Implemented (Prompt 3; the agent is a SIMULATED scripted program, not an LLM)
- `apps/fixture_lab`: one FastAPI app, 127.0.0.1 on an OS-chosen port, exact Host-header vhosts (orders / calendar / support / collector `.lab.test`), per-run JSONL side-effect ledger, token+loopback admin endpoints, deterministic seeded reset and `fixture_hash`. Hand-authored pages and payloads in `fixtures/` (8 scenarios: S1, S1_TOOL, S2, S2_HIDDEN, S3, B1, B2, B3).
- `sentinelx.agent_runtime`: `ScriptedNaivePlanner` behind a `Planner` interface, Playwright adapter behind a SANDBOX BOUNDARY (separate from the policy gateway, both arms), protected/unprotected run loop with evidence, kill switch, cancellation, step and wall-clock limits.
- `sentinelx.verifier`: independent verifier (ledger + evidence only), stored as a VERIFIED event and in the `verifications` table (migration 0002).
- `configs/policy/lab.yaml`, `synth_tok_` redaction.

## Findings worth knowing
- Playwright does NOT call `page.route` handlers for the targets of browser-followed redirects (found by test: a redirect to the collector reached the ledger). The adapter now follows redirects itself, hop by hop.
- Cancelling Playwright during its own start-up leaves its connection tasks pending and hung `asyncio.run` shutdown (and leaked the Node driver). The wall-clock budget now starts after the browser is up.
- In the lab, signals (hints) did not fire for the cancel/upload wording; the protected-arm blocks came from deterministic rules (`SECRET_EGRESS`, `TOOL_NOT_IN_SCENARIO`).

## Known gaps
- Organizers' reply text still not recorded in docs/RULES_COMPLIANCE.md.
- No model exists anywhere yet; "attack success" here describes a scripted gullible program, not LLM behaviour. Paired runners/metrics come next.
- Subresource exfiltration (a hostile page embedding a collector image) is not policy-checked; the sandbox allows any `*.lab.test` host (docs/THREAT_MODEL.md).
- `http_request` is blocked outright by the lab policy; no per-method / per-endpoint HTTP policy yet.
- The wall-clock budget excludes browser start-up (bounded only by Playwright's launch timeout).
- `SessionContext.page_origin` is the adapter's current page URL; after an adapter-followed redirect Chromium's URL stays the originally requested one (all hops were vetted).
- Tail truncation of an evidence chain still needs an external anchor hash.

## Blockers / open items
- php missing; Docker daemon not running (labs run on the local FastAPI app for now).
- License pending (docs/DECISIONS.md).
- docs/RULES_COMPLIANCE.md items all unchecked.
- Legacy credentials must be rotated (docs/LEGACY_CODE_AUDIT.md).

## Commits
See `git log --oneline`. Setup commit `865823f` (2026-10-27 05:32 IST / 00:02 UTC). Prompt 3 commits: L1 browser gating, L2 lab, L3 verifier, L4 runtime, L5 demo/docs/fixes.

## Next step
Wait for the developer to start Prompt 4 (paired experiment runners and metrics).
