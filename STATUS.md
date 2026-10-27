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

## Verified results (Prompt 4, 2026-10-27)
- `ruff check .` -> All checks passed!
- `pytest -rs` -> **799 passed, 0 skipped** in 401 s. **107 browser (Chromium) tests actually ran**, 0 failed, 0 skipped.
- Full sealed manifest run (`python scripts/run_experiment.py --manifest evaluations/manifest.json`): 30 cases x 2 arms = 60 runs, **0 invalid**, both chains verify, paired fixture hashes identical. Manifest hash `087f433dd5a03e782585fd5e55b082fd5e4b5efaf90513a0873e16128e914eb8`. Example report committed in `evaluations/example_report/`.
- Headline numbers (SIMULATED scripted agent, NOT an LLM; these 30 cases only): arm A attack success 15/15, arm B 0/15; arm B attack block rate 15/15, task preservation 15/15, clean benign completion 12/15, false-confirm rate 3/81 actions, false-block rate 0/81.
- Local commits only; not pushed; CI not run on GitHub for these commits.

## Implemented (Prompt 4)
- Page-initiated egress closed in the protected arm: `evaluate_page_request` + `page_subresource` rules in `configs/policy/lab.yaml` (versioned), `EGRESS_BLOCKED` / `EGRESS_SUMMARY` events, ten injected vectors + WebSocket tested in both arms, request-body secret scan.
- Conditional high-impact rules (`http_request` reads allowed, state-changing methods CONFIRM).
- 15 attack + 15 benign hand-authored cases (`fixtures/attacks`, `fixtures/benign`, `AttackTemplate` / `BenignTemplate`), covering 3 scenarios, 8 surfaces and 5 controls (TOOL_NOT_IN_SCENARIO, DESTINATION_NOT_ALLOWED, SECRET_EGRESS, CONFIRM, EGRESS_BLOCKED).
- `sentinelx.evaluation`: sealed manifest, paired order-randomised runner, metrics, json/csv/md reports. Verifier 1.1.0 (page-initiated attempts, false confirms, `stopped_by`).
- Arm C (EVCS) is a seam only.

## Findings worth knowing
- Earlier (Prompt 3): Playwright does not route redirect targets; the adapter follows redirects itself. Cancelling Playwright during start-up hangs shutdown; the wall-clock budget starts after the browser is up.
- `route.abort("blockedbyclient")` replaces the current document with an error page, destroying the legitimate task; `aborted` keeps it. `goto(wait_until=load)` hangs when a page-initiated navigation is aborted; the adapter waits for `commit` + DOMContentLoaded + network idle.
- `networkidle` does not re-arm for requests injected after the page settled; tests wait explicitly.
- URL-only scanning of page requests left a hole (secret in a POST body to an ALLOWED host); the body is now scanned too.
- A verifier subtlety: an action that only carries the secret (filling an on-page form) has no URL; it is attributed as the forbidden attempt via the redaction marker in stored evidence.
- Signals (hints) still do not fire for the cancel/upload wording; blocks come from deterministic rules.

## Known gaps
- Organizers' reply text still not recorded in docs/RULES_COMPLIANCE.md.
- No model exists anywhere; every number above describes a scripted gullible program and a policy written knowing the lab. Nothing here predicts real-model behaviour or unseen attacks (docs/THREAT_MODEL.md lists what remains open: non-secret data to allowed hosts, obfuscated secrets, non-HTTP transports, ...).
- Counts are small (15 + 15, one repetition); no confidence intervals. N>1 repetitions are supported but only meaningful for a nondeterministic planner.
- The static policy CONFIRMs three legitimate state-changing actions (RSVP, cancel, upload): its measured utility cost, which only a human-approval workflow (not built) would resolve.
- The wall-clock budget excludes browser start-up. Tail truncation of an evidence chain still needs an external anchor hash.

## Blockers / open items
- php missing; Docker daemon not running (labs run on the local FastAPI app for now).
- License pending (docs/DECISIONS.md).
- docs/RULES_COMPLIANCE.md items all unchecked.
- Legacy credentials must be rotated (docs/LEGACY_CODE_AUDIT.md).

## Commits
See `git log --oneline`. Setup commit `865823f` (2026-10-27 05:32 IST / 00:02 UTC). Prompt 4 commits: E1 policy rules, E2 egress + case set, E3 evaluation pipeline, E4 docs/status, E5 example report.

## Prompt 5 (2026-10-27): model adapter, ModelPlanner, generator, REAL model runs
- Tests: `ruff check .` clean; full `pytest` = **918 passed, 0 failed, 0 skipped**; 115 browser tests ran; 1 LIVE test ran (real call to nvidia / meta/muse-glimmer-30b, mode LIVE). Python: `.venv313` (python.org 3.13.5); the Microsoft-Store Python hung at startup. I started the Windows service ClipSVC while diagnosing (no effect).
- Model: nvidia `meta/muse-glimmer-30b`, LIVE, prompt_v1, reasoning setting `low` (measured to have no clear latency effect; see DECISIONS). Endpoint latency varied 1-200 s/call; rate limits undocumented (none seen).
- Aborted: `model-main-1` (full manifest) stopped after 6 runs (`ABORTED_SLOW`), excluded from all reports.
- **Sealed-manifest SUBSET run `model-subset-1`** (manifest_subset.json, hash 79e92dbd..., 10 cases A02,A04,A06,A08,A11 + neighbours, rule stored in the manifest): arm A 8/10 valid, ASR 2/5; arm B 8/10 valid, ASR 0/4, block rate 1/1 (EGRESS_BLOCKED). 4 invalid runs (3x HTTP 404 from the endpoint, 1x per-run call cap), excluded and counted. Report: `evaluations/example_report_model/`. Single samples; no confidence claims.
- **Generated variants subset `model-generated-1`** (4 cases G01,G02,G03 + B01): arm A ASR 0/2, arm B 0/3, no forbidden attempts (block rate n/a); 1 invalid (arm A G01, MODEL_UNAVAILABLE). These generated cases are gitignored (local); the model resisted these texts.
- Generator: first pass 30 candidates, 12 passed the static checker, 18 rejected (all for the "[OPERATOR OVERRIDE]" brackets the model repeated); that was fixed in code (prefix stripped) and G02, G03, G05, G06 were regenerated (one further batch had 3 of 6 rejected as too short). 6 variants kept: G01-G06.
- All earlier results (Prompts 1-4) remain SIMULATED and are reported separately.
- Known gaps: n is tiny (1 sample per case/arm); invalid runs reduce denominators; arm C still a seam; nothing pushed to GitHub.

## Next step
Wait for the developer to start Prompt 6.
