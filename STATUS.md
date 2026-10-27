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

## Verified results (Prompt 2, 2026-10-27)
- `ruff check .` -> All checks passed!
- `pytest` -> 443 passed, 0 skipped (adds policy table tests, ~60 URL cases, signal tests, hypothesis property tests with 1000 examples each, evidence integration, static purity checks).
- `python scripts/demo_policy.py` prints decision / rule_ids / reason_code for 12 sample actions.
- Local commits only; not pushed. CI not re-run on GitHub for these commits.

## Implemented (Prompt 2; no model calls, browser or network anywhere in the policy package)
- `sentinelx.policy`: frozen content-addressed policy config (`configs/policy/{default,strict,monitor}.yaml`), pure `evaluate()` pipeline, strict URL normaliser/matcher with `check_redirect`, evidence-only signal helpers (`configs/policy/signals.yaml`), `decide_and_record` evidence recorder (`sentinelx.policy.gateway`).
- Additive schema fields for monitor mode, signals and `ApprovalRequest` (see docs/DECISIONS.md).
- Still planned: agent runtime, fixtures, model client, scanner, shield, SDK, CLI, API, dashboard.

## Known gaps
- Organizers' reply text still not recorded in docs/RULES_COMPLIANCE.md.
- The gateway decides only; nothing executes or enforces it yet (no runtime exists). `SessionContext` counters (`steps_taken`, `last_step`, `requests_last_minute`) must be supplied by the future runtime.
- Argument-level URL detection relies on the policy's `url_args`; a URL hidden in a non-URL argument is only caught by secret/egress rules and signals.
- Redirect checking (`check_redirect`) exists but nothing calls it yet.
- Tail truncation of an evidence chain still needs an external anchor hash.

## Blockers / open items
- php missing; Docker daemon not running; Playwright browsers untested.
- License pending (docs/DECISIONS.md).
- docs/RULES_COMPLIANCE.md items all unchecked.
- Legacy credentials must be rotated (docs/LEGACY_CODE_AUDIT.md).

## Commits
See `git log --oneline`. Setup commit `865823f` (2026-10-27 05:32 IST / 00:02 UTC); Prompt 1 commits follow it (A1-A5, contracts, persistence, evidence, state machine).

## Next step
Wait for the developer to start Prompt 3.
