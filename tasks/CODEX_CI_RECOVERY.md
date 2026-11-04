# CI recovery after the completion merge

The first hosted run for `13212a5` was NOT green:
[run 41826402330](https://github.com/satvikp-coder/sentinelx/actions/runs/41826402330).
Actual summary: **8 failed, 1558 passed, 1 skipped, 12 errors**.
The web job passed. The live-model test was skipped; no real model ran.

## Corrected causes

1. `apps/labctl.py`: Linux rejects binding a wildcard socket when a loopback
   listener already owns the port. That failure does not prove a wildcard
   listener exists. Verification now inspects the positively identified process's
   actual TCP listening addresses and retains local-interface reachability probes.
   PID ownership includes the lab's cwd and server script; shutdown refuses a
   reused PID belonging to another Node application.
2. PHP fixture bind mounts hide the image's `/data` ownership. Prepare only the
   registered synthetic scratch directories for both Apache's container UID and
   host test cleanup. Reject redirected data paths before making directories or
   changing modes. No production/source directory receives these permissions.
   A container preflight checks SQLite PDO and scratch writeability explicitly.
   Hosted Linux/Docker execution is required to close this gate.
3. `packages/shield/rules.py`: Python 3.11 enum containment raises for strings.
   Validate by constructing `ShieldAction`, rejecting ValueError/TypeError with
   a safe constant diagnostic. No authorization behavior is loosened.
4. `packages/fixer/models.py`: reject Windows drive, UNC and backslash traversal
   syntax on every host before resolving the disposable scope path. Keep the
   existing canonical containment/symlink check and avoid echoing rejected input.
5. `scripts/final_run.py`: every dry-run step is marked unexecuted, including
   steps with missing prerequisites. Preserve planned provider/cost estimates and
   report prerequisite notes separately. Resolve a newly generated scan report
   when the fix stage actually executes, rather than skipping a fresh pipeline
   because no report existed when the plan was built. No live calls were tested.
6. `numbers_signature()` compares stable security outcomes and exact tool-decision
   counts. Only browser egress request multiplicity is compared as control
   presence: Chromium may retry a blocked request. Raw event counts remain
   unchanged in reports and evidence. Missing controls, changed tool counts and
   changed outcome numerators still change the signature. No claimed benchmark
   rate or historical evidence was rewritten.
7. Runtime publication now requires an already-activated lifecycle object before
   its atomic durable publication. It does not promote a proposal merely because
   a caller supplied approval metadata. This also removes a confusing indirect
   ACTIVE constant while preserving the activation-assignment audit.
8. Declare `psutil` as a runtime dependency, not a dev-only dependency: normal
   lab-manager execution imports it. A fresh plain `pip install -e .` environment
   successfully imported psutil, the lab manager and the CLI without dev extras.

## Execution so far

- Focused portability, final-run and Node-lab checks: **37 passed, 2 skipped,
  8 deselected**, exit 0. Windows skips explicitly cover POSIX modes and symlink
  permission; the Docker cases were deselected, not marked passed.
- Actual Chromium reproducibility check: **1 passed**, exit 0.
- Shield staging/publication/approval checks: **26 passed**, exit 0.
- Complete worker fast suite: **1439 passed, 2 skipped, 150 deselected**, exit 0 (610.38s).
  The additional staging guard was verified by its separate focused group.
- Project Ruff and diff whitespace checks passed.
- Complete worker/post-merge/hosted results must be taken from the final audit,
  not inferred from these focused counts.

## Reproduction method

Use the reviewed Python environment; use a fresh external `--basetemp` and
`-p no:cacheprovider`. Run the full fast suite, the exact browser reproducibility
case, and all Docker/PHP checks on a Linux runner with the daemon available.
CI explicitly installs Python 3.11, Node 22, the Python SDK and Playwright.
Never bypass the tests, edit sealed policy/reference fixtures, use real provider
credentials, or treat skipped/collected cases as passes. Preserve raw request
telemetry and genuine verification outcomes when investigating nondeterminism.
