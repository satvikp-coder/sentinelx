# MIT licensing and unknown model costs — local verification

Owner requested integration of `fc6d639`, MIT licensing (Satvik Patel, 2026),
truthful NVIDIA pricing and local checks. No push is authorized until the owner
sends `push`. No provider call or real credential-file read was performed.

## Integration and preservation

Full `git show fc6d639` reviewed: 21 documentation/ignore files, including root
README.md and scripts/README.md as documentation outside docs/tasks. No application
source in that commit. Main fast-forwarded normally from d855c4e to fc6d639.
The newer untracked final-check snapshot was preserved before integration at:
`C:/Users/satvi/AppData/Local/Temp/sentinelx-license-cost-c3f0779eda9a4793afe6fe4cc2ed8cc7/FINAL_CHECK.before-merge.md`.
The committed historical report remains intact, with this follow-up noted.

## Changes

- Root LICENSE and sdk/python/LICENSE: MIT, copyright (c) 2026 Satvik Patel.
  Both pyproject.toml files declare the corresponding license file.
- NVIDIA unverified prices are explicit YAML nulls, not placeholder zero rates.
  The estimator returns None for unverified or missing prices.
- CLI, final-run and reports show **unknown (free tier, not billed)** for the
  unpriced NVIDIA integration. This is an uncertainty label, not a provider invoice.
- Final-run manifests keep an unknown overall total null and report known subtotal
  plus unknown-step names separately. They never silently drop unknown steps.
- SQL spend aggregation propagates unknown recorded costs instead of SUM/COALESCE
  treating them as zero. Budgeted unknown usage refuses further calls until
  reconciled; thresholds remain hard 70 / warning 50 / reserve 30 USD.
- Fix batch reports format unknown spend/caps safely. Legacy NVIDIA zero report
  amounts are normalized only in the display layer; stored reports are not rewritten.
- Submission documentation records the owner's MIT decision.
- Eight production-path regression cases cover estimator/CLI, dry-run and executed
  manifest totals, mixed known/unknown ledgers, refusal and legacy HTML/provenance.

## Actual checks

Interpreter: `C:/Users/satvi/Desktop/sentinelx-ds/.venv/Scripts/python.exe`.
CWD: `C:/Users/satvi/Desktop/AI Cybersecurity`.
An external pytest launcher forwards to real pytest with main-source imports,
external evidence paths and credential/network guards; actual credential files
are unavailable to tests, while synthetic configuration fixtures remain unchanged.
No policy, scanner authorization/HTTP, PLANTED or tracked reference file was edited.

```text
python -m ruff check .
All checks passed!
exit 0
```

Focused command: pytest on test_cost_uncertainty.py, test_model_profiles.py,
test_final_run.py, test_report.py and test_ci_portability.py with a fresh external
basetemp, `-q -o addopts= -rs -p no:cacheprovider`:

```text
SKIPPED [1] tests\unit\test_ci_portability.py:61: POSIX bind-mount permissions require Linux
SKIPPED [1] tests\unit\test_ci_portability.py:84: directory symlink permission unavailable
52 passed, 2 skipped in 3.72s
EXIT=0
```

Full command forwarded by the external launcher:
`pytest -m "not slow" -q -o addopts= -rs -p no:cacheprovider`
with fresh basetemp
`C:/Users/satvi/AppData/Local/Temp/sentinelx-license-cost-c3f0779eda9a4793afe6fe4cc2ed8cc7/full-fast-fresh`.

Actual tail:

```text
........................................................................ [ 99%]
..........                                                               [100%]
docker-dependent tests actually ran: 0 (0 passed, 0 failed, 0 skipped)
browser tests actually ran: 0 (0 passed, 0 failed, 0 skipped)
=========================== short test summary info ===========================
SKIPPED [1] tests\unit\test_ci_portability.py:61: POSIX bind-mount permissions require Linux
SKIPPED [1] tests\unit\test_ci_portability.py:84: directory symlink permission unavailable
1448 passed, 2 skipped, 150 deselected in 587.84s (0:09:47)
EXIT=0
```

Both Python wheels built with normal isolated build dependencies. Their METADATA
and included license files were inspected and contain MIT / 2026 Satvik Patel.
The first optional offline/no-build-isolation attempt failed because the worker
venv has no setuptools backend; the isolated build succeeded without altering it.

`git diff --check`: exit 0. Protected tracked path diff: empty.
Logs and wheel artifacts are retained in the external directory above.
These new local source changes have no hosted CI result yet; historical green CI
at d855c4e is not attributed to this unpushed revision.

PUSHED: NO. Visibility/deployment/provider usage: unchanged.
