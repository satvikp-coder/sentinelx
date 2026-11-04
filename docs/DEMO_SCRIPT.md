# Reproducible local demo

For the timed submission recording, use [SUBMISSION_DEMO_SCRIPT.md](SUBMISSION_DEMO_SCRIPT.md)
and [SUBMISSION_RECORDING_GUIDE.md](SUBMISSION_RECORDING_GUIDE.md). The latter gives
actual launch/public-API commands and cleanup; the outline below is historical context.

**Scope:** local single-operator prototype; synthetic traffic; no provider calls.
**Label:** TEMPORARY SHIELD, NOT A FIX.

1. Install `pip install -e ".[dev]"` and `pip install -e sdk/python`.
2. Run `npm install`, `npm run build`, and `npm test --workspace sdk/typescript`.
3. Demonstrate the real separate-process workflow:
   `python -m pytest tests/integration/test_shield_public_processes.py -q -p no:cacheprovider --basetemp=PATH_TO_A_NEW_TEMP_DIRECTORY`.
   Choose a fresh directory outside the repository. The test starts loopback-only
   API/proxy/upstream processes, uses public approvals, checks actual upstream
   receipt, and cleans up its own processes. It also verifies natural TTL,
   manual expiry/removal, mode separation, kill switch and both process restarts.
4. For the dashboard, run the API on `127.0.0.1:8080`, the Shield factory with
   the same `SHIELD_RUNTIME_DB` and `SHIELD_UPSTREAM`, then preview the built web
   app on loopback. Set `SHIELD_MODE=enforce` explicitly only for this authorized
   synthetic demo; the default remains monitor.
5. Open Live Shield: propose a narrow rule, create a local approval session,
   inspect the displayed content, then choose Approve and activate. Show matching
   proxy traffic blocked and benign traffic forwarded. Show durable evidence,
   expire/remove the rule, and show traffic passing again.
6. Explain boundaries: a representative replay is not a universal false-positive
   guarantee; a proxy rule is not a verified patch. API/session authentication is
   for one trusted local demo operator. Models do not authorize actions.

Show only actual run evidence. Do not advertise live model comparisons, PHP/Docker
coverage, external scanner execution or published CI results unless those checks
actually ran successfully for the demonstrated revision. See the completion report
for observed counts and remaining owner gates. Recording and submission are owner actions.
