# Shield Recovery — Test Matrix

**Date:** 2026-11-04
**Interpreter:** `C:\Users\satvi\Desktop\sentinelx-ds\.venv\Scripts\python.exe`
**Basetemp:** external unique dirs under `%TEMP%\opencode\...`, `-p no:cacheprovider`

## SH-01..SH-08 defect regressions

| Defect | Test | Location | Result |
|--------|------|----------|--------|
| SH-01 canonical subject | `test_sh06_approval_subject_is_canonical` | test_shield_recovery_failures.py | PASS |
| SH-01 valid activation | `test_shield_approve_valid_approves_rule` | test_api_units.py | PASS |
| SH-01 duplicate/not-PROPOSED | `test_shield_approve_duplicate_is_idempotent` | test_api_units.py | PASS |
| SH-02 cross-process enforcement | `test_e2e02_separate_proxy_process_enforces_api_activation` | test_shield_e2e_public_api.py | PASS |
| SH-02 separate object graph | `test_sh02_separate_proxy_process_enforces_api_activation` | test_shield_recovery_failures.py | PASS |
| SH-02 tampered ACTIVE row never enforced | `test_sh02_runtime_store_rejects_tampered_payload` | test_shield_recovery_failures.py | PASS |
| SH-02 natural TTL | `test_sh02_runtime_store_expires_overdue` | test_shield_recovery_failures.py | PASS |
| SH-03 manual expiry stops proxy | `test_e2e_manual_expiry_and_removal_stop_enforcement` | test_shield_e2e_public_api.py | PASS |
| SH-03 manual removal stops proxy | `test_e2e_manual_expiry_and_removal_stop_enforcement` | test_shield_e2e_public_api.py | PASS |
| SH-03 cross-process removal | `test_sh02_separate_proxy_process_enforces_api_activation` (part 2) | test_shield_e2e_public_api.py | PASS |
| SH-04 evidence failure rollback | `test_sh04_evidence_failure_rolls_back_runtime` | test_shield_recovery_failures.py | PASS |
| SH-04 runtime-store failure rollback | `test_sh04_runtime_store_failure_rolls_back` | test_shield_recovery_failures.py | PASS |
| SH-05 gate rejection without evidence | `test_sh05_gate_rejection_without_evidence_does_not_crash` | test_shield_recovery_failures.py | PASS |
| SH-05 proposal has real evidence | `test_sh05_api_proposal_has_real_evidence` | test_shield_recovery_failures.py | PASS |
| SH-06 cross-session denied | `test_e2e_cross_session_approval_cannot_activate` | test_shield_e2e_public_api.py | PASS |
| SH-06 revoked approval denied | `test_e2e_revoked_approval_cannot_activate` | test_shield_e2e_public_api.py | PASS |
| SH-06 modified rule invalidates approval | `test_e2e_modified_rule_invalidates_approval` | test_shield_e2e_public_api.py | PASS |
| SH-07 proxy log redaction | `test_sh07_proxy_request_log_redacts_paths` | test_shield_recovery_failures.py | PASS |
| SH-07 API echo redaction | `test_sh07_api_response_redacts_rule_echo` | test_shield_recovery_failures.py | PASS |
| SH-07 SSE/evidence redaction | `test_e2e_sse_activation_event_is_redacted` | test_shield_e2e_public_api.py | PASS |
| SH-08 real upstream + real proxy | `test_e2e_full_lifecycle_block_and_benign` | test_shield_e2e_public_api.py | PASS |
| SH-08 blocked request never reaches upstream | same | test_shield_e2e_public_api.py | PASS |
| SH-08 unauthenticated denied | `test_e2e_unauthenticated_activation_rejected` | test_shield_e2e_public_api.py | PASS |
| SH-08 failed activation no orphan | `test_e2e_failed_activation_no_orphan` | test_shield_e2e_public_api.py | PASS |
| SH-08 broad/invalid rule rejected | `test_e2e_broad_rule_rejected`, `test_e2e_invalid_route_pattern_rejected` | test_shield_e2e_public_api.py | PASS |

## Negative/security matrix

| Scenario | Expected | Test | Result |
|----------|----------|------|--------|
| Missing approval | 400 denied | test_shield_approve_rejects_missing_approval | PASS |
| Wrong action id | 400 denied | test_shield_approve_rejects_wrong_action_id | PASS |
| Cross-session approval | 400 denied | test_shield_approve_rejects_cross_session | PASS |
| Rejected approval | 400 denied | test_shield_approve_rejects_rejected_approval | PASS |
| Revocation defeats approval | 400 denied | test_e2e_revoked_approval_cannot_activate | PASS |
| Approval once, rule modified | 400 denied | test_e2e_modified_rule_invalidates_approval | PASS |
| Unknown rule | 400/404 denied | test_shield_activation_unknown_rule_rejected | PASS |
| Broad rule | 400 rejected | test_shield_broad_rule_rejected / test_e2e_broad_rule_rejected | PASS |
| Kill switch | 400 denied, no activation | (code path; kill-switch proxy tests PASS) | PASS |
| Duplicate activation | second 400, ACTIVE preserved | test_shield_approve_duplicate_is_idempotent | PASS |
| Tampered runtime row | never enforced | test_sh02_runtime_store_rejects_tampered_payload | PASS |
| Natural expiry | enforcement stops | test_sh02_runtime_store_expires_overdue + list mirroring | PASS |
| Noise/redaction | no markers in logs/evidence/SSE | SH-07 tests above | PASS |

## Commands and exit codes (executed)

| Command | Result |
|---------|--------|
| `pytest tests/unit/test_shield_rules.py tests/unit/test_shield_proxy.py tests/unit/test_shield_modes_approval.py tests/unit/test_shield_modes_sim_isolation.py tests/unit/test_shield_model.py tests/unit/test_shield_intent.py tests/unit/test_shield_intent_aggregate.py tests/unit/test_shield_isolation.py tests/unit/test_shield_evidence.py tests/unit/test_shield_detect.py tests/unit/test_shield_config.py tests/unit/test_shield_activation_integration.py tests/unit/test_shield_e2e_public_api.py tests/unit/test_shield_recovery_failures.py tests/unit/test_api_units.py tests/unit/test_api_security_repair2.py` | all passed, exit 0 |
| `pytest tests/integration/test_labs.py` | 26 passed, 8 docker-skipped, exit 0 |
| `pytest tests/integration/test_scanner_against_labs.py` | 10 passed, 4 docker-skipped, exit 0 |
| `ruff check .` | All checks passed, exit 0 |
| `git diff --check` | clean, exit 0 |

## Known environment issue fixed

The earlier full-suite failures (5 failed, 8 errors) were caused by a lab Node
process (`node --no-warnings server.js`, PID 24524) **started by this session
earlier** holding `labs/vibe_notes_node/data/notes.db`. The process was
verified by command line, stopped (only that PID), and the lab suites now
pass. No other Node processes were touched (Codex tooling PIDs 9196/22384 left
untouched). No database was deleted or modified; no reference labs changed.
