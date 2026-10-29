# Scan report - vibe_notes_node

## Provenance

| field | value |
|---|---|
| git_commit | fa56fce24f7dbff992ec9b99f9fa8465b931017b |
| date_utc | 2026-10-29T02:39:12Z |
| scanner_version | scanner-1.0 |
| profile_name | lab_default |
| profile_version | lab-default-1 |
| profile_sha256 | 2ac0367ed54103229ba12d6f085d73b3cb1f77fb8357d749283649c3c48a942a |
| target_id | vibe_notes_node |
| target_lab | True |
| authz_status | VERIFIED |
| session_id | ses_e174a1a1313346a3aea76bf053e8af53 |
| coverage_percent | 97.3 |
| requests_used | 123 |
| request_budget | 500 |
| duration_ms | 25347.5 |
| stop_reason | completed |
| plan_prompt_version | scan_prompt_v1 |
| explain_prompt_version | explain_prompt_v1 |
| model | {'provider': 'nvidia', 'model': 'meta/muse-glimmer-30b', 'mode': 'LIVE'} |

## Findings by class

| vuln_class | confirmed | needs_validation | rejected |
|---|---|---|---|
| sensitive_file_exposure | 1 | 1 | 0 |
| security_headers_and_cookies | 2 | 0 | 0 |
| debug_exposure | 1 | 0 | 0 |
| missing_authentication | 1 | 0 | 0 |
| broken_object_authorization | 3 | 0 | 0 |
| missing_rate_limit | 0 | 1 | 0 |
| permissive_cors | 1 | 0 | 0 |
| sql_injection | 1 | 0 | 0 |
| verbose_errors | 1 | 0 | 0 |

## Coverage: 97.3%

Skipped checks: none

## Limitations

- Lab-only synthetic targets: non-lab scanning is disabled by the authorization gate.
- The scanner and the labs were authored in the same project: recall measures how well this scanner finds weaknesses planted in OUR OWN labs, not its performance against real sites.
- Behavioural findings (missing_rate_limit) are weaker evidence than a structural reproduction and never reach the 'confirmed' state; they stay 'needs_validation'.
- A confirmed finding that matches no planted class/endpoint is reported separately for manual review; it may be a real, unplanted weakness and is never counted as a false positive automatically.
- No claim of complete coverage is made; the coverage ledger lists every unexercised cell and why.
- The model, when used, only orders/selects checks from the fixed catalog and writes explanations of already-confirmed findings; it never decides what is vulnerable.
