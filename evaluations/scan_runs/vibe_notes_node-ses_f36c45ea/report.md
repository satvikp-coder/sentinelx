# Scan report - vibe_notes_node

## Provenance

| field | value |
|---|---|
| git_commit | 9b134d78e62d75d0cd794c9ccf5c579447e744c2 |
| date_utc | 2026-10-29T02:06:51Z |
| scanner_version | scanner-1.0 |
| profile_name | lab_default |
| profile_version | lab-default-1 |
| profile_sha256 | 2ac0367ed54103229ba12d6f085d73b3cb1f77fb8357d749283649c3c48a942a |
| target_id | vibe_notes_node |
| target_lab | True |
| authz_status | VERIFIED |
| session_id | ses_f36c45ea9aa84da281debdb167599746 |
| coverage_percent | 93.1 |
| requests_used | 71 |
| request_budget | 500 |
| duration_ms | 3294.7 |
| stop_reason | completed |
| plan_prompt_version | None |
| explain_prompt_version | None |
| model | {'provider': 'none', 'model': 'none', 'mode': 'none'} |

## Findings by class

| vuln_class | confirmed | needs_validation | rejected |
|---|---|---|---|
| security_headers_and_cookies | 2 | 0 | 0 |
| permissive_cors | 1 | 0 | 0 |
| verbose_errors | 1 | 0 | 0 |
| missing_rate_limit | 0 | 1 | 0 |

## Coverage: 93.1%

Skipped checks: none

## Limitations

- Lab-only synthetic targets: non-lab scanning is disabled by the authorization gate.
- The scanner and the labs were authored in the same project: recall measures how well this scanner finds weaknesses planted in OUR OWN labs, not its performance against real sites.
- Behavioural findings (missing_rate_limit) are weaker evidence than a structural reproduction and never reach the 'confirmed' state; they stay 'needs_validation'.
- A confirmed finding that matches no planted class/endpoint is reported separately for manual review; it may be a real, unplanted weakness and is never counted as a false positive automatically.
- No claim of complete coverage is made; the coverage ledger lists every unexercised cell and why.
- The model, when used, only orders/selects checks from the fixed catalog and writes explanations of already-confirmed findings; it never decides what is vulnerable.
