# Shield evaluation: three-way run through a real proxy

Generated 2026-10-30T14:54:45+00:00. Lab `vibe_notes_node`, reset before each arm. Tables are generated only from `requests.jsonl` and the proxy's own stats endpoint.

Columns: sent / reached upstream / **blocked by shield (X-Sentinel-Shield marker)** / lab responded 4xx-5xx (informational, NOT counted as blocked).

## Attack traffic, per arm

| Arm | sent | reached upstream | blocked by shield | lab 4xx/5xx | records |
|---|---|---|---|---|---|
| A: no shield | 65 | 65 | 0 | 46 | 107 |
| B: monitor | 65 | 65 | 0 | 46 | 107 |
| C: enforce + auto_shield | 65 | 27 | 38 | 13 | 107 |

## Per stage (sent / reached / blocked by shield / lab 4xx-5xx)

| Stage | A: no shield | B: monitor | C: enforce + auto_shield |
|---|---|---|---|
| recon | 17 / 17 / 0 / 12 | 17 / 17 / 0 / 12 | 17 / 12 / 5 / 7 |
| failed_logins | 15 / 15 / 0 / 15 | 15 / 15 / 0 / 15 | 15 / 5 / 10 / 5 |
| object_enum | 19 / 19 / 0 / 13 | 19 / 19 / 0 / 13 | 19 / 1 / 18 / 0 |
| injection | 8 / 8 / 0 / 1 | 8 / 8 / 0 / 1 | 8 / 8 / 0 / 1 |
| admin_probe | 6 / 6 / 0 / 5 | 6 / 6 / 0 / 5 | 6 / 1 / 5 / 0 |

## Intent accuracy (shield's own labels vs stage ground truth; unlabelled = miss)

| Stage | A: no shield | B: monitor | C: enforce + auto_shield |
|---|---|---|---|
| recon | n/a | 6/17 correct (6 labelled) | 6/17 correct (6 labelled) |
| failed_logins | n/a | 10/15 correct (14 labelled) | 10/15 correct (10 labelled) |
| object_enum | n/a | 0/19 correct (19 labelled) | 0/19 correct (19 labelled) |
| injection | n/a | 3/8 correct (8 labelled) | 3/8 correct (8 labelled) |
| admin_probe | n/a | 0/6 correct (6 labelled) | 0/6 correct (6 labelled) |

## Arm C: rules and time-to-protect

Proposed 30, activated 26, rejected by the benign-replay gate 4, escalations 4, rejected by the compiler 0. Rules proposed against the BENIGN client (false-positive detections): 0.

| Stage | time-to-protect (s from stage's first request to first ACTIVE rule covering it) |
|---|---|
| recon | 0.047 |
| failed_logins | 0.139 |
| object_enum | 0.016 |
| injection | not protected |
| admin_probe | 0.0 (rule already active before the stage began) |

Activated rules:

- ACTIVE: `block_route_pattern` route `/.env` (RECON)
- ACTIVE: `block_route_pattern` route `/.git` (RECON)
- REJECTED by gate: `block_route_pattern` route `/debug` (RECON)
- ACTIVE: `block_route_pattern` route `/admin` (RECON)
- ACTIVE: `block_route_pattern` route `/phpinfo` (RECON)
- ACTIVE: `block_route_pattern` route `/info` (RECON)
- ACTIVE: `rate_limit_client` route `/api/login` (CREDENTIAL_GUESSING)
- REJECTED by gate: `rate_limit_client` route `/api/notes/1` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/2` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/3` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/4` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/5` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/6` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/7` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/8` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/9` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/10` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/11` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/12` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/13` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/14` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/15` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/16` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/17` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/18` (CREDENTIAL_GUESSING)
- ACTIVE: `rate_limit_client` route `/api/notes/19` (CREDENTIAL_GUESSING)
- REJECTED by gate: `reject_param_pattern` route `/api/search` param `q` (INJECTION_PROBE)
- REJECTED by gate: `rate_limit_client` route `/api/search` (CREDENTIAL_GUESSING)
- ACTIVE: `block_route_pattern` route `/admin/users` (RECON)
- ACTIVE: `block_route_pattern` route `/admin/settings` (RECON)

## Benign traffic

| Arm | sent | falsely blocked or altered (marker) | lab 4xx/5xx |
|---|---|---|---|
| A: no shield | 40 | 0 | 0 |
| B: monitor | 40 | 0 | 0 |
| C: enforce + auto_shield | 40 | 0 | 0 |

## Latency (ms, shield overhead measured in the proxy over real HTTP)

| Arm | shield p50 / p95 | client end-to-end p50 / p95 |
|---|---|---|
| A: no shield | n/a | 1.422 / 31.191 (n=107) |
| B: monitor | 0.292 / 0.584 (n=108) | 3.462 / 36.62 (n=107) |
| C: enforce + auto_shield | 0.268 / 1.05 (n=108) | 5.671 / 59.583 (n=107) |

## Suspiciously good numbers / caveats raised by the run

- arm C: 0 benign false blocks is by construction: every rule is scoped to the attacker's client key, and benign traffic uses another key

## Limitations

- One scripted attacker, one run per arm, no repetition: no confidence intervals.
- The per-request intent label comes from deterministic signals; requests that fire no signal are unlabelled and count as misses.
- Rules take effect only after enough requests to fire a signal (behavioural signals need 5 to 10 requests), so early requests of a stage reach the lab before activation.
- Every rule is scoped to the flagged client key (the `X-Lab-Client` header in lab mode), so benign false blocks of 0 reflect that scoping, not a general guarantee.
- The benign-replay gate replays the benign set as if it came from the flagged client; rules on routes the benign set also uses are rejected and escalated, not activated.
- Window signals are sticky per client: after the failed-login stage every later request from the same client still carries `repeated_failed_logins`, so object_enum and injection requests are labelled CREDENTIAL_GUESSING and get per-path `rate_limit_client` rules. Those rules block the right traffic for the wrong reason; the intent table shows the mislabelling.
- `admin_probe` needs 5 hits on `/admin*` inside one window; this script sends 4, so that signal never fires and admin routes are labelled RECON.
- `rate_limit_client` is enforced as a hard block on its route for that client (no counting window yet).
- Lab 4xx/5xx counts include lab authentication errors and are not shield action.
- Local loopback only; latency figures do not represent a networked deployment.
