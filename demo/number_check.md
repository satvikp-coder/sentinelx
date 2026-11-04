# Demo number check

PASS — all numerical claims match their cited artifacts.

| Claim | Actual | Expected | Source | Result |
|---|---|---|---|---|
| simulated blocked | (15, 15) | (15, 15) | example_report/report.json / arms/B/overall | PASS |
| simulated false blocks | (0, 81) | (0, 81) | example_report/report.json / arms/B/overall | PASS |
| false confirmations caveat | (3, 81) | (3, 81) | example_report/report.json / arms/B/overall | PASS |
| observed unprotected | (2, 5) | (2, 5) | example_report_model/report.json / arms/A/overall | PASS |
| observed gated | (0, 4) | (0, 4) | example_report_model/report.json / arms/B/overall | PASS |
| historical planted recall | (6, 10) | (6, 10) | example_scan_report/vibe_notes_node/scoring.json / overall_recall (companion scoring) | PASS |
| historical coverage | 97.3 | 97.3 | example_scan_report/vibe_notes_node/report.json / provenance | PASS |
| independently checked; awaiting approval | 2 | 2 | example_fix_report/report.json / results | PASS |
| fix denominator | 8 | 8 | example_fix_report/report.json / results | PASS |
| escalations | 6 | 6 | example_fix_report/report.json / results | PASS |
| rejected check | True | True | example_fix_report/report.json / results/verification | PASS |
| shield blocked/sent | (38, 65) | (38, 65) | example_shield_report/report.json / arms/C/attack/total | PASS |
| shield benign blocked/sent | (0, 40) | (0, 40) | example_shield_report/report.json / arms/C/benign | PASS |
| injection unprotected | 0 | 0 | example_shield_report/report.json / arms/C/attack/per_stage/injection | PASS |
| weak enumeration labels | 0 | 0 | example_shield_report/report.json / arms/C/intent_accuracy | PASS |
| fresh HTTP blocked_http | 403 | 403 | demo/out/shield-summary.json (fresh production HTTP capture) | PASS |
| fresh HTTP blocked_upstream_delta | 0 | 0 | demo/out/shield-summary.json (fresh production HTTP capture) | PASS |
| fresh HTTP benign_http | 200 | 200 | demo/out/shield-summary.json (fresh production HTTP capture) | PASS |
| fresh HTTP after_removal_http | 200 | 200 | demo/out/shield-summary.json (fresh production HTTP capture) | PASS |
| fresh scanner completed | completed | completed | demo/out/scan/report.json | PASS |
| fresh scanner independently rechecked | True | True | demo/out/scan/report.json / findings | PASS |
| clean/tamper live evidence | True | True | demo/out/evidence.txt | PASS |

Narration: 421 words; planned duration 175 seconds. These are build metadata, not security results.

Numeric narration inventory: fifteen/fifteen, zero/eighty-one; twice/five, zero/four; six/ten; two/eight, six escalated; thirty-eight/sixty-five, zero/forty; HTTP four-oh-three and two hundred. Each is bound above. Runtime activation milliseconds and fresh coverage are read dynamically from current capture JSON, not hardcoded historical values.

Recall 6/10 is explicitly from the stored companion scoring.json. It is NOT a field in report.json and is never called fresh scan recall. Historical 97.3% and fresh coverage are explicitly separated. No numerical metric is inferred from video timing.

Additional on-screen numbers in unmodified terminal/report excerpts originate in the logged commands or report.json; IDs, hashes, model names, URLs and video timecodes are identifiers, not measured performance.

- `agent-enforce.txt` SHA256: `ad48f027ac89b8ee98e7b958b3add24d78fc5367625682beef42ee02984383a5`
- `agent-monitor.txt` SHA256: `043039713b9d80d811bf201669d96364d9a1b0640104a66693998091d44cad67`
- `scan.txt` SHA256: `215696843828e3e9556c73d35029580af38e7fc5b1a18f08a18543950e8121ea`
- `shield.txt` SHA256: `1292174f9203ffbe9999a62e100383c57806d4fdcfdfafc12de42f356181f28f`
- `evidence.txt` SHA256: `5309a15007627233d732fae02fa8696d1ed0129444e37d9167b10c94be2a8919`
