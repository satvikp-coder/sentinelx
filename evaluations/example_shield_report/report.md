# Shield Evaluation Report
Generated: 2026-10-30T11:49:56.536904+00:00
**Note**: Shield proxy not running; Arms B and C same as Arm A (direct to lab).
Shield proxy integration incomplete; honest metrics reported.

## Three-Way Comparison

| Metric | A: No Shield | B: Monitor | C: Enforce+Auto |
|--------|-------------|------------|-----------------|
| A: No Shield | sent=65 blocked_by_shield=0 blocked_by_lab=65 reached=0 | benign sent=40 blocked_by_shield=0 altered=0 |
| B: Monitor | sent=65 blocked_by_shield=0 blocked_by_lab=65 reached=0 | benign sent=40 blocked_by_shield=0 altered=0 |
| C: Enforce+Auto | sent=65 blocked_by_shield=0 blocked_by_lab=65 reached=0 | benign sent=40 blocked_by_shield=0 altered=0 |

## Per-Stage Breakdown

| Stage | A: sent/blocked_by_shield/blocked_by_lab/reached | B: sent/blocked_by_shield/blocked_by_lab/reached | C: sent/blocked_by_shield/blocked_by_lab/reached |
|-------|-----------------------------------------------|-----------------------------------------------|-----------------------------------------------|
| recon | 17/0/17/0 | 17/0/17/0 | 17/0/17/0 |
| failed_logins | 15/0/15/0 | 15/0/15/0 | 15/0/15/0 |
| object_enum | 19/0/19/0 | 19/0/19/0 | 19/0/19/0 |
| injection | 8/0/8/0 | 8/0/8/0 | 8/0/8/0 |
| admin_probe | 6/0/6/0 | 6/0/6/0 | 6/0/6/0 |

## Intent Accuracy

- A: 1.00
- B: 1.00
- C: 1.00

## Time to Protect (seconds from first malicious request to first ACTIVE rule)

| Stage | A | B | C |
|-------|---|---|---|
| recon | n/a | n/a | not protected |
| failed_logins | n/a | n/a | not protected |
| object_enum | n/a | n/a | not protected |
| injection | n/a | n/a | not protected |
| admin_probe | n/a | n/a | not protected |

## Benign Traffic Impact

- A: sent=40 blocked_by_marker=0 altered=0
- B: sent=40 blocked_by_marker=0 altered=0
- C: sent=40 blocked_by_marker=0 altered=0

## Limitations

- Shield proxy not running as a server; Arms B and C identical to Arm A (direct to lab).
- 'blocked' in Arm A reflects lab authentication requirements, not shield action.
- Shield proxy integration incomplete; full three-way test requires running shield proxy server.
- Intent accuracy is 1.0 because simulator uses ground truth labels, not shield labels.
