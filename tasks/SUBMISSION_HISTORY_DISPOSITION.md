# History scanner — security disposition

Code baseline: `d855c4ece913775306295a8fec54254e7c2181d1`.
Scan source: `scripts/history_secret_scan.py`, all 189 reachable commits at review
start. The scanner's heuristic result is **exit 1 / review required**, not proof of
a real credential and not a clean scan. Full-history content candidates were
reviewed without displaying matched values or credential-file contents.

| Classification | Content occurrences |
|---|---:|
| Actual credential confirmed | 0 |
| Integrity hash / provenance identifier | 462 |
| Synthetic fixture / inert lab credential / canary | 24 |
| False positive (alphabet literal, slash-separated prose, URL/status labels) | 11 |
| Content candidate unresolved | 0 |
| Total content occurrences | 497 |

These are 401 distinct path/line/pattern/value contexts across 49 file paths;
repeated revisions are counted separately. The complete value-free ledger is
`SUBMISSION_HISTORY_CANDIDATES.csv`: every row has full commit, file, line,
pattern, classification and rationale. Candidate values are deliberately absent.
Generic long-token matches were not treated as credentials solely by shape:
contexts include npm integrity fields, evidence/request/manifest digests, Git
identifiers and explicit synthetic test literals. No rotation claim is made.

## Content-excluded credential-pattern filenames

The scanner did not open these three versions of `.env.example`:

- `950c3354a0828f12bfe8ebcf2d8d5ebfe8c289f7:.env.example`
- `5c0d83719759b15182b5c04475790185e29e39f4:.env.example`
- `865823fdaf5a84460ed921ba44efb5e5f922c653:.env.example`

Classification: **Needs investigation — owner content inspection required**.
The filename alone cannot prove placeholders. No actual `.env` file was opened.
No real `.env`, opencode.json, credential key file or database is tracked in the
current release. The `.env.example` exception in `.gitignore` is intentional.

## Supplemental history/working-tree review

Additional value-redacted inventory covers credential prefixes, Bearer/header/
key-assignment plumbing, possible emails and local developer paths. A deduplicated
blob scan complements the commit-occurrence scanner; it is not added to the 497
as if the categories were independent. See `SUBMISSION_SUPPLEMENTAL_HISTORY.csv`
and `SUBMISSION_WORKTREE_HITS.csv` for file/commit references and redacted hits.
URL-userinfo confusion cases are synthetic fixtures, and the disposable-copy Git
author is a synthetic local identity. Local developer paths are metadata, not
provider secrets; avoid putting private owner identity on video unnecessarily.

The scan is heuristic. It cannot establish that arbitrary short strings are not
secrets, cannot inspect credentials never committed, and does not verify provider
revocation. It covers reachable Git refs, not unreachable garbage objects or the
owner's other repositories. No history was deleted, rewritten or pushed.

**Disposition:** no confirmed actual key leak in reviewed candidates; public
release remains conditional on excluded-template review and owner security signoff.
If a real key is confirmed, stop publication, identify commit/path without values,
revoke/rotate and assess exposure before any separately authorized history action.
