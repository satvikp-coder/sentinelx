# Site Guard fix engine — example run (Prompt 9 Part G)

Model profile: **baseten_spark_open** (Baseten, `meta-models/muse-spark-open-1026`), no fallback used.
Selection: BY RULE, before any run — the first 3 confirmed AUTO-class findings (lexicographic by
class, then id) plus 1 confirmed NEEDS_HUMAN-class finding, per lab. Never cherry-picked afterwards.

## Results

| Lab | Finding | Class | Status | Verification | Retries | Time |
|---|---|---|---|---|---|---|
| vibe_shop_php | cand_broken_object_authorization_0008 | broken_object_authorization | **AWAITING_APPROVAL** | VERIFIED | 0 | 28.6s |
| vibe_shop_php | cand_debug_exposure_0003 | debug_exposure | ESCALATED | REJECTED (apply_diff: corrupt patch) | 1 | 9.0s |
| vibe_shop_php | cand_reflected_xss_0007 | reflected_xss | **AWAITING_APPROVAL** | VERIFIED | 0 | 32.2s |
| vibe_shop_php | cand_missing_authentication_0004 | missing_authentication | ESCALATED (NEEDS_HUMAN policy) | REJECTED (benign_traffic broke) | 0 | 34.6s |
| vibe_notes_node | cand_broken_object_authorization_0009 | broken_object_authorization | ESCALATED | REJECTED (apply_diff: corrupt patch) | 1 | 6.6s |
| vibe_notes_node | cand_debug_exposure_0005 | debug_exposure | ESCALATED | REJECTED (apply_diff: does not apply) | 1 | 7.0s |
| vibe_notes_node | cand_security_headers_and_cookies_0001 | security_headers_and_cookies | ESCALATED | diagnosis failure | 0 | 0.5s |
| vibe_notes_node | cand_permissive_cors_0006 | permissive_cors | ESCALATED (NEEDS_HUMAN policy) | diagnosis failure | 0 | 0.5s |

**2 VERIFIED (awaiting human approval), 6 ESCALATED (0 silently dropped).** Every ESCALATED
finding has an OPEN ticket with 2-3 concrete options; every AWAITING_APPROVAL finding has a
patch PROPOSAL and a VERIFIED `RepairVerification` with per-check timing.

Model calls: 2 per attempt (diagnosis + patch_generation), ×1 for a 0-retry finding or ×2 for a
1-retry finding (2 diagnosis calls were never made at all — the 2 diagnosis-failure findings
below) = **11 calls total**. Tokens and spend: **$0.04360 estimated** (Baseten's published
per-token prices) **/ $70.00 hard cap, $69.95640 remaining**. This is an ESTIMATE from published
prices, not a bill — check the Baseten dashboard for the real one.

## One VERIFIED example

**`cand_broken_object_authorization_0008`** (vibe_shop_php, `order_view.php`): any logged-in
user could view any order by changing the `id` query parameter — no ownership check.

Diff (applied, committed in the disposable fix scope):
```diff
--- a/order_view.php
+++ b/order_view.php
@@ -3,9 +3,14 @@ require_once __DIR__ . '/bootstrap.php';
 require_login();
 page_start('Order');
 $st = db()->prepare('SELECT id, user_id, total_cents, status, created_at FROM orders WHERE id = ?');
 $st->execute([$_GET['id'] ?? 0]);
 $o = $st->fetch(PDO::FETCH_ASSOC);
 if (!$o) { echo '<p>Order not found</p>'; page_end(); exit; }
+$currentUserId = $_SESSION['user_id'] ?? $_SESSION['uid'] ?? null;
+if ((int)$o['user_id'] !== (int)$currentUserId) {
+    http_response_code(403);
+    echo '<p>Forbidden</p>'; page_end(); exit;
+}
 if (!empty($_GET['placed'])) echo '<p>Order placed. Thank you!</p>';
 echo '<h1>Order #' . (int)$o['id'] . '</h1><p>Status: ' . h($o['status']) . '</p><p>Total: $' . number_format($o['total_cents'] / 100, 2) . '</p>';
 $items = db()->prepare('SELECT p.name, i.qty FROM order_items i JOIN products p ON p.id = i.product_id WHERE i.order_id = ?');
```

Per-check verification (all passed -> VERIFIED):

| Check | Passed | Time |
|---|---|---|
| diff_review | yes | 0ms |
| syntax (`php -l` inside the pinned image) | yes | 1007ms |
| benign_traffic (20/20 features) | yes | 2793ms |
| exploit no longer reproduces + no new finding | yes (`still_broken=False`, `newly_introduced=[]`) | 8307ms |

Not yet applied to `labs_applied/vibe_shop_php/` — that needs a human
`scripts/run_fix.py --approve patch_<id> --reviewer <name>`, which was deliberately not run for
this example (no human reviewed it).

## One REJECTED example

**`cand_missing_authentication_0004`** (vibe_shop_php, `admin.php`): the model's diff was
syntactically valid PHP and applied cleanly —
```diff
--- admin.php
+++ admin.php
@@ -1,5 +1,11 @@
 <?php
 require_once __DIR__ . '/bootstrap.php';
+// Require authentication and admin authorization
+if (session_status() !== PHP_SESSION_ACTIVE) session_start();
+if (empty($_SESSION['user_id']) || empty($_SESSION['is_admin'])) {
+    http_response_code(403);
+    exit('Forbidden: admin access required');
+}
 page_start('Admin');
 echo '<h1>Admin panel</h1><h2>Users</h2><ul>';
```
— but the lab's own benign-traffic generator FAILED after it: `admin panel: got 403; marker
MISSING`. The benign-traffic feature that visits the admin panel does not itself authenticate
as an admin, so a (correct, intended) admin-only gate also blocks that legitimate feature check.
REJECTED rather than applied, exactly as it should be — a security-correct patch is still not
safe to auto-apply if it breaks something the independent verification can observe. This
finding is `missing_authentication` (`NEEDS_HUMAN` by policy) regardless, so it would have
escalated either way; the REJECTED verification result is reported honestly rather than hidden
behind the policy-based escalation.

A second, different REJECTED pattern seen 3 times in this batch: `git apply` failing with
`corrupt patch at line N` or `patch does not apply` — the model's proposed diff CONTENT was a
plausible enough fix, but its unified-diff hunk-header line-count arithmetic was wrong. Nothing
was ever applied unsafely in either case; the ladder retried once, failed the same way, and
escalated rather than guessing.

## One escalation ticket

```
esc_c47ff3081cae  OPEN
finding: cand_missing_authentication_0004 (missing_authentication, vibe_shop_php)
explanation: missing_authentication fixes depend on a business decision this patch cannot
  make on its own; a proposed patch (patch_3aa6077ccccf) exists for a human to review, but
  this class is never auto-applied.
options:
  1. Review and approve patch patch_3aa6077ccccf as written.
  2. Ask for a different fix approach (e.g. a stricter policy).
  3. Reject and have a human implement the business rule directly.
```

## Limitations

- This batch was selected BY RULE (first 3 AUTO classes + 1 NEEDS_HUMAN per lab, lexicographic)
  before any run — no cherry-picking of good results afterwards. Two separate runs of this same
  batch (before and after a shared-redactor fix made mid-session) picked the identical 8
  findings both times, but landed on different individual outcomes for 3 of them (retries and a
  verification result changed) — the model is not perfectly deterministic call to call.
- The diff validator does not check a unified diff's hunk-header line-count arithmetic before
  `git apply` is tried; a model diff with correct CONTENT but a wrong `@@ -a,b +c,d @@` count is
  caught only at apply time (3 of 8 attempts here across the two runs), consuming a retry rather
  than getting precise feedback on the FIRST attempt. The diff is still never applied partially
  or unsafely — the failure is just discovered one stage later than it could be.
- `route_to_file()`'s static mapping has no entry for routes served by framework/static
  middleware rather than an explicit `app.<method>(path, ...)` registration (Node's `GET /`,
  served by `express.static`); 2 of 8 findings here escalated for exactly this reason, with no
  model call even attempted. This is reported honestly as a diagnosis-stage gap, not hidden.
- Verification measures the scanner's own check plus the lab's benign traffic, not completeness
  of security — a VERIFIED patch is not a guarantee against every other possible bug, and (as
  the `missing_authentication` example shows) a security-correct patch can still legitimately
  fail verification if it changes behaviour a benign-traffic feature relies on.
- NEEDS_HUMAN findings are never auto-fixed, regardless of verification outcome.
- Estimated spend is computed from Baseten's published per-token prices, not a real invoice —
  check the Baseten dashboard for the actual bill.
- The sample is small (2 labs, 8 findings); it demonstrates the mechanism working end to end on
  a real model against real labs, not statistical confidence in the fixer's overall success rate.
