# Decisions Log

## 2026-10-27 - Model API facts are unverified until Prompt 5
All details of the NVIDIA-hosted Muse Glimmer 30B endpoint (model id, base URL, parameters, limits, terms) come from the developer's brief and are UNVERIFIED. Prompt 5 re-reads the docs before any model code is written. Do not guess parameters.

## 2026-10-27 - License choice pending
No LICENSE file yet. The developer must confirm their rights and the hackathon's requirements first. Decision open.

## 2026-10-27 - Python package layout (supersedes earlier top-level layout)
Packages live under `packages/` and are importable ONLY as `sentinelx.<name>` via setuptools `package-dir = {"sentinelx" = "packages"}`. No top-level `policy`, `evidence` etc.; a test asserts `find_spec(name) is None`.

## 2026-10-27 - Frontend toolchain
Vite and React pinned from the npm registry at setup time; TypeScript pinned to 5.x for tool compatibility rather than the newest major.

## 2026-10-27 - Windows is the primary dev platform
Windows is the primary dev platform; scripts are Python; labs run in Docker (PHP is not installed locally).

## 2026-10-27 - Lab hostnames
Lab hostnames: do not edit the Windows hosts file; resolve *.lab.test inside our own code (browser host-resolver rules / proxy mapping) in a later prompt.

## 2026-10-27 - Additive PolicyDecision fields (schema_version stays 1.0)
Added to `PolicyDecision`: `policy_mode`, `effective_action`, `would_have_decided`, `signals` (list of `PolicySignal`). All have defaults (`effective_action` defaults to `decision`), so older 1.0 documents still validate. Also added the new `ApprovalRequest` model and the `PolicyMode` / `SignalKind` enums. No version bump; exported JSON Schemas regenerated.

## 2026-10-27 - Policy gateway choices
- `tool` is the action type: a tool absent from `tool_argument_rules` is "unknown tool / unknown action type" (UNKNOWN_TOOL).
- Relative URLs resolve against `SessionContext.page_origin`, supplied by the trusted runtime, not by the (model-proposed) request arguments.
- Trailing-dot hosts are REJECTED by default (`trailing_dot: reject`) so "orders.lab.test." cannot reach the allowed host; `normalize` is an explicit opt-in.
- An allowlist entry without a port matches only the scheme's default port; IP literals match only in canonical form and only when listed.
- Monitor mode keeps a few hard stops enforced (kill switch, session not RUNNING, session mismatch, malformed/invalid inputs). The prompt said monitor returns ALLOW; a kill switch that monitor mode could override would not be a kill switch.
- `policy_version` hashes the canonical policy content (not raw file bytes), so comment/whitespace-only edits keep the same version; any semantic edit changes it. The signal phrase list is not part of the hash because signals cannot affect decisions.
- Approvals are bound to `action_id` + a digest of the exact tool and arguments, so an approval for one set of arguments cannot be replayed for another.
- Signal detectors and phrases are hints only (small, reviewed list in `configs/policy/signals.yaml`), not a defense.

## 2026-10-27 - Lab policy and scenario materialisation
- `configs/policy/lab.yaml` is the lab's policy: only `navigate, read_page, click, submit_form, tool_call` are allowed tools; `http_request` is known but high-impact BLOCK; `secret_patterns` include `synth_tok_[0-9a-f]{8,}`. `collector.lab.test` is deliberately NOT in `blocked_destinations`, so the scope and secret rules must stop the exfiltration on their own. `synth_tok_` is also a built-in redaction pattern so it can never be stored raw.
- The lab picks a free port at runtime, so scenario JSON lists bare hosts (`orders.lab.test`) and the runtime materialises them to exact `host:port` allowlist entries per run. Fixture hashes do not include the port.
- Protected-arm blocks come from different layers on purpose: S1 / S1_TOOL by `SECRET_EGRESS` (rule 2); S2 / S2_HIDDEN / S3 by `TOOL_NOT_IN_SCENARIO` (rule 3, the scenario never permits `http_request`).
- Playwright route handlers are not invoked for redirect targets; the adapter follows redirects itself (see docs/ARCHITECTURE.md). Found by test, not assumed.
- The planner returns an `ActionRequest` built from the `Observation` (session id, step and timestamp are supplied by the runtime). This keeps the Planner interface identical for a future model-driven planner.
- `verifications` gained a `kind` column and nullable `patch_id` / `session_id` (migration 0002) so run verifications and repair verifications share the table, as specified.
- Browser tests carry the `browser` marker; they skip with a clear message locally if Chromium is missing and FAIL when `SENTINELX_CI=1`. The pytest summary prints how many browser tests actually ran.
- `apps/` is not an installed package: scripts add the repo root to `sys.path` and tests import `apps.fixture_lab` from the repo root.
- The `tool_call(name, arguments)` and `submit_form(selector, fields)` tools from the brief are represented with flat scalar arguments because the policy gateway only accepts scalar argument values.
