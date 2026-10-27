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
