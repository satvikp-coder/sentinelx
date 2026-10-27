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
