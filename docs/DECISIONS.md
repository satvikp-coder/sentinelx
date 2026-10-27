# Decisions Log

## 2026-10-27 - Model API facts are unverified until Prompt 5
All details of the NVIDIA-hosted Muse Glimmer 30B endpoint (model id, base URL, parameters, limits, terms) come from the developer's brief and are UNVERIFIED. Prompt 5 re-reads the docs before any model code is written. Do not guess parameters.

## 2026-10-27 - License choice pending
No LICENSE file yet. The developer must confirm their rights and the hackathon's requirements first. Decision open.

## 2026-10-27 - Python package layout
Packages live under `packages/` and are imported by top-level name (e.g. `import policy`) via setuptools `where=["packages"]`; pytest also sets `pythonpath=["packages"]`. Top-level names are generic and could collide with other installed packages; revisit (e.g. a `sentinelx` namespace) before the first feature prompt.

## 2026-10-27 - Frontend toolchain
Vite and React pinned from the npm registry at setup time; TypeScript pinned to 5.x for tool compatibility rather than the newest major.
