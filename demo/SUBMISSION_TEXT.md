# Sentinel X

**Verification-first security for AI agents and vibe-coded sites. Models propose; deterministic code and independent tests decide.**

## Description (150 words)

Sentinel X helps developers inspect what an AI agent attempts and what a security system actually permits. Agent Guard wraps tools with deterministic policy checks and records evidence. Site Guard scans authorized local labs, independently rechecks candidate findings, verifies proposed patches on disposable copies, and escalates failures for human review. Its temporary Shield requires approval and benign replay before installing scoped proxy rules. The demo shows real local HTTP blocking, benign forwarding, removal, and a tamper-detection example. Recorded evaluations retain denominators and distinguish simulation from observed model runs. Meta open-weight models support agent proposals and patch reasoning; they never decide whether a vulnerability is confirmed or a patch is verified. This is a lab-only prototype with incomplete coverage, tiny model samples, weak intent classification, and unprotected injection traffic. It offers agent builders, solo founders, and small teams an auditable starting point for testing generated software, not a production security guarantee.

## How it uses Meta open-weight models

- `meta/muse-glimmer-30b` via NVIDIA: recorded agent evaluation provenance in `evaluations/example_report_model/report.json`.
- `meta-models/muse-spark-open-1026` via Baseten: configured model-assisted diagnosis/patch proposals; stored fix report records the `baseten_spark_open` profile. Preserve recorded provenance rather than asserting a new invocation.
- This demo performs **no new provider/model calls**. The offline SDK example is explicitly SIMULATED, not a live-model benchmark.
- Deterministic policy, independent rechecks, approval and disposable-copy patch verification remain separate from model assertions.

## Portal selections — owner to confirm

- Requested track: **Indie** (confirm exact portal spelling and eligibility).
- Requested problem statement: **Build for Your World** (confirm against authenticated participant instructions).
- No organizer eligibility, acceptance or submission completion is asserted by this document.

## Honest limitations

Own authorized labs only; non-lab scanning disabled. Historical metrics are not current live measurements. Small, unequal valid-model samples are not statistically conclusive. Coverage is not recall. Patch checks do not imply deployment. Shield is temporary and not a fix; historical injection requests were unprotected and intent labels were weak. Benign replay used different client scopes and cannot establish general zero false positives. Docker is unavailable here, so PHP verification is stored evidence. The recorded public approval workflow uses a shared local demo principal, not production multi-user authentication. Historical evidence databases are absent and the rebuilt report shows NO_DB; the fresh tamper demo is separate. Browser media capture is not a dashboard E2E certification.

## Links

- Repository: https://github.com/satvikp-coder/sentinelx
- Demo page: https://github.com/satvikp-coder/sentinelx/releases/tag/hackathon-demo-2026-11-05
- Direct video: https://github.com/satvikp-coder/sentinelx/releases/download/hackathon-demo-2026-11-05/sentinelx_demo.mp4
- Confirm the portal accepts a GitHub-hosted MP4; if it requires another video platform, upload this same file there and substitute that URL.
- Setup and reproducibility: README.md; demo/storyboard.md; demo/number_check.md.

## AI-assistance disclosure

Built with AI coding agents under human direction, with independent automated review and tests. Local Windows speech synthesis narrates the demo; the owner can replace it with their own voice. No claim that every generated line was manually audited or that the project is production-ready.
