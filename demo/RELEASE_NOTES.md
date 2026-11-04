# Sentinel X — hackathon demo

This prerelease packages the **local lab-prototype demonstration**, not a production security release.

## Video assets

- `sentinelx_demo.mp4`: narrated, burned-in captions; 2:55, 1920×1080, 30 fps; H.264/AAC.
- `sentinelx_demo_silent.mp4`: identical captioned video without audio.
- `narration.srt`: exported captions.
- `voice.wav`: local Windows SAPI Zira narration for replacement/editing.

Download the MP4 and play it locally. No video binaries are committed in the source tree. See `demo/script.md`, `demo/storyboard.md`, `demo/README.md`, `demo/number_check.md` and `demo/MEDIA_VERIFICATION.md` in the source for reproduction and evidence.

## What was actually captured

- Fresh offline SDK execution, explicitly SIMULATED with stubbed tools.
- A fresh authorized Node-lab scan with independently rechecked findings.
- Separate API and Shield proxy processes using real loopback HTTP and a synthetic upstream: approval, activation, 403, no blocked request forwarded, benign 200, removal restoring forwarding.
- A fresh disposable evidence tamper-detection example.

Model comparisons, patch/PHP checks and the three-way Shield benchmark are **historical stored results**, not new live runs. The fresh scan coverage is explicitly separated from historical coverage. No new model/provider calls were made. Docker was unavailable for this recording.

## Limits and owner actions

Lab-only scope; incomplete coverage; tiny model samples; historical Shield injection traffic unprotected; weak intent labels; temporary mitigation, not a fix. Historical report evidence databases remain NO_DB. Shared local demo authentication is not production multi-user authorization.

Review the complete playback and narration before submission. Confirm eligibility, rules, track and required video hosting in the participant portal. This release is not a submitted hackathon entry or proof of eligibility. No portal form was submitted by these tools.
