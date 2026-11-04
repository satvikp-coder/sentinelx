# Storyboard and source map

| Time | Scene | Capture / provenance |
|---|---|---|
| 0:00–0:20 | One guard. Two attack surfaces. | LAB DEMONSTRATION · hook |
| 0:20–0:40 | Hostile instructions meet a real gate. | SIMULATED AGENT / ACTUAL SDK EXECUTION · agent |
| 0:40–1:00 | Small results. Visible denominators. | SIMULATED + HISTORICAL OBSERVED · agent-results |
| 1:00–1:18 | Findings need a fresh-session re-check. | OBSERVED / INDEPENDENT RE-CHECK · scan |
| 1:18–1:35 | A patch proposal is not a fix. | VERIFIED CHECKS / HISTORICAL RECORD · fix |
| 1:35–1:57 | Approval. Activation. Actual HTTP enforcement. | OBSERVED / TEMPORARY SHIELD, NOT A FIX · shield |
| 1:57–2:15 | Protection has boundaries. | OBSERVED / HISTORICAL LAB REPLAY · shield-results |
| 2:15–2:30 | Models propose. Independent checks decide. | OBSERVED + VERIFIED CHAIN CHECK · evidence |
| 2:30–2:40 | For agent builders and small teams. | NO NEW MODEL CALLS IN THIS DEMO · adopt |
| 2:40–2:55 | Sentinel X | LAB-ONLY PROTOTYPE / HUMAN REVIEW REQUIRED · close |

## Build and cleanup

From MAIN with the known venv: `python demo/capture.py`, `powershell -NoProfile -ExecutionPolicy Bypass -File demo/voice.ps1`, `python demo/build_video.py`. Requires Playwright Chromium and FFmpeg. All captures and child-process logs are ignored under demo/out. Only owned services are terminated. Port cleanup is in capture-manifest.json. Rebuilding report/index.html is an intentional generated-report change.

`clips/demo-browser.webm` is the real Playwright terminal-style presentation capture. `clips/report-scroll.webm` separately captures the real report scrolling. In-film report tables are actual report DOM excerpts, not recreated metric tables. No royalty-free local music is used. Caption text is verbatim narration; captions are time allocated within each TTS scene, not forced-aligned phoneme timestamps.

## Manual owner review

Listen to the TTS, check the full final playback, replace with own narration using voice.wav or silent version if desired; publish externally and paste the URL into SUBMISSION_TEXT.md. Never commit video files. Windows Zira can pronounce model/tool identifiers mechanically. No stock visuals or fabricated dashboard UI are used.
