# Rebuild the submission video

Use MAIN and the known Python environment; do not display private configuration or inherited shell variables.

```cmd
C:\Users\satvi\Desktop\sentinelx-ds\.venv\Scripts\python.exe -m pip install playwright
C:\Users\satvi\Desktop\sentinelx-ds\.venv\Scripts\python.exe -m playwright install chromium
winget install --id Gyan.FFmpeg --exact --accept-package-agreements --accept-source-agreements --silent
C:\Users\satvi\Desktop\sentinelx-ds\.venv\Scripts\python.exe demo\capture.py
powershell.exe -NoProfile -ExecutionPolicy Bypass -File demo\voice.ps1
C:\Users\satvi\Desktop\sentinelx-ds\.venv\Scripts\python.exe demo\number_check.py
C:\Users\satvi\Desktop\sentinelx-ds\.venv\Scripts\python.exe demo\build_video.py
```

If FFmpeg already exists, skip its installation. The build script resolves the WinGet install path even before a shell restart. `build_video.py --assemble-only` re-encodes an existing Playwright capture without recording again. `capture.py --shield-only` repeats only the real public HTTP workflow in a new private runtime database. It is not needed to render already captured media.

The runtime launcher imports MAIN source explicitly, removes provider credential variables from child environments, disables dotenv loading, and rejects non-loopback connections. It never reads private credential files. Node dependencies must already be installed for the existing lab reset/up workflow. Docker is not used. Shield uses an ephemeral loopback upstream and separate API and proxy processes, all stopped by the capture runner. Only owned child processes are terminated. No external scanner or model is invoked.

All media, raw logs, SRT, audio, local SQLite state and screenshots live under gitignored `demo/out/`. Source scripts, narration, storyboard, number-check report and portal copy belong in Git. The report rebuild intentionally refreshes generated `report/index.html`; it does not repair absent historical evidence databases or relabel them OK.

## Outputs

- `out/sentinelx_demo.mp4`: narrated H.264/AAC with burned subtitles.
- `out/sentinelx_demo_silent.mp4`: identical captioned video with no audio stream.
- `out/voice.wav`: scene-fitted local SAPI voiceover.
- `out/narration.srt`: exported captions.
- `out/clips/demo-browser.webm`: raw 1920×1080 Playwright capture.
- `out/clips/report-scroll.webm`: actual generated report scrolling through sections.
- `out/frames/`: eight frames extracted from the encoded final video.
- `out/ffprobe.json`: actual codecs, frame rate, dimensions, duration and sizes.
- `out/capture-manifest.json`: command exit codes, durations, stdout hashes and port cleanup.

The final uses legible report DOM table excerpts alongside numerical cards, with the complete scrolling report retained as a separate raw clip. It does not pretend a terminal recording is an interactive desktop shell. Excerpts preserve actual captured lines without fake typing. A short illustration quotes the hostile instruction but omits its synthetic token. No royalty-free music asset was verified, so no music is included.

The public demo is hosted as assets on the [hackathon prerelease](https://github.com/satvikp-coder/sentinelx/releases/tag/hackathon-demo-2026-11-05), outside Git source history. The owner should listen to the synthesized voice and play the entire video before portal submission. Record a human voice over `script.md` and use the silent captioned version if preferred. Never commit a video or real credentials. Confirm the portal accepts the linked hosting and rehost the same MP4 if its rules require another platform. The capture/build scripts do not publish or submit anything.
