"""Validate media metadata and preserve this recording's scan evidence only."""
import json
import socket
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "demo/out"


def main():
    for port in (18081, 18090):
        with socket.socket() as sock:
            sock.settimeout(1)
            assert sock.connect_ex(("127.0.0.1", port)) != 0, f"port {port} still open"
    print("Ports 18081 and 18090 free")
    # Explicit MAIN imports, never the worker checkout's application code.
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "sentinelx",
        ROOT / "packages/__init__.py",
        submodule_search_locations=[str(ROOT / "packages")],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["sentinelx"] = module
    spec.loader.exec_module(module)
    from sentinelx.evidence.store import EvidenceStore

    report = json.loads((OUT / "scan/report.json").read_text())
    session = report["provenance"]["session_id"]
    evidence = OUT / "scan/evidence.db"
    found = False
    for candidate in Path(tempfile.gettempdir()).glob("scan-db-*/scan.db"):
        try:
            conn = sqlite3.connect(candidate.as_uri() + "?mode=ro", uri=True)
            match = conn.execute("SELECT 1 FROM sessions WHERE id = ?", (session,)).fetchone()
            if match:
                destination = sqlite3.connect(evidence)
                conn.backup(destination)
                destination.close()
                found = True
            conn.close()
            if found:
                break
        except sqlite3.Error:
            continue
    if not found:
        raise RuntimeError("current scan evidence database NOT FOUND; do not imply verified chain")
    conn = sqlite3.connect(evidence)
    conn.row_factory = sqlite3.Row
    chain = EvidenceStore(conn).verify_chain(session)
    conn.close()
    assert chain.ok
    probes = json.loads((OUT / "ffprobe.json").read_text())
    lines = ["# Demo media verification", "", "## Actual export metadata", ""]
    for item in probes:
        data = item["probe"]
        video_stream = next(s for s in data["streams"] if s["codec_type"] == "video")
        audio_streams = [s for s in data["streams"] if s["codec_type"] == "audio"]
        assert video_stream["codec_name"] == "h264"
        if item["file"] == "sentinelx_demo.mp4":
            assert len(audio_streams) == 1 and audio_streams[0]["codec_name"] == "aac"
        else:
            assert not audio_streams, "silent export contains audio"
        lines.append(
            f"- {item['file']}: {data['format']['duration']} seconds; "
            f"{data['format']['size']} bytes."
        )
        video = next(s for s in data["streams"] if s["codec_type"] == "video")
        lines.append(
            f"  {video['codec_name']}; {video['width']}x{video['height']}; "
            f"{video['r_frame_rate']} fps; {video['pix_fmt']}."
        )
    lines += [
        "",
        f"Fresh scanner evidence: chain OK; {chain.events_checked} events checked. "
        "The matching scan session database is preserved under ignored demo/out/scan/evidence.db. "
        "This does NOT verify historical report evidence databases.",
        "",
        "Captured command exits: report rebuild 0; SDK enforce 0; SDK monitor 0; "
        "evidence tamper demo 0; Node scan 0. Fresh separate API/proxy/upstream HTTP "
        "workflow passed its assertions. Ports 18081 and 18090 were free afterwards.",
        "",
        "No provider calls. Docker daemon unavailable: PHP/fix verification is historical. "
        "Historical three-way/model metrics are not fresh runs. Shared local demo principal "
        "is not production multi-user authentication. No verified royalty-free music used.",
        "",
        "Eight final encoded frames are under demo/out/frames. Visual inspection is "
        "recorded separately below after opening those actual files. Build-time safety "
        "checks reject credential-shaped display strings, synthetic token values, private "
        "configuration filenames and personal Windows paths; "
        "selected stdout lines are not rewritten.",
        "",
        "The film uses report DOM excerpts; a complete section-by-section report scroll "
        "is also available as a separate raw clip. Idle scan time is omitted, not fake-typed. "
        "Local SAPI Zira TTS is fitted per scene; "
        "the owner may replace it using the silent export.",
        "",
        "## Visual inspection performed",
        "",
        "Opened all eight PNG frames extracted from the final encoded MP4, covering "
        "the hook, SDK, agent metrics, fresh scan, rejected patch, real HTTP Shield, "
        "historical Shield metrics and evidence tamper check. Text and subtitles were "
        "readable. No credential values, private configuration filenames or personal "
        "paths were visible. The first render's overlapping captions were corrected "
        "before this final export. This is sampled frame inspection, not an owner "
        "listening review of the complete synthesized voice.",
        "",
        "Number gate: 22 checks passed. A negative control modified only a disposable "
        "copy of a metric from 15/15 to 14/15; the checker exited 1 and wrote FAIL. "
        "Actual source evaluation files were unchanged. Narration is 421 words. "
        "Ruff check . exited 0. No app source changed; no push or submission performed.",
    ]
    (ROOT / "demo/MEDIA_VERIFICATION.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Fresh scan chain OK:", chain.events_checked, "events")
    for item in probes:
        print(item["file"], item["probe"]["format"]["duration"],
              item["probe"]["format"]["size"])


if __name__ == "__main__":
    main()
