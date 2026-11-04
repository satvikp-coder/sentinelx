# ruff: noqa: E501 -- Preserve the exact human-readable claim/provenance prose.
"""Fail closed on every numerical claim used in the film.

The planted recall uses the explicitly linked companion scoring.json; that
number is not invented from scan coverage. Fresh scan numbers stay separate.
"""

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "demo/out"


def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def check():
    checks, failures = [], []

    def claim(label, actual, expected, source):
        passed = actual == expected
        checks.append((label, actual, expected, source, passed))
        if not passed:
            failures.append(label)

    sim = load("evaluations/example_report/report.json")["arms"]["B"]["overall"]
    model = load("evaluations/example_report_model/report.json")["arms"]
    shield = load("evaluations/example_shield_report/report.json")["arms"]["C"]
    fixes = load("evaluations/example_fix_report/report.json")["results"]
    score = load("evaluations/example_scan_report/vibe_notes_node/scoring.json")
    historic_scan = load("evaluations/example_scan_report/vibe_notes_node/report.json")

    def rate(label, row, expected, source):
        claim(label, (row["numerator"], row["denominator"]), expected, source)

    rate(
        "simulated blocked",
        sim["attack_block_rate"],
        (15, 15),
        "example_report/report.json / arms/B/overall",
    )
    rate(
        "simulated false blocks",
        sim["false_block_rate"],
        (0, 81),
        "example_report/report.json / arms/B/overall",
    )
    rate(
        "false confirmations caveat",
        sim["false_confirm_rate"],
        (3, 81),
        "example_report/report.json / arms/B/overall",
    )
    rate(
        "observed unprotected",
        model["A"]["overall"]["attack_success_rate"],
        (2, 5),
        "example_report_model/report.json / arms/A/overall",
    )
    rate(
        "observed gated",
        model["B"]["overall"]["attack_success_rate"],
        (0, 4),
        "example_report_model/report.json / arms/B/overall",
    )
    rate(
        "historical planted recall",
        score["overall_recall"],
        (6, 10),
        "example_scan_report/vibe_notes_node/scoring.json / overall_recall (companion scoring)",
    )
    claim(
        "historical coverage",
        historic_scan["provenance"]["coverage_percent"],
        97.3,
        "example_scan_report/vibe_notes_node/report.json / provenance",
    )
    claim(
        "independently checked; awaiting approval",
        sum(
            r["status"] == "AWAITING_APPROVAL" and all(v["passed"] for v in r["verification"])
            for r in fixes
        ),
        2,
        "example_fix_report/report.json / results",
    )
    claim("fix denominator", len(fixes), 8, "example_fix_report/report.json / results")
    claim(
        "escalations",
        sum(r["status"] == "ESCALATED" for r in fixes),
        6,
        "example_fix_report/report.json / results",
    )
    claim(
        "rejected check",
        any(
            v["name"] == "apply_diff"
            and not v["passed"]
            and "corrupt patch" in v.get("excerpt", "")
            for r in fixes
            for v in r.get("verification", [])
        ),
        True,
        "example_fix_report/report.json / results/verification",
    )
    claim(
        "shield blocked/sent",
        (shield["attack"]["total"]["blocked_by_shield"], shield["attack"]["total"]["sent"]),
        (38, 65),
        "example_shield_report/report.json / arms/C/attack/total",
    )
    claim(
        "shield benign blocked/sent",
        (shield["benign"]["blocked_or_altered_by_shield"], shield["benign"]["sent"]),
        (0, 40),
        "example_shield_report/report.json / arms/C/benign",
    )
    claim(
        "injection unprotected",
        shield["attack"]["per_stage"]["injection"]["blocked_by_shield"],
        0,
        "example_shield_report/report.json / arms/C/attack/per_stage/injection",
    )
    claim(
        "weak enumeration labels",
        shield["intent_accuracy"]["object_enum"]["correct"],
        0,
        "example_shield_report/report.json / arms/C/intent_accuracy",
    )
    live = load("demo/out/shield-summary.json")
    for key, expected in (
        ("blocked_http", 403),
        ("blocked_upstream_delta", 0),
        ("benign_http", 200),
        ("after_removal_http", 200),
    ):
        claim(
            "fresh HTTP " + key,
            live[key],
            expected,
            "demo/out/shield-summary.json (fresh production HTTP capture)",
        )
    scan = load("demo/out/scan/report.json")
    claim(
        "fresh scanner completed",
        scan["provenance"]["stop_reason"],
        "completed",
        "demo/out/scan/report.json",
    )
    claim(
        "fresh scanner independently rechecked",
        any(
            f["verification"]["state"] == "confirmed"
            and f["verification"]["fresh_session"]
            and f["verification"]["event_ids"]
            for f in scan["findings"]
        ),
        True,
        "demo/out/scan/report.json / findings",
    )
    claim(
        "clean/tamper live evidence",
        all(
            s in (OUT / "evidence.txt").read_text()
            for s in ("ChainStatus.OK", "ChainStatus.MODIFIED")
        ),
        True,
        "demo/out/evidence.txt",
    )
    scenes = load("demo/scenes.json")
    words = sum(len(s["narration"].split()) for s in scenes)
    numeric_phrases = re.compile(
        r"\b(?:four-oh-three|two hundred|thirty-eight|sixty-five|eighty-one|"
        r"zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|"
        r"thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|"
        r"thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|"
        r"million|billion|twice)\b", re.I,
    )
    approved_inventory = {
        "hook": ["one"],  # narrative hook, not a performance count
        "agent": [],
        "agent-results": ["fifteen", "fifteen", "zero", "eighty-one",
                          "twice", "five", "zero", "four"],
        "scan": ["six", "ten"],
        "fix": ["two", "eight", "six"],
        "shield": ["four-oh-three", "two hundred"],
        "shield-results": ["thirty-eight", "sixty-five", "zero", "forty"],
        "evidence": [], "adopt": [], "close": [],
    }
    # Narrative numeric phrases are an explicit inventory; unreviewed digits fail.
    for scene in scenes:
        if any(c.isdigit() for c in scene["narration"]):
            failures.append("unregistered digit in narration")
        spoken = [v.lower() for v in numeric_phrases.findall(scene["narration"])]
        if spoken != approved_inventory[scene["kind"]]:
            failures.append("unreviewed spoken number in " + scene["kind"])
    text = "# Demo number check\n\n" + (
        "FAIL — DO NOT SUBMIT\n"
        if failures
        else "PASS — all numerical claims match their cited artifacts.\n"
    )
    text += "\n| Claim | Actual | Expected | Source | Result |\n|---|---|---|---|---|\n"
    for label, actual, expected, source, passed in checks:
        text += f"| {label} | {actual} | {expected} | {source} | {'PASS' if passed else 'FAIL'} |\n"
    text += f"\nNarration: {words} words; planned duration {sum(s['seconds'] for s in scenes)} seconds. These are build metadata, not security results.\n"
    text += "\nNumeric narration inventory: fifteen/fifteen, zero/eighty-one; twice/five, zero/four; six/ten; two/eight, six escalated; thirty-eight/sixty-five, zero/forty; HTTP four-oh-three and two hundred. Each is bound above. Runtime activation milliseconds and fresh coverage are read dynamically from current capture JSON, not hardcoded historical values.\n"
    text += "\nRecall 6/10 is explicitly from the stored companion scoring.json. It is NOT a field in report.json and is never called fresh scan recall. Historical 97.3% and fresh coverage are explicitly separated. No numerical metric is inferred from video timing.\n"
    text += "\nAdditional on-screen numbers in unmodified terminal/report excerpts originate in the logged commands or report.json; IDs, hashes, model names, URLs and video timecodes are identifiers, not measured performance.\n"
    for name in (
        "agent-enforce.txt",
        "agent-monitor.txt",
        "scan.txt",
        "shield.txt",
        "evidence.txt",
    ):
        text += f"\n- `{name}` SHA256: `{hashlib.sha256((OUT / name).read_bytes()).hexdigest()}`"
    (ROOT / "demo/number_check.md").write_text(text + "\n", encoding="utf-8")
    if failures:
        raise SystemExit("NUMBER CHECK FAILED: " + ", ".join(failures))
    print(f"number check PASS: {len(checks)} claims; {words} narration words")
    return checks


if __name__ == "__main__":
    check()
