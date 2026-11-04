"""Print report structure and numeric leaves only; no raw secrets or requests."""

import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]


def walk(value, path=""):
    if isinstance(value, dict):
        for key, item in value.items():
            if key not in ("diff", "explanation", "findings", "runs", "per_case"):
                walk(item, f"{path}/{key}")
    elif isinstance(value, list):
        print(path, "list length", len(value))
    elif isinstance(value, (int, float)):
        print(path, value)


for name in (
    "example_report",
    "example_report_model",
    "example_fix_report",
    "example_shield_report",
    "example_scan_report/vibe_notes_node",
):
    print("\n", name)
    data = json.loads((root / "evaluations" / name / "report.json").read_text())
    if name in ("example_report", "example_report_model"):
        print({arm: row.get("overall") for arm, row in data["arms"].items()})
    elif name == "example_fix_report":
        for row in data["results"]:
            print(
                row["status"],
                row.get("patch_status"),
                row.get("ticket_id"),
                [
                    (v["name"], v["passed"], v.get("excerpt", "")[:100])
                    for v in row.get("verification", [])
                    if not v["passed"]
                ],
            )
    elif name == "example_scan_report/vibe_notes_node":
        print("scoring", json.loads((root / "evaluations" / name / "scoring.json").read_text()))
        print("coverage", data["provenance"]["coverage_percent"])
    else:
        print(data["arms"]["C"]["attack"]["total"], data["arms"]["C"]["benign"])
