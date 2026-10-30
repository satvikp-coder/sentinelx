"""Isolation test: packages/shield must never read PLANTED.json or *_reference paths."""

from pathlib import Path

SHIELD_DIR = Path("packages/shield")

FORBIDDEN = ("PLANTED.json", "_reference")


def test_shield_never_reads_planted_or_reference():
    hits = []
    for py in SHIELD_DIR.glob("*.py"):
        text = py.read_text(encoding="utf-8")
        for token in FORBIDDEN:
            if token in text:
                hits.append((str(py), token))
    assert not hits, f"forbidden references in shield: {hits}"
