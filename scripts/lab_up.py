"""Start labs, health-check them and prove they listen on 127.0.0.1 only.

Usage: python scripts/lab_up.py [lab ...]
Labs: vibe_shop_php, vibe_notes_node and the *_reference copies (default: the two vulnerable labs).
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from apps import labctl  # noqa: E402


def main() -> int:
    for name in sys.argv[1:] or ["vibe_shop_php", "vibe_notes_node"]:
        lab = labctl.up(name)
        proof = labctl.assert_loopback_only(name)
        checked = list(proof["non_loopback_checked"])  # type: ignore[call-overload]
        print(f"{name}: healthy at {lab.base_url}; published {proof['published']}; "
              f"non-loopback addresses checked and refused: {checked}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
