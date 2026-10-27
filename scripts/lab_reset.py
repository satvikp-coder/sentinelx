"""Restore a lab to its seeded state and print the state hash.

Usage: python scripts/lab_reset.py <lab>
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from apps import labctl  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    print(f"{sys.argv[1]}: reset to seed; state hash {labctl.reset(sys.argv[1])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
