"""Stop labs started by lab_up.py (only what labctl started: compose projects / its own pid file).

Usage: python scripts/lab_down.py [lab ...]
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from apps import labctl  # noqa: E402


def main() -> int:
    for name in sys.argv[1:] or list(labctl.LABS):
        labctl.down(name)
        print(f"{name}: stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
