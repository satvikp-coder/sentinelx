"""Install Playwright's Chromium and report whether it can actually launch.

Usage: python scripts/setup_browsers.py [--with-deps]
(--with-deps also installs OS libraries on Linux CI; it needs root and is never used by default.)
Downloads the browser into the user-level Playwright cache (no system packages, no admin).
Exit code 0 only if Chromium launches headless.
"""

import subprocess
import sys
from pathlib import Path


def main() -> int:
    print("Installing Chromium via Playwright ...")
    cmd = [sys.executable, "-m", "playwright", "install", "chromium"]
    if "--with-deps" in sys.argv[1:]:
        cmd.append("--with-deps")
    proc = subprocess.run(cmd, check=False)
    if proc.returncode != 0:
        print(f"FAILED: playwright install exited with {proc.returncode}")
        return proc.returncode
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        exe = Path(p.chromium.executable_path)
        if not exe.exists():
            print(f"FAILED: expected browser at {exe}")
            return 1
        browser = p.chromium.launch()
        version = browser.version
        browser.close()
    print(f"OK: Chromium {version} launches headless ({exe})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
