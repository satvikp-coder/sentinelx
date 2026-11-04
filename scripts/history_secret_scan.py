#!/usr/bin/env python3
"""Secret-history scan: search git history for leaked secrets.

Scans all commits (not just the working tree) for patterns that look like
secrets (API keys, tokens, passwords, private keys). Reports matches with
commit, file, and line context. Does NOT modify any files.

Exit codes:
  0 - no secrets found
  1 - potential secrets found (review required)
  2 - error
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import PurePosixPath

# Patterns that suggest a secret may be present.
SECRET_PATTERNS = [
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI-style API key"),
    (r"sk-or-[A-Za-z0-9]{20,}", "OpenAI org key"),
    (r"nvapi-[A-Za-z0-9]{20,}", "NVIDIA API key"),
    (r"[A-Za-z0-9+/]{40,}", "long base64-like token (possible secret)"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key block"),
    (r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*"
     r"['\"][A-Za-z0-9+/=]{16,}", "key/token assignment"),
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^\s'\"]{8,}", "password assignment"),
]


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=60)


def main() -> int:
    # Verify we're in a git repo (works for worktrees too)
    result = run(["git", "rev-parse", "--git-dir"])
    if result.returncode != 0:
        print("ERROR: not a git repository", file=sys.stderr)
        return 2

    # Get all commits
    result = run(["git", "log", "--all", "--format=%H"])
    if result.returncode != 0:
        print(f"ERROR: git log failed: {result.stderr}", file=sys.stderr)
        return 2
    commits = result.stdout.strip().splitlines()

    found_any = False
    for commit in commits:
        # Get the diff for this commit (files changed)
        result = run(["git", "show", "--format=", "--name-status", commit])
        if result.returncode != 0:
            continue
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            status, filepath = parts[0], parts[1]
            # Credential files are never opened, even from historical objects.
            name = PurePosixPath(filepath).name
            if name == ".env" or name.startswith(".env."):
                print(f"CREDENTIAL FILE REQUIRES OWNER REVIEW: {commit[:8]}:{filepath}")
                found_any = True
                continue
            # Skip deletions
            if status.startswith("D"):
                continue
            # Get the file content at this commit
            result2 = run(["git", "show", f"{commit}:{filepath}"])
            if result2.returncode != 0:
                continue
            content = result2.stdout
            if not isinstance(content, str) or not content:
                continue
            for pattern, desc in SECRET_PATTERNS:
                try:
                    matches = list(re.finditer(pattern, content))
                except TypeError:
                    continue
                for m in matches:
                    line_no = content[: m.start()].count("\n") + 1
                    # Never print a matched line: partial regex redaction can
                    # expose surrounding credentials or arbitrary secret formats.
                    print(
                        f"POTENTIAL SECRET: {commit[:8]}:{filepath}:{line_no} "
                        f"({desc}; value omitted)"
                    )
                    found_any = True

    if found_any:
        print(
            "\nPotential secrets found in git history. "
            "Review and rotate if real.",
            file=sys.stderr,
        )
        return 1
    print("No secrets found in git history.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
