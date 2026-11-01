#!/usr/bin/env python3
"""sentinelx report build - generate the static HTML report from stored results."""

from __future__ import annotations

import sys
from pathlib import Path


def report_cmd(args) -> int:
    if args.report_cmd != "build":
        print(f"Unknown report command: {args.report_cmd}", file=sys.stderr)
        return 1
    return report_build(Path(args.out), Path(args.evaluations),
                        Path(args.db) if args.db else None)


def report_build(out: Path, evaluations: Path, db: Path | None) -> int:
    from sentinelx.report.integrity import check_integrity
    from sentinelx.report.loader import load_all
    from sentinelx.report.render import render_index

    sections = load_all(evaluations)
    integrity = check_integrity(evaluations, db)
    result = render_index(sections, integrity, out)
    for name, section in sections.items():
        if section.ok:
            print(f"{name}: OK ({section.source})")
        else:
            print(f"{name}: {section.status} ({section.error})")
    print(f"evidence integrity: sessions checked {len(integrity.rows)}, OK "
          f"{integrity.ok_count}, failed/missing {len(integrity.failed)} "
          f"(db: {integrity.db_path or 'none found'})")
    print(f"wrote {result.out_path.as_posix()} ({result.size_bytes} bytes)")
    if result.not_available:
        print(f"sections NOT AVAILABLE: {', '.join(sorted(result.not_available))}")
    return 0
