#!/usr/bin/env python3
"""Emit the measured coverage from coverage.json, and write coverage.txt.

The coverage number belongs in a generated file, not typed into a markdown
document where it is stale the moment the next test lands. CI runs this after
pytest and the two artifacts (coverage.json, coverage.txt) are the source of
truth any document points at.

    python scripts/coverage_summary.py [coverage.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    src = Path(args[0] if args else "coverage.json")
    pct = json.loads(src.read_text(encoding="utf-8"))["totals"]["percent_covered"]
    line = f"coverage: {pct:.2f}%"
    Path("coverage.txt").write_text(line + "\n", encoding="utf-8")
    print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
