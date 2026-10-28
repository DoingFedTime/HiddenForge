#!/usr/bin/env python3
"""Move apk pins whose exact version Alpine has pruned to the version it now carries.

`check_pins.py` reports a pin that has disappeared from the index (exit 2). This
script acts on that report: for every such pin it writes the newest version the
index lists into the Dockerfile and into the places that quote the pin
(README.md and docs/DEPENDENCIES.md), then prints what it changed.

It changes pins and nothing else. It does not build, scan, sign or publish, and
it never touches a pin that still exists unless `--all` is given. A bumped tree
is a candidate: it must still pass the build, the scan and the tests before it is
released.

Exit codes: 0 nothing needed changing, 10 pins were changed, 3 the index could
not be read (nothing is written).

Usage:
    python3 scripts/bump_pins.py [--branch v3.23] [--arch x86_64] [--all] [--root DIR] [--json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent


def _load_check_pins():
    spec = importlib.util.spec_from_file_location("check_pins", HERE / "check_pins.py")
    if spec is None or spec.loader is None:
        raise SystemExit("bump_pins: cannot load check_pins.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Files that quote a pin as `name=version` or as a bare version next to the name.
QUOTING = ("README.md", "docs/DEPENDENCIES.md")


def plan(
    pins: dict[str, str], index: dict[str, list[str]], key, bump_all: bool
) -> dict[str, tuple[str, str]]:
    """{package: (old, new)} for the pins that must move."""
    out: dict[str, tuple[str, str]] = {}
    for name, pinned in sorted(pins.items()):
        versions = index.get(name)
        if not versions:
            continue
        newest = max(versions, key=key)
        gone = pinned not in versions
        if newest != pinned and (gone or (bump_all and key(newest) > key(pinned))):
            out[name] = (pinned, newest)
    return out


def apply(root: pathlib.Path, changes: dict[str, tuple[str, str]]) -> list[str]:
    """Rewrite the Dockerfile and the quoting docs. Returns the files changed."""
    touched: list[str] = []
    dockerfile = root / "Dockerfile"
    text = dockerfile.read_text()
    new_text = text
    for name, (old, new) in changes.items():
        pattern = re.compile(rf"(\b{re.escape(name)}=){re.escape(old)}(?![0-9A-Za-z._-])")
        new_text, n = pattern.subn(rf"\g<1>{new}", new_text)
        if n == 0:
            raise SystemExit(f"bump_pins: {name}={old} is not in the Dockerfile; nothing written")
    if new_text != text:
        dockerfile.write_text(new_text)
        touched.append("Dockerfile")
    for rel in QUOTING:
        path = root / rel
        if not path.exists():
            continue
        doc = path.read_text()
        out = doc
        for name, (old, new) in changes.items():
            # `name=old` anywhere, the table form "| `name` apk | `old` |", and the
            # bare "`=old`" the README uses when the package was just named.
            tail = r"(?![0-9A-Za-z._-])"
            old_re = re.escape(old)
            out = re.sub(rf"(\b{re.escape(name)}=){old_re}{tail}", rf"\g<1>{new}", out)
            out = re.sub(
                rf"(\|\s*`{re.escape(name)}`[^|\n]*\|\s*`){old_re}(`)", rf"\g<1>{new}\g<2>", out
            )
            out = re.sub(rf"(`=){old_re}{tail}", rf"\g<1>{new}", out)
        if out != doc:
            path.write_text(out)
            touched.append(rel)
    return touched


def main() -> int:
    cp = _load_check_pins()
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--branch", default="v3.23")
    ap.add_argument("--arch", default="x86_64")
    ap.add_argument("--all", action="store_true",
                    help="also bump pins that still exist but are not the newest")
    ap.add_argument("--root", default=str(cp.REPO),
                    help="repository root (default: this repository)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if not (cp._BRANCH_RE.fullmatch(args.branch) and cp._ARCH_RE.fullmatch(args.arch)):
        print("bump_pins: implausible --branch or --arch", file=sys.stderr)
        return 3
    root = pathlib.Path(args.root)
    pins = cp.parse_pins((root / "Dockerfile").read_text())
    if not pins:
        print("bump_pins: no pins parsed from the Dockerfile", file=sys.stderr)
        return 3
    index = cp.fetch_index(args.branch, args.arch)  # exits 3 if unreadable
    changes = plan(pins, index, cp._version_key, args.all)
    touched = apply(root, changes) if changes else []
    if args.json:
        report = {"changes": {k: {"from": a, "to": b} for k, (a, b) in changes.items()},
                  "files": touched}
        print(json.dumps(report, indent=2))
    elif changes:
        for name, (old, new) in changes.items():
            print(f"  {name}: {old} -> {new}")
        print("changed: " + ", ".join(touched))
    else:
        print("no pin needs to move")
    return 10 if changes else 0


if __name__ == "__main__":
    raise SystemExit(main())
