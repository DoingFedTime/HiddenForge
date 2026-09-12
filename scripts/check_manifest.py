#!/usr/bin/env python3
"""Assert manifest.json agrees with the code. CI drift gate.

The CI step this replaces ran `json.load(open("manifest.json"))`, which parses
the file and compares it to nothing: it passed whatever the file said. A green
tick named "manifest.json must match the code" that does not check that is worse
than no check, because it suppresses the instinct to look.

This compares the file to build_manifest() field by field (the version, the
registered command list, the env contract, the exit codes) and exits non-zero on
any drift, naming the field that moved.

    python3 scripts/check_manifest.py
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_cli():
    """Load scripts/hiddenforge WITHOUT the bytecode cache.

    The CLI has no .py extension, so a SourceFileLoader caches it at
    scripts/__pycache__/hiddenforgecpython-312.pyc. That cache is validated on
    the source's second-resolution mtime AND its size, so a same-second edit that
    does not change the length (e.g. "2.1.0" -> "2.1.1") is served from STALE
    bytecode. That actually happened: this checker reported the old version code
    while the source on disk was correct. Compile the source directly; never
    trust a cache keyed that loosely for a correctness gate.
    """
    import types

    path = os.path.join(ROOT, "scripts", "hiddenforge")
    module = types.ModuleType("hiddenforge_cli")
    module.__file__ = path
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    exec(compile(source, path, "exec"), module.__dict__)
    return module


def main() -> int:
    hf = load_cli()
    with open(os.path.join(ROOT, "manifest.json"), encoding="utf-8") as fh:
        on_disk = json.load(fh)
    expected = hf.build_manifest()

    if on_disk != expected:
        print("manifest.json has drifted from build_manifest():", file=sys.stderr)
        for key in sorted(set(on_disk) | set(expected)):
            if on_disk.get(key) != expected.get(key):
                print(f"  {key}:\n    file: {on_disk.get(key)!r}\n    code: {expected.get(key)!r}",
                      file=sys.stderr)
        return 1

    print(f"manifest.json matches build_manifest(): version {expected['version']}, "
          f"{len(expected['commands'])} commands, contract {expected['contract_version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
