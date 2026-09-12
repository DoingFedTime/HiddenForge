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

import importlib.machinery
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _NoCacheLoader(importlib.machinery.SourceFileLoader):
    """A SourceFileLoader that never reads or writes a bytecode cache.

    scripts/hiddenforge has no .py extension, so a SourceFileLoader caches it at
    scripts/__pycache__/hiddenforgecpython-312.pyc. That cache is validated on
    the source's second-resolution mtime AND its size, so a same-second edit that
    does not change the length (e.g. "2.1.0" -> "2.1.1") is served from STALE
    bytecode. That actually happened: this checker reported the old version while
    the source on disk was correct. Compiling the source ourselves removes the
    cache, and as a side benefit needs no exec() for a scanner to flag.
    """

    def get_code(self, fullname):
        return compile(self.get_source(fullname), self.path, "exec", dont_inherit=True)


def load_cli():
    """Load scripts/hiddenforge without the bytecode cache."""
    name = "hiddenforge_cli"
    loader = _NoCacheLoader(name, os.path.join(ROOT, "scripts", "hiddenforge"))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
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
