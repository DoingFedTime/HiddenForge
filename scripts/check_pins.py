#!/usr/bin/env python3
"""Report pinned-version drift against the Alpine package index.

Pins are CVE-driven and changed by hand, which is correct: bumping a crypto or
anonymity dependency is a reviewed decision, not an automated one. What is not
acceptable is that a pin silently *disappears* -- as `tor=0.4.9.11-r0` did when
Alpine pruned it, leaving `master` unbuildable until someone hit it. Nothing
watched for that.

This script watches. For every `pkg=version` pin in the runtime stage it checks
the exact version still exists in the pinned Alpine branch:

  - a pin whose exact version is GONE          -> exit 2 (the build will fail)
  - a pin with a newer version available       -> reported, exit 0 (a decision)
  - the index cannot be fetched                -> exit 3 (never a false pass)

Exit 0 means every pinned version still exists. It does not mean they are current;
that is a human call, and the report names what a human should look at.

Usage:
    python3 scripts/check_pins.py [--branch v3.23] [--arch x86_64] [--json]
"""
from __future__ import annotations

import argparse
import http.client
import io
import json
import pathlib
import re
import sys
import tarfile
import urllib.error
import urllib.request
import zlib
from typing import NoReturn

REPO = pathlib.Path(__file__).resolve().parent.parent
DOCKERFILE = REPO / "Dockerfile"
MIRROR = "https://dl-cdn.alpinelinux.org/alpine"
REPOS = ("main", "community")

# Only the runtime stage matters for "does the image still build": the builder
# stage's packages are unpinned build tools in a discarded stage.
_PIN = re.compile(r"\b([a-z0-9][a-z0-9._+-]*)=([0-9][0-9A-Za-z._-]*)")

# semgrep flags argv-derived values flowing into urllib (it supports file://).
# The URL is always the literal https mirror below, but the branch and arch are
# bounded anyway: a value that cannot be a branch or an architecture has no
# business reaching a URL, and rejecting it is cheaper than explaining it.
_BRANCH_RE = re.compile(r"^v[0-9]+(\.[0-9]+)*$")
_ARCH_RE = re.compile(r"^[a-z0-9_]+$")


def _version_key(v: str) -> tuple[tuple[int, int, str], ...]:
    """Approximate Alpine version ordering (numeric components first)."""
    parts = re.split(r"[.\-]", v)
    key = [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in parts]
    return tuple(key)


def _unavailable(message: str) -> NoReturn:
    """Exit 3: the check could not be made. Never confused with a pass (0) or a
    pruned pin (2). `raise SystemExit("...")` would print the message but exit 1,
    which is what this replaced."""
    print(f"check_pins: {message}", file=sys.stderr)
    sys.exit(3)


def parse_pins(text: str) -> dict[str, str]:
    """Return {package: version} from `apk add` argument blocks only.

    Restricting to `apk add` avoids the false positives from unrelated
    `key=value` tokens in the Dockerfile (healthcheck `interval=60s`,
    `strip-components=1`), which are not package pins.
    """
    pins: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if re.search(r"\bapk\s+add\b", lines[i]):
            block = [lines[i]]
            while i + 1 < len(lines) and "&&" not in lines[i]:
                if not lines[i].rstrip().endswith("\\"):
                    break
                i += 1
                block.append(lines[i])
            pins.update(dict(_PIN.findall("\n".join(block))))
        i += 1
    return pins


def fetch_index(branch: str, arch: str) -> dict[str, list[str]]:
    """Return {package: [versions]} from the branch's APKINDEX files."""
    index: dict[str, list[str]] = {}
    for repo in REPOS:
        url = f"{MIRROR}/{branch}/{repo}/{arch}/APKINDEX.tar.gz"
        try:
            # url is the literal https mirror plus branch/arch, and both are
            # bounded by _BRANCH_RE/_ARCH_RE above. Semgrep's dynamic-urllib rule
            # flags the value reaching urlopen; the bare `# nosemgrep` suppresses
            # it, and the rule is named here so the reason travels with the code.
            with urllib.request.urlopen(url, timeout=60) as resp:  # nosemgrep  # noqa: S310
                blob = resp.read()
        except (OSError, http.client.HTTPException) as exc:
            # URLError, timeouts, resets and refused connections are all OSError;
            # a truncated body is an HTTPException. None of them is an answer.
            _unavailable(f"cannot fetch {url}: {exc}")
        try:
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
                member = next((m for m in tar.getmembers() if m.name == "APKINDEX"), None)
                handle = tar.extractfile(member) if member is not None else None
                if handle is None:
                    _unavailable(f"{url} has no readable APKINDEX")
                text = handle.read().decode("utf-8", "replace")
        except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
            _unavailable(f"{url} is not a readable index archive: {exc}")
        name = None
        for block in text.split("\n\n"):
            for line in block.splitlines():
                if line.startswith("P:"):
                    name = line[2:].strip()
                elif line.startswith("V:") and name:
                    index.setdefault(name, []).append(line[2:].strip())
    return index


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--branch", default="v3.23")
    ap.add_argument("--arch", default="x86_64")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    pins = parse_pins(DOCKERFILE.read_text())
    if not pins:
        _unavailable("no pins parsed from Dockerfile (parser drift?)")
    if not _BRANCH_RE.fullmatch(args.branch):
        _unavailable(f"refusing implausible --branch {args.branch!r}")
    if not _ARCH_RE.fullmatch(args.arch):
        _unavailable(f"refusing implausible --arch {args.arch!r}")
    index = fetch_index(args.branch, args.arch)

    missing, stale = [], []
    for name, pinned in sorted(pins.items()):
        versions = index.get(name)
        if versions is None:
            missing.append((name, pinned, "package not in index"))
            continue
        if pinned not in versions:
            missing.append((name, pinned, f"gone; index has {sorted(versions)}"))
            continue
        newest = max(versions, key=_version_key)
        if _version_key(newest) > _version_key(pinned):
            stale.append((name, pinned, newest))

    report = {
        "branch": args.branch,
        "arch": args.arch,
        "pins": pins,
        "missing": [{"package": n, "pinned": p, "detail": d} for n, p, d in missing],
        "newer_available": [
            {"package": n, "pinned": p, "newest": w} for n, p, w in stale
        ],
    }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"checking {len(pins)} pins against Alpine {args.branch}/{args.arch}")
        for name, pinned, detail in missing:
            print(f"  MISSING {name}={pinned}: {detail}")
        for name, pinned, newest in stale:
            print(f"  newer   {name}={pinned} (available {newest}; bump is a decision)")
        if not missing and not stale:
            print("  all pinned versions present and current")

    if missing:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
