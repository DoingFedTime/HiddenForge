#!/usr/bin/env python3
"""A curated mutation kill-check: prove the suite notices security-critical code
being wrong, without depending on mutmut's harness.

Why this exists. mutmut 3.5.0 (the pinned dev venv) generates and maps mutants
correctly, but under this project's pytest configuration (`--import-mode=importlib`
plus a conftest that rewrites sys.path) its full run reported 502 mutants checked
and ZERO killed, while hand-applying the same mutations is caught immediately.
That is a harness-integration defect, not a test weakness, and a kill-rate you
cannot reproduce is not a result -- so this script is the number we can stand
behind. It is deliberately small and security-scoped: every mutation below is a
silent wrong answer in the key-handling, validation or hardening path.

Each mutation is applied to the real source, the named tests are run, and a
non-zero pytest exit is a KILL. The source is restored from memory in a finally,
so an interrupted run cannot leave a mutation behind.

    python scripts/mutation_spotcheck.py

Exit 0 if every mutation is killed, 1 if any survives.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (label, file, exact_old, exact_new, pytest target)
MUTATIONS = [
    (
        "validate_port accepts port 1 -> range starts at 2",
        "entrypoint.py",
        "    if not 1 <= port <= 65535:",
        "    if not 2 <= port <= 65535:",
        "tests/test_validators.py",
    ),
    (
        "service-directory chmod runs AFTER chown (symlink escape)",
        "entrypoint.py",
        "    _chmod_dir_nofollow(hs_dir, 0o700, only_if_root_owned=True)\n"
        "    _chown_r(hs_dir, tor_pw.pw_uid, tor_pw.pw_gid)",
        "    _chown_r(hs_dir, tor_pw.pw_uid, tor_pw.pw_gid)\n"
        "    _chmod_dir_nofollow(hs_dir, 0o700, only_if_root_owned=True)",
        "tests/test_privileged_fs.py",
    ),
    (
        "vanguards-lite guard pin dropped (1 -> 0)",
        "entrypoint.py",
        "VanguardsLiteEnabled 1",
        "VanguardsLiteEnabled 0",
        "tests/test_torrc_gen.py",
    ),
    (
        "restore no longer forces 0600 on key files",
        "scripts/hiddenforge",
        "            for path in sorted(keys.rglob(\"*\")):\n"
        "                if path.is_symlink():\n"
        "                    continue\n"
        "                os.chmod(path, 0o700 if path.is_dir() else 0o600)",
        "            for path in sorted(keys.rglob(\"*\")):\n"
        "                if path.is_symlink():\n"
        "                    continue\n"
        "                os.chmod(path, 0o700 if path.is_dir() else 0o644)",
        "tests/test_backup.py",
    ),
    (
        "validate_service_name accepts a leading hyphen",
        "entrypoint.py",
        "    if not re.fullmatch(r'[a-z0-9][a-z0-9\\-]*', name) or len(name) > 63:",
        "    if not re.fullmatch(r'[a-z0-9\\-][a-z0-9\\-]*', name) or len(name) > 63:",
        "tests/test_validators.py",
    ),
    (
        "image-ref validation accepts a leading dash (docker flag injection)",
        "scripts/hiddenforge",
        'IMAGE_REF_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,254}$")',
        'IMAGE_REF_RE = re.compile(r"^[a-zA-Z0-9-][a-zA-Z0-9._/:@-]{0,254}$")',
        "tests/test_cli.py -k image_ref or validate_image",
    ),
]


def _invalidate_bytecode_cache(path: Path) -> None:
    """Delete the .pyc for a file we just mutated, and bump its mtime.

    Without this the mutation can be invisible: a reorder that keeps the file the
    same size, edited in the same second as the cached .pyc, is served from the
    STALE bytecode, so the tests run the unmutated code and the mutation
    "survives". Two of the six mutations below did exactly that on the first run.
    """
    try:
        cache = Path(importlib.util.cache_from_source(str(path)))
    except (ValueError, NotImplementedError):
        return
    cache.unlink(missing_ok=True)
    future = time.time() + 60
    os.utime(path, (future, future))


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)


def main() -> int:
    killed = 0
    survived: list[str] = []
    for label, rel, old, new, target in MUTATIONS:
        path = ROOT / rel
        original = path.read_text(encoding="utf-8")
        if original.count(old) != 1:
            print(f"SKIP  {label}: anchor found {original.count(old)} times in {rel} "
                  "(the code moved; fix the mutation anchor)")
            survived.append(label)
            continue
        try:
            path.write_text(original.replace(old, new), encoding="utf-8")
            _invalidate_bytecode_cache(path)
            proc = run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                        *target.split()])
        finally:
            path.write_text(original, encoding="utf-8")
            _invalidate_bytecode_cache(path)
        if proc.returncode != 0:
            killed += 1
            print(f"KILLED  {label}")
        else:
            survived.append(label)
            print(f"SURVIVED  {label}  (run: python3 -m pytest {target})")

    total = len(MUTATIONS)
    print(f"\nkill-rate: {killed}/{total}")
    if survived:
        print("survivors (a surviving mutation is a missing test):")
        for s in survived:
            print(f"  - {s}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
