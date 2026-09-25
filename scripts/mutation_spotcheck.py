#!/usr/bin/env python3
"""A curated mutation kill-check for the code mutmut cannot reach.

Scope, and an earlier claim withdrawn. This script was written when a full
`mutmut run` reported ~500 mutants checked and ZERO killed, and its docstring
blamed a harness-integration defect in mutmut 3.5.0 under this project's pytest
configuration. That was wrong, and the real causes were found by reproducing the
run rather than reasoning about it:

  1. `mutmut run` was being invoked as `python -m mutmut`. That executes
     mutmut/__main__.py as `__main__`, so the trampoline's
     `from mutmut.__main__ import record_trampoline_hit` re-imports the whole
     module, which calls `set_start_method('fork')` a second time and raises.
     The stats phase died on the first test. Use the console script (`mutmut`),
     where mutmut.__main__ is already in sys.modules.
  2. tests/test_subprocess_timeouts.py is a source-TEXT audit and read
     `Path(__file__).parent.parent / "entrypoint.py"` -- which, under mutmut, is
     the generated one-function-per-mutant copy, whose call sites no longer have
     their justifying comments adjacent. It failed on an unmutated baseline, and
     the stats phase runs with `-x`, so it aborted the whole run. With no stats,
     every mutant maps to zero tests and is recorded as "not checked".

Both are fixed, mutmut runs, and entrypoint.py / healthcheck.py / vanity.py now
have a real, reproducible kill rate (see `mutmut run && mutmut results`).

What is left for this script is the one file mutmut cannot mutate:
`scripts/hiddenforge` has no .py extension, and mutmut only generates mutants for
files ending in .py (walk_source_files / should_ignore_for_mutation in
mutmut/__main__.py). That file holds the backup encryption, the restore path and
the image-reference validation, so it is exactly the code least acceptable to
leave unmeasured. The entrypoint.py mutations below are kept as a fast canary --
they are also covered by the full run, and a disagreement between the two is
itself a finding.

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
        "                for path in sorted(keys.rglob(\"*\")):\n"
        "                    if path.is_symlink():\n"
        "                        continue\n"
        "                    os.chmod(path, 0o700 if path.is_dir() else 0o600)",
        "                for path in sorted(keys.rglob(\"*\")):\n"
        "                    if path.is_symlink():\n"
        "                        continue\n"
        "                    os.chmod(path, 0o700 if path.is_dir() else 0o644)",
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
    (
        "_safe stops escaping control characters (log injection)",
        "entrypoint.py",
        "        ch if ch.isprintable() else f'\\\\x{ord(ch):02x}'",
        "        ch",
        "tests/test_entrypoint_fs.py",
    ),
    (
        "openssl refusal removed (unauthenticated cipher accepted)",
        "scripts/hiddenforge",
        '        raise ValueError("openssl is refused: it provides no authentication. '
        'Use age or gpg.")',
        '        return plaintext, "none"',
        "tests/test_backup.py",
    ),
    (
        "key-volume size budget checked after the read, not before",
        "scripts/hiddenforge",
        "            total += path.stat().st_size\n"
        "            count += 1\n"
        "            if total > max_bytes:\n"
        '                raise ValueError("key volume is unexpectedly large")\n'
        "            data = path.read_bytes()",
        "            data = path.read_bytes()\n"
        "            total += len(data)\n"
        "            count += 1\n"
        "            if total > max_bytes:\n"
        '                raise ValueError("key volume is unexpectedly large")',
        "tests/test_backup.py",
    ),
    (
        "the key path goes into the compose fragment unquoted (container escape)",
        "scripts/hiddenforge",
        '    keys_mount = json.dumps(f"{keys}:/var/lib/tor/hidden_service")',
        '    keys_mount = f"{keys}:/var/lib/tor/hidden_service"',
        "tests/test_cli.py -k compose_key",
    ),
    (
        "the key path goes into deploy.sh unquoted (arbitrary code execution)",
        "scripts/hiddenforge",
        "    keys_q = shlex.quote(keys_dir)",
        "    keys_q = keys_dir",
        "tests/test_cli.py -k inject_a_command",
    ),
    (
        "a stripped ML-DSA half is shrugged off instead of failing (downgrade)",
        "scripts/hiddenforge",
        "    if pub.is_file() != sig.is_file():\n"
        '        missing = "public key" if sig.is_file() else "signature"\n'
        '        return False, (f"the ML-DSA {missing} is missing while the other half is "\n'
        '                       "present; this signature set has been altered")',
        "    if pub.is_file() != sig.is_file():\n"
        '        return None, "ML-DSA public key or signature missing"',
        "tests/test_cli.py -k mldsa",
    ),
    (
        "--delete-plaintext destroys the key without verifying the archive",
        "scripts/hiddenforge",
        "                recovered = _decrypt_bytes(tool, blob.read_bytes(), passphrase)\n"
        "                if _tar_sha256(recovered) != _tar_sha256(plaintext):",
        "                recovered = plaintext\n"
        "                if _tar_sha256(recovered) != _tar_sha256(plaintext):",
        "tests/test_backup.py",
    ),
    (
        "restore follows a symlinked directory already in the key volume",
        "scripts/hiddenforge",
        "    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)",
        "    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent_fd)",
        "tests/test_backup.py",
    ),
    (
        "restore accepts '..' path-traversal members again",
        "scripts/hiddenforge",
        '                if name.is_absolute() or ".." in name.parts:',
        "                if name.is_absolute():",
        "tests/test_backup.py",
    ),
    (
        "restore reports success over an archive holding no identity",
        "scripts/hiddenforge",
        "                if not restores_a_key:",
        "                if False:",
        "tests/test_backup.py -k no_identity",
    ),
    (
        "restore accepts a control character in an archive member name",
        "scripts/hiddenforge",
        "                    if bad:",
        "                    if False:",
        "tests/test_backup.py -k control_character_in_a_member",
    ),
    (
        "verify-image calls a half-checked hybrid signature complete",
        "scripts/hiddenforge",
        "        complete = ok and not unchecked",
        "        complete = ok",
        "tests/test_cli.py -k not_complete_without_pqsign",
    ),
]


def _invalidate_bytecode_cache(path: Path, *, bump_mtime: bool = True) -> None:
    """Delete the .pyc for a file we just mutated, and bump its mtime.

    Without this the mutation can be invisible: a reorder that keeps the file the
    same size, edited in the same second as the cached .pyc, is served from the
    STALE bytecode, so the tests run the unmutated code and the mutation
    "survives". Two of the mutations below did exactly that on the first run.
    """
    try:
        cache = Path(importlib.util.cache_from_source(str(path)))
    except (ValueError, NotImplementedError):
        return
    cache.unlink(missing_ok=True)
    if not bump_mtime:
        # Restoring the original: the cache is already gone, so the next import
        # recompiles whatever the timestamp says. Leave the file with an honest
        # mtime instead of one 60 seconds in the future -- a future timestamp on
        # a working tree confuses anything that reasons about "changed since",
        # and it cost time here when a source file appeared to have been edited
        # during a mutation run that had only read it.
        now = time.time()
        os.utime(path, (now, now))
        return
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
            _invalidate_bytecode_cache(path, bump_mtime=False)
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
