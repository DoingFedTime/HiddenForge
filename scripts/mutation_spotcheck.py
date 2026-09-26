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

Each mutation is applied to a THROWAWAY COPY of the tree, the named tests are
run there, and a non-zero pytest exit is a KILL. It used to rewrite the real
source and restore it in a `finally`: anything that read the working tree during
a run saw a mutant (a scratch image build did, 2026-09-25), and a SIGKILL would
have left one behind. The real tree is now only ever read.

    python scripts/mutation_spotcheck.py

Exit 0 if every mutation is killed, 1 if any survives.
"""
from __future__ import annotations

import importlib.util
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
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
        "        _secure_service_dir(hs_dir)\n"
        "        _chown_r(hs_dir, tor_pw.pw_uid, tor_pw.pw_gid)",
        "        _chown_r(hs_dir, tor_pw.pw_uid, tor_pw.pw_gid)\n"
        "        _secure_service_dir(hs_dir)",
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
        "        with os.fdopen(fd, \"wb\") as fh:\n"
        "            os.fchmod(fh.fileno(), 0o600)\n"
        "            fh.write(src_fh.read())",
        "        with os.fdopen(fd, \"wb\") as fh:\n"
        "            os.fchmod(fh.fileno(), 0o644)\n"
        "            fh.write(src_fh.read())",
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
        "tests/test_cli.py -k 'image_ref or validate_image'",
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
        '                raise ValueError("key volume is unexpectedly large")\n',
        "            data = _read_nofollow(path, max_bytes)\n"
        "            total += len(data)\n"
        "            count += 1\n"
        "            if total > max_bytes:\n"
        '                raise ValueError("key volume is unexpectedly large")\n',
        "tests/test_backup.py -k 'size_budget or oversized'",
    ),
    (
        "backup reads a key file through a symlink swapped in after the check",
        "scripts/hiddenforge",
        "            data = _read_nofollow(path, max_bytes)",
        "            data = path.read_bytes()",
        "tests/test_backup.py -k swapped_for_a_symlink",
    ),
    (
        "vanity accepts a key path the engine cannot mount",
        "scripts/hiddenforge",
        '    if ":" in str(keys):',
        "    if False:",
        "tests/test_cli.py -k cannot_mount",
    ),
    (
        "doctor fails every tor-owned service directory seen from the host",
        "scripts/hiddenforge",
        "        except PermissionError:\n            closed.append(name)\n            continue\n",
        "",
        "tests/test_doctor_keys.py",
    ),
    (
        "status answers not-ready without saying why",
        "scripts/hiddenforge",
        "    if not ready and not reason:",
        "    if False:",
        "tests/test_cli.py -k inconsistent_key_set_as_the_reason",
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
        "    keys_q = shlex.quote(keys_dir)\n    # Inside an echo's",
        "    keys_q = keys_dir\n    # Inside an echo's",
        "tests/test_cli.py -k inject_a_command",
    ),
    (
        "a stripped ML-DSA half is shrugged off instead of failing (downgrade)",
        "scripts/hiddenforge",
        "    if trusted_pub is None and pub.is_file() != sig.is_file():\n"
        '        missing = "public key" if sig.is_file() else "signature"\n'
        '        return False, (f"the ML-DSA {missing} is missing while the other half is "\n'
        '                       "present; this signature set has been altered")',
        "    if trusted_pub is None and pub.is_file() != sig.is_file():\n"
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
        '        if name.is_absolute() or ".." in name.parts:',
        "        if name.is_absolute():",
        "tests/test_backup.py",
    ),
    (
        "restore reports success over an archive holding no identity",
        "scripts/hiddenforge",
        "    if not has_identity:\n        raise ValueError(\n            f\"this archive",
        "    if False:\n        raise ValueError(\n            f\"this archive",
        "tests/test_backup.py -k no_identity",
    ),
    (
        "restore accepts a control character in an archive member name",
        "scripts/hiddenforge",
        "        if bad:\n            raise ValueError(\n"
        "                f\"refusing archive member",
        "        if False:\n            raise ValueError(\n"
        "                f\"refusing archive member",
        "tests/test_backup.py -k control_character_in_a_member",
    ),
    (
        "verify-image calls a half-checked hybrid signature complete",
        "scripts/hiddenforge",
        "        complete = ok and not unchecked",
        "        complete = ok",
        "tests/test_cli.py -k not_complete_without_pqsign",
    ),
    (
        "verify-image trusts the signature directory's own allowed-signers again",
        "scripts/hiddenforge",
        '            allowed_signers = "\\n".join(PINNED_ALLOWED_SIGNERS) + "\\n"',
        '            allowed_signers = (sigdir / "allowed-signers").read_text()',
        "tests/test_verify_trust.py",
    ),
    (
        "verify-image accepts an ML-DSA public key that is not the pinned one",
        "scripts/hiddenforge",
        "        if hashlib.sha256(pub_bytes).hexdigest() != PINNED_MLDSA_PUB_SHA256:",
        "        if False:",
        "tests/test_verify_trust.py",
    ),
    (
        "verify-image exits 0 with the ML-DSA half unchecked, without being asked to",
        "scripts/hiddenforge",
        "            if not args.allow_classical_only:",
        "            if False:",
        "tests/test_verify_trust.py",
    ),
    (
        "decrypt-key extracts over an existing key set again",
        "scripts/hiddenforge",
        "            if d.is_dir() and any(d.iterdir()):",
        "            if False:",
        "tests/test_backup.py -k decrypt",
    ),
    (
        "a refused restore leaves directories behind (conflict scan creates them)",
        "scripts/hiddenforge",
        "_dir_fd_under(root_fd, parts[:-1], dir_fds, create=False)",
        "_dir_fd_under(root_fd, parts[:-1], dir_fds)",
        "tests/test_backup.py -k leaves_nothing_behind",
    ),
    (
        "restore keeps a published address file that may name the replaced key",
        "scripts/hiddenforge",
        "        stale = _drop_stale_published(keys, restored)",
        "        stale = []",
        "tests/test_backup.py -k stale",
    ),
    (
        "show reports the hostname file's address when the key disagrees",
        "scripts/hiddenforge",
        "    if derived_matches is False:\n        extra =",
        "    if False:\n        extra =",
        "tests/test_cli.py -k 'inconsistent or derived'",
    ),
    (
        "setup's README prints the key path unquoted inside a command",
        "scripts/hiddenforge",
        "    keys_q = shlex.quote(keys_dir)\n    return f\"\"\"hiddenforge, your setup",
        "    keys_q = keys_dir\n    return f\"\"\"hiddenforge, your setup",
        "tests/test_cli.py -k 'readme or descriptor'",
    ),
    (
        "setup's descriptor carries the output path unquoted in merge/bare_command",
        "scripts/hiddenforge",
        '        fragment_q = shlex.quote(f"{out}/compose.service.yml")',
        '        fragment_q = f"{out}/compose.service.yml"',
        "tests/test_cli.py -k 'readme or descriptor'",
    ),
    (
        "setup stops validating --container (a YAML key in the fragment)",
        "scripts/hiddenforge",
        "        container = validate_container(args.container)",
        "        container = args.container",
        "tests/test_cli.py -k container",
    ),
    (
        "doctor demands the rootful capability set under rootless Podman again",
        "scripts/hiddenforge",
        "    required = ROOTLESS_REQUIRED_CAP_ADD if _is_rootless() else REQUIRED_CAP_ADD",
        "    required = REQUIRED_CAP_ADD",
        "tests/test_cli.py -k doctor",
    ),
    (
        "restore/decrypt-key accept a truncated or untagged secret key",
        "scripts/hiddenforge",
        "            if m.size != SECRET_KEY_FILE_LEN or not head.startswith(SECRET_TAG):",
        "            if False:",
        "tests/test_backup.py -k named_like_a_key",
    ),
    (
        "doctor passes a tor-owned service the container reported nothing about",
        "scripts/hiddenforge",
        "        if n in covered:\n            continue\n        if configured",
        "        if True:\n            continue\n        if configured",
        "tests/test_doctor_keys.py",
    ),
    (
        "doctor downgrades a CONFIGURED service the container is silent about to a warning",
        "scripts/hiddenforge",
        "        if configured is not None and n not in configured:",
        "        if True:",
        "tests/test_doctor_keys.py",
    ),
    (
        "status blames waiting for an inconsistent key set",
        "scripts/hiddenforge",
        "        if inconsistent:\n            reason =",
        "        if False:\n            reason =",
        "tests/test_cli.py -k inconsistent_key_set_as_the_reason",
    ),
    (
        "the supervisor opens its temp file without O_EXCL (hardlink clobbers the key)",
        "entrypoint.py",
        "os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)",
        "os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)",
        "tests/test_publication.py -k hardlink",
    ),
    (
        "the supervisor's address read blocks on a FIFO again",
        "entrypoint.py",
        "    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)\n    try:\n"
        "        if not stat.S_ISREG",
        "    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)\n    try:\n"
        "        if not stat.S_ISREG",
        "tests/test_publication.py -k fifo",
    ),
    (
        "the CLI's key-volume read blocks on a FIFO again",
        "scripts/hiddenforge",
        "    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)",
        "    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)",
        "tests/test_cli.py -k fifo",
    ),
    (
        "_chown_r chowns a hardlinked file (and so the file it links to) again",
        "entrypoint.py",
        "        if not stat.S_ISDIR(st.st_mode) and st.st_nlink > 1:",
        "        if False:",
        "tests/test_privileged_fs.py -k hardlinked",
    ),
    (
        "setup, backup and encrypt-key write through whatever inode sits at the output path again",
        "scripts/hiddenforge",
        "    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)\n"
        "    try:\n        with os.fdopen(fd, \"wb\") as fh:\n"
        "            fh.write(data)\n            fh.flush()\n"
        "            os.fchmod(fh.fileno(), mode)\n"
        "            if owner is not None:\n                os.fchown(fh.fileno(), *owner)\n"
        "            os.fsync(fh.fileno())\n        os.replace(tmp, path)",
        "    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)\n"
        "    try:\n        with os.fdopen(fd, \"wb\") as fh:\n"
        "            fh.write(data)\n            fh.flush()\n"
        "            os.fchmod(fh.fileno(), mode)\n"
        "            if owner is not None:\n                os.fchown(fh.fileno(), *owner)\n"
        "            os.fsync(fh.fileno())",
        "tests/test_cli.py tests/test_backup.py -k 'hardlinked_output or hardlink'",
    ),
    (
        "extraction writes key material through a hardlink planted after the scan",
        "scripts/hiddenforge",
        "        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,",
        "        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,",
        "tests/test_backup.py -k planted_after_the_scan",
    ),
    (
        "status runs the in-container healthcheck as root again (rootless: never ready)",
        "scripts/hiddenforge",
        '    hc = (_docker_exec_json(resolved, ["su-exec", "tor", "python3",',
        '    hc = (_docker_exec_json(resolved, ["python3",',
        "tests/test_cli.py -k rootless_podman",
    ),
    (
        "status stops filling host-unreadable addresses from the container",
        "scripts/hiddenforge",
        '            if a["onion"] is None and e["source"] is None:',
        "            if False:",
        "tests/test_cli.py -k rootless_podman",
    ),
    (
        "doctor trusts the engine's capability report over the measured bounding set",
        "scripts/hiddenforge",
        '    if runtime.get("capbnd") is not None:',
        "    if False:",
        "tests/test_doctor_keys.py -k caps",
    ),
    (
        "rotate renames a mount point again (EBUSY inside the container)",
        "scripts/hiddenforge",
        "        if os.path.ismount(keys):",
        "        if False:",
        "tests/test_cli.py -k mount_point",
    ),
    (
        "show ignores --container when the host cannot read the address",
        "scripts/hiddenforge",
        "    if container is None or entry[\"onion\"] is not None "
        "or entry[\"source\"] is not None:",
        "    if True:",
        "tests/test_doctor_keys.py -k with_container",
    ),
    (
        "backup silently skips a service directory it cannot read (no key in it)",
        "scripts/hiddenforge",
        "    for root, dirs, files in os.walk(keys, onerror=fail, followlinks=False):",
        "    for root, dirs, files in os.walk(keys, followlinks=False):",
        "tests/test_backup.py -k cannot_read_a_service_directory",
    ),
    (
        "backup writes an archive with no identity in it",
        "scripts/hiddenforge",
        "        if not has_identity:\n            raise ValueError(\n"
        "                f\"no {SECRET_FILE} and no encrypted key envelope under {keys}",
        "        if False:\n            raise ValueError(\n"
        "                f\"no {SECRET_FILE} and no encrypted key envelope under {keys}",
        "tests/test_backup.py -k no_identity_is_not_backed_up",
    ),
    (
        "the publication gate is asked every second again",
        "entrypoint.py",
        "        if self._no_until is not None and now < self._no_until:",
        "        if False:",
        "tests/test_publication.py -k remembered",
    ),
    (
        "one lookup is enough to restart over a moved backend",
        "entrypoint.py",
        "            if self.misses[name] >= BACKEND_MOVE_CONFIRMATIONS:",
        "            if self.misses[name] >= 1:",
        "tests/test_backend_watch.py -k consecutive",
    ),
    (
        "a failed lookup counts as evidence of a move",
        "entrypoint.py",
        "            except (OSError, UnicodeError):\n                self.misses[name] = 0\n"
        "                continue",
        "            except (OSError, UnicodeError):\n                self.misses[name] += 1\n"
        "                continue",
        "tests/test_backend_watch.py -k failed_lookup",
    ),
    (
        "a service directory the operator created keeps its open mode again",
        "entrypoint.py",
        "            os.fchmod(fd, 0o700)\n        except PermissionError as exc:",
        "            pass\n        except PermissionError as exc:",
        "tests/test_torrc_write.py -k tightened",
    ),
    (
        "a symlink at a service path is not named before use",
        "entrypoint.py",
        "    if st is not None and not stat.S_ISDIR(st.st_mode):",
        "    if False:",
        "tests/test_privileged_fs.py -k chmods_before_chown",
    ),
    (
        "the socket wait ignores a Tor that already died",
        "entrypoint.py",
        "        if tor is not None and tor.poll() is not None:",
        "        if False:",
        "tests/test_probes.py -k died",
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


_COPY_IGNORE = shutil.ignore_patterns(".git", ".venv", "mutants", "__pycache__",
                                      ".hypothesis", ".pytest_cache", "*.pyc",
                                      "evidence", "security-reports")


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="hf-spotcheck-") as tmp:
        work = Path(tmp) / "tree"
        shutil.copytree(ROOT, work, ignore=_COPY_IGNORE)
        return _check_all(work)


def _check_all(work: Path) -> int:
    killed = 0
    survived: list[str] = []
    for label, rel, old, new, target in MUTATIONS:
        path = work / rel
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
                        *shlex.split(target)], work)
        finally:
            path.write_text(original, encoding="utf-8")
            _invalidate_bytecode_cache(path, bump_mtime=False)
        # Only exit 1 -- "tests ran and at least one failed" -- is a kill. Any
        # other non-zero code means the tests did not run as intended (2: usage
        # error, 4: a target that does not exist, 5: a -k filter that selected
        # nothing), and counting those as kills is how an unparsed `-k a or b`
        # target was reported KILLED here without running a single test.
        if proc.returncode == 1:
            killed += 1
            print(f"KILLED  {label}")
        elif proc.returncode == 0:
            survived.append(label)
            print(f"SURVIVED  {label}  (run: python3 -m pytest {target})")
        else:
            survived.append(label)
            tail = (proc.stdout + proc.stderr).strip().splitlines()[-1:]
            print(f"ERROR  {label}: pytest exited {proc.returncode}, so no verdict "
                  f"({' '.join(tail)})")

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
