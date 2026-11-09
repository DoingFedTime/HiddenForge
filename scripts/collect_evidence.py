#!/usr/bin/env python3
"""Collect the release evidence bundle.

The problem this solves: HiddenForge's claims are
self-certified and do not travel with the release. A `PRODUCTION-READINESS.md`
that says "292 tests pass" is a sentence; a verifier cannot check it and cannot
tell whether it was ever true.

This produces the artifact that does travel. It runs each gate and writes its
raw output, unedited, into one directory, then hashes the directory so the bundle
itself can be verified. Nothing in the bundle is typed by hand.

Usage:
    python3 scripts/collect_evidence.py [--out evidence] [--image <ref>]

Then, at release time, the bundle is signed alongside the image digest. This
script never signs anything and never invents a result: if a gate cannot run, the
failure is recorded in its own file.
"""
from __future__ import annotations

import argparse
import hashlib
import getpass
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
PY = REPO / ".venv" / "bin" / "python"


def _scrub(text: str) -> str:
    """Remove the build machine's layout and identity from raw output.

    The bundle is published and signed, and gate output is full of absolute
    paths, the user's home directory, temp directories named after the user and
    sometimes the host name. None of that belongs in a public file.
    """
    for real, shown in ((str(REPO), "<repo>"), (str(pathlib.Path.home()), "<home>"),
                        (socket.gethostname(), "<host>")):
        if real and len(real) > 1:
            text = text.replace(real, shown)
    user = re.escape(getpass.getuser())
    text = re.sub(rf"(?<=[/-]){user}(?=[/\s:\"'.,)]|$)", "user", text)
    return re.sub(r"/tmp/user/\d+", "/tmp/user/<uid>", text)


def _run(name: str, cmd: list[str], out: pathlib.Path,
         env: dict[str, str] | None = None) -> int:
    """Run a gate, capture combined output to out/<name>.txt, return its rc."""
    started = time.time()
    try:
        proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True,
                              timeout=1800, check=False, env=env)
        body = "$ " + " ".join(cmd) + "\n\n" + proc.stdout + proc.stderr
        rc = proc.returncode
    except FileNotFoundError as exc:
        body = f"$ {' '.join(cmd)}\n\nGATE COULD NOT RUN: {exc}\n"
        rc = 127
    except subprocess.TimeoutExpired:
        body = f"$ {' '.join(cmd)}\n\nGATE TIMED OUT after 1800s\n"
        rc = 124
    elapsed = time.time() - started
    header = f"# {name}\nexit_code: {rc}\nduration_s: {elapsed:.1f}\n\n"
    (out / f"{name}.txt").write_text(_scrub(header + body))
    return rc


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True,
                          text=True, check=False).stdout.strip()


def _image_digest(image: str | None, out: pathlib.Path) -> str | None:
    """Record the OCI index digest of the built image, if one is available.

    This is the index digest, not `docker image inspect .Id` (the config
    digest); comparing the wrong one reports a false NOT REPRODUCIBLE.
    """
    if not image:
        return None
    proc = subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", image],
        cwd=REPO, capture_output=True, text=True, check=False)
    text = proc.stdout + proc.stderr
    if proc.returncode != 0:
        # A local, unpublished image has no registry index; record the local
        # RepoDigests instead of inventing one. At release time the image is
        # pushed, so the imagetools path is the one that runs.
        local = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}",
             image], cwd=REPO, capture_output=True, text=True, check=False)
        text += (
            "\n(local image; buildx imagetools needs a pushed ref) "
            f"RepoDigests={local.stdout.strip() or '[]'}\n"
        )
    (out / "image-digest.txt").write_text(
        _scrub(f"$ docker buildx imagetools inspect {image}\n\n{text}"))
    if proc.returncode != 0:
        return None
    for line in text.splitlines():
        if "Digest:" in line:
            return line.split("Digest:")[1].strip()
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="evidence")
    ap.add_argument("--image", default=os.environ.get("HIDDENFORGE_IMAGE", ""))
    ap.add_argument("--inputs", default=os.environ.get("HIDDENFORGE_INPUTS", ""),
                    help="the build-input archive directory, verified into the bundle")
    args = ap.parse_args()

    out = (REPO / args.out).resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    # Record what was built, so the bundle is bound to a commit.
    source_date_epoch = _git("log", "-1", "--format=%ct")
    meta = {
        "commit": _git("rev-parse", "HEAD"),
        "commit_subject": _git("log", "-1", "--format=%s"),
        "tree": _git("rev-parse", "HEAD^{tree}"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "source_date_epoch": source_date_epoch,
        "dirty": bool(_git("status", "--porcelain")),
        "collected_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version.split()[0],
        "docker_buildx": subprocess.run(
            ["docker", "buildx", "version"], cwd=REPO, capture_output=True,
            text=True, check=False).stdout.strip(),
    }

    rc_total = 0
    rc_total |= _run("unit-tests", [str(PY), "-m", "pytest", "-q",
                                    "-p", "no:cacheprovider"], out)
    rc_total |= _run("typecheck", ["sh", str(REPO / "scripts" / "typecheck.sh")],
                     out, env={**os.environ, "MYPY": str(PY.parent / "mypy")})
    rc_total |= _run("mutation-spotcheck", [str(PY),
                     str(REPO / "scripts" / "mutation_spotcheck.py")], out)
    rc_total |= _run("manifest-drift", [str(PY),
                     str(REPO / "scripts" / "check_manifest.py")], out)
    rc_total |= _run("lint-ruff", [str(REPO / ".venv" / "bin" / "ruff"),
                                   "check", ".", "scripts/hiddenforge"], out)
    # The runtime (3.0): its own tests, lints, and the differential tests that
    # hold it to the 2.x reference.
    rs = REPO / "hiddenforge-rs"
    rc_total |= _run("rust-fmt", ["cargo", "fmt", "--manifest-path", str(rs / "Cargo.toml"),
                                  "--check"], out)
    rc_total |= _run("rust-clippy", ["cargo", "clippy", "--manifest-path", str(rs / "Cargo.toml"),
                                     "--release", "--locked", "--all-targets", "--",
                                     "-D", "warnings"], out)
    rc_total |= _run("rust-tests", ["cargo", "test", "--manifest-path", str(rs / "Cargo.toml"),
                                    "--release", "--locked"], out)
    rc_total |= _run("differential-tests", [str(PY), "-m", "pytest", "-q", "-p",
                                            "no:cacheprovider", "tests/rust",
                                            "tests/test_wizard_diff.py"], out)
    if args.inputs:
        rc_total |= _run("build-inputs", [str(PY), str(REPO / "scripts" / "build_inputs.py"),
                                          "verify", args.inputs], out)

    # Copy generated artifacts rather than re-running (they are the same run).
    cov = REPO / "coverage.json"
    if cov.exists():
        shutil.copy(cov, out / "coverage.json")
    for extra in ("sbom.spdx.json", "sbom.cdx.json"):
        src = REPO / extra
        if src.exists():
            shutil.copy(src, out / extra)

    meta["image_digest"] = _image_digest(args.image or None, out)
    meta["gates_exit_code"] = rc_total
    (out / "build.json").write_text(_scrub(json.dumps(meta, indent=2)) + "\n")

    # manifest over every file, excluding itself.
    lines = [
        f"{_sha256(path)}  {path.relative_to(out)}"
        for path in sorted(out.rglob("*"))
        if path.is_file() and path.name != "MANIFEST.sha256"
    ]
    (out / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")

    (out / "README.md").write_text(
        "# Release evidence bundle\n\n"
        f"Commit `{meta['commit']}` on `{meta['branch']}`, tree "
        f"`{meta['tree']}`, SOURCE_DATE_EPOCH `{source_date_epoch}`.\n\n"
        "Every file here is raw gate output, captured by "
        "`scripts/collect_evidence.py`; no value is typed by hand. Verify with:\n\n"
        "```\nsha256sum -c MANIFEST.sha256\n```\n\n"
        "`build.json` binds the bundle to the commit and the image index digest. "
        "`MANIFEST.sha256` covers every other file. The bundle is signed alongside "
        "the image digest at release time; signing is never done here.\n")

    print(f"evidence bundle: {out}")
    print(f"gates exit code: {rc_total}")
    print(f"image digest: {meta['image_digest']}")
    return rc_total


if __name__ == "__main__":
    raise SystemExit(main())
