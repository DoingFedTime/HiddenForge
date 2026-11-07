"""Static guard for a shell-precedence bug the Dockerfile shipped with.

`A && B || true && C` parses as `(A && B) || true && C`, so an `|| true` written
to tolerate one cleanup step also swallowed a --require-hashes mismatch in the
pip install before it: a corrupted hash built successfully (measured). Every
tolerated failure must be grouped -- `{ step || true; }` -- so it can only
excuse itself.
"""
import re

from loader import repo_root

DOCKERFILE = repo_root(__file__) / "Dockerfile"


def test_every_tolerated_failure_is_grouped():
    bare = []
    for n, line in enumerate(DOCKERFILE.read_text().splitlines(), 1):
        code = line.split("#", 1)[0] if line.lstrip().startswith("#") else line
        tolerated = re.search(r"\|\|\s*(true|:|exit 0)\b|\|\|\s*:", code)
        grouped = (code.strip().startswith("{")
                   and re.search(r"\|\|\s*(true|:|exit 0)\s*;\s*\}", code) is not None)
        if tolerated and not grouped:
            bare.append(f"{n}: {line.strip()}")
    assert not bare, "an ungrouped tolerated failure can excuse earlier steps:\n" + "\n".join(bare)


def test_cli_tor_version_matches_the_tor_the_dockerfile_builds():
    """The CLI reports TOR_VERSION in `info` and manifest.json. Tie it to the
    tarball the Dockerfile compiles, so a Tor update cannot leave the CLI
    advertising the old version."""
    from loader import load_file

    built = re.findall(r"tor/tor-([0-9.]+)\.tar\.gz", DOCKERFILE.read_text())
    assert built and len(set(built)) == 1, f"expected one Tor tarball, found {built}"
    cli = load_file(repo_root(__file__) / "scripts" / "hiddenforge", "hf_cli_torpin")
    assert built[0] == cli.TOR_VERSION


def test_the_tor_tarball_is_locked():
    """The Tor tarball the Dockerfile copies must be one build-inputs.sha256 locks."""
    built = re.findall(r"(tor/tor-[0-9.]+\.tar\.gz)", DOCKERFILE.read_text())
    lock = (repo_root(__file__) / "build-inputs.sha256").read_text()
    for path in set(built):
        assert f"./{path}\n" in lock, f"{path} is not in build-inputs.sha256"


def test_every_copy_states_its_mode():
    """A COPY without --chmod records the build context's mode in its layer, and
    that mode is whatever the builder's checkout and umask produced. The same
    commit cloned under umask 007 and under 022 built two different image
    digests (measured on 2.1.0), which is a reproducibility failure a verifier
    cannot tell from tampering. A `RUN chmod` afterwards does not help: it adds a
    layer and leaves the COPY layer as it was.
    """
    lines = DOCKERFILE.read_text().splitlines()
    copies = [(n, line.strip()) for n, line in enumerate(lines, 1)
              if re.match(r"\s*(COPY|ADD)\s", line)]
    assert copies, "no COPY in the Dockerfile: the parser is looking at the wrong file"
    # From the build context (no --from): its modes come from the checkout. A
    # copy from another stage or from the verified inputs carries modes the
    # build itself set, and the reproducibility job checks those.
    unmoded = [f"{n}: {text}" for n, text in copies
               if "--from=" not in text and not re.search(r"\s--chmod=0[0-7]{3}\s", text)]
    assert unmoded == [], "COPY/ADD from the build context without --chmod:\n" + "\n".join(unmoded)


def test_every_copy_destination_directory_exists_before_the_copy():
    """`COPY --chmod=0644 f /new/dir/f` creates /new/dir with mode 0644 as well
    (measured, BuildKit v0.30.0), and a 0644 directory cannot be entered by any
    non-root user. 2.1.1 shipped /opt/hiddenforge and /usr/local/bin/tests that
    way. Every destination directory must be one the base image already has or
    one an earlier RUN creates with `mkdir -p`.
    """
    base_dirs = {"/", "/build"}  # WORKDIR /build precedes the copies into it
    created: set[str] = set()
    missing = []
    for n, line in enumerate(_logical_lines(), 1):
        if line.startswith("RUN") and "mkdir -p" in line:
            for arg in line.split("mkdir -p", 1)[1].split("&&", 1)[0].split(";", 1)[0].split():
                created.add(arg.rstrip("/"))
                parts = arg.rstrip("/").split("/")
                created.update("/".join(parts[:i]) for i in range(2, len(parts)))
        # Only a copy with --chmod gives the directories it creates that mode.
        m = re.match(r"(COPY|ADD)\s+(?:--\S+\s+)*\S+\s+(\S+)$", line)
        if m and "--chmod=" not in line:
            # A copy without --chmod creates its parents with ordinary modes.
            parts = m.group(2).rstrip("/").split("/")
            created.update("/".join(parts[:i]) for i in range(2, len(parts)))
        elif m:
            dest = m.group(2)
            parent = dest.rstrip("/").rsplit("/", 1)[0] or "/"
            if parent not in base_dirs and parent not in created:
                missing.append(f"{n}: {line}  (parent {parent} is created by the COPY)")
    assert missing == [], "COPY into a directory nothing created first:\n" + "\n".join(missing)


def _logical_lines() -> list[str]:
    """The Dockerfile with comments dropped and backslash continuations joined."""
    out, cur = [], ""
    for raw in DOCKERFILE.read_text().splitlines():
        if raw.lstrip().startswith("#"):
            continue
        if raw.rstrip().endswith("\\"):
            cur += raw.rstrip()[:-1] + " "
            continue
        cur += raw
        if cur.strip():
            out.append(" ".join(cur.split()))
        cur = ""
    return out
