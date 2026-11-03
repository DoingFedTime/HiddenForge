"""Static guard for a shell-precedence bug the Dockerfile shipped with.

`A && B || true && C` parses as `(A && B) || true && C`, so an `|| true` written
to tolerate one cleanup step also swallowed a --require-hashes mismatch in the
pip install before it: a corrupted hash built successfully (measured). Every
tolerated failure must be grouped -- `{ step || true; }` -- so it can only
excuse itself.
"""
import re

import pytest

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


def test_cli_tor_version_matches_the_dockerfile_pin():
    """The CLI reports TOR_VERSION in `info` and manifest.json, but nothing tied it
    to the apk pin the image actually installs. When Alpine pruned 0.4.9.13 and
    the pin moved, the CLI kept advertising the old version. Read both and compare.
    """
    from loader import load_file

    pins = re.findall(r"^\s*tor=([0-9.]+)-r\d+\b", DOCKERFILE.read_text(), re.M)
    assert len(pins) == 1, f"expected exactly one tor apk pin, found {pins}"
    cli = load_file(repo_root(__file__) / "scripts" / "hiddenforge", "hf_cli_torpin")
    assert pins[0] == cli.TOR_VERSION


def test_every_apk_pin_is_documented_with_its_exact_version():
    """The README pin table and docs/DEPENDENCIES.md quote each pinned version.
    A pin bump that forgets either one leaves the published docs naming a package
    the image no longer installs, so read the pins the way check_pins.py does
    and require each one, version included, in both tables."""
    from loader import load_file

    root = repo_root(__file__)
    pins = load_file(root / "scripts" / "check_pins.py", "hf_check_pins").parse_pins(
        DOCKERFILE.read_text())
    expected = {"tor", "python3", "openssl", "zlib", "libexpat", "musl", "su-exec", "py3-pip"}
    assert expected <= set(pins)
    readme = (root / "README.md").read_text()
    deps = (root / "docs" / "DEPENDENCIES.md").read_text()
    missing = [f"README: {p}={v}" for p, v in pins.items()
               if f"| `{p}` apk | `{v}` |" not in readme]
    missing += [f"DEPENDENCIES: {p}={v}" for p, v in pins.items()
                if f"| `{p}` | `{v}` |" not in deps]
    assert not missing, "pins not documented at their exact version: " + ", ".join(missing)


def test_check_pins_exits_3_when_it_cannot_check():
    """Exit 3 means "could not check", distinct from a pruned pin (2). It used to
    be `raise SystemExit("exit 3: ...")`, which prints the text and exits 1."""
    import subprocess
    import sys

    root = repo_root(__file__)
    proc = subprocess.run([sys.executable, str(root / "scripts" / "check_pins.py"),
                           "--branch", "not a branch"],
                          capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 3, (proc.returncode, proc.stderr)
    assert "implausible --branch" in proc.stderr



@pytest.mark.parametrize("failure", ["reset", "partial", "junk", "no-index", "empty-index"])
def test_check_pins_never_mistakes_a_bad_download_for_an_answer(failure, monkeypatch, capsys):
    """Every way of not getting the index is exit 3, not a traceback (exit 1)."""
    import gzip
    import http.client
    import io
    import tarfile

    from loader import load_file

    cp = load_file(repo_root(__file__) / "scripts" / "check_pins.py", "hf_check_pins_f")

    def empty_tar():
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz"):
            pass
        return buf.getvalue()

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake(url, timeout):
        if failure == "reset":
            raise ConnectionResetError("reset by peer")
        if failure == "partial":
            raise http.client.IncompleteRead(b"x")
        if failure == "junk":
            return Resp(gzip.compress(b"not a tar"))
        if failure == "empty-index":
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                info = tarfile.TarInfo("APKINDEX")
                info.size = 0
                tar.addfile(info, io.BytesIO(b""))
            return Resp(buf.getvalue())
        return Resp(empty_tar())

    monkeypatch.setattr(cp.urllib.request, "urlopen", fake)
    with pytest.raises(SystemExit) as exc:
        cp.fetch_index("v3.23", "x86_64")
    assert exc.value.code == 3



def test_check_pins_usage_errors_are_not_mistaken_for_a_pruned_pin():
    """argparse exits 2 on a bad option, which is also "a pin is gone"."""
    import subprocess
    import sys

    proc = subprocess.run([sys.executable, str(repo_root(__file__) / "scripts" / "check_pins.py"),
                           "--no-such-option"], capture_output=True, text=True, timeout=60,
                          check=False)
    assert proc.returncode == 3, (proc.returncode, proc.stderr)


def test_check_pins_an_empty_community_index_is_not_a_pruned_pin(monkeypatch):
    """main lists packages, community comes back as a valid but empty index:
    that is "could not check" (3), not "every community pin is gone" (2)."""
    import io
    import tarfile

    from loader import load_file

    cp = load_file(repo_root(__file__) / "scripts" / "check_pins.py", "hf_check_pins_repo")

    def index(text):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = text.encode()
            info = tarfile.TarInfo("APKINDEX")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake(url, timeout):
        return Resp(index("P:tor\nV:0.4.9.14-r0\n\n" if "/main/" in url else ""))

    monkeypatch.setattr(cp.urllib.request, "urlopen", fake)
    with pytest.raises(SystemExit) as exc:
        cp.fetch_index("v3.23", "x86_64")
    assert exc.value.code == 3


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
    unmoded = [f"{n}: {text}" for n, text in copies
               if not re.search(r"\s--chmod=0[0-7]{3}\s", text)]
    assert unmoded == [], "COPY/ADD without an explicit --chmod:\n" + "\n".join(unmoded)


def test_every_copy_destination_directory_exists_before_the_copy():
    """`COPY --chmod=0644 f /new/dir/f` creates /new/dir with mode 0644 as well
    (measured, BuildKit v0.30.0), and a 0644 directory cannot be entered by any
    non-root user. 2.1.1 shipped /opt/hiddenforge and /usr/local/bin/tests that
    way. Every destination directory must be one the base image already has or
    one an earlier RUN creates with `mkdir -p`.
    """
    base_dirs = {"/tmp", "/usr/local/bin"}  # noqa: S108 - paths inside the image
    created: set[str] = set()
    missing = []
    for n, line in enumerate(_logical_lines(), 1):
        if line.startswith("RUN") and "mkdir -p" in line:
            for arg in line.split("mkdir -p", 1)[1].split("&&", 1)[0].split():
                created.add(arg.rstrip("/"))
        m = re.match(r"(COPY|ADD)\s+(?:--\S+\s+)*\S+\s+(\S+)$", line)
        if m:
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
