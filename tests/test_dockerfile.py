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
    assert {"tor", "python3", "openssl", "zlib", "su-exec", "py3-pip"} <= set(pins)
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
    import gzip  # noqa: F401
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
