"""Shared helpers for the binary-level CLI tests (no tests live here).

The expected values come from the Python host CLI (scripts/hiddenforge) and
vanity.py, which stay in the repository as the reference: `Pair` runs the same
arguments against both on identical fixtures and `same()` compares what a caller
sees (exit code, stdout, stderr, and the state left on disk).
"""

import base64
import hashlib
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
RUST = Path(os.environ.get("HIDDENFORGE_RUST_BIN")
            or REPO / "hiddenforge-rs" / "target" / "release" / "hiddenforge")
PY_CLI = REPO / "scripts" / "hiddenforge"
PY_VANITY = REPO / "vanity.py"
FAKE = REPO / "tests" / "fake_mkp224o.py"

needs_rust = pytest.mark.skipif(
    not RUST.exists(), reason="build hiddenforge-rs first (cargo build --release)"
)

PUBLIC_TAG = b"== ed25519v1-public: type0 =="
PUB = bytes(range(1, 33))
OTHER_PUB = bytes(range(101, 133))


def derive(pub: bytes) -> str:
    """Tor v3 address of an ed25519 public key (rend-spec-v3 section 6)."""
    checksum = hashlib.sha3_256(b".onion checksum" + pub + b"\x03").digest()[:2]
    return base64.b32encode(pub + checksum + b"\x03").decode("ascii").lower() + ".onion"


ONION = derive(PUB)
OTHER_ONION = derive(OTHER_PUB)


def pubfile(pub: bytes = PUB) -> bytes:
    return PUBLIC_TAG.ljust(32, b"\x00") + pub


@dataclass
class Result:
    rc: int
    out: str
    err: str


def env_for(**extra: str) -> dict:
    return {"PATH": os.environ["PATH"], "HOME": tempfile.gettempdir(), **extra}


def _run(cmd, cwd, env, stdin, timeout) -> Result:
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True,
                       stdin=stdin if stdin is not None else subprocess.DEVNULL,
                       timeout=timeout)
    return Result(p.returncode, p.stdout, p.stderr)


def rust(args, cwd, env=None, stdin=None, timeout=60, argv0="hiddenforge") -> Result:
    """Run the Rust binary under the name `argv0` (a symlink in a private dir)."""
    exe = RUST
    if argv0 != "hiddenforge":
        link_dir = Path(tempfile.mkdtemp(prefix="hf-argv0-"))
        try:
            (link_dir / argv0).symlink_to(RUST)
            return _run([str(link_dir / argv0), *args], cwd,
                        env if env is not None else env_for(), stdin, timeout)
        finally:
            (link_dir / argv0).unlink()
            link_dir.rmdir()
    return _run([str(exe), *args], cwd, env if env is not None else env_for(), stdin, timeout)


def py(args, cwd, env=None, stdin=None, timeout=60) -> Result:
    return _run([sys.executable, str(PY_CLI), *args], cwd,
                env if env is not None else env_for(), stdin, timeout)


_TIME = re.compile(r"(?<![0-9])1[0-9]{9}(?![0-9])")


def norm(s: str) -> str:
    """Epoch-second archive names differ between two runs; nothing else may."""
    return _TIME.sub("<T>", s)


def snapshot(root: Path) -> dict:
    """Relative path -> (kind, mode, content for small files) for a whole tree."""
    snap = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for n in [*dirnames, *filenames]:
            p = Path(dirpath) / n
            st = p.lstat()
            rel = norm(str(p.relative_to(root)))
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                snap[rel] = ("link", os.readlink(p))
            elif stat.S_ISDIR(st.st_mode):
                snap[rel] = ("dir", mode)
            elif not stat.S_ISREG(st.st_mode):
                snap[rel] = ("special", stat.S_IFMT(st.st_mode), mode)
            else:
                try:
                    body = p.read_bytes()[:4096]
                    for form in {str(root), os.path.realpath(root)}:
                        body = body.replace(form.encode(), b"<D>")
                except OSError:
                    body = None
                snap[rel] = ("file", mode, body)
    return snap


def same(a: Result, b: Result, what: str = "") -> None:
    assert (norm(a.out), a.rc) == (norm(b.out), b.rc), (
        f"{what}\nrust: rc={a.rc}\n{a.out}\n{a.err}\npython: rc={b.rc}\n{b.out}\n{b.err}")
    assert norm(a.err) == norm(b.err), f"{what}\nstderr differs\nrust: {a.err}\npython: {b.err}"


class Pair:
    """Two identical scratch directories, one per implementation."""

    def __init__(self, root: Path, build):
        self.dirs = []
        for tag in ("rust", "py"):
            d = root / tag
            d.mkdir()
            build(d)
            self.dirs.append(d)

    def run(self, args, rust_args=None, env=None, stdin=None):
        r = rust(rust_args if rust_args is not None else args, self.dirs[0], env, stdin)
        p = py(args, self.dirs[1], env, stdin)
        return r, p

    def check(self, args, rust_args=None, env=None, stdin=None, what=""):
        r, p = self.run(args, rust_args, env, stdin)
        same(r, p, what or " ".join(args))
        assert snapshot(self.dirs[0]) == snapshot(self.dirs[1]), f"{what}: files left behind differ"
        return r


def reopen(root: Path) -> None:
    """Make every directory under root traversable so the tree can be removed."""
    for dirpath, dirnames, _ in os.walk(root):
        for n in dirnames:
            try:
                os.chmod(Path(dirpath) / n, 0o700)
            except OSError:
                pass
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass


@pytest.fixture
def scratch(tmp_path):
    """A temp dir whose tree is made removable again even when a test fails."""
    yield tmp_path
    reopen(tmp_path)


def write(path: Path, data, mode: int | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)
    if mode is not None:
        path.chmod(mode)
    return path


def service(keys: Path, name: str, hostname=ONION, pub=PUB, secret=True,
            dirmode=0o700, keymode=0o600, sealed=False) -> Path:
    """One key directory as Tor leaves it. `hostname`/`pub` of None omit the file."""
    d = keys / name
    d.mkdir(parents=True, exist_ok=True)
    if hostname is not None:
        write(d / "hostname", hostname + "\n", 0o644)
    if pub is not None:
        write(d / "hs_ed25519_public_key", pubfile(pub), 0o600)
    if secret:
        write(d / ("hs_ed25519_secret_key.enc" if sealed else "hs_ed25519_secret_key"),
              b"S" * 96, keymode)
    d.chmod(dirmode)
    return d
