"""scripts/build_inputs.py: the lock, the deterministic pack, the safe fetch.

The signature checks need the real archive and are exercised by CI's
`inputs-integrity` job; these tests cover the parts that decide which files are
accepted at all, on a small synthetic archive.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import tarfile

import pytest

from loader import repo_root

# repo_root, not parents[1]: mutmut runs the suite from a copy of the tree in
# mutants/, which has no scripts/ directory.
SCRIPT = repo_root(__file__) / "scripts" / "build_inputs.py"


@pytest.fixture
def bi(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("build_inputs", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    src = tmp_path / "src"
    (src / "tor").mkdir(parents=True)
    (src / "tor" / "a.tar.gz").write_bytes(b"tor bytes")
    (src / "b.txt").write_bytes(b"bee")
    lines = [
        f"{hashlib.sha256((src / n).read_bytes()).hexdigest()}  ./{n}"
        for n in ("b.txt", "tor/a.tar.gz")
    ]
    lock = tmp_path / "build-inputs.sha256"
    lock.write_text("\n".join(lines) + "\n")
    (src / "MANIFEST.sha256").write_text(lock.read_text())
    monkeypatch.setattr(mod, "LOCK", lock)
    return mod, src


def _lock_only(mod, d):
    """verify() up to and including the lock step (no signatures in the fixture)."""
    with pytest.raises(FileNotFoundError):
        mod.verify(d)  # passes the lock, then looks for the real package index


def test_lock_accepts_exact_archive(bi):
    mod, src = bi
    _lock_only(mod, src)


def test_lock_rejects_extra_file(bi):
    mod, src = bi
    (src / "extra.apk").write_bytes(b"x")
    with pytest.raises(SystemExit, match="unlisted"):
        mod.verify(src)


def test_lock_rejects_changed_file(bi):
    mod, src = bi
    (src / "b.txt").write_bytes(b"bed")
    with pytest.raises(SystemExit, match="does not match"):
        mod.verify(src)


def test_lock_rejects_a_different_manifest(bi):
    """An archive whose own manifest lists other files is not this release's."""
    mod, src = bi
    (src / "MANIFEST.sha256").write_text("00  ./b.txt\n")
    with pytest.raises(SystemExit, match=r"not build-inputs\.sha256"):
        mod.verify(src)


def test_lock_rejects_symlink(bi):
    mod, src = bi
    (src / "b.txt").unlink()
    (src / "b.txt").symlink_to(src / "tor" / "a.tar.gz")
    with pytest.raises(SystemExit):
        mod.verify(src)


def _pack(mod, src, out, monkeypatch):
    monkeypatch.setattr(mod, "verify", lambda d: 0)
    mod.pack(src, out)
    return out.read_bytes()


def test_pack_is_deterministic(bi, tmp_path, monkeypatch):
    mod, src = bi
    a = _pack(mod, src, tmp_path / "a.tar", monkeypatch)
    (src / "b.txt").touch()  # a new mtime must not change the bytes
    b = _pack(mod, src, tmp_path / "b.tar", monkeypatch)
    assert a == b
    with tarfile.open(fileobj=io.BytesIO(a)) as t:
        assert [m.name for m in t.getmembers()] == ["MANIFEST.sha256", "b.txt", "tor/a.tar.gz"]
        assert all(m.mtime == 0 and m.uid == 0 and m.mode == 0o644 for m in t.getmembers())


class _Resp(io.BytesIO):
    def __init__(self, blob, url):
        super().__init__(blob)
        self.url = url

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _serve(mod, monkeypatch, blob, landed_at=None):
    # landed_at: where redirects ended up (urlopen follows them silently).
    monkeypatch.setattr(mod.urllib.request, "urlopen",
                        lambda url, timeout: _Resp(blob, landed_at or url))


def test_fetch_roundtrip(bi, tmp_path, monkeypatch):
    mod, src = bi
    blob = _pack(mod, src, tmp_path / "a.tar", monkeypatch)
    _serve(mod, monkeypatch, blob)
    seen = []
    monkeypatch.setattr(mod, "verify", lambda d: seen.append(d) or 0)
    dest = tmp_path / "dest"
    assert mod.fetch("https://example.invalid/a.tar", dest) == 0
    assert seen == [dest]
    assert (dest / "tor" / "a.tar.gz").read_bytes() == b"tor bytes"


@pytest.mark.parametrize("kind", ["symlink", "parent", "absolute", "unlisted"])
def test_fetch_rejects_hostile_entries(bi, tmp_path, monkeypatch, kind):
    mod, _ = bi
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        if kind == "symlink":
            info = tarfile.TarInfo("b.txt")
            info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
            t.addfile(info)
        else:
            name = {"parent": "../b.txt", "absolute": "/b.txt", "unlisted": "evil"}[kind]
            info = tarfile.TarInfo(name)
            info.size = 1
            t.addfile(info, io.BytesIO(b"x"))
    _serve(mod, monkeypatch, buf.getvalue())
    with pytest.raises(SystemExit, match="unexpected entry"):
        mod.fetch("https://example.invalid/a.tar", tmp_path / "dest")
    assert not (tmp_path / "b.txt").exists()


def test_fetch_refuses_a_redirect_to_plain_http(bi, tmp_path, monkeypatch):
    mod, src = bi
    blob = _pack(mod, src, tmp_path / "a.tar", monkeypatch)
    _serve(mod, monkeypatch, blob, landed_at="http://mirror.invalid/a.tar")
    monkeypatch.setattr(mod, "verify", lambda d: 0)
    with pytest.raises(SystemExit, match="https only"):
        mod.fetch("https://example.invalid/a.tar", tmp_path / "dest")
    assert not any((tmp_path / "dest").iterdir())


def test_fetch_refuses_plain_http_and_nonempty_dest(bi, tmp_path):
    mod, _ = bi
    with pytest.raises(SystemExit, match="https only"):
        mod.fetch("http://example.invalid/a.tar", tmp_path / "d")
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "x").write_text("x")
    with pytest.raises(SystemExit, match="not empty"):
        mod.fetch("https://example.invalid/a.tar", tmp_path / "d")
