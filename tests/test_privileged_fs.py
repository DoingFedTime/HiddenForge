"""Tests for the privileged filesystem helpers in entrypoint.py.

These helpers run as root (PID 1) over the operator-supplied hidden-service bind
mount, so every path they touch is attacker-influenceable if that volume is ever
restored from untrusted media or is writable by another host user.

The property under test is narrow and absolute: **no operation may ever follow a
symlink out of the hidden-service tree.** Before this was fixed, ``_chown_r``
used a plain ``os.chown()``, which follows symlinks — giving a hostile key volume
a root-privileged arbitrary-chown primitive (demonstrated: a symlink inside the
key dir caused a file outside it to change owner 0 -> 100).

The chown tests do not require root: they assert on *how* the syscall is invoked
rather than on its effect, which is both root-free and a stricter check.
"""
import errno
import os
from collections import namedtuple

import pytest

import entrypoint as e


# ─────────────────────────────────────────────────────────────────────────────
# _open_dir_nofollow — the primitive everything else is built on
# ─────────────────────────────────────────────────────────────────────────────

def test_open_dir_nofollow_opens_a_real_directory(tmp_path):
    d = tmp_path / "real"
    d.mkdir()
    fd = e._open_dir_nofollow(str(d))
    try:
        assert os.fstat(fd).st_ino == os.stat(str(d)).st_ino
    finally:
        os.close(fd)


def test_open_dir_nofollow_refuses_a_symlinked_directory(tmp_path):
    """A symlinked hidden-service dir must fail loudly, not be silently followed."""
    target = tmp_path / "outside"
    target.mkdir()
    link = tmp_path / "hs"
    link.symlink_to(target)

    with pytest.raises(OSError) as exc:
        e._open_dir_nofollow(str(link))
    # O_DIRECTORY is evaluated before O_NOFOLLOW, so the kernel reports ENOTDIR
    # here rather than ELOOP. What matters is that the open is REFUSED.
    assert exc.value.errno == errno.ENOTDIR


def test_open_dir_nofollow_refuses_a_regular_file(tmp_path):
    f = tmp_path / "notadir"
    f.write_text("x")
    with pytest.raises(OSError) as exc:
        e._open_dir_nofollow(str(f))
    assert exc.value.errno == errno.ENOTDIR


# ─────────────────────────────────────────────────────────────────────────────
# _chmod_dir_nofollow
# ─────────────────────────────────────────────────────────────────────────────

def test_chmod_dir_nofollow_sets_mode(tmp_path):
    d = tmp_path / "hs"
    d.mkdir()
    os.chmod(str(d), 0o777)  # noqa: S103 - the loose mode is the precondition under test
    assert e._chmod_dir_nofollow(str(d), 0o700) is True
    assert os.stat(str(d)).st_mode & 0o777 == 0o700


def test_chmod_dir_nofollow_does_not_chmod_through_a_symlink(tmp_path):
    """The symlink target's mode must be untouched."""
    target = tmp_path / "outside"
    target.mkdir()
    os.chmod(str(target), 0o755)  # noqa: S103 - must stay 0755; that is the assertion
    link = tmp_path / "hs"
    link.symlink_to(target)

    with pytest.raises(OSError) as exc:
        e._chmod_dir_nofollow(str(link), 0o700)
    assert exc.value.errno == errno.ENOTDIR
    assert os.stat(str(target)).st_mode & 0o777 == 0o755, \
        "symlink target was chmod'ed — the escape is still open"


def test_chmod_dir_nofollow_skips_when_not_root_owned(tmp_path):
    """only_if_root_owned must not chmod a dir we do not own as root.

    The test process is not root, so the directory is owned by a non-zero uid and
    the mode must be left exactly as-is.
    """
    d = tmp_path / "hs"
    d.mkdir()
    os.chmod(str(d), 0o755)  # noqa: S103 - must be left untouched; that is the assertion
    assert e._chmod_dir_nofollow(str(d), 0o700, only_if_root_owned=True) is False
    assert os.stat(str(d)).st_mode & 0o777 == 0o755


def test_chmod_dir_nofollow_leaks_no_file_descriptors(tmp_path):
    """The fd must be closed on both the success and the skip path."""
    d = tmp_path / "hs"
    d.mkdir()
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(50):
        e._chmod_dir_nofollow(str(d), 0o700)
        e._chmod_dir_nofollow(str(d), 0o700, only_if_root_owned=True)
    after = len(os.listdir("/proc/self/fd"))
    assert after <= before + 1, f"fd leak: {before} -> {after}"


def _record_chowns(monkeypatch, calls, *, realpath=False, basename=False):
    """Record every ownership change _chown_r makes, by path.

    It chowns symlinks with lchown and everything else through a descriptor
    (fchown), so both are recorded; an fchown is reported with the path the
    descriptor was opened on, read back from /proc/self/fd.
    """
    real_chown, real_fchown = os.chown, os.fchown

    def fmt(p):
        if basename:
            return os.path.basename(p)
        return os.path.realpath(p) if realpath else p

    def recording_chown(path, uid, gid, *args, **kwargs):
        calls.append((fmt(path), kwargs.get("follow_symlinks", True)))
        return real_chown(path, uid, gid, *args, **kwargs)

    def recording_fchown(fd, uid, gid):
        calls.append((fmt(os.readlink(f"/proc/self/fd/{fd}")), False))
        return real_fchown(fd, uid, gid)

    monkeypatch.setattr(os, "chown", recording_chown)
    monkeypatch.setattr(os, "fchown", recording_fchown)


# ─────────────────────────────────────────────────────────────────────────────
# _chown_r — the function that had the real bug
# ─────────────────────────────────────────────────────────────────────────────

def test_chown_r_never_follows_symlinks(tmp_path, monkeypatch):
    """EVERY os.chown call must pass follow_symlinks=False.

    Asserting on the call itself rather than the effect means this test needs no
    root privileges and cannot be fooled by a uid that happens to already match.
    """
    d = tmp_path / "hs"
    d.mkdir()
    (d / "hostname").write_text("x.onion")
    sub = d / "authorized_clients"
    sub.mkdir()
    (sub / "a.auth").write_text("x")
    # The symlink target must EXIST, so that vulnerable code succeeds in
    # following it (and is caught by the assertion) rather than dying on ENOENT
    # — a crash would be an accidental, fragile way to "pass" this test.
    outside_target = tmp_path / "outside_target"
    outside_target.write_text("sensitive")
    (d / "evil").symlink_to(outside_target)

    calls = []
    _record_chowns(monkeypatch, calls)
    e._chown_r(str(d), os.getuid(), os.getgid())

    assert calls, "no chown calls recorded"
    assert str(outside_target) not in [p for p, _ in calls], "chowned the link target"
    followed = [p for p, follow in calls if follow]
    assert not followed, f"these chowns would follow a symlink: {followed}"


def test_chown_r_does_not_descend_into_symlinked_directories(tmp_path, monkeypatch):
    """A symlinked subdirectory must not be walked into."""
    d = tmp_path / "hs"
    d.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SHOULD_NOT_BE_TOUCHED").write_text("x")
    (d / "sneaky").symlink_to(outside)

    calls = []
    _record_chowns(monkeypatch, calls, realpath=True)
    e._chown_r(str(d), os.getuid(), os.getgid())

    escaped = [p for p, _ in calls if "SHOULD_NOT_BE_TOUCHED" in p]
    assert not escaped, f"walk descended through a symlink: {escaped}"


def test_chown_r_still_chowns_the_legitimate_tree(tmp_path, monkeypatch):
    """Guard against 'fixing' the escape by simply not chowning anything."""
    d = tmp_path / "hs"
    d.mkdir()
    (d / "hs_ed25519_secret_key").write_text("k")
    sub = d / "authorized_clients"
    sub.mkdir()
    (sub / "a.auth").write_text("x")

    calls = []
    _record_chowns(monkeypatch, calls, basename=True)
    e._chown_r(str(d), os.getuid(), os.getgid())
    seen = [p for p, _ in calls]

    assert "hs_ed25519_secret_key" in seen
    assert "authorized_clients" in seen
    assert "a.auth" in seen


def test_chown_r_passes_follow_symlinks_false(tmp_path, monkeypatch):
    """The lchown property itself, asserted with no symlink present.

    ``test_chown_r_never_follows_symlinks`` proves it through a planted symlink.
    This asserts the same property unconditionally, so an edit that drops the
    kwarg fails here even if the symlink fixture is ever changed. ``os.chown``
    follows symlinks by default; dropping the flag would make ``_chown_r`` a
    root-privileged arbitrary-chown primitive.
    """
    d = tmp_path / "hs"
    d.mkdir()
    (d / "hostname").write_text("x.onion")

    seen = []
    real_chown = os.chown

    def recording_chown(path, uid, gid, *args, **kwargs):
        seen.append(kwargs.get("follow_symlinks"))
        return real_chown(path, uid, gid, *args, **kwargs)

    monkeypatch.setattr(os, "chown", recording_chown)
    e._chown_r(str(d), os.getuid(), os.getgid())

    assert seen, "no chown calls recorded"
    assert all(v is False for v in seen), \
        f"a chown did not pass follow_symlinks=False: {seen}"


def test_prepare_hs_dir_chmods_before_chown(tmp_path, monkeypatch):
    """The symlink rejection depends on the chmod running BEFORE the chown.

    ``Path.mkdir(exist_ok=True)`` succeeds through a symlink, so
    ``_chmod_dir_nofollow`` (which refuses a symlink via O_NOFOLLOW) must run
    before ``_chown_r``. Reordered, a symlinked service directory would be
    chowned by root -- a privileged escape.

    Tested behaviourally. The previous version of this test read the source text
    of generate_basic_torrc and passed in CI, but broke mutation testing: mutmut
    replaces the function body with a trampoline, so the source no longer
    contained the call and every mutant run aborted at setup.
    """
    target = tmp_path / "outside"
    target.mkdir()
    link = tmp_path / "hs"
    link.symlink_to(target)

    calls = []
    monkeypatch.setattr(e, "_chown_r", lambda *a, **k: calls.append(a))
    tor_pw = namedtuple("TorPw", "pw_uid pw_gid")(os.getuid(), os.getgid())

    with pytest.raises(RuntimeError, match="is a symlink"):
        e._prepare_hs_dir(str(link), tor_pw)
    assert calls == [], "the chown ran despite the symlink: the ordering regressed"


def test_prepare_hs_dir_chmods_then_chowns(tmp_path, monkeypatch):
    """The normal path chmods to 0700 first, then chowns to the tor user.

    Records the call order rather than the resulting mode: the chmod is
    ``only_if_root_owned`` (root creates the dir, then secures it), so a temp dir
    owned by the test user would legitimately skip it.
    """
    d = tmp_path / "hs"
    order = []
    monkeypatch.setattr(e, "_secure_service_dir",
                        lambda path: order.append(("chmod", path, 0o700)))
    monkeypatch.setattr(e, "_chown_r",
                        lambda path, uid, gid: order.append(("chown", path, uid, gid)))
    tor_pw = namedtuple("TorPw", "pw_uid pw_gid")(12345, 67890)

    e._prepare_hs_dir(str(d), tor_pw)

    assert d.is_dir()
    assert order == [("chmod", str(d), 0o700), ("chown", str(d), 12345, 67890)]


def test_chown_r_refuses_a_hardlinked_file(tmp_path, monkeypatch, capsys):
    """A hardlink is the same inode as a file elsewhere, so chowning it chowns
    that file too, and lchown does not help (there is no link to not-follow).
    Run as root at boot over the key volume, that handed an outside file to the
    tor uid. Refused, and said so."""
    d = tmp_path / "hs"
    d.mkdir()
    outside = tmp_path / "outside-file"
    outside.write_text("not the key volume's")
    os.link(outside, d / "hs_ed25519_secret_key")
    (d / "hostname").write_text("x.onion")
    calls = []
    _record_chowns(monkeypatch, calls, basename=True)
    e._chown_r(str(d), os.getuid(), os.getgid())
    seen = [p for p, _ in calls]
    assert "outside-file" not in seen and "hs_ed25519_secret_key" not in seen
    assert "hostname" in seen, "the rest of the directory is still handed over"
    assert "2 hard links" in capsys.readouterr().out


def test_chown_r_does_not_abort_startup_on_a_socket(tmp_path, capsys):
    """Opening a socket fails (ENXIO); before this, one planted socket stopped
    the container from booting at all. It is skipped and named instead."""
    import socket as _socket
    d = tmp_path / "hs"
    d.mkdir()
    (d / "hostname").write_text("x.onion")
    sock = _socket.socket(_socket.AF_UNIX)
    try:
        sock.bind(str(d / "planted.sock"))
        e._chown_r(str(d), os.getuid(), os.getgid())
    finally:
        sock.close()
    assert "device node or socket" in capsys.readouterr().out


# ─────────────────────────────────────────────────────────────────────────────
# a restart over a directory a previous start already handed to tor
# ─────────────────────────────────────────────────────────────────────────────

class _Tor:
    def __init__(self, uid):
        self.pw_uid, self.pw_gid = uid, os.getgid()


def _denied(*a, **kw):
    raise PermissionError(13, "Permission denied")


def test_a_tor_owned_closed_directory_is_left_alone_on_restart(tmp_path,
                                                                monkeypatch, capsys):
    """Rootless Podman, podman-compose.yml as shipped: root has no DAC_OVERRIDE,
    so it cannot open a service directory a previous start handed to tor.
    Measured: every restart died here and the container restart-looped. That
    directory is already in the state being asked for, so this is not an error."""
    d = tmp_path / "hs"
    d.mkdir(mode=0o700)
    monkeypatch.setattr(e, "_secure_service_dir", _denied)
    e._prepare_hs_dir(str(d), _Tor(os.getuid()))
    assert "already the tor user's" in capsys.readouterr().out


@pytest.mark.parametrize("case", ["other-owner", "open-mode", "symlink"])
def test_anything_else_behind_a_permission_error_still_fails(tmp_path, monkeypatch,
                                                             case):
    """The excuse is narrow: a real directory, owned by tor, closed to others."""
    d = tmp_path / "hs"
    if case == "symlink":
        (tmp_path / "real").mkdir(mode=0o700)
        d.symlink_to(tmp_path / "real")
    else:
        d.mkdir(mode=0o755 if case == "open-mode" else 0o700)
    uid = os.getuid() + 1 if case == "other-owner" else os.getuid()
    monkeypatch.setattr(e, "_secure_service_dir", _denied)
    with pytest.raises((PermissionError, RuntimeError)):
        e._prepare_hs_dir(str(d), _Tor(uid))
