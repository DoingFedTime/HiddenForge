"""Tests that pin _chown_one's refusals and the messages an operator reads.

Each test drives the real function (on the host, no root needed): refusals are
asserted on the exact warning text, and the accepted paths are asserted on how
the descriptor is opened -- without O_NOFOLLOW a symlink swapped in after the
lstat would be followed, and without O_NONBLOCK a FIFO could block startup.
"""
import os
import stat


import entrypoint as e


def _record(monkeypatch, calls):
    """Record chown/fchown calls; fchown is reported with the fd's own flags."""
    real_chown, real_fchown, real_open = os.chown, os.fchown, os.open

    def recording_chown(path, uid, gid, *args, **kwargs):
        calls.append(("chown", path, kwargs.get("follow_symlinks", True)))
        return real_chown(path, uid, gid, *args, **kwargs)

    def recording_fchown(fd, uid, gid):
        calls.append(("fchown", fd))
        return real_fchown(fd, uid, gid)

    def recording_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        calls.append(("open", fd))
        return fd

    monkeypatch.setattr(os, "chown", recording_chown)
    monkeypatch.setattr(os, "fchown", recording_fchown)
    monkeypatch.setattr(os, "open", recording_open)


def test_a_regular_file_is_chowned_through_a_nonblocking_nofollow_descriptor(
        tmp_path, monkeypatch):
    """The descriptor is opened O_NOFOLLOW|O_NONBLOCK: O_NOFOLLOW closes the
    swap-for-a-symlink window, and O_NONBLOCK keeps a FIFO from blocking boot."""
    f = tmp_path / "hostname"
    f.write_text("x.onion")
    opened = []
    real_open = os.open

    def recording_open(path, flags, *a, **kw):
        opened.append(flags)
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", recording_open)
    calls = []
    _record(monkeypatch, calls)
    e._chown_one(str(f), os.getuid(), os.getgid())

    assert len(opened) == 1
    flags = opened[0]
    assert flags & os.O_NOFOLLOW
    assert flags & os.O_NONBLOCK
    assert flags & os.O_RDONLY == os.O_RDONLY
    assert [c[0] for c in calls] == ["open", "fchown"]


def test_a_character_device_is_refused_before_any_open(tmp_path, monkeypatch, capsys):
    """Opening a device node can have side effects, so it is refused before the
    open and named in the warning."""
    dev = tmp_path / "planted"
    dev.touch()
    st = os.lstat(dev)
    fake_mode = (st.st_mode & ~stat.S_IFMT(st.st_mode)) | stat.S_IFCHR
    real_lstat = os.lstat
    monkeypatch.setattr(os, "lstat",
                        lambda p: real_lstat(p) if p != str(dev)
                        else os.stat_result((fake_mode, st.st_ino, st.st_dev,
                                             st.st_nlink, st.st_uid, st.st_gid,
                                             st.st_size, st.st_atime,
                                             st.st_mtime, st.st_ctime)))
    calls = []
    _record(monkeypatch, calls)
    e._chown_one(str(dev), os.getuid(), os.getgid())

    out = capsys.readouterr().out
    assert calls == []
    assert (f"Warning: not taking ownership of {dev} in the key volume: "
            "it is a device node or socket, which does not belong there.\n") == out


def test_a_block_device_is_refused_before_any_open(tmp_path, monkeypatch, capsys):
    """A block device is refused too -- not only sockets."""
    dev = tmp_path / "planted-block"
    dev.touch()
    st = os.lstat(dev)
    fake_mode = (st.st_mode & ~stat.S_IFMT(st.st_mode)) | stat.S_IFBLK
    real_lstat = os.lstat
    monkeypatch.setattr(os, "lstat",
                        lambda p: real_lstat(p) if p != str(dev)
                        else os.stat_result((fake_mode, st.st_ino, st.st_dev,
                                             st.st_nlink, st.st_uid, st.st_gid,
                                             st.st_size, st.st_atime,
                                             st.st_mtime, st.st_ctime)))
    calls = []
    _record(monkeypatch, calls)
    e._chown_one(str(dev), os.getuid(), os.getgid())

    assert calls == []
    assert "it is a device node or socket, which does not belong there." in \
        capsys.readouterr().out


def test_a_socket_is_refused_and_named(tmp_path, monkeypatch, capsys):
    import socket as _socket
    d = tmp_path
    sock = _socket.socket(_socket.AF_UNIX)
    try:
        sock.bind(str(d / "planted.sock"))
        calls = []
        _record(monkeypatch, calls)
        e._chown_one(str(d / "planted.sock"), os.getuid(), os.getgid())
    finally:
        sock.close()
    assert calls == []
    assert "it is a device node or socket, which does not belong there." in \
        capsys.readouterr().out


def test_a_hardlinked_file_is_refused_with_the_link_count_and_the_path(
        tmp_path, monkeypatch, capsys):
    """A hardlink is the same inode as a file elsewhere; chowning it chowns that
    file. Refused, left alone, and the warning names the file and its link count
    so an operator knows what to remove."""
    outside = tmp_path / "outside-file"
    outside.write_text("not the key volume's")
    d = tmp_path / "hs"
    d.mkdir()
    linked = d / "hs_ed25519_secret_key"
    os.link(outside, linked)
    real_fchown = os.fchown
    chowned = []

    def recording_fchown(fd, uid, gid):
        chowned.append(fd)
        return real_fchown(fd, uid, gid)

    monkeypatch.setattr(os, "fchown", recording_fchown)
    e._chown_one(str(linked), os.getuid(), os.getgid())

    out = capsys.readouterr().out
    assert chowned == [], "the hardlinked inode was handed over anyway"
    assert (f"Warning: not taking ownership of {linked}: it has 2 hard links, "
            "so it is also a file outside this directory. "
            "Tor never hard-links its key files; remove the extra links."
            in out), out
