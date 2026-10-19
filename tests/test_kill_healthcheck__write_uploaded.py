"""Behaviour of healthcheck._write_uploaded: atomic, 0600, no-follow, ascii.

These pin what an operator relies on: the uploaded-address file is written with
exactly 0600 permissions, a symlink planted at the temp path is never followed,
and the file content is sorted ASCII with one address per line.
"""
import codecs
import os

import pytest

from loader import load_file, source_path

HEALTHCHECK_PATH = source_path(__file__, "healthcheck.py")

ONION = "a" * 56
OTHER = "b" * 56


@pytest.fixture(scope="module")
def hc():
    return load_file(HEALTHCHECK_PATH, "healthcheck")


def test_the_uploads_file_is_created_with_exactly_0600_permissions(hc, tmp_path):
    """0600 is what keeps the upload record private to the tor user."""
    path = tmp_path / "hs-uploaded"
    old = os.umask(0)
    try:
        hc._write_uploaded(str(path), {ONION})
    finally:
        os.umask(old)
    assert path.exists()
    assert oct(path.stat().st_mode & 0o777) == oct(0o600)


def test_the_uploads_file_is_sorted_one_address_per_line(hc, tmp_path):
    path = tmp_path / "hs-uploaded"
    hc._write_uploaded(str(path), {OTHER, ONION})
    assert path.read_bytes() == f"{ONION}\n{OTHER}\n".encode("ascii")
    assert hc._uploaded_addresses(str(path)) == {ONION, OTHER}


def test_a_planted_symlink_at_the_temp_path_is_never_followed(hc, tmp_path):
    """O_NOFOLLOW: a symlink at <path>.<pid>.tmp must not redirect the write."""
    victim = tmp_path / "victim"
    victim.write_text("untouched\n")
    tmp = f"{tmp_path / 'hs-uploaded'}.{os.getpid()}.tmp"
    os.symlink(victim, tmp)
    hc._write_uploaded(str(tmp_path / "hs-uploaded"), {ONION})
    assert victim.read_text() == "untouched\n"
    assert (tmp_path / "hs-uploaded").read_text() == f"{ONION}\n"


def test_no_leftover_temp_file_remains(hc, tmp_path):
    tmp = f"{tmp_path / 'hs-uploaded'}.{os.getpid()}.tmp"
    hc._write_uploaded(str(tmp_path / "hs-uploaded"), {ONION})
    assert not os.path.lexists(tmp)


def test_end_to_end_through_the_watcher_writes_a_private_file(hc, tmp_path):
    """The file watch_uploads publishes has the same guarantees."""
    import socket
    import threading

    sock_path = str(tmp_path / "control.sock")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(sock_path)
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        conn.recv(4096)
        conn.sendall(f"650 HS_DESC UPLOADED {ONION} UNKNOWN $AAAA~relay\r\n".encode())
        conn.close()
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    out = tmp_path / "hs-uploaded"
    old = os.umask(0)
    try:
        assert hc.watch_uploads(str(out), sock_path=sock_path, connect_timeout=5) == 0
    finally:
        os.umask(old)
    assert out.read_text() == f"{ONION}\n"
    assert oct(out.stat().st_mode & 0o777) == oct(0o600)


def _strict_open(wants):
    """An os.open wrapper that fails if any flag in `wants` is missing.

    O_EXCL and O_NOFOLLOW have no overlapping bits, so `|` versus `&` is
    invisible to a plain file open; the flags themselves still have to be
    there, which is what this checks.
    """
    real_open = os.open

    def strict_open(path, flags, *a, **kw):
        if os.fspath(path).endswith(".tmp"):
            assert flags & wants == wants, f"flags {flags:#o} lost a safety bit"
        return real_open(path, flags, *a, **kw)

    return strict_open


def test_the_temp_file_is_opened_with_wronly_create_excl_and_no_follow(
        hc, tmp_path, monkeypatch):
    """All four safety flags must reach os.open.

    (Dropping O_NOFOLLOW by AND-ing it with O_EXCL cannot be seen by any file
    operation -- O_EXCL already refuses a symlink or an existing path -- so this
    pins the flags rather than pretending the mutation is observable.)
    """
    assert os.O_NOFOLLOW != 0
    assert os.O_EXCL & os.O_NOFOLLOW == 0
    wants = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    monkeypatch.setattr(hc.os, "open", _strict_open(wants))
    path = tmp_path / "hs-uploaded"
    hc._write_uploaded(str(path), {ONION})
    assert path.read_text() == f"{ONION}\n"


def test_the_temp_file_is_created_with_mode_0600(hc, tmp_path):
    """A umask of 0 makes the mode passed to os.open the mode on disk."""
    seen = []
    real_open = os.open

    def recording_open(path, flags, mode=0o777, *a, **kw):
        seen.append(mode)
        return real_open(path, flags, mode, *a, **kw)

    hc.os.open = recording_open
    old = os.umask(0)
    try:
        hc._write_uploaded(str(tmp_path / "hs-uploaded"), {ONION})
    finally:
        os.umask(old)
        hc.os.open = real_open
    assert seen == [0o600]


def test_non_ascii_addresses_are_rejected_not_silently_transcoded(hc, tmp_path):
    """UnicodeEncodeError means the strict ascii encoder is in force."""
    p = tmp_path / "hs-uploaded"
    hc._write_uploaded(str(p), {ONION})
    with pytest.raises(UnicodeEncodeError):
        hc._write_uploaded(str(p), {"t\xe9st"})


def test_a_non_ascii_locale_cannot_change_what_is_written(hc, tmp_path, monkeypatch):
    """A locale-derived encoder would happily accept the accented address."""
    import locale
    p = tmp_path / "hs-uploaded"
    hc._write_uploaded(str(p), {ONION})
    monkeypatch.setattr(locale, "getpreferredencoding", lambda do_setlocale=True: "latin-1")
    monkeypatch.setattr(locale, "getencoding", lambda: "latin-1")
    try:
        with pytest.raises(UnicodeEncodeError):
            hc._write_uploaded(str(p), {"t\xe9st"})
    finally:
        hc._write_uploaded(str(p), {OTHER})
    assert p.read_text() == f"{OTHER}\n"


def test_the_file_is_written_with_the_ascii_codec(hc, tmp_path):
    """No encoding at all would mean the locale decides which bytes are written.
    The codec is compared, not the spelling: codec names are case-insensitive,
    so "ASCII" and "ascii" are the same codec."""
    real_fdopen = os.fdopen
    requested = []

    def fdopen(fd, mode="r", *args, **kwargs):
        requested.append(kwargs.get("encoding", args[0] if args else None))
        return real_fdopen(fd, mode, *args, **kwargs)

    hc.os.fdopen = fdopen
    try:
        hc._write_uploaded(str(tmp_path / "hs-uploaded"), {ONION})
    finally:
        hc.os.fdopen = real_fdopen
    assert len(requested) == 1 and requested[0] is not None
    assert codecs.lookup(requested[0]).name == "ascii"
