"""Mutation-killing tests for entrypoint._prepare_hs_dir.

The operator-facing diagnostics of _prepare_hs_dir are the contract: the message
an operator reads on a tampered key volume tells them exactly which kind of
object was refused and what to do about it, and the restart message names the
directory that was left alone. Those strings are pinned verbatim here.
"""
import os
from collections import namedtuple

import pytest

import entrypoint as e

TorPw = namedtuple("TorPw", "pw_uid pw_gid")


def _denied(*a, **kw):
    raise PermissionError(13, "Permission denied")


def test_a_regular_file_is_refused_as_not_a_directory(tmp_path):
    """A file in the key volume is reported as "not a directory" — the exact
    wording an operator uses to decide whether the volume was tampered with."""
    f = tmp_path / "hs"
    f.write_text("x")

    with pytest.raises(RuntimeError) as exc:
        e._prepare_hs_dir(str(f), TorPw(os.getuid(), os.getgid()))

    msg = str(exc.value)
    assert "in the key volume is not a directory;" in msg
    assert "a symlink" not in msg


def test_a_symlink_is_refused_as_a_symlink(tmp_path):
    """A planted link is diagnosed as a symlink, not as a generic non-directory."""
    target = tmp_path / "outside"
    target.mkdir()
    link = tmp_path / "hs"
    link.symlink_to(target)

    with pytest.raises(RuntimeError) as exc:
        e._prepare_hs_dir(str(link), TorPw(os.getuid(), os.getgid()))

    assert "in the key volume is a symlink;" in str(exc.value)


def test_the_refusal_says_how_to_recover(tmp_path):
    """The remedy sentence is part of the operator message and is pinned."""
    f = tmp_path / "hs"
    f.write_text("x")

    with pytest.raises(RuntimeError) as exc:
        e._prepare_hs_dir(str(f), TorPw(os.getuid(), os.getgid()))

    assert ("a service directory. Replace it with the real directory "
            "(restore it from a backup).") in str(exc.value)


def test_the_restart_message_names_the_directory(tmp_path, monkeypatch, capsys):
    """On a rootless-Podman restart the log line must name the actual directory
    (escaped through _safe), otherwise it cannot be diagnosed from the logs."""
    d = tmp_path / "hs"
    d.mkdir(mode=0o700)
    monkeypatch.setattr(e, "_secure_service_dir", _denied)

    e._prepare_hs_dir(str(d), TorPw(os.getuid(), os.getgid()))

    out = capsys.readouterr().out
    assert f"{e._safe(str(d))} is already the tor user's" in out
    assert "(prepared by a previous start); nothing to change." in out
