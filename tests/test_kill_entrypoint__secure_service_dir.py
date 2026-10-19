"""Tests pinning the operator-facing diagnostics of _secure_service_dir.

When a service directory cannot be tightened to 0700 (no FOWNER and not the
owner) the raised PermissionError is the only thing an operator sees in the log.
These tests assert its errno and the exact message text, because that message
tells the operator what to run on the host.
"""
import errno
import os

import pytest

import entrypoint as e


def _deny_fchmod(monkeypatch):
    def denied(fd, mode):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(e.os, "fchmod", denied)


def test_unfixable_directory_reports_eperm(tmp_path, monkeypatch):
    """The errno must be EPERM: callers (and operators) read it, so a missing or
    None errno is a behaviour change even though the exception type is the same.
    """
    d = tmp_path / "hs"
    d.mkdir()
    os.chmod(d, 0o755)  # noqa: S103 - the state under test
    _deny_fchmod(monkeypatch)

    with pytest.raises(PermissionError) as exc:
        e._secure_service_dir(str(d))
    assert exc.value.errno == errno.EPERM


def test_unfixable_directory_message_names_the_permission_and_the_fix(
        tmp_path, monkeypatch, capsys):
    """The exact sentence an operator reads to diagnose the fault."""
    d = tmp_path / "hs"
    d.mkdir()
    os.chmod(d, 0o755)  # noqa: S103 - the state under test
    _deny_fchmod(monkeypatch)

    with pytest.raises(PermissionError) as exc:
        e._secure_service_dir(str(d))
    msg = str(exc.value)
    assert "grants no FOWNER). Run `chmod 700` on it on the host." in msg
    assert "is mode 0o755, which Tor refuses" in msg
    assert "XXgrants" not in msg
    assert "YYgrants" not in msg
    assert f"it belongs to uid {os.stat(str(d)).st_uid}" in msg
