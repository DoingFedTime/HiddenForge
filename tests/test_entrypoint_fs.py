"""Host tests for the entrypoint's filesystem side-effect helpers.

These are the functions entrypoint.py runs as root, exercised against a temp
directory instead of /var/lib/tor. They cover the address publication, the
dropped-mapping record, the control-socket probe, and the subcommand dispatch --
the pieces that are otherwise only exercised inside a container.
"""
import os
import stat
import subprocess
from collections import namedtuple

import pytest

import entrypoint as e

TorPw = namedtuple("TorPw", "pw_uid pw_gid")
ONION = "atdorl67o6q7anir2qm3sly4expi3ywvs2ltw3wl53zezgycohzi2zqd.onion"


# ─────────────────────────────────────────────────────────────────────────────
# _write_dropped_mappings
# ─────────────────────────────────────────────────────────────────────────────

def test_write_dropped_mappings_writes_then_removes(tmp_path, monkeypatch):
    path = tmp_path / "dropped-mappings"
    monkeypatch.setattr(e, "DROPPED_MAPPINGS", str(path))
    e._write_dropped_mappings(["a: bad", "b: worse"], TorPw(os.getuid(), os.getgid()))
    assert path.read_text() == "a: bad\nb: worse\n"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    # Nothing to report -> the stale file must go, not linger.
    e._write_dropped_mappings([], TorPw(os.getuid(), os.getgid()))
    assert not path.exists()


def test_write_dropped_mappings_empty_is_noop_when_absent(tmp_path, monkeypatch):
    path = tmp_path / "nope"
    monkeypatch.setattr(e, "DROPPED_MAPPINGS", str(path))
    e._write_dropped_mappings([], TorPw(os.getuid(), os.getgid()))
    assert not path.exists()


# ─────────────────────────────────────────────────────────────────────────────
# _publish_addresses
# ─────────────────────────────────────────────────────────────────────────────

def _service(root, name, hostname):
    d = root / name
    d.mkdir(parents=True)
    if hostname is not None:
        (d / "hostname").write_text(hostname)
    return d


def test_publish_addresses_writes_readable_onion(tmp_path):
    root = tmp_path / "keys"
    root.mkdir()
    hs = _service(root, "app", ONION + "\n")
    e._publish_addresses([str(hs)], keys_root=str(root))
    out = root / "app.onion"
    assert out.read_text() == ONION + "\n"
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o644
    # Idempotent: a second pass leaves the same bytes.
    e._publish_addresses([str(hs)], keys_root=str(root))
    assert out.read_text() == ONION + "\n"


def test_publish_addresses_ignores_missing_or_invalid_hostname(tmp_path):
    root = tmp_path / "keys"
    root.mkdir()
    missing = _service(root, "missing", None)
    invalid = _service(root, "invalid", "not-an-onion\n")
    e._publish_addresses([str(missing), str(invalid)], keys_root=str(root))
    assert not (root / "missing.onion").exists()
    assert not (root / "invalid.onion").exists()


# ─────────────────────────────────────────────────────────────────────────────
# _control_socket_ready
# ─────────────────────────────────────────────────────────────────────────────

def test_control_socket_ready_reflects_the_probe(monkeypatch):
    def fake(returncode):
        return lambda *a, **k: subprocess.CompletedProcess(a[0], returncode, "", "")

    monkeypatch.setattr(e.subprocess, "run", fake(0))
    assert e._control_socket_ready() is True
    monkeypatch.setattr(e.subprocess, "run", fake(1))
    assert e._control_socket_ready() is False


def test_control_socket_ready_swallows_errors(monkeypatch):
    def boom(*a, **k):
        raise OSError("no su-exec")

    monkeypatch.setattr(e.subprocess, "run", boom)
    assert e._control_socket_ready() is False


# ─────────────────────────────────────────────────────────────────────────────
# dispatch_subcommand
# ─────────────────────────────────────────────────────────────────────────────

def test_dispatch_falls_through_to_boot_for_non_subcommands(monkeypatch):
    monkeypatch.setattr(e, "HF_CLI", "/nonexistent")
    assert e.dispatch_subcommand([]) is None
    assert e.dispatch_subcommand(["tor", "-f", "/etc/tor/torrc"]) is None
    assert e.dispatch_subcommand(["python3", "/usr/local/bin/tests/test_torrc.py"]) is None


def test_dispatch_reports_missing_cli(monkeypatch, capsys):
    monkeypatch.setattr(e, "HF_CLI", "/nonexistent/hiddenforge")
    assert e.dispatch_subcommand(["show"]) == 2
    assert "not found" in capsys.readouterr().err


def test_assert_can_drop_privileges_ok(monkeypatch):
    monkeypatch.setattr(e.subprocess, "run", lambda *a, **k: (
        subprocess.CompletedProcess(a[0], 0, b"", b"")))
    e._assert_can_drop_privileges()   # must not raise


def test_assert_can_drop_privileges_reports_nproc_eagain(monkeypatch):
    """A setuid EAGAIN must name the real cause, not loop silently."""
    monkeypatch.setattr(e.subprocess, "run", lambda *a, **k: (
        subprocess.CompletedProcess(a[0], 1, b"", b"Resource temporarily unavailable")))
    with pytest.raises(RuntimeError, match="nproc"):
        e._assert_can_drop_privileges()


def test_safe_escapes_control_characters():
    assert e._safe("plain") == "plain"
    assert e._safe("a\nb") == "a\\x0ab"
    assert e._safe("\x1b[31m") == "\\x1b[31m"
