"""The default arguments that decide timing and limits.

The mutation gate used to blank each function's def line before diffing, which
hid every mutation of a default argument. These defaults are behaviour: how long
shutdown waits for a child, how long startup waits for Tor, how big an address
file may be, whether a plain chmod call is applied. Each test calls the function
WITHOUT the argument, so it is the default that is pinned.
"""
import os
import stat

import pytest

import entrypoint as e
from loader import load_file, source_path

HEALTHCHECK_PATH = source_path(__file__, "healthcheck.py")


@pytest.fixture
def hc():
    # Loaded as "healthcheck": mutmut picks mutants by the module's __name__.
    return load_file(HEALTHCHECK_PATH, "healthcheck")


def _fake_clock(monkeypatch, module, start=1000.0):
    clock = [start]

    def sleep(seconds):
        clock[0] += seconds

    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module.time, "sleep", sleep)
    return clock


def test_chmod_dir_nofollow_applies_the_mode_unless_told_to_check_ownership(tmp_path):
    """By default the mode is applied whoever owns the directory; the
    root-ownership guard is opt-in."""
    d = tmp_path / "d"
    d.mkdir()
    os.chmod(d, 0o755)  # noqa: S103 - the state under test
    assert e._chmod_dir_nofollow(str(d), 0o700) is True
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700


def test_kill_proc_gives_a_child_ten_seconds_by_default():
    waited = []

    class Child:
        def terminate(self):
            pass

        def wait(self, timeout=None):
            waited.append(timeout)
            return 0

    e._kill_proc(Child(), "child")
    assert waited == [10]


def test_wait_for_socket_gives_tor_two_minutes_by_default(monkeypatch, capsys):
    clock = _fake_clock(monkeypatch, e)
    monkeypatch.setattr(e, "_control_socket_ready", lambda: False)
    with pytest.raises(TimeoutError) as exc:
        e.wait_for_socket()
    assert "after 120s" in str(exc.value)
    # Gives up at the first poll past 120 s, polling every 0.5 s.
    assert 1120.0 < clock[0] <= 1121.0


def test_assert_process_dropped_waits_five_seconds_by_default(monkeypatch, capsys):
    """A su-exec that never gets past setuid() is refused at the deadline."""
    clock = _fake_clock(monkeypatch, e)

    class Status:
        def __init__(self, path):
            pass

        def read_text(self, encoding=None):
            return "Name:\tsu-exec\nUid:\t0\t0\t0\t0\n"

    monkeypatch.setattr(e, "Path", Status)

    class Proc:
        pid = 4242

    assert e._assert_process_dropped(Proc(), "Tor") is False
    assert 1005.0 <= clock[0] < 1005.02


def test_an_address_file_over_256_bytes_is_not_read(hc, tmp_path):
    p = tmp_path / "hostname"
    p.write_bytes(b"x" * 257)
    assert hc._read_address_file(str(p)) is None
    p.write_bytes(b"x" * 256)
    assert hc._read_address_file(str(p)) == "x" * 256


def test_watch_uploads_retries_the_connect_for_a_minute_by_default(hc, tmp_path, monkeypatch):
    clock = _fake_clock(monkeypatch, hc)
    assert hc.watch_uploads(str(tmp_path / "out"), str(tmp_path / "missing.sock")) == 2
    assert 1060.0 < clock[0] <= 1060.5
