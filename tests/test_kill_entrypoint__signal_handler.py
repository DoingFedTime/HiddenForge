"""The signal handler must hand _kill_proc the actual upload-watcher child.

`docker stop` arrives as SIGTERM. The handler stops the control-socket clients
and then Tor; passing `None` instead of the running upload watcher stops
nothing, leaving a child that talks to a control socket Tor is about to close,
which then outlives PID 1.
"""
import pytest

import entrypoint as e


def test_the_signal_handler_stops_the_actual_upload_watcher(monkeypatch, capsys):
    watcher, vanguards, tor = object(), object(), object()
    monkeypatch.setattr(e, "_upload_watcher", watcher)
    monkeypatch.setattr(e, "_vanguards_process", vanguards)
    monkeypatch.setattr(e, "_tor_process", tor)

    killed = []
    monkeypatch.setattr(e, "_kill_proc",
                        lambda proc, name, timeout=10: killed.append((proc, name, timeout)))

    with pytest.raises(SystemExit) as excinfo:
        e.signal_handler(15, None)

    assert excinfo.value.code == 0
    assert killed == [
        (watcher, "upload watcher", 5),
        (vanguards, "Vanguards", 5),
        (tor, "Tor", 10),
    ]
    assert "Received signal 15, shutting down..." in capsys.readouterr().out
