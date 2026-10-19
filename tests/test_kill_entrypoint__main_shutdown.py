"""Pin the shutdown order and timeouts of main()'s two supervision-exit paths.

When Tor exits on its own, and when a backend has moved, main() stops the
upload watcher, Vanguards and (on a move) Tor. The process objects, the order
and the per-process timeouts are what decide whether an addon outlives PID 1
or a wedged child is left running; nothing else in the suite asserts them.

Uses the `supervisor` fixture (tests/supervisor_harness.py), which
records every _kill_proc call instead of performing it.
"""

import entrypoint as e

from supervisor_harness import FakeProc, _MovedAfter


def _stopped(h):
    return [(name, timeout, proc) for proc, name, timeout in h.killed]


def test_tor_exit_stops_watcher_then_vanguards_with_their_timeouts(supervisor, capsys):
    """A Tor that died takes both children with it: the watcher first (5s), then
    Vanguards (5s). Passing None terminates nothing and the child is orphaned."""
    _code, h = supervisor(tor_polls=[None, 3], vanguards_polls=(None,))
    assert "Tor exited with code 3, shutting down." in capsys.readouterr().out
    stopped = _stopped(h)
    assert [name for name, _t, _p in stopped] == ["upload watcher", "Vanguards"]
    (_w_name, w_timeout, w_proc), (_v_name, v_timeout, v_proc) = stopped
    assert w_timeout == 5
    assert v_timeout == 5
    assert isinstance(w_proc, FakeProc), f"a {type(w_proc).__name__} was stopped, not the watcher"
    assert isinstance(v_proc, FakeProc), f"a {type(v_proc).__name__} was stopped, not the addon"


def test_a_backend_move_stops_watcher_vanguards_then_tor(supervisor, monkeypatch, capsys):
    """On a confirmed move ALL THREE children are stopped, in that order, with
    the watcher and Vanguards at 5s and Tor (the primary process) at 10s. Tor's
    own exit path does not go through here -- this is the only place Tor is
    stopped from the loop, and a None or a different timeout leaves a stale Tor
    forwarding to an address nobody listens on."""
    monkeypatch.setattr(e, "_BackendWatch", _MovedAfter(3))
    code, h = supervisor(tor_polls=[None] * 20, vanguards_polls=(None,))
    assert code == 1
    assert "now resolves to" in capsys.readouterr().out
    stopped = _stopped(h)
    assert [name for name, _t, _p in stopped] == ["upload watcher", "Vanguards", "Tor"]
    assert [t for _n, t, _p in stopped] == [5, 5, 10]
    for name, _t, proc in stopped:
        assert isinstance(proc, FakeProc), f"a {type(proc).__name__} was stopped for {name}"


def test_a_backend_that_appeared_also_stops_all_three(supervisor, monkeypatch, capsys):
    """The pending-backend path (old is None) shares the shutdown and must not
    skip Tor: the container is about to exit 1 and be restarted."""
    monkeypatch.setattr(e, "_BackendWatch", _MovedAfter(3, old=None))
    code, h = supervisor(tor_polls=[None] * 20, vanguards_polls=(None,))
    assert code == 1
    stopped = _stopped(h)
    assert [name for name, _t, _p in stopped] == ["upload watcher", "Vanguards", "Tor"]
    assert [t for _n, t, _p in stopped] == [5, 5, 10]
    for name, _t, proc in stopped:
        assert isinstance(proc, FakeProc), f"a {type(proc).__name__} was stopped for {name}"
