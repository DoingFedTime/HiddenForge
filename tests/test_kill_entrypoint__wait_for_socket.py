"""Pin the operator-facing message of a Tor that died before its socket.

When Tor refuses its config at startup, wait_for_socket raises a RuntimeError
whose text is what an operator greps for in the container log to tell "Tor died"
apart from "Tor is slow": the message carries both the words "socket appeared"
and the exit code, so the sentence is asserted exactly.
"""
import pytest

import entrypoint as e


class _DeadTor:
    """A Tor process that has already exited with a known code."""

    def __init__(self, code=1):
        self._code = code

    def poll(self):
        return self._code


def test_a_dead_tor_reports_the_exact_reason_and_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(e, "_control_socket_ready", lambda: False)

    def no_sleep(seconds):
        raise AssertionError("waited on a Tor that had already exited")

    monkeypatch.setattr(e.time, "sleep", no_sleep)

    with pytest.raises(RuntimeError) as exc:
        e.wait_for_socket(timeout=120, tor=_DeadTor(3))

    assert str(exc.value) == "Tor exited (code 3) before its control socket appeared"
    out = capsys.readouterr().out
    assert out == "Waiting for Tor control socket...\n"
