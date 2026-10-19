"""The wait on a not-yet-dropped su-exec must be a short hop, not a stall.

su-exec at uid 0 is "not yet", not "failed" -- but the supervisor sits in this
loop while a child it started is still root, so the pause between polls is the
only thing keeping a nearly-exec'd su-exec from costing the container a whole
extra second of start-up. The value is pinned exactly: 0.01 s, not 1 s.
"""
import entrypoint as e


class _Pid:
    def __init__(self, pid=12345):
        self.pid = pid


def test_su_exec_is_repolled_after_a_hundredth_of_a_second(monkeypatch):
    frames = iter([
        "Name:\tsu-exec\nUid:\t0\t0\t0\t0\n",
        "Name:\ttor\nUid:\t100\t100\t100\t100\n",
    ])

    class Status:
        def __init__(self, path):
            pass

        def read_text(self, encoding=None):
            return next(frames)

    slept = []
    monkeypatch.setattr(e, "Path", Status)
    monkeypatch.setattr(e.time, "sleep", slept.append)
    assert e._assert_process_dropped(_Pid(), "Tor", timeout=5) is True
    # A tenth of a second (the /proc-missing pause) would mean a visible delay
    # in every container start; a whole second would be a stall.
    assert slept == [0.01]
