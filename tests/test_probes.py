"""The small commands the supervisor runs, and the argv it runs them with.

Every one of these functions is a one-line shell-out whose whole meaning is in
its argument list: `test -S` asks whether a path is a SOCKET, `test -s` asks
whether a file is non-empty; `su-exec tor` drops privilege, `SU-EXEC tor` is a
binary that does not exist; `--disable_vanguards` is the flag that keeps the addon
from issuing a SETCONF that Tor's sandbox refuses.

Mutation testing showed the suite could not tell any of those apart:
`wait_for_socket` and `start_vanguards` had no tests at all, and the argv of the
control-socket probe could be rewritten freely without a single failure. These
pin the exact commands, the timeouts that keep the once-a-second loop from
hanging, and the shutdown order.
"""
import subprocess

import pytest

import entrypoint as e


class _Recorder:
    """Stand in for subprocess.run and remember exactly how it was called."""

    def __init__(self, returncode=0, raises=None):
        self.returncode = returncode
        self.raises = raises
        self.cmd = None
        self.kwargs = None
        self.calls = 0

    def __call__(self, cmd, **kwargs):
        self.cmd = cmd
        self.kwargs = kwargs
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(cmd, self.returncode, b"", b"")


# ─────────────────────────────────────────────────────────────────────────────
# _control_socket_ready
# ─────────────────────────────────────────────────────────────────────────────

def test_the_socket_probe_asks_for_a_socket_as_the_tor_user(monkeypatch):
    """`-S` (is a socket), not `-s` (is a non-empty file): the control socket is
    a Unix socket inside a 0700 tor-owned DataDirectory that root cannot traverse
    under rootless Podman, so the question and the asker both matter."""
    rec = _Recorder(returncode=0)
    monkeypatch.setattr(e.subprocess, "run", rec)
    assert e._control_socket_ready() is True
    assert rec.cmd == ["su-exec", "tor", "test", "-S", e.CONTROL_SOCKET]
    assert rec.kwargs["timeout"] == 10
    assert rec.kwargs["check"] is False
    assert rec.kwargs["capture_output"] is True


def test_the_socket_probe_is_bounded(monkeypatch):
    """It runs once a second from the supervision loop; an unbounded probe would
    wedge the loop that is supposed to notice things going wrong."""
    rec = _Recorder()
    monkeypatch.setattr(e.subprocess, "run", rec)
    e._control_socket_ready()
    assert isinstance(rec.kwargs.get("timeout"), int)


@pytest.mark.parametrize("failure", [
    OSError("no su-exec"),
    subprocess.TimeoutExpired(cmd="test", timeout=10),
])
def test_a_probe_that_cannot_run_is_not_a_ready_socket(monkeypatch, failure):
    monkeypatch.setattr(e.subprocess, "run", _Recorder(raises=failure))
    assert e._control_socket_ready() is False


# ─────────────────────────────────────────────────────────────────────────────
# _assert_can_drop_privileges
# ─────────────────────────────────────────────────────────────────────────────

def test_the_privilege_probe_runs_true_as_tor_with_a_timeout(monkeypatch):
    rec = _Recorder(returncode=0)
    monkeypatch.setattr(e.subprocess, "run", rec)
    e._assert_can_drop_privileges()
    assert rec.cmd == ["su-exec", "tor", "true"]
    assert rec.kwargs == {"capture_output": True, "check": False, "timeout": 10}


def test_the_privilege_probe_message_is_the_whole_remedy(monkeypatch):
    """This error is the container's last word before it exits 1, and the cause
    it names -- RLIMIT_NPROC counted per HOST uid, shared with any other
    container that also runs something as uid 100 -- is not something an operator
    will work out from "su-exec failed"."""
    monkeypatch.setattr(
        e.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, b"", b"boom"))
    with pytest.raises(RuntimeError) as exc:
        e._assert_can_drop_privileges()
    assert str(exc.value) == (
        "cannot switch to the tor user: boom. If this deployment sets a low "
        "`ulimits.nproc`, remove it: RLIMIT_NPROC is counted per host uid, "
        "and uid 100 is shared with other containers (i2pforge's i2pd is "
        "also uid 100). Use `pids_limit` for process containment instead.")


def test_non_utf8_stderr_from_su_exec_is_replaced_not_raised(monkeypatch):
    """su-exec's stderr is whatever the C library wrote; it is not promised to be
    UTF-8. A strict decode here would replace a named startup failure with a
    UnicodeDecodeError traceback that says nothing about nproc."""
    monkeypatch.setattr(
        e.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, b"", b"bad \xff byte"))
    with pytest.raises(RuntimeError) as exc:
        e._assert_can_drop_privileges()
    assert "bad \ufffd byte" in str(exc.value)


def test_a_silent_su_exec_failure_still_names_a_cause(monkeypatch):
    """su-exec can fail with nothing on stderr. An error message that is just an
    empty string is not actionable, so there is a fallback."""
    monkeypatch.setattr(
        e.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, b"", b""))
    with pytest.raises(RuntimeError) as exc:
        e._assert_can_drop_privileges()
    assert str(exc.value).startswith("cannot switch to the tor user: su-exec failed.")


# ─────────────────────────────────────────────────────────────────────────────
# wait_for_socket
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def clock(monkeypatch):
    """A monotonic clock the test advances by hand, and a sleep that records."""
    # Deliberately NOT zero: with start == 0 a `-` becoming a `+` in the deadline
    # arithmetic is indistinguishable, and time.monotonic() has an arbitrary
    # origin in real life.
    state = {"t": 9_000.0, "slept": []}

    def sleep(seconds):
        state["slept"].append(seconds)
        state["t"] += seconds

    monkeypatch.setattr(e.time, "monotonic", lambda: state["t"])
    monkeypatch.setattr(e.time, "sleep", sleep)
    return state


def test_waiting_returns_as_soon_as_the_socket_is_there(clock, monkeypatch, capsys):
    monkeypatch.setattr(e, "_control_socket_ready", lambda: True)
    e.wait_for_socket(timeout=120)
    # Exact lines: these two are what an operator greps for when a container is
    # stuck before Tor ever started.
    assert capsys.readouterr().out == (
        "Waiting for Tor control socket...\n"
        "Control socket ready.\n")
    # The settle sleep after the socket appears: Tor is still setting its mode.
    assert clock["slept"] == [0.5]


def test_waiting_polls_until_the_socket_appears(clock, monkeypatch):
    answers = [False, False, True]
    monkeypatch.setattr(e, "_control_socket_ready", lambda: answers.pop(0))
    e.wait_for_socket(timeout=120)
    assert answers == []
    # Two poll intervals plus the settle sleep; a longer interval would slow
    # every container start, a shorter one would spin.
    assert clock["slept"] == [0.5, 0.5, 0.5]


def test_waiting_gives_up_and_says_how_long_it_waited(clock, monkeypatch):
    """main() catches this and carries on retrying Vanguards. A wait that never
    returned would hang the container before Tor was ever supervised."""
    monkeypatch.setattr(e, "_control_socket_ready", lambda: False)
    start = clock["t"]
    with pytest.raises(TimeoutError, match="not found after 3s"):
        e.wait_for_socket(timeout=3)
    # Elapsed time, measured against the clock's own origin -- the deadline is a
    # difference, and a clock that does not start at zero is what makes that
    # testable at all.
    assert 3 < clock["t"] - start < 4


def test_a_zero_timeout_does_not_wait_forever(clock, monkeypatch):
    monkeypatch.setattr(e, "_control_socket_ready", lambda: False)
    with pytest.raises(TimeoutError):
        e.wait_for_socket(timeout=0)


# ─────────────────────────────────────────────────────────────────────────────
# start_vanguards
# ─────────────────────────────────────────────────────────────────────────────

def test_vanguards_is_started_as_the_tor_user_with_the_documented_flags(monkeypatch, capsys):
    """--disable_vanguards is load-bearing, not cosmetic: the addon applies its
    guard sets with SETCONF, and under `Sandbox 1` every SETCONF fails because it
    forces a config re-validation that re-reads the HiddenServiceDir. Dropping the
    flag means the addon dies on startup and the container loses bandguards and
    rendguard with it."""
    seen = {}

    def fake_popen(argv, **kwargs):
        seen["argv"] = argv
        return "handle"

    monkeypatch.setattr(e.subprocess, "Popen", fake_popen)
    assert e.start_vanguards() == "handle"
    assert seen["argv"] == [
        "su-exec", "tor",
        e.VANGUARDS_BIN,
        "--control_socket", e.CONTROL_SOCKET,
        "--state", e.VANGUARDS_STATE,
        "--loglevel", "NOTICE",
        "--disable_vanguards",
    ]
    assert " ".join(seen["argv"][2:]) in capsys.readouterr().out


def test_the_vanguards_paths_are_inside_the_tor_data_directory(monkeypatch):
    """The state file records the pinned guards. Writing it anywhere the tor user
    cannot reach, or outside the 0700 DataDirectory, either breaks the addon or
    leaks which guards this service uses."""
    assert e.VANGUARDS_STATE.startswith("/var/lib/tor/")
    assert e.CONTROL_SOCKET.startswith("/var/lib/tor/")


# ─────────────────────────────────────────────────────────────────────────────
# _kill_proc and the shutdown order
# ─────────────────────────────────────────────────────────────────────────────

class _Child:
    def __init__(self, wait_raises=None):
        self.wait_raises = wait_raises
        self.terminated = False
        self.killed = False
        self.wait_timeout = None
        self.order = None

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.wait_timeout = timeout
        if self.wait_raises is not None:
            raise self.wait_raises
        return 0

    def kill(self):
        self.killed = True


def test_killing_nothing_is_not_an_error():
    """Vanguards may never have started; the signal handler must still stop Tor."""
    e._kill_proc(None, "Vanguards", timeout=5)


def test_a_child_that_ignores_terminate_is_killed(capsys):
    child = _Child(wait_raises=subprocess.TimeoutExpired(cmd="tor", timeout=1))
    e._kill_proc(child, "Tor", timeout=3)
    assert child.terminated
    assert child.killed
    assert child.wait_timeout == 3
    assert "Tor did not stop in time, killing" in capsys.readouterr().out


def test_a_child_that_stops_is_not_killed():
    child = _Child()
    e._kill_proc(child, "Tor", timeout=3)
    assert child.terminated
    assert not child.killed


def test_a_broken_child_handle_does_not_abort_the_shutdown():
    """We are already terminating; an error stopping one child must not stop the
    other from being stopped."""
    class Broken(_Child):
        def terminate(self):
            raise OSError("gone")

    e._kill_proc(Broken(), "Vanguards", timeout=5)


def test_shutdown_stops_the_actual_children(monkeypatch):
    """The handler reads the two module globals. Handing _kill_proc anything else
    -- None included -- means `docker stop` reaps PID 1 while Tor is still holding
    circuits open, which is the whole reason the handler exists."""
    tor, vanguards = _Child(), _Child()
    monkeypatch.setattr(e, "_tor_process", tor)
    monkeypatch.setattr(e, "_vanguards_process", vanguards)
    with pytest.raises(SystemExit):
        e.signal_handler(15, None)
    assert vanguards.terminated
    assert tor.terminated


def test_shutdown_stops_vanguards_first_with_the_shorter_grace(monkeypatch, capsys):
    """Vanguards talks to Tor over the control socket, so it goes first; and it
    gets the shorter grace period because Tor needs longer to close circuits
    cleanly."""
    order = []
    grants = {}

    def record(proc, name, timeout=10):
        order.append(name)
        grants[name] = timeout

    monkeypatch.setattr(e, "_kill_proc", record)
    with pytest.raises(SystemExit) as exc:
        e.signal_handler(15, None)
    assert exc.value.code == 0
    # The upload watcher is a control-socket client too, so it goes before Tor.
    assert order == ["upload watcher", "Vanguards", "Tor"]
    assert grants == {"upload watcher": 5, "Vanguards": 5, "Tor": 10}
    assert "Received signal 15" in capsys.readouterr().out


# ─────────────────────────────────────────────────────────────────────────────
# _assert_process_dropped
# ─────────────────────────────────────────────────────────────────────────────

class _Pid:
    def __init__(self, pid=12345):
        self.pid = pid


def test_a_status_file_that_is_not_there_yet_is_retried(monkeypatch):
    """Popen returns before the child has been scheduled, so /proc/<pid>/status
    can legitimately be missing for the first few reads. Giving up there would
    report every Tor as unverified and refuse to start the container."""
    reads = []

    class Flaky:
        def __init__(self, path):
            self.path = path

        def read_text(self, encoding=None):
            reads.append(1)
            if len(reads) < 3:
                raise FileNotFoundError(2, "No such file or directory")
            return "Name:\ttor\nUid:\t100\t100\t100\t100\n"

    slept = []
    monkeypatch.setattr(e, "Path", Flaky)
    monkeypatch.setattr(e.time, "sleep", slept.append)
    assert e._assert_process_dropped(_Pid(), "Tor", timeout=5) is True
    assert len(reads) == 3
    # A tenth of a second: long enough not to spin, short enough that the check
    # does not itself delay the start of the container.
    assert slept == [0.1, 0.1]


def test_a_status_file_that_never_appears_is_a_refusal_not_an_assumption(
        monkeypatch, capsys):
    """Timing out means we could not confirm the drop. "Could not confirm" and
    "confirmed" must not be the same answer when the thing being confirmed is
    whether the onion key is held by a root process."""
    clock = {"t": 0.0}

    class Missing:
        def __init__(self, path):
            pass

        def read_text(self, encoding=None):
            raise FileNotFoundError(2, "gone")

    monkeypatch.setattr(e, "Path", Missing)
    monkeypatch.setattr(e.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(e.time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s))
    assert e._assert_process_dropped(_Pid(), "Tor", timeout=2) is False
    assert capsys.readouterr().out == (
        "FATAL: could not confirm Tor dropped privileges within 2s.\n")
    # Polled, rather than spinning or sleeping through the whole budget.
    assert 2 <= clock["t"] < 2.5


def test_a_child_still_at_uid_zero_is_named_in_the_refusal(monkeypatch, capsys):
    """The operator has to be told WHICH process, and that the container is
    stopping on purpose rather than crashing."""
    monkeypatch.setattr(e, "_uid_from_status", lambda text: 0)

    class Status:
        def __init__(self, path):
            pass

        def read_text(self, encoding=None):
            return "Uid:\t0\t0\t0\t0\n"

    monkeypatch.setattr(e, "Path", Status)
    assert e._assert_process_dropped(_Pid(777), "Vanguards", timeout=1) is False
    assert capsys.readouterr().out == (
        "FATAL: Vanguards (pid 777) is running as root; the privilege drop to "
        "the tor user failed. Refusing to continue.\n")


def test_a_status_file_with_no_uid_line_is_retried_then_refused(monkeypatch, capsys):
    """/proc/<pid>/status is readable before it is fully populated. A missing Uid
    line is "not yet", not "not root" -- and if it never arrives, the answer is
    still a refusal."""
    clock = {"t": 0.0}
    slept = []

    class NoUid:
        def __init__(self, path):
            pass

        def read_text(self, encoding=None):
            return "Name:\ttor\nState:\tR (running)\n"

    def sleep(seconds):
        slept.append(seconds)
        clock["t"] += seconds

    monkeypatch.setattr(e, "Path", NoUid)
    monkeypatch.setattr(e.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(e.time, "sleep", sleep)
    assert e._assert_process_dropped(_Pid(), "Tor", timeout=1) is False
    assert set(slept) == {0.1}
    # Ten polls to cover a one-second budget at a tenth of a second each. (Eleven
    # is also correct: 0.1 summed ten times falls a float epsilon short of 1.0.)
    assert len(slept) in (10, 11), "polled for the whole budget, not once or forever"
    assert "could not confirm Tor dropped privileges within 1s" in capsys.readouterr().out


def test_the_deadline_is_a_deadline(monkeypatch, capsys):
    """`<`, not `<=`: the loop must stop AT the budget, not one poll past it."""
    clock = {"t": 0.0}

    class Missing:
        def __init__(self, path):
            pass

        def read_text(self, encoding=None):
            raise FileNotFoundError(2, "gone")

    monkeypatch.setattr(e, "Path", Missing)
    monkeypatch.setattr(e.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(e.time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s))
    # 0.4, not 0.5: four sleeps of 0.1 land exactly ON the deadline, which is the
    # only value where `<` and `<=` differ. At 0.5 the float sum overshoots and
    # both spellings stop in the same place.
    assert e._assert_process_dropped(_Pid(), "Tor", timeout=0.4) is False
    assert clock["t"] == pytest.approx(0.4, abs=0.01)


def test_su_exec_at_uid_zero_is_not_yet_not_failed(monkeypatch):
    """The child is su-exec until it execs Tor, and su-exec is root until its own
    setuid() -- that is its job. Measured in the image: a read right after Popen
    saw `su-exec` at uid 0 in 294 of 300 tries, and treating that as failure
    killed 4 of 16 concurrent container starts with a false "running as root"."""
    frames = iter([
        "Name:\tsu-exec\nUid:\t0\t0\t0\t0\n",
        "Name:\tsu-exec\nUid:\t0\t0\t0\t0\n",
        "Name:\ttor\nUid:\t100\t100\t100\t100\n",
    ])

    class Status:
        def __init__(self, path):
            pass

        def read_text(self, encoding=None):
            return next(frames)

    monkeypatch.setattr(e, "Path", Status)
    monkeypatch.setattr(e.time, "sleep", lambda s: None)
    assert e._assert_process_dropped(_Pid(), "Tor", timeout=5) is True


def test_the_target_itself_at_uid_zero_is_still_refused(monkeypatch, capsys):
    """The allowance is for su-exec only: once the process is Tor, root is fatal."""
    class Status:
        def __init__(self, path):
            pass

        def read_text(self, encoding=None):
            return "Name:\ttor\nUid:\t0\t0\t0\t0\n"

    monkeypatch.setattr(e, "Path", Status)
    assert e._assert_process_dropped(_Pid(5), "Tor", timeout=1) is False
    assert "is running as root" in capsys.readouterr().out


def test_a_su_exec_that_never_drops_is_refused_at_the_deadline(monkeypatch, capsys):
    """Waiting on su-exec must not become waiting forever, or a pass."""
    clock = {"t": 0.0}

    class Status:
        def __init__(self, path):
            pass

        def read_text(self, encoding=None):
            return "Name:\tsu-exec\nUid:\t0\t0\t0\t0\n"

    monkeypatch.setattr(e, "Path", Status)
    monkeypatch.setattr(e.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(e.time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s))
    assert e._assert_process_dropped(_Pid(), "Tor", timeout=1) is False
    assert "could not confirm Tor dropped privileges" in capsys.readouterr().out


def test_a_tor_that_died_ends_the_wait_at_once(monkeypatch):
    """Measured: a Tor that refused its config at startup left the supervisor
    waiting the full two minutes for a socket that would never appear, with the
    container showing "running" over no Tor."""
    class Dead:
        def poll(self):
            return 1
    monkeypatch.setattr(e, "_control_socket_ready", lambda: False)
    monkeypatch.setattr(e.time, "sleep", lambda s: pytest.fail("waited on a dead Tor"))
    with pytest.raises(RuntimeError, match="Tor exited"):
        e.wait_for_socket(timeout=120, tor=Dead())
