"""Tests for entrypoint.main() -- the container's whole startup and steady state.

The earlier tests covered the supervision loop: a child dying, a restart, a signal, a
shutdown. Mutation testing then showed that everything AROUND the loop was
still unheld -- 145 surviving mutants in this one function. The startup
sequence could be rewritten freely and the suite stayed green:

  - `su-exec tor tor -f /etc/tor/torrc` could become `SU-EXEC`, `-F`, or a
    different torrc path -- the privilege drop and the config Tor reads
  - the DataDirectory chown could gain `follow_symlinks=True`, or lose the
    `only_if_root_owned` guard on its chmod
  - the capability drop could move, or the dropped-mapping record be handed the
    wrong list
  - `sys.argv[1:]` could become `sys.argv[2:]`, silently eating the subcommand

So this harness RECORDS what main() does rather than stubbing it out, and the
tests assert the sequence, the arguments, and the ordering constraints that the
comments in entrypoint.py say are load-bearing.

The clock is driven by the loop's own `time.sleep(1)`, so "after 70 seconds"
means seventy iterations, and the Vanguards restart budget can be tested at its
real thresholds.
"""
import sys
from collections import namedtuple
from itertools import pairwise

import pytest

import entrypoint as e

TorPw = namedtuple("TorPw", "pw_uid pw_gid")
TOR_UID, TOR_GID = 100, 101


class FakeProc:
    """A child whose poll() walks a scripted list of return codes."""

    def __init__(self, polls, pid=4242):
        self._polls = list(polls)
        self.pid = pid
        self.terminated = False
        self.killed = False

    def poll(self):
        rc = self._polls[0]
        if len(self._polls) > 1:
            self._polls.pop(0)
        return rc

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return self._polls[0]

    def kill(self):
        self.killed = True
        self.terminated = True


class Harness:
    """Everything main() reaches for, recorded rather than performed."""

    def __init__(self):
        self.events = []            # ordered phase names
        self.signals = []
        self.popen_argv = []
        self.dropped_record = None
        self.datadir_chmod = None
        self.datadir_chown = None
        self.published = []
        self.publish_calls = 0
        self.dropped_checks = []
        self.killed = []
        self.wait_kwargs = None
        self.vanguards_started = 0
        self.vanguards_start_times = []
        self.pwnam_asked = []
        self.socket_probes = 0
        self.dispatch_argv = None
        self.time = 1000.0

    # A mutant that breaks the loop's exit condition runs main() for ever. A
    # recorder that appends once per iteration then turns that into unbounded
    # memory growth: three mutation runs were killed by the OOM killer, taking
    # the whole grading job with them, before the cause was this and not the
    # code under test. Everything here is capped, so a runaway mutant is a
    # timeout -- which is a result -- rather than a dead machine.
    LIMIT = 10_000

    def note(self, name):
        if len(self.events) < self.LIMIT:
            self.events.append(name)


@pytest.fixture
def supervisor(monkeypatch, tmp_path):
    """Run main() headless. Returns (exit_code, harness)."""

    def run(tor_polls=(0,), vanguards_polls=(1,), *, vanguards_lives=None,
            hs_dirs=("/keys/app",),
            dropped=(), dropped_ok=True, start_vanguards_raises=None,
            wait_raises=None, generate_raises=None, can_drop_raises=None,
            data_dir_exists=True, argv=("entrypoint.py",), socket_ready=True):
        h = Harness()
        data_dir = tmp_path / "var-lib-tor"
        if data_dir_exists:
            # exist_ok: a test may drive main() more than once.
            data_dir.mkdir(exist_ok=True)

        # main() assigns to these module globals so the signal handler can reach
        # both children; a value left behind by a previous run makes the loop
        # believe a child is already alive.
        monkeypatch.setattr(e, "_tor_process", None)
        monkeypatch.setattr(e, "_vanguards_process", None)
        monkeypatch.setattr(sys, "argv", list(argv))
        monkeypatch.setattr(e, "DATA_DIR", str(data_dir))
        monkeypatch.setattr(
            e.pwd, "getpwnam",
            lambda name: h.pwnam_asked.append(name) or TorPw(TOR_UID, TOR_GID))

        def dispatch(a):
            h.dispatch_argv = a
            return None

        monkeypatch.setattr(e, "dispatch_subcommand", dispatch)
        monkeypatch.setattr(e.signal, "signal",
                            lambda sig, handler: h.signals.append((sig, handler)))

        def can_drop():
            h.note("assert_can_drop")
            if can_drop_raises:
                raise can_drop_raises

        monkeypatch.setattr(e, "_assert_can_drop_privileges", can_drop)

        def generate():
            h.note("generate_torrc")
            if generate_raises:
                raise generate_raises
            return list(hs_dirs), list(dropped)

        monkeypatch.setattr(e, "generate_basic_torrc", generate)

        def write_dropped(reasons, pw):
            h.note("write_dropped")
            h.dropped_record = (reasons, pw)

        monkeypatch.setattr(e, "_write_dropped_mappings", write_dropped)

        def chmod(path, mode, **kw):
            h.note("datadir_chmod")
            h.datadir_chmod = (str(path), mode, kw)
            return True

        monkeypatch.setattr(e, "_chmod_dir_nofollow", chmod)

        def chown(path, uid, gid, **kw):
            h.note("datadir_chown")
            h.datadir_chown = (str(path), uid, gid, kw)

        monkeypatch.setattr(e.os, "chown", chown)

        def drop_caps(mask=e.POST_SETUP_CAPS):
            # Never for real: executed as root, capset(2) would irreversibly
            # narrow the test runner's own capabilities.
            h.note("drop_caps")
            return True

        monkeypatch.setattr(e, "_drop_setup_capabilities", drop_caps)

        tor = FakeProc(tor_polls)

        def popen(argv_, **kwargs):
            h.note("start_tor")
            h.popen_argv.append(argv_)
            return tor

        monkeypatch.setattr(e.subprocess, "Popen", popen)

        def assert_dropped(proc, name, timeout=5):
            h.note("assert_dropped")
            h.dropped_checks.append((proc, name, timeout))
            return dropped_ok

        monkeypatch.setattr(e, "_assert_process_dropped", assert_dropped)

        def kill(proc, name, timeout=10):
            if len(h.killed) < Harness.LIMIT:
                h.killed.append((proc, name, timeout))

        monkeypatch.setattr(e, "_kill_proc", kill)

        def publish(dirs, keys_root=e.KEYS_ROOT, gate=None):
            # Not merely a stub. An earlier version of the readiness gate was
            # added to _publish_addresses' signature and documented, but never
            # actually passed at the call site, so the gate was inert and a
            # container with no working onion-service circuits published its
            # address anyway. Nothing caught it.
            assert gate is e._service_reachable, (
                "the supervision loop must pass the readiness gate to "
                "_publish_addresses; without it an unreachable service publishes "
                "its .onion")
            h.publish_calls += 1
            if len(h.published) < Harness.LIMIT:
                h.published.append(list(dirs))

        monkeypatch.setattr(e, "_publish_addresses", publish)

        def wait(**kwargs):
            h.note("wait_for_socket")
            h.wait_kwargs = kwargs
            if wait_raises:
                raise wait_raises

        monkeypatch.setattr(e, "wait_for_socket", wait)

        def start_vg():
            h.vanguards_started += 1
            if len(h.vanguards_start_times) < Harness.LIMIT:
                h.vanguards_start_times.append(h.time)
            if start_vanguards_raises:
                raise start_vanguards_raises
            if vanguards_lives:
                index = min(h.vanguards_started - 1, len(vanguards_lives) - 1)
                return FakeProc(list(vanguards_lives[index]))
            return FakeProc(list(vanguards_polls))

        monkeypatch.setattr(e, "start_vanguards", start_vg)
        def socket_probe():
            h.socket_probes += 1
            return socket_ready

        monkeypatch.setattr(e, "_control_socket_ready", socket_probe)

        # The loop's own sleep is the clock: one iteration is one second.
        def sleep(seconds):
            h.time += seconds

        monkeypatch.setattr(e.time, "sleep", sleep)
        monkeypatch.setattr(e.time, "monotonic", lambda: h.time)

        with pytest.raises(SystemExit) as excinfo:
            e.main()
        return excinfo.value.code, h

    return run


# ─────────────────────────────────────────────────────────────────────────────
# Startup: the order is the security property
# ─────────────────────────────────────────────────────────────────────────────

def test_startup_runs_in_the_documented_order(supervisor):
    """Three orderings in here are load-bearing, and all three are comments in
    entrypoint.py rather than anything the code enforces:

      - the dropped-mapping record is written BEFORE /var/lib/tor is handed to
        the tor user, because afterwards container root cannot write there at all
        under rootless Podman;
      - the DataDirectory chown happens AFTER the torrc generation that creates
        the service directories inside it, for the same reason;
      - the capabilities are dropped AFTER all ownership fixing and BEFORE any
        long-lived process is started.
    """
    code, h = supervisor(tor_polls=[0])
    assert code == 1
    assert h.events[:8] == [
        "assert_can_drop",
        "generate_torrc",
        "write_dropped",
        "datadir_chmod",
        "datadir_chown",
        "drop_caps",
        "start_tor",
        "assert_dropped",
    ]


def test_both_shutdown_signals_reach_the_handler(supervisor):
    """SIGTERM is `docker stop`; SIGINT is Ctrl-C on an attached run. Without the
    handler the default disposition kills PID 1 outright and Tor and Vanguards
    are reaped by the kernel with no chance to close circuits."""
    _code, h = supervisor(tor_polls=[0])
    assert h.signals == [
        (e.signal.SIGTERM, e.signal_handler),
        (e.signal.SIGINT, e.signal_handler),
    ]


def test_the_whole_command_line_is_offered_to_the_dispatcher(supervisor):
    """argv[1:], not argv[2:]: `docker run <image> show --json` must reach the
    CLI whole. Dropping the first element turns `show` into a boot."""
    _code, h = supervisor(tor_polls=[0], argv=["entrypoint.py", "show", "--json"])
    assert h.dispatch_argv == ["show", "--json"]


def test_a_dispatched_subcommand_exits_with_its_own_code(monkeypatch):
    """`docker run <image> doctor` must report doctor's verdict, not 0."""
    monkeypatch.setattr(sys, "argv", ["entrypoint.py", "doctor"])
    monkeypatch.setattr(e, "dispatch_subcommand", lambda argv: 4)
    with pytest.raises(SystemExit) as excinfo:
        e.main()
    assert excinfo.value.code == 4


def test_the_output_streams_are_reconfigured_before_anything_is_printed(monkeypatch):
    """A lone surrogate -- from a non-UTF-8 environment value or path -- makes the
    default UTF-8 stdout raise UnicodeEncodeError and aborts startup. Found by
    the fuzz target. _safe() escapes the values we know about; this catches the
    ones we did not think of, and it has to happen before the first print."""
    class Stream:
        def __init__(self):
            self.reconfigured = None

        def reconfigure(self, **kwargs):
            self.reconfigured = kwargs

        def write(self, _text):
            pass

        def flush(self):
            pass

    out, err = Stream(), Stream()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    monkeypatch.setattr(sys, "argv", ["entrypoint.py", "version"])
    monkeypatch.setattr(e, "dispatch_subcommand", lambda argv: 0)
    with pytest.raises(SystemExit):
        e.main()
    assert out.reconfigured == {"errors": "backslashreplace"}
    assert err.reconfigured == {"errors": "backslashreplace"}


def test_a_stream_without_reconfigure_is_left_alone(monkeypatch):
    """Under `docker run` with a redirected stdout the stream may not be a
    TextIOWrapper at all. Startup must not die on that."""
    monkeypatch.setattr(sys, "stdout", object())
    monkeypatch.setattr(sys, "argv", ["entrypoint.py", "version"])
    monkeypatch.setattr(e, "dispatch_subcommand", lambda argv: 0)
    with pytest.raises(SystemExit) as excinfo:
        e.main()
    assert excinfo.value.code == 0


# ─────────────────────────────────────────────────────────────────────────────
# Startup: the arguments
# ─────────────────────────────────────────────────────────────────────────────

def test_tor_is_started_as_the_tor_user_with_the_generated_config(supervisor):
    """The whole design rests on this one argv: `su-exec tor` is the privilege
    drop, and `-f <TORRC_PATH>` is the hardened config rather than Tor's
    compiled-in defaults."""
    _code, h = supervisor(tor_polls=[0])
    assert h.popen_argv == [["su-exec", "tor", "tor", "-f", e.TORRC_PATH]]


def test_the_dropped_mappings_recorded_are_the_ones_generation_produced(supervisor):
    _code, h = supervisor(tor_polls=[0], dropped=["APP: no valid port mappings"])
    reasons, pw = h.dropped_record
    assert reasons == ["APP: no valid port mappings"]
    assert (pw.pw_uid, pw.pw_gid) == (TOR_UID, TOR_GID)


def test_the_data_directory_is_secured_without_following_a_symlink(supervisor):
    """0700, only if root still owns it (chmod'ing a directory we do not own
    needs CAP_FOWNER), and an lchown so a symlinked DataDirectory cannot redirect
    root's chown elsewhere."""
    _code, h = supervisor(tor_polls=[0])
    path, mode, kw = h.datadir_chmod
    assert (mode, kw) == (0o700, {"only_if_root_owned": True})
    chown_path, uid, gid, chown_kw = h.datadir_chown
    assert (uid, gid) == (TOR_UID, TOR_GID)
    assert chown_kw == {"follow_symlinks": False}
    assert path == chown_path


def test_a_missing_data_directory_is_skipped_not_created(supervisor):
    """Under Docker the tmpfs is mounted tor:tor already; there is nothing to do
    and nothing to fail on."""
    _code, h = supervisor(tor_polls=[0], data_dir_exists=False)
    assert h.datadir_chmod is None
    assert h.datadir_chown is None
    assert "start_tor" in h.events


def test_the_child_is_checked_for_a_real_privilege_drop(supervisor):
    _code, h = supervisor(tor_polls=[0])
    proc, name, _timeout = h.dropped_checks[0]
    assert name == "Tor"
    assert proc is not None


def test_a_tor_still_running_as_root_is_killed_not_trusted(supervisor, capsys):
    """A silent su-exec failure would run Tor -- and the onion key -- as root.
    Refusing to continue is the only safe answer, and the process must not be
    left behind."""
    code, h = supervisor(tor_polls=[None], dropped_ok=False)
    assert code == 1
    assert h.killed == [(h.dropped_checks[0][0], "Tor", 5)]
    assert h.popen_argv, "Tor was started"
    assert h.events[-1] == "assert_dropped", "the loop must not have been entered"


def test_the_socket_wait_is_bounded(supervisor):
    """An unbounded wait would hang a container whose Tor never opens its control
    socket, with Tor unsupervised behind it."""
    _code, h = supervisor(tor_polls=[0])
    assert h.wait_kwargs == {"timeout": 120}


# ─────────────────────────────────────────────────────────────────────────────
# Startup failures
# ─────────────────────────────────────────────────────────────────────────────

def test_a_failed_privilege_probe_is_fatal_and_says_why(supervisor, capsys):
    code, h = supervisor(tor_polls=[0],
                         can_drop_raises=RuntimeError("cannot switch to the tor user"))
    assert code == 1
    assert "FATAL: cannot switch to the tor user" in capsys.readouterr().out
    assert h.popen_argv == [], "Tor must not be started"


def test_a_failed_torrc_generation_is_fatal_and_says_why(supervisor, capsys):
    """Starting Tor on a stale or absent torrc would serve the wrong config, or
    none; there is nothing to fall back to."""
    code, h = supervisor(tor_polls=[0], generate_raises=OSError("/etc/tor is read-only"))
    assert code == 1
    assert "Error generating configuration: /etc/tor is read-only" in capsys.readouterr().out
    assert h.popen_argv == []


def test_a_control_socket_that_never_appears_does_not_stop_tor(supervisor, capsys):
    """Tor is the primary process. Vanguards not starting is a degraded
    container, not a dead one, and the loop keeps retrying."""
    code, h = supervisor(tor_polls=[None] * 3 + [0],
                         wait_raises=TimeoutError("Tor control socket not found after 120s"))
    assert code == 1
    out = capsys.readouterr().out
    assert "Will keep retrying Vanguards" in out
    assert h.vanguards_started >= 1, "the loop retried the addon"


def test_a_vanguards_that_cannot_start_at_boot_does_not_stop_tor(supervisor, capsys):
    code, _h = supervisor(tor_polls=[None] * 3 + [0],
                          start_vanguards_raises=OSError("no such binary"))
    assert code == 1
    out = capsys.readouterr().out
    assert "could not start Vanguards: no such binary" in out
    assert "Will keep retrying" in out


# ─────────────────────────────────────────────────────────────────────────────
# The steady state
# ─────────────────────────────────────────────────────────────────────────────

def test_addresses_are_republished_every_iteration_for_every_service(supervisor):
    """Cheap by design -- a 56-byte read per service, skipped once already
    correct -- and it must cover every configured service, not the first."""
    _code, h = supervisor(tor_polls=[None] * 3 + [0],
                          hs_dirs=["/keys/app", "/keys/web"])
    assert h.published
    assert all(dirs == ["/keys/app", "/keys/web"] for dirs in h.published)


def test_the_loop_ticks_once_a_second(supervisor):
    """The publication gate and the liveness checks all hang off this. A longer
    tick delays the address; a shorter one spends CPU on a container that is
    supposed to be idle."""
    _code, h = supervisor(tor_polls=[None] * 9 + [0])
    assert h.time == 1000.0 + 10


def test_tor_exiting_zero_is_reported_as_failure(supervisor):
    """An onion that died must not exit 0: under restart:on-failure the container
    would stay DOWN with a success status, leaving a dead onion that still looks
    healthy in `docker ps`."""
    code, _h = supervisor(tor_polls=[0])
    assert code == 1


def test_tor_exiting_nonzero_is_preserved(supervisor):
    code, _h = supervisor(tor_polls=[7])
    assert code == 7


def test_a_dying_tor_takes_vanguards_with_it(supervisor, capsys):
    """Vanguards talks to Tor's control socket; leaving it behind gives a process
    that can do nothing but log connection failures. It must be handed the actual
    child -- `None` there terminates nothing and the addon outlives PID 1."""
    # vanguards_polls=(None,): the addon is still alive when Tor dies, which is
    # the case where there is something to stop.
    _code, h = supervisor(tor_polls=[None, 3], vanguards_polls=(None,))
    killed = [(proc, name, timeout) for proc, name, timeout in h.killed
              if name == "Vanguards"]
    assert killed, "Vanguards was not stopped"
    proc, _name, timeout = killed[0]
    assert timeout == 5
    assert isinstance(proc, FakeProc), f"a {type(proc).__name__} was killed, not the child"
    assert "Tor exited with code 3, shutting down." in capsys.readouterr().out


def test_vanguards_crashes_are_restarted_then_disabled(supervisor, capsys):
    """initial start + up to VANGUARDS_MAX_RESTARTS restarts, then it is disabled
    and the loop carries on with Tor alone. Unbounded restarting of a component
    that is failing for a structural reason is a busy loop, not resilience."""
    code, h = supervisor(tor_polls=[None] * 200 + [0], vanguards_polls=(1,))
    assert code == 1
    assert h.vanguards_started == 1 + e.VANGUARDS_MAX_RESTARTS
    out = capsys.readouterr().out
    assert "Vanguards exited (code 1), retrying in 10s (attempt 1/5)..." in out
    assert "Vanguards exited (code 1) too many times in quick succession — disabling addon." in out


def test_the_retry_budget_is_spaced_out_not_spun(supervisor):
    """Each retry waits VANGUARDS_RETRY_DELAY. A next-attempt time in the PAST
    turns the budget into five restarts in five iterations and then a permanently
    disabled addon, five seconds into a container's life."""
    _code, h = supervisor(tor_polls=[None] * 200 + [0], vanguards_polls=(1,))
    # First start at t0, then one restart per retry delay.
    assert h.time >= 1000.0 + e.VANGUARDS_MAX_RESTARTS * e.VANGUARDS_RETRY_DELAY


def test_an_addon_that_ran_for_over_a_minute_gets_its_budget_back(supervisor):
    """The budget is for a component crashing in quick succession. One exit an
    hour, for the life of a long-running container, is not that -- and must not
    accumulate into a permanently disabled addon on day three."""
    # Alive for 61 iterations (61s > 60), then exits; repeated well past the
    # restart budget. Every exit resets the counter, so it is never exhausted.
    long_lived = [None] * 61 + [1]
    _code, h = supervisor(tor_polls=[None] * 800 + [0],
                          vanguards_polls=long_lived)
    assert h.vanguards_started > 1 + e.VANGUARDS_MAX_RESTARTS


def test_a_missing_control_socket_does_not_consume_the_restart_budget(supervisor, capsys):
    """Tor still bootstrapping is not Vanguards failing. Spending the budget on
    it would leave a healthy container with no addon."""
    code, h = supervisor(tor_polls=[None] * 200 + [0], socket_ready=False,
                         wait_raises=TimeoutError("not yet"))
    assert code == 1
    assert h.vanguards_started == 0
    assert "disabling addon" not in capsys.readouterr().out


# ─────────────────────────────────────────────────────────────────────────────
# The boot log
# ─────────────────────────────────────────────────────────────────────────────
#
# The shipped compose file sets `logging: driver: none` so that the host keeps no
# record of onion activity, which means these lines exist for the case where an
# operator has turned the log driver back on to find out why a container is not
# working. A boot that says nothing, or says it in a form nobody greps for, is
# the difference between a five-minute diagnosis and a rebuild.

def test_a_clean_boot_says_each_step_once(supervisor, capsys):
    _code, _h = supervisor(tor_polls=[0])
    assert capsys.readouterr().out == (
        "Generating Tor configuration...\n"
        "Tor configuration generated successfully.\n"
        "Starting Tor...\n"
        "Vanguards addon started.\n"
        "Tor exited with code 0, shutting down.\n")


def test_the_tor_user_is_looked_up_by_name(supervisor):
    """`pwd.getpwnam('tor')`. The uid is not hardcoded because the image builds
    the user; asking for any other name is a KeyError at boot at best, and the
    wrong owner on the onion keys at worst."""
    _code, h = supervisor(tor_polls=[0])
    assert h.pwnam_asked == ["tor"]


def test_a_restarted_addon_announces_itself_too(supervisor, capsys):
    """The restart path prints the same line as the boot path, on purpose: an
    operator grepping for "Vanguards addon started" is asking "is it running
    now", not "did it start at boot"."""
    _code, _h = supervisor(tor_polls=[None] * 30 + [0], vanguards_polls=(1,))
    out = capsys.readouterr().out
    assert out.count("Vanguards addon started.\n") >= 2


def test_each_retry_waits_the_full_delay(supervisor):
    """A next-attempt time in the past, or an off-by-one comparison, turns the
    bounded retry into five restarts in five seconds followed by a permanently
    disabled addon -- five seconds into the container's life, while Tor is still
    bootstrapping."""
    _code, h = supervisor(tor_polls=[None] * 300 + [0], vanguards_polls=(1,))
    gaps = [b - a for a, b in pairwise(h.vanguards_start_times)]
    # One iteration to notice the exit, then the full delay before retrying.
    assert gaps == [1 + e.VANGUARDS_RETRY_DELAY] * e.VANGUARDS_MAX_RESTARTS


def test_an_addon_alive_for_exactly_sixty_seconds_has_not_earned_a_reset(supervisor):
    """The threshold is "more than a minute", not "a minute". Sixty seconds is
    the boundary the code names; a reset at exactly sixty would make a component
    crashing on a one-minute cycle restartable for ever."""
    # Exit noticed exactly 60 seconds after the start: no reset, so the budget
    # runs out. One second later (61s) it would be refunded -- see
    # test_an_addon_that_ran_for_over_a_minute_gets_its_budget_back.
    _code, h = supervisor(tor_polls=[None] * 900 + [0], vanguards_polls=[None] * 59 + [1])
    assert h.vanguards_started == 1 + e.VANGUARDS_MAX_RESTARTS


def test_a_generator_that_keeps_failing_is_disabled_after_its_budget(supervisor, capsys):
    """A start that RAISES is counted where it happens, so this path spends one
    more attempt than the exit path does: the boot attempt, then MAX_RESTARTS + 1
    in the loop, the last of which trips the limit. Stated here rather than
    rounded off, because the count is what stops a container that can never load
    the addon from spinning on it for ever."""
    _code, h = supervisor(tor_polls=[None] * 300 + [0],
                          start_vanguards_raises=OSError("no such binary"))
    assert h.vanguards_started == 2 + e.VANGUARDS_MAX_RESTARTS
    out = capsys.readouterr().out
    assert out.count("Could not start Vanguards: no such binary") == e.VANGUARDS_MAX_RESTARTS + 1
    assert "Vanguards could not be started — disabling addon." in out


def test_a_disabled_addon_is_never_retried_again(supervisor):
    """`vanguards_given_up` is final. A falsy value there would make the
    "disabling addon" line a lie and put the loop straight back into retrying."""
    _code, h = supervisor(tor_polls=[None] * 900 + [0],
                          start_vanguards_raises=OSError("gone"))
    assert h.vanguards_started == 2 + e.VANGUARDS_MAX_RESTARTS


def test_a_healthy_spell_refunds_the_whole_budget_not_all_but_one(supervisor):
    """After more than a minute alive the counter goes back to ZERO, so the next
    bad patch gets the full five restarts. Resetting to one silently spends a
    restart that the operator was never told about, and the addon is disabled a
    crash earlier than the documented budget.

    Three quick crashes, then a spell over a minute, then quick crashes again.
    The reset happens on the healthy spell's exit and is immediately followed by
    that exit's own increment, so the counter lands on 1 and five more starts
    follow. A reset to one would land on 2 and allow only four.
    """
    quick = [1]
    long_lived = [None] * 61 + [1]
    lives = [quick, quick, quick, long_lived] + [quick] * 20
    _code, h = supervisor(tor_polls=[None] * 900 + [0], vanguards_lives=lives)
    assert h.vanguards_started == 4 + e.VANGUARDS_MAX_RESTARTS


def test_a_failing_start_also_waits_the_full_delay_before_retrying(supervisor):
    """The exception path has its own next-attempt arithmetic, and it must not be
    a retry time in the past: that turns the budget into five attempts in five
    seconds while Tor is still bootstrapping."""
    _code, h = supervisor(tor_polls=[None] * 300 + [0],
                          start_vanguards_raises=OSError("gone"))
    gaps = [b - a for a, b in pairwise(h.vanguards_start_times)]
    # The boot attempt fails before the loop, so the loop's first attempt is one
    # iteration later; every attempt after that waits the full delay.
    assert gaps[0] == 1
    assert set(gaps[1:]) == {e.VANGUARDS_RETRY_DELAY}


def test_the_disabling_lines_are_exact(supervisor, capsys):
    """Two different ways to lose the addon, two different messages; both mean
    bandguards and rendguard are gone for the life of the container, and the
    health status is the only other place that is visible."""
    supervisor(tor_polls=[None] * 300 + [0], start_vanguards_raises=OSError("gone"))
    assert "Vanguards could not be started — disabling addon.\n" in capsys.readouterr().out
    supervisor(tor_polls=[None] * 300 + [0], vanguards_polls=(9,))
    assert ("Vanguards exited (code 9) too many times in quick succession — "
            "disabling addon.\n") in capsys.readouterr().out


def test_a_down_socket_is_re_probed_on_the_retry_delay_not_every_second(supervisor):
    """`now + VANGUARDS_RETRY_DELAY`. A next-attempt time in the PAST makes the
    loop shell out to `su-exec tor test -S` every single second for as long as Tor
    takes to bootstrap -- on a container whose whole steady state is supposed to
    be one cheap read per second."""
    _code, h = supervisor(tor_polls=[None] * 100 + [0], socket_ready=False,
                          wait_raises=TimeoutError("not yet"))
    # 100 iterations, one probe per retry delay, give or take the first.
    assert h.socket_probes <= 100 // e.VANGUARDS_RETRY_DELAY + 2
    assert h.socket_probes >= 2, "it must keep looking"


def test_sixty_one_seconds_alive_does_earn_a_reset(supervisor):
    """The other side of the threshold from
    test_an_addon_alive_for_exactly_sixty_seconds_has_not_earned_a_reset. One
    second more than the minute refunds the budget; a comparison against 61 would
    make the documented "more than a minute" quietly mean "more than a minute and
    a second", and an addon on a 61-second crash cycle would be disabled."""
    _code, h = supervisor(tor_polls=[None] * 900 + [0],
                          vanguards_lives=[[None] * 60 + [1]] * 30)
    assert h.vanguards_started > 1 + e.VANGUARDS_MAX_RESTARTS
