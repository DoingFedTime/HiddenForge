"""The recorder that drives entrypoint.main() headless.

Shared by test_supervisor.py and the mutation-killing tests; conftest.py turns
`make_supervisor` into the `supervisor` fixture. It RECORDS what main() does
(processes started, privileges dropped, children stopped) rather than stubbing
it out, so tests can assert sequence, arguments and ordering.
"""
import sys
from collections import namedtuple

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
        self.watchers_started = 0
        self.watcher_start_times = []
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


def make_supervisor(monkeypatch, tmp_path):
    """Run main() headless. Returns (exit_code, harness)."""
    """Run main() headless. Returns (exit_code, harness)."""

    def run(tor_polls=(0,), vanguards_polls=(1,), *, vanguards_lives=None,
            hs_dirs=("/keys/app",),
            dropped=(), dropped_ok=True, start_vanguards_raises=None,
            wait_raises=None, generate_raises=None, can_drop_raises=None,
            data_dir_exists=True, argv=("entrypoint.py",), socket_ready=True,
            watcher_polls=(None,), watcher_raises=None):
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
        monkeypatch.setattr(e, "_upload_watcher", None)
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
            assert (isinstance(gate, e._ThrottledGate)
                    and gate.gate is e._service_reachable), (
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

        def start_watcher():
            h.note("start_upload_watcher")
            h.watchers_started += 1
            if len(h.watcher_start_times) < Harness.LIMIT:
                h.watcher_start_times.append(h.time)
            if watcher_raises:
                raise watcher_raises
            return FakeProc(list(watcher_polls), pid=5151)

        monkeypatch.setattr(e, "start_upload_watcher", start_watcher)
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


class _MovedAfter:
    """A stand-in _BackendWatch whose verdict arrives after `ticks` loop turns."""
    def __init__(self, ticks, old="172.20.0.3"):
        self.ticks = ticks
        self.old = old

    def __call__(self, recorded, pending=()):
        return self

    def start(self):
        return self

    @property
    def moved(self):
        self.ticks -= 1
        return ("web", self.old, ["172.20.0.9"]) if self.ticks <= 0 else None
