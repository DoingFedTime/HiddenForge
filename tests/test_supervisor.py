"""Tests for the supervision loop in entrypoint.main().

Coverage of entrypoint.py missed the supervision loop -- essentially the
whole steady-state runtime of the container. Everything else tested startup. A
production incident happens here: a child dying, a restart, a signal, a
shutdown. These drive the loop headless with fake children and assert its stated
behaviour, which is read from the code rather than assumed:

  - Tor exits 0 on its own  -> exit 1 (a dead onion must never look successful)
  - Tor exits N on its own  -> exit N
  - SIGTERM                 -> Vanguards killed first, then Tor, exit 0
  - Vanguards crashing      -> restarted, bounded, then disabled
"""
import os
import subprocess
from collections import namedtuple

import pytest

import entrypoint as e

TorPw = namedtuple("TorPw", "pw_uid pw_gid")


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


def _headless_main(monkeypatch, tor_polls, vanguards_polls=(1,)):
    """Run main() headless, returning (SystemExit code, started_vanguards list)."""
    started = []
    clock = {"t": 0.0}

    monkeypatch.setattr(e.pwd, "getpwnam", lambda n: TorPw(os.getuid(), os.getgid()))
    monkeypatch.setattr(
        e, "generate_basic_torrc",
        lambda: (["/var/lib/tor/hidden_service/app"], []))
    monkeypatch.setattr(e, "_assert_can_drop_privileges", lambda: None)
    monkeypatch.setattr(e, "_assert_process_dropped", lambda proc, name, timeout=5: True)
    def _fake_publish(dirs, keys_root=e.KEYS_ROOT, gate=None):
        # Not merely a stub. An earlier version of the readiness gate was added to
        # _publish_addresses' signature and documented, but never actually passed
        # at the call site, so the gate was inert and a container with no working
        # onion-service circuits published its address anyway. Nothing caught it.
        # Asserting here means that regression fails the supervisor tests.
        assert gate is e._service_reachable, (
            "the supervision loop must pass the readiness gate to "
            "_publish_addresses; without it an unreachable service publishes "
            "its .onion")

    monkeypatch.setattr(e, "_publish_addresses", _fake_publish)
    # Never let the capability drop run for real here: executed as root, capset(2)
    # would irreversibly narrow the test runner's own capabilities.
    monkeypatch.setattr(e, "_drop_setup_capabilities",
                        lambda mask=e.POST_SETUP_CAPS: True)
    monkeypatch.setattr(e, "_write_dropped_mappings", lambda reasons, pw: None)
    monkeypatch.setattr(e, "wait_for_socket", lambda timeout=120: None)
    monkeypatch.setattr(e, "_control_socket_ready", lambda: True)
    monkeypatch.setattr(e.time, "sleep", lambda s: None)
    monkeypatch.setattr(e.signal, "signal", lambda *a: None)
    # The DataDirectory chmod/chown touches the host's /var/lib/tor; stub them.
    monkeypatch.setattr(e, "_chmod_dir_nofollow", lambda *a, **k: True)
    monkeypatch.setattr(e.os, "chown", lambda *a, **k: None)
    # Advance the clock fast so the retry backoff does not stall the test.
    monkeypatch.setattr(
        e.time, "monotonic",
        lambda: clock.__setitem__("t", clock["t"] + 5) or clock["t"])

    tor = FakeProc(tor_polls)
    monkeypatch.setattr(e.subprocess, "Popen", lambda *a, **k: tor)

    def fake_start_vanguards():
        started.append(True)
        return FakeProc(list(vanguards_polls))

    monkeypatch.setattr(e, "start_vanguards", fake_start_vanguards)

    with pytest.raises(SystemExit) as excinfo:
        e.main()
    return excinfo.value.code, started


def test_tor_exiting_zero_is_reported_as_failure(monkeypatch):
    """An onion that died must not exit 0: restart:on-failure would leave it down."""
    code, _ = _headless_main(monkeypatch, tor_polls=[0])
    assert code == 1


def test_tor_exiting_nonzero_is_preserved(monkeypatch):
    code, _ = _headless_main(monkeypatch, tor_polls=[7])
    assert code == 7


def test_vanguards_crashes_are_restarted_then_disabled(monkeypatch):
    """Tor survives a few iterations; Vanguards exits each time.

    initial start + up to VANGUARDS_MAX_RESTARTS restarts, then it is disabled
    and the loop carries on with Tor alone.
    """
    # Tor: "alive" for 40 polls, then exits 0 so the loop terminates.
    code, started = _headless_main(monkeypatch, tor_polls=[None] * 40 + [0],
                                   vanguards_polls=(1,))
    assert code == 1
    # The first start plus the bounded restarts; never unbounded.
    assert len(started) == 1 + e.VANGUARDS_MAX_RESTARTS


def test_sigterm_kills_vanguards_then_tor_and_exits_zero(monkeypatch):
    tor = FakeProc([None])
    vg = FakeProc([None])
    monkeypatch.setattr(e, "_tor_process", tor)
    monkeypatch.setattr(e, "_vanguards_process", vg)
    with pytest.raises(SystemExit) as excinfo:
        e.signal_handler(15, None)
    assert excinfo.value.code == 0
    assert vg.terminated, "Vanguards must be stopped first"
    assert tor.terminated, "Tor must be stopped"


# ─────────────────────────────────────────────────────────────────────────────
# _assert_can_drop_privileges
# ─────────────────────────────────────────────────────────────────────────────

def test_privilege_drop_probe_raises_on_a_nonzero_su_exec(monkeypatch):
    """A failed `su-exec tor true` must raise, not be ignored.

    This probe exists to turn a silent restart loop (RLIMIT_NPROC exhausted on
    the shared host uid 100) into one named error, and main() only exits on the
    RuntimeError. Nothing held the `returncode != 0` branch, so dropping the
    check left the suite green while the container went back to restarting with
    no explanation.
    """
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        stderr = b"su-exec: setgroups: Resource temporarily unavailable"
        return subprocess.CompletedProcess(cmd, 1, b"", stderr)

    monkeypatch.setattr(e.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError) as excinfo:
        e._assert_can_drop_privileges()

    message = str(excinfo.value)
    assert "cannot switch to the tor user" in message
    # The operator-facing detail is what makes the error actionable: su-exec's
    # own stderr, and the nproc/pids_limit remedy.
    assert "Resource temporarily unavailable" in message
    assert "ulimits.nproc" in message
    assert calls[0][0] == ["su-exec", "tor", "true"]
    assert calls[0][1]["check"] is False, "check=True would raise the wrong exception type"


def test_privilege_drop_probe_is_silent_when_su_exec_succeeds(monkeypatch):
    monkeypatch.setattr(
        e.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, b"", b""))
    assert e._assert_can_drop_privileges() is None
