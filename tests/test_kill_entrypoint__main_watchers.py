"""Holds on entrypoint.main() that mutation testing found unheld.

Covers: the upload watcher must actually be started at boot; _BackendWatch must
be handed the live resolution dicts (both of them, in that order); the two
backend-move operator messages must name the backend and the addresses; the
upload-watcher restart line must be exactly what an operator greps for; and the
Vanguards restart budget must always start at ZERO.

The harness is the same recorder used by test_supervisor.py.
"""
from typing import ClassVar

import pytest
from itertools import pairwise

import entrypoint as e


class _MovedAfterTwo:
    """Like test_supervisor._MovedAfter, but the moved backend reports TWO
    addresses, so a join that corrupted the separator would show up."""

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
        if self.ticks > 0:
            return None
        if self.old is None:
            return ("web", None, ["172.20.0.9", "172.20.0.10"])
        return ("web", self.old, ["172.20.0.9", "172.20.0.10"])


class _BackendWatchRecorder:
    """Records how main() constructs _BackendWatch, and never finds a move."""

    calls: ClassVar[list] = []

    def __init__(self, *args, **kwargs):
        _BackendWatchRecorder.calls.append(args)
        self.moved = None

    def start(self):
        return self


class _WatchStartedBeforeTheBackendWatch:
    """A _BackendWatch that, when constructed, records whether a watcher exists.

    main() starts the upload watcher BEFORE it constructs this, so `seen` is
    the watcher object main() is holding (or None) at that moment. A boot that
    never starts a watcher is only observable from inside main(); this is the
    earliest hook that can see it.
    """

    seen: ClassVar[list] = []

    def __init__(self, *args, **kwargs):
        _WatchStartedBeforeTheBackendWatch.seen.append(e._upload_watcher)
        self.moved = None

    def start(self):
        return self


@pytest.fixture(autouse=True)
def _reset_recorder():
    _BackendWatchRecorder.calls = []
    _WatchStartedBeforeTheBackendWatch.seen = []
    yield
    _BackendWatchRecorder.calls = []
    _WatchStartedBeforeTheBackendWatch.seen = []


# ─────────────────────────────────────────────────────────────────────────────
# Startup wiring
# ─────────────────────────────────────────────────────────────────────────────

def test_a_clean_boot_starts_the_upload_watcher_and_never_restarts_it(
        supervisor, monkeypatch, capsys):
    """A boot that never starts a watcher leaves every service unreachable, and
    the restart line is a lie about a watcher that never existed: on a clean
    boot nothing exited."""
    monkeypatch.setattr(e, "_BackendWatch", _WatchStartedBeforeTheBackendWatch)
    code, h = supervisor(tor_polls=[None] * 3 + [0])
    assert code == 1
    watcher = _WatchStartedBeforeTheBackendWatch.seen[-1]
    assert watcher is not None, \
        "the upload watcher must be started at boot, before the loop"
    assert getattr(watcher, "pid", None) == 5151
    assert "upload watcher" in [name for _p, name, _t in h.killed]
    assert "Upload watcher exited; restarting it." not in capsys.readouterr().out


def test_the_backend_watch_is_handed_the_live_resolution_dicts(
        supervisor, monkeypatch):
    """_BackendWatch needs BOTH: `recorded` (name -> IP written into the torrc)
    and `pending` (names that did not resolve at start). Generating the torrc
    fills those very module-level objects, so passing a different object, or
    dropping either argument, silently disables backend-move detection."""
    monkeypatch.setattr(e, "_BackendWatch", _BackendWatchRecorder)
    code, _h = supervisor(tor_polls=[None] * 3 + [0])
    assert code == 1
    assert _BackendWatchRecorder.calls == [(e._backend_ips, e._backend_pending)]
    assert isinstance(e._backend_ips, dict)
    assert isinstance(e._backend_pending, set)


# ─────────────────────────────────────────────────────────────────────────────
# The operator messages for a backend that moved
# ─────────────────────────────────────────────────────────────────────────────

def test_a_backend_reaching_a_new_address_names_name_and_addresses(
        supervisor, monkeypatch, capsys):
    """`old` is an IP here. The message must name the backend and both the new
    addresses and the stale one, because it is the only thing an operator sees
    before the container restarts."""
    monkeypatch.setattr(e, "_BackendWatch", _MovedAfterTwo(3))
    code, _h = supervisor(tor_polls=[None] * 20)
    assert code == 1
    out = capsys.readouterr().out
    assert ("Backend 'web' now resolves to 172.20.0.9, 172.20.0.10, but Tor "
            "is still forwarding to 172.20.0.3. Restarting so the onion "
            "follows it (the address itself does not change).") in out


def test_a_backend_that_appeared_late_names_name_and_addresses(
        supervisor, monkeypatch, capsys):
    """`old is None`: the backend did not resolve at startup and was dropped
    from the torrc. Here too the message must name the backend and the
    addresses it now has -- not 'None'."""
    monkeypatch.setattr(e, "_BackendWatch", _MovedAfterTwo(3, old=None))
    code, _h = supervisor(tor_polls=[None] * 20)
    assert code == 1
    out = capsys.readouterr().out
    assert ("Backend 'web' did not resolve at startup and now resolves to "
            "172.20.0.9, 172.20.0.10. Restarting so the service it was "
            "dropped from is configured (addresses do not change).") in out


# ─────────────────────────────────────────────────────────────────────────────
# The upload watcher restart line
# ─────────────────────────────────────────────────────────────────────────────

def test_a_watcher_that_exited_is_announced_verbatim(supervisor, capsys):
    """An operator greps for this exact line to tell "the watcher is cycling"
    from "the watcher never started"."""
    _code, h = supervisor(tor_polls=[None] * 100 + [0], watcher_polls=(1,))
    assert h.watchers_started >= 2
    assert "Upload watcher exited; restarting it.\n" in capsys.readouterr().out


# ─────────────────────────────────────────────────────────────────────────────
# The Vanguards restart budget starts at ZERO
# ─────────────────────────────────────────────────────────────────────────────

def test_a_fresh_container_gets_the_whole_restart_budget_for_the_exit_path(
        supervisor, capsys):
    """Initial start + exactly VANGUARDS_MAX_RESTARTS restarts, and the first
    retry is announced as attempt 1/5. A budget that starts at one spends a
    restart nobody was told about: the addon is disabled one crash early and
    the operator reads "attempt 2/5" first."""
    code, h = supervisor(tor_polls=[None] * 200 + [0], vanguards_polls=(1,))
    assert code == 1
    assert h.vanguards_started == 1 + e.VANGUARDS_MAX_RESTARTS
    out = capsys.readouterr().out
    assert (f"Vanguards exited (code 1), retrying in {e.VANGUARDS_RETRY_DELAY}s "
            f"(attempt 1/{e.VANGUARDS_MAX_RESTARTS})...") in out


def test_a_fresh_container_gets_the_whole_restart_budget_for_the_start_path(
        supervisor, capsys):
    """Same budget on the exception path, which counts its own failures: the
    boot attempt, then MAX_RESTARTS + 1 loop attempts, the last of which trips
    the limit. A budget starting at one would trip one attempt earlier."""
    _code, h = supervisor(tor_polls=[None] * 300 + [0],
                          start_vanguards_raises=OSError("no such binary"))
    assert h.vanguards_started == 2 + e.VANGUARDS_MAX_RESTARTS
    out = capsys.readouterr().out
    assert out.count("Could not start Vanguards: no such binary") \
        == e.VANGUARDS_MAX_RESTARTS + 1


def real_retries(gaps):
    """The quick retries at the head of `gaps`, and how many there were.

    `gaps` are the delays between consecutive start attempts that follow a
    cooldown. A quick retry with budget left is one iteration to notice the
    exit plus the retry delay; a pause is the (much longer) cooldown. So the
    quick retries are the run of short gaps at the head, and the first long
    gap is the next pause.
    """
    count = 0
    for gap in gaps:
        if 0 < gap < e.VANGUARDS_COOLDOWN_SECONDS:
            count += 1
        else:
            break
    return count


def test_the_cooldown_after_the_exit_path_returns_the_budget_to_zero(
        supervisor):
    """When the exit path pauses the addon it resets the counter to ZERO, so
    the attempt after the cooldown gets the documented five quick retries. A
    reset to one silently spends one of them: the next pause arrives after
    four retries instead of five. The cooldown gap itself is the same either
    way -- only the following gap shows it."""
    _code, h = supervisor(tor_polls=[None] * 2000 + [0], vanguards_polls=(1,))
    times = h.vanguards_start_times
    cooldown_gap = e.VANGUARDS_COOLDOWN_SECONDS
    pause = next(i for i, (a, b) in enumerate(pairwise(times))
                 if b - a >= cooldown_gap)
    # The attempt before the pause, then every gap after it: the retries
    # after the cooldown must be a full budget again before the next pause.
    retries_after = [b - a for a, b in pairwise(times[pause + 1:])]
    assert real_retries(retries_after) == e.VANGUARDS_MAX_RESTARTS


def test_the_cooldown_after_the_start_path_returns_the_budget_to_zero(
        supervisor):
    """Same reset on the exception path. There the counter is incremented by
    each failed start, so a reset to one leaves two-thirds of a budget: the
    next pause comes after MAX_RESTARTS - 1 retries rather than after
    MAX_RESTARTS."""
    _code, h = supervisor(tor_polls=[None] * 2400 + [0],
                          start_vanguards_raises=OSError("gone"))
    times = h.vanguards_start_times
    pause = next(i for i, (a, b) in enumerate(pairwise(times))
                 if b - a >= e.VANGUARDS_COOLDOWN_SECONDS)
    after = times[pause + 1:]
    retries_after = [b - a for a, b in pairwise(after)]
    assert real_retries(retries_after) == e.VANGUARDS_MAX_RESTARTS
