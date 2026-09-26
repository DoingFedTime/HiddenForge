"""A backend that moves must not silently blackhole the onion.

Tor accepts only IPs in HiddenServicePort, so backend names are resolved once,
at start. A recreated backend container usually comes back on another IP, and
from then on every request went to an address nobody listens on while the
healthcheck stayed green. The supervisor now watches the names and restarts the
container on a CONFIRMED move -- never on a failed lookup, never on a scaled
service's other addresses.
"""
import socket

import entrypoint as e


def _resolver(*answers):
    """Each call returns the next answer; an Exception instance is raised."""
    seq = list(answers)

    def resolve(name):
        a = seq.pop(0) if len(seq) > 1 else seq[0]
        if isinstance(a, Exception):
            raise a
        return name, [], list(a)
    return resolve


def test_a_name_still_pointing_where_the_torrc_sends_is_never_a_move():
    w = e._BackendWatch({"web": "172.20.0.3"}, resolver=_resolver(["172.20.0.3"]))
    assert all(w.check_once() is None for _ in range(10))


def test_a_move_is_declared_only_after_consecutive_confirmations():
    w = e._BackendWatch({"web": "172.20.0.3"}, resolver=_resolver(["172.20.0.9"]))
    assert w.check_once() is None, "one observation is not a confirmed move"
    assert w.check_once() == ("web", "172.20.0.3", ["172.20.0.9"])


def test_a_failed_lookup_is_not_evidence_and_resets_the_count():
    """The backend being down, or DNS briefly gone, must never restart the
    container: that would turn a blip into an outage."""
    w = e._BackendWatch({"web": "172.20.0.3"},
                        resolver=_resolver(["172.20.0.9"],
                                           socket.gaierror(-2, "Name or service not known"),
                                           ["172.20.0.9"]))
    assert w.check_once() is None
    assert w.check_once() is None     # the failure
    assert w.check_once() is None, "the count restarted after the failure"


def test_a_scaled_service_answering_with_several_addresses_is_not_a_move():
    """Round-robin answers come back in any order; the recorded IP being among
    them is all that matters."""
    w = e._BackendWatch({"web": "172.20.0.3"},
                        resolver=_resolver(["172.20.0.8", "172.20.0.3"]))
    assert all(w.check_once() is None for _ in range(5))


def test_garbage_in_an_answer_is_ignored_not_trusted():
    w = e._BackendWatch({"web": "172.20.0.3"}, resolver=_resolver(["not-an-ip", ""]))
    assert all(w.check_once() is None for _ in range(5))


def test_only_names_are_watched_not_ip_literals(monkeypatch, mock_dns):
    monkeypatch.setenv("APP_TOR_SERVICE_HOSTS", "80:backend:8080,81:10.0.0.5:81")
    resolved = {}
    e.build_torrc_string(resolved=resolved)
    assert resolved == {"backend": "192.0.2.1"}


def test_nothing_to_watch_starts_no_thread():
    w = e._BackendWatch({})
    assert w.start() is w and w.moved is None



# ── A backend that did not resolve at boot ──────────────────────────────────
# After a host reboot the runtime starts containers in no particular order, so
# the backend's name may not exist yet. Measured before this was handled: the
# service was dropped, Tor ran with no onion service, and it stayed that way.

def test_an_unresolvable_backend_is_recorded_as_pending_not_just_dropped(
        monkeypatch, mock_dns):
    monkeypatch.setenv("APP_TOR_SERVICE_HOSTS", "80:web:80")
    monkeypatch.setenv("OTHER_TOR_SERVICE_HOSTS", "80:backend:8080")
    resolved, pending, dropped = {}, set(), []
    torrc, dirs = e.build_torrc_string(dropped=dropped, resolved=resolved,
                                       unresolved=pending)
    assert pending == {"web"}
    assert resolved == {"backend": "192.0.2.1"}
    assert [d.rsplit("/", 1)[1] for d in dirs] == ["other"]
    assert "hidden_service/app" not in torrc
    assert "added automatically once the name resolves" in dropped[0]


def test_an_invalid_address_is_a_typo_not_a_pending_backend(monkeypatch, mock_dns):
    """Only a failed lookup can change by itself; a malformed IP never will."""
    monkeypatch.setenv("APP_TOR_SERVICE_HOSTS", "80:999.1.1.1:80")
    pending = set()
    e.build_torrc_string(unresolved=pending)
    assert pending == set()


def test_a_pending_backend_that_resolves_triggers_the_restart():
    w = e._BackendWatch({}, pending={"web"}, resolver=_resolver(["172.20.0.4"]))
    assert w.check_once() is None, "one observation is not confirmation"
    assert w.check_once() == ("web", None, ["172.20.0.4"])


def test_a_pending_backend_still_missing_never_restarts():
    w = e._BackendWatch({}, pending={"web"},
                        resolver=_resolver(socket.gaierror(-3, "Try again")))
    assert all(w.check_once() is None for _ in range(10))


def test_a_pending_backend_flapping_needs_consecutive_answers():
    w = e._BackendWatch({}, pending={"web"},
                        resolver=_resolver(["172.20.0.4"], socket.gaierror(-3, "x"),
                                           ["172.20.0.4"], ["172.20.0.4"]))
    assert w.check_once() is None
    assert w.check_once() is None
    assert w.check_once() is None
    assert w.check_once() == ("web", None, ["172.20.0.4"])


def test_a_pending_backend_alone_starts_the_watch(monkeypatch):
    started = []
    monkeypatch.setattr(e.threading, "Thread",
                        lambda **kw: type("T", (), {"start": lambda s: started.append(kw)})())
    e._BackendWatch({}, pending={"web"}).start()
    assert [kw["name"] for kw in started] == ["backend-watch"]
