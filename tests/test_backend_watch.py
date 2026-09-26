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

