"""generate_basic_torrc must hand the module's live backend registries to the
builder.

The supervisor starts a _BackendWatch over the module-level `_backend_ips`
(name -> IP written into the torrc) and `_backend_pending` (names that did not
resolve at start). Those two objects are populated *by* build_torrc_string,
through the `resolved`/`unresolved` arguments generate_basic_torrc passes in.
If either argument is omitted -- or a fresh object is passed -- the watch starts
empty and a backend that is recreated on a new IP, or that was down at start
and comes up later, is never noticed: the onion forwards to an address nobody
listens on while the healthcheck stays green.
"""
import os
from collections import namedtuple

import pytest

import entrypoint as e

TorPw = namedtuple("TorPw", "pw_uid pw_gid")


@pytest.fixture
def container(tmp_path, monkeypatch):
    keys = tmp_path / "hidden_service"
    torrc = tmp_path / "etc" / "torrc"
    torrc.parent.mkdir(parents=True)
    monkeypatch.setattr(e, "KEYS_ROOT", str(keys))
    monkeypatch.setattr(e, "TORRC_PATH", str(torrc))
    monkeypatch.setattr(e.pwd, "getpwnam",
                        lambda name: TorPw(os.getuid(), os.getgid()))
    monkeypatch.setattr(e, "_backend_ips", {})
    monkeypatch.setattr(e, "_backend_pending", set())
    return namedtuple("Container", "keys torrc")(keys, torrc)


def _dns(monkeypatch, answers):
    import socket

    def fake_gethostbyname(host):
        if host in answers:
            return answers[host]
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)


def test_a_backend_given_by_name_is_recorded_for_the_supervisor(
        container, monkeypatch):
    """`resolved=_backend_ips`. Empty, the recheck watch has nothing to compare
    against and a recreated backend is never followed."""
    _dns(monkeypatch, {"backend": "192.0.2.1"})
    monkeypatch.setenv("APP_TOR_SERVICE_HOSTS", "80:backend:8080")
    e.generate_basic_torrc()
    assert e._backend_ips == {"backend": "192.0.2.1"}
    assert "HiddenServicePort 80 192.0.2.1:8080" in container.torrc.read_text()


def test_a_backend_that_did_not_resolve_is_remembered_as_pending(
        container, monkeypatch):
    """`unresolved=_backend_pending`. Empty, the service dropped at start is
    never configured once its backend finally comes up."""
    _dns(monkeypatch, {})
    monkeypatch.setenv("APP_TOR_SERVICE_HOSTS", "80:backend:8080")
    hs_dirs, dropped = e.generate_basic_torrc()
    assert e._backend_pending == {"backend"}
    assert hs_dirs == []
    assert any("Cannot resolve" in reason for reason in dropped)
