"""Shared pytest fixtures for HiddenForge host unit tests.

These tests import entrypoint.py directly and run on the host (no container).
entrypoint.py executes nothing at import time (main() is guarded), so importing
it is side-effect free.
"""
import os
import sys

import pytest

# Make entrypoint.py importable regardless of where pytest is invoked from.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# test_torrc.py is the IN-CONTAINER smoke test: it does real filesystem work at
# import time (writes /etc/tor/torrc, needs the 'tor' user) and is run directly
# via python3 inside the container by CI — never collected in the host run.
collect_ignore = ["test_torrc.py"]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Remove every var generate_basic_torrc reads, so tests can't pollute each other.

    generate_basic_torrc()/build_torrc_string() iterate os.environ looking for
    *_TOR_SERVICE_HOSTS and read TOR_SANDBOX. A stray var from the developer's
    shell (or a previous test) would otherwise leak into the generated config.
    """
    for key in list(os.environ):
        if key.endswith("_TOR_SERVICE_HOSTS") or key == "TOR_SANDBOX":
            monkeypatch.delenv(key, raising=False)
    yield


@pytest.fixture
def mock_dns(monkeypatch):
    """Deterministic DNS: 'backend' -> TEST-NET (RFC 5737); everything else NXDOMAIN.

    Mirrors the address used by the existing in-container test so golden files
    line up. Records whether resolution was attempted so tests can assert that
    a literal IP target does NOT trigger a lookup.
    """
    import socket

    calls = []

    def fake_gethostbyname(host):
        calls.append(host)
        if host == "backend":
            return "192.0.2.1"
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)
    return calls
