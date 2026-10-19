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

# Make the shared test helper (tests/directives.py) importable.
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)

# test_torrc.py is the IN-CONTAINER smoke test: it does real filesystem work at
# import time (writes /etc/tor/torrc, needs the 'tor' user) and is run directly
# via python3 inside the container by CI — never collected in the host run.
collect_ignore = ["test_torrc.py"]


@pytest.fixture(autouse=True)
def disposable_cwd(tmp_path_factory, monkeypatch):
    """Run every test from a throwaway directory, so nothing can touch the tree.

    Not hygiene for its own sake. Several functions under test open a file
    relative to a directory DESCRIPTOR (`os.open(name, dir_fd=fd)`,
    `os.listdir(fd)`) precisely so a path cannot be re-resolved mid-operation.
    Python's API for that falls back to the CURRENT WORKING DIRECTORY when the
    descriptor is absent, so a mutation that drops it does not fail -- it walks
    the working directory instead and applies the operation there.

    That is not hypothetical. `vanity._harden` with `dir_fd = None` chmods every
    entry of the working directory to 0600, and under mutmut that directory is
    the generated `mutants/` tree: it made `mutants/tests` unreadable, and the
    265 tests that ran afterwards failed at conftest load, scoring as kills. A
    whole run was thrown away twice before the cause was found.

    Mutation testing deliberately produces destructive code. Where the working
    directory is the blast radius, the containment belongs here, once, rather
    than in each test that happens to reach such a function.
    """
    # A sibling of tmp_path, not a child of it: several tests use tmp_path AS the
    # key volume and enumerate its entries, and a scratch directory inside it
    # would read as an extra hidden service.
    monkeypatch.chdir(tmp_path_factory.mktemp("cwd"))


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


@pytest.fixture
def supervisor(monkeypatch, tmp_path):
    """Run entrypoint.main() headless; see tests/supervisor_harness.py."""
    from supervisor_harness import make_supervisor
    return make_supervisor(monkeypatch, tmp_path)
