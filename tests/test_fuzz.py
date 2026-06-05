"""Property-based (fuzz) tests for the validators and torrc assembly.

Curated negative tests prove the cases we thought of. These properties assert
invariants over a large space of random/adversarial inputs to catch the cases
we did NOT think of. The headline property: NO env-var value can make
build_torrc_string emit a line outside the known-directive whitelist.
"""
import os
import re

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import entrypoint as e

# Mirrors tests/test_torrc_gen.ALLOWED_DIRECTIVES (kept local to avoid a
# cross-test-module import). If a directive is added to the generator, both
# lists must be updated — the golden tests will fail loudly if they drift.
ALLOWED_DIRECTIVES = {
    "ControlSocket", "SocksPort", "DataDirectory", "ClientOnly", "ExitPolicy",
    "Log", "SafeLogging", "HeartbeatPeriod", "Sandbox",
    "DisableDebuggerAttachment", "AvoidDiskWrites", "FetchUselessDescriptors",
    "HiddenServiceDir", "HiddenServiceVersion", "HiddenServiceNumIntroductionPoints",
    "HiddenServiceMaxStreams", "HiddenServiceMaxStreamsCloseCircuit",
    "HiddenServicePoWDefensesEnabled", "HiddenServicePoWQueueRate",
    "HiddenServicePoWQueueBurst", "HiddenServicePort",
    "HiddenServiceEnableIntroDoSDefense", "HiddenServiceEnableIntroDoSRatePerSec",
    "HiddenServiceEnableIntroDoSBurstPerSec",
}

# Text excluding NUL: the OS forbids NUL in env var values, so it can never
# reach this code via the environment. Everything else (newlines, CR, control
# chars, unicode, colons, commas) is fair game.
_no_nul = st.text(
    alphabet=st.characters(blacklist_characters="\x00"), max_size=200
)


def _set_only(value):
    for k in list(os.environ):
        if k.endswith("_TOR_SERVICE_HOSTS") or k == "TOR_SANDBOX":
            del os.environ[k]
    os.environ["SERVICE_TOR_SERVICE_HOSTS"] = value


# ─────────────────────────────────────────────────────────────────────────────
# THE invariant: no injection, ever, for any value
# ─────────────────────────────────────────────────────────────────────────────

@settings(max_examples=1000, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(_no_nul)
def test_fuzz_no_injection_from_any_value(mock_dns, value):
    _set_only(value)
    try:
        torrc, _ = e.build_torrc_string()
    finally:
        os.environ.pop("SERVICE_TOR_SERVICE_HOSTS", None)
    for line in torrc.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        token = stripped.split()[0]
        assert token in ALLOWED_DIRECTIVES, f"injected line from {value!r}: {stripped!r}"


# ─────────────────────────────────────────────────────────────────────────────
# Validator output invariants (input → either a well-formed result or ValueError)
# ─────────────────────────────────────────────────────────────────────────────

@settings(max_examples=1000)
@given(_no_nul)
def test_fuzz_validate_port_invariant(s):
    try:
        result = e.validate_port(s, "label")
    except ValueError:
        return
    assert result.isdigit()
    assert 1 <= int(result) <= 65535


@settings(max_examples=1000)
@given(_no_nul)
def test_fuzz_validate_service_name_invariant(s):
    try:
        result = e.validate_service_name(s)
    except ValueError:
        return
    assert re.fullmatch(r"[a-z0-9][a-z0-9\-]*", result)
    assert len(result) <= 63
    # A returned name can never contain a path separator or whitespace.
    assert "/" not in result and not any(c.isspace() for c in result)


@settings(max_examples=1000)
@given(_no_nul)
def test_fuzz_validate_hostname_invariant(s):
    try:
        result = e.validate_hostname(s, "label")
    except ValueError:
        return
    assert re.fullmatch(r"[a-zA-Z0-9._\-]{1,253}", result)
    assert not any(c.isspace() for c in result)


@settings(max_examples=1000)
@given(_no_nul)
def test_fuzz_resolve_to_ip_invariant(mock_dns, s):
    # mock_dns raises for anything but 'backend', so no real network is touched.
    try:
        result = e.resolve_to_ip(s, "label")
    except ValueError:
        return
    # Any returned value must be a parseable IPv4 with no whitespace/newline.
    import ipaddress
    ipaddress.IPv4Address(result)  # raises if malformed → test failure
    assert not any(c.isspace() for c in result)
