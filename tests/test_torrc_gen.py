"""Tests for torrc assembly via the pure build_torrc_string().

build_torrc_string() performs no filesystem operations, so it runs on the host.
Covers: mapping shapes, multi-service determinism, malformed-skip behaviour,
presence of every security-critical directive, the Sandbox toggle, golden
snapshots, and — most importantly — the injection-proof property.
"""
import os

import pytest

import entrypoint as e
from directives import ALLOWED_DIRECTIVES

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden")



def _set_services(monkeypatch, **services):
    for name, value in services.items():
        monkeypatch.setenv(name, value)


def directive_lines(torrc):
    """Non-comment, non-blank lines as (first_token, full_line)."""
    out = []
    for line in torrc.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        out.append((stripped.split()[0], stripped))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Mapping shapes
# ─────────────────────────────────────────────────────────────────────────────

def test_threepart_ip_mapping(monkeypatch):
    _set_services(monkeypatch, SERVICE_TOR_SERVICE_HOSTS="80:127.0.0.1:8080")
    torrc, dirs = e.build_torrc_string()
    assert "HiddenServicePort 80 127.0.0.1:8080" in torrc
    assert dirs == ["/var/lib/tor/hidden_service/service"]


def test_twopart_mapping_defaults_to_localhost(monkeypatch):
    _set_services(monkeypatch, SERVICE_TOR_SERVICE_HOSTS="80:8080")
    torrc, _ = e.build_torrc_string()
    assert "HiddenServicePort 80 127.0.0.1:8080" in torrc


def test_threepart_hostname_resolves(monkeypatch, mock_dns):
    _set_services(monkeypatch, SERVICE_TOR_SERVICE_HOSTS="80:backend:8080")
    torrc, _ = e.build_torrc_string()
    assert "HiddenServicePort 80 192.0.2.1:8080" in torrc
    assert mock_dns == ["backend"]


def test_multiple_ports_preserve_input_order(monkeypatch):
    _set_services(monkeypatch, SERVICE_TOR_SERVICE_HOSTS="443:127.0.0.1:8443,80:127.0.0.1:8080")
    torrc, _ = e.build_torrc_string()
    i443 = torrc.index("HiddenServicePort 443")
    i80 = torrc.index("HiddenServicePort 80")
    assert i443 < i80  # emitted in the order given, not sorted


# ─────────────────────────────────────────────────────────────────────────────
# Multi-service determinism
# ─────────────────────────────────────────────────────────────────────────────

def test_multiple_services_sorted_deterministically(monkeypatch):
    # Insert in non-alphabetical order; output must be alphabetical (sorted env).
    _set_services(
        monkeypatch,
        WEB_TOR_SERVICE_HOSTS="80:127.0.0.1:8080",
        APP_TOR_SERVICE_HOSTS="9000:127.0.0.1:9000",
    )
    torrc, dirs = e.build_torrc_string()
    assert torrc.index("Service: app") < torrc.index("Service: web")
    assert dirs == [
        "/var/lib/tor/hidden_service/app",
        "/var/lib/tor/hidden_service/web",
    ]


def test_underscore_in_env_name_becomes_hyphen(monkeypatch):
    _set_services(monkeypatch, MY_APP_TOR_SERVICE_HOSTS="80:127.0.0.1:8080")
    torrc, dirs = e.build_torrc_string()
    assert "/var/lib/tor/hidden_service/my-app" in dirs
    assert "Service: my-app" in torrc


# ─────────────────────────────────────────────────────────────────────────────
# Malformed mappings are skipped, never fatal, never injected
# ─────────────────────────────────────────────────────────────────────────────

def test_malformed_mappings_skipped_valid_kept(monkeypatch):
    _set_services(
        monkeypatch,
        SERVICE_TOR_SERVICE_HOSTS="80:127.0.0.1:8080,8080,99:1.2.3.4:5:6,443:127.0.0.1:8443",
    )
    torrc, _ = e.build_torrc_string()
    assert "HiddenServicePort 80 127.0.0.1:8080" in torrc    # valid kept
    assert "HiddenServicePort 443 127.0.0.1:8443" in torrc   # valid after malformed kept
    assert "HiddenServicePort 99" not in torrc               # 4-part skipped


def test_invalid_service_name_skips_whole_service(monkeypatch):
    # An env key whose derived name fails validation must be skipped entirely.
    monkeypatch.setenv("_TOR_SERVICE_HOSTS", "80:127.0.0.1:8080")  # empty name
    torrc, dirs = e.build_torrc_string()
    assert dirs == []
    assert "HiddenServiceDir" not in torrc


# ─────────────────────────────────────────────────────────────────────────────
# Security-critical directives always present
# ─────────────────────────────────────────────────────────────────────────────

GLOBAL_REQUIRED = [
    "ControlSocket /var/lib/tor/control.sock",
    "SocksPort 0",
    "ClientOnly 1",
    "ExitPolicy reject *:*",
    "SafeLogging 1",
    "DisableDebuggerAttachment 1",
    "AvoidDiskWrites 1",
    "FetchUselessDescriptors 0",
    "VanguardsLiteEnabled 1",
]
PER_SERVICE_REQUIRED = [
    "HiddenServiceVersion 3",
    "HiddenServiceNumIntroductionPoints 6",
    "HiddenServiceMaxStreams 100",
    "HiddenServiceMaxStreamsCloseCircuit 1",
    "HiddenServicePoWDefensesEnabled 1",
    "HiddenServicePoWQueueRate  250",
    "HiddenServicePoWQueueBurst 2500",
    "HiddenServiceEnableIntroDoSDefense 1",
    "HiddenServiceEnableIntroDoSRatePerSec 25",
    "HiddenServiceEnableIntroDoSBurstPerSec 200",
]


@pytest.mark.parametrize("directive", GLOBAL_REQUIRED)
def test_global_hardening_directive_present(monkeypatch, directive):
    _set_services(monkeypatch, SERVICE_TOR_SERVICE_HOSTS="80:127.0.0.1:8080")
    torrc, _ = e.build_torrc_string()
    assert directive in torrc


@pytest.mark.parametrize("directive", PER_SERVICE_REQUIRED)
def test_per_service_hardening_directive_present(monkeypatch, directive):
    _set_services(monkeypatch, SERVICE_TOR_SERVICE_HOSTS="80:127.0.0.1:8080")
    torrc, _ = e.build_torrc_string()
    assert directive in torrc


def test_global_directives_present_even_with_no_services(monkeypatch):
    torrc, dirs = e.build_torrc_string()
    assert dirs == []
    for directive in GLOBAL_REQUIRED:
        assert directive in torrc


# ─────────────────────────────────────────────────────────────────────────────
# One bad service must not take down the whole container
# ─────────────────────────────────────────────────────────────────────────────

def test_service_with_no_valid_ports_is_dropped_entirely(monkeypatch):
    """A HiddenServiceDir with no HiddenServicePort makes Tor refuse to start.

    Observed live: `Hidden service (...) with no ports configured` ->
    `Failed to parse/validate config` -> `Reading config failed`. Tor aborts
    completely, so a portless block does not degrade one service, it kills the
    entire container. Such a service must be omitted, not emitted empty.
    """
    _set_services(monkeypatch, BAD_TOR_SERVICE_HOSTS="99999:127.0.0.1:8080")
    torrc, dirs = e.build_torrc_string()
    assert "/var/lib/tor/hidden_service/bad" not in torrc
    assert "HiddenServiceDir" not in torrc
    assert dirs == [], "a key directory must not be created for a dropped service"


def test_one_bad_service_does_not_kill_a_good_one(monkeypatch):
    """The good service must survive a sibling with entirely invalid mappings."""
    _set_services(
        monkeypatch,
        GOOD_TOR_SERVICE_HOSTS="80:127.0.0.1:8080",
        BAD_TOR_SERVICE_HOSTS="-1:127.0.0.1:-5",
    )
    torrc, dirs = e.build_torrc_string()
    assert dirs == ["/var/lib/tor/hidden_service/good"]
    assert "HiddenServicePort 80 127.0.0.1:8080" in torrc
    assert "hidden_service/bad" not in torrc
    # Exactly one service block, and it has a port.
    assert torrc.count("HiddenServiceDir") == 1


def test_partially_valid_service_keeps_its_good_ports(monkeypatch):
    """Dropping portless services must not also drop merely-partial ones."""
    _set_services(
        monkeypatch,
        SERVICE_TOR_SERVICE_HOSTS="99999:127.0.0.1:8080,443:127.0.0.1:8443",
    )
    torrc, dirs = e.build_torrc_string()
    assert dirs == ["/var/lib/tor/hidden_service/service"]
    assert "HiddenServicePort 443 127.0.0.1:8443" in torrc
    assert "99999" not in torrc


# ─────────────────────────────────────────────────────────────────────────────
# Guard-discovery protection must not be delegated to the consensus
# ─────────────────────────────────────────────────────────────────────────────

def test_vanguards_lite_is_pinned_not_auto(monkeypatch):
    """VanguardsLiteEnabled must be hard-set to 1, never left at "auto".

    The full Vanguards addon's layer-2/3 pinning is unavailable to us (Sandbox 1
    rejects the SETCONF it needs), so vanguards-lite is our ONLY defence against
    guard-discovery attacks. Per the Tor manual, "auto" delegates the decision to
    the `vanguards-lite-enabled` consensus parameter — i.e. to the directory
    authorities. An adversary with influence over the consensus could then
    disable guard-discovery protection for every deployment at once, silently.
    Pinning it locally removes that lever.
    """
    _set_services(monkeypatch, SERVICE_TOR_SERVICE_HOSTS="80:127.0.0.1:8080")
    torrc, _ = e.build_torrc_string()
    assert "VanguardsLiteEnabled 1" in torrc
    assert "VanguardsLiteEnabled auto" not in torrc
    assert "VanguardsLiteEnabled 0" not in torrc


def test_vanguards_lite_pinned_even_with_sandbox_disabled(monkeypatch):
    """Turning off Tor's seccomp sandbox must not silently drop the guard pin."""
    _set_services(monkeypatch, SERVICE_TOR_SERVICE_HOSTS="80:127.0.0.1:8080")
    monkeypatch.setenv("TOR_SANDBOX", "0")
    torrc, _ = e.build_torrc_string()
    assert "VanguardsLiteEnabled 1" in torrc


# ─────────────────────────────────────────────────────────────────────────────
# Sandbox toggle
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "value,expected",
    [(None, "Sandbox 1"), ("1", "Sandbox 1"), ("anything", "Sandbox 1"), ("0", "Sandbox 0")],
)
def test_sandbox_toggle(monkeypatch, value, expected):
    _set_services(monkeypatch, SERVICE_TOR_SERVICE_HOSTS="80:127.0.0.1:8080")
    if value is not None:
        monkeypatch.setenv("TOR_SANDBOX", value)
    torrc, _ = e.build_torrc_string()
    assert expected in torrc
    other = "Sandbox 0" if expected == "Sandbox 1" else "Sandbox 1"
    assert other not in torrc


# ─────────────────────────────────────────────────────────────────────────────
# THE injection-proof property
# ─────────────────────────────────────────────────────────────────────────────

INJECTION_PAYLOADS = [
    "80:127.0.0.1:8080\nORPort 9001",
    "80:127.0.0.1:8080\r\nDirPort 9030",
    "80:127.0.0.1:8080\nControlPort 0.0.0.0:9051",
    "80\nExitPolicy accept *:*:8080",
    "80:127.0.0.1\n:8080",
    "80:evil\nORPort 9001:8080",
    "\nORPort 9001",
    # NB: NUL bytes cannot reach this code path — the OS rejects them in env
    # var values (verified). The NUL case is tested at the validator level.
    "80:127.0.0.1:8080\n\n__OwningControllerProcess 1",
]


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_no_injection_via_service_hosts_value(monkeypatch, payload):
    _set_services(monkeypatch, SERVICE_TOR_SERVICE_HOSTS=payload)
    torrc, _ = e.build_torrc_string()
    for token, line in directive_lines(torrc):
        assert token in ALLOWED_DIRECTIVES, f"INJECTED line: {line!r}"
    # explicit belt-and-suspenders: none of these dangerous directives appear
    for forbidden in ("ORPort", "DirPort", "ControlPort", "__OwningControllerProcess"):
        assert forbidden not in torrc
    assert "accept *:*" not in torrc


@pytest.mark.parametrize(
    "evil_name",
    ["WEB\nORPORT 9001_TOR_SERVICE_HOSTS", "../../X_TOR_SERVICE_HOSTS"],
)
def test_no_injection_via_env_var_name(monkeypatch, evil_name):
    # Even a crafted env var NAME cannot inject: the derived service name is
    # validated and a failing service is skipped wholesale.
    monkeypatch.setenv(evil_name, "80:127.0.0.1:8080")
    torrc, dirs = e.build_torrc_string()
    for token, line in directive_lines(torrc):
        assert token in ALLOWED_DIRECTIVES, f"INJECTED line: {line!r}"
    assert "ORPORT" not in torrc.upper().replace("ORPORT 9001", "X") or "ORPort" not in torrc


# ─────────────────────────────────────────────────────────────────────────────
# Golden snapshots — lock the deterministic byte output
# ─────────────────────────────────────────────────────────────────────────────

GOLDEN_SCENARIOS = {
    "single_ip": {"SERVICE_TOR_SERVICE_HOSTS": "80:127.0.0.1:8080"},
    "multi_port_ip": {"SERVICE_TOR_SERVICE_HOSTS": "80:127.0.0.1:8080,443:127.0.0.1:8443"},
    "twopart": {"SERVICE_TOR_SERVICE_HOSTS": "80:8080"},
    "dns_service": {"SERVICE_TOR_SERVICE_HOSTS": "80:backend:8080,443:backend:8443"},
    "two_services": {
        "WEB_TOR_SERVICE_HOSTS": "80:127.0.0.1:8080",
        "APP_TOR_SERVICE_HOSTS": "9000:127.0.0.1:9000",
    },
    "sandbox_off": {"SERVICE_TOR_SERVICE_HOSTS": "80:127.0.0.1:8080", "TOR_SANDBOX": "0"},
    "no_services": {},
    "malformed_mix": {
        "SERVICE_TOR_SERVICE_HOSTS": "80:127.0.0.1:8080,8080,99:1.2.3.4:5:6,443:127.0.0.1:8443"
    },
}


@pytest.mark.parametrize("name", sorted(GOLDEN_SCENARIOS))
def test_matches_golden(monkeypatch, mock_dns, name):
    for key, value in GOLDEN_SCENARIOS[name].items():
        monkeypatch.setenv(key, value)
    torrc, _ = e.build_torrc_string()
    with open(os.path.join(GOLDEN_DIR, f"{name}.torrc"), encoding="utf-8") as fh:
        expected = fh.read()
    assert torrc == expected, f"golden drift in {name}.torrc"


# ─────────────────────────────────────────────────────────────────────────────
# Resolver OUTPUT is untrusted too, not just user input
# ─────────────────────────────────────────────────────────────────────────────

# Answers that are merely dirty but recover to a valid address: safe to use.
RECOVERABLE_RESOLVER_ANSWERS = ["10.0.0.5\n", " 10.0.0.5 ", "10.0.0.5\r\n"]

# Answers that cannot be a canonical IPv4 address: the mapping must be dropped.
REJECTED_RESOLVER_ANSWERS = [
    "10.0.0.5\nORPort 9001",       # embedded newline + directive
    "10.0.0.5\r\nDirPort 9030",    # CRLF variant
    "not-an-ip",
    "::1",                          # IPv6 where IPv4 is required
    "999.999.999.999",              # dotted-quad shaped but invalid
    "",
]


def _resolver(monkeypatch, answer):
    import socket
    monkeypatch.setattr(socket, "gethostbyname", lambda h: answer)
    _set_services(monkeypatch, SERVICE_TOR_SERVICE_HOSTS="80:backend:8080")
    return e.build_torrc_string()


@pytest.mark.parametrize("answer", REJECTED_RESOLVER_ANSWERS + RECOVERABLE_RESOLVER_ANSWERS)
def test_hostile_resolver_output_never_injects(monkeypatch, answer):
    """The resolver's answer is the one torrc input this module does not build itself.

    CPython constructs that string with inet_ntop from a 4-byte struct, so a
    hostile DNS server cannot actually smuggle a newline through it. The
    invariant is enforced anyway so a future change of resolver cannot silently
    reintroduce the gap: whatever comes back, nothing outside the allowed
    directive set may appear in the generated config.
    """
    torrc, _ = _resolver(monkeypatch, answer)
    for token, line in directive_lines(torrc):
        assert token in ALLOWED_DIRECTIVES, f"INJECTED line: {line!r}"
    for forbidden in ("ORPort", "DirPort", "ControlPort"):
        assert forbidden not in torrc


@pytest.mark.parametrize("answer", REJECTED_RESOLVER_ANSWERS)
def test_unusable_resolver_output_drops_the_mapping(monkeypatch, answer):
    """An answer that is not a canonical IPv4 address must not reach the torrc."""
    torrc, _ = _resolver(monkeypatch, answer)
    assert "HiddenServicePort" not in torrc


@pytest.mark.parametrize("answer", RECOVERABLE_RESOLVER_ANSWERS)
def test_whitespace_padded_resolver_output_is_normalised(monkeypatch, answer):
    """Surrounding whitespace is stripped, not rejected — and never reaches the file."""
    torrc, _ = _resolver(monkeypatch, answer)
    assert "HiddenServicePort 80 10.0.0.5:8080" in torrc


def test_valid_resolver_output_is_still_used(monkeypatch):
    """Guard against 'fixing' the above by rejecting every resolver answer."""
    torrc, _ = _resolver(monkeypatch, "10.1.2.3")
    assert "HiddenServicePort 80 10.1.2.3:8080" in torrc


# ─────────────────────────────────────────────────────────────────────────────
# Two env vars must never collapse into the same service directory
# ─────────────────────────────────────────────────────────────────────────────

COLLIDING_PAIRS = [
    ("MYAPP_TOR_SERVICE_HOSTS", "myapp_TOR_SERVICE_HOSTS"),   # differ only in case
    ("MY_APP_TOR_SERVICE_HOSTS", "my-app_TOR_SERVICE_HOSTS"), # underscore vs hyphen
    ("WEB_TOR_SERVICE_HOSTS", "web_TOR_SERVICE_HOSTS"),
]


@pytest.mark.parametrize("first,second", COLLIDING_PAIRS)
def test_colliding_service_names_emit_one_block(monkeypatch, first, second):
    """Names are lowercased and underscores hyphenated, so distinct env vars can
    collapse to one directory. Env var names are case-sensitive, so both can be
    set at once.

    Emitting the block twice does not merge the services: Tor rejects the entire
    config ("Another hidden service is already configured for directory ...") and
    refuses to start, killing every other onion in the container. Verified live
    against 2.0.4. Exactly one block must be emitted.
    """
    _set_services(monkeypatch, **{first: "80:127.0.0.1:8080",
                                  second: "9000:127.0.0.1:9000"})
    torrc, dirs = e.build_torrc_string()
    assert torrc.count("HiddenServiceDir") == 1, "duplicate HiddenServiceDir emitted"
    assert len(dirs) == len(set(dirs)) == 1, f"duplicate service dirs: {dirs}"


def test_collision_keeps_the_first_and_drops_the_second(monkeypatch):
    """Deterministic: env vars are iterated sorted, so the first wins."""
    _set_services(monkeypatch,
                  MYAPP_TOR_SERVICE_HOSTS="80:127.0.0.1:8080",
                  myapp_TOR_SERVICE_HOSTS="9000:127.0.0.1:9000")
    torrc, _ = e.build_torrc_string()
    assert "HiddenServicePort 80 127.0.0.1:8080" in torrc
    assert "HiddenServicePort 9000" not in torrc


def test_distinct_names_are_unaffected(monkeypatch):
    """Guard against 'fixing' collisions by dropping legitimate second services."""
    _set_services(monkeypatch,
                  WEB_TOR_SERVICE_HOSTS="80:127.0.0.1:8080",
                  API_TOR_SERVICE_HOSTS="9000:127.0.0.1:9000")
    torrc, dirs = e.build_torrc_string()
    assert torrc.count("HiddenServiceDir") == 2
    assert sorted(dirs) == ["/var/lib/tor/hidden_service/api",
                            "/var/lib/tor/hidden_service/web"]
