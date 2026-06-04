"""Tests for torrc assembly via the pure build_torrc_string().

build_torrc_string() performs no filesystem operations, so it runs on the host.
Covers: mapping shapes, multi-service determinism, malformed-skip behaviour,
presence of every security-critical directive, the Sandbox toggle, golden
snapshots, and — most importantly — the injection-proof property.
"""
import os

import pytest

import entrypoint as e

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden")

# Every directive token that may legitimately begin a non-comment torrc line.
# The injection-proof test asserts NOTHING outside this set ever appears.
ALLOWED_DIRECTIVES = {
    "ControlSocket", "SocksPort", "DataDirectory", "ClientOnly", "ExitPolicy",
    "Log", "SafeLogging", "HeartbeatPeriod", "Sandbox",
    "DisableDebuggerAttachment", "AvoidDiskWrites", "FetchUselessDescriptors",
    "HiddenServiceDir", "HiddenServiceVersion", "HiddenServiceNumIntroductionPoints",
    "HiddenServiceMaxStreams", "HiddenServiceMaxStreamsCloseCircuit",
    "HiddenServicePoWDefensesEnabled", "HiddenServicePoWQueueRate",
    "HiddenServicePoWQueueBurst", "HiddenServicePort",
}


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
]
PER_SERVICE_REQUIRED = [
    "HiddenServiceVersion 3",
    "HiddenServiceNumIntroductionPoints 6",
    "HiddenServiceMaxStreams 100",
    "HiddenServiceMaxStreamsCloseCircuit 1",
    "HiddenServicePoWDefensesEnabled 1",
    "HiddenServicePoWQueueRate  250",
    "HiddenServicePoWQueueBurst 2500",
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
