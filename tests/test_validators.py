"""Negative + positive unit tests for HiddenForge's input validators.

THE security property under test: no value reachable from an environment
variable may inject an arbitrary directive into the generated torrc. Every
rejection case below exists to falsify "the validators are sufficient."

The validators are pure functions; these tests need no container.
"""
import pytest

import entrypoint as e


# ─────────────────────────────────────────────────────────────────────────────
# validate_service_name
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("good", ["web", "web-app", "a", "app1", "x-y-z", "web-"])
def test_service_name_accepts_valid(good):
    assert e.validate_service_name(good) == good


@pytest.mark.parametrize(
    "bad",
    [
        "web\nORPort 9001",        # LF torrc injection
        "web\r\nORPort 9001",      # CRLF torrc injection
        "web\x00relay",            # NUL truncation
        "../../etc/tor",           # path traversal (name is used in a dir path)
        "web/../../",              # embedded traversal
        "-web",                    # leading hyphen (regex requires [a-z0-9] first)
        "WEB",                     # uppercase
        "Web",                     # mixed case
        "web service",             # space
        "wéb",                     # non-ASCII
        "ｗｅｂ",                   # fullwidth homoglyph (intentional)  # noqa: RUF001
        "",                        # empty
        "web.app",                 # dot not allowed
        "web_app",                 # underscore not allowed (transform happens earlier)
    ],
)
def test_service_name_rejects_bad(bad):
    with pytest.raises(ValueError):
        e.validate_service_name(bad)


@pytest.mark.parametrize(
    "surrogate_input",
    ["web\ud800", "\udfffsvc", "ab\ud834cd"],
)
def test_validators_reject_surrogates(surrogate_input):
    """Surrogate code points can reach a real env via surrogateescape decoding
    of non-UTF8 bytes; all validators must reject them, not crash."""
    with pytest.raises(ValueError):
        e.validate_service_name(surrogate_input)
    with pytest.raises(ValueError):
        e.validate_hostname(surrogate_input, "label")
    with pytest.raises(ValueError):
        e.validate_port(surrogate_input, "label")


@pytest.mark.parametrize("good_len", [1, 2, 63])
def test_service_name_length_boundary_accepted(good_len):
    name = "a" * good_len
    assert e.validate_service_name(name) == name


@pytest.mark.parametrize("bad_len", [64, 100, 300])
def test_service_name_overlong_rejected(bad_len):
    """F19 fixed: names longer than 63 chars are rejected (was previously accepted)."""
    with pytest.raises(ValueError):
        e.validate_service_name("a" * bad_len)


# ─────────────────────────────────────────────────────────────────────────────
# validate_port
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "value,expected",
    [("1", "1"), ("80", "80"), ("65535", "65535"), (" 80 ", "80"), ("08080", "8080")],
)
def test_port_accepts_valid(value, expected):
    assert e.validate_port(value, "label") == expected


@pytest.mark.parametrize(
    "bad",
    [
        "0",                    # below range
        "65536",                # above range (5 digits → passes regex, caught by range)
        "99999",                # above range
        "123456",               # 6 digits → regex reject
        "8080\nORPort 9001",    # injection
        "8 0",                  # interior space
        "0x50",                 # hex
        "80.0",                 # float
        "-1",                   # signed
        "+80",                  # signed
        "",                     # empty
        "   ",                  # all whitespace
        "abc",                  # non-numeric
    ],
)
def test_port_rejects_bad(bad):
    with pytest.raises(ValueError):
        e.validate_port(bad, "label")


# ─────────────────────────────────────────────────────────────────────────────
# validate_hostname
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "good",
    ["backend", "my-app.local", "127.0.0.1", "host.example.com", "a" * 253, "-host"],
)
def test_hostname_accepts_valid(good):
    assert e.validate_hostname(good, "label") == good


@pytest.mark.parametrize(
    "bad",
    [
        "backend\nHiddenServicePort 22 0.0.0.0:22",  # injection
        "back end",                                   # space
        "host;rm -rf",                                # shell metachars
        "::1",                                        # IPv6 (unsupported by design)
        "fe80::1",                                    # IPv6
        "a" * 254,                                    # over 253
        "",                                           # empty
        "host\x00",                                   # NUL
    ],
)
def test_hostname_rejects_bad(bad):
    with pytest.raises(ValueError):
        e.validate_hostname(bad, "label")


# ─────────────────────────────────────────────────────────────────────────────
# resolve_to_ip  (monkeypatched DNS via mock_dns fixture)
# ─────────────────────────────────────────────────────────────────────────────

def test_resolve_literal_ip_does_not_hit_dns(mock_dns):
    assert e.resolve_to_ip("192.0.2.1", "label") == "192.0.2.1"
    assert mock_dns == []  # no DNS lookup attempted for a dotted-quad


def test_resolve_service_name_uses_dns(mock_dns):
    assert e.resolve_to_ip("backend", "label") == "192.0.2.1"
    assert mock_dns == ["backend"]


def test_resolve_unresolvable_raises(mock_dns):
    with pytest.raises(ValueError):
        e.resolve_to_ip("nonexistent-host", "label")


@pytest.mark.parametrize("interior_newline", ["10.0.0.5\nfoo", "10.0.0.5\r\nbar"])
def test_resolve_interior_newline_not_treated_as_ip(mock_dns, interior_newline):
    # The dotted-quad regex must NOT match a value with an interior newline;
    # it should fall through to DNS, which raises.
    with pytest.raises(ValueError):
        e.resolve_to_ip(interior_newline, "label")


@pytest.mark.parametrize("bad_ip", ["999.999.999.999", "256.1.1.1", "010.0.0.1", "1.2.3.4.5"])
def test_resolve_invalid_dotted_quad_rejected(mock_dns, bad_ip):
    """F18 fixed: dotted-quad-shaped values must be VALID IPv4 (was passed through).

    A value with the shape of a dotted quad but invalid octets (or leading zeros)
    is rejected outright rather than emitted into the torrc. '1.2.3.4.5' is not
    dotted-quad shaped so it falls through to DNS, which also fails.
    """
    with pytest.raises(ValueError):
        e.resolve_to_ip(bad_ip, "label")


@pytest.mark.parametrize("good_ip", ["192.0.2.1", "127.0.0.1", "1.2.3.4", "10.0.0.255"])
def test_resolve_valid_ip_passthrough(mock_dns, good_ip):
    assert e.resolve_to_ip(good_ip, "label") == good_ip
    assert mock_dns == []  # valid dotted-quad → no DNS lookup


def test_resolve_whitespace_stripped(mock_dns):
    assert e.resolve_to_ip(" 10.0.0.5 ", "label") == "10.0.0.5"
