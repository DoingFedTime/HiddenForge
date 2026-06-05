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
        "ｗｅｂ",                   # fullwidth homoglyph
        "",                        # empty
        "web.app",                 # dot not allowed
        "web_app",                 # underscore not allowed (transform happens earlier)
    ],
)
def test_service_name_rejects_bad(bad):
    with pytest.raises(ValueError):
        e.validate_service_name(bad)


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


def test_resolve_octet_overflow_is_a_known_gap(mock_dns):
    """FINDING F18: resolve_to_ip accepts 999.999.999.999 (no octet range check).

    Documents CURRENT behavior. Tor rejects such an address at parse time, so it
    is not exploitable, but the validator is too permissive. When F18 is fixed,
    flip this to assert rejection.
    """
    assert e.resolve_to_ip("999.999.999.999", "label") == "999.999.999.999"
    assert mock_dns == []  # matched the dotted-quad regex, so no DNS lookup


def test_resolve_whitespace_stripped(mock_dns):
    assert e.resolve_to_ip(" 10.0.0.5 ", "label") == "10.0.0.5"
