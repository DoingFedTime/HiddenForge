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


# ─────────────────────────────────────────────────────────────────────────────
# What the refusals say
# ─────────────────────────────────────────────────────────────────────────────
#
# Every one of these raises a ValueError whose message is built with _safe(), and
# `raise ValueError(None)` passes any test that only checks the exception type --
# which is all the suite did, so mutation testing survived stripping the message
# from every validator. Two things are actually being asserted here:
#
#   1. The message names the value that was refused. The shipped compose file
#      sets `logging: driver: none`, and a container that refuses a mapping
#      without saying which one leaves the operator with a silent onion.
#   2. The value is control-character ESCAPED on its way into that message.
#      These values come from the environment and land in a log an operator may
#      later read with the json-file driver enabled; a raw ANSI escape or bare
#      newline in there forges log lines. That escaping is the whole reason
#      _safe() exists, and it is only exercised at these call sites.

def test_a_refused_service_name_is_quoted_back_escaped():
    with pytest.raises(ValueError) as exc:
        e.validate_service_name("web\nORPort 9001")
    message = str(exc.value)
    assert message == (
        "Invalid service name 'web\\x0aORPort 9001': only lowercase alphanumeric "
        "and hyphens allowed, max 63 chars")
    assert "\n" not in message


def test_a_refused_port_names_the_value_and_the_label_escaped():
    with pytest.raises(ValueError) as exc:
        e.validate_port("80\x1b[31m", "80\x1b[31m:127.0.0.1:8080")
    message = str(exc.value)
    assert message.count("\\x1b[31m") == 2, "both the value and its label are escaped"
    assert "\x1b" not in message


def test_an_out_of_range_port_names_the_port_and_the_label():
    """A separate message from the shape refusal: "65536 out of range" and
    "'8 0' is not a port" are different mistakes with different fixes."""
    with pytest.raises(ValueError) as exc:
        e.validate_port("65536", "65536:127.0.0.1:8080")
    message = str(exc.value)
    assert "65536" in message
    assert "out of range" in message
    assert "65536:127.0.0.1:8080" in message


def test_a_refused_hostname_names_the_value_and_the_label_escaped():
    with pytest.raises(ValueError) as exc:
        e.validate_hostname("host\nX", "80:host\nX:8080")
    message = str(exc.value)
    assert message.count("\\x0a") == 2
    assert "\n" not in message


def test_hostname_accepts_uppercase():
    """DNS labels are case-insensitive and Docker/Compose service names are
    matched case-insensitively too. Narrowing the class to lowercase would
    refuse a legitimate backend and drop the mapping."""
    assert e.validate_hostname("Backend", "label") == "Backend"
    assert e.validate_hostname("API.Example.COM", "label") == "API.Example.COM"


def test_a_refused_dotted_quad_names_the_address_and_the_label(mock_dns):
    with pytest.raises(ValueError) as exc:
        e.resolve_to_ip("999.999.999.999", "80:999.999.999.999:8080")
    message = str(exc.value)
    assert "Invalid IPv4 address '999.999.999.999'" in message
    assert "80:999.999.999.999:8080" in message


def test_an_unresolvable_host_says_what_to_check(mock_dns):
    """The overwhelmingly common cause is a backend that is not up yet or not on
    the same network. The message is the only place that is said."""
    with pytest.raises(ValueError) as exc:
        e.resolve_to_ip("nosuchhost", "80:nosuchhost:8080")
    message = str(exc.value)
    assert message == (
        "Cannot resolve 'nosuchhost' in 80:nosuchhost:8080: "
        "[Errno -2] Name or service not known. "
        "Is the backend container running and on the same network?")


def test_an_escaping_hostname_cannot_forge_a_log_line(mock_dns):
    """Whatever the resolver failure text contains, the host it was asked about
    came from the environment."""
    with pytest.raises(ValueError) as exc:
        e.resolve_to_ip("evil\x1b[2Khost", "label")
    assert "\x1b" not in str(exc.value)
    assert "\\x1b[2Khost" in str(exc.value)


def test_a_resolver_answer_that_is_not_an_ipv4_address_is_named(monkeypatch):
    """This is the one value reaching the torrc that the module did not build or
    validate itself, so the refusal has to be specific about what came back."""
    monkeypatch.setattr(e.socket, "gethostbyname", lambda host: "not-an-ip")
    with pytest.raises(ValueError) as exc:
        e.resolve_to_ip("backend", "80:backend:8080")
    assert str(exc.value) == (
        "Resolver returned a non-IPv4 value 'not-an-ip' for 'backend' "
        "in 80:backend:8080 — refusing to write it to the torrc")


def test_a_successful_resolution_is_announced_with_both_ends(mock_dns, capsys):
    """An operator reading the boot log needs to see which name became which
    address; that is the only record of what the torrc was built from."""
    e.resolve_to_ip("backend", "label")
    out = capsys.readouterr().out
    assert "Resolved 'backend'" in out
    assert "192.0.2.1" in out
