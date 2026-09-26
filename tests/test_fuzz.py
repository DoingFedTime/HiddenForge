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
from directives import ALLOWED_DIRECTIVES

# Strategy for values set via os.environ. Excludes:
#   - NUL: the OS forbids it in env var values.
#   - surrogates (category Cs): os.environ[...] = value cannot ENCODE a lone
#     surrogate in this test harness. (Surrogates CAN appear in a real env via
#     surrogateescape decoding of non-UTF8 bytes, but the validators reject them
#     — covered directly in test_validators, not via this env-based strategy.)
# Everything else (newlines, CR, control chars, unicode, colons, commas) is fair game.
_no_nul = st.text(
    alphabet=st.characters(
        blacklist_characters="\x00",
        blacklist_categories=("Cs",),  # type: ignore[arg-type]  # runtime accepts "Cs"
    ),
    max_size=200,
)


def _set_only(value):
    for k in list(os.environ):
        if k.endswith("_TOR_SERVICE_HOSTS") or k == "TOR_SANDBOX":
            del os.environ[k]
    os.environ["SERVICE_TOR_SERVICE_HOSTS"] = value


# ─────────────────────────────────────────────────────────────────────────────
# THE invariant: no injection, ever, for any value
# ─────────────────────────────────────────────────────────────────────────────

@settings(
    max_examples=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)
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

@settings(max_examples=1000, deadline=None)
@given(_no_nul)
def test_fuzz_validate_port_invariant(s):
    try:
        result = e.validate_port(s, "label")
    except ValueError:
        return
    assert result.isdigit()
    assert 1 <= int(result) <= 65535


@settings(max_examples=1000, deadline=None)
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


@settings(max_examples=1000, deadline=None)
@given(_no_nul)
def test_fuzz_validate_hostname_invariant(s):
    try:
        result = e.validate_hostname(s, "label")
    except ValueError:
        return
    assert re.fullmatch(r"[a-zA-Z0-9._\-]{1,253}", result)
    assert not any(c.isspace() for c in result)


@settings(
    max_examples=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)
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


# ── The key path cannot change what `setup` generates ─────────────────────
# The coverage-guided fuzz target asserts this, but it does not run in CI, and a
# deploy.sh line added in one cycle let a key path holding `"` inject a command
# while every CI test passed: their payloads were all newlines, which the
# validator refuses anyway. This is the same structure invariant, in CI, over
# every character the validator ACCEPTS.

import shlex

import yaml
from loader import load_file, repo_root

_HF = load_file(repo_root(__file__) / "scripts" / "hiddenforge", "hf_fuzz_setup")
_SERVICES = {"app": ["80:127.0.0.1:8080"]}
_path_chars = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")) | st.sampled_from(
        list("\"'`$\\;|&(){}[]<>*?!#~ =:/.-_")),
    min_size=1, max_size=40)


@settings(max_examples=400, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(_path_chars)
def test_no_key_path_changes_the_structure_of_the_setup_files(keys):
    try:
        _HF.validate_keys_dir(keys)
    except ValueError:
        return                       # refused before it reaches any file
    for runtime in ("docker", "podman"):
        benign_sh = shlex.split(_HF.render_deploy_sh(_SERVICES, "/keys", "tor", runtime),
                                comments=True)
        got_sh = shlex.split(_HF.render_deploy_sh(_SERVICES, keys, "tor", runtime),
                             comments=True)
        assert len(got_sh) == len(benign_sh), (runtime, keys)
        for got, want in zip(got_sh, benign_sh, strict=True):
            assert got == want or "/keys" in want, (runtime, keys, want, got)
        benign_doc = yaml.safe_load(_HF.render_compose_fragment(
            _SERVICES, "img:1", "/keys", "tor", runtime))
        got_doc = yaml.safe_load(_HF.render_compose_fragment(
            _SERVICES, "img:1", keys, "tor", runtime))
        assert set(got_doc["services"]["tor"]) == set(benign_doc["services"]["tor"])
        assert got_doc["services"]["tor"]["volumes"] == [
            f"{keys}:/var/lib/tor/hidden_service"]
