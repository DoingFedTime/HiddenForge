#!/usr/bin/env python3
"""libFuzzer target for hiddenforge's untrusted-input parsers.

Run by `atheris`:

    fuzz/fuzz_parsers.py <scratch-corpus> [seed-corpus] -max_total_time=120

The point is not to re-run the property tests; it is to let coverage-guided
mutation reach inputs the hand-written generators never produce. Three
invariants are asserted, and an assertion failure is a bug, not a validation
rejection:

  * every value parser either raises ValueError or returns a well-formed value.
    A TypeError / AttributeError / IndexError escaping one of them is a crash.
  * no environment value, however hostile, can make build_torrc_string emit a
    directive outside the known whitelist, and none can make it raise on the way
    to that check. That second half is not theoretical: this target found a
    UnicodeEncodeError where a lone surrogate in an env value reached a log line
    and aborted startup.
  * no key-volume path, however hostile, can change the STRUCTURE of the two
    files `setup` writes for the operator: the compose fragment must parse to the
    same YAML keys and the same one volume, and deploy.sh must split into the
    same shell words, differing only where the benign path was.

The project modules are imported INSIDE `atheris.instrument_imports()` so the
fuzzer actually gets edge coverage; importing them at module scope (the obvious
way) leaves the target fuzzing blind, which libFuzzer reports as "no interesting
inputs were found".
"""
import contextlib
import os
import shlex
import socket
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (ROOT, os.path.join(ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Populated by _load(); module globals so TestOneInput can reach them.
e = None
hf = None
vanity = None
ALLOWED_DIRECTIVES = frozenset()

SERVICES = {"fuzz": ["80:127.0.0.1:8080"]}
RUNTIMES = ("docker", "podman")
BENIGN: dict = {}


def _load() -> None:
    """Import the project modules (call this under atheris instrumentation)."""
    global e, hf, vanity, ALLOWED_DIRECTIVES

    import importlib.machinery
    import importlib.util

    import entrypoint as _e
    from directives import ALLOWED_DIRECTIVES as _ALLOWED
    import vanity as _vanity

    # The operator CLI has no .py extension, so it cannot be imported by name.
    loader = importlib.machinery.SourceFileLoader(
        "hf_cli", os.path.join(ROOT, "scripts", "hiddenforge"))
    spec = importlib.util.spec_from_loader("hf_cli", loader)
    _hf = importlib.util.module_from_spec(spec)
    loader.exec_module(_hf)

    # Deterministic resolution: no network, and every hostname "resolves" so the
    # torrc path that emits a HiddenServicePort is reached more often.
    socket.gethostbyname = lambda host: "10.0.0.1"

    e, hf, vanity, ALLOWED_DIRECTIVES = _e, _hf, _vanity, _ALLOWED

    # The benign side of every shape invariant is a constant. Rendering and
    # parsing it per input cost 40x the exec rate, which is coverage the fuzzer
    # never gets to spend.
    # Both runtimes: their fragments and scripts differ (restart policy,
    # healthcheck, the address hint), and the Podman variants were once never
    # fuzzed at all.
    for runtime in RUNTIMES:
        BENIGN[runtime, "doc"] = yaml.safe_load(
            _hf.render_compose_fragment(SERVICES, "img:1", "/keys", "tor", runtime))
        BENIGN[runtime, "tokens"] = shlex.split(
            _hf.render_deploy_sh(SERVICES, "/keys", "tor", runtime), comments=True)


def TestOneInput(data: bytes) -> None:
    # NUL cannot live in an environment value; drop it rather than crash on the
    # harness itself (a crash there would be a false positive).
    text = data.decode("utf-8", "surrogateescape").replace("\x00", "")

    for fn, args in (
        (e.validate_service_name, (text,)),
        (e.validate_port, (text, "fuzz")),
        (e.validate_hostname, (text, "fuzz")),
        (hf.validate_image_ref, (text,)),
        (hf.validate_container, (text,)),
        (hf.validate_keys_dir, (text,)),
    ):
        with contextlib.suppress(ValueError):
            fn(*args)

    for spec in (text, text[:200]):
        with contextlib.suppress(ValueError):
            hf._parse_service_spec(spec)
        with contextlib.suppress(ValueError):
            hf._parse_backend(spec)

    # derive_onion: any length other than 32 must raise, never return junk.
    with contextlib.suppress(ValueError):
        onion = vanity.derive_onion(data)
        assert len(onion) == 62 and onion.endswith(".onion"), onion

    # The injection property, at byte level, plus "must not raise on the way".
    os.environ["FUZZ_TOR_SERVICE_HOSTS"] = text
    try:
        torrc, _dirs = e.build_torrc_string()
    finally:
        os.environ.pop("FUZZ_TOR_SERVICE_HOSTS", None)

    for line in torrc.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        token = s.split()[0]
        assert token in ALLOWED_DIRECTIVES, f"injected directive {s!r} from {text!r}"

    # The same property for the two files `setup` generates. The key path is the
    # third input channel that reaches an operator-executed artifact: it lands in
    # compose.service.yml, which the operator merges into their own stack, and in
    # deploy.sh, which is written 0755 and which the README tells them to run.
    # A path that opens a compose key or a shell command has done what
    # `privileged: true` and `; curl ... | sh` do, so the invariant is that the
    # rendered output has the same STRUCTURE whatever the path contains: the
    # same YAML keys, and the same shell words.
    for runtime in RUNTIMES:
        _check_setup_outputs(text, runtime)


def _check_setup_outputs(text: str, runtime: str) -> None:
    services = SERVICES
    fuzz_yaml = hf.render_compose_fragment(services, "img:1", text, "tor", runtime)
    # Structure, not line count. A line count was the first attempt and it was
    # wrong in the unsafe direction and the safe one at once: json.dumps writes a
    # newline as the two characters \n inside one double-quoted scalar, which
    # adds no line and is safe, while a value that really did open a key could in
    # principle replace one line with one line. Parsing asks the question the
    # invariant is actually about.
    fuzz_doc = yaml.safe_load(fuzz_yaml)
    benign_doc = BENIGN[runtime, "doc"]
    assert set(fuzz_doc) == set(benign_doc), (
        f"the key path changed the fragment's top level: {text!r}")
    assert sorted(fuzz_doc["services"]) == sorted(benign_doc["services"]), (
        f"the key path added or renamed a service: {text!r}")
    got, want = fuzz_doc["services"]["tor"], benign_doc["services"]["tor"]
    assert set(got) == set(want), (
        f"the key path opened a compose key: {sorted(set(got) - set(want))!r} "
        f"from {text!r}")
    assert len(got["volumes"]) == len(want["volumes"]), (
        f"the key path added a volume: {got['volumes']!r} from {text!r}")
    assert all(v.endswith(":/var/lib/tor/hidden_service") for v in got["volumes"]), (
        f"the key path escaped its mount: {got['volumes']!r} from {text!r}")

    fuzz_sh = hf.render_deploy_sh(services, text, "tor", runtime)
    # Same reasoning: the path is single-quoted, so a newline inside it is data
    # and adds a line without adding a command. What must not change is the
    # script's WORDS -- an injected command is new tokens, and a token that
    # changed where no path was is a payload that got out of its quotes.
    benign_tokens = BENIGN[runtime, "tokens"]
    try:
        fuzz_tokens = shlex.split(fuzz_sh, comments=True)
    except ValueError as exc:
        raise AssertionError(
            f"the key path left deploy.sh unparseable: {text!r} ({exc})") from exc
    assert len(fuzz_tokens) == len(benign_tokens), (
        f"the key path changed deploy.sh's word count "
        f"{len(benign_tokens)} -> {len(fuzz_tokens)}: {text!r}")
    for got_tok, want_tok in zip(fuzz_tokens, benign_tokens, strict=True):
        if got_tok != want_tok:
            assert "/keys" in want_tok, (
                f"the key path changed a word that held no path: "
                f"{want_tok!r} -> {got_tok!r} from {text!r}")


if __name__ == "__main__":
    import atheris

    with atheris.instrument_imports():
        _load()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
