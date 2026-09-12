#!/usr/bin/env python3
"""libFuzzer target for hiddenforge's untrusted-input parsers.

Run by `atheris`:

    fuzz/fuzz_parsers.py <scratch-corpus> [seed-corpus] -max_total_time=120

The point is not to re-run the property tests; it is to let coverage-guided
mutation reach inputs the hand-written generators never produce. Two invariants
are asserted, and an assertion failure is a bug, not a validation rejection:

  * every value parser either raises ValueError or returns a well-formed value.
    A TypeError / AttributeError / IndexError escaping one of them is a crash.
  * no environment value, however hostile, can make build_torrc_string emit a
    directive outside the known whitelist, and none can make it raise on the way
    to that check. That second half is not theoretical: this target found a
    UnicodeEncodeError where a lone surrogate in an env value reached a log line
    and aborted startup.

The project modules are imported INSIDE `atheris.instrument_imports()` so the
fuzzer actually gets edge coverage; importing them at module scope (the obvious
way) leaves the target fuzzing blind, which libFuzzer reports as "no interesting
inputs were found".
"""
import contextlib
import os
import socket
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (ROOT, os.path.join(ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Populated by _load(); module globals so TestOneInput can reach them.
e = None
hf = None
vanity = None
ALLOWED_DIRECTIVES = frozenset()


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


if __name__ == "__main__":
    import atheris

    with atheris.instrument_imports():
        _load()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
