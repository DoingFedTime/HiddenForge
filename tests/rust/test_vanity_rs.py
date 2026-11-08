"""The Rust vanity generator (argv0 vanity.py), run against tests/fake_mkp224o.py."""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
RUST = Path(os.environ.get("HIDDENFORGE_RUST_BIN")
            or REPO / "hiddenforge-rs" / "target" / "release" / "hiddenforge")
FAKE = REPO / "tests" / "fake_mkp224o.py"
pytestmark = pytest.mark.skipif(
    not RUST.exists(), reason="build hiddenforge-rs first (cargo build --release)"
)


@pytest.fixture
def vanity(tmp_path):
    """Return a runner for the binary invoked as vanity.py with the fake generator."""
    wrapper = tmp_path / "mkp224o"
    wrapper.write_text(f'#!/bin/sh\nexec {sys.executable} {FAKE} "$@"\n')
    wrapper.chmod(0o755)
    link = tmp_path / "vanity.py"
    link.symlink_to(RUST)

    def run(args, mode, timeout, **env):
        full = {**os.environ, "MKP224O": str(wrapper), "HF_FAKE_MKP224O": mode,
                **{k: str(v) for k, v in env.items()}}
        return subprocess.run([str(link), *args], env=full, capture_output=True,
                              text=True, timeout=timeout)

    return run


def test_benchmark_kills_a_generator_that_ignores_terminate(vanity):
    """SIGTERM, then at most 5 s, then SIGKILL (Python: wait(5) then kill()).

    The fake bounds itself far beyond the test window: a generator that exits
    on its own would rescue an unbounded wait.
    """
    started = time.monotonic()
    try:
        r = vanity(["--prefix", "a", "--bench", "--seconds", "1", "--threads", "1"],
                   "deaf", timeout=15, HF_FAKE_MKP224O_MAX=10_000)
    except subprocess.TimeoutExpired:
        pytest.fail("benchmark waited for ever on a generator that ignores SIGTERM")
    assert time.monotonic() - started < 12
    assert r.returncode == 0, r.stdout + r.stderr
