"""The Rust bandguards/rendguard port against Vanguards 0.3.1's decisions.

fake_tor_control.py plays a scripted control port and records every
CLOSECIRCUIT. golden_guards_closes.json is what Vanguards 0.3.1 sent for that
script (the 2.1.6 image's own copy, recorded once); the Rust monitor must send
the same circuits, in the same order.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BIN = REPO / "hiddenforge-rs" / "target" / "release" / "hiddenforge"


@pytest.mark.skipif(not BIN.exists(), reason="build hiddenforge-rs first (cargo build --release)")
def test_rust_guards_close_exactly_what_vanguards_closed():
    want = json.loads((HERE / "golden_guards_closes.json").read_text())["closes"]
    # AF_UNIX paths are limited to 108 bytes, so keep the directory short.
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="hfg") as d:
        os.mkdir(f"{d}/data")
        guards = Path(d) / "hiddenforge-guards"
        guards.symlink_to(BIN)
        sock, out = f"{d}/c.sock", f"{d}/out.json"
        ctl = subprocess.Popen([sys.executable, "-I", str(HERE / "fake_tor_control.py"),
                                sock, f"{d}/data", out])
        try:
            deadline = time.monotonic() + 10
            while not os.path.exists(sock):
                assert ctl.poll() is None, "the fake control port exited early"
                assert time.monotonic() < deadline, "the fake control port never listened"
                time.sleep(0.05)
            mon = subprocess.Popen([str(guards), "--control_socket", sock,
                                    "--disable_vanguards", "--loglevel", "WARN"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ctl.wait(timeout=90)
        finally:
            for p in (locals().get("mon"), ctl):
                if p is not None and p.poll() is None:
                    p.kill()
                    p.wait()
        got = json.loads(Path(out).read_text())["closes"]
    assert got == want
