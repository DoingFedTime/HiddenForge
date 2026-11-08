"""The Rust bandguards/rendguard port against Vanguards 0.3.1's decisions.

fake_tor_control.py plays a scripted control port and records every
CLOSECIRCUIT. golden_guards_closes.json is what Vanguards 0.3.1 sent for that
script (the 2.1.6 image's own copy, recorded once); the Rust monitor must send
the same circuits, in the same order.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
# HIDDENFORGE_RUST_BIN points the tests at another build: mutation testing
# runs them against each mutated binary (hiddenforge-rs/tests/differential.rs).
BIN = Path(os.environ.get("HIDDENFORGE_RUST_BIN")
           or REPO / "hiddenforge-rs" / "target" / "release" / "hiddenforge")


def _run_guards(extra: list[str], d: str, loglevel: str = "WARN") -> dict:
    """Run the Rust monitor against the scripted control port; return its record
    (plus its standard output under "stdout")."""
    os.mkdir(f"{d}/data")
    guards = Path(d) / "hiddenforge-guards"
    guards.symlink_to(BIN)
    sock, out = f"{d}/c.sock", f"{d}/out.json"
    ctl = subprocess.Popen([sys.executable, "-I", str(HERE / "fake_tor_control.py"),
                            sock, f"{d}/data", out])
    mon = None
    try:
        deadline = time.monotonic() + 10
        while not os.path.exists(sock):
            assert ctl.poll() is None, "the fake control port exited early"
            assert time.monotonic() < deadline, "the fake control port never listened"
            time.sleep(0.05)
        with open(f"{d}/stdout.txt", "wb") as so:
            mon = subprocess.Popen([str(guards), "--control_socket", sock, "--loglevel", loglevel,
                                    *extra], stdout=so, stderr=subprocess.DEVNULL)
            ctl.wait(timeout=90)
    finally:
        for p in (mon, ctl):
            if p is not None and p.poll() is None:
                p.kill()
                p.wait()
    rec = json.loads(Path(out).read_text())
    rec["stdout"] = Path(f"{d}/stdout.txt").read_text()
    return rec


@pytest.mark.skipif(not BIN.exists(), reason="build hiddenforge-rs first (cargo build --release)")
def test_full_vanguards_pin_both_layers_and_persist_them():
    """HIDDENFORGE_VANGUARDS=full: the monitor pins layer 2 and 3 with one
    SETCONF, as Vanguards' configure_tor() does, persists the sets, and still
    makes exactly the same bandguards/rendguard decisions."""
    want = json.loads((HERE / "golden_guards_closes.json").read_text())["closes"]
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="hfg") as d:
        state = f"{d}/vanguards-full.state"
        rec = _run_guards(["--state", state], d)
        assert rec["closes"] == want
        assert len(rec["setconf"]) >= 1
        sc = rec["setconf"][0].split()
        assert sc[:2] == ["NumEntryGuards=2", "NumPrimaryGuards=2"]
        l2 = sc[2].removeprefix("HSLayer2Nodes=").split(",")
        l3 = sc[3].removeprefix("HSLayer3Nodes=").split(",")
        # The script's consensus has three Fast+Stable+Valid relays (B, C, D).
        relays = {c * 40 for c in "BCD"}
        assert set(l2) <= relays and len(set(l2)) == len(l2) == 3
        assert set(l3) <= relays and len(set(l3)) == len(l3) == 3
        lines = [x.split() for x in Path(state).read_text().splitlines() if not x.startswith("#")]
        assert sorted(x[1] for x in lines if x[0] == "L2") == sorted(l2)
        assert oct(os.stat(state).st_mode & 0o777) == "0o600"


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


# logger.py: "%(levelname)s[%(asctime)s]: %(message)s" with "%a %b %d %H:%M:%S %Y".
LOG_LINE = re.compile(
    r"^(DEBUG|INFO|NOTICE|WARN|ERROR)"
    r"\[(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-6][0-9] [0-9]{4}\]: (.+)$"
)


def _parse_log(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        m = LOG_LINE.match(line)
        assert m, f"not a Vanguards log line: {line!r}"
        out.append((m.group(1), m.group(4)))
    return out


@pytest.mark.skipif(not BIN.exists(), reason="build hiddenforge-rs first (cargo build --release)")
def test_guards_log_what_vanguards_logs_in_its_format():
    """Standard output at DEBUG for the scripted session: every line has the
    addon's format, the force-closes appear in the order Vanguards made them,
    and the full-vanguards pin message appears once."""
    want = json.loads((HERE / "golden_guards_closes.json").read_text())["closes"]
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="hfg") as d:
        rec = _run_guards(["--state", f"{d}/vanguards-full.state"], d, loglevel="DEBUG")
    log = _parse_log(rec["stdout"])
    assert rec["closes"] == want
    notices = [m for lv, m in log if lv == "NOTICE"]
    assert notices[0].startswith("Full vanguards enabled: 0 layer-2 and 0 layer-3 guards restored from ")
    assert re.fullmatch(r"Vanguards \(HiddenForge guards \S+\) connected to Tor 0\.4\.9\.16", notices[1])
    assert notices.count("Full vanguards: 3 layer-2 and 3 layer-3 guards pinned.") == 1
    assert [m.removeprefix("We force-closed circuit ") for m in notices
            if m.startswith("We force-closed circuit ")] == want
    # Bandguards' own decisions, with Vanguards' wording.
    assert ("NOTICE", "Tor bug #29699: Got 2 dropped cell on circ 10 "
            "(in state HS_SERVICE_INTRO HSSI_ESTABLISHED; old state None None).") in log
    assert ("WARN", "Possible Tor bug, or possible attack if very frequent: Got 3 dropped cell on circ 13 "
            "(in state GENERAL None; old state None None)") in log
    assert ("WARN", "Circ 12 exceeded CIRC_MAX_HSDESC_KILOBYTES: 31745 > 30720. ".strip()) in log
    assert ("INFO", "Tor bug #29927: Got a dropped cell on circ 14 "
            "(in state GENERAL None; old state None None).") in log
    assert ("INFO", "Tor bug #29786: Got a dropped cell on circ 15 "
            "(in state PATH_BIAS_TESTING None; old state HS_CLIENT_REND HSCR_CONNECTING).") in log
    assert any(lv == "DEBUG" and m.startswith("Added circ for 650 CIRC 10 BUILT ") for lv, m in log)
    assert any(lv == "DEBUG" and m.startswith("Closed hs circ for 650 CIRC 17 CLOSED ") for lv, m in log)
    # Rendguard: the unknown rend point and the overused one.
    assert ("INFO", f"Relay {'E' * 40} is not in our consensus.") in log
    assert any(lv == "NOTICE" and m.startswith(f"Relay {'B' * 40} used ")
               and "This is above its consensus weight of 0.066667%" in m for lv, m in log)
