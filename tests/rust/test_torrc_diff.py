"""Differential test: Rust torrc builder vs entrypoint.build_torrc_string (2.1.6).

Both run on the same host and the same libc resolver, with the same environment.
Every byte must match: the torrc, the service dirs, the dropped-mapping reasons,
the recorded/unresolved backends and every log line.
"""

import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

REPO = Path(__file__).resolve().parents[2]
# HIDDENFORGE_RUST_BIN points the tests at another build: mutation testing
# runs them against each mutated binary (hiddenforge-rs/tests/differential.rs).
BIN = Path(os.environ.get("HIDDENFORGE_RUST_BIN")
           or REPO / "hiddenforge-rs" / "target" / "release" / "hiddenforge")
sys.path.insert(0, str(REPO))
import entrypoint


def python_side(env):
    saved = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(env)
        dropped, resolved, unresolved = [], {}, set()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            content, dirs = entrypoint.build_torrc_string(
                dropped=dropped, resolved=resolved, unresolved=unresolved
            )
        return {
            "content": content,
            "hs_dirs": dirs,
            "dropped": dropped,
            "resolved": resolved,
            "unresolved": sorted(unresolved),
            "log": buf.getvalue().splitlines(),
        }
    finally:
        os.environ.clear()
        os.environ.update(saved)


def rust_side(env):
    out = subprocess.run(
        [str(BIN), "torrc-preview"], env=env, capture_output=True, check=True, timeout=30
    ).stdout
    doc = json.loads(out)
    doc["unresolved"] = sorted(doc["unresolved"])
    return doc


def check(env):
    py, rs = python_side(env), rust_side(env)
    for key in ("content", "hs_dirs", "dropped", "resolved", "unresolved", "log"):
        assert rs[key] == py[key], (key, env)


FIXED = [
    {},
    {"MYAPP_TOR_SERVICE_HOSTS": "80:10.0.0.2:8080"},
    {"MYAPP_TOR_SERVICE_HOSTS": "80:8080,443:127.0.0.1:8443"},
    {"MYAPP_TOR_SERVICE_HOSTS": "80:localhost:80"},
    {"MYAPP_TOR_SERVICE_HOSTS": "80:nonexistent-host.invalid:80,81:8081"},
    {
        "MY_APP_TOR_SERVICE_HOSTS": "80:8080",
        "myapp_TOR_SERVICE_HOSTS": "81:8081",
        "MYAPP_TOR_SERVICE_HOSTS": "82:8082",
    },
    {"BAD.NAME_TOR_SERVICE_HOSTS": "80:8080", "GOOD_TOR_SERVICE_HOSTS": "80:8080"},
    {"A_TOR_SERVICE_HOSTS": "0:8080,70000:1,abc:1,1:2:3:4,,  ,nocolon"},
    {"A_TOR_SERVICE_HOSTS": "80:010.0.0.1:80,80:256.1.1.1:80,80:1.2.3.4:080"},
    {"A_TOR_SERVICE_HOSTS": "80:bad host:80,80:x" + "a" * 260 + ":80"},
    {"A_TOR_SERVICE_HOSTS": "80:1.2.3.4:80\nSocksPort 9050"},
    {"A_TOR_SERVICE_HOSTS": " 80 : 1.2.3.4 : 80 \t"},
    {"A_TOR_SERVICE_HOSTS": "80:8080", "TOR_SANDBOX": "0"},
    {"A_TOR_SERVICE_HOSTS": "80:8080", "TOR_SANDBOX": "false"},
    {"\x1b[31mX_TOR_SERVICE_HOSTS": "80:8080"},
    {"Z_TOR_SERVICE_HOSTS": "80:8080", "A_TOR_SERVICE_HOSTS": "80:8080"},
    {"A_TOR_SERVICE_HOSTS_TOR_SERVICE_HOSTS": "80:8080"},
    {"_TOR_SERVICE_HOSTS": "80:8080"},
    {"A" * 70 + "_TOR_SERVICE_HOSTS": "80:8080"},
    {"A_TOR_SERVICE_HOSTS": "80:\u200blocalhost:80,81:é:80"},
    {"A_TOR_SERVICE_HOSTS": "80:localhost:99999"},
]


pytestmark = pytest.mark.skipif(
    not BIN.exists(), reason="build hiddenforge-rs first (cargo build --release)"
)


@pytest.mark.parametrize("env", FIXED)
def test_fixed_cases(env):
    base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    check({**base, **env})


ALPHA = "0123456789:,.abcz-_ \t\n\x1c" + "AZ" + "é\u200b"
names = st.text(alphabet="ABCXYZ_-.abc0\x1b", min_size=0, max_size=12).map(
    lambda s: s + "_TOR_SERVICE_HOSTS"
)
values = st.text(alphabet=ALPHA, max_size=60)


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.dictionaries(names, values, max_size=4))
def test_random_environments(env):
    if any("\x00" in k or "\x00" in v or "=" in k for k, v in env.items()):
        return
    base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    check({**base, **env})
