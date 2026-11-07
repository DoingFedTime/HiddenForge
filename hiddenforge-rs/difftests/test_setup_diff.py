"""Differential test: Rust `setup` (in the image) vs the Python host CLI `setup`.

Same arguments, same environment: every generated file must be byte-identical,
and the --json descriptor identical once output_dir (an absolute path) is
normalised.
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
RUST = REPO / "hiddenforge-rs" / "target" / "release" / "hiddenforge"
PY = REPO / "scripts" / "hiddenforge"
FILES = ("compose.service.yml", "deploy.sh", "README.txt", "hiddenforge.json")

CASES = [
    ["--backend", "web:80"],
    ["--backend", "web:8080", "--name", "my-app", "--onion-port", "443"],
    ["--service", "a:80:web:80", "--service", "b:443:api:8443", "--service", "a:81:web:81"],
    ["--services", "x:80:10.0.0.5:80,y:80:db.internal:5432"],
    ["--backend", "web:80", "--runtime", "podman"],
    ["--backend", "web:80", "--keys", "/srv/keys with space/k'q\"$x`", "--container", "onion.1"],
    ["--backend", "web:80", "--image", "sambent.dev/sam/hiddenforge@sha256:" + "a" * 64],
    ["--backend", "web:80", "--keys", "./tor-keys/📁é"],
    ["--backend", "bad host:80"],
    ["--backend", "web:0"],
    ["--backend", "web:80", "--onion-port", "70000"],
    ["--service", "Bad:80:web:80"],
    ["--backend", "web:80", "--container", "-privileged"],
    ["--backend", "web:80", "--image", "--privileged"],
    ["--backend", "web:80", "--keys", "a\nb"],
    [],
    ["--backend", "web:80", "--no-root"],
    ["--backend", "web:80", "--no-root", "--runtime", "podman"],
    ["--service", "a:80:web:80", "--no-root", "--keys", "/srv/k ey"],
]


def run(prog, args, out):
    env = {"PATH": os.environ["PATH"], "HOME": "/tmp", "HIDDENFORGE_IMAGE": "sambent.dev/sam/hiddenforge:latest"}
    cmd = [str(prog)] if prog == RUST else [str(REPO / ".venv" / "bin" / "python"), str(PY)]
    if prog == RUST:
        cmd = [str(RUST)]
    p = subprocess.run([*cmd, "setup", "-o", out, "--non-interactive", "--json", *args],
                       capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=60)
    files = {f: (Path(out) / f).read_bytes() if (Path(out) / f).exists() else None for f in FILES}
    if files["hiddenforge.json"]:
        files["hiddenforge.json"] = files["hiddenforge.json"].replace(os.getcwd().encode(), b"<cwd>")
    modes = {f: oct((Path(out) / f).stat().st_mode & 0o777) if (Path(out) / f).exists() else None for f in FILES}
    doc = json.loads(p.stdout) if p.stdout.strip() else None
    if isinstance(doc, dict) and "output_dir" in doc:
        doc["output_dir"] = "<out>"
    return p.returncode, doc, files, modes


@pytest.mark.parametrize("args", CASES, ids=[" ".join(c)[:40] or "none" for c in CASES])
def test_setup_identical(args):
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        # The same relative output name inside each temp dir, so paths match.
        oa, ob = os.path.join(a, "deploy"), os.path.join(b, "deploy")
        os.chdir(a)
        rp = run("py", args, "deploy")
        os.chdir(b)
        rr = run(RUST, args, "deploy")
        assert rr[0] == rp[0], (rr[1], rp[1])
        assert rr[1] == rp[1]
        for f in FILES:
            assert rr[2][f] == rp[2][f], f
            assert rr[3][f] == rp[3][f], f
