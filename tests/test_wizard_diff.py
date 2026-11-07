"""The browser wizard's file generation (wizard/render.js, run under Node)
must produce exactly the files `hiddenforge setup` writes."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
FILES = ("compose.service.yml", "deploy.sh", "README.txt", "hiddenforge.json")

CASES = [
    dict(services={"myapp": ["80:web:80"]}),
    dict(services={"a": ["80:web:80", "81:web:81"], "b": ["443:api:8443"]}, runtime="podman"),
    dict(services={"x": ["80:10.0.0.5:80"], "y": ["80:db.internal:5432"]}),
    dict(
        services={"myapp": ["80:web:80"]}, keys="/srv/keys with space/k'q\"$x`", container="onion.1"
    ),
    dict(services={"myapp": ["80:web:80"]}, keys="./tor-keys/📁é"),
    dict(services={"myapp": ["80:web:80"]}, no_root=True),
    dict(services={"myapp": ["80:web:80"]}, no_root=True, runtime="podman"),
    dict(services={"myapp": ["80:web:80"]}, encrypt=True),
    dict(
        services={"myapp": ["80:web:80"]},
        encrypt=True,
        no_root=True,
        runtime="podman",
        pp="/srv/pp'x",
    ),
    dict(
        services={"my-app": ["443:web:8080"]},
        onion_port=443,
        image="sambent.dev/sam/hiddenforge@sha256:" + "a" * 64,
    ),
]


def cli_args(c):
    a = []
    for n, maps in c["services"].items():
        for m in maps:
            a += ["--service", f"{n}:{m}"]
    for k, flag in (
        ("keys", "--keys"),
        ("container", "--container"),
        ("runtime", "--runtime"),
        ("image", "--image"),
    ):
        if k in c:
            a += [flag, c[k]]
    if c.get("onion_port"):
        a += ["--onion-port", str(c["onion_port"])]
    if c.get("no_root"):
        a += ["--no-root"]
    if c.get("encrypt"):
        a += ["--encrypt-keys"] + (["--passphrase-file", c["pp"]] if "pp" in c else [])
    return a


@pytest.mark.skipif(NODE is None, reason="node not installed")
@pytest.mark.parametrize("case", CASES, ids=[str(i) for i in range(len(CASES))])
def test_wizard_matches_setup(case):
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "deploy")
        env = {
            "PATH": os.environ["PATH"],
            "HOME": tmp,
            "HIDDENFORGE_IMAGE": "sambent.dev/sam/hiddenforge:latest",
        }
        subprocess.run(
            [
                str(REPO / ".venv/bin/python"),
                str(REPO / "scripts/hiddenforge"),
                "setup",
                "-o",
                out,
                "--non-interactive",
                *cli_args(case),
            ],
            check=True,
            capture_output=True,
            env=env,
            stdin=subprocess.DEVNULL,
            timeout=60,
        )
        opts = dict(
            services=case["services"],
            image=case.get("image", "sambent.dev/sam/hiddenforge:latest"),
            keys=case.get("keys", "./tor-keys"),
            container=case.get("container", "tor"),
            runtime=case.get("runtime", "docker"),
            noRoot=case.get("no_root", False),
            encryptKeys=case.get("encrypt", False),
            passphraseFile=case.get("pp"),
            onionPort=case.get("onion_port", 80),
            out=out,
            outputDir=os.path.realpath(out),
        )
        js = (
            "const r=require(process.argv[1]);const o=JSON.parse(process.argv[2]);"
            "process.stdout.write(JSON.stringify(r.generate(o).files));"
        )
        got = json.loads(
            subprocess.run(
                [NODE, "-e", js, str(REPO / "wizard/render.js"), json.dumps(opts)],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            ).stdout
        )
        for f in FILES:
            assert got[f] == Path(out, f).read_text(), f
