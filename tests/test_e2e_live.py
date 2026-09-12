"""Live end-to-end acceptance tests. Docker + network required.

Skipped unless HIDDENFORGE_E2E=1 (set it to run the acceptance criteria):

    HIDDENFORGE_E2E=1 .venv/bin/python -m pytest tests/test_e2e_live.py -v

They:
  * start the built image and prove a throwaway app publishes itself as a .onion
    by adding only the emitted merge fragment (examples/demo),
  * wait for the address file and assert it parses as a v3 onion and agrees with
    `hiddenforge show --json`,
  * run a vanity search for a short prefix inside the image and assert the
    resulting key's .onion actually starts with that prefix,
  * validate the emitted fragment with `docker compose config`.

Image under test: $HIDDENFORGE_TEST_IMAGE (default sambent.dev/sam/hiddenforge:latest).
"""
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from loader import repo_root

REPO = repo_root(__file__)
CLI = REPO / "scripts" / "hiddenforge"
DEMO = REPO / "examples" / "demo"
IMAGE = os.environ.get("HIDDENFORGE_TEST_IMAGE",
                       "sambent.dev/sam/hiddenforge:latest")
ONION_RE = re.compile(r"^[a-z2-7]{56}\.onion$")

pytestmark = pytest.mark.skipif(
    os.environ.get("HIDDENFORGE_E2E") != "1",
    reason="live E2E disabled; set HIDDENFORGE_E2E=1 (needs docker + network)",
)


def _load(path: Path, name: str):
    """Load a file without the bytecode cache (see tests/loader.py)."""
    from loader import load_file
    return load_file(path, name)


def _have_docker() -> bool:
    return shutil.which("docker") is not None and \
        subprocess.run(["docker", "image", "inspect", IMAGE],
                       capture_output=True).returncode == 0


requires_image = pytest.mark.skipif(not _have_docker(),
                                    reason=f"image {IMAGE} not built")


def _compose(tmp: Path, *extra):
    return ["docker", "compose", "-f", str(tmp / "app.yml"),
            "-f", str(tmp / "compose.service.yml"), *extra]


@requires_image
def test_emitted_fragment_validates(tmp_path):
    subprocess.run([str(CLI), "setup", "--backend", "web:80", "--name", "demo",
                    "--out", str(tmp_path)], check=True, capture_output=True)
    shutil.copy(DEMO / "app.yml", tmp_path / "app.yml")
    proc = subprocess.run(_compose(tmp_path, "config"), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


@requires_image
def test_vanity_short_prefix_matches(tmp_path):
    keys = tmp_path / "keys"
    keys.mkdir()
    os.chmod(keys, 0o700)
    proc = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{keys}:/keys", IMAGE, "vanity",
         "--prefix", "a", "--name", "v", "--out", "/keys", "--threads", "2",
         "--uid", str(os.getuid()), "--gid", str(os.getgid()), "--json"],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout.strip().splitlines()[-1])
    assert doc["onion"].startswith("a")
    assert doc["address_matches_prefix"] is True
    hostname = (keys / "v" / "hostname").read_text().strip()
    assert hostname == doc["onion"]
    assert ONION_RE.fullmatch(hostname)
    # Independent derivation from the generated public key must agree.
    vanity = _load(REPO / "vanity.py", "hf_vanity_e2e")
    pub = vanity.read_public_key(keys / "v" / "hs_ed25519_public_key")
    assert vanity.derive_onion(pub) == hostname


@requires_image
def test_demo_publishes_and_show_agrees(tmp_path):
    subprocess.run([str(CLI), "setup", "--backend", "web:80", "--name", "demo",
                    "--keys", "./tor-keys", "--out", str(tmp_path)],
                   check=True, capture_output=True)
    shutil.copy(DEMO / "app.yml", tmp_path / "app.yml")
    shutil.copytree(DEMO / "site", tmp_path / "site")
    try:
        proc = subprocess.run(_compose(tmp_path, "up", "-d"),
                              capture_output=True, text=True, timeout=300)
        assert proc.returncode == 0, proc.stderr

        published = tmp_path / "tor-keys" / "demo.onion"
        deadline = time.time() + 300
        while time.time() < deadline and not published.exists():
            time.sleep(3)
        assert published.exists(), "address file was never published"
        onion = published.read_text().strip()
        assert ONION_RE.fullmatch(onion), onion

        # The host CLI must report the same address, without docker exec.
        show = subprocess.run(
            [str(CLI), "show", "--keys", str(tmp_path / "tor-keys"),
             "--name", "demo", "--json"],
            capture_output=True, text=True)
        doc = json.loads(show.stdout)
        assert doc["onion"] == onion
        assert doc["name"] == "demo"
        assert doc["key_path"].endswith("hs_ed25519_secret_key")

        # And status must eventually report ready with the address attached.
        deadline = time.time() + 300
        ready = False
        while time.time() < deadline:
            st = subprocess.run(
                [str(CLI), "status", "--container", "tor",
                 "--keys", str(tmp_path / "tor-keys"), "--json"],
                capture_output=True, text=True)
            sdoc = json.loads(st.stdout)
            if sdoc.get("ready"):
                ready = True
                assert sdoc["address"] == onion
                break
            time.sleep(5)
        assert ready, "status never reported ready"

        # doctor must verify the running container end to end, including that
        # the generated torrc still carries every hardening directive.
        doc = subprocess.run(
            [str(CLI), "doctor", "--container", "tor",
             "--keys", str(tmp_path / "tor-keys"), "--json"],
            capture_output=True, text=True)
        ddoc = json.loads(doc.stdout)
        assert ddoc["ok"], f"doctor failures: {ddoc.get('failures')}"
        assert any(c["check"].startswith("generated torrc") and c["ok"]
                   for c in ddoc["checks"]), "doctor did not check the torrc"
    finally:
        subprocess.run(_compose(tmp_path, "down", "-v"),
                       capture_output=True, timeout=120)
