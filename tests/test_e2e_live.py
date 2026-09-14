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


def _rmtree_as_root(path):
    """Remove a scratch tree the container chowned to tor/root.

    pytest's own tmp_path cleanup cannot delete the tor-owned 0700 key
    directories the container writes into the bind mount, so every E2E run ended
    in a wall of `(rm_rf) ... Directory not empty` warnings -- which trains
    everyone to ignore stderr, where the next real failure will appear. The
    confirmed cause is exactly that uid mismatch; removing the tree from a
    throwaway root container is the fix.
    """
    parent = path.parent
    # Pin the platform to the daemon's own architecture. A stale local tag for a
    # multi-arch image (pulled earlier for arm64) otherwise makes this helper run
    # under emulation and fail with "exec format error", silently leaving the
    # scratch tree behind -- which is how the teardown noise started.
    arch = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Arch}}"],
        capture_output=True, text=True, check=False).stdout.strip()
    platform = f"linux/{arch}" if arch else "linux/amd64"
    subprocess.run(
        ["docker", "run", "--rm", "--platform", platform,
         "-v", f"{parent}:/p", "alpine:3.23.5",
         "rm", "-rf", f"/p/{path.name}"],
        capture_output=True, check=False)


@pytest.fixture
def workdir():
    """A scratch directory pytest will NOT try to clean up itself."""
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="hiddenforge-e2e-"))
    try:
        yield d
    finally:
        _rmtree_as_root(d)
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


def _compose(tmp: Path, *extra, override: bool = False):
    cmd = ["docker", "compose", "-f", str(tmp / "app.yml"),
           "-f", str(tmp / "compose.service.yml")]
    if override:
        cmd += ["-f", str(_write_override(tmp))]
    return cmd + list(extra)


def _write_override(tmp: Path) -> Path:
    """A merge layer that makes the running stack testable.

    Two things the emitted fragment gets right for production and wrong for a
    test:

    * It pins `image: sambent.dev/sam/hiddenforge:latest` by name, so the stack
      ran whatever happened to carry that tag locally -- NOT the image under
      test. This module's docstring has always claimed the image under test is
      $HIDDENFORGE_TEST_IMAGE; for the headline test that was simply untrue, and
      a run against a three-week-old `:latest` was reported as a result for a
      branch that image predates.
    * It sets `logging: driver: none`, which is right for an onion service and
      leaves `docker logs` empty exactly when a failing test needs it. Every
      failure here was "address file was never published" with no cause attached.

    The override is a separate merge layer, so `docker compose config` in
    test_emitted_fragment_validates still validates the fragment as shipped.
    """
    path = tmp / "e2e-override.yml"
    path.write_text(
        "services:\n"
        "  tor:\n"
        f"    image: {IMAGE}\n"
        "    logging:\n"
        "      driver: json-file\n")
    return path


@requires_image
def test_emitted_fragment_validates(workdir):
    subprocess.run([str(CLI), "setup", "--backend", "web:80", "--name", "demo",
                    "--out", str(workdir)], check=True, capture_output=True)
    shutil.copy(DEMO / "app.yml", workdir / "app.yml")
    proc = subprocess.run(_compose(workdir, "config"), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


@requires_image
def test_vanity_short_prefix_matches(workdir):
    keys = workdir / "keys"
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
def test_demo_publishes_and_show_agrees(workdir):
    subprocess.run([str(CLI), "setup", "--backend", "web:80", "--name", "demo",
                    "--keys", "./tor-keys", "--out", str(workdir)],
                   check=True, capture_output=True)
    shutil.copy(DEMO / "app.yml", workdir / "app.yml")
    shutil.copytree(DEMO / "site", workdir / "site")
    try:
        proc = subprocess.run(_compose(workdir, "up", "-d", override=True),
                              capture_output=True, text=True, timeout=300)
        assert proc.returncode == 0, proc.stderr

        published = workdir / "tor-keys" / "demo.onion"
        deadline = time.time() + 300
        while time.time() < deadline and not published.exists():
            time.sleep(3)
        # Attach the container's own output to the failure. Without it this
        # assertion says only that something did not happen, which is how a
        # stale-image run got mistaken for a branch regression.
        assert published.exists(), "address file was never published\n" + \
            subprocess.run(_compose(workdir, "logs", "--tail", "40", "tor",
                                    override=True),
                           capture_output=True, text=True).stdout
        onion = published.read_text().strip()
        assert ONION_RE.fullmatch(onion), onion

        # The host CLI must report the same address, without docker exec.
        show = subprocess.run(
            [str(CLI), "show", "--keys", str(workdir / "tor-keys"),
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
                 "--keys", str(workdir / "tor-keys"), "--json"],
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
             "--keys", str(workdir / "tor-keys"), "--json"],
            capture_output=True, text=True)
        ddoc = json.loads(doc.stdout)
        assert ddoc["ok"], f"doctor failures: {ddoc.get('failures')}"
        assert any(c["check"].startswith("generated torrc") and c["ok"]
                   for c in ddoc["checks"]), "doctor did not check the torrc"
    finally:
        subprocess.run(_compose(workdir, "down", "-v", override=True),
                       capture_output=True, timeout=120)
