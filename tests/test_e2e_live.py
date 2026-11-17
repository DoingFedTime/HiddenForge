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
# How long a fresh key may take to be published, and then reported ready. A
# fresh Tor bootstrap plus first descriptor upload was measured at 365s on a
# slow directory fetch (Docker, 2026-09-26) and 27-252s across real reboots, so
# the old 300s limit failed healthy runs whenever the Tor network was slow
# (seen 2026-10-19: "No circuits are opened", passed on immediate re-run).
PUBLISH_DEADLINE_S = 600


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
    text = ("services:\n"
            "  tor:\n"
            f"    image: {IMAGE}\n"
            "    logging:\n"
            "      driver: json-file\n")
    # On a host whose default address pools are used up, name two free subnets:
    # HIDDENFORGE_E2E_SUBNETS=10.251.0.0/24,10.252.0.0/24 (internal, external).
    subnets = os.environ.get("HIDDENFORGE_E2E_SUBNETS")
    if subnets:
        internal, external = (n.strip() for n in subnets.split(","))
        text += ("networks:\n"
                 f"  tor-internal:\n    ipam: {{config: [{{subnet: {internal}}}]}}\n"
                 f"  tor-external:\n    ipam: {{config: [{{subnet: {external}}}]}}\n")
    path.write_text(text)
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


def _assert_stack_up(proc):
    """Fail with the cause named, not with `assert 1 == 0`.

    A host that has run out of Docker subnets produces the same red as a broken
    entrypoint, and the two need completely different responses. Seen on a
    self-hosted runner shared with forty-five other compose projects: every
    acceptance test failed at `up`, with the real reason four lines into a
    captured stderr nobody reads before assuming a regression.
    """
    if proc.returncode == 0:
        return
    if "address pools have been fully subnetted" in (proc.stderr or ""):
        raise AssertionError(
            "docker has no free subnets left on this host, so the stack could "
            "not be created. This is the machine, not the code: free a network "
            "(`docker network ls`), or name two free subnets in "
            "HIDDENFORGE_E2E_SUBNETS, and re-run.\n" + proc.stderr)
    raise AssertionError(f"the stack did not come up:\n{proc.stderr}")


def _container_id(workdir) -> str:
    proc = subprocess.run(_compose(workdir, "ps", "-q", "tor", override=True),
                          capture_output=True, text=True, timeout=60, check=True)
    cid = proc.stdout.strip()
    assert cid, "the tor container is not running"
    return cid


def _host_pids(cid: str) -> dict[str, list[str]]:
    """Host PIDs of the container's processes by name. 3.0 has no shell or
    procps inside the image, so the processes are read from the host's /proc
    (status and mounts are world-readable; nothing here needs root)."""
    out = subprocess.run(["docker", "top", cid, "-eo", "pid,comm"], capture_output=True,
                         text=True, timeout=60, check=True).stdout.splitlines()[1:]
    pids: dict[str, list[str]] = {}
    for line in out:
        pid, comm = line.split(None, 1)
        pids.setdefault(comm.strip(), []).append(pid)
    return pids


def _proc_field(pid: str, field: str) -> str:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith(field + ":"):
            return line.split(":", 1)[1].split()[0]
    raise AssertionError(f"no {field} in /proc/{pid}/status")


@requires_image
def test_the_running_container_has_the_posture_the_fragment_promises(workdir):
    """The emitted fragment asks for a hardened runtime. This checks it got one.

    Every property here was previously an assertion about a YAML file rather
    than about a process: the fragment says `cap_drop: [ALL]` and `read_only`,
    and nothing confirmed that the Tor daemon actually ends up with an empty
    capability set, that the supervisor's irreversible drop really happened, or
    that the tmpfs mounts carry the flags the file asks for. A container that
    silently failed the drop would serve traffic and pass every other test.

    Measured live, so it is checked from inside the container against /proc.
    """
    entrypoint = _load(REPO / "entrypoint.py", "hf_entrypoint_e2e")
    subprocess.run([str(CLI), "setup", "--backend", "web:80", "--name", "demo",
                    "--keys", "./tor-keys", "--out", str(workdir)],
                   check=True, capture_output=True)
    shutil.copy(DEMO / "app.yml", workdir / "app.yml")
    shutil.copytree(DEMO / "site", workdir / "site")
    try:
        proc = subprocess.run(_compose(workdir, "up", "-d", override=True),
                              capture_output=True, text=True, timeout=300)
        _assert_stack_up(proc)

        published = workdir / "tor-keys" / "demo.onion"
        deadline = time.time() + PUBLISH_DEADLINE_S
        while time.time() < deadline and not published.exists():
            time.sleep(3)
        assert published.exists(), "address file was never published\n" + \
            subprocess.run(_compose(workdir, "logs", "--tail", "40", "tor",
                                    override=True),
                           capture_output=True, text=True).stdout

        cid = _container_id(workdir)
        pids = _host_pids(cid)
        assert pids.get("tor"), f"no tor process in the container: {pids}"
        tor_pid = pids["tor"][0]
        sup_pid = subprocess.run(["docker", "inspect", "-f", "{{.State.Pid}}", cid],
                                 capture_output=True, text=True, timeout=60,
                                 check=True).stdout.strip()   # the container's init

        # Tor: not root, and no capabilities at all. The uid change clears
        # permitted and effective; an empty ambient set keeps them cleared.
        assert _proc_field(tor_pid, "Uid") == "100"
        assert _proc_field(tor_pid, "CapEff") == "0" * 16
        assert _proc_field(tor_pid, "CapPrm") == "0" * 16
        # The guard monitors, the upload watcher and every helper run as tor
        # with nothing, too. They are the same binary as the supervisor (the
        # kernel truncates their names to 15 characters), so the supervisor
        # itself is left out by PID.
        helpers = [pid for comm, ps in pids.items() if comm.startswith("hiddenforge")
                   for pid in ps if pid != sup_pid]
        assert helpers, f"no guard monitor or watcher in the container: {pids}"
        for pid in helpers:
            assert _proc_field(pid, "Uid") == "100", (pid, pids)
            assert _proc_field(pid, "CapEff") == "0" * 16

        # The supervisor stays root for the container's life, so what bounds it
        # is its capability set. The drop must have happened, and must have come
        # out of PERMITTED -- a capability still permitted can be raised again.
        expected = f"{entrypoint.POST_SETUP_CAPS:016x}"
        assert _proc_field(sup_pid, "CapEff") == expected
        assert _proc_field(sup_pid, "CapPrm") == expected
        retained = entrypoint.POST_SETUP_CAPS
        assert not retained & (1 << entrypoint.CAP_CHOWN), "CHOWN was not given up"
        assert not retained & (1 << entrypoint.CAP_FOWNER), "FOWNER was not given up"

        for pid, who in ((tor_pid, "tor"), (sup_pid, "the supervisor")):
            assert _proc_field(pid, "NoNewPrivs") == "1", who
            # 2 == SECCOMP_MODE_FILTER. Docker's default profile applies to the
            # whole container; Tor's own Sandbox 1 stacks on top of it.
            assert _proc_field(pid, "Seccomp") == "2", who

        # read_only: true, checked by trying to write rather than by reading
        # YAML: the engine itself must refuse a file copied into the rootfs.
        probe = workdir / "rootfs-write-probe"
        probe.write_text("x")
        wrote = subprocess.run(["docker", "cp", str(probe), f"{cid}:/rootfs-write-probe"],
                               capture_output=True, text=True, timeout=60)
        assert wrote.returncode != 0, "the root filesystem is writable"

        # These are mount points inside the container under test, not temporary
        # files this process creates.
        mount_lines = Path(f"/proc/{tor_pid}/mounts").read_text().splitlines()
        mounts = {f[1]: f[3].split(",") for f in (line.split() for line in mount_lines)}
        for mount in ("/tmp", "/etc/tor", "/var/lib/tor"):  # noqa: S108
            for flag in ("noexec", "nosuid", "nodev"):
                assert flag in mounts[mount], f"{mount} is missing {flag}: {mounts[mount]}"
        # Tor's DataDirectory: 0700, owned by tor (Tor also refuses to start otherwise).
        assert "mode=700" in mounts["/var/lib/tor"] and "uid=100" in mounts["/var/lib/tor"]

        # The key's modes, as the image's own doctor reports them.
        doc = subprocess.run(_compose(workdir, "exec", "-T", "tor", "hiddenforge", "doctor",
                                      "--keys-only", "--json", override=True),
                             capture_output=True, text=True, timeout=60)
        checks = {c["check"]: c for c in json.loads(doc.stdout)["checks"]}
        assert checks["key dir demo is 0700"]["ok"], checks
        assert checks["secret key demo is 0600"]["ok"], checks
    finally:
        subprocess.run(_compose(workdir, "down", "-v", override=True),
                       capture_output=True, timeout=120)


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
        _assert_stack_up(proc)

        published = workdir / "tor-keys" / "demo.onion"
        deadline = time.time() + PUBLISH_DEADLINE_S
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
        deadline = time.time() + PUBLISH_DEADLINE_S
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


# ─────────────────────────────────────────────────────────────────────────────
# upgrading in place keeps the address; rolling back keeps it too
# ─────────────────────────────────────────────────────────────────────────────

PREVIOUS_IMAGE = os.environ.get("HIDDENFORGE_PREVIOUS_IMAGE",
                                "sambent.dev/sam/hiddenforge:2.0.4")


def _boot(image: str, keys: Path) -> str:
    """Start `image` on `keys` with the shipped Docker flags; no network is
    needed -- Tor creates the service key before it ever reaches the network."""
    cid = subprocess.run(
        ["docker", "run", "-d", "--network", "none", "--cap-drop", "ALL",
         *[a for c in ("CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID")
           for a in ("--cap-add", c)],
         "--security-opt", "no-new-privileges", "--read-only",
         "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",  # noqa: S108 - a container mount spec
         "--tmpfs", "/etc/tor:rw,noexec,nosuid,nodev,size=8m",
         "--tmpfs", "/var/lib/tor:rw,noexec,nosuid,nodev,size=64m,uid=100,gid=101,mode=0700",
         "-e", "MYSITE_TOR_SERVICE_HOSTS=80:127.0.0.1:8080",
         "-v", f"{keys}:/var/lib/tor/hidden_service", image],
        capture_output=True, text=True, check=True).stdout.strip()
    return cid


def _identity(keys: Path) -> tuple[str, str]:
    """(sha256 of the secret key, hostname), read as root in a throwaway container.

    Read with the PREVIOUS image (2.x has a shell and coreutils; 3.0 has
    neither), which is also the one the upgrade is tested against."""
    out = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "sh", "-v", f"{keys}:/k:ro", PREVIOUS_IMAGE,
         "-c", "sha256sum /k/mysite/hs_ed25519_secret_key; cat /k/mysite/hostname"],
        capture_output=True, text=True, check=True).stdout.split()
    return out[0], out[-1]


def _run_for(image: str, keys: Path, seconds: int = 20) -> str:
    cid = _boot(image, keys)
    try:
        time.sleep(seconds)
        return subprocess.run(["docker", "inspect", "-f", "{{.State.Status}}", cid],
                              capture_output=True, text=True, check=True).stdout.strip()
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, check=False)


@requires_image
def test_upgrading_and_rolling_back_keep_the_address(workdir):
    """The wiki promises an in-place upgrade from the previous release keeps the
    same address, and that rolling back does too. That was a claim; this makes it
    a release gate. The key IS the address, and nobody gets a second one."""
    if subprocess.run(["docker", "image", "inspect", PREVIOUS_IMAGE],
                      capture_output=True).returncode != 0:
        pulled = subprocess.run(["docker", "pull", PREVIOUS_IMAGE],
                                capture_output=True, text=True)
        assert pulled.returncode == 0, (
            f"cannot fetch the previous release {PREVIOUS_IMAGE} to test the upgrade "
            f"from (set HIDDENFORGE_PREVIOUS_IMAGE): {pulled.stderr.strip()[-300:]}")
    keys = workdir / "keys"
    keys.mkdir()
    assert _run_for(PREVIOUS_IMAGE, keys) == "running"
    before = _identity(keys)
    assert ONION_RE.fullmatch(before[1]), before

    assert _run_for(IMAGE, keys) == "running", "the new image did not stay up"
    assert _identity(keys) == before, "upgrading changed the identity"

    assert _run_for(PREVIOUS_IMAGE, keys) == "running", "rollback did not stay up"
    assert _identity(keys) == before, "rolling back changed the identity"


# ─────────────────────────────────────────────────────────────────────────────
# an existing compose file keeps working; Tor keeps its guards across restarts
# ─────────────────────────────────────────────────────────────────────────────

# The healthcheck every compose file written before 3.0.1 declares. Those files
# live on operators' hosts; an image update cannot change them.
LEGACY_HEALTHCHECK = ["CMD", "su-exec", "tor", "python3", "/usr/local/bin/healthcheck.py"]


def _health(cid: str) -> str:
    return subprocess.run(["docker", "inspect", "-f", "{{.State.Health.Status}}", cid],
                          capture_output=True, text=True, check=False).stdout.strip()


def _wait_healthy(cid: str, deadline_s: int = PUBLISH_DEADLINE_S) -> None:
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        if _health(cid) == "healthy":
            return
        time.sleep(5)
    raise AssertionError(f"the container never became healthy (last: {_health(cid)})")


def _read_as_root(path: Path) -> str:
    """A tor-owned 0600 file in the key volume, read in a throwaway container."""
    return subprocess.run(
        ["docker", "run", "--rm", "-v", f"{path.parent}:/d:ro", "alpine:3.23.5",
         "cat", f"/d/{path.name}"],
        capture_output=True, text=True, check=False).stdout


def _guards(state: str) -> set[str]:
    return set(re.findall(r"^Guard .*\brsa_id=([0-9A-F]{40})\b", state, re.M))


def _demo_stack(workdir: Path, extra: str) -> list[str]:
    """`setup` output for the demo, plus one more merge layer (`extra`)."""
    subprocess.run([str(CLI), "setup", "--backend", "web:80", "--name", "demo",
                    "--keys", "./tor-keys", "--out", str(workdir)],
                   check=True, capture_output=True)
    shutil.copy(DEMO / "app.yml", workdir / "app.yml")
    shutil.copytree(DEMO / "site", workdir / "site")
    (workdir / "extra.yml").write_text(extra)
    return [*_compose(workdir, override=True), "-f", str(workdir / "extra.yml")]


@requires_image
def test_an_older_compose_file_stays_healthy_and_tor_keeps_its_guards(workdir):
    """Update in place with a compose file from an earlier release: the stack
    must become healthy through the healthcheck that file declares, every other
    old command must be refused, and a restart must hand Tor back the guards it
    had chosen instead of making it choose new ones."""
    hc = json.dumps(LEGACY_HEALTHCHECK)
    compose = _demo_stack(workdir, (
        "services:\n  tor:\n    healthcheck:\n"
        f"      test: {hc}\n      interval: 10s\n      start_period: 0s\n"))
    state = workdir / "tor-keys" / "demo" / "tor-state"
    try:
        proc = subprocess.run([*compose, "up", "-d"], capture_output=True, text=True,
                              timeout=300)
        _assert_stack_up(proc)
        cid = _container_id(workdir)
        _wait_healthy(cid)
        replay = subprocess.run(["bash", str(REPO / "tests" / "rust" / "compat_replay.sh"),
                                 cid, "demo"], capture_output=True, text=True, timeout=300)
        assert replay.returncode == 0, replay.stdout + replay.stderr

        subprocess.run([*compose, "stop", "tor"], check=True, capture_output=True,
                       timeout=120)
        before = _read_as_root(state)
        assert before.startswith("# Tor state file"), "no Tor state was saved at shutdown"
        assert _guards(before), "the saved state holds no entry guards"

        subprocess.run([*compose, "start", "tor"], check=True, capture_output=True,
                       timeout=120)
        _wait_healthy(cid)
        logs = subprocess.run(["docker", "logs", cid], capture_output=True, text=True).stdout
        assert "Restored Tor's saved state" in logs, logs[-2000:]
        subprocess.run([*compose, "stop", "tor"], check=True, capture_output=True,
                       timeout=120)
        after = _read_as_root(state)
        assert _guards(before) <= _guards(after), (
            "Tor chose new guards after the restart\n"
            f"before: {sorted(_guards(before))}\nafter: {sorted(_guards(after))}")
    finally:
        subprocess.run([*compose, "down", "-v"], capture_output=True, timeout=120)


@requires_image
def test_a_fresh_setup_uses_no_old_command(workdir):
    """What `setup` writes for a new install names only `hiddenforge` commands."""
    subprocess.run([str(CLI), "setup", "--backend", "web:80", "--name", "demo",
                    "--keys", "./tor-keys", "--out", str(workdir)],
                   check=True, capture_output=True)
    for name in ("compose.service.yml", "deploy.sh", "README.txt"):
        text = (workdir / name).read_text()
        for old in ("su-exec", "python3", "healthcheck.py", "entrypoint.py", " cat ",
                    "sh -c"):
            assert old not in text, f"{name} still uses {old!r}"


@requires_image
def test_the_backend_can_tell_circuits_apart_when_it_asks_to(workdir):
    """`<NAME>_TOR_EXPORT_CIRCUIT_ID=haproxy`: fetched through Tor on two
    isolated circuits, the backend sees two different circuit addresses in the
    PROXY header."""
    (workdir / "nginx.conf").write_text(
        "server {\n  listen 80 proxy_protocol;\n"
        "  location / { default_type text/plain; return 200 \"$proxy_protocol_addr\\n\"; }\n}\n")
    compose = _demo_stack(workdir, (
        "services:\n  tor:\n    environment:\n      DEMO_TOR_EXPORT_CIRCUIT_ID: haproxy\n"
        "  web:\n    volumes:\n"
        "      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro\n"))
    port = 10000 + int.from_bytes(os.urandom(2), "big") % 50000
    client = f"hf-e2e-client-{os.getpid()}"
    try:
        proc = subprocess.run([*compose, "up", "-d"], capture_output=True, text=True,
                              timeout=300)
        _assert_stack_up(proc)
        published = workdir / "tor-keys" / "demo.onion"
        deadline = time.time() + PUBLISH_DEADLINE_S
        while time.time() < deadline and not published.exists():
            time.sleep(3)
        assert published.exists(), "address file was never published"
        onion = published.read_text().strip()
        # A Tor client: the image's own tor, with only a SOCKS port.
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", client, "--user", "100:101",
             "--tmpfs", "/var/lib/tor:uid=100,gid=101,mode=0700",
             "-p", f"127.0.0.1:{port}:9050",
             "--entrypoint", "/usr/bin/tor", IMAGE,
             "--SocksPort", "0.0.0.0:9050", "--DataDirectory", "/var/lib/tor/c"],
            check=True, capture_output=True)
        seen = {}
        deadline = time.time() + PUBLISH_DEADLINE_S
        while time.time() < deadline and len(seen) < 2:
            for user in ("a", "b"):
                if user in seen:
                    continue
                r = subprocess.run(
                    ["curl", "-sS", "-m", "60", "--socks5-hostname",
                     f"{user}:x@127.0.0.1:{port}", f"http://{onion}/"],
                    capture_output=True, text=True, check=False)
                if r.returncode == 0 and r.stdout.strip():
                    seen[user] = r.stdout.strip()
            time.sleep(5)
        assert len(seen) == 2, f"the onion was not reachable on two circuits: {seen}"
        for addr in seen.values():
            assert re.fullmatch(r"fc00:dead:beef:4dad::[0-9a-f:]+", addr), addr
        assert seen["a"] != seen["b"], "two isolated circuits reached the backend as one"
    finally:
        subprocess.run(["docker", "rm", "-f", client], capture_output=True, check=False)
        subprocess.run([*compose, "down", "-v"], capture_output=True, timeout=120)
