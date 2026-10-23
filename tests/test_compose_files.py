"""The two shipped compose files, and the fragment `setup` emits, held to one shape.

docker-compose.yml and podman-compose.yml carry the same hardening block by
hand. They differ on purpose in a few places (documented in each file's header
and in docs/INTEGRATION.md), and nothing else may differ. A key added to one
file and forgotten in the other, a capability dropped from one, or a hardening
key deleted outright fails here, before anyone runs the file.

These tests parse the YAML; they do not need Docker or Podman. CI also runs
`docker compose config -q` over both files, which catches what a parser cannot:
an option the engine rejects.
"""
from pathlib import Path

import pytest
import yaml

from loader import load_file, repo_root

REPO = repo_root(__file__)
DOCKER = REPO / "docker-compose.yml"
PODMAN = REPO / "podman-compose.yml"

DOCKER_CAPS = {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"}
# Rootless Podman: the container's root already owns the bind mount, so
# DAC_OVERRIDE and FOWNER are not needed and are not granted.
PODMAN_CAPS = {"CHOWN", "SETUID", "SETGID"}
# `setup --runtime podman` cannot tell rootful from rootless Podman, and the
# three-capability set breaks a rootful first boot, so the fragment keeps five.
FRAGMENT_CAPS = DOCKER_CAPS

# Keys of services.tor that are allowed to differ between the two files. Every
# other key must be present in both and equal.
#   restart        Docker: unless-stopped. Podman: always (it is what brings a
#                  rootless container back after a reboot).
#   cap_add        see DOCKER_CAPS / PODMAN_CAPS above.
#   security_opt   Docker adds apparmor=docker-default; rootless Podman has no
#                  AppArmor profile to name.
#   tmpfs          Docker sets uid/gid/mode on /var/lib/tor; Podman rejects them.
#   healthcheck    Docker only: rootless Podman 4.9 never restarts a container
#                  with a healthcheck when no systemd user session is reachable.
ALLOWED_TOR_DIFFERENCES = {"restart", "cap_add", "security_opt", "tmpfs", "healthcheck"}
DOCKER_ONLY_TMPFS_OPTIONS = ("uid=", "gid=", "mode=")


def _load(path: Path) -> dict:
    with path.open() as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def docker():
    return _load(DOCKER)


@pytest.fixture(scope="module")
def podman():
    return _load(PODMAN)


@pytest.fixture(scope="module")
def fragments(tmp_path_factory):
    hf = load_file(REPO / "scripts" / "hiddenforge", "hf_cli_compose")
    out = {}
    for runtime in ("docker", "podman"):
        d = tmp_path_factory.mktemp(f"setup-{runtime}")
        rc = hf.main(["setup", "--backend", "web:80", "--name", "blog",
                      "--keys", "./tor-keys", "-o", str(d), "--runtime", runtime,
                      "--json"])
        assert rc == 0
        out[runtime] = _load(d / "compose.service.yml")
    return out


def _strip_docker_tmpfs_options(entries):
    stripped = []
    for entry in entries:
        path, _, opts = entry.partition(":")
        kept = [o for o in opts.split(",") if not o.startswith(DOCKER_ONLY_TMPFS_OPTIONS)]
        stripped.append(f"{path}:{','.join(kept)}")
    return stripped


def _assert_hardened_tor(doc, where):
    tor = doc["services"]["tor"]
    assert doc["networks"]["tor-internal"]["internal"] is True, where
    assert "tor-external" in doc["networks"], where
    assert tor["cap_drop"] == ["ALL"], where
    assert tor["read_only"] is True, where
    assert "no-new-privileges:true" in tor["security_opt"], where
    assert tor["logging"] == {"driver": "none"}, where
    assert tor["dns"] == "127.0.0.1", where
    # Equal limits mean no swap: key material is never paged to disk.
    assert tor["memswap_limit"] == tor["mem_limit"], where
    assert tor["pids_limit"], where
    assert sorted(tor["networks"]) == ["tor-external", "tor-internal"], where
    for entry in tor["tmpfs"]:
        opts = entry.partition(":")[2].split(",")
        assert {"noexec", "nosuid", "nodev"} <= set(opts), (where, entry)


@pytest.mark.parametrize("path", [DOCKER, PODMAN], ids=["docker", "podman"])
def test_shipped_file_is_hardened(path):
    _assert_hardened_tor(_load(path), path.name)


@pytest.mark.parametrize("path", [DOCKER, PODMAN], ids=["docker", "podman"])
def test_no_service_publishes_a_port(path):
    for name, svc in _load(path)["services"].items():
        assert "ports" not in svc, f"{path.name}: service {name} publishes ports"


@pytest.mark.parametrize("path", [DOCKER, PODMAN], ids=["docker", "podman"])
def test_backend_is_internal_only_and_hardened(path):
    web = _load(path)["services"]["web"]
    assert web["networks"] == ["tor-internal"], path.name
    assert web["cap_drop"] == ["ALL"], path.name
    assert web["read_only"] is True, path.name
    assert "no-new-privileges:true" in web["security_opt"], path.name


def test_capability_sets(docker, podman, fragments):
    assert set(docker["services"]["tor"]["cap_add"]) == DOCKER_CAPS
    assert set(podman["services"]["tor"]["cap_add"]) == PODMAN_CAPS
    assert set(fragments["podman"]["services"]["tor"]["cap_add"]) == FRAGMENT_CAPS
    assert set(fragments["docker"]["services"]["tor"]["cap_add"]) == FRAGMENT_CAPS


def test_tor_service_differs_only_where_documented(docker, podman):
    d, p = docker["services"]["tor"], podman["services"]["tor"]
    assert set(d) - {"healthcheck"} == set(p), (
        "services.tor keys differ between the files: "
        f"docker-only {sorted(set(d) - set(p))}, podman-only {sorted(set(p) - set(d))}")
    for key in sorted(set(d) - ALLOWED_TOR_DIFFERENCES):
        assert d[key] == p[key], f"services.tor.{key} differs between the two files"


def test_documented_differences_are_exactly_what_is_documented(docker, podman):
    d, p = docker["services"]["tor"], podman["services"]["tor"]
    assert d["restart"] == "unless-stopped"
    assert p["restart"] == "always"
    assert d["security_opt"] == p["security_opt"] + ["apparmor=docker-default"]
    assert _strip_docker_tmpfs_options(d["tmpfs"]) == p["tmpfs"]
    assert not any(o in e for e in p["tmpfs"] for o in DOCKER_ONLY_TMPFS_OPTIONS)
    assert "healthcheck" in d
    assert "healthcheck" not in p


def test_top_level_networks_match(docker, podman):
    assert docker["networks"] == podman["networks"]


@pytest.mark.parametrize("runtime", ["docker", "podman"])
def test_emitted_fragment_is_hardened(fragments, runtime):
    _assert_hardened_tor(fragments[runtime], f"setup --runtime {runtime}")
