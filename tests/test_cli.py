"""Host unit tests for scripts/hiddenforge (the machine contract) and manifest.json.

These run on the host with no container and no docker: the CLI is stdlib-only and
side-effect free until a subcommand actually writes something. The property under
test is the machine contract itself - stable JSON field names, exit codes, name
validation (names become directories), and Tor v3 address derivation against a
real mkp224o-generated vector.
"""
import json
import os
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
    assert "podman-compose" in (tmp_path / "deploy.sh").read_text()


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


# ─────────────────────────────────────────────────────────────────────────────
# doctor: torrc hardening directives
# ─────────────────────────────────────────────────────────────────────────────

def _fake_inspect():
    return {
        "HostConfig": {
            "CapDrop": ["ALL"],
            "CapAdd": ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"],
            "SecurityOpt": ["no-new-privileges:true", "seccomp=unconfined",
                            "apparmor=docker-default"],
            "ReadonlyRootfs": True,
            "PidsLimit": 256,
            "Memory": 536870912,
            "MemorySwap": 536870912,
            "LogConfig": {"Type": "none"},
        },
        "NetworkSettings": {"Ports": {}},
        "AppArmorProfile": "docker-default",
        "State": {"Running": True},
    }


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

def _sigdir(tmp_path, digest="sha256:abc"):
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
    monkeypatch.setattr(hf, "_resolve_registry_digest", lambda i: ("sha256:abc", None))
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda s, i, b: (True, "Good"))
    monkeypatch.setattr(hf, "_verify_mldsa_signature", lambda s: (None, "pqsign not installed"))
    rc = hf.main(["verify-image", "example/img:1", "--sigdir", str(d), "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["digest_match"] is True and doc["ssh_fido2"] is True


def test_verify_image_digest_mismatch_fails(hf, tmp_path, capsys, monkeypatch):
    d = _sigdir(tmp_path)
    monkeypatch.setattr(hf, "_resolve_registry_digest", lambda i: ("sha256:deadbeef", None))
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda s, i, b: (True, "Good"))
    monkeypatch.setattr(hf, "_verify_mldsa_signature", lambda s: (None, "n/a"))
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
    monkeypatch.setattr(hf, "_verify_ssh_signature", lambda s, i, b: (True, "Good"))
    monkeypatch.setattr(hf, "_verify_mldsa_signature", lambda s: (True, "ok"))
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
