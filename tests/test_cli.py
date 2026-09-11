"""Host unit tests for scripts/hiddenforge (the machine contract) and manifest.json.

These run on the host with no container and no docker: the CLI is stdlib-only and
side-effect free until a subcommand actually writes something. The property under
test is the machine contract itself - stable JSON field names, exit codes, name
validation (names become directories), and Tor v3 address derivation against a
real mkp224o-generated vector.
"""
import importlib.machinery
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CLI_PATH = REPO / "scripts" / "hiddenforge"
VANITY_PATH = REPO / "vanity.py"


def _load(path: Path, name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


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
                "volumes", "health", "address", "key", "exit_codes", "networks"):
        assert key in m, f"manifest missing {key!r}"
    assert m["name"] == "hiddenforge"
    assert m["address"]["command"].startswith("hiddenforge show")
    assert m["health"]["ready_field"] == "ready"
    assert m["volumes"][0]["contains"] == ["keys", "address"]
    assert m["address"]["file"].endswith("/hostname")
    assert m["key"]["secret"]["mode"] == "0600"


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


def test_setup_requires_backend_non_interactive(hf, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", type("S", (), {"isatty": lambda self: False})())
    rc = hf.main(["setup", "-o", str(tmp_path), "--json", "--non-interactive"])
    assert rc == hf.EXIT_USAGE
    doc = json.loads(capsys.readouterr().out)
    assert doc["ok"] is False


def test_setup_rejects_bad_backend(hf, tmp_path, capsys):
    rc = hf.main(["setup", "--backend", "web", "-o", str(tmp_path), "--json"])
    assert rc == hf.EXIT_USAGE


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
# exit-code contract
# ─────────────────────────────────────────────────────────────────────────────

def test_exit_codes_are_documented(hf):
    m = hf.build_manifest()
    for code in ("0", "1", "2", "3", "4", "130"):
        assert code in m["exit_codes"]
    assert m["exit_codes"]["4"].startswith("not ready")
