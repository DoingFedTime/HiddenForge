"""Host tests for the encrypted backup/restore lifecycle.

Skipped when gpg is unavailable. These exercise the real gpg invocation (AEAD),
including the fail-closed paths: a wrong passphrase and an unauthenticated tool.
"""
import json
import os
import shutil
from pathlib import Path

import pytest

from loader import repo_root

REPO = repo_root(__file__)
CLI_PATH = REPO / "scripts" / "hiddenforge"
PUBLIC_TAG = b"== ed25519v1-public: type0 =="

pytestmark = pytest.mark.skipif(shutil.which("gpg") is None,
                                reason="gpg not installed")


def _load(path: Path, name: str):
    """Load a file without the bytecode cache (see tests/loader.py)."""
    from loader import load_file
    return load_file(path, name)


@pytest.fixture(scope="module")
def hf():
    return _load(CLI_PATH, "hf_cli_backup")


@pytest.fixture
def keys(tmp_path):
    d = tmp_path / "tor-keys" / "app"
    d.mkdir(parents=True)
    (d / "hs_ed25519_public_key").write_bytes(PUBLIC_TAG.ljust(32, b"\x00") + b"\x11" * 32)
    (d / "hs_ed25519_secret_key").write_bytes(b"\x22" * 96)
    (d / "hostname").write_text("a" * 56 + ".onion\n")
    for p in d.iterdir():
        os.chmod(p, 0o600)
    os.chmod(d, 0o700)
    return tmp_path / "tor-keys"


def _run(hf, capsys, argv):
    rc = hf.main(argv)
    return rc, json.loads(capsys.readouterr().out)


def test_backup_restore_roundtrip(hf, keys, tmp_path, capsys):
    pp = tmp_path / "pp"
    pp.write_text("correct horse battery staple\n")
    out = tmp_path / "keys.tar.gpg"
    rc, doc = _run(hf, capsys, ["backup", "--keys", str(keys), "--out", str(out),
                                "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    assert rc == 0 and doc["ok"] and doc["tool"] == "gpg"
    assert out.exists() and (os.stat(out).st_mode & 0o777) == 0o600

    dest = tmp_path / "restored"
    rc, doc = _run(hf, capsys, ["restore", "--keys", str(dest), "--input", str(out),
                                "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    assert rc == 0 and doc["ok"]
    assert (dest / "app" / "hs_ed25519_secret_key").read_bytes() == b"\x22" * 96
    assert (dest / "app" / "hostname").read_text().strip() == "a" * 56 + ".onion"


def test_wrong_passphrase_fails_closed(hf, keys, tmp_path, capsys):
    good = tmp_path / "good"
    good.write_text("right passphrase\n")
    bad = tmp_path / "bad"
    bad.write_text("wrong passphrase\n")
    out = tmp_path / "keys.tar.gpg"
    assert hf.main(["backup", "--keys", str(keys), "--out", str(out), "--tool", "gpg",
                    "--passphrase-file", str(good), "--json"]) == 0
    capsys.readouterr()
    rc = hf.main(["restore", "--keys", str(tmp_path / "r"), "--input", str(out),
                  "--tool", "gpg", "--passphrase-file", str(bad), "--json"])
    assert rc == hf.EXIT_FAIL
    doc = json.loads(capsys.readouterr().out)
    assert doc["ok"] is False


def test_backup_refuses_openssl(hf, keys, tmp_path, capsys):
    rc = hf.main(["backup", "--keys", str(keys), "--out", str(tmp_path / "x.enc"),
                  "--tool", "openssl", "--json"])
    assert rc == hf.EXIT_USAGE


def test_restore_refuses_conflict_without_force(hf, keys, tmp_path, capsys):
    pp = tmp_path / "pp"
    pp.write_text("pass\n")
    out = tmp_path / "keys.tar.gpg"
    hf.main(["backup", "--keys", str(keys), "--out", str(out), "--tool", "gpg",
             "--passphrase-file", str(pp), "--json"])
    capsys.readouterr()
    # Restoring onto the same directory must refuse: the key files already exist.
    rc = hf.main(["restore", "--keys", str(keys), "--input", str(out), "--tool", "gpg",
                  "--passphrase-file", str(pp), "--json"])
    assert rc == hf.EXIT_FAIL
    doc = json.loads(capsys.readouterr().out)
    assert "app/hs_ed25519_secret_key" in doc["conflicts"]


def test_restore_force_archives_nested_conflicts(hf, keys, tmp_path, capsys):
    """Regression: archiving a conflict under <name>/ needs its parent dir.

    os.rename into .replaced-<t>/app/... used to raise FileNotFoundError because
    the nested parent was never created, so restore --force aborted.
    """
    pp = tmp_path / "pp"
    pp.write_text("pass\n")
    out = tmp_path / "keys.tar.gpg"
    assert hf.main(["backup", "--keys", str(keys), "--out", str(out), "--tool", "gpg",
                    "--passphrase-file", str(pp), "--json"]) == 0
    capsys.readouterr()
    # Make the on-disk key differ so the restore is a genuine conflict.
    (keys / "app" / "hs_ed25519_secret_key").write_bytes(b"\x33" * 96)
    rc = hf.main(["restore", "--keys", str(keys), "--input", str(out), "--tool", "gpg",
                  "--passphrase-file", str(pp), "--force", "--json"])
    assert rc == 0, capsys.readouterr().out
    doc = json.loads(capsys.readouterr().out)
    archived = Path(doc["archived"])
    assert (archived / "app" / "hs_ed25519_secret_key").exists(), \
        "nested conflict was not archived"
    assert (keys / "app" / "hs_ed25519_secret_key").read_bytes() == b"\x22" * 96


def test_restore_forces_key_modes_ignoring_archive(hf, tmp_path, capsys):
    """A crafted archive must not leave a key world-readable.

    The restorer used to honour the tar member's own mode (`m.mode or 0o600`),
    so an archive declaring 0644 on hs_ed25519_secret_key was restored 0644.
    Modes are now forced: 0700 on directories, 0600 on files.
    """
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        d = tarfile.TarInfo("app")
        d.type = tarfile.DIRTYPE
        d.mode = 0o755
        tar.addfile(d)
        f = tarfile.TarInfo("app/hs_ed25519_secret_key")
        f.size = 6
        f.mode = 0o644
        tar.addfile(f, io.BytesIO(b"secret"))

    pp = tmp_path / "pp"
    pp.write_text("a passphrase\n")
    blob = tmp_path / "keys.tar.gpg"
    ciphertext, _mode = hf._encrypt_bytes("gpg", buf.getvalue(), "a passphrase")
    blob.write_bytes(ciphertext)

    keys = tmp_path / "restored"
    rc = hf.main(["restore", "--keys", str(keys), "--input", str(blob),
                  "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    assert rc == 0, capsys.readouterr().out
    assert os.stat(keys / "app").st_mode & 0o777 == 0o700, "directory mode not forced"
    assert os.stat(keys / "app" / "hs_ed25519_secret_key").st_mode & 0o777 == 0o600, \
        "file mode not forced"


def test_backup_empty_dir_refused(hf, tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    pp = tmp_path / "pp"
    pp.write_text("pass\n")
    rc = hf.main(["backup", "--keys", str(empty), "--out", str(tmp_path / "e.gpg"),
                  "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    assert rc == hf.EXIT_USAGE


def test_backup_default_tool_works_non_interactively(hf, keys, tmp_path, capsys):
    """Regression: the default used to pick age, which cannot take a passphrase
    file, so `backup --out x --passphrase-file pp` failed whenever age was
    installed and no --tool was given."""
    pp = tmp_path / "pp"
    pp.write_text("a passphrase\n")
    out = tmp_path / "keys.tar"  # no suffix hint
    rc, doc = _run(hf, capsys, ["backup", "--keys", str(keys), "--out", str(out),
                                "--passphrase-file", str(pp), "--json"])
    assert rc == 0 and doc["ok"], doc
    assert doc["tool"] == "gpg"
    assert out.exists()


def test_encrypt_key_really_encrypts_and_roundtrips(hf, keys, tmp_path, capsys):
    """encrypt-key must produce an *encrypted* blob, not a plain tar.

    A tar stores member filenames in cleartext; if the secret key name appears in
    the blob the data was not encrypted.
    """
    pp = tmp_path / "pp"
    pp.write_text("a strong passphrase\n")
    rc, doc = _run(hf, capsys, ["encrypt-key", "--keys", str(keys), "--name", "app",
                                "--tool", "gpg", "--passphrase-file", str(pp),
                                "--delete-plaintext", "--json"])
    assert rc == 0 and doc["ok"] is True
    blob = Path(doc["archive"])
    assert blob.exists() and (os.stat(blob).st_mode & 0o777) == 0o600
    assert not (keys / "app").exists(), "--delete-plaintext must remove the plaintext"
    raw = blob.read_bytes()
    assert b"hs_ed25519_secret_key" not in raw, "blob is not encrypted (tar names visible)"

    rc, doc = _run(hf, capsys, ["decrypt-key", "--keys", str(keys), "--name", "app",
                                "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    assert rc == 0 and doc["ok"] is True
    assert (keys / "app" / "hs_ed25519_secret_key").read_bytes() == b"\x22" * 96


def test_decrypt_key_wrong_passphrase_fails_closed(hf, keys, tmp_path, capsys):
    good = tmp_path / "good"
    good.write_text("right\n")
    bad = tmp_path / "bad"
    bad.write_text("wrong\n")
    assert hf.main(["encrypt-key", "--keys", str(keys), "--name", "app", "--tool", "gpg",
                    "--passphrase-file", str(good), "--delete-plaintext", "--json"]) == 0
    capsys.readouterr()
    rc = hf.main(["decrypt-key", "--keys", str(keys), "--name", "app", "--tool", "gpg",
                  "--passphrase-file", str(bad), "--json"])
    assert rc == hf.EXIT_FAIL
    assert not (keys / "app").exists()
