"""Host tests for the encrypted backup/restore lifecycle.

Skipped when gpg is unavailable. These exercise the real gpg invocation (AEAD),
including the fail-closed paths: a wrong passphrase and an unauthenticated tool.
"""
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from loader import repo_root

REPO = repo_root(__file__)
CLI_PATH = REPO / "scripts" / "hiddenforge"
PUBLIC_TAG = b"== ed25519v1-public: type0 =="
# A fixture value, not a credential: every test writes it to a temp file and
# hands it to gpg, and nothing outside this file has ever been encrypted with it.
TEST_PASSPHRASE = "correct horse battery staple"  # noqa: S105

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


def test_encrypt_bytes_refuses_openssl_at_the_function(hf):
    """The openssl refusal must hold at the function, not only at the CLI.

    Found by mutation testing: cmd_backup rejects --tool openssl before
    _encrypt_bytes runs, so the identical guard INSIDE _encrypt_bytes was
    untested -- removing it failed no test. Direct callers still depend on it.
    """
    with pytest.raises(ValueError, match="openssl is refused"):
        hf._encrypt_bytes("openssl", b"secret", None)


def test_restore_rejects_path_traversal(hf, tmp_path, capsys):
    """A crafted archive must not write outside the keys directory.

    Also found by mutation testing: removing the `..` check from cmd_restore's
    member loop failed no test. The guard existed but nothing held it.
    """
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        # A legitimate key member alongside the hostile one, so the archive is a
        # plausible backup and the ONLY reason to refuse it is the traversal.
        # Without it, the "this archive holds no identity" check refuses first,
        # and this test passes even with the `..` guard deleted -- measured by
        # the mutation spot-check, which reported the guard SURVIVED.
        keep = tarfile.TarInfo("app/hs_ed25519_secret_key")
        keep.size = 4
        tar.addfile(keep, io.BytesIO(b"key!"))
        f = tarfile.TarInfo("../escaped")
        f.size = 6
        tar.addfile(f, io.BytesIO(b"secret"))

    pp = tmp_path / "pp"
    pp.write_text("a passphrase\n")
    blob = tmp_path / "keys.tar.gpg"
    ciphertext, _mode = hf._encrypt_bytes("gpg", buf.getvalue(), "a passphrase")
    blob.write_bytes(ciphertext)

    keys = tmp_path / "nested" / "restored"
    rc = hf.main(["restore", "--keys", str(keys), "--input", str(blob),
                  "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    assert rc != 0, "a path-traversal member must fail closed"
    assert not (tmp_path / "nested" / "escaped").exists()
    assert not (tmp_path / "escaped").exists()


def _sealed(hf, tmp_path, build):
    """An encrypted archive whose members `build(tar)` adds, plus its passphrase."""
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        build(tar, io)
    pp = tmp_path / "pp"
    pp.write_text("a passphrase\n")
    blob = tmp_path / "hostile.tar.gpg"
    ciphertext, _mode = hf._encrypt_bytes("gpg", buf.getvalue(), "a passphrase")
    blob.write_bytes(ciphertext)
    return blob, pp


def test_restore_rejects_an_absolute_member_path(hf, tmp_path, capsys):
    """`../` is not the only way out of the keys directory.

    `Path.is_absolute()` guards a member named "/etc/hiddenforge-owned", which
    carries no `..` at all. Dropping that half of the check was a *proven*
    mutation survivor: the suite stayed green while a malicious archive wrote
    outside the target directory. The `..` case has a test; this one did not.
    """
    escape = tmp_path / "absolute-escape"

    def build(tar, io):
        member = tar.tarinfo(str(escape))  # e.g. "/tmp/.../absolute-escape"
        member.size = 6
        tar.addfile(member, io.BytesIO(b"secret"))
        keep = tar.tarinfo("app/hs_ed25519_secret_key")
        keep.size = 4
        tar.addfile(keep, io.BytesIO(b"key!"))

    blob, pp = _sealed(hf, tmp_path, build)
    keys = tmp_path / "restored"
    rc = hf.main(["restore", "--keys", str(keys), "--input", str(blob),
                  "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    assert rc != 0, "an absolute member path must fail closed"
    assert not escape.exists(), "the archive wrote outside --keys"


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "device"])
def test_restore_rejects_link_and_device_members(hf, tmp_path, capsys, kind):
    """Non-regular members are refused before anything is extracted.

    Also a proven mutation survivor: dropping `issym()`/`islnk()` from the
    member walk let symlink and hardlink members through with the suite green.
    A symlink named `hostname` pointing at /etc/shadow turns a later write into
    a write through the link; a device node needs no explanation. None of the
    three has a legitimate reason to appear in a key backup -- `_tar_keys`
    writes regular files only.
    """
    import tarfile

    def build(tar, io):
        member = tar.tarinfo("app/hostname")
        if kind == "symlink":
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/shadow"
        elif kind == "hardlink":
            member.type = tarfile.LNKTYPE
            member.linkname = "app/hs_ed25519_secret_key"
        else:
            member.type = tarfile.CHRTYPE
            member.devmajor, member.devminor = 1, 3  # /dev/null
        tar.addfile(member)
        # See test_restore_rejects_path_traversal: a hostile archive that is
        # otherwise empty gets refused for holding no identity, which would let
        # this test pass with the member-type guard deleted.
        keep = tar.tarinfo("app/hs_ed25519_secret_key")
        keep.size = 4
        tar.addfile(keep, io.BytesIO(b"key!"))

    blob, pp = _sealed(hf, tmp_path, build)
    keys = tmp_path / "restored"
    rc = hf.main(["restore", "--keys", str(keys), "--input", str(blob),
                  "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    assert rc != 0, f"a {kind} member must fail closed"
    assert not (keys / "app" / "hostname").exists()


def test_an_oversized_key_volume_is_refused_before_it_is_read(hf, tmp_path,
                                                              monkeypatch):
    """The size budget must be a budget, not a post-mortem.

    It used to be checked against `len(data)` AFTER `path.read_bytes()`, so a
    single file larger than memory was already read in full by the time the guard
    ran. This walks the operator-supplied key volume, which the threat model
    explicitly allows to have been restored from untrusted media, so a planted
    file is in scope.

    Asserted by making read_bytes fail loudly: a correct implementation never
    reaches it for a file that blows the budget.
    """
    keys = tmp_path / "keys"
    (keys / "app").mkdir(parents=True)
    fat = keys / "app" / "hs_ed25519_secret_key"
    fat.write_bytes(b"x" * 64)

    real_stat = Path.stat

    def huge_stat(self, *a, **kw):
        result = real_stat(self, *a, **kw)
        if self.name == "hs_ed25519_secret_key":
            return os.stat_result((result.st_mode, result.st_ino, result.st_dev,
                                   result.st_nlink, result.st_uid, result.st_gid,
                                   10 * 1024 * 1024 * 1024, 0, 0, 0))
        return result

    def refuse_read(self, *a, **kw):
        raise AssertionError(f"{self.name} was read before the size guard ran")

    monkeypatch.setattr(Path, "stat", huge_stat)
    monkeypatch.setattr(Path, "read_bytes", refuse_read)
    # Key files are read through _read_nofollow now; refuse that too, so the
    # test still proves the guard runs BEFORE any read, whichever way it reads.
    monkeypatch.setattr(hf, "_read_nofollow",
                        lambda path, *a, **kw: refuse_read(path))
    with pytest.raises(ValueError, match="unexpectedly large"):
        hf._tar_keys(keys)


def test_a_key_file_swapped_for_a_symlink_is_not_read_through(hf, tmp_path,
                                                              monkeypatch):
    """rglob and is_symlink() are one lookup, the read is another. A file
    replaced by a symlink in between must fail, not archive the link's target."""
    keys = tmp_path / "keys"
    (keys / "app").mkdir(parents=True)
    victim = keys / "app" / "hs_ed25519_secret_key"
    victim.write_bytes(b"k" * 96)
    outside = tmp_path / "outside-secret"
    outside.write_bytes(b"not a key, and not in the volume")
    real_is_symlink = Path.is_symlink

    def swap_after_check(self):
        answer = real_is_symlink(self)
        if self == victim and not answer:
            victim.unlink()
            victim.symlink_to(outside)
        return answer

    monkeypatch.setattr(Path, "is_symlink", swap_after_check)
    with pytest.raises(OSError):
        hf._tar_keys(keys)


def test_the_size_budget_admits_an_ordinary_key_volume(hf, keys):
    """Guard against 'fixing' the budget by refusing everything."""
    data = hf._tar_keys(keys)
    assert data
    assert b"hs_ed25519_secret_key" in data


def test_restore_refuses_a_symlinked_directory_in_the_key_volume(hf, keys, tmp_path,
                                                                 capsys):
    """A clean archive path is not enough; the DESTINATION can traverse.

    Refusing absolute paths and ".." covers the archive. It does not cover a key
    volume that already contains `app -> /somewhere/else`: the member
    `app/hs_ed25519_secret_key` is absolute-free, ".."-free, and every check
    passes, while `mkdir(parents=True)` followed by `open(dest)` writes the onion
    secret key outside the volume -- reproduced before this test was written.

    The volume is operator-supplied and the threat model allows it to have been
    restored from untrusted media, so a planted link is in scope. Every write is
    now made relative to a descriptor opened O_NOFOLLOW, so the restore fails
    loudly instead.
    """
    passfile = tmp_path / "pp"
    passfile.write_text("correct horse battery staple\n")
    backup = tmp_path / "keys.gpg"
    rc = hf.main(["backup", "--keys", str(keys), "--out", str(backup),
                  "--tool", "gpg", "--passphrase-file", str(passfile), "--json"])
    assert rc == 0

    outside = tmp_path / "outside"
    outside.mkdir()
    fresh = tmp_path / "fresh-keys"
    fresh.mkdir()
    (fresh / "app").symlink_to(outside)

    rc = hf.main(["restore", "--input", str(backup), "--keys", str(fresh),
                  "--tool", "gpg", "--passphrase-file", str(passfile), "--force",
                  "--json"])
    assert rc != 0
    assert list(outside.iterdir()) == [], "the secret key was written outside the volume"


def test_delete_plaintext_verifies_the_archive_before_destroying_the_key(hf, keys,
                                                                        tmp_path,
                                                                        monkeypatch,
                                                                        capsys):
    """The key IS the .onion address, and losing it loses the address for good.

    A zero exit from gpg says the command ran, not that what reached the disk can
    be opened again: a full filesystem, a short write, or a passphrase file with
    one byte the operator did not mean all exit 0 and leave a blob that never
    decrypts. Deleting the only copy on that evidence is the one mistake this tool
    cannot undo, so the archive is read back and decrypted first.

    Forced here by corrupting the file after it is written.
    """
    pp = tmp_path / "pp"
    pp.write_text("correct horse battery staple\n")
    blob = keys / "app.keys.tar.gpg"

    real_read = Path.read_bytes

    def corrupting_read(self, *a, **kw):
        data = real_read(self, *a, **kw)
        if self == blob:
            return data[:-8]          # a truncated write
        return data

    monkeypatch.setattr(Path, "read_bytes", corrupting_read)
    rc = hf.main(["encrypt-key", "--keys", str(keys), "--name", "app",
                  "--tool", "gpg", "--passphrase-file", str(pp),
                  "--delete-plaintext", "--json"])
    capsys.readouterr()
    assert rc != 0
    assert (keys / "app" / "hs_ed25519_secret_key").exists(), \
        "the plaintext key was destroyed on an archive that does not open"


def test_delete_plaintext_refuses_when_it_cannot_verify(hf, keys, tmp_path, capsys):
    """age decrypts only from a TTY, so the read-back cannot be done
    non-interactively. Refusing is the only safe answer: the alternative is
    deleting an unrecoverable identity on an unverified archive."""
    rc = hf.main(["encrypt-key", "--keys", str(keys), "--name", "app",
                  "--tool", "age", "--delete-plaintext", "--json"])
    capsys.readouterr()
    assert rc != 0
    assert (keys / "app" / "hs_ed25519_secret_key").exists()


def test_delete_plaintext_still_works_when_the_archive_verifies(hf, keys, tmp_path,
                                                               capsys):
    """Guard against 'fixing' this by refusing every deletion."""
    pp = tmp_path / "pp"
    pp.write_text("correct horse battery staple\n")
    rc = hf.main(["encrypt-key", "--keys", str(keys), "--name", "app",
                  "--tool", "gpg", "--passphrase-file", str(pp),
                  "--delete-plaintext", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0 and doc["deleted_plaintext"] is True
    assert not (keys / "app").exists()
    assert (keys / "app.keys.tar.gpg").exists()


def test_decrypt_key_refuses_a_symlinked_directory_in_the_destination(hf, keys,
                                                                      tmp_path,
                                                                      capsys):
    """Same traversal as `restore`, one command over: the archive is clean and the
    destination is not. `decrypt-key` writes into `<keys>/<name>/`, so a symlinked
    subdirectory there redirects the extracted key material out of the volume."""
    pp = tmp_path / "pp"
    pp.write_text("correct horse battery staple\n")
    assert hf.main(["encrypt-key", "--keys", str(keys), "--name", "app",
                    "--tool", "gpg", "--passphrase-file", str(pp), "--json"]) == 0
    capsys.readouterr()

    # A plausible planted link: the archive has no subdirectories, so this proves
    # the descriptor walk refuses the component rather than relying on the
    # archive's shape.
    outside = tmp_path / "outside"
    outside.mkdir()
    nested = keys / "app" / "sub"
    nested.symlink_to(outside)

    import io as _io
    import tarfile as _tarfile
    # Re-encrypt an archive that DOES name a nested member, so the walk is used.
    buf = _io.BytesIO()
    with _tarfile.open(fileobj=buf, mode="w", format=_tarfile.PAX_FORMAT) as tar:
        info = _tarfile.TarInfo(name="sub/hs_ed25519_secret_key")
        payload = b"\x33" * 96
        info.size = len(payload)
        info.mode = 0o600
        tar.addfile(info, _io.BytesIO(payload))
    ciphertext, _mode = hf._encrypt_bytes("gpg", buf.getvalue(),
                                          "correct horse battery staple")
    (keys / "app.keys.tar.gpg").write_bytes(ciphertext)

    rc = hf.main(["decrypt-key", "--keys", str(keys), "--name", "app",
                  "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    capsys.readouterr()
    assert rc != 0
    assert list(outside.iterdir()) == [], "key material was written outside the volume"


# ─────────────────────────────────────────────────────────────────────────────
# restore, against archives built to be hostile
# ─────────────────────────────────────────────────────────────────────────────

def _encrypted_archive(hf, tmp_path, members, passphrase=TEST_PASSPHRASE):
    """An encrypted backup containing exactly `members` (name -> bytes)."""
    import io as _io
    import tarfile as _tarfile
    buf = _io.BytesIO()
    with _tarfile.open(fileobj=buf, mode="w", format=_tarfile.PAX_FORMAT) as tar:
        for name, payload in members.items():
            info = _tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mode = 0o600
            tar.addfile(info, _io.BytesIO(payload))
    ciphertext, _mode = hf._encrypt_bytes("gpg", buf.getvalue(), passphrase)
    blob = tmp_path / "hostile.gpg"
    blob.write_bytes(ciphertext)
    return blob


@pytest.mark.parametrize("name", [
    "../escape",
    "app/../../escape",
    "/etc/escape",
    "//etc/escape",
    "app/./../../escape",
])
def test_restore_refuses_every_shape_of_traversing_name(hf, tmp_path, name, capsys):
    """One parametrised case per shape, because "it refuses `..`" is a claim about
    a family, and the family is where these bugs live."""
    pp = tmp_path / "pp"
    pp.write_text("correct horse battery staple\n")
    # The key member keeps the archive a plausible backup; see
    # test_restore_rejects_path_traversal for why that matters.
    blob = _encrypted_archive(
        hf, tmp_path, {"app/hs_ed25519_secret_key": b"k" * 32, name: b"k"})
    dest = tmp_path / "dest"
    rc = hf.main(["restore", "--input", str(blob), "--keys", str(dest),
                  "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    capsys.readouterr()
    assert rc != 0
    escaped = tmp_path / "escape"
    assert not escaped.exists(), f"{name} escaped the key volume"


def test_restore_creates_nested_directories_it_was_given(hf, tmp_path, capsys):
    """The other side: a legitimate nested member must still arrive. A refusal
    that rejects everything is not a fix."""
    pp = tmp_path / "pp"
    pp.write_text("correct horse battery staple\n")
    blob = _encrypted_archive(
        hf, tmp_path, {"app/sub/deep/hs_ed25519_secret_key": b"\x44" * 32})
    dest = tmp_path / "dest"
    rc = hf.main(["restore", "--input", str(blob), "--keys", str(dest),
                  "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    capsys.readouterr()
    assert rc == 0
    got = dest / "app" / "sub" / "deep" / "hs_ed25519_secret_key"
    assert got.read_bytes() == b"\x44" * 32
    assert stat.S_IMODE(os.stat(got).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(dest / "app" / "sub").st_mode) == 0o700


def test_restore_forces_0600_whatever_the_archive_declares(hf, tmp_path, capsys):
    """A crafted archive must not be able to leave an onion secret key
    world-readable, and the caller's umask must not be able to either."""
    pp = tmp_path / "pp"
    pp.write_text("correct horse battery staple\n")
    import io as _io
    import tarfile as _tarfile
    buf = _io.BytesIO()
    with _tarfile.open(fileobj=buf, mode="w", format=_tarfile.PAX_FORMAT) as tar:
        info = _tarfile.TarInfo(name="app/hs_ed25519_secret_key")
        info.size = 4
        info.mode = 0o777
        tar.addfile(info, _io.BytesIO(b"key!"))
    ciphertext, _m = hf._encrypt_bytes("gpg", buf.getvalue(),
                                       "correct horse battery staple")
    blob = tmp_path / "loose.gpg"
    blob.write_bytes(ciphertext)
    dest = tmp_path / "dest"
    old = os.umask(0o000)
    try:
        rc = hf.main(["restore", "--input", str(blob), "--keys", str(dest),
                      "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    finally:
        os.umask(old)
    capsys.readouterr()
    assert rc == 0
    assert stat.S_IMODE(os.stat(dest / "app" / "hs_ed25519_secret_key").st_mode) == 0o600


def test_restore_refuses_an_archive_that_carries_no_identity(hf, tmp_path, capsys):
    """An archive that decrypts but holds no secret key is not a restore.

    Found by feeding `restore` a hand-built archive: it reported `ok: true` over
    a volume it had left empty. That is the worst answer this command can give.
    The operator reads success, believes the identity is back, and the only
    remaining copy may be the one they are about to delete. A .onion address IS
    its key: there is no reissuing it.
    """
    def build(tar, io):
        info = tar.tarinfo("app/hostname")
        info.size = 5
        tar.addfile(info, io.BytesIO(b"x.oni"))

    blob, pp = _sealed(hf, tmp_path, build)
    dest = tmp_path / "dest"
    rc = hf.main(["restore", "--keys", str(dest), "--input", str(blob),
                  "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    out = capsys.readouterr().out
    assert rc != 0, "an archive with no secret key must not report success"
    assert "no hs_ed25519_secret_key and no encrypted key envelope" in out
    # And it must fail closed: nothing at all written into the volume, not even
    # the directories the archive names (the old conflict scan created those).
    assert not dest.exists() or not any(dest.iterdir())


def test_restore_still_accepts_a_real_backup(hf, keys, tmp_path, capsys):
    """Guard against 'fixing' the above by refusing archives people actually have."""
    out = tmp_path / "backup.tar.gpg"
    pp = tmp_path / "pp"
    pp.write_text("correct horse battery staple\n")
    assert hf.main(["backup", "--keys", str(keys), "--out", str(out),
                    "--tool", "gpg", "--passphrase-file", str(pp), "--json"]) == 0
    capsys.readouterr()
    dest = tmp_path / "dest"
    assert hf.main(["restore", "--keys", str(dest), "--input", str(out),
                    "--tool", "gpg", "--passphrase-file", str(pp), "--json"]) == 0
    capsys.readouterr()
    assert list(dest.rglob("hs_ed25519_secret_key")), "a real backup must restore"


@pytest.mark.parametrize("name", [
    "app\n/hs_ed25519_secret_key",
    "ap\x00p/hs_ed25519_secret_key",
    "app/hs_ed25519_secret_key\x1b[2J",
    "app\x7f/hs_ed25519_secret_key",
])
def test_restore_refuses_a_control_character_in_a_member_name(hf, tmp_path,
                                                              capsys, name):
    """The archive is the one path into the key volume that skips name validation.

    `validate_name` guards names arriving from the CLI and `validate_keys_dir`
    guards the volume path, both because these names become directories and get
    printed back by `show`, `status` and `doctor`. A member name came from the
    archive and passed neither. A newline in one splits a line of operator
    output in two; an ESC sequence rewrites the terminal it is printed to.
    """
    def build(tar, io):
        info = tar.tarinfo(name)
        info.size = 4
        tar.addfile(info, io.BytesIO(b"key!"))

    blob, pp = _sealed(hf, tmp_path, build)
    dest = tmp_path / "dest"
    rc = hf.main(["restore", "--keys", str(dest), "--input", str(blob),
                  "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    capsys.readouterr()
    assert rc != 0, f"a control character in {name!r} must fail closed"
    assert not list(dest.rglob("*")) or not any(p.is_file() for p in dest.rglob("*"))


def test_a_backup_of_an_encrypted_volume_still_restores(hf, keys, tmp_path, capsys):
    """The volume left by `encrypt-key --delete-plaintext` has no plaintext key.

    Refusing an archive with no `hs_ed25519_secret_key` would have refused this
    one, which is a worse failure than the one that check exists to prevent: the
    operator who encrypted their key at rest is exactly the operator whose only
    copy is that backup. Proven end to end rather than asserted, because a
    narrowing that is merely claimed is a narrowing nobody has checked.
    """
    pp = tmp_path / "pp"
    pp.write_text("correct horse battery staple\n")
    original = (keys / "app" / "hs_ed25519_secret_key").read_bytes()

    assert hf.main(["encrypt-key", "--keys", str(keys), "--name", "app",
                    "--tool", "gpg", "--passphrase-file", str(pp),
                    "--delete-plaintext", "--json"]) == 0
    capsys.readouterr()
    assert not (keys / "app" / "hs_ed25519_secret_key").exists()

    out = tmp_path / "encrypted-volume.tar.gpg"
    assert hf.main(["backup", "--keys", str(keys), "--out", str(out),
                    "--tool", "gpg", "--passphrase-file", str(pp), "--json"]) == 0
    capsys.readouterr()

    dest = tmp_path / "dest"
    assert hf.main(["restore", "--keys", str(dest), "--input", str(out),
                    "--tool", "gpg", "--passphrase-file", str(pp), "--json"]) == 0
    capsys.readouterr()
    assert list(dest.glob("*.keys.tar.gpg")), "the envelope did not come back"

    assert hf.main(["decrypt-key", "--keys", str(dest), "--name", "app",
                    "--tool", "gpg", "--passphrase-file", str(pp), "--json"]) == 0
    capsys.readouterr()
    assert (dest / "app" / "hs_ed25519_secret_key").read_bytes() == original


# ─────────────────────────────────────────────────────────────────────────────
# decrypt-key must never write over a live key set
# ─────────────────────────────────────────────────────────────────────────────

def _key_set(d: Path, fill: int, onion_char: str) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "hs_ed25519_public_key").write_bytes(PUBLIC_TAG.ljust(32, b"\x00")
                                             + bytes([fill]) * 32)
    (d / "hs_ed25519_secret_key").write_bytes(bytes([fill]) * 96)
    (d / "hostname").write_text(onion_char * 56 + ".onion\n")


def _encrypted_then_replaced(hf, keys, tmp_path, capsys):
    """Encrypt app's key (0x22), then give app a DIFFERENT live key (0x33): the
    state after a vanity --force, a rotate, or a container that regenerated."""
    pp = tmp_path / "pp"
    pp.write_text(TEST_PASSPHRASE + "\n")
    assert hf.main(["encrypt-key", "--keys", str(keys), "--name", "app", "--tool", "gpg",
                    "--passphrase-file", str(pp), "--delete-plaintext", "--json"]) == 0
    capsys.readouterr()
    _key_set(keys / "app", 0x33, "b")
    (keys / "app" / "extra-live-file").write_bytes(b"live")
    return pp


def test_decrypt_key_refuses_to_overwrite_a_different_live_key(hf, keys, tmp_path,
                                                                capsys):
    """Reproduced before the fix: the live key was replaced by the archived one,
    exit 0, no copy kept. The key IS the address, so that is a permanent loss."""
    pp = _encrypted_then_replaced(hf, keys, tmp_path, capsys)
    rc, doc = _run(hf, capsys, ["decrypt-key", "--keys", str(keys), "--name", "app",
                                "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    assert rc == hf.EXIT_FAIL and doc["ok"] is False
    assert "--force" in doc["error"]
    assert (keys / "app" / "hs_ed25519_secret_key").read_bytes() == b"\x33" * 96


def test_decrypt_key_force_moves_the_live_key_aside_whole(hf, keys, tmp_path, capsys):
    """--force archives, never deletes, and extracts into a FRESH directory: the
    old per-file overwrite left a mixed key set when the live directory had a
    file the archive lacked."""
    pp = _encrypted_then_replaced(hf, keys, tmp_path, capsys)
    rc, doc = _run(hf, capsys, ["decrypt-key", "--keys", str(keys), "--name", "app",
                                "--tool", "gpg", "--passphrase-file", str(pp),
                                "--force", "--json"])
    assert rc == 0, doc
    archived = Path(doc["archived"])
    assert (archived / "hs_ed25519_secret_key").read_bytes() == b"\x33" * 96
    assert (keys / "app" / "hs_ed25519_secret_key").read_bytes() == b"\x22" * 96
    assert not (keys / "app" / "extra-live-file").exists(), "mixed key set"
    assert stat.S_IMODE(os.stat(keys / "app").st_mode) == 0o700


def test_decrypt_key_removes_a_published_address_that_may_be_stale(hf, keys, tmp_path,
                                                                    capsys):
    pp = _encrypted_then_replaced(hf, keys, tmp_path, capsys)
    (keys / "app.onion").write_text("b" * 56 + ".onion\n")
    rc, doc = _run(hf, capsys, ["decrypt-key", "--keys", str(keys), "--name", "app",
                                "--tool", "gpg", "--passphrase-file", str(pp),
                                "--force", "--json"])
    assert rc == 0 and doc["stale_address_files"] == []
    assert not (keys / "app.onion").exists()


def test_decrypt_key_refuses_an_archive_with_no_key(hf, tmp_path, capsys):
    """decrypt-key used to skip what restore refused, and accept a keyless archive."""
    def build(tar, io):
        info = tar.tarinfo("hostname")
        info.size = 5
        tar.addfile(info, io.BytesIO(b"x.oni"))

    blob, pp = _sealed(hf, tmp_path, build)
    keys = tmp_path / "k"
    keys.mkdir()
    blob.rename(keys / "app.keys.tar.gpg")
    rc = hf.main(["decrypt-key", "--keys", str(keys), "--name", "app", "--tool", "gpg",
                  "--passphrase-file", str(pp), "--json"])
    assert rc != 0
    assert "no hs_ed25519_secret_key" in capsys.readouterr().out
    assert not (keys / "app").exists()


# ─────────────────────────────────────────────────────────────────────────────
# restore: leave nothing behind when refusing; touch nothing it did not write
# ─────────────────────────────────────────────────────────────────────────────

def test_a_conflict_refusal_leaves_nothing_behind(hf, keys, tmp_path, capsys):
    """The conflict scan used to CREATE each member's parent directory while it
    looked, so a restore refused for a conflict still left new directories."""
    def build(tar, io):
        for name in ("app/hs_ed25519_secret_key", "other/hs_ed25519_secret_key"):
            info = tar.tarinfo(name)
            info.size = 96
            tar.addfile(info, io.BytesIO(b"\x44" * 96))

    blob, pp = _sealed(hf, tmp_path, build)
    rc = hf.main(["restore", "--keys", str(keys), "--input", str(blob),
                  "--tool", "gpg", "--passphrase-file", str(pp), "--json"])
    capsys.readouterr()
    assert rc == hf.EXIT_FAIL
    assert not (keys / "other").exists()


def test_restore_removes_a_stale_published_address(hf, keys, tmp_path, capsys):
    """After a key is replaced, `<name>.onion` names the OLD key until the
    container republishes, and `show` reads it from the host."""
    out = tmp_path / "b.tar.gpg"
    pp = tmp_path / "pp"
    pp.write_text(TEST_PASSPHRASE + "\n")
    assert hf.main(["backup", "--keys", str(keys), "--out", str(out), "--tool", "gpg",
                    "--passphrase-file", str(pp), "--json"]) == 0
    capsys.readouterr()
    (keys / "app.onion").write_text("b" * 56 + ".onion\n")
    rc, doc = _run(hf, capsys, ["restore", "--keys", str(keys), "--input", str(out),
                                "--tool", "gpg", "--passphrase-file", str(pp),
                                "--force", "--json"])
    assert rc == 0 and doc["stale_address_files"] == []
    assert not (keys / "app.onion").exists()


def test_restore_leaves_files_it_did_not_write_alone(hf, keys, tmp_path, capsys):
    """The old final pass chmod'ed EVERY entry in the volume by path, resetting an
    unrelated service's published 0644 address file to 0600."""
    out = tmp_path / "b.tar.gpg"
    pp = tmp_path / "pp"
    pp.write_text(TEST_PASSPHRASE + "\n")
    assert hf.main(["backup", "--keys", str(keys), "--out", str(out), "--tool", "gpg",
                    "--passphrase-file", str(pp), "--json"]) == 0
    capsys.readouterr()
    dest = tmp_path / "dest"
    dest.mkdir()
    other = dest / "other.onion"
    other.write_text("c" * 56 + ".onion\n")
    os.chmod(other, 0o644)
    assert hf.main(["restore", "--keys", str(dest), "--input", str(out), "--tool", "gpg",
                    "--passphrase-file", str(pp), "--json"]) == 0
    capsys.readouterr()
    assert stat.S_IMODE(os.stat(other).st_mode) == 0o644
    assert stat.S_IMODE(os.stat(dest / "app" / "hs_ed25519_secret_key").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(dest / "app").st_mode) == 0o700
