"""verify-image's trust anchor, exercised with real ssh-keygen and the real signatures.

The signer keys used to be read from the signature directory being verified, so
anyone able to alter that directory could substitute their own key, sign their
own digest and get exit 0. These tests use a genuinely forged set -- a real
ed25519 key, a real signature -- because a mock of ssh-keygen would agree with
whatever the code under test believes.

ssh-keygen is REQUIRED, not optional: the CI runner is in host mode on a machine
that has it, and a test that skips when its tool is missing is how this project
once reported a container-escape guard as green while checking nothing.
"""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from loader import load_file, repo_root

REPO = repo_root(__file__)
SIGNATURES = REPO / "signatures"


@pytest.fixture(scope="module")
def hf():
    assert shutil.which("ssh-keygen"), "ssh-keygen is required for these tests"
    return load_file(REPO / "scripts" / "hiddenforge", "hf_cli_trust")


def _verify(hf, capsys, sigdir, *extra):
    rc = hf.main(["verify-image", "example.com/x:1", "--sigdir", str(sigdir),
                  "--skip-registry", "--json", *extra])
    return rc, json.loads(capsys.readouterr().out)


def _forged_set(tmp_path: Path, *, keep_real_signers: bool) -> Path:
    """A signature set signed by a key that is not the release key."""
    d = tmp_path / "forged"
    d.mkdir()
    key = tmp_path / "evil"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "evil",
                    "-f", str(key)], check=True)
    (d / "hiddenforge.digest").write_text("sha256:" + "e" * 64 + "\n")
    pub = key.with_suffix(".pub").read_text().split()
    if keep_real_signers:
        shutil.copy(SIGNATURES / "allowed-signers", d / "allowed-signers")
    else:
        (d / "allowed-signers").write_text(f"sam@sambent.com {pub[0]} {pub[1]}\n")
    subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", "file",
                    str(d / "hiddenforge.digest")], check=True)
    return d


def test_the_pinned_keys_are_the_ones_in_the_signature_directory(hf):
    """If these drift, either the pin or the published set is wrong; both are a
    release-blocking inconsistency, so it fails here rather than at a user."""
    shipped = [ln for ln in (SIGNATURES / "allowed-signers").read_text().splitlines()
               if ln.strip()]
    assert list(hf.PINNED_ALLOWED_SIGNERS) == shipped
    digest = hashlib.sha256((SIGNATURES / "sambent-mldsa.pub").read_bytes()).hexdigest()
    assert digest == hf.PINNED_MLDSA_PUB_SHA256


def test_a_signer_planted_in_the_signature_directory_is_not_trusted(hf, tmp_path,
                                                                    capsys):
    """The attack, reproduced: own key, labelled sam@sambent.com, own signature.
    The old code answered ssh_fido2: true."""
    d = _forged_set(tmp_path, keep_real_signers=False)
    rc, doc = _verify(hf, capsys, d, "--allow-classical-only")
    assert rc == hf.EXIT_FAIL
    assert doc["ssh_fido2"] is False
    assert doc["trust_anchor"] == "pinned"


def test_the_genuine_release_signature_verifies_against_the_pin(hf, capsys, tmp_path):
    """The other side, with the real published signature: the pin must accept it,
    or the fix would just be a verifier that refuses everything."""
    d = tmp_path / "sig"
    shutil.copytree(SIGNATURES, d)
    (d / "allowed-signers").write_text("")   # prove the file is not consulted
    rc, doc = _verify(hf, capsys, d, "--allow-classical-only")
    assert doc["ssh_fido2"] is True, doc["ssh_fido2_detail"]
    assert rc == 0


def test_an_operator_supplied_anchor_is_used_and_said(hf, tmp_path, capsys):
    """Verifying an image someone else signed is legitimate; it must be explicit
    and visible, never inferred from the directory being verified."""
    d = _forged_set(tmp_path, keep_real_signers=False)
    rc, doc = _verify(hf, capsys, d, "--allow-classical-only",
                      "--allowed-signers", str(d / "allowed-signers"))
    assert rc == 0 and doc["ssh_fido2"] is True
    assert doc["trust_anchor"] == "operator-supplied"
    assert doc["complete"] is False


def test_an_mldsa_key_that_is_not_the_pinned_one_is_a_failure(hf, tmp_path):
    """Swapping the post-quantum public key is the ML-DSA half of the same attack.
    Decided before pqsign is ever run, so it holds on a host without pqsign."""
    d = tmp_path / "sig"
    shutil.copytree(SIGNATURES, d)
    shutil.copy(SIGNATURES / "hiddenforge-mldsa.pub", d / "sambent-mldsa.pub")
    verdict, detail = hf._verify_mldsa_signature(d, (d / "hiddenforge.digest").read_bytes())
    assert verdict is False
    assert "not the pinned release key" in detail


def test_the_real_set_without_pqsign_is_refused_by_default(hf, tmp_path, capsys,
                                                           monkeypatch):
    d = tmp_path / "sig"
    shutil.copytree(SIGNATURES, d)
    real_which = shutil.which
    monkeypatch.setattr(hf.shutil, "which",
                        lambda n: None if n == "pqsign" else real_which(n))
    rc, doc = _verify(hf, capsys, d)
    assert rc == hf.EXIT_FAIL
    assert doc["mldsa"] is None
    assert any("--allow-classical-only" in f for f in doc["failures"])
