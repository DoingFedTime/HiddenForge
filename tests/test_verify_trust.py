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
    monkeypatch.setattr(hf, "_openssl_mldsa", lambda level: (False, "OpenSSL 3.0.13"))
    rc, doc = _verify(hf, capsys, d)
    assert rc == hf.EXIT_FAIL
    assert doc["mldsa"] is None
    assert any("--allow-classical-only" in f for f in doc["failures"])


# ── The ML-DSA half with stock OpenSSL ──────────────────────────────────────
# pqsign, the signer's own tool, is not published, so a verifier that needed it
# left the post-quantum half uncheckable for everyone else. OpenSSL 3.5+
# implements FIPS 204. The encoding below is the one measured to verify the
# release signature with OpenSSL 3.5.8.

def test_the_release_key_becomes_the_spki_openssl_accepted(hf):
    pub = (SIGNATURES / "sambent-mldsa.pub").read_bytes()
    sig = (SIGNATURES / "hiddenforge.digest.mldsa").read_bytes()
    level, spki, raw = hf._pqsign_to_openssl(pub, sig)
    assert level == "ML-DSA-65"
    assert spki == bytes.fromhex(
        "308207b2300b0609608648016503040312038207a100") + pub[16:]
    assert raw == sig[16:] and len(raw) == 3309


def test_the_ml_dsa_87_oid_is_encoded_per_rfc_9881(hf):
    assert hf._der_oid("2.16.840.1.101.3.4.3.19") == bytes.fromhex(
        "0609608648016503040313")


@pytest.mark.parametrize("pub, sig, message", [
    (b"PQSIGN_MLDSA65_P" + b"\x00" * 1952, b"PQSIGN_MLDSA87_G" + b"\x00" * 4627,
     "not a pqsign ML-DSA-65 signature"),
    (b"PQSIGN_MLDSA65_P" + b"\x00" * 1951, b"PQSIGN_MLDSA65_G" + b"\x00" * 3309,
     "is 1951 bytes, not 1952"),
    (b"-----BEGIN PUBLIC KEY-----\n", b"PQSIGN_MLDSA65_G",
     "not in pqsign's format"),
])
def test_a_malformed_key_or_signature_is_refused_by_name(hf, pub, sig, message):
    with pytest.raises(ValueError, match=message):
        hf._pqsign_to_openssl(pub, sig)


def test_openssl_is_preferred_over_pqsign(hf, tmp_path, monkeypatch):
    d = tmp_path / "sig"
    shutil.copytree(SIGNATURES, d)
    ran = []
    monkeypatch.setattr(hf, "_openssl_mldsa", lambda level: (True, "OpenSSL 3.5.8"))
    ok = "Signature Verified Successfully\n"
    monkeypatch.setattr(hf, "_run", lambda cmd, **kw: ran.append(cmd) or
                        subprocess.CompletedProcess(cmd, 0, ok, ""))
    verdict, detail = hf._verify_mldsa_signature(d, (d / "hiddenforge.digest").read_bytes())
    assert verdict is True
    assert [c[:2] for c in ran] == [["openssl", "pkeyutl"]]
    assert detail == "ML-DSA-65 via OpenSSL 3.5.8: Signature Verified Successfully"


def test_pqsign_is_the_fallback_when_openssl_cannot(hf, tmp_path, monkeypatch):
    d = tmp_path / "sig"
    shutil.copytree(SIGNATURES, d)
    ran = []
    monkeypatch.setattr(hf, "_openssl_mldsa", lambda level: (False, "OpenSSL 3.0.13"))
    real_which = shutil.which
    monkeypatch.setattr(hf.shutil, "which",
                        lambda n: "/usr/bin/pqsign" if n == "pqsign" else real_which(n))
    monkeypatch.setattr(hf, "_run", lambda cmd, **kw: ran.append(cmd) or
                        subprocess.CompletedProcess(cmd, 2, "", "INVALID signature\n"))
    verdict, detail = hf._verify_mldsa_signature(d, (d / "hiddenforge.digest").read_bytes())
    assert verdict is False
    assert [c[:2] for c in ran] == [["pqsign", "verify"]]
    assert detail == "ML-DSA-65 via pqsign: INVALID signature"


def _openssl_can_mldsa():
    if shutil.which("openssl") is None:
        return False
    out = subprocess.run(["openssl", "list", "-signature-algorithms"],
                         capture_output=True, text=True, check=False).stdout
    return "ML-DSA-65" in out


needs_openssl_mldsa = pytest.mark.skipif(
    not _openssl_can_mldsa(), reason="this host's OpenSSL has no ML-DSA (needs 3.5+)")


@needs_openssl_mldsa
def test_the_genuine_release_signature_verifies_with_openssl(hf):
    verdict, detail = hf._verify_mldsa_signature(
        SIGNATURES, (SIGNATURES / "hiddenforge.digest").read_bytes())
    assert verdict is True, detail
    assert "via OpenSSL" in detail


@needs_openssl_mldsa
def test_a_digest_changed_by_one_byte_fails_with_openssl(hf):
    verdict, detail = hf._verify_mldsa_signature(
        SIGNATURES, (SIGNATURES / "hiddenforge.digest").read_bytes() + b" ")
    assert verdict is False, detail


# ── The SSH-FIDO2 half missing (a release signed before the hardware key) ───

def _without_hardware_sig(tmp_path: Path) -> Path:
    d = tmp_path / "sig"
    shutil.copytree(SIGNATURES, d)
    (d / "hiddenforge.digest.sig").unlink()
    return d


def _mldsa_verified(monkeypatch, hf, verdict=True):
    monkeypatch.setattr(hf, "_verify_mldsa_signature",
                        lambda d, b, t=None: (verdict, "ML-DSA-65 via test"))


def test_a_missing_hardware_signature_is_refused_by_default(hf, tmp_path, capsys,
                                                             monkeypatch):
    """Deleting the .sig must not quietly reduce the hybrid to one signature."""
    _mldsa_verified(monkeypatch, hf)
    rc, doc = _verify(hf, capsys, _without_hardware_sig(tmp_path))
    assert rc == hf.EXIT_FAIL
    assert doc["ssh_fido2"] is None
    assert any("--allow-pq-only" in f for f in doc["failures"])


def test_allow_pq_only_accepts_the_ml_dsa_signature_alone(hf, tmp_path, capsys,
                                                           monkeypatch):
    _mldsa_verified(monkeypatch, hf)
    rc, doc = _verify(hf, capsys, _without_hardware_sig(tmp_path), "--allow-pq-only")
    assert rc == 0
    assert doc["mldsa"] is True and doc["ssh_fido2"] is None
    assert doc["complete"] is False
    assert any(u.startswith("SSH-FIDO2 signature:") for u in doc["unchecked"])


def test_allow_pq_only_does_not_excuse_a_bad_hardware_signature(hf, tmp_path, capsys,
                                                                 monkeypatch):
    """The flag covers a MISSING half, never a wrong one."""
    _mldsa_verified(monkeypatch, hf)
    d = _forged_set(tmp_path, keep_real_signers=False)
    rc, doc = _verify(hf, capsys, d, "--allow-pq-only")
    assert rc == hf.EXIT_FAIL and doc["ssh_fido2"] is False


def test_allow_pq_only_does_not_excuse_a_failed_ml_dsa_signature(hf, tmp_path, capsys,
                                                                  monkeypatch):
    _mldsa_verified(monkeypatch, hf, verdict=False)
    rc, doc = _verify(hf, capsys, _without_hardware_sig(tmp_path), "--allow-pq-only")
    assert rc == hf.EXIT_FAIL and doc["mldsa"] is False


def test_both_opt_outs_together_never_accept_an_unsigned_image(hf, tmp_path, capsys,
                                                                monkeypatch):
    """Each flag accepts one missing half. Passing both must not accept zero."""
    _mldsa_verified(monkeypatch, hf, verdict=None)
    rc, doc = _verify(hf, capsys, _without_hardware_sig(tmp_path),
                      "--allow-pq-only", "--allow-classical-only")
    assert rc == hf.EXIT_FAIL
    assert "neither signature was verified" in doc["failures"]


def test_an_ssh_keygen_that_hangs_is_not_checked_rather_than_a_crash(hf, tmp_path,
                                                                     monkeypatch):
    d = tmp_path / "sig"
    shutil.copytree(SIGNATURES, d)

    def hang(*a, **kw):
        raise subprocess.TimeoutExpired(a[0] if a else "ssh-keygen", 60)
    monkeypatch.setattr(hf.subprocess, "run", hang)
    verdict, detail = hf._verify_ssh_signature(
        d, "sam@sambent.com", (d / "hiddenforge.digest").read_bytes(), "")
    assert verdict is None and "NOT checked" in detail
