"""doctor and show against a key volume the host user may not enter.

On a running Docker deployment every service directory is 0700 and owned by the
container's `tor` user, so from the host `lstat` inside it fails with EACCES.
That is the correct state, and it used to make `doctor` FAIL every service, on
the project's own recommended deployment, via the command docs/INTEGRATION.md
gives for verifying one. These tests reproduce the directory with mode 000 on a
directory the test user owns, which gives the same EACCES.
"""
import json
import os
import subprocess

import pytest

from loader import load_file, repo_root

REPO = repo_root(__file__)

pytestmark = pytest.mark.skipif(
    os.geteuid() == 0,
    reason="root bypasses directory permissions, so EACCES cannot be reproduced")


@pytest.fixture(scope="module")
def hf():
    return load_file(REPO / "scripts" / "hiddenforge", "hf_cli_doctor_keys")


@pytest.fixture
def closed_keys(tmp_path):
    keys = tmp_path / "tor-keys"
    (keys / "app").mkdir(parents=True)
    (keys / "app" / "hs_ed25519_secret_key").write_bytes(b"\x00" * 96)
    os.chmod(keys, 0o751)  # noqa: S103 - the mode the entrypoint really sets
    os.chmod(keys / "app", 0o000)
    yield keys
    os.chmod(keys / "app", 0o700)


def _doctor(hf, monkeypatch, capsys, keys, in_container):
    info = {"HostConfig": {"CapDrop": ["ALL"],
                           "CapAdd": ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"],
                           "SecurityOpt": ["no-new-privileges:true"],
                           "ReadonlyRootfs": True, "PidsLimit": 256,
                           "Memory": 1, "MemorySwap": 1, "LogConfig": {"Type": "none"}},
            "NetworkSettings": {"Ports": {}}, "State": {"Running": True}}
    asked = []

    def exec_json(container, argv):
        asked.append((container, argv))
        return in_container

    monkeypatch.setattr(hf, "_docker_inspect", lambda c: (info, None))
    monkeypatch.setattr(hf, "_resolve_container", lambda c: "cid")
    monkeypatch.setattr(hf, "_engine", lambda: "docker")
    monkeypatch.setattr(hf, "_is_rootless", lambda: False)
    monkeypatch.setattr(hf, "_docker_exec_json", exec_json)
    monkeypatch.setattr(hf, "_docker_exec_text",
                        lambda c, a: "ClientOnly 1\nExitPolicy reject *:*\nSafeLogging 1\n"
                        "AvoidDiskWrites 1\nDisableDebuggerAttachment 1\n"
                        "FetchUselessDescriptors 0\nVanguardsLiteEnabled 1\n"
                        "HiddenServicePoWDefensesEnabled 1\n"
                        "HiddenServiceEnableIntroDoSDefense 1\nHiddenServiceVersion 3\n")
    monkeypatch.setattr(hf, "_run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 1, "", ""))
    rc = hf.main(["doctor", "--container", "tor", "--keys", str(keys), "--json"])
    doc = json.loads(capsys.readouterr().out)
    return rc, doc, {c["check"]: c for c in doc["checks"]}, asked


def _inner(secret_mode_ok=True):
    return {"checks": [
        {"check": "key dir app is 0700", "ok": True, "detail": "mode=0o700",
         "severity": "fail"},
        {"check": "secret key app is 0600", "ok": secret_mode_ok,
         "detail": "mode=0o600" if secret_mode_ok else "mode=0o644", "severity": "fail"},
        {"check": "key volume is not group/world writable or world readable",
         "ok": False, "detail": "mode=0o770", "severity": "warn"},
    ]}


def test_a_tor_owned_service_directory_is_not_a_failure(hf, monkeypatch, capsys,
                                                         closed_keys):
    rc, doc, checks, asked = _doctor(hf, monkeypatch, capsys, closed_keys, _inner())
    assert "key modes for app" not in checks
    assert rc == 0, doc["failures"]
    assert checks["secret key app is 0600 (checked in container)"]["ok"] is True
    # Asked as the tor user, who owns the directory; and only about key checks
    # for the service the host could not see, not the whole in-container report.
    assert asked and asked[0][1][:2] == ["su-exec", "tor"]
    assert not any("(checked in container)" in k and "volume" in k for k in checks)


def test_a_bad_mode_seen_from_inside_still_fails(hf, monkeypatch, capsys, closed_keys):
    """Delegating must not soften anything: a wrong mode inside is a failure."""
    rc, doc, _checks, _ = _doctor(hf, monkeypatch, capsys, closed_keys,
                                  _inner(secret_mode_ok=False))
    assert rc == hf.EXIT_FAIL
    assert "secret key app is 0600 (checked in container)" in doc["failures"]


def test_a_container_that_cannot_be_asked_is_said_not_passed(hf, monkeypatch, capsys,
                                                              closed_keys):
    """Not a FAIL (nothing is known to be wrong) and not silence (nothing was
    checked): a named warning."""
    _rc, doc, checks, _ = _doctor(hf, monkeypatch, capsys, closed_keys, None)
    assert checks["key modes for app"]["severity"] == "warn"
    assert "key modes for app" in doc["warnings"]


def test_keys_only_on_the_host_reports_what_it_could_not_inspect(hf, capsys,
                                                                 closed_keys):
    rc = hf.main(["doctor", "--keys-only", "--keys", str(closed_keys), "--json"])
    doc = json.loads(capsys.readouterr().out)
    checks = {c["check"]: c for c in doc["checks"]}
    assert checks["key modes for app"]["severity"] == "warn"
    assert rc == 0


def test_show_says_why_there_is_no_address(hf, capsys, closed_keys):
    """"Not generated yet" was false for a key that exists but cannot be read,
    and under rootless Podman a caller told that would wait for ever."""
    rc = hf.main(["show", "--keys", str(closed_keys), "--name", "app", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == hf.EXIT_NOT_READY
    assert "not readable by this user" in doc["error"]
    assert "su-exec tor cat" in doc["error"]


def test_show_still_says_not_generated_when_nothing_is_there(hf, capsys, tmp_path):
    (tmp_path / "k").mkdir()
    rc = hf.main(["show", "--keys", str(tmp_path / "k"), "--name", "app", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == hf.EXIT_NOT_READY
    assert "not generated yet" in doc["error"]
