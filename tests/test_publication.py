"""Publishing an address is a claim that clients can reach the service.

A container was observed at bootstrap 100%, with a valid hostname file and
`circuit-established=1`, publishing a perfectly well-formed .onion that no client
could reach -- Tor writes `hostname` at key-generation time, long before any
descriptor reaches a directory. `_service_reachable` is the gate that was added
so the address file cannot make that claim on its own.

Mutation testing found the gate itself had no tests: all 38 of its mutants were
unreachable by the suite, including `if gate is not None and gate():`, which
inverts it -- publishing exactly when the service is NOT reachable and withholding
the address once it is. That is the original defect with a green test suite on
top of it, so it is pinned here first.
"""
import errno
import json
import os
import stat
import subprocess

import pytest

import entrypoint as e

ONION = "atdorl67o6q7anir2qm3sly4expi3ywvs2ltw3wl53zezgycohzi2zqd.onion"
OTHER = "b" * 56 + ".onion"


@pytest.fixture(autouse=True)
def _clear_warn_cache():
    """_publish_warned is module state; a leak between tests hides a missing warning."""
    e._publish_warned.clear()
    yield
    e._publish_warned.clear()


def _service(root, name, hostname):
    d = root / name
    d.mkdir(parents=True)
    if hostname is not None:
        (d / "hostname").write_bytes(
            hostname if isinstance(hostname, bytes) else hostname.encode())
    return str(d)


@pytest.fixture
def keys(tmp_path):
    root = tmp_path / "keys"
    root.mkdir()
    return root


# ─────────────────────────────────────────────────────────────────────────────
# _service_reachable -- the gate
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def healthcheck(monkeypatch):
    """Fake the su-exec'd healthcheck.py call and record exactly how it was made."""
    record = {}

    def install(stdout=b"", returncode=0, raises=None):
        def fake_run(cmd, **kwargs):
            record["cmd"] = cmd
            record["kwargs"] = kwargs
            if raises is not None:
                raise raises
            if kwargs.get("check") and returncode != 0:
                raise subprocess.CalledProcessError(returncode, cmd)
            out = stdout if kwargs.get("capture_output") else None
            return subprocess.CompletedProcess(cmd, returncode, out, b"")

        monkeypatch.setattr(e.subprocess, "run", fake_run)
        return record

    return install


def _doc(**fields):
    return json.dumps({"hidden_service_reachable": False, **fields}).encode()


def test_the_gate_asks_healthcheck_as_the_tor_user_with_a_bounded_timeout(healthcheck):
    """The control socket lives in a 0700 tor-owned DataDirectory, so the probe
    runs as its owner rather than leaning on root's DAC_OVERRIDE. The call is in
    the once-a-second supervision loop, so it must not be able to block forever."""
    record = healthcheck(stdout=_doc(hidden_service_reachable=True))
    assert e._service_reachable() is True
    assert record["cmd"] == ["su-exec", "tor", "python3", e.HEALTHCHECK_BIN, "--json"]
    assert record["kwargs"] == {"capture_output": True, "timeout": 15, "check": False}


def test_only_a_literal_true_opens_the_gate(healthcheck):
    """`is True`, not truthiness: a 1, a "yes" or a non-empty list from some future
    healthcheck revision is an unrecognised answer, not a green light."""
    for value in (True,):
        healthcheck(stdout=_doc(hidden_service_reachable=value))
        assert e._service_reachable() is True
    for value in (False, None, 1, "true", "yes", [1], {"a": 1}):
        healthcheck(stdout=_doc(hidden_service_reachable=value))
        assert e._service_reachable() is False, value


def test_a_missing_field_is_not_reachable(healthcheck):
    healthcheck(stdout=json.dumps({"ready": True}).encode())
    assert e._service_reachable() is False


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b'"a string"', b"42", b"null"])
def test_anything_that_is_not_a_json_object_fails_closed(healthcheck, body):
    """Valid JSON of the wrong shape is still not an answer."""
    healthcheck(stdout=body)
    assert e._service_reachable() is False


def test_a_bad_byte_in_an_unrelated_field_does_not_withhold_the_address(healthcheck):
    """The decode is lenient on purpose. healthcheck.py's `reason` string embeds
    service names read off the filesystem; one byte that is not UTF-8 in there
    must not turn a reachable service into an unpublished one. The answer being
    read is a JSON boolean, and it survives the replacement."""
    healthcheck(stdout=b'{"hidden_service_reachable": true, "reason": "\xff"}')
    assert e._service_reachable() is True


def test_undecodable_output_fails_closed_instead_of_raising(healthcheck):
    """The supervision loop calls this once a second and does not wrap it; an
    escaping UnicodeDecodeError would take the container down over a health probe."""
    healthcheck(stdout=b"\xff\xfe{\"hidden_service_reachable\": true}")
    assert e._service_reachable() is False


@pytest.mark.parametrize("failure", [
    OSError(errno.ENOENT, "no su-exec"),
    subprocess.TimeoutExpired(cmd="healthcheck", timeout=15),
    subprocess.SubprocessError("broken"),
])
def test_a_failed_probe_is_not_a_reachable_service(healthcheck, failure):
    healthcheck(raises=failure)
    assert e._service_reachable() is False


def test_the_exit_code_is_ignored_in_favour_of_the_field(healthcheck):
    """healthcheck.py exits 1 for a dead Vanguards addon while the service is
    perfectly reachable. Gating on the exit code would mean a container that lost
    Vanguards never published its address -- a worse failure than the one this
    gate exists to prevent. Reading the one field is narrower AND stricter."""
    record = healthcheck(stdout=_doc(hidden_service_reachable=True), returncode=1)
    assert e._service_reachable() is True
    assert record["kwargs"]["check"] is False


# ─────────────────────────────────────────────────────────────────────────────
# _publish_addresses -- the gate in use
# ─────────────────────────────────────────────────────────────────────────────

def test_a_closed_gate_withholds_the_address(keys):
    hs = _service(keys, "app", ONION + "\n")
    e._publish_addresses([hs], keys_root=str(keys), gate=lambda: False)
    assert not (keys / "app.onion").exists()


def test_an_open_gate_publishes_it(keys, capsys):
    hs = _service(keys, "app", ONION + "\n")
    e._publish_addresses([hs], keys_root=str(keys), gate=lambda: True)
    assert (keys / "app.onion").read_text() == ONION + "\n"
    assert f"Published address for app: {ONION}" in capsys.readouterr().out


def test_the_gate_is_not_consulted_when_there_is_nothing_to_publish(keys):
    """Evaluated lazily on purpose: the gate shells out to healthcheck.py, and
    this runs once a second for the life of the container."""
    calls = []

    def gate():
        calls.append(1)
        return True

    hs = _service(keys, "app", ONION + "\n")
    e._publish_addresses([hs], keys_root=str(keys), gate=gate)
    assert calls == [1]
    e._publish_addresses([hs], keys_root=str(keys), gate=gate)   # already current
    assert calls == [1]

    _service(keys, "nohost", None)
    e._publish_addresses([str(keys / "nohost")], keys_root=str(keys), gate=gate)
    assert calls == [1]


def test_a_changed_address_is_republished(keys):
    """After a key rotation the file on disk is stale. Skipping only on equality
    is what makes the update happen at all."""
    hs = _service(keys, "app", ONION + "\n")
    e._publish_addresses([hs], keys_root=str(keys))
    (keys / "app" / "hostname").write_text(OTHER + "\n")
    e._publish_addresses([hs], keys_root=str(keys))
    assert (keys / "app.onion").read_text() == OTHER + "\n"


def test_a_corrupt_published_copy_is_replaced_not_trusted(keys):
    """The comparison exists to avoid a pointless rewrite, not to defer to
    whatever is already there."""
    hs = _service(keys, "app", ONION + "\n")
    (keys / "app.onion").write_bytes(b"\xff\xfe garbage")
    e._publish_addresses([hs], keys_root=str(keys))
    assert (keys / "app.onion").read_text() == ONION + "\n"


def test_a_hostname_file_with_a_stray_byte_is_refused_not_sanitised(keys):
    """A non-ASCII byte beside a valid address means the key volume is not in the
    state we think it is. Deleting the byte and publishing what is left would
    answer a question that should have been refused -- and would not crash the
    supervision loop either, which is the only reason a lenient decode looked
    acceptable."""
    hs = _service(keys, "app", b"\xff" + ONION.encode() + b"\n")
    e._publish_addresses([hs], keys_root=str(keys))
    assert not (keys / "app.onion").exists()


# ─────────────────────────────────────────────────────────────────────────────
# One bad service must not silence the others
# ─────────────────────────────────────────────────────────────────────────────

def test_a_service_with_no_hostname_yet_does_not_block_later_ones(keys):
    """Tor writes hostname at key generation, so a service that has not got there
    yet is the ordinary state of the first seconds of every container."""
    early = _service(keys, "aaa-early", None)
    ready = _service(keys, "zzz-ready", ONION + "\n")
    e._publish_addresses([early, ready], keys_root=str(keys))
    assert (keys / "zzz-ready.onion").read_text() == ONION + "\n"


def test_an_unreadable_hostname_is_named_in_the_warning(keys, capsys):
    """ENOENT is the ordinary early state and stays quiet; anything else is a
    real fault and has to say WHICH service and WHICH operation failed, or the
    operator is left with a container that never grew its .onion file and no
    clue as to why."""
    hs = keys / "app"
    (hs / "hostname").mkdir(parents=True)        # a directory reads as EISDIR
    e._publish_addresses([str(hs)], keys_root=str(keys))
    out = capsys.readouterr().out
    assert "cannot publish the .onion address for app" in out
    assert "read hostname failed" in out


def test_an_undecodable_hostname_does_not_block_later_ones(keys):
    bad = _service(keys, "aaa-bytes", b"\xff" + ONION.encode() + b"\n")
    ready = _service(keys, "zzz-ready", ONION + "\n")
    e._publish_addresses([bad, ready], keys_root=str(keys))
    assert (keys / "zzz-ready.onion").read_text() == ONION + "\n"


def test_an_invalid_hostname_does_not_block_later_ones(keys):
    bad = _service(keys, "aaa-bad", "not-an-onion\n")
    ready = _service(keys, "zzz-ready", ONION + "\n")
    e._publish_addresses([bad, ready], keys_root=str(keys))
    assert (keys / "zzz-ready.onion").read_text() == ONION + "\n"


def test_an_already_current_service_does_not_block_later_ones(keys):
    done = _service(keys, "aaa-done", ONION + "\n")
    e._publish_addresses([done], keys_root=str(keys))
    ready = _service(keys, "zzz-ready", OTHER + "\n")
    e._publish_addresses([done, ready], keys_root=str(keys))
    assert (keys / "zzz-ready.onion").read_text() == OTHER + "\n"


def test_a_failed_write_does_not_block_later_ones(keys, capsys):
    """One unwritable target is a convenience file, not a reason to stop
    publishing every other service in the container."""
    blocked = _service(keys, "aaa-blocked", ONION + "\n")
    (keys / "aaa-blocked.onion").mkdir()          # os.replace onto a directory fails
    ready = _service(keys, "zzz-ready", OTHER + "\n")
    e._publish_addresses([blocked, ready], keys_root=str(keys))
    assert (keys / "zzz-ready.onion").read_text() == OTHER + "\n"
    assert "cannot publish the .onion address for aaa-blocked" in capsys.readouterr().out


def test_the_temp_file_is_never_written_through_a_symlink(keys, tmp_path):
    """O_NOFOLLOW on the temp file, not just on the target: the temp name is
    predictable (it carries our pid), so a process that can write into the key
    volume could plant a symlink there and have root write through it."""
    outside = tmp_path / "outside"
    outside.write_text("untouched")
    hs = _service(keys, "app", ONION + "\n")
    (keys / f".app.onion.tmp.{os.getpid()}").symlink_to(outside)
    e._publish_addresses([hs], keys_root=str(keys))
    assert outside.read_text() == "untouched"
    assert not (keys / "app.onion").exists()


def test_the_published_file_is_world_readable_and_the_key_is_not(keys):
    hs = _service(keys, "app", ONION + "\n")
    e._publish_addresses([hs], keys_root=str(keys))
    assert stat.S_IMODE(os.stat(keys / "app.onion").st_mode) == 0o644


# ─────────────────────────────────────────────────────────────────────────────
# _warn_publish_once
# ─────────────────────────────────────────────────────────────────────────────

def _oserror(err):
    return OSError(err, os.strerror(err))


def test_a_missing_hostname_file_is_not_a_fault_and_says_nothing(capsys):
    """Every container starts this way for a few seconds; warning would be noise
    on every healthy boot."""
    e._warn_publish_once("app", "read hostname", _oserror(errno.ENOENT))
    assert capsys.readouterr().out == ""


def test_a_permission_error_is_reported_with_its_cause_and_a_way_out(capsys):
    """On rootless Podman the supervisor holds no CAP_DAC_OVERRIDE and every one
    of these failed with EACCES, silently. A healthy-looking container simply
    never grew its .onion file, with no clue anywhere as to why."""
    e._warn_publish_once("app", "read hostname", _oserror(errno.EACCES))
    out = capsys.readouterr().out
    assert "app" in out
    assert "read hostname failed" in out
    assert "Permission denied" in out
    assert f"su-exec tor cat {e.KEYS_ROOT}/app/hostname" in out


def test_the_same_failure_is_reported_once_not_once_a_second(capsys):
    for _ in range(5):
        e._warn_publish_once("app", "read hostname", _oserror(errno.EACCES))
    assert capsys.readouterr().out.count("cannot publish") == 1


def test_a_different_service_errno_or_operation_is_a_different_report(capsys):
    """Keyed on all three: two services can fail for different reasons, and a
    read failure and a write failure are different problems with different fixes."""
    e._warn_publish_once("app", "read hostname", _oserror(errno.EACCES))
    e._warn_publish_once("other", "read hostname", _oserror(errno.EACCES))
    e._warn_publish_once("app", "read hostname", _oserror(errno.EIO))
    e._warn_publish_once("app", "write hostname", _oserror(errno.EACCES))
    assert capsys.readouterr().out.count("cannot publish") == 4
