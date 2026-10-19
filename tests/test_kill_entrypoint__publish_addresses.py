"""The temp-file contract of _publish_addresses, pinned from the outside.

A temporary file is only useful if its name is unpredictable (so nothing can be
planted at it), if it leaves no trace of a name this call did not create, and if
a failure after ``os.open`` removes the temp FIFO this call did create. Those
properties are observable through the filesystem and through the operator
message, so they are what these tests assert.
"""
import errno
import os
import stat

import pytest

import entrypoint as e

ONION = "atdorl67o6q7anir2qm3sly4expi3ywvs2ltw3wl53zezgycohzi2zqd.onion"
TOKEN_LEN = 8


@pytest.fixture(autouse=True)
def _clear_warn_cache():
    """_publish_warned is module state; a leak between tests hides a warning."""
    e._publish_warned.clear()
    yield
    e._publish_warned.clear()


@pytest.fixture
def keys(tmp_path):
    root = tmp_path / "keys"
    root.mkdir()
    return root


def _service(root, name, hostname):
    d = root / name
    d.mkdir(parents=True)
    if hostname is not None:
        (d / "hostname").write_bytes(
            hostname if isinstance(hostname, bytes) else hostname.encode())
    return str(d)


def _temp_names(root, name="app"):
    return [p.name for p in root.iterdir() if p.name.startswith(f".{name}.onion")]


def test_the_temp_name_carries_eight_hex_bytes_of_entropy(keys, monkeypatch):
    """The temp name must be unguessable: the old one was `.app.onion.tmp.1`
    (the supervisor is PID 1) and something could be planted at it. The width of
    the random part is what makes planting infeasible, so it is recorded and
    measured at the call site, not assumed."""
    widths = []
    real = e.secrets.token_hex

    def spy(n):
        widths.append(n)
        return real(n)

    monkeypatch.setattr(e.secrets, "token_hex", spy)
    hs = _service(keys, "app", ONION + "\n")
    e._publish_addresses([hs], keys_root=str(keys))
    assert widths == [TOKEN_LEN], "token_hex must be asked for 8 random bytes"
    token = real(TOKEN_LEN)
    assert len(token) == 2 * TOKEN_LEN
    assert int(token, 16) >= 0            # it is hex, not some other encoding
    assert (keys / "app.onion").read_text() == ONION + "\n"
    assert _temp_names(keys) == [], "the temp file is renamed away, not left behind"


def test_a_temp_name_this_call_did_not_create_is_left_alone(keys, monkeypatch):
    """`created` starts False so that a failure BEFORE os.open -- a planted
    symlink or hardlink at the temp name, which O_EXCL refuses -- does not delete
    whatever is sitting there. The planted object here is a file belonging to
    somebody else: if the code treats it as its own, it removes it."""
    monkeypatch.setattr(e.secrets, "token_hex", lambda n: "t0")
    hs = _service(keys, "app", ONION + "\n")
    planted = keys / ".app.onion.t0.tmp"
    planted.write_text("not ours")
    e._publish_addresses([hs], keys_root=str(keys))
    assert planted.exists(), "a name this call never created is not ours to remove"
    assert planted.read_text() == "not ours"
    assert not (keys / "app.onion").exists()


def test_a_temp_file_created_by_this_call_is_removed_when_the_write_fails(
        keys, monkeypatch):
    """`created = True` right after os.open is what makes the cleanup possible: a
    fault AFTER the temp file exists must not leave the temp behind. Without it
    the key volume slowly fills with `.app.onion.<hex>.tmp` on every tick."""
    monkeypatch.setattr(e.secrets, "token_hex", lambda n: "t0")
    hs = _service(keys, "app", ONION + "\n")

    def boom(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(e.os, "fchmod", boom)

    def no_op(*a, **k):
        raise AssertionError("must not reach os.replace after a failed write")

    monkeypatch.setattr(e.os, "replace", no_op)
    e._publish_addresses([hs], keys_root=str(keys))

    assert _temp_names(keys) == [], "the temp file this call made must be cleaned up"
    assert not (keys / "app.onion").exists()


def test_a_fault_after_the_temp_file_exists_is_reported(keys, monkeypatch,
                                                                    capsys):
    """Suppressing OSError while unlinking must not suppress the warning itself:
    the operator still needs to be told which write failed and why."""
    monkeypatch.setattr(e.secrets, "token_hex", lambda n: "t0")
    hs = _service(keys, "app", ONION + "\n")

    def boom(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(e.os, "fchmod", boom)
    e._publish_addresses([hs], keys_root=str(keys))
    out = capsys.readouterr().out
    assert "cannot publish the .onion address for app" in out
    assert "write" in out and "app.onion" in out and "failed" in out
    assert "No space left on device" in out


def test_cleanup_never_masks_the_real_failure(keys, monkeypatch, capsys):
    """The unlink is best-effort: if the temp cannot be removed either, that
    second OSError must not escape. The supervision loop calls this once a
    second and does not wrap it, so an escaping error takes PID 1 down."""
    monkeypatch.setattr(e.secrets, "token_hex", lambda n: "t0")
    hs = _service(keys, "app", ONION + "\n")

    def bad_chmod(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    def bad_unlink(self, *a, **k):
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(e.os, "fchmod", bad_chmod)
    monkeypatch.setattr(e.Path, "unlink", bad_unlink)
    e._publish_addresses([hs], keys_root=str(keys))   # must not raise
    assert "write" in capsys.readouterr().out


def test_a_successful_publish_leaves_no_temp_file(keys):
    """Steady state: one readable address file, nothing else."""
    hs = _service(keys, "app", ONION + "\n")
    e._publish_addresses([hs], keys_root=str(keys))
    published = keys / "app.onion"
    assert published.read_text() == ONION + "\n"
    assert stat.S_IMODE(os.stat(published).st_mode) == 0o644
    assert _temp_names(keys) == []
