"""Writing the torrc, and securing the directories it names.

`build_torrc_string` is pure and heavily tested; `generate_basic_torrc` is the
privileged half that puts the result on disk -- the parent-directory traversal
fix, the per-service mkdir/chmod/chown, and the O_NOFOLLOW write of the config
file itself. Mutation testing found it had no tests at all: all 61 of its mutants
were unreachable, including ones that write the config somewhere else entirely,
loosen the parent directory from 0751 to 0755, or drop the mode from the open.

It was untestable on the host because it spelled `/etc/tor/torrc` and
`/var/lib/tor/hidden_service` inline, so exercising it meant being root inside a
container. Those are now the module constants TORRC_PATH and KEYS_ROOT -- the
same two strings the rest of the module already needed -- and the whole function
runs against a temp directory here.
"""
import os
import stat
from collections import namedtuple

import pytest

import entrypoint as e

TorPw = namedtuple("TorPw", "pw_uid pw_gid")


@pytest.fixture
def container(tmp_path, monkeypatch):
    """Relocate the container's two absolute paths into a temp tree."""
    keys = tmp_path / "hidden_service"
    torrc = tmp_path / "etc" / "torrc"
    torrc.parent.mkdir(parents=True)
    monkeypatch.setattr(e, "KEYS_ROOT", str(keys))
    monkeypatch.setattr(e, "TORRC_PATH", str(torrc))
    monkeypatch.setattr(e.pwd, "getpwnam", lambda name: TorPw(os.getuid(), os.getgid()))
    return namedtuple("Container", "keys torrc")(keys, torrc)


def _one_service(monkeypatch):
    monkeypatch.setenv("APP_TOR_SERVICE_HOSTS", "80:127.0.0.1:8080")


# ─────────────────────────────────────────────────────────────────────────────
# The config file
# ─────────────────────────────────────────────────────────────────────────────

def test_the_torrc_is_written_where_tor_will_read_it(container, monkeypatch, capsys):
    _one_service(monkeypatch)
    hs_dirs, dropped = e.generate_basic_torrc()
    assert container.torrc.exists()
    assert "HiddenServicePort 80 127.0.0.1:8080" in container.torrc.read_text()
    assert hs_dirs == [str(container.keys / "app")]
    assert dropped == []
    assert str(container.torrc) in capsys.readouterr().out


def test_the_torrc_is_readable_by_tor_and_nobody_else(container, monkeypatch):
    """0640 tor:tor. The torrc names every HiddenServiceDir on the host; a
    world-readable copy hands that list to any other uid in the container."""
    _one_service(monkeypatch)
    e.generate_basic_torrc()
    assert stat.S_IMODE(os.stat(container.torrc).st_mode) == 0o640


def test_the_written_bytes_are_exactly_what_the_pure_builder_produced(
        container, monkeypatch):
    """The split into a pure builder plus a privileged writer is only safe while
    the writer adds nothing of its own."""
    _one_service(monkeypatch)
    e.generate_basic_torrc()
    expected, _ = e.build_torrc_string()
    assert container.torrc.read_text() == expected


def test_an_existing_torrc_is_truncated_not_appended_to(container, monkeypatch):
    """O_TRUNC. Appending would leave the previous boot's HiddenServiceDir lines
    in place, and Tor refuses to start on a duplicate directory."""
    container.torrc.write_text("STALE LINE\n" * 500)
    _one_service(monkeypatch)
    e.generate_basic_torrc()
    assert "STALE LINE" not in container.torrc.read_text()


def test_a_symlinked_torrc_is_refused_not_followed(container, monkeypatch, tmp_path):
    """/etc/tor is a tmpfs that starts empty and this runs early as PID 1, so the
    window is small -- but a process that got there first could otherwise have
    root truncate, chmod and chown any file it named."""
    outside = tmp_path / "outside"
    outside.write_text("sensitive")
    container.torrc.symlink_to(outside)
    _one_service(monkeypatch)
    with pytest.raises(OSError):
        e.generate_basic_torrc()
    assert outside.read_text() == "sensitive"


def test_the_write_leaks_no_file_descriptors(container, monkeypatch):
    """The metadata fd is a dup of the write fd and is closed in a finally."""
    _one_service(monkeypatch)
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(25):
        e.generate_basic_torrc()
    assert len(os.listdir("/proc/self/fd")) <= before + 1


# ─────────────────────────────────────────────────────────────────────────────
# The key directories
# ─────────────────────────────────────────────────────────────────────────────

def test_each_service_directory_is_created(container, monkeypatch):
    monkeypatch.setenv("APP_TOR_SERVICE_HOSTS", "80:127.0.0.1:8080")
    monkeypatch.setenv("WEB_TOR_SERVICE_HOSTS", "80:127.0.0.1:9090")
    hs_dirs, _ = e.generate_basic_torrc()
    assert sorted(hs_dirs) == [str(container.keys / "app"), str(container.keys / "web")]
    for d in hs_dirs:
        assert os.path.isdir(d)


def test_a_dropped_service_gets_no_key_directory(container, monkeypatch):
    """Creating a directory for a service that was refused would leave Tor with a
    HiddenServiceDir it was never told about, and the operator with a key
    directory that means nothing."""
    monkeypatch.setenv("BAD_TOR_SERVICE_HOSTS", "99999:127.0.0.1:8080")
    hs_dirs, dropped = e.generate_basic_torrc()
    assert hs_dirs == []
    assert any("no valid port mappings" in reason for reason in dropped)
    assert not (container.keys / "bad").exists()


def test_the_parent_directory_grants_traverse_but_not_list(container, monkeypatch):
    """0751, not 0755. Tor opens its HiddenServiceDir by full path, so it needs
    the execute bit and nothing else; the read bit would let any other uid in the
    container enumerate the name of every onion service configured on the host."""
    container.keys.mkdir()
    os.chmod(container.keys, 0o700)
    _one_service(monkeypatch)
    e.generate_basic_torrc()
    mode = stat.S_IMODE(os.stat(container.keys).st_mode)
    assert mode == 0o751
    assert not mode & stat.S_IROTH, "the service list is readable by other"


def test_a_missing_parent_directory_is_not_an_error(container, monkeypatch):
    """A first boot with no bind mount yet: the per-service mkdir creates the
    whole path, and the parent chmod is simply skipped."""
    assert not container.keys.exists()
    _one_service(monkeypatch)
    hs_dirs, _ = e.generate_basic_torrc()
    assert os.path.isdir(hs_dirs[0])


def test_a_symlinked_parent_directory_is_refused(container, monkeypatch, tmp_path):
    """The key volume is operator-supplied and may be restored from untrusted
    media. A symlink in its place must stop startup, not redirect root's chmod."""
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    os.chmod(outside, 0o700)
    container.keys.symlink_to(outside)
    _one_service(monkeypatch)
    with pytest.raises(OSError):
        e.generate_basic_torrc()
    assert stat.S_IMODE(os.stat(outside).st_mode) == 0o700


def test_every_service_directory_is_handed_to_the_tor_user(container, monkeypatch):
    """Tor drops to uid 100 before it ever opens these; a directory left owned by
    root is a service that cannot start."""
    seen = []
    monkeypatch.setattr(e, "_chown_r", lambda path, uid, gid: seen.append((path, uid, gid)))
    monkeypatch.setattr(e.pwd, "getpwnam", lambda name: TorPw(100, 101))
    # The torrc fchown to uid 100 needs root; the subject here is the key dirs.
    monkeypatch.setattr(e.os, "fchown", lambda fd, uid, gid: None)
    monkeypatch.setenv("APP_TOR_SERVICE_HOSTS", "80:127.0.0.1:8080")
    monkeypatch.setenv("WEB_TOR_SERVICE_HOSTS", "80:127.0.0.1:9090")
    e.generate_basic_torrc()
    assert sorted(seen) == [
        (str(container.keys / "app"), 100, 101),
        (str(container.keys / "web"), 100, 101),
    ]


def test_the_owner_looked_up_is_the_tor_user(container, monkeypatch):
    """`pwd.getpwnam('tor')`. Any other name is either a lookup failure at boot or,
    worse, a different uid owning the onion keys."""
    asked = []
    monkeypatch.setattr(e.pwd, "getpwnam",
                        lambda name: asked.append(name) or TorPw(os.getuid(), os.getgid()))
    _one_service(monkeypatch)
    e.generate_basic_torrc()
    assert asked == ["tor"]


# ─────────────────────────────────────────────────────────────────────────────
# _prepare_hs_dir, the per-service half
# ─────────────────────────────────────────────────────────────────────────────

def test_preparing_an_existing_directory_is_not_an_error(tmp_path):
    """Containers restart. On the second boot the directory is already there,
    owned by the tor user, holding the onion key -- and must be left alone, not
    refused and not recreated."""
    d = tmp_path / "app"
    d.mkdir()
    (d / "hs_ed25519_secret_key").write_text("key")
    e._prepare_hs_dir(str(d), TorPw(os.getuid(), os.getgid()))
    assert (d / "hs_ed25519_secret_key").read_text() == "key"


def test_preparing_creates_missing_parents(tmp_path):
    d = tmp_path / "keys" / "nested" / "app"
    e._prepare_hs_dir(str(d), TorPw(os.getuid(), os.getgid()))
    assert d.is_dir()


def test_preparing_only_chmods_a_directory_it_owns_as_root(tmp_path, monkeypatch):
    """CAP_FOWNER is not assumed, and on a restart the directory already belongs
    to the tor user: chmod'ing it would fail. Passing the guard is what makes the
    second boot work."""
    seen = {}
    monkeypatch.setattr(
        e, "_chmod_dir_nofollow",
        lambda path, mode, **kw: seen.update(path=path, mode=mode, kw=kw))
    monkeypatch.setattr(e, "_chown_r", lambda *a: None)
    e._prepare_hs_dir(str(tmp_path / "app"), TorPw(1, 1))
    assert seen["mode"] == 0o700
    assert seen["kw"] == {"only_if_root_owned": True}


# ─────────────────────────────────────────────────────────────────────────────
# _chmod_dir_nofollow's ownership guard
# ─────────────────────────────────────────────────────────────────────────────

def _fake_fstat(monkeypatch, uid):
    real = os.fstat

    def fake(fd):
        st = real(fd)
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, uid,
                               st.st_gid, st.st_size, 0, 0, 0))

    monkeypatch.setattr(e.os, "fstat", fake)


def test_the_ownership_guard_compares_against_root_not_some_other_uid(
        tmp_path, monkeypatch):
    """`st_uid != 0`. The guard means "root still owns this, so we may secure it".
    Against any other uid it either chmods directories we do not own (which needs
    CAP_FOWNER and fails) or skips ones we do."""
    d = tmp_path / "hs"
    d.mkdir()
    os.chmod(d, 0o755)  # noqa: S103 - the loose mode is the precondition

    _fake_fstat(monkeypatch, uid=0)
    assert e._chmod_dir_nofollow(str(d), 0o700, only_if_root_owned=True) is True
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700

    os.chmod(d, 0o755)  # noqa: S103 - must be left untouched; that is the assertion
    _fake_fstat(monkeypatch, uid=1)
    assert e._chmod_dir_nofollow(str(d), 0o700, only_if_root_owned=True) is False
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o755


def test_a_failure_while_writing_does_not_fail_again_in_the_cleanup(container,
                                                                    monkeypatch):
    """The metadata descriptor is a dup of the write descriptor, closed in a
    finally. If the dup itself fails, the finally must still be able to tell that
    there is nothing to close -- a sentinel that is merely falsy would raise a
    TypeError from os.close and replace the real error with a confusing one."""
    _one_service(monkeypatch)

    def no_dup(fd):
        raise OSError(24, "Too many open files")

    monkeypatch.setattr(e.os, "dup", no_dup)
    with pytest.raises(OSError) as exc:
        e.generate_basic_torrc()
    assert exc.value.errno == 24
