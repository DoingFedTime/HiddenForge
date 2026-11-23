"""vanity.py driven end to end against a real generator process.

The onion key IS the address, and losing it loses the address permanently. So
almost everything in vanity.py is a refusal: refuse to install a key set whose
directory name, hostname file and public key disagree; refuse to overwrite an
existing key set; archive rather than delete when forced; refuse to clobber a
key that appeared while the search was running.

None of those refusals were tested. Mutation testing put a number on it: 595 of
vanity.py's 696 mutants had no test touching them at all, because the existing
suite covers the pure helpers and leaves the generator path to the live E2E run
that needs the built image.

They are exercised here for real, against tests/fake_mkp224o.py -- a stand-in
that speaks mkp224o's actual command line and writes a real Tor key directory
from a published test vector. The vector's address starts with `a`, so `a` is
the prefix throughout: a one-character prefix is satisfied on the first try and
keeps the tests about the refusals rather than about searching.
"""
import ast
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from loader import load_file, source_path

VANITY_PATH = source_path(__file__, "vanity.py")
FAKE = Path(__file__).resolve().parent / "fake_mkp224o.py"

VECTOR_ONION = "atdorl67o6q7anir2qm3sly4expi3ywvs2ltw3wl53zezgycohzi2zqd.onion"
PREFIX = "a"


@pytest.fixture(scope="module")
def v():
    # The module name is load-bearing under mutation testing; see test_vanity.py.
    return load_file(VANITY_PATH, "vanity")


@pytest.fixture
def mkp224o(tmp_path, monkeypatch):
    """Point vanity.py at the fake generator and return a mode setter.

    A shell wrapper rather than the .py directly: mkp224o_path() requires the
    executable bit, and a file copied into a mutation-testing tree does not
    necessarily keep one.
    """
    wrapper = tmp_path / "mkp224o"
    wrapper.write_text(f'#!/bin/sh\nexec {sys.executable} {FAKE} "$@"\n')
    wrapper.chmod(0o755)
    monkeypatch.setenv("MKP224O", str(wrapper))

    def mode(name, **env):
        monkeypatch.setenv("HF_FAKE_MKP224O", name)
        for key, value in env.items():
            monkeypatch.setenv(key, str(value))

    mode("ok")
    mode.wrapper = wrapper
    return mode


@pytest.fixture
def keys(tmp_path):
    return tmp_path / "keys"


# ─────────────────────────────────────────────────────────────────────────────
# Finding and invoking the generator
# ─────────────────────────────────────────────────────────────────────────────

def test_the_env_override_wins_over_the_image_paths(v, mkp224o):
    assert v.mkp224o_path() == str(mkp224o.wrapper)


def test_a_non_executable_override_is_skipped_not_used(v, tmp_path, monkeypatch):
    """A path that exists but cannot be executed is not a generator. Returning it
    turns a clear "not found" into a PermissionError from Popen."""
    dud = tmp_path / "mkp224o"
    dud.write_text("#!/bin/sh\n")
    dud.chmod(0o644)
    monkeypatch.setenv("MKP224O", str(dud))
    monkeypatch.setattr(v.shutil, "which", lambda name: None)
    with pytest.raises(FileNotFoundError):
        v.mkp224o_path()


def test_a_directory_named_like_the_generator_is_skipped(v, tmp_path, monkeypatch):
    d = tmp_path / "mkp224o"
    d.mkdir(mode=0o755)
    monkeypatch.setenv("MKP224O", str(d))
    monkeypatch.setattr(v.shutil, "which", lambda name: None)
    with pytest.raises(FileNotFoundError):
        v.mkp224o_path()


def test_the_path_is_the_last_resort(v, tmp_path, monkeypatch):
    monkeypatch.delenv("MKP224O", raising=False)
    monkeypatch.setattr(v.shutil, "which", lambda name: "/somewhere/mkp224o")
    assert v.mkp224o_path() == "/somewhere/mkp224o"


def test_a_missing_generator_says_where_to_get_one(v, monkeypatch):
    """This module only ever runs inside the image, which vendors mkp224o. Run
    on a host it has to say so rather than report a bare ENOENT."""
    monkeypatch.delenv("MKP224O", raising=False)
    monkeypatch.setattr(v.shutil, "which", lambda name: None)
    monkeypatch.setattr(v.os.path, "isfile", lambda p: False)
    with pytest.raises(FileNotFoundError) as exc:
        v.mkp224o_path()
    assert "requires the hiddenforge image" in str(exc.value)
    assert "hiddenforge vanity" in str(exc.value)


def test_the_generator_is_invoked_with_the_documented_flags(v, mkp224o, tmp_path,
                                                            monkeypatch):
    """-d output dir, -t threads, -n how many to find, and the prefix LAST --
    mkp224o takes filters as positional arguments, so a prefix that moved in
    front of a flag would be read as that flag's value."""
    record = tmp_path / "argv"
    monkeypatch.setenv("HF_FAKE_MKP224O_RECORD", str(record))
    out = tmp_path / "out"
    out.mkdir()
    proc = v._run_mkp224o(PREFIX, out, threads=3, count=1)
    proc.communicate()
    assert record.read_text().strip() == repr(
        ["-d", str(out), "-t", "3", "-n", "1", PREFIX])


def test_the_benchmark_invocation_asks_for_statistics(v, mkp224o, tmp_path, monkeypatch):
    """-S <secs> -T is what makes mkp224o emit the calc/sec lines the benchmark
    reads; -n 0 means "never stop", which is what a timed measurement wants."""
    record = tmp_path / "argv"
    monkeypatch.setenv("HF_FAKE_MKP224O_RECORD", str(record))
    out = tmp_path / "out"
    out.mkdir()
    # -n 0 runs until it is killed, exactly as the real generator does, so this
    # reads the recorded argv and stops it rather than waiting for an exit.
    proc = v._run_mkp224o("zz", out, threads=2, count=0, stats_every=1)
    try:
        deadline = time.monotonic() + 10
        while not record.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    assert record.read_text().strip() == repr(
        ["-d", str(out), "-t", "2", "-n", "0", "-S", "1", "-T", "zz"])


def test_the_generator_stdout_is_discarded_and_stderr_is_captured(v, mkp224o, tmp_path):
    """mkp224o prints found addresses on stdout and statistics on stderr. The
    addresses are read off the filesystem, and stderr is the only thing that
    explains a failure."""
    out = tmp_path / "out"
    out.mkdir()
    proc = v._run_mkp224o(PREFIX, out, threads=1, count=1)
    stdout, stderr = proc.communicate()
    assert stdout is None
    assert stderr == ""


# ─────────────────────────────────────────────────────────────────────────────
# benchmark
# ─────────────────────────────────────────────────────────────────────────────

def test_the_benchmark_reports_the_measured_rate(v, mkp224o):
    mkp224o("bench", HF_FAKE_MKP224O_RATE=2_500_000)
    assert v.benchmark(1, threads=2) == pytest.approx(2_500_000)


def test_the_benchmark_kills_the_generator_it_started(v, mkp224o):
    """mkp224o is started with -n 0: it runs until it is stopped. A benchmark
    that returned without terminating it would leave a process pinning every
    core of the container for the rest of its life."""
    started = []
    real_popen = subprocess.Popen

    def recording(cmd, **kwargs):
        proc = real_popen(cmd, **kwargs)
        started.append(proc)
        return proc

    # The fake must outlive the window, or it exits on its own and the assertion
    # below passes whether or not benchmark stopped anything. Two other tests in
    # this file were weakened the same way; a stand-in that finishes by itself
    # rescues the mutant it was written to catch.
    mkp224o("bench", HF_FAKE_MKP224O_MAX=10_000)
    original = v.subprocess.Popen
    v.subprocess.Popen = recording
    try:
        v.benchmark(1, threads=1)
    finally:
        v.subprocess.Popen = original
    assert started
    assert started[0].poll() is not None, "the benchmark child is still running"


def test_a_generator_that_reports_nothing_is_a_failed_benchmark(v, mkp224o):
    """Returning 0 keys/sec would make the difficulty table read "infinite" for
    every prefix; returning some default would be a fabricated measurement."""
    mkp224o("silent")
    with pytest.raises(RuntimeError, match="no statistics"):
        v.benchmark(1, threads=1)


def test_a_zero_second_benchmark_still_measures_something(v, mkp224o):
    """`--seconds 0` is a plausible thing for an operator to type. A zero-length
    window would read no lines at all and fail as "no statistics"."""
    mkp224o("bench")
    assert v.benchmark(0, threads=1) > 0


# ─────────────────────────────────────────────────────────────────────────────
# generate: the verification chain
# ─────────────────────────────────────────────────────────────────────────────

def test_a_generated_key_set_is_installed_and_described(v, mkp224o, keys):
    result = v.generate(PREFIX, "app", keys, threads=1, force=False)
    target = keys / "app"
    assert result["onion"] == VECTOR_ONION
    assert result["name"] == "app"
    assert result["key_dir"] == str(target)
    assert result["key_path"] == str(target / "hs_ed25519_secret_key")
    assert result["archived"] is None
    assert result["threads"] == 1
    assert (target / "hostname").read_text().strip() == VECTOR_ONION
    assert (target / "hs_ed25519_secret_key").exists()


def test_the_installed_key_set_has_tor_modes(v, mkp224o, keys):
    """0700 directory, 0600 keys. The hostname is 0644 because it is the public
    address and the entrypoint republishes it anyway."""
    v.generate(PREFIX, "app", keys, threads=1, force=False)
    target = keys / "app"
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(target / "hs_ed25519_secret_key").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(target / "hs_ed25519_public_key").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(target / "hostname").st_mode) == 0o644


def test_nothing_is_left_behind_in_the_key_volume(v, mkp224o, keys):
    """The search runs in a temp directory INSIDE the key volume, so a leaked one
    leaves key material outside the 0700 service directory."""
    v.generate(PREFIX, "app", keys, threads=1, force=False)
    assert [p.name for p in keys.iterdir()] == ["app"]


def test_an_address_that_does_not_match_the_prefix_is_refused(v, mkp224o, keys):
    """The one thing the operator actually asked for. A generator that ignored
    the filter would otherwise install an unrelated address under the name they
    chose, and the key is the address."""
    with pytest.raises(RuntimeError, match="does not start with prefix"):
        v.generate("zz", "app", keys, threads=1, force=False)
    assert not (keys / "app").exists()


def test_a_directory_name_that_is_not_an_address_is_refused(v, mkp224o, keys):
    mkp224o("badname")
    with pytest.raises(RuntimeError, match="invalid address name"):
        v.generate(PREFIX, "app", keys, threads=1, force=False)
    assert not (keys / "app").exists()


def test_a_hostname_file_that_disagrees_is_refused(v, mkp224o, keys):
    mkp224o("hostname")
    with pytest.raises(RuntimeError, match="disagrees with directory name"):
        v.generate(PREFIX, "app", keys, threads=1, force=False)
    assert not (keys / "app").exists()


def test_a_public_key_that_derives_elsewhere_is_refused(v, mkp224o, keys):
    """The independent re-derivation is the only check that catches a swapped or
    corrupt key pair: the directory name and the hostname file both come from
    the generator and can agree with each other while being wrong."""
    mkp224o("pubkey")
    with pytest.raises(RuntimeError, match="derived from public key"):
        v.generate(PREFIX, "app", keys, threads=1, force=False)
    assert not (keys / "app").exists()


def test_more_than_one_generated_address_is_refused(v, mkp224o, keys):
    """Which one would be installed? Picking arbitrarily means the operator
    cannot know which key set they got."""
    mkp224o("two")
    with pytest.raises(RuntimeError, match="exactly one"):
        v.generate(PREFIX, "app", keys, threads=1, force=False)


def test_a_generator_that_produced_nothing_is_refused(v, mkp224o, keys):
    mkp224o("empty")
    with pytest.raises(RuntimeError, match="found 0"):
        v.generate(PREFIX, "app", keys, threads=1, force=False)


def test_a_generator_that_failed_reports_its_stderr(v, mkp224o, keys):
    """Exit code alone does not say what went wrong, and this is the only place
    mkp224o's own diagnostics are ever seen."""
    mkp224o("fail")
    with pytest.raises(RuntimeError) as exc:
        v.generate(PREFIX, "app", keys, threads=1, force=False)
    assert "exited 2" in str(exc.value)
    assert "exploded" in str(exc.value)


# ─────────────────────────────────────────────────────────────────────────────
# generate: never destroy a key
# ─────────────────────────────────────────────────────────────────────────────

def test_an_existing_key_set_is_not_overwritten(v, mkp224o, keys):
    existing = keys / "app"
    existing.mkdir(parents=True)
    (existing / "hs_ed25519_secret_key").write_bytes(b"the real key")
    with pytest.raises(FileExistsError) as exc:
        v.generate(PREFIX, "app", keys, threads=1, force=False)
    assert "there is no recovery" in str(exc.value)
    assert (existing / "hs_ed25519_secret_key").read_bytes() == b"the real key"


def test_a_symlink_where_the_key_set_goes_is_not_overwritten(v, mkp224o, keys, tmp_path):
    """`Path.exists()` follows symlinks and reports False for a broken one, so
    the symlink is tested for separately. Without that, a dangling link at the
    destination would be silently replaced -- and a live one would have the
    rename land on whatever it pointed at."""
    keys.mkdir()
    (keys / "app").symlink_to(tmp_path / "nowhere")
    with pytest.raises(FileExistsError):
        v.generate(PREFIX, "app", keys, threads=1, force=False)


def test_force_archives_the_old_key_set_rather_than_deleting_it(v, mkp224o, keys):
    """--force means "I want a new address", not "destroy the old identity". The
    old key set is renamed aside and the path is reported back."""
    existing = keys / "app"
    existing.mkdir(parents=True)
    (existing / "hs_ed25519_secret_key").write_bytes(b"the old key")
    result = v.generate(PREFIX, "app", keys, threads=1, force=True)
    archived = Path(result["archived"])
    assert archived.is_dir()
    assert archived.name.startswith("app.replaced-")
    assert (archived / "hs_ed25519_secret_key").read_bytes() == b"the old key"
    assert (keys / "app" / "hostname").read_text().strip() == VECTOR_ONION


def test_force_removes_the_published_address_of_the_replaced_key(v, mkp224o, keys):
    """<name>.onion is the container's copy of the OLD address. `show` reads it
    from the host, so leaving it would report the replaced key's address with
    ok: true until the container republished."""
    (keys / "app").mkdir(parents=True)
    (keys / "app" / "hs_ed25519_secret_key").write_bytes(b"the old key")
    (keys / "app.onion").write_text("b" * 56 + ".onion\n")
    (keys / "other.onion").write_text("c" * 56 + ".onion\n")
    v.generate(PREFIX, "app", keys, threads=1, force=True)
    assert not (keys / "app.onion").exists()
    assert (keys / "other.onion").exists(), "only the replaced service's file goes"


def test_two_forced_replacements_in_the_same_second_do_not_collide(v, mkp224o, keys):
    """The archive name carries a whole-second timestamp, so two runs a moment
    apart would otherwise rename the second key set onto the first -- destroying
    the very thing the archive exists to preserve."""
    first = keys / "app"
    first.mkdir(parents=True)
    (first / "hs_ed25519_secret_key").write_bytes(b"key one")
    v.generate(PREFIX, "app", keys, threads=1, force=True)
    (keys / "app" / "hs_ed25519_secret_key").write_bytes(b"key two")
    v.generate(PREFIX, "app", keys, threads=1, force=True)
    archives = sorted(p for p in keys.iterdir() if p.name.startswith("app.replaced-"))
    assert len(archives) == 2
    contents = {(p / "hs_ed25519_secret_key").read_bytes() for p in archives}
    assert contents == {b"key one", b"key two"}


def test_the_archive_path_keeps_looking_until_it_finds_a_free_name(v, keys):
    keys.mkdir()
    base = v._unique_archive_path(keys, "app")
    base.mkdir()
    Path(f"{base}-1").mkdir()
    third = v._unique_archive_path(keys, "app")
    assert third.name.endswith("-2")
    assert not third.exists()


def test_a_key_that_appears_during_the_search_is_not_clobbered(v, mkp224o, keys,
                                                               monkeypatch):
    """Exit code 3 in the contract this shares with the host CLI, and its own
    exception type: something else wrote to the key volume while we were
    searching, and nothing of theirs was touched."""
    real_rename = os.rename

    def racing_rename(src, dst):
        if str(dst).endswith("/app"):
            os.makedirs(dst, exist_ok=True)
            raise OSError(39, "Directory not empty")
        return real_rename(src, dst)

    monkeypatch.setattr(v.os, "rename", racing_rename)
    with pytest.raises(v.KeyRaceError) as exc:
        v.generate(PREFIX, "app", keys, threads=1, force=False)
    assert "appeared while the search was running" in str(exc.value)
    assert isinstance(exc.value, FileExistsError), "old callers must still catch it"


def test_a_rename_that_failed_for_another_reason_is_not_called_a_race(v, mkp224o,
                                                                     keys, monkeypatch):
    """Reporting every rename failure as a race would send an operator looking
    for a second writer that does not exist."""
    def broken_rename(src, dst):
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr(v.os, "rename", broken_rename)
    with pytest.raises(OSError) as exc:
        v.generate(PREFIX, "app", keys, threads=1, force=False)
    assert not isinstance(exc.value, FileExistsError)


# ─────────────────────────────────────────────────────────────────────────────
# _harden
# ─────────────────────────────────────────────────────────────────────────────

def test_hardening_never_follows_a_symlink_into_the_key_volume(v, tmp_path):
    """The output directory is operator-supplied. A symlink planted inside it
    must not have its target's mode or owner changed."""
    outside = tmp_path / "outside"
    outside.write_text("sensitive")
    os.chmod(outside, 0o666)  # noqa: S103 - must stay 0666; that is the assertion
    d = tmp_path / "svc"
    d.mkdir()
    (d / "hostname").write_text(VECTOR_ONION + "\n")
    (d / "evil").symlink_to(outside)

    v._harden(d, None, None)
    assert stat.S_IMODE(os.stat(outside).st_mode) == 0o666
    assert (d / "evil").is_symlink(), "the link itself must be left in place"
    # And the scan CONTINUES past it. "evil" sorts before "hostname", so a `break`
    # there would leave every later file at whatever mode it was created with --
    # including the secret key.
    assert stat.S_IMODE(os.stat(d / "hostname").st_mode) == 0o644


def test_hardening_cannot_be_redirected_by_a_symlink_swapped_in_mid_flight(v, tmp_path,
                                                                           monkeypatch):
    """The real property, not the easy one. Checking `is_symlink()` and then
    calling `os.chmod(path, ...)` re-resolves the name, so a process that can
    write into the key volume could swap a regular file for a symlink between the
    two and have the chmod land on the target.

    The swap is forced here by replacing os.listdir: by the time the entry is
    opened, `secret` is a symlink to a file outside the directory. An
    implementation that chmods by path changes that file's mode; one that holds
    an O_NOFOLLOW descriptor cannot."""
    outside = tmp_path / "outside"
    outside.write_text("sensitive")
    os.chmod(outside, 0o666)  # noqa: S103 - must stay 0666; that is the assertion
    d = tmp_path / "svc"
    d.mkdir()
    (d / "hostname").write_text(VECTOR_ONION + "\n")
    (d / "secret").write_bytes(b"k")

    real_listdir = os.listdir

    def swapping_listdir(target):
        names = real_listdir(target)
        (d / "secret").unlink()
        (d / "secret").symlink_to(outside)
        return names

    monkeypatch.setattr(v.os, "listdir", swapping_listdir)
    v._harden(d, None, None)
    assert stat.S_IMODE(os.stat(outside).st_mode) == 0o666


def test_hardening_refuses_a_key_directory_that_is_not_a_directory(v, tmp_path):
    """O_DIRECTORY, not just O_NOFOLLOW. Without it, a FIFO planted where the key
    directory should be is opened for reading and BLOCKS until someone writes to
    it -- `hiddenforge vanity` would hang for ever instead of refusing. With it
    the open fails immediately.

    Run on a thread with a bound, because the failure this guards against is a
    hang, and a hang in a test run is indistinguishable from a slow machine."""
    fifo = tmp_path / "svc"
    os.mkfifo(fifo)
    box = {}

    def run():
        try:
            v._harden(fifo, None, None)
        except BaseException as exc:   # reported in the calling thread
            box["exc"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive(), "_harden blocked on a FIFO instead of refusing it"
    assert isinstance(box.get("exc"), OSError)


def test_hardening_sets_the_owner_on_the_same_descriptor_as_the_mode(v, tmp_path,
                                                                     monkeypatch):
    """Asserted on the call rather than the effect, so it needs no root. Every
    fchown must name a descriptor this function opened, not a path and not None."""
    calls = []

    def record(fd, u, g):
        assert isinstance(fd, int), f"fchown was handed a {type(fd).__name__}"
        calls.append((fd, u, g))

    monkeypatch.setattr(v.os, "fchown", record)
    d = tmp_path / "svc"
    d.mkdir()
    (d / "hostname").write_text(VECTOR_ONION + "\n")
    (d / "hs_ed25519_secret_key").write_bytes(b"k")
    v._harden(d, 100, 101)
    assert len(calls) == 3, "both files and the directory"
    assert {(u, g) for _fd, u, g in calls} == {(100, 101)}


@pytest.mark.parametrize("uid,gid,expected", [
    (100, None, (100, -1)),
    (None, 101, (-1, 101)),
    (100, 101, (100, 101)),
])
def test_hardening_leaves_unspecified_ids_alone(v, tmp_path, monkeypatch, uid, gid,
                                                 expected):
    """-1 is chown's "do not change this". Any other filler -- 0, or 1 -- hands
    the onion key to root or to daemon."""
    calls = []

    def record(fd, u, g):
        assert isinstance(fd, int), f"fchown was handed a {type(fd).__name__}"
        calls.append((u, g))

    monkeypatch.setattr(v.os, "fchown", record)
    d = tmp_path / "svc"
    d.mkdir()
    (d / "hostname").write_text(VECTOR_ONION + "\n")
    v._harden(d, uid, gid)
    assert set(calls) == {expected}


def test_hardening_is_skipped_entirely_when_no_owner_was_asked_for(v, tmp_path,
                                                                   monkeypatch):
    calls = []
    monkeypatch.setattr(v.os, "fchown", lambda *a: calls.append(a))
    d = tmp_path / "svc"
    d.mkdir()
    (d / "hostname").write_text(VECTOR_ONION + "\n")
    v._harden(d, None, None)
    assert calls == []


def test_hardening_refuses_a_symlinked_key_directory(v, tmp_path):
    """The directory itself is opened O_NOFOLLOW too: a symlink in place of the
    freshly renamed key directory must stop the operation, not be followed."""
    real = tmp_path / "real"
    real.mkdir()
    os.chmod(real, 0o755)  # noqa: S103 - must stay 0755; that is the assertion
    link = tmp_path / "svc"
    link.symlink_to(real)
    with pytest.raises(OSError):
        v._harden(link, None, None)
    assert stat.S_IMODE(os.stat(real).st_mode) == 0o755


# ─────────────────────────────────────────────────────────────────────────────
# The CLI
# ─────────────────────────────────────────────────────────────────────────────
#
# main() is what `docker run <image> vanity ...` reaches, and its exit codes are
# a published contract: manifest.json and `hiddenforge info` both carry the same
# table, and the host CLI branches on them. They are asserted as numbers here
# for that reason.

def _json(capsys):
    return json.loads(capsys.readouterr().out)


def test_a_generated_address_is_reported_and_exits_zero(v, mkp224o, keys, capsys):
    rc = v.main(["--prefix", PREFIX, "--name", "app", "--out", str(keys),
                 "--seconds", "1", "--json"])
    assert rc == 0
    doc = _json(capsys)
    assert doc["ok"] is True
    assert doc["exit_code"] == 0
    assert doc["onion"] == VECTOR_ONION
    assert doc["address_matches_prefix"] is True
    assert doc["key_dir"] == str(keys / "app")


def test_the_human_output_says_where_the_key_is_and_to_back_it_up(v, mkp224o, keys,
                                                                  capsys):
    """Losing this directory loses the address permanently and there is no
    recovery, so the one line an operator must read is the backup line."""
    rc = v.main(["--prefix", PREFIX, "--name", "app", "--out", str(keys),
                 "--seconds", "1"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out == (
        f"Found {VECTOR_ONION}\n"
        f"Wrote {keys / 'app' / 'hs_ed25519_secret_key'} (secret, mode 0600)\n"
        f"Back up {keys / 'app'} - losing it loses the address permanently.\n")


@pytest.mark.parametrize("bad", ["", "A", "a0", "a1", "a8", "a9", "a-b", "a" * 13])
def test_a_prefix_that_is_not_base32_is_a_usage_error(v, mkp224o, keys, capsys, bad):
    """0, 1, 8 and 9 are not in the base32 alphabet, so no such address can ever
    exist. Searching for one would run until the heat death of the container."""
    rc = v.main(["--prefix", bad, "--out", str(keys), "--json"])
    assert rc == 2
    doc = _json(capsys)
    assert doc["ok"] is False
    # Exact: this message is the only place the alphabet is written down for the
    # operator, and "0,1,8,9" is the part they need.
    assert doc["error"] == (
        f"invalid prefix {bad!r}: use base32 characters a-z and 2-7 "
        "(no 0,1,8,9), max 12")


def test_an_invalid_service_name_is_a_usage_error(v, mkp224o, keys, capsys):
    """The name becomes a directory under the key volume and, later, a
    HiddenServiceDir."""
    rc = v.main(["--prefix", PREFIX, "--name", "../escape", "--out", str(keys),
                 "--json"])
    assert rc == 2
    assert "invalid name" in _json(capsys)["error"]
    assert not keys.exists(), "nothing may be created for a refused name"


def test_the_validation_happens_before_any_work(v, keys, monkeypatch, capsys):
    """A bad prefix must not cost a five-second benchmark first, and must not
    require a generator to be present at all."""
    monkeypatch.delenv("MKP224O", raising=False)

    def fail(*a, **k):
        raise AssertionError("the generator was consulted for an invalid prefix")

    monkeypatch.setattr(v, "benchmark", fail)
    assert v.main(["--prefix", "!", "--out", str(keys), "--json"]) == 2


def test_an_existing_key_set_exits_two_and_says_how_to_replace_it(v, mkp224o, keys,
                                                                  capsys):
    (keys / "app").mkdir(parents=True)
    rc = v.main(["--prefix", PREFIX, "--name", "app", "--out", str(keys),
                 "--seconds", "1", "--json"])
    assert rc == 2
    doc = _json(capsys)
    assert "--force" in doc["error"]
    assert doc["name"] == "app"


def test_a_lost_race_exits_three_not_two(v, mkp224o, keys, monkeypatch, capsys):
    """Its own code in the contract: 2 tells a caller to fix its arguments, 3
    tells it that something else wrote to the key volume and nothing was lost."""
    real_rename = os.rename

    def racing_rename(src, dst):
        if str(dst).endswith("/app"):
            os.makedirs(dst, exist_ok=True)
            raise OSError(39, "Directory not empty")
        return real_rename(src, dst)

    monkeypatch.setattr(v.os, "rename", racing_rename)
    rc = v.main(["--prefix", PREFIX, "--name", "app", "--out", str(keys),
                 "--seconds", "1", "--json"])
    assert rc == 3
    assert _json(capsys)["exit_code"] == 3


def test_a_generator_failure_exits_one(v, mkp224o, keys, capsys):
    """1 is "refused or failed"; it is not a usage error and it is not a race."""
    mkp224o("pubkey")
    rc = v.main(["--prefix", PREFIX, "--name", "app", "--out", str(keys),
                 "--seconds", "1", "--json"])
    assert rc == 1
    doc = _json(capsys)
    # The same two fields every failure emits, under the documented names.
    assert sorted(doc) == ["error", "exit_code", "name", "ok"]
    assert doc["name"] == "app"
    assert "derived from public key" in doc["error"]


def test_a_benchmark_that_cannot_run_is_a_usage_error(v, mkp224o, keys, capsys):
    """No generator, or one that says nothing, is an environment problem -- which
    is what 2 means. It must not be reported as a failed generation."""
    mkp224o("silent")
    rc = v.main(["--prefix", PREFIX, "--out", str(keys), "--seconds", "1", "--json"])
    assert rc == 2
    assert "benchmark failed" in _json(capsys)["error"]


# ─────────────────────────────────────────────────────────────────────────────
# --bench
# ─────────────────────────────────────────────────────────────────────────────

def test_bench_reports_throughput_and_the_difficulty_table(v, mkp224o, capsys):
    mkp224o("bench", HF_FAKE_MKP224O_RATE=1_000_000)
    rc = v.main(["--prefix", PREFIX, "--bench", "--threads", "4", "--seconds", "1",
                 "--json"])
    assert rc == 0
    doc = _json(capsys)
    assert doc["threads"] == 4
    assert doc["keys_per_sec"] == 1_000_000.0
    assert doc["keys_per_sec_per_thread"] == 250_000.0
    assert [row["prefix_len"] for row in doc["difficulty"]] == list(range(1, 9))
    assert doc["difficulty"][0]["average_attempts"] == 32


def test_bench_writes_no_keys(v, mkp224o, keys, capsys):
    """--bench measures; it must not generate an address as a side effect."""
    mkp224o("bench")
    v.main(["--prefix", PREFIX, "--out", str(keys), "--bench", "--seconds", "1"])
    assert not keys.exists()


def test_the_bench_table_is_readable_without_json(v, mkp224o, capsys):
    mkp224o("bench", HF_FAKE_MKP224O_RATE=1_000_000)
    rc = v.main(["--prefix", PREFIX, "--bench", "--threads", "2", "--seconds", "1"])
    assert rc == 0, "a successful measurement is exit 0, not None and not 1"
    lines = capsys.readouterr().out.splitlines()
    # Exact, including the blank separator: this table is read by a human deciding
    # how long a prefix they can afford, and a header that no longer lines up with
    # its columns is a table that gets misread.
    assert lines[0] == ("mkp224o throughput: 1,000,000 keys/sec "
                        "(2 threads, 500,000 keys/sec/thread)")
    assert lines[1] == ""
    assert lines[2] == "prefix len   average attempts        expected time"
    assert lines[3] == "        1                   32             <1s"
    assert len(lines) == 3 + v.DIFFICULTY_MAX_LEN


# ─────────────────────────────────────────────────────────────────────────────
# Threads, warnings, and the JSON envelope
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("asked,expected", [("0", None), ("-4", None), ("3", 3),
                                            ("100000", 256), ("1", 1)])
def test_the_thread_count_is_clamped_to_something_runnable(v, mkp224o, capsys,
                                                           asked, expected):
    """0 means auto. A negative number is auto too rather than an argv that
    mkp224o would reject, and the upper bound stops `-t 100000` from asking the
    kernel for a hundred thousand threads inside a container."""
    mkp224o("bench")
    v.main(["--prefix", PREFIX, "--bench", "--threads", asked, "--seconds", "1",
            "--json"])
    threads = _json(capsys)["threads"]
    assert threads == (expected if expected is not None else (os.cpu_count() or 1))
    assert 1 <= threads <= 256


def test_an_effectively_impossible_prefix_is_warned_about_on_stderr(v, mkp224o, keys,
                                                                    capsys):
    """Honest rather than optimistic: the operator is told, before the search
    starts, roughly how long it will take on THIS machine."""
    mkp224o("bench", HF_FAKE_MKP224O_RATE=1000)
    v.main(["--prefix", "aaaaaaa", "--name", "app", "--out", str(keys),
            "--seconds", "1"])
    err = capsys.readouterr().err
    assert "warning: a 7-character prefix needs ~" in err
    assert "docs/INTEGRATION.md" in err


def test_a_short_prefix_is_not_warned_about(v, mkp224o, keys, capsys):
    mkp224o("bench", HF_FAKE_MKP224O_RATE=1_000_000_000)
    v.main(["--prefix", PREFIX, "--name", "app", "--out", str(keys), "--seconds", "1"])
    assert "warning:" not in capsys.readouterr().err


def test_json_mode_keeps_stdout_a_single_document(v, mkp224o, keys, capsys):
    """A machine-readable mode that also prints a human warning is not
    machine-readable. The consumer is the host CLI, which parses stdout."""
    mkp224o("bench", HF_FAKE_MKP224O_RATE=1000)
    v.main(["--prefix", "aaaaaaa", "--name", "app", "--out", str(keys),
            "--seconds", "1", "--json"])
    captured = capsys.readouterr()
    json.loads(captured.out)
    assert captured.err == ""


def test_the_json_envelope_reports_ok_and_the_exit_code(v):
    assert v._emit(0, True, {}, "") == 0
    assert v._emit(1, True, {}, "") == 1


def test_the_json_envelope_omits_fields_with_no_value(v, capsys):
    """`"archived": null` on every successful run invites a consumer to branch on
    a key that is only ever meaningful after --force."""
    v._emit(0, True, {"name": "app", "archived": None}, "")
    doc = _json(capsys)
    assert doc == {"ok": True, "exit_code": 0, "name": "app"}


def test_human_mode_prints_nothing_when_there_is_nothing_to_say(v, capsys):
    v._emit(0, False, {"name": "app"}, "")
    assert capsys.readouterr().out == ""


# ─────────────────────────────────────────────────────────────────────────────
# The difficulty table's edges
# ─────────────────────────────────────────────────────────────────────────────

def test_a_zero_rate_does_not_divide_by_zero(v):
    """rate comes from a measurement; a machine that reported 0 must produce an
    honest "forever", not a ZeroDivisionError traceback."""
    table = v.difficulty_table(0.0, max_len=2)
    assert all(row["estimated_seconds"] == float("inf") for row in table)
    assert all(row["estimated_human"] == "9223372036854775807.0y" or
               row["estimated_human"].endswith("y") for row in table)


def test_the_table_covers_every_length_up_to_the_maximum(v):
    table = v.difficulty_table(1000.0)
    assert [row["prefix_len"] for row in table] == list(range(1, v.DIFFICULTY_MAX_LEN + 1))


@pytest.mark.parametrize("seconds,expected", [
    (0, "<1s"), (0.999, "<1s"), (1, "1s"), (59, "59s"), (60, "1.0m"),
    (3599, "60.0m"), (3600, "1.0h"), (86399, "24.0h"), (86400, "1.0d"),
    (86400 * 364, "364.0d"), (86400 * 365, "1.0y"),
])
def test_every_duration_boundary(v, seconds, expected):
    """Each boundary is a place the unit changes; an off-by-one there reports
    "60.0m" as "1.0h" or a day as an hour, and this table is the only basis an
    operator has for choosing a prefix length."""
    assert v.human_duration(seconds) == expected


# ─────────────────────────────────────────────────────────────────────────────
# What the second mutation pass found still unheld
# ─────────────────────────────────────────────────────────────────────────────

def test_the_secret_key_never_leaves_the_key_volume_even_transiently(v, mkp224o, keys,
                                                                     monkeypatch):
    """The search directory is created INSIDE --out on purpose. Defaulting it to
    the system temp directory would write a fresh onion secret key to /tmp -- a
    different filesystem, a different owner, and one the operator is not backing
    up or wiping."""
    seen = {}
    real = v.tempfile.TemporaryDirectory

    def recording(*args, **kwargs):
        seen.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(v.tempfile, "TemporaryDirectory", recording)
    v.generate(PREFIX, "app", keys, threads=1, force=False)
    assert seen["dir"] == str(keys)
    assert seen["prefix"] == "hf-vanity-"


def test_the_key_volume_is_never_created_more_permissive_than_0700(v, mkp224o, keys):
    """mkdir's mode is a request the umask can only narrow, so asking for more
    than 0700 is invisible under a restrictive umask and real under a permissive
    one. Forced here, because a container's umask is whatever the runtime gave
    PID 1."""
    old = os.umask(0o000)
    try:
        v.generate(PREFIX, "app", keys, threads=1, force=False)
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(keys).st_mode) == 0o700


def test_a_key_volume_several_levels_deep_is_created(v, mkp224o, tmp_path):
    """`--out /srv/onions/prod/keys` on a fresh host. Refusing to create the
    intermediate directories would make the first run fail with ENOENT."""
    nested = tmp_path / "srv" / "onions" / "prod"
    v.generate(PREFIX, "app", nested, threads=1, force=False)
    assert (nested / "app" / "hostname").exists()


def test_exactly_one_key_is_asked_for(v, mkp224o, keys, tmp_path, monkeypatch):
    """`-n 1`, and the thread count the caller chose. Asking for two keys makes
    the verification step refuse the result -- safe, but it burns an unbounded
    search and reports "expected exactly one" for what is really a wrong flag."""
    record = tmp_path / "argv"
    monkeypatch.setenv("HF_FAKE_MKP224O_RECORD", str(record))
    v.generate(PREFIX, "app", keys, threads=7, force=False)
    argv = ast.literal_eval(record.read_text().strip())
    assert argv[-3:] == ["-n", "1", PREFIX]
    assert argv[argv.index("-t") + 1] == "7"


def test_a_generator_that_found_a_key_and_then_failed_is_not_thrown_away(v, mkp224o,
                                                                        keys):
    """mkp224o can write a key set and still exit non-zero. The key is the
    address and it cannot be regenerated, so a non-zero exit is only fatal when
    nothing was produced."""
    mkp224o("found_then_fail")
    result = v.generate(PREFIX, "app", keys, threads=1, force=False)
    assert result["onion"] == VECTOR_ONION
    assert (keys / "app" / "hs_ed25519_secret_key").exists()


def test_a_silent_failure_still_names_the_exit_code(v, mkp224o, keys):
    mkp224o("fail_silent")
    with pytest.raises(RuntimeError) as exc:
        v.generate(PREFIX, "app", keys, threads=1, force=False)
    assert str(exc.value) == "mkp224o exited 2: "


def test_only_onion_directories_are_considered_generated(v, mkp224o, keys):
    """The search directory is ours, but it is inside an operator-supplied volume.
    Counting anything that is merely a directory, or merely ends in .onion, turns
    a stray entry into "expected exactly one, found 2" and fails a good run."""
    mkp224o("noise")
    result = v.generate(PREFIX, "app", keys, threads=1, force=False)
    assert result["onion"] == VECTOR_ONION


def test_the_found_address_is_not_echoed_into_the_container_log(v, mkp224o, keys,
                                                                capfd):
    """mkp224o announces each hit on stdout. The shipped compose file discards the
    log driver precisely so the host keeps no record of onion activity; letting
    the generator's stdout through would defeat that from inside."""
    capfd.readouterr()
    v.generate(PREFIX, "app", keys, threads=1, force=False)
    captured = capfd.readouterr()
    assert VECTOR_ONION not in captured.out
    assert VECTOR_ONION not in captured.err


def test_force_on_a_fresh_key_volume_is_not_an_error(v, mkp224o, keys):
    """--force means "replace it if it is there", not "there must be something to
    replace". Renaming a directory that does not exist would fail the first run
    of any script that always passes --force."""
    result = v.generate(PREFIX, "app", keys, threads=1, force=True)
    assert result["archived"] is None
    assert (keys / "app" / "hostname").exists()


def test_the_first_archive_collision_is_numbered_one(v, keys):
    keys.mkdir()
    base = v._unique_archive_path(keys, "app")
    base.mkdir()
    second = v._unique_archive_path(keys, "app")
    assert second.name == base.name + "-1"


def test_the_requested_owner_reaches_the_key_files(v, mkp224o, keys, monkeypatch):
    """--uid/--gid exist so the host CLI can hand the key volume to the tor user
    in one step. Dropping either on the way to _harden leaves keys the container
    cannot read."""
    calls = []
    monkeypatch.setattr(v.os, "fchown", lambda fd, u, g: calls.append((u, g)))
    v.generate(PREFIX, "app", keys, threads=1, force=False, uid=100, gid=101)
    assert calls
    assert set(calls) == {(100, 101)}


def test_the_result_payload_is_the_contract(v, mkp224o, keys):
    """scripts/hiddenforge parses this document. A renamed or null field is a
    silently missing one."""
    result = v.generate(PREFIX, "app", keys, threads=1, force=False)
    target = keys / "app"
    assert result == {
        "name": "app",
        "onion": VECTOR_ONION,
        "key_path": str(target / "hs_ed25519_secret_key"),
        "public_key_path": str(target / "hs_ed25519_public_key"),
        "address_path": str(target / "hostname"),
        "key_dir": str(target),
        "archived": None,
        "threads": 1,
    }


# ─────────────────────────────────────────────────────────────────────────────
# read_public_key, derive_onion, the tables
# ─────────────────────────────────────────────────────────────────────────────

def test_a_64_byte_file_without_the_tag_is_refused(v, tmp_path):
    """Both conditions, not either. Accepting any 64-byte file would take its
    last 32 bytes as the public key -- and the address is then derived from
    whatever those bytes happened to be, which is how a corrupt key set gets
    installed under a name the operator trusts."""
    p = tmp_path / "pub"
    p.write_bytes(b"NOT THE TAG".ljust(32, b"\x00") + b"\x01" * 32)
    with pytest.raises(ValueError) as exc:
        v.read_public_key(p)
    assert str(exc.value) == "pub: expected 64 bytes (tagged) or 32 bytes (bare), got 64"


def test_a_wrong_length_public_key_names_both_accepted_lengths(v, tmp_path):
    p = tmp_path / "pub"
    p.write_bytes(b"x" * 10)
    with pytest.raises(ValueError) as exc:
        v.read_public_key(p)
    assert str(exc.value) == "pub: expected 64 bytes (tagged) or 32 bytes (bare), got 10"


def test_a_wrong_length_key_is_refused_before_any_address_is_derived(v):
    with pytest.raises(ValueError) as exc:
        v.derive_onion(b"\x00" * 31)
    assert str(exc.value) == "public key must be 32 bytes, got 31"


def test_a_slow_machine_still_gets_a_number_not_infinity(v):
    """`rate > 0`, not `rate > 1`. A machine measuring under one key per second
    is absurd but real under heavy contention, and reporting "forever" there
    hides a merely-slow host behind an impossible one."""
    table = v.difficulty_table(0.5, max_len=1)
    assert table[0]["estimated_seconds"] == 64.0


@pytest.mark.parametrize("seconds,expected", [
    (3780, "1.1h"),        # 3600, not 3601
    (90720, "1.1d"),       # 86400, not 86401
    (33112800, "1.1y"),    # 86400 * 365, not 86401 * 365 or 86400 * 366
])
def test_each_unit_divides_by_the_right_constant(v, seconds, expected):
    """The boundary tests catch a wrong comparison; these catch a wrong divisor,
    which shifts every estimate in the table by a fraction an operator would
    never notice."""
    assert v.human_duration(seconds) == expected


# ─────────────────────────────────────────────────────────────────────────────
# mkp224o_path, benchmark, and the parser contract
# ─────────────────────────────────────────────────────────────────────────────

def test_the_image_paths_are_the_ones_the_dockerfile_installs(v, monkeypatch):
    """Two fallbacks, in order, for the vendored binary. A wrong path here means
    every `hiddenforge vanity` falls through to $PATH, which inside the image is
    the only other place it could be -- and outside it, nowhere."""
    monkeypatch.delenv("MKP224O", raising=False)
    monkeypatch.setattr(v.shutil, "which", lambda name: None)
    for expected in ("/usr/local/bin/mkp224o", "/usr/bin/mkp224o"):
        monkeypatch.setattr(v.os.path, "isfile", lambda p, want=expected: p == want)
        monkeypatch.setattr(v.os, "access", lambda p, mode, want=expected: p == want)
        assert v.mkp224o_path() == expected


def test_the_path_lookup_asks_for_the_right_binary(v, monkeypatch):
    asked = []
    monkeypatch.delenv("MKP224O", raising=False)
    monkeypatch.setattr(v.os.path, "isfile", lambda p: False)
    monkeypatch.setattr(v.shutil, "which",
                        lambda name: asked.append(name) or "/x/mkp224o")
    v.mkp224o_path()
    assert asked == ["mkp224o"]


def test_the_missing_generator_message_is_exact(v, monkeypatch):
    monkeypatch.delenv("MKP224O", raising=False)
    monkeypatch.setattr(v.shutil, "which", lambda name: None)
    monkeypatch.setattr(v.os.path, "isfile", lambda p: False)
    with pytest.raises(FileNotFoundError) as exc:
        v.mkp224o_path()
    assert str(exc.value) == (
        "mkp224o not found. This subcommand requires the hiddenforge image "
        "(which vendors it); run it via `hiddenforge vanity` on the host.")


def test_the_benchmark_searches_for_something_unfindable(v, mkp224o, tmp_path,
                                                          monkeypatch):
    """A ten-character filter is never hit inside a measurement window, so the
    process only ever measures raw generation rate. A shorter one would find a
    key, stop early, and report a rate measured over an unknown interval -- and
    write an unwanted key set into a temp directory."""
    record = tmp_path / "argv"
    monkeypatch.setenv("HF_FAKE_MKP224O_RECORD", str(record))
    mkp224o("bench", HF_FAKE_MKP224O_MAX=2)
    v.benchmark(1, threads=1)
    argv = ast.literal_eval(record.read_text().strip())
    assert argv[-1] == "zzzzzzzzzz"
    assert len(argv[-1]) == 10
    # Statistics every second, and -T so they are wall-clock rather than CPU time.
    assert argv[-4:-1] == ["-S", "1", "-T"]
    assert argv[argv.index("-n") + 1] == "0", "never stop; this is a timed window"


def test_the_benchmark_scratch_directory_is_named_for_what_it_is(v, mkp224o,
                                                                 monkeypatch):
    seen = {}
    real = v.tempfile.TemporaryDirectory

    def recording(*args, **kwargs):
        seen.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(v.tempfile, "TemporaryDirectory", recording)
    mkp224o("bench")
    v.benchmark(1, threads=1)
    assert seen["prefix"] == "hf-bench-"


def test_a_benchmark_shorter_than_a_second_is_raised_to_one(v, mkp224o):
    """`--seconds 0` must not become a zero-length window that reads no lines,
    and must not become a longer one that makes `--seconds 1` a lie."""
    import time as _time
    # The fake must outlive the measurement window, or IT ends the benchmark and
    # the window is never the thing under test. Found by mutation: `max(2, ...)`
    # survived because the generator was exiting at ~1.5s either way.
    mkp224o("bench", HF_FAKE_MKP224O_MAX=10_000)
    start = _time.monotonic()
    assert v.benchmark(0, threads=1) > 0
    assert _time.monotonic() - start < 1.9, "one second, not two"


def test_a_rate_of_exactly_zero_is_not_a_measurement(v, mkp224o, monkeypatch):
    """`best <= 0`, not `best <= 1`: a genuine sub-1 rate is a slow machine, and
    refusing it would report a working generator as broken."""
    monkeypatch.setattr(v, "_rate_from_stats_line", lambda line: 0.5)
    mkp224o("bench")
    assert v.benchmark(1, threads=1) == 0.5


def test_the_parser_defaults_are_the_documented_ones(v, monkeypatch):
    """These defaults are what `docker run <image> vanity --prefix x` means."""
    monkeypatch.delenv("HIDDENFORGE_KEYS_DIR", raising=False)
    args = v.build_parser().parse_args(["--prefix", "a"])
    assert args.name == "myapp"
    assert args.out == "/var/lib/tor/hidden_service"
    assert args.threads == 0
    assert args.seconds == 5
    assert args.force is False
    assert args.bench is False
    assert args.json is False
    assert args.uid is None
    assert args.gid is None


def test_the_key_directory_can_be_set_from_the_environment(v, monkeypatch):
    """The host CLI bind-mounts the key volume and passes its path this way."""
    monkeypatch.setenv("HIDDENFORGE_KEYS_DIR", "/keys")
    # The default is read at parser-construction time, so rebuild it here.
    assert v.build_parser().parse_args(["--prefix", "a"]).out == "/keys"


def test_the_numeric_options_are_parsed_as_numbers(v):
    args = v.build_parser().parse_args(
        ["--prefix", "a", "--threads", "4", "--seconds", "9", "--uid", "100",
         "--gid", "101"])
    assert (args.threads, args.seconds, args.uid, args.gid) == (4, 9, 100, 101)


def test_a_missing_prefix_is_a_clean_usage_error(v, capsys):
    """--prefix is required. Without that, argparse leaves it None and the first
    thing the program does is match a regex against None."""
    with pytest.raises(SystemExit) as exc:
        v.build_parser().parse_args([])
    assert exc.value.code == 2
    assert "--prefix" in capsys.readouterr().err


def test_the_help_text_is_the_operator_documentation(v, monkeypatch):
    """`vanity.py --help` inside the image is the only documentation an operator
    has to hand, and the "1-7 chars is useful" guidance is the difference between
    a search that finishes and one that does not."""
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.delenv("HIDDENFORGE_KEYS_DIR", raising=False)
    lines = [" ".join(line.split()) for line in v.build_parser().format_help().splitlines()]
    assert "usage: vanity.py [-h] --prefix PREFIX [--name NAME] [--out OUT]" in lines[0]
    assert "Generate a Tor v3 vanity address inside the hiddenforge image." in lines
    for option, help_text in [
        ("--prefix PREFIX", "base32 prefix to search for (1-7 chars is useful)"),
        ("--name NAME", "service directory name under --out (default: myapp)"),
        ("--out OUT", "key volume directory (default: $HIDDENFORGE_KEYS_DIR)"),
        ("--threads THREADS", "worker threads (0 = auto)"),
        ("--force", "archive an existing key set and generate a new address"),
        ("--uid UID", "chown output to this uid"),
        ("--gid GID", "chown output to this gid"),
        ("--bench", "measure throughput and print the difficulty table only"),
        ("--seconds SECONDS", "benchmark duration in seconds (default: 5)"),
        ("--json", "machine-readable output"),
    ]:
        assert f"{option} {help_text}" in lines, option


def test_the_bench_payload_keys_are_the_contract(v, mkp224o, capsys):
    mkp224o("bench", HF_FAKE_MKP224O_RATE=1_000_000)
    v.main(["--prefix", "ab", "--bench", "--threads", "4", "--seconds", "1", "--json"])
    doc = _json(capsys)
    assert sorted(doc) == ["difficulty", "exit_code", "keys_per_sec",
                           "keys_per_sec_per_thread", "ok", "prefix", "seconds",
                           "threads"]
    assert doc["prefix"] == "ab"
    assert doc["seconds"] == 1


def test_the_reported_rate_is_rounded_to_two_places(v, mkp224o, capsys, monkeypatch):
    """Two decimals is a readable number; more is noise from a sampled
    measurement, and none loses a slow machine's rate entirely."""
    monkeypatch.setattr(v, "benchmark", lambda seconds, threads: 1234.56789)
    v.main(["--prefix", "a", "--bench", "--threads", "2", "--seconds", "1", "--json"])
    doc = _json(capsys)
    assert doc["keys_per_sec"] == 1234.57
    assert doc["keys_per_sec_per_thread"] == 617.28


def test_the_json_document_is_key_sorted(v, capsys):
    v._emit(0, True, {"zebra": 1, "alpha": 2}, "")
    assert capsys.readouterr().out == '{"alpha": 2, "exit_code": 0, "ok": true, "zebra": 1}\n'


def test_the_search_space_is_32_to_the_power_of_the_prefix_length(v, mkp224o, capsys,
                                                                  monkeypatch):
    """base32: each character multiplies the space by 32. Any other base makes
    the warning threshold fire at the wrong prefix length."""
    monkeypatch.setattr(v, "benchmark", lambda seconds, threads: 32.0 ** 5 / 86400.0)
    # Exactly one day of work for a five-character prefix: the warning fires
    # above a day, so five is silent and six is not.
    v.main(["--prefix", "aaaaa", "--bench", "--seconds", "1", "--json"])
    rows = _json(capsys)["difficulty"]
    assert [row["average_attempts"] for row in rows[:3]] == [32, 1024, 32768]


def test_the_usage_errors_say_what_was_wrong_on_stdout_too(v, keys, capsys,
                                                            monkeypatch):
    """Without --json the human line is the only output; `None` there would exit
    2 in silence."""
    monkeypatch.delenv("MKP224O", raising=False)
    assert v.main(["--prefix", "A", "--out", str(keys)]) == 2
    assert capsys.readouterr().out == "error: invalid prefix 'A'\n"
    assert v.main(["--prefix", "a", "--name", "BAD", "--out", str(keys)]) == 2
    assert capsys.readouterr().out == "error: invalid name 'BAD'\n"


def test_a_failed_benchmark_says_so_on_stdout_too(v, mkp224o, keys, capsys):
    mkp224o("silent")
    assert v.main(["--prefix", "a", "--out", str(keys), "--seconds", "1"]) == 2
    assert capsys.readouterr().out.startswith(
        "error: benchmark failed: mkp224o produced no statistics")


# ─────────────────────────────────────────────────────────────────────────────
# The honest warning, and the arithmetic behind it
# ─────────────────────────────────────────────────────────────────────────────
#
# Before the search starts, main() estimates how long the requested prefix will
# take ON THIS MACHINE and says so if the answer is more than a day. That is the
# only warning an operator gets before a command that otherwise looks like it has
# hung. Every constant in `32 ** len(prefix) / rate > 86400` is load-bearing: a
# wrong base, a wrong direction, or a comparison that never fires turns an honest
# estimate into silence.

def _bench(v, monkeypatch, rate):
    monkeypatch.setattr(v, "benchmark", lambda seconds, threads: rate)


def test_the_search_space_is_exactly_32_to_the_prefix_length(v, mkp224o, keys, capsys,
                                                             monkeypatch):
    """base32. A rate is chosen here so that 32**5 attempts land just UNDER a day
    and 33**5 land just over it: with the right base the run is silent, with any
    larger one it warns about work that is not actually required. A base of 32*len
    instead of 32**len collapses the estimate to nothing and is silent for every
    prefix."""
    _bench(v, monkeypatch, 33554432 / (86400 / 1.08))
    v.main(["--prefix", "aaaaa", "--name", "app", "--out", str(keys), "--seconds", "1"])
    assert "warning:" not in capsys.readouterr().err

    # One character more is 32x the work, and that must be said out loud.
    v.main(["--prefix", "aaaaaa", "--name", "app2", "--out", str(keys), "--seconds", "1"])
    assert "warning: a 6-character prefix needs ~" in capsys.readouterr().err


def test_the_estimate_divides_by_the_rate(v, mkp224o, keys, capsys, monkeypatch):
    """Attempts per second, so attempts DIVIDED by rate. Multiplying makes a fast
    machine look slow and warns about everything."""
    _bench(v, monkeypatch, 1_000_000_000_000.0)
    v.main(["--prefix", "aaaaaa", "--name", "app", "--out", str(keys), "--seconds", "1"])
    assert "warning:" not in capsys.readouterr().err


def test_a_machine_that_measured_nothing_warns_instead_of_dividing_by_zero(
        v, mkp224o, keys, capsys, monkeypatch):
    """`rate > 0`. At exactly zero the estimate is infinite, not an exception --
    and "forever" is the most important warning this command can print."""
    _bench(v, monkeypatch, 0.0)
    rc = v.main(["--prefix", "a", "--name", "app", "--out", str(keys), "--seconds", "1"])
    assert rc == 0
    assert "warning: a 1-character prefix needs ~" in capsys.readouterr().err


def test_a_sub_one_rate_reports_the_real_estimate_not_forever(v, mkp224o, keys,
                                                              capsys, monkeypatch):
    """A rate under one key per second is a contended machine, not an impossible
    one. Reporting it as infinite hides a host that merely needs longer."""
    _bench(v, monkeypatch, 0.5)
    v.main(["--prefix", "aaaa", "--name", "app", "--out", str(keys), "--seconds", "1"])
    err = capsys.readouterr().err
    assert "needs ~24.3d " in err, err
    assert "inf" not in err


def test_the_benchmark_searches_inside_its_own_scratch_directory(v, mkp224o, tmp_path,
                                                                  monkeypatch):
    """`-d <scratch>`. Without it the generator writes wherever it is told to by
    default, which for a measurement that is deliberately never going to find a
    key is still a directory nobody cleans up."""
    record = tmp_path / "argv"
    monkeypatch.setenv("HF_FAKE_MKP224O_RECORD", str(record))
    seen = {}
    real = v.tempfile.TemporaryDirectory

    class Recording(real):
        def __enter__(self):
            path = super().__enter__()
            seen["path"] = path
            return path

    monkeypatch.setattr(v.tempfile, "TemporaryDirectory", Recording)
    mkp224o("bench", HF_FAKE_MKP224O_MAX=2)
    v.benchmark(1, threads=1)
    argv = ast.literal_eval(record.read_text().strip().splitlines()[0])
    assert argv[argv.index("-d") + 1] == seen["path"]


def test_a_generator_that_ignores_terminate_is_killed(v, mkp224o):
    """`proc.wait(timeout=5)` then `proc.kill()`. An unbounded wait on a process
    that is ignoring SIGTERM never returns, and `hiddenforge vanity` hangs before
    it has even started searching.

    Two details are load-bearing, both found by mutation. The fake is given a
    self-bound far beyond the test's window, because a generator that exits on its
    own rescues the very mutant this is meant to catch. And the call runs on a
    bounded thread, because an unbounded wait fails by HANGING, and a hang is
    indistinguishable from a slow machine.
    """
    mkp224o("deaf", HF_FAKE_MKP224O_MAX=10_000)
    box = {}

    def run():
        try:
            box["rate"] = v.benchmark(1, threads=1)
        except BaseException as exc:   # re-raised in the calling thread
            box["exc"] = exc

    thread = threading.Thread(target=run, daemon=True)
    started = time.monotonic()
    thread.start()
    # The measurement window plus at most the escalation budget.
    thread.join(timeout=12)
    assert not thread.is_alive(), "benchmark waited for ever on a deaf generator"
    if "exc" in box:
        raise box["exc"]
    assert box["rate"] > 0
    assert time.monotonic() - started < 12


def test_a_generator_started_without_a_stderr_pipe_is_refused(v, mkp224o, monkeypatch):
    """A defensive branch, but it has to say something useful if it ever fires:
    the whole measurement is read off that pipe, and a None there would otherwise
    surface as `AttributeError: 'NoneType' object has no attribute 'readline'`."""
    class NoPipe:
        stderr = None

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

        def kill(self):
            pass

    monkeypatch.setattr(v, "_run_mkp224o", lambda *a, **kw: NoPipe())
    with pytest.raises(RuntimeError) as exc:
        v.benchmark(1, threads=1)
    assert str(exc.value) == "mkp224o stderr pipe is unavailable"


def test_a_machine_that_cannot_count_its_cpus_still_gets_one_thread(v, mkp224o,
                                                                    monkeypatch,
                                                                    capsys):
    """`os.cpu_count() or 1`. It returns None on some platforms and inside some
    sandboxes; the fallback has to be a number mkp224o will accept, and one
    thread is the honest answer when the count is unknown rather than a guess at
    two."""
    monkeypatch.setattr(v.os, "cpu_count", lambda: None)
    mkp224o("bench")
    v.main(["--prefix", PREFIX, "--bench", "--threads", "0", "--seconds", "1",
            "--json"])
    assert _json(capsys)["threads"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# What main() actually passes to generate()
# ─────────────────────────────────────────────────────────────────────────────
#
# The refusals in generate() are tested directly above. These drive them through
# the command line, because a flag that never reaches the function it names is a
# flag that silently does nothing: `--force` arriving as None is indistinguishable
# from not passing it, and `--uid` arriving as None leaves the keys owned by
# whoever ran the container.

def test_force_reaches_generate_from_the_command_line(v, mkp224o, keys, capsys):
    existing = keys / "app"
    existing.mkdir(parents=True)
    (existing / "hs_ed25519_secret_key").write_bytes(b"the old key")
    rc = v.main(["--prefix", PREFIX, "--name", "app", "--out", str(keys),
                 "--seconds", "1", "--force", "--json"])
    doc = _json(capsys)
    assert rc == 0, doc
    archived = Path(doc["archived"])
    assert archived.is_dir()
    assert (archived / "hs_ed25519_secret_key").read_bytes() == b"the old key"


def test_without_force_the_command_line_refuses(v, mkp224o, keys, capsys):
    """The other half: --force must not be implied."""
    (keys / "app").mkdir(parents=True)
    rc = v.main(["--prefix", PREFIX, "--name", "app", "--out", str(keys),
                 "--seconds", "1", "--json"])
    capsys.readouterr()
    assert rc == 2


def test_uid_and_gid_reach_generate_from_the_command_line(v, mkp224o, keys,
                                                          monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(v.os, "fchown", lambda fd, u, g: calls.append((u, g)))
    rc = v.main(["--prefix", PREFIX, "--name", "app", "--out", str(keys),
                 "--seconds", "1", "--uid", "100", "--gid", "101", "--json"])
    capsys.readouterr()
    assert rc == 0
    assert calls and set(calls) == {(100, 101)}


@pytest.mark.parametrize("seconds,warns", [(86400, False), (86401, True)])
def test_the_warning_threshold_is_more_than_a_day(v, mkp224o, keys, capsys,
                                                  monkeypatch, seconds, warns):
    """Exactly a day is not more than a day. The boundary is stated in the
    message the operator reads, so it should be the boundary the code uses."""
    want = 32 ** 4
    monkeypatch.setattr(v, "benchmark", lambda s, threads: want / seconds)
    v.main(["--prefix", "aaaa", "--name", f"app{seconds}", "--out", str(keys),
            "--seconds", "1"])
    assert ("warning:" in capsys.readouterr().err) is warns


def test_a_failed_generation_says_why_without_json(v, mkp224o, keys, capsys):
    """Without --json the human line is the only output; None there would fail in
    silence."""
    mkp224o("pubkey")
    rc = v.main(["--prefix", PREFIX, "--name", "app", "--out", str(keys),
                 "--seconds", "1"])
    assert rc == 1
    assert capsys.readouterr().out.startswith("error: address derived from public key")


def test_the_race_document_reports_the_error_under_the_documented_key(v, mkp224o,
                                                                      keys,
                                                                      monkeypatch,
                                                                      capsys):
    """`error` and `name`, the same two fields every other failure emits."""
    real_rename = os.rename

    def racing_rename(src, dst):
        if str(dst).endswith("/app"):
            os.makedirs(dst, exist_ok=True)
            raise OSError(39, "Directory not empty")
        return real_rename(src, dst)

    monkeypatch.setattr(v.os, "rename", racing_rename)
    rc = v.main(["--prefix", PREFIX, "--name", "app", "--out", str(keys),
                 "--seconds", "1", "--json"])
    doc = _json(capsys)
    assert rc == 3
    assert sorted(doc) == ["error", "exit_code", "name", "ok"]
    assert "appeared while the search was running" in doc["error"]


def test_every_failure_arm_prints_its_reason_without_json(v, mkp224o, keys,
                                                          monkeypatch, capsys):
    """Three except arms, three exit codes, and without --json the human line is
    the only thing an operator sees. A None there exits non-zero in silence,
    which for a command that may have been running for hours reads as a crash."""
    # 2: it already exists.
    (keys / "app").mkdir(parents=True)
    assert v.main(["--prefix", PREFIX, "--name", "app", "--out", str(keys),
                   "--seconds", "1"]) == 2
    assert capsys.readouterr().out.startswith("error: ")

    # 3: it appeared while we were searching.
    real_rename = os.rename

    def racing_rename(src, dst):
        if str(dst).endswith("/fresh"):
            os.makedirs(dst, exist_ok=True)
            raise OSError(39, "Directory not empty")
        return real_rename(src, dst)

    monkeypatch.setattr(v.os, "rename", racing_rename)
    assert v.main(["--prefix", PREFIX, "--name", "fresh", "--out", str(keys),
                   "--seconds", "1"]) == 3
    out = capsys.readouterr().out
    assert out.startswith("error: ")
    assert "appeared while the search was running" in out

    # 1: the generator produced something unusable.
    # Restore rename specifically; monkeypatch.undo() would also drop the fixture's
    # MKP224O environment variable and the failure would be "no generator" instead.
    monkeypatch.setattr(v.os, "rename", real_rename)
    mkp224o("hostname")
    assert v.main(["--prefix", PREFIX, "--name", "other", "--out", str(keys),
                   "--seconds", "1"]) == 1
    assert capsys.readouterr().out.startswith("error: hostname file")
