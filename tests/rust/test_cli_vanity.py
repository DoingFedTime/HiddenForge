"""The Rust vanity generator (argv0 vanity.py) against vanity.py, on the fake generator.

Both run the same arguments, the same fake mkp224o and an identical output
directory; exit code, stdout, stderr and the files left behind must agree.
"""

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cli_common import (  # noqa: E402
    FAKE, PY_VANITY, REPO, Result, env_for, needs_rust, norm, reopen, rust, scratch,  # noqa: F401
    snapshot, write,
)

pytestmark = needs_rust

ADDR = "atdorl67o6q7anir2qm3sly4expi3ywvs2ltw3wl53zezgycohzi2zqd.onion"
sys.path.insert(0, str(REPO))
import vanity  # noqa: E402  (the reference implementation)

GEN = ["--prefix", "a", "--name", "svc", "--threads", "2", "--seconds", "1"]


class Lab:
    """Fresh twin directories per call, the fake generator behind MKP224O."""

    def __init__(self, root: Path):
        self.root = root
        self.n = 0
        self.wrapper = root / "mkp224o"
        self.wrapper.write_text(f'#!/bin/sh\nexec {sys.executable} {FAKE} "$@"\n')
        self.wrapper.chmod(0o755)

    def env(self, mode, **extra):
        return env_for(MKP224O=str(self.wrapper), HF_FAKE_MKP224O=mode,
                       **{k: str(v) for k, v in extra.items()})

    def twins(self, build=None):
        self.n += 1
        dirs = []
        for tag in ("rust", "py"):
            d = self.root / f"c{self.n}" / tag
            d.mkdir(parents=True)
            if build:
                build(d)
            dirs.append(d)
        return dirs

    def both(self, args, mode="ok", build=None, **extra):
        rd, pd = self.twins(build)

        def run_py():
            p = subprocess.run([sys.executable, str(PY_VANITY), *args], cwd=pd,
                               env=self.env(mode, **extra), capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, timeout=90)
            return Result(p.returncode, p.stdout, p.stderr)

        with ThreadPoolExecutor(1) as ex:
            fut = ex.submit(run_py)
            r = rust(args, rd, env=self.env(mode, **extra), argv0="vanity.py", timeout=90)
            p = fut.result()
        return r, p, rd, pd

    def check(self, args, mode="ok", build=None, rc=None, **extra):
        r, p, rd, pd = self.both(args, mode, build, **extra)
        assert (norm(r.out), r.rc) == (norm(p.out), p.rc), (
            f"{args} {mode}\nrust: {r.rc}\n{r.out}\n{r.err}\npython: {p.rc}\n{p.out}\n{p.err}")
        assert norm(r.err) == norm(p.err), f"stderr\nrust: {r.err}\npython: {p.err}"
        assert snapshot(rd) == snapshot(pd), "files left behind differ"
        if rc is not None:
            assert r.rc == rc, r.out + r.err
        return r, rd


@pytest.fixture
def lab(scratch):
    yield Lab(scratch)


def doc(r):
    return json.loads(r.out)


# ───────────────────────────── benchmark / table ─────────────────────────────

@pytest.mark.parametrize("rate", ["1", "0.5", "999", "1000", "12345", "1234567", "123456789012"])
def test_benchmark_table_matches(lab, rate):
    for flags in (["--json"], []):
        lab.check(["--prefix", "ab", "--bench", "--seconds", "1", "--threads", "4", *flags],
                  "bench", HF_FAKE_MKP224O_RATE=rate, HF_FAKE_MKP224O_MAX=3, rc=0)


def test_benchmark_numbers_are_exact(lab):
    r, _ = lab.check(["--prefix", "ab", "--bench", "--seconds", "1", "--threads", "4", "--json"],
                     "bench", HF_FAKE_MKP224O_RATE="1234567", HF_FAKE_MKP224O_MAX=3)
    d = doc(r)
    assert (d["keys_per_sec"], d["keys_per_sec_per_thread"]) == (1234567.0, 308641.75)
    assert (d["threads"], d["seconds"], d["prefix"], d["ok"], d["exit_code"]) == (4, 1, "ab", True, 0)
    assert [row["prefix_len"] for row in d["difficulty"]] == list(range(1, 9))
    assert d["difficulty"][2]["average_attempts"] == 32768
    assert d["difficulty"][2]["estimated_seconds"] == 32768 / 1234567.0


def test_benchmark_text_is_grouped_by_thousands(lab):
    r, _ = lab.check(["--prefix", "ab", "--bench", "--seconds", "1", "--threads", "4"], "bench",
                     HF_FAKE_MKP224O_RATE="1234567", HF_FAKE_MKP224O_MAX=3)
    lines = r.out.split("\n")
    assert lines[0] == ("mkp224o throughput: 1,234,567 keys/sec (4 threads, "
                        "308,642 keys/sec/thread)")
    assert lines[1] == ""
    assert lines[2] == "prefix len   average attempts        expected time"
    for row, line in zip(vanity.difficulty_table(1234567.0), lines[3:11]):
        assert line == (f"{row['prefix_len']:>9}   {row['average_attempts']:>18,}   "
                        f"{row['estimated_human']:>13}")
    assert len(lines) == 12 and lines[11] == ""


@pytest.mark.parametrize("seconds", ["0", "-3"])
def test_the_benchmark_runs_for_at_least_one_second(lab, seconds):
    """vanity.py: seconds = max(1, seconds); the document still reports what was asked for."""
    r, _ = lab.check(["--prefix", "ab", "--bench", "--seconds=" + seconds, "--threads", "1",
                      "--json"], "bench", HF_FAKE_MKP224O_MAX=3, rc=0)
    assert doc(r)["seconds"] == int(seconds)
    assert doc(r)["keys_per_sec"] == 1000000.0


def test_benchmark_without_statistics_is_an_error(lab):
    for flags in (["--json"], []):
        r, _ = lab.check([*GEN, *flags], "silent", rc=2)
    r, _ = lab.check([*GEN, "--json"], "silent", rc=2)
    assert doc(r) == {"ok": False, "exit_code": 2,
                      "error": "benchmark failed: mkp224o produced no statistics; cannot benchmark"}


def test_threads_option(lab):
    for given, want in (("3", 3), ("1000", 256), ("1", 1), ("256", 256), ("257", 256), ("-4", None),
                        ("0", None)):
        args = ["--prefix", "ab", "--bench", "--seconds", "1", "--threads", given, "--json"]
        r, _ = lab.check(args, "bench", HF_FAKE_MKP224O_MAX=3)
        if want is None:
            want = max(1, min(len(os.sched_getaffinity(0)), 256))
        assert doc(r)["threads"] == want, given


def test_a_slow_prefix_warns_on_stderr_except_in_json(lab):
    r, _ = lab.check(["--prefix", "atdorl67", "--name", "svc", "--threads", "1", "--seconds", "1", "--out", "out"],
                     "ok", rc=0)
    assert r.err == ("warning: a 8-character prefix needs ~12.7d on this machine. Consider a "
                     "shorter prefix or a faster host (see docs/INTEGRATION.md, "
                     "'Long prefixes').\n")
    r, _ = lab.check(["--prefix", "atdorl67", "--name", "svc", "--threads", "1", "--seconds", "1",
                      "--out", "out", "--json"], "ok", rc=0)
    assert r.err == ""
    r, _ = lab.check(["--prefix", "atdorl6", "--name", "svc", "--threads", "1", "--seconds", "1", "--out", "out"],
                     "ok", rc=0, HF_FAKE_MKP224O_RATE="397000")
    assert r.err.startswith("warning: a 7-character prefix needs ~1.0d")
    r, _ = lab.check(["--prefix", "a", "--name", "svc", "--threads", "1", "--seconds", "1", "--out", "out"],
                     "ok", rc=0)
    assert r.err == ""


# ───────────────────────────── validation / argparse ─────────────────────────

@pytest.mark.parametrize("prefix", ["", "A", "a0", "a1", "a8", "a9", "a b", "abcdefghijklm",
                                    "é", "a-b", "../x"])
def test_invalid_prefixes(lab, prefix):
    for flags in (["--json"], []):
        r, _ = lab.check(["--prefix", prefix, *flags], "ok", rc=2)
        if flags:
            assert doc(r)["error"].startswith(f"invalid prefix {prefix!r}"[:15])


@pytest.mark.parametrize("prefix", ["a", "2", "7", "z", "abcdefghijkl"])
def test_valid_prefix_edges_pass_validation(lab, prefix):
    r, p, _, _ = lab.both(["--prefix", prefix, "--bench", "--seconds", "1", "--threads", "1",
                           "--json"], "bench", HF_FAKE_MKP224O_MAX=3)
    assert (r.rc, p.rc) == (0, 0)


@pytest.mark.parametrize("name", ["", "-a", "A", "a_b", "a.b", "é", "a" * 64])
def test_invalid_names(lab, name):
    for flags in (["--json"], []):
        r, _ = lab.check(["--prefix", "a", "--name=" + name, *flags], "ok", rc=2)
        if flags:
            assert doc(r)["error"] == f"invalid name {name!r}"


@pytest.mark.parametrize("name", ["a", "0", "a-b", "a" * 63])
def test_valid_name_edges(lab, name):
    r, p, _, _ = lab.both(["--prefix", "a", "--name", name, "--threads", "1", "--seconds", "1",
                           "--out", "out", "--json"], "ok")
    assert (r.rc, p.rc) == (0, 0)


@pytest.mark.parametrize("argv,message", [
    ([], "vanity.py: error: the following arguments are required: --prefix"),
    (["--prefix"], "vanity.py: error: argument --prefix: expected one argument"),
    (["--prefix", "a", "--threads", "x"],
     "vanity.py: error: argument --threads: invalid int value: 'x'"),
    (["--prefix", "a", "--seconds", "1.5"],
     "vanity.py: error: argument --seconds: invalid int value: '1.5'"),
    (["--prefix", "a", "--bogus"], "vanity.py: error: unrecognized arguments: --bogus"),
    (["--prefix", "a", "--json=1"],
     "vanity.py: error: argument --json: ignored explicit argument '1'"),
])
def test_argparse_errors(lab, argv, message):
    r, p, _, _ = lab.both(argv)
    assert (r.rc, p.rc) == (2, 2)
    assert r.err.strip().splitlines()[-1] == message == p.err.strip().splitlines()[-1]
    assert r.out == ""


def test_abbreviated_and_equals_options(lab):
    lab.check(["--pre=a", "--na", "svc", "--thr", "1", "--sec=1", "--ou", "out", "--js"], "ok", rc=0)


# ───────────────────────────── generating ────────────────────────────────────

def test_generate_installs_a_hardened_key_set(lab):
    r, rd = lab.check([*GEN, "--out", "out", "--json"], "ok", rc=0)
    d = doc(r)
    assert d == {
        "ok": True, "exit_code": 0, "name": "svc", "onion": ADDR,
        "key_path": "out/svc/hs_ed25519_secret_key",
        "public_key_path": "out/svc/hs_ed25519_public_key",
        "address_path": "out/svc/hostname", "key_dir": "out/svc",
        "threads": 2, "address_matches_prefix": True}
    modes = {p.name: p.stat().st_mode & 0o7777 for p in (rd / "out" / "svc").iterdir()}
    assert modes == {"hostname": 0o644, "hs_ed25519_public_key": 0o600,
                     "hs_ed25519_secret_key": 0o600}
    assert (rd / "out" / "svc").stat().st_mode & 0o7777 == 0o700
    assert [p.name for p in (rd / "out").iterdir()] == ["svc"], "no scratch directory is left"


def test_generate_text_output(lab):
    r, _ = lab.check([*GEN, "--out", "out"], "ok", rc=0)
    assert r.out == (f"Found {ADDR}\nWrote out/svc/hs_ed25519_secret_key (secret, mode 0600)\n"
                     "Back up out/svc - losing it loses the address permanently.\n")


def test_generate_default_out_comes_from_the_environment(lab):
    r, p, rd, pd = lab.both([*GEN, "--json"], "ok", HIDDENFORGE_KEYS_DIR="fromenv")
    assert (r.rc, p.rc) == (0, 0)
    assert doc(r)["key_dir"] == doc(p)["key_dir"] == "fromenv/svc"


def existing(d):
    (d / "out" / "svc").mkdir(parents=True)
    write(d / "out" / "svc" / "hostname", "old\n")
    write(d / "out" / "svc.onion", "old\n")


def test_an_existing_key_set_is_never_overwritten_without_force(lab):
    for flags in (["--json"], []):
        r, rd = lab.check([*GEN, "--out", "out", *flags], "ok", build=existing, rc=2)
    assert (rd / "out" / "svc" / "hostname").read_text() == "old\n"
    r, rd = lab.check([*GEN, "--out", "out", "--json"], "ok", build=existing)
    assert doc(r)["error"] == (
        "out/svc already exists. Refusing to overwrite a key set: the key IS the .onion "
        "address and there is no recovery. Pass --force to archive the old one and generate "
        "a fresh address.")
    assert doc(r)["name"] == "svc"


def test_a_dangling_symlink_counts_as_an_existing_key_set(lab):
    def build(d):
        (d / "out").mkdir()
        (d / "out" / "svc").symlink_to("nowhere")

    lab.check([*GEN, "--out", "out", "--json"], "ok", build=build, rc=2)


def test_force_archives_the_old_set_and_drops_its_published_address(lab):
    r, rd = lab.check([*GEN, "--out", "out", "--force", "--json"], "ok", build=existing, rc=0)
    d = doc(r)
    assert norm(d["archived"]) == "out/svc.replaced-<T>"
    assert not (rd / "out" / "svc.onion").exists()
    assert (rd / d["archived"] / "hostname").read_text() == "old\n"
    assert (rd / "out" / "svc" / "hostname").read_text() == ADDR + "\n"


def test_force_picks_a_free_archive_name(lab):
    def build(d):
        existing(d)
        now = int(time.time())
        for t in range(now - 2, now + 4):
            (d / "out" / f"svc.replaced-{t}").mkdir()
            (d / "out" / f"svc.replaced-{t}-1").mkdir()

    r, _ = lab.check([*GEN, "--out", "out", "--force", "--json"], "ok", build=build, rc=0)
    assert norm(doc(r)["archived"]) == "out/svc.replaced-<T>-2"


def test_force_without_an_existing_set_archives_nothing(lab):
    r, _ = lab.check([*GEN, "--out", "out", "--force", "--json"], "ok", rc=0)
    assert "archived" not in doc(r)


def test_uid_and_gid_are_applied(lab):
    uid, gid = os.getuid(), os.getgid()
    r, rd = lab.check([*GEN, "--out", "out", "--uid", str(uid), "--gid", str(gid), "--json"],
                      "ok", rc=0)
    assert (rd / "out" / "svc").stat().st_uid == uid


@pytest.mark.parametrize("mode,rc", [
    ("genfail", 1), ("fail_silent", 1), ("found_then_fail", 0), ("empty", 1), ("two", 1),
    ("badname", 1), ("hostname", 1), ("pubkey", 1), ("noise", 0), ("barekey", 0),
    ("badpub", 1),
])
def test_generator_outcomes(lab, mode, rc):
    for flags in (["--json"], []):
        lab.check([*GEN, "--out", "out", *flags], mode, rc=rc)


def test_generator_failure_messages(lab):
    msg = {}
    for mode in ("genfail", "fail_silent", "empty", "two", "badname", "hostname", "pubkey", "badpub"):
        r, _ = lab.check([*GEN, "--out", "out", "--json"], mode, rc=1)
        msg[mode] = doc(r)["error"]
    assert msg["genfail"] == "mkp224o exited 2: fake mkp224o: exploded"
    assert msg["fail_silent"] == "mkp224o exited 2: "
    assert msg["empty"] == "expected exactly one generated .onion directory, found 0"
    assert msg["two"] == "expected exactly one generated .onion directory, found 2"
    assert msg["badname"] == f"generator produced an invalid address name: {'0' * 56 + '.onion'!r}"
    assert msg["hostname"] == (f"hostname file ({'b' * 56 + '.onion'!r}) disagrees with "
                               f"directory name ({ADDR!r})")
    assert msg["badpub"] == "hs_ed25519_public_key: expected 64 bytes (tagged) or 32 bytes (bare), got 40"
    assert msg["pubkey"].startswith("address derived from public key (")


def test_a_failing_generator_that_still_produced_a_key_is_used(lab):
    r, rd = lab.check([*GEN, "--out", "out", "--json"], "found_then_fail", rc=0)
    assert (rd / "out" / "svc" / "hs_ed25519_secret_key").exists()


def test_an_address_that_does_not_start_with_the_prefix_is_refused(lab):
    r, rd = lab.check(["--prefix", "b", "--name", "svc", "--threads", "1", "--seconds", "1",
                       "--out", "out", "--json"], "ok", rc=1)
    assert doc(r)["error"] == f"generated address {ADDR} does not start with prefix 'b'"
    assert not (rd / "out" / "svc").exists()


def test_losing_the_race_exits_three_and_touches_nothing(lab):
    def build(d):
        (d / "out").mkdir()

    rd, pd = lab.twins(build)
    outs = []
    for d, run in ((rd, lambda args, env: rust(args, rd, env=env, argv0="vanity.py")),
                   (pd, lambda args, env: Result(*(lambda p: (p.returncode, p.stdout, p.stderr))(
                       subprocess.run([sys.executable, str(PY_VANITY), *args], cwd=pd, env=env,
                                      capture_output=True, text=True, timeout=60))))):
        env = lab.env("race", HF_FAKE_MKP224O_RACE=str(d / "out" / "svc"))
        outs.append((d, run([*GEN, "--out", "out", "--json"], env)))
    (_, r), (_, p) = outs
    assert (r.rc, p.rc) == (3, 3)
    assert doc(r)["error"] == ("out/svc appeared while the search was running; refusing to "
                               "clobber it (exit 3)")
    assert doc(r) == doc(p)
    assert (rd / "out" / "svc" / "rival").read_text() == "someone else's key\n"
    assert [p.name for p in (rd / "out").iterdir()] == ["svc"]


def test_a_missing_generator_is_a_clean_error(lab, scratch):
    env = env_for(MKP224O=str(scratch / "absent"))
    r = rust([*GEN, "--out", "out", "--json"], scratch, env=env, argv0="vanity.py")
    # Neither /usr/local/bin/mkp224o nor /usr/bin/mkp224o exists on a test host.
    if not (Path("/usr/local/bin/mkp224o").exists() or Path("/usr/bin/mkp224o").exists()):
        assert r.rc == 2
        assert doc(r)["error"] == (
            "benchmark failed: mkp224o not found. This subcommand requires the hiddenforge "
            "image (which vendors it); run it via `hiddenforge vanity` on the host.")


def test_mkp224o_must_be_an_executable_regular_file(lab, scratch):
    """MKP224O naming a directory or a non-executable file is skipped, not run."""
    if Path("/usr/local/bin/mkp224o").exists() or Path("/usr/bin/mkp224o").exists():
        pytest.skip("a real mkp224o is installed")
    plain = write(scratch / "plain", "#!/bin/sh\nexit 0\n", 0o644)
    for bad in (scratch, plain):
        r = rust([*GEN, "--json"], scratch, env=env_for(MKP224O=str(bad)), argv0="vanity.py")
        assert r.rc == 2 and "mkp224o not found" in doc(r)["error"], bad
    good = write(scratch / "good", "#!/bin/sh\nsleep 0.1\n", 0o755)
    r = rust([*GEN, "--json"], scratch, env=env_for(MKP224O=str(good)), argv0="vanity.py")
    assert doc(r)["error"] == "benchmark failed: mkp224o produced no statistics; cannot benchmark"
