"""Which program the binary is, by name: dispatch, internal probes, host-only commands.

The binary is one multi-call executable chosen by argv0. These tests start it
under each name and check who answered. Nothing here may boot the supervisor
(an unknown argument to entrypoint.py would) and nothing signals a process the
test did not start itself.
"""

import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cli_common import REPO, RUST, env_for, needs_rust, rust, scratch, write  # noqa: E402,F401

pytestmark = needs_rust

VERSION = re.search(r'^version = "([^"]+)"', (REPO / "hiddenforge-rs" / "Cargo.toml").read_text(),
                    re.M).group(1)
SUBCOMMANDS = ["setup", "show", "doctor", "version", "info", "vanity", "encrypt-key",
               "decrypt-key", "backup", "restore", "rotate", "unseal-keys", "client-auth"]


def run(argv0, args, cwd, **kw):
    return rust(args, cwd, argv0=argv0, **kw)


# ───────────────────────── who answers to which name ─────────────────────────

def test_version_text_and_json(scratch):
    for argv0, args in (("hiddenforge", ["version"]), ("entrypoint.py", ["version"]),
                        ("python3", ["/usr/local/bin/entrypoint.py", "version"])):
        r = run(argv0, args, scratch)
        assert (r.rc, r.out, r.err) == (0, f"hiddenforge {VERSION} (contract 1)\n", ""), argv0
        r = run(argv0, [*args, "--json"], scratch)
        assert r.rc == 0 and json.loads(r.out) == {
            "ok": True, "exit_code": 0, "name": "hiddenforge", "version": VERSION,
            "contract_version": 1}, argv0


@pytest.mark.parametrize("cmd", SUBCOMMANDS)
@pytest.mark.parametrize("argv0,prefix", [("hiddenforge", ""), ("entrypoint.py", ""),
                                          ("entrypoint", ""),
                                          ("python3", "/usr/local/bin/entrypoint.py")])
def test_every_operator_command_is_reached_by_name(scratch, cmd, argv0, prefix):
    args = ([prefix] if prefix else []) + [cmd, "-h"]
    r = run(argv0, args, scratch)
    prog = "vanity.py" if cmd == "vanity" else f"hiddenforge {cmd}"
    if cmd == "client-auth":  # needs an operation first: its own usage error, as JSON
        assert r.rc == 2 and "usage: hiddenforge client-auth {add,remove,list}" in json.loads(r.out)["error"]
    else:
        assert r.rc == 0 and r.out.startswith(f"usage: {prog} [-h]"), (r.out, r.err)


def test_vanity_py_and_the_python_form_reach_the_generator(scratch):
    for argv0, args in (("vanity.py", ["-h"]), ("python3", ["/usr/local/bin/vanity.py", "-h"]),
                        ("python", ["/usr/local/bin/vanity.py", "-h"]),
                        ("python3.12", ["/usr/local/bin/vanity.py", "-h"])):
        r = run(argv0, args, scratch)
        assert r.rc == 0 and r.out.startswith("usage: vanity.py [-h] --prefix PREFIX"), argv0
    r = run("vanity.py", [], scratch)
    assert r.rc == 2 and "the following arguments are required: --prefix" in r.err


def test_the_python_form_answers_only_three_scripts(scratch):
    for args in ([], ["other.py"], ["-c", "print(1)"], ["/usr/local/bin/entrypoint.py.bak"],
                 ["/tmp/healthcheck.py"], ["healthcheck.py"]):
        r = run("python3", args, scratch)
        assert r.rc == 127 and r.out == ""
        assert r.err == ("python3: HiddenForge 3.0 has no Python in the image; this form is "
                         f"not one it answers: {' '.join(args)}\n"), args


def test_the_python_form_reaches_the_healthcheck(scratch):
    r = run("python3", ["/usr/local/bin/healthcheck.py", "--bogus"], scratch)
    assert (r.rc, r.err) == (2, "usage: healthcheck.py [-h] [--json] [--watch-uploads]\n")
    r = run("healthcheck.py", ["--bogus"], scratch)
    assert (r.rc, r.err) == (2, "usage: healthcheck.py [-h] [--json] [--watch-uploads]\n")


def test_healthcheck_json_and_plain_forms_differ(scratch):
    a = run("healthcheck.py", ["--json"], scratch)
    doc = json.loads(a.out)
    assert doc["ready"] in (True, False) and a.rc == doc["exit_code"]
    b = run("hiddenforge", ["healthcheck", "--json"], scratch)
    assert json.loads(b.out).keys() == doc.keys()
    plain = run("hiddenforge", ["healthcheck"], scratch)
    assert plain.out != a.out, "the plain form is not the JSON document"


def test_unknown_names_do_nothing(scratch):
    for name in ("frobnicate", "hiddenforge2", "su_exec", "Hiddenforge"):
        r = run(name, ["version"], scratch)
        assert r.rc == 2 and r.out == ""
        assert r.err == f"hiddenforge: started under an unknown name {name}; nothing to do\n"


def test_true_cat_sh_test_and_su_exec_forms(scratch):
    assert run("true", ["anything"], scratch).rc == 0
    assert run("test", ["-S", str(scratch)], scratch).rc == 1
    assert run("su-exec", [], scratch).rc == 1
    r = run("su-exec", ["root", "true"], scratch)
    assert r.rc != 0 and r.out == ""
    assert run("su-exec", ["tor"], scratch).err == "Usage: su-exec user-spec command [args]\n"


# ───────────────────────── the hiddenforge CLI proper ────────────────────────

def test_hiddenforge_without_a_command_prints_usage(scratch):
    r = run("hiddenforge", [], scratch)
    assert (r.rc, r.out) == (2, "")
    assert r.err == "usage: hiddenforge <command> [options]   (see `hiddenforge info`)\n"


def test_unknown_commands_are_refused(scratch):
    for cmd in ("nosuch", "", "Show", "__true", "status2"):
        args = [cmd] + (["x"] if cmd == "__true" else [])
        r = run("hiddenforge", args, scratch)
        assert (r.rc, r.out) == (2, "")
        assert r.err == f"hiddenforge: unknown command {cmd}\n"


@pytest.mark.parametrize("cmd", ["status", "verify-image", "sbom"])
def test_host_commands_say_so(scratch, cmd):
    for argv0, args in (("hiddenforge", [cmd]), ("entrypoint.py", [cmd, "--json"])):
        r = run(argv0, args, scratch)
        if argv0 == "entrypoint.py":
            # not an image subcommand: entrypoint.py would boot; it must not be asked
            continue
        doc = json.loads(r.out)
        assert r.rc == 2 and doc == {
            "ok": False, "exit_code": 2,
            "error": f"`hiddenforge {cmd}` runs on the HOST (it needs the container engine or "
                     "the registry), not inside the image"}


def test_the_parser_rejects_what_argparse_rejects(scratch):
    r = run("hiddenforge", ["version", "--bogus"], scratch)
    assert r.rc == 2 and r.err.splitlines()[-1] == "hiddenforge version: error: unrecognized arguments: --bogus"
    r = run("hiddenforge", ["setup", "--runtime", "lxc"], scratch)
    assert r.rc == 2 and r.err.splitlines()[-1] == (
        "hiddenforge setup: error: argument --runtime: invalid choice: 'lxc' "
        "(choose from 'docker', 'podman')")
    r = run("hiddenforge", ["doctor", "--k", "x"], scratch)
    assert r.rc == 2 and "ambiguous option: --k could match --keys, --keys-only" in r.err
    r = run("hiddenforge", ["show", "--json=1"], scratch)
    assert r.rc == 2 and "argument --json: ignored explicit argument '1'" in r.err
    r = run("hiddenforge", ["backup"], scratch)
    assert r.rc == 2 and r.err.splitlines()[-1] == (
        "hiddenforge backup: error: the following arguments are required: --out")
    r = run("hiddenforge", ["encrypt-key", "--name", "a", "--tool", "openssl"], scratch)
    assert r.rc == 2 and "invalid choice: 'openssl' (choose from 'age', 'gpg')" in r.err


def test_client_auth_needs_an_operation(scratch):
    for args in ([], ["frob"], ["--json"]):
        r = run("hiddenforge", ["client-auth", *args], scratch)
        assert r.rc == 2 and json.loads(r.out) == {
            "ok": False, "exit_code": 2,
            "error": "usage: hiddenforge client-auth {add,remove,list} [--name <service>] "
                     "[--client <name>] [--keys DIR] [--json]"}


# ───────────────────────── internal probes (supervisor) ──────────────────────

def test_is_socket_probe(scratch):
    sock_path = scratch / "s"
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(str(sock_path))
    try:
        assert run("hiddenforge", ["__is-socket", str(sock_path)], scratch).rc == 0
    finally:
        srv.close()
    write(scratch / "f", "x")
    assert run("hiddenforge", ["__is-socket", str(scratch / "f")], scratch).rc == 1
    assert run("hiddenforge", ["__is-socket", str(scratch / "missing")], scratch).rc == 1
    (scratch / "link").symlink_to(sock_path)
    assert run("hiddenforge", ["__is-socket", str(scratch / "link")], scratch).rc == 1, \
        "a symlink to a socket is not a socket (lstat)"
    r = run("hiddenforge", ["__is-socket"], scratch)
    assert (r.rc, r.err) == (2, "hiddenforge: unknown command __is-socket\n")


def test_true_probe_takes_no_arguments(scratch):
    assert run("hiddenforge", ["__true"], scratch).rc == 0
    assert run("hiddenforge", ["__true", "x"], scratch).rc == 2


READ_HOSTNAME_OK = ["/var/lib/tor/hidden_service/a/hostname", "/var/lib/tor/hs-ram/a/hostname",
                    "/var/lib/tor/hidden_service/a/b/hostname", "/var/lib/tor/hs-ram/hostname"]
READ_HOSTNAME_NO = ["/etc/hostname", "/var/lib/tor/hidden_service/a/hostnam",
                    "/var/lib/tor/hidden_service/a/hostname2",
                    "/var/lib/tor/hidden_service/a/xhostname",
                    "/var/lib/tor/other/a/hostname", "/var/lib/tor/hidden_servic/a/hostname",
                    "var/lib/tor/hidden_service/a/hostname", "hostname",
                    "/var/lib/tor/hidden_service/../../../etc/hostname",
                    "/var/lib/tor/hidden_service/a/../../../../etc/hostname",
                    "/var/lib/tor/hidden_service", "/var/lib/tor/hs-ram", ""]


def test_read_hostname_accepts_only_tor_volume_hostname_files(scratch):
    """Accepted paths are read (and fail with 1: nothing there); refused ones are 'unknown command'."""
    for p in READ_HOSTNAME_OK:
        r = run("hiddenforge", ["__read-hostname", p], scratch)
        assert (r.rc, r.out) == (1, ""), p
        assert "unknown command" not in r.err, p
    for p in READ_HOSTNAME_NO:
        r = run("hiddenforge", ["__read-hostname", p], scratch)
        assert (r.rc, r.err) == (2, f"hiddenforge: unknown command __read-hostname\n"), p
    r = run("hiddenforge", ["__read-hostname"], scratch)
    assert (r.rc, r.err) == (2, "hiddenforge: unknown command __read-hostname\n")


def spawn_sleeper():
    return subprocess.Popen(["sleep", "60"], stdin=subprocess.DEVNULL)


@pytest.mark.parametrize("sig,name", [(signal.SIGTERM, "TERM"), (signal.SIGINT, "INT"),
                                      (signal.SIGKILL, "KILL")])
def test_kill_probe_signals_only_what_it_is_told_to(scratch, sig, name):
    victim = spawn_sleeper()
    try:
        r = run("hiddenforge", ["__kill", str(victim.pid), str(int(sig))], scratch)
        assert (r.rc, r.out, r.err) == (0, "", "")
        assert victim.wait(timeout=10) == -int(sig)
    finally:
        if victim.poll() is None:
            victim.kill()
            victim.wait()


def test_kill_probe_refuses_other_signals_and_bad_arguments(scratch):
    victim = spawn_sleeper()
    try:
        for sig in ("0", "1", "3", "10", "12", "17", "18", "19", "20", "-15", "x", "", "15.0", "9 "):
            r = run("hiddenforge", ["__kill", str(victim.pid), sig], scratch)
            assert r.rc == 2 and r.out == "", sig
        for pid in ("x", "", "1.5", "abc", "99999999999999999999"):
            r = run("hiddenforge", ["__kill", pid, "15"], scratch)
            assert r.rc == 2, pid
        assert run("hiddenforge", ["__kill", str(victim.pid)], scratch).rc == 2
        assert victim.poll() is None, "nothing may have signalled it"
    finally:
        victim.kill()
        victim.wait()


def test_kill_probe_reports_failure_for_a_missing_process(scratch):
    gone = spawn_sleeper()
    pid = gone.pid
    gone.kill()
    gone.wait()
    r = run("hiddenforge", ["__kill", str(pid), "15"], scratch)
    assert r.rc == 1, "kill(2) failed (no such process) is exit 1"


def test_keys_helper_arguments(scratch):
    """__keys <op> <name> reads a passphrase on stdin; bad name or op is exit 2, silently."""
    for args in (["unseal", "Bad"], ["unseal", ""], ["unseal", "a_b"], ["bogus", "ab"],
                 ["seal", "a b"]):
        r = run("hiddenforge", ["__keys", *args], scratch, stdin=subprocess.DEVNULL)
        assert (r.rc, r.out, r.err) == (2, "", ""), args
    for args in (["unseal"], ["unseal", "a", "b"], []):
        r = run("hiddenforge", ["__keys", *args], scratch)
        assert (r.rc, r.err) == (2, "hiddenforge: unknown command __keys\n"), args


def test_torrc_preview_reports_the_generated_torrc(scratch):
    env = env_for(MYAPP_TOR_SERVICE_HOSTS="80:127.0.0.1:8080")
    r = run("hiddenforge", ["torrc-preview"], scratch, env=env)
    doc = json.loads(r.out)
    assert r.rc == 0 and set(doc) == {
        "content", "dropped", "hs_dirs", "log", "resolved", "unresolved"}
    assert doc["hs_dirs"] == ["/var/lib/tor/hidden_service/myapp"]
    assert "HiddenServicePort 80 127.0.0.1:8080" in doc["content"]
    assert (doc["dropped"], doc["unresolved"]) == ([], [])
    assert run("hiddenforge", ["torrc-preview", "x"], scratch).rc == 2


# ───────────────────────── process hardening ─────────────────────────────────

def test_no_process_of_ours_can_dump_core_or_be_read(scratch):
    """Started with RLIMIT_CORE 0 and PR_SET_DUMPABLE 0: a crash must not put keys on disk."""
    exe = scratch / "hiddenforge"
    exe.symlink_to(RUST)
    # `__keys bogus ab` blocks reading its passphrase from stdin, then refuses the
    # operation without touching any volume: a stable moment to look at the process.
    child = subprocess.Popen([str(exe), "__keys", "bogus", "ab"], stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{child.pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
                if state == "S" and Path(f"/proc/{child.pid}/exe").resolve() == RUST.resolve():
                    break
            except OSError:
                pass
            time.sleep(0.02)
        limits = Path(f"/proc/{child.pid}/limits").read_text()
        core = next(l for l in limits.splitlines() if l.startswith("Max core file size"))
        assert core.split()[-3:-1] == ["0", "0"], core
        # A non-dumpable process has its /proc/<pid>/environ (and mem) owned by root.
        assert os.stat(f"/proc/{child.pid}/environ").st_uid == 0
    finally:
        child.stdin.close()
        assert child.wait(timeout=10) == 2


# ───────────────────────── option tables, info, write failures ───────────────

def python_options():
    """Option strings and arity per subcommand, read from the Python host CLI's parser."""
    import argparse
    import importlib.machinery
    import importlib.util

    loader = importlib.machinery.SourceFileLoader("hf_host_cli", str(REPO / "scripts" / "hiddenforge"))
    spec = importlib.util.spec_from_loader("hf_host_cli", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    top = mod.build_parser()
    sub = next(a for a in top._actions if isinstance(a, argparse._SubParsersAction))
    table = {}
    for cmd, sp in sub.choices.items():
        for a in sp._actions:
            if a.option_strings and a.option_strings != ["-h", "--help"]:
                first_choice = list(a.choices)[0] if a.choices else "x"
                table.setdefault(cmd, []).append((a.option_strings[-1], a.nargs == 0, first_choice))
    return table


IN_IMAGE = ["setup", "show", "doctor", "version", "info", "rotate", "backup", "restore",
            "encrypt-key", "decrypt-key"]
OPTIONS = python_options()


@pytest.mark.parametrize("cmd", IN_IMAGE)
def test_every_option_of_the_host_cli_is_accepted_in_the_image(scratch, cmd):
    """The image CLI accepts what the host CLI accepts for the same command (argparse forms)."""
    required = {"restore": ["--input", "in.age"], "backup": ["--out", "o.age"],
                "encrypt-key": ["--name", "svc"], "decrypt-key": ["--name", "svc"]}.get(cmd, [])
    for opt, is_flag, value in OPTIONS[cmd]:
        if opt in required[::2]:
            continue
        args = [cmd, *required, opt] + ([] if is_flag else [value])
        # The scratch directory is empty: each of these stops before it writes anything.
        r = rust(args, scratch, argv0="hiddenforge")
        for bad in ("unrecognized arguments", "expected one argument", "invalid choice",
                    "ambiguous"):
            assert bad not in r.err, (args, r.err)


@pytest.mark.skipif(Path("/opt/hiddenforge/manifest.json").exists(), reason="manifest installed")
def test_info_without_the_image_manifest(scratch):
    for flags in ([], ["--json"]):
        r = run("hiddenforge", ["info", *flags], scratch)
        assert r.rc == 1 and json.loads(r.out) == {
            "ok": False, "exit_code": 1, "error": "cannot read /opt/hiddenforge/manifest.json"}


def test_a_write_that_fails_part_way_leaves_nothing_behind(scratch):
    """RLIMIT_FSIZE makes write(2) fail with EFBIG: the error is reported and no temp file stays."""
    import resource

    def limit():
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (100, 100))

    p = subprocess.run([str(RUST), "setup", "-o", "out", "--backend", "web:80", "--non-interactive"],
                       cwd=scratch, env=env_for(), capture_output=True, text=True,
                       stdin=subprocess.DEVNULL, preexec_fn=limit, timeout=30)
    assert p.returncode == 1
    assert json.loads(p.stdout) == {"ok": False, "exit_code": 1,
                                    "error": "[Errno 27] File too large"}
    assert list((scratch / "out").iterdir()) == [], "no half-written file and no .tmp"
