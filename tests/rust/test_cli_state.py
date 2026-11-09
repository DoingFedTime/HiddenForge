"""Commands that read or change state: setup, client-auth, the key-archive family, unseal-keys.

Where the Python host CLI can answer the same question it is run alongside and
must agree; the rest asserts the messages and codes the host CLI and its
contract define (the strings are quoted from scripts/hiddenforge).
"""

import json
import os
import pty
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cli_common import (  # noqa: F401  (scratch is a fixture, used by name)
    ONION,
    Pair,
    RUST,
    Result,
    env_for,
    needs_rust,
    py,
    rust,
    same,
    scratch,
    service,
    snapshot,
    write,
)

pytestmark = needs_rust


# ─────────────────────────────────── setup ───────────────────────────────────


def setup_run(prog, args, cwd, **kw):
    full = ["setup", "-o", "out", *args]
    return (rust if prog == "rust" else py)(full, cwd, **kw)


def rel(res, cwd):
    """Make the two runs comparable: they differ in the absolute scratch path only."""
    return type(res)(res.rc, res.out.replace(str(cwd), "<D>"), res.err.replace(str(cwd), "<D>"))


def both_setup(scratch, build, calls):
    """Run each (args, kwargs) call on twin directories; outputs and files must agree."""
    dirs = {}
    for tag in ("rust", "py"):
        d = scratch / tag
        d.mkdir()
        build(d)
        dirs[tag] = d
    results = []
    for args in calls:
        r = rel(setup_run("rust", args, dirs["rust"]), dirs["rust"])
        p = rel(setup_run("py", args, dirs["py"]), dirs["py"])
        same(r, p, " ".join(args))
        assert snapshot(dirs["rust"]) == snapshot(dirs["py"]), f"files differ after {args}"
        results.append(r)
    return results, dirs["rust"]


WEB = ["--backend", "web:80", "--non-interactive"]


@pytest.mark.parametrize("flags", [[], ["--json"]], ids=["text", "json"])
def test_a_second_setup_lists_what_exists_and_needs_force(scratch, flags):
    (first, second, forced), d = both_setup(
        scratch, lambda d: None, [[*WEB, *flags], [*WEB, *flags], [*WEB, *flags, "--force"]]
    )
    assert first.rc == 0 and second.rc == 2 and forced.rc == 0
    if flags:
        assert json.loads(second.out)["error"] == (
            "out already contains compose.service.yml, deploy.sh, README.txt, hiddenforge.json; "
            "pass --force to overwrite"
        )
    modes = {
        n: stat.S_IMODE((d / "out" / n).stat().st_mode)
        for n in ("compose.service.yml", "deploy.sh", "README.txt", "hiddenforge.json")
    }
    assert modes == {
        "compose.service.yml": 0o644,
        "deploy.sh": 0o755,
        "README.txt": 0o644,
        "hiddenforge.json": 0o644,
    }


def test_only_the_files_that_exist_are_listed(scratch):
    def build(d):
        write(d / "out" / "README.txt", "mine")
        write(d / "out" / "deploy.sh", "mine")

    (r,), _d = both_setup(scratch, build, [[*WEB, "--json"]])
    assert (
        json.loads(r.out)["error"]
        == "out already contains deploy.sh, README.txt; pass --force to overwrite"
    )


def test_force_replaces_a_regular_file(scratch):
    def build(d):
        write(d / "out" / "README.txt", "mine")

    (r,), d = both_setup(scratch, build, [[*WEB, "--force", "--json"]])
    assert r.rc == 0 and (d / "out" / "README.txt").read_text().startswith(
        "hiddenforge, your setup"
    )


@pytest.mark.parametrize("kind", ["symlink", "dir", "fifo"])
def test_force_never_replaces_a_link_a_directory_or_a_fifo(scratch, kind):
    def build(d):
        out = d / "out"
        out.mkdir()
        write(d / "target", "precious")
        if kind == "symlink":
            (out / "deploy.sh").symlink_to("../target")
        elif kind == "dir":
            (out / "deploy.sh").mkdir()
        else:
            os.mkfifo(out / "deploy.sh")

    (r,), d = both_setup(scratch, build, [[*WEB, "--force", "--json"]])
    assert r.rc == 2
    assert json.loads(r.out)["error"] == (
        "refusing to replace deploy.sh in out: not a regular file (a symlink, directory or "
        "FIFO is not something setup wrote)"
    )
    assert sorted(p.name for p in (d / "out").iterdir()) == ["deploy.sh"], "nothing was written"
    assert (d / "target").read_text() == "precious"


def test_setup_text_output_matches(scratch):
    (r,), _ = both_setup(scratch, lambda d: None, [[*WEB]])
    assert r.out.startswith("Wrote out/compose.service.yml\n")


def test_setup_service_flags_and_defaults(scratch):
    (scratch / "one").mkdir()
    (scratch / "two").mkdir()
    both_setup(
        scratch / "one",
        lambda d: None,
        [["--service", "b:80:y:81", "--service", "a:80:x:80", "--non-interactive", "--json"]],
    )
    both_setup(
        scratch / "two",
        lambda d: None,
        [
            [
                "--services",
                "a:80:x:80, b:81:y:81 ,",
                "--backend",
                "web:8080",
                "--name",
                "w",
                "--onion-port",
                "8080",
                "--non-interactive",
            ]
        ],
    )


def run_on_pty(args, cwd, typed, env=None, timeout=20):
    """Run the binary with a terminal as stdin; `typed` is written after it starts."""
    master, slave = pty.openpty()
    p = subprocess.Popen(
        [str(RUST), *args],
        cwd=cwd,
        env=env or env_for(),
        stdin=slave,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(slave)
    try:
        if typed is not None:
            time.sleep(0.3)
            os.write(master, typed.encode())
        else:
            os.close(master)
            master = None
        out, err = p.communicate(timeout=timeout)
    finally:
        if master is not None:
            os.close(master)
    return p.returncode, out.decode(), err.decode()


def test_setup_prompts_for_a_backend_on_a_terminal(scratch):
    rc, out, err = run_on_pty(["setup", "-o", "out", "--json"], scratch, None)
    assert rc == 2 and json.loads(out)["error"] == (
        "--backend service:port is required (or --service/--services)"
    ), "--json never prompts"
    rc, out, err = run_on_pty(["setup", "-o", "out"], scratch, "web:80\n")
    assert rc == 0, (out, err)
    assert "Backend service:port (e.g. web:80): " in err
    assert (
        'MYAPP_TOR_SERVICE_HOSTS: "80:web:80"'
        in (scratch / "out" / "compose.service.yml").read_text()
    )


def test_setup_prompt_abort_and_garbage(scratch):
    for typed in ("\n", "   \n"):
        rc, out, _err = run_on_pty(["setup", "-o", "out"], scratch, typed)
        assert rc == 130 and json.loads(out) == {
            "ok": False,
            "exit_code": 130,
            "error": "aborted at prompt",
        }, repr(typed)
    rc, out, _err = run_on_pty(["setup", "-o", "out"], scratch, "\x04")  # EOF at the prompt
    assert rc == 130 and json.loads(out)["error"] == "aborted at prompt"
    rc, out, _err = run_on_pty(["setup", "-o", "out"], scratch, "no-port\n")
    assert rc == 2 and json.loads(out)["error"] == "--backend must be host:port, got 'no-port'"
    rc, out, _err = run_on_pty(["setup", "-o", "out"], scratch, "web:80\n")
    assert not (scratch / "out" / "ghost").exists()
    assert rc == 0


def test_setup_non_interactive_or_no_terminal_never_prompts(scratch):
    for args in (["setup", "-o", "out", "--non-interactive"], ["setup", "-o", "out", "--json"]):
        rc, _out, err = run_on_pty(args, scratch, "web:80\n")
        assert rc == 2 and "Backend service" not in err, args
    r = rust(["setup", "-o", "out"], scratch)  # stdin is /dev/null
    assert r.rc == 2 and json.loads(r.out)["error"] == (
        "--backend service:port is required (or --service/--services)"
    )


# ───────────────────────────────── client-auth ───────────────────────────────

RESTART = "Restart the container: Tor reads the authorized clients when it starts."
PRIVATE = re.compile(r"^[a-z2-7]{56}:descriptor:x25519:[A-Z2-7]{52}$")


@pytest.fixture
def ca(scratch):
    service(scratch / "keys", "svc")

    def call(*args, **kw):
        return rust(["client-auth", *args], scratch, **kw)

    call.dir = scratch
    return call


def test_client_auth_list_when_nobody_is_authorized(ca):
    r = ca("list", "--keys", "keys", "--name", "svc")
    assert (r.rc, r.out) == (
        0,
        "svc: no client authorization (anyone with the address can connect)\n",
    )
    r = ca("list", "--keys", "keys", "--name", "svc", "--json")
    assert json.loads(r.out) == {"ok": True, "exit_code": 0, "name": "svc", "clients": []}


def test_client_auth_add_list_remove_cycle(ca):
    r = ca("add", "--keys", "keys", "--name", "svc", "--client", "alice", "--json")
    doc = json.loads(r.out)
    assert r.rc == 0 and doc["first_client"] is True and doc["onion"] == ONION
    assert PRIVATE.match(doc["client_auth_private"])
    assert doc["client_auth_private"].startswith(ONION[:-6] + ":descriptor:x25519:")
    auth = ca.dir / "keys" / "svc" / "authorized_clients"
    assert stat.S_IMODE(auth.stat().st_mode) == 0o700
    f = auth / "alice.auth"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert re.fullmatch(r"descriptor:x25519:[A-Z2-7]{52}\n", f.read_text())
    assert doc["client_auth_private"].rsplit(":", 1)[1] not in f.read_text(), (
        "no private half stored"
    )

    r = ca("add", "--keys", "keys", "--name", "svc", "--client", "bob", "--json")
    assert json.loads(r.out)["first_client"] is False

    r = ca("add", "--keys", "keys", "--name", "svc", "--client", "alice", "--json")
    assert r.rc == 1 and json.loads(r.out)["error"] == (
        "client alice already exists for svc; remove it first to issue a new key"
    )

    assert ca("list", "--keys", "keys", "--name", "svc").out == (
        "svc: only these clients can connect: alice, bob\n"
    )
    assert json.loads(ca("list", "--keys", "keys", "--name", "svc", "--json").out)["clients"] == [
        "alice",
        "bob",
    ]

    r = ca("remove", "--keys", "keys", "--name", "svc", "--client", "alice", "--json")
    assert (r.rc, json.loads(r.out)) == (
        0,
        {"ok": True, "exit_code": 0, "name": "svc", "client": "alice", "removed": True},
    )
    assert r.out.count("\n") == 1, "one JSON document and nothing else"
    r = ca("remove", "--keys", "keys", "--name", "svc", "--client", "alice", "--json")
    assert json.loads(r.out)["removed"] is False
    assert not f.exists()


def test_client_auth_text_output(ca):
    r = ca("add", "--keys", "keys", "--name", "svc", "--client", "alice")
    lines = r.out.split("\n")
    assert r.rc == 0
    assert lines[0] == "svc: authorized client alice."
    assert lines[1] == (
        f"This is the first client: from the next start, ONLY authorized clients can reach {ONION}."
    )
    assert lines[2] == RESTART and lines[3] == ""
    assert lines[4] == (
        "Give this line to alice, over a channel you trust, and nowhere else. "
        "It is shown once and not stored:"
    )
    assert PRIVATE.match(lines[5]) and lines[6] == ""
    assert lines[7].startswith(
        "The client saves it as a file ending in .auth_private in the "
        "directory its torrc names with"
    )
    assert (
        "ClientOnionAuthDir (Tor Browser: paste the key part when it asks for the onion's key)."
        in r.out
    )
    r = ca("add", "--keys", "keys", "--name", "svc", "--client", "bob")
    assert "This is the first client" not in r.out
    r = ca("remove", "--keys", "keys", "--name", "svc", "--client", "bob")
    assert r.out == f"svc: removed bob. {RESTART}\n"
    r = ca("remove", "--keys", "keys", "--name", "svc", "--client", "bob")
    assert r.out == f"svc: bob was not authorized. {RESTART}\n"


def test_client_auth_refusals(ca, scratch):
    def err(*args):
        r = ca(*args)
        return r.rc, json.loads(r.out)["error"]

    assert err("list", "--keys", "keys", "--name", "nope") == (
        2,
        "no service nope in keys: start it once, or generate its key, before authorizing clients",
    )
    assert err("list", "--keys", "keys", "--name", "Bad")[0] == 2
    assert err("add", "--keys", "keys", "--name", "svc") == (2, "--client <name> is required")
    assert err("remove", "--keys", "keys", "--name", "svc") == (2, "--client <name> is required")
    for bad in ("Alice", "-x", "a b", "../x", "a" * 64, ""):
        assert err("add", "--keys", "keys", "--name", "svc", f"--client={bad}")[0] == 2, bad
    service(scratch / "keys", "nokey", pub=None)
    assert err("add", "--keys", "keys", "--name", "nokey", "--client", "a") == (
        2,
        "nokey has no public key yet: start it once before authorizing clients",
    )
    # the default service name is myapp
    assert err("list", "--keys", "keys")[1].startswith("no service myapp in keys")


def test_client_auth_names_are_checked_before_the_directory(ca):
    r = ca("list", "--keys", "nowhere", "--name=-bad")
    assert r.rc == 2 and "invalid service name" in json.loads(r.out)["error"]


@pytest.mark.parametrize("client", ["a", "a-b", "a_b", "0", "a" * 63])
def test_client_auth_accepts_valid_names(ca, client):
    r = ca("add", "--keys", "keys", "--name", "svc", "--client", client, "--json")
    assert r.rc == 0, r.out


def test_client_auth_refuses_to_follow_links_in_the_auth_dir(ca, scratch):
    auth = scratch / "keys" / "svc" / "authorized_clients"
    auth.mkdir()
    write(scratch / "elsewhere", "precious")
    (auth / "evil.auth").symlink_to(scratch / "elsewhere")
    r = ca("remove", "--keys", "keys", "--name", "svc", "--client", "evil", "--json")
    assert r.rc == 1 and "is not a regular file; refusing to touch it" in json.loads(r.out)["error"]
    assert (scratch / "elsewhere").read_text() == "precious"


# ──────────────────── backup / restore / encrypt-key / decrypt-key ───────────


def tools(scratch, *names):
    d = scratch / "bin"
    d.mkdir(exist_ok=True)
    for n in names:
        write(d / n, "", 0o755)
    return d


def bare_env(path, **extra):
    return {"PATH": str(path), "HOME": "/tmp", **extra}  # noqa: S108  (a HOME that exists; nothing is written there)


NO_TOOL = "no encryption tool found: install `age` (preferred) or `gpg`"
HINT = (
    ". The hiddenforge image ships no crypto tooling on purpose; run this command on the "
    "HOST that holds your backup, not with docker exec"
)


def error_of(r):
    return json.loads(r.out)["error"]


@pytest.fixture
def kd(scratch):
    """A scratch dir holding keys/, an empty PATH dir, and a passphrase file."""
    service(scratch / "keys", "svc")
    (scratch / "empty").mkdir()
    write(scratch / "pp", "correct horse battery staple\n")
    return scratch


PAIR_CASES = [
    ("backup-no-keys-dir", ["backup", "--keys", "nokeys", "--out", "o.age"]),
    ("backup-no-tool", ["backup", "--keys", "keys", "--out", "o.age"]),
    (
        "backup-no-tool-gpg",
        ["backup", "--keys", "keys", "--out", "o.gpg", "--passphrase-file", "pp"],
    ),
    ("restore-missing", ["restore", "--keys", "keys", "--input", "nope.age"]),
    ("restore-dir", ["restore", "--keys", "keys", "--input", "keys"]),
    ("restore-cannot-infer", ["restore", "--keys", "keys", "--input", "pp"]),
    ("encrypt-bad-name", ["encrypt-key", "--keys", "keys", "--name", "Bad"]),
    ("decrypt-bad-name", ["decrypt-key", "--keys", "keys", "--name", "../x"]),
    ("encrypt-no-tool", ["encrypt-key", "--keys", "keys", "--name", "svc"]),
    ("backup-openssl", ["backup", "--keys", "keys", "--out", "o", "--tool", "openssl"]),
]


@pytest.mark.parametrize(
    "path_has", [(), ("age",), ("gpg",), ("age", "gpg")], ids=["none", "age", "gpg", "both"]
)
@pytest.mark.parametrize("case,args", PAIR_CASES, ids=[c[0] for c in PAIR_CASES])
def test_refusals_before_any_tool_runs_match_the_host_cli(scratch, case, args, path_has):
    """Everything that fails before a tool would be started has the host CLI's words and code."""
    if case == "backup-no-tool-gpg" and path_has:
        pytest.skip("with a tool installed the host CLI would run it")

    def build(d):
        service(d / "keys", "svc")
        write(d / "pp", "correct horse battery staple\n")
        (d / "bin").mkdir()
        for n in path_has:
            write(d / "bin" / n, "", 0o755)

    p = Pair(scratch, build)
    env = lambda d: bare_env(d / "bin", HIDDENFORGE_IN_CONTAINER="1")  # noqa: E731
    r = rust(args, p.dirs[0], env=env(p.dirs[0]))
    q = py(args, p.dirs[1], env=env(p.dirs[1]))
    same(r, q, f"{case} {path_has}")
    assert snapshot(p.dirs[0]) == snapshot(p.dirs[1])
    assert r.rc == 2


def test_no_tool_message_adds_the_hint_inside_the_image(kd):
    env = bare_env(kd / "empty", HIDDENFORGE_IN_CONTAINER="1")
    r = rust(["backup", "--keys", "keys", "--out", "o.age"], kd, env=env)
    assert (r.rc, error_of(r)) == (2, NO_TOOL + HINT)
    if not Path("/etc/tor/torrc").exists():
        r = rust(["backup", "--keys", "keys", "--out", "o.age"], kd, env=bare_env(kd / "empty"))
        assert error_of(r) == NO_TOOL
    r = rust(
        ["backup", "--keys", "keys", "--out", "o.age"],
        kd,
        env=bare_env(kd / "empty", HIDDENFORGE_IN_CONTAINER="0"),
    )
    assert error_of(r) == (NO_TOOL + HINT if Path("/etc/tor/torrc").exists() else NO_TOOL)


def test_a_directory_named_like_a_tool_is_not_a_tool(kd):
    (kd / "bin" / "age").mkdir(parents=True)
    write(kd / "bin" / "gpg", "", 0o644)  # present but not executable
    r = rust(
        ["backup", "--keys", "keys", "--out", "o.age"],
        kd,
        env=bare_env(kd / "bin", HIDDENFORGE_IN_CONTAINER="1"),
    )
    assert error_of(r) == NO_TOOL + HINT


def tool_missing(tool):
    return f"{tool}: [Errno 2] No such file or directory: '{tool}'. {NO_TOOL}{HINT}"


def backup(kd, path_has, out, *extra, stdin=None, **env):
    bindir = kd / "bin"
    for f in list(bindir.glob("*")) if bindir.exists() else []:
        f.unlink()
    tools(kd, *path_has)
    return rust(
        ["backup", "--keys", "keys", "--out", out, *extra],
        kd,
        env=bare_env(bindir, HIDDENFORGE_IN_CONTAINER="1", **env),
        stdin=stdin,
    )


@pytest.mark.parametrize(
    "path_has,out,tool",
    [
        (("age", "gpg"), "o.age", "age"),
        (("age", "gpg"), "o.gpg", "gpg"),
        (("age", "gpg"), "o.tar", "gpg"),  # unattended: gpg is the usable default
        (("age",), "o.tar", "age"),
        (("gpg",), "o.age", "gpg"),
        (("gpg",), "o.gpg", "gpg"),
        (("age",), "o.gpg", "age"),
        (("age",), "o.age", "age"),
    ],
)
def test_backup_picks_the_tool_from_the_name_and_what_is_installed(kd, path_has, out, tool):
    r = backup(kd, path_has, out, "--passphrase-file", "pp")
    assert (r.rc, error_of(r)) == (2, tool_missing(tool))


def test_an_explicit_tool_wins(kd):
    r = backup(kd, ("age", "gpg"), "o.age", "--tool", "gpg", "--passphrase-file", "pp")
    assert error_of(r) == tool_missing("gpg")
    r = backup(kd, (), "o.age", "--tool", "age", "--passphrase-file", "pp")
    assert error_of(r) == tool_missing("age")


def test_backup_refuses_openssl(kd):
    r = backup(kd, ("age", "gpg"), "o", "--tool", "openssl", "--passphrase-file", "pp")
    assert (r.rc, error_of(r)) == (2, "openssl is refused for backup creation (no authentication)")


def test_unattended_backup_needs_a_passphrase_file(kd):
    """/dev/null is not a terminal: age cannot prompt, gpg needs a file."""
    r = backup(kd, ("age", "gpg"), "o.age")
    assert (r.rc, error_of(r)) == (
        2,
        "age prompts for its passphrase on a TTY and cannot run "
        "unattended; use --tool gpg with --passphrase-file instead",
    )
    r = backup(kd, ("age", "gpg"), "o.gpg")
    assert error_of(r) == "no passphrase source: pass --passphrase-file (or a TTY)"
    r = backup(kd, ("age", "gpg"), "o.tar", "--tool", "gpg")
    assert error_of(r) == "no passphrase source: pass --passphrase-file (or a TTY)"


def test_the_passphrase_file_is_size_capped(kd):
    for size, ok in ((0, True), (1, True), (4096, True), (4097, False), (100000, False)):
        write(kd / "pp", b"x" * size)
        r = backup(kd, ("gpg",), "o.gpg", "--passphrase-file", "pp")
        want = tool_missing("gpg") if ok else "passphrase file too large"
        assert error_of(r) == want, size


def test_a_missing_passphrase_file_is_reported_with_the_path(kd):
    # Python's host CLI exits 1 here (an OSError); the image CLI exits 2 (open decision).
    r = backup(kd, ("gpg",), "o.gpg", "--passphrase-file", "absent")
    assert (r.rc, error_of(r)) == (2, "[Errno 2] No such file or directory: 'absent'")


def pty_backup(kd, path_has, out, *extra):
    tools(kd, *path_has)
    master, slave = pty.openpty()
    p = subprocess.run(
        [str(RUST), "backup", "--keys", "keys", "--out", out, *extra],
        cwd=kd,
        env=bare_env(kd / "bin", HIDDENFORGE_IN_CONTAINER="1"),
        stdin=slave,
        capture_output=True,
        text=True,
        timeout=30,
    )
    os.close(slave)
    os.close(master)
    return Result(p.returncode, p.stdout, p.stderr)


def test_on_a_terminal_age_is_preferred_and_needs_no_passphrase_file(scratch):
    (scratch / "keys").mkdir()
    for old in (scratch / "bin").glob("*") if (scratch / "bin").exists() else []:
        old.unlink()
    p = pty_backup(scratch, ("age", "gpg"), "o.tar")
    assert (p.rc, error_of(p)) == (2, tool_missing("age"))
    for old in (scratch / "bin").glob("*"):
        old.unlink()
    p = pty_backup(scratch, ("gpg",), "o.tar")
    assert error_of(p) == tool_missing("gpg")
    p = pty_backup(scratch, ("gpg",), "o.age")
    assert error_of(p) == tool_missing("gpg")


def restore(kd, path_has, input_name, *extra, **env):
    tools(kd, *path_has)
    return rust(
        ["restore", "--keys", "keys", "--input", input_name, *extra],
        kd,
        env=bare_env(kd / "bin", HIDDENFORGE_IN_CONTAINER="1", **env),
    )


def test_restore_infers_the_tool_from_the_file_name(kd):
    write(kd / "b.age", "x")
    write(kd / "b.gpg", "x")
    write(kd / "b.tar", "x")
    r = restore(kd, (), "b.age", "--passphrase-file", "pp")
    assert (r.rc, error_of(r)) == (2, tool_missing("age"))
    r = restore(kd, (), "b.gpg", "--passphrase-file", "pp")
    assert error_of(r) == tool_missing("gpg")
    r = restore(kd, (), "b.tar", "--passphrase-file", "pp")
    assert (r.rc, error_of(r)) == (2, "cannot infer --tool from the input name; pass --tool")
    r = restore(kd, (), "b.tar", "--passphrase-file", "pp", "--tool", "gpg")
    assert error_of(r) == tool_missing("gpg")
    r = restore(kd, (), "b.tar", "--passphrase-file", "pp", "--tool", "openssl")
    assert error_of(r) == tool_missing("openssl")


def test_restore_refuses_a_missing_input_and_passphrase_problems(kd):
    r = restore(kd, (), "gone.age")
    assert (r.rc, error_of(r)) == (2, "backup gone.age does not exist")
    r = restore(kd, (), "keys")
    assert error_of(r) == "backup keys does not exist"
    write(kd / "b.age", "x")
    r = restore(kd, (), "b.age")
    assert error_of(r) == (
        "age prompts for its passphrase on a TTY and cannot run unattended; "
        "use --tool gpg with --passphrase-file instead"
    )
    write(kd / "b.gpg", "x")
    r = restore(kd, (), "b.gpg")
    assert error_of(r) == "no passphrase source: pass --passphrase-file (or a TTY)"
    write(kd / "big", b"x" * 4097)
    r = restore(kd, (), "b.gpg", "--passphrase-file", "big")
    assert error_of(r) == "passphrase file too large"


@pytest.mark.parametrize("cmd", ["encrypt-key", "decrypt-key"])
def test_key_encryption_commands(kd, cmd):
    def call(path_has, *extra):
        tools(kd, *path_has)
        for old in [f for f in (kd / "bin").glob("*") if f.name not in path_has]:
            old.unlink()
        return rust(
            [cmd, "--keys", "keys", *extra],
            kd,
            env=bare_env(kd / "bin", HIDDENFORGE_IN_CONTAINER="1"),
        )

    r = call((), "--name", "svc")
    assert (r.rc, error_of(r)) == (2, NO_TOOL + HINT)
    r = call(("age", "gpg"), "--name", "svc", "--passphrase-file", "pp")
    assert error_of(r) == tool_missing("gpg"), "a passphrase file means unattended: gpg"
    r = call(("age",), "--name", "svc", "--passphrase-file", "pp")
    assert error_of(r) == tool_missing("age")
    r = call(("age", "gpg"), "--name", "svc", "--tool", "age", "--passphrase-file", "pp")
    assert error_of(r) == tool_missing("age")
    r = call(("age", "gpg"), "--name", "svc")  # no terminal: gpg is the usable default
    assert error_of(r) == "no passphrase source: pass --passphrase-file (or a TTY)"
    r = call(("age",), "--name", "svc")
    assert error_of(r).startswith("age prompts for its passphrase")
    r = call(("age", "gpg"), "--name", "svc", "--tool", "gpg")
    assert error_of(r) == "no passphrase source: pass --passphrase-file (or a TTY)"
    r = call(("gpg",), "--name", "Bad")
    assert error_of(r).startswith("invalid service name 'Bad'")
    write(kd / "zeropp", b"")
    r = call(("gpg",), "--name", "svc", "--passphrase-file", "zeropp")
    assert error_of(r) == tool_missing("gpg")


# ───────────────────────────────── unseal-keys ───────────────────────────────

STRONG = "correct horse battery staple"


def unseal(scratch, *args, stdin=None, **env):
    return rust(["unseal-keys", *args], scratch, env=env_for(**env), stdin=stdin)


def test_unseal_without_a_passphrase_source(scratch):
    r = unseal(scratch, "--name", "hftestsvc")
    assert (r.rc, json.loads(r.out)) == (
        2,
        {
            "ok": False,
            "exit_code": 2,
            "error": "no passphrase: pass --passphrase-file or set HIDDENFORGE_KEY_PASSPHRASE_FILE",
        },
    )


def test_unseal_names_come_from_the_flag_or_the_environment(scratch):
    write(scratch / "pp", STRONG + "\n")
    r = unseal(scratch, "--passphrase-file", "pp", "--json", "--name", "hftest-one")
    assert (r.rc, json.loads(r.out)) == (
        0,
        {"ok": True, "exit_code": 0, "unsealed": [], "not_sealed": ["hftest-one"]},
    )
    r = unseal(
        scratch,
        "--passphrase-file",
        "pp",
        "--json",
        HFTEST_B_TOR_SERVICE_HOSTS="80:x:80",
        HFTEST_A_TOR_SERVICE_HOSTS="80:x:80",
        hftest_b_TOR_SERVICE_HOSTS="80:x:80",
        _LEAD_TOR_SERVICE_HOSTS="x",
        HFTEST_9_TOR_SERVICE_HOSTS="80:x:80",
        OTHER_VAR="1",
    )
    assert json.loads(r.out)["not_sealed"] == ["hftest-9", "hftest-a", "hftest-b"], (
        "sorted, lowercased, underscores to hyphens, duplicates and invalid names dropped"
    )
    r = unseal(scratch, "--passphrase-file", "pp", "--json")
    assert (r.rc, json.loads(r.out)["error"]) == (
        2,
        "no service named: pass --name, or run it in "
        "the tor service, where <NAME>_TOR_SERVICE_HOSTS is set",
    )
    r = unseal(scratch, "--passphrase-file", "pp", "--name", "Bad")
    assert r.rc == 2 and json.loads(r.out)["error"].startswith("invalid service name 'Bad'")


def test_unseal_text_output(scratch):
    write(scratch / "pp", STRONG + "\n")
    r = unseal(scratch, "--passphrase-file", "pp", "--name", "hftest-one")
    assert (r.rc, r.out) == (
        0,
        "hftest-one: no sealed key; nothing to do\n"
        "Remove HIDDENFORGE_KEY_PASSPHRASE_FILE and the passphrase secret "
        "from the compose file before the next start; otherwise the key is "
        "sealed again.\n",
    )


def test_unseal_reads_the_passphrase_from_the_environment_file_or_stdin(scratch):
    write(scratch / "pp", STRONG)
    r = unseal(scratch, "--name", "hftest-one", "--json", HIDDENFORGE_KEY_PASSPHRASE_FILE="pp")  # noqa: S106  (the NAME of a file, not a secret)
    assert r.rc == 0
    p = subprocess.run(
        [str(RUST), "unseal-keys", "--name", "hftest-one", "--json", "--passphrase-file", "-"],
        input=STRONG + "\n",
        text=True,
        capture_output=True,
        cwd=scratch,
        env=env_for(),
        timeout=30,
    )
    assert (p.returncode, json.loads(p.stdout)["not_sealed"]) == (0, ["hftest-one"])


@pytest.mark.parametrize("source", ["file", "stdin"])
def test_unseal_refuses_a_short_passphrase(scratch, source):
    short = "x" * 11
    if source == "file":
        write(scratch / "pp", short + "\n")
        r = unseal(scratch, "--name", "hftest-one", "--passphrase-file", "pp")
    else:
        p = subprocess.run(
            [str(RUST), "unseal-keys", "--name", "hftest-one", "--passphrase-file", "-"],
            input=short + "\n",
            text=True,
            capture_output=True,
            cwd=scratch,
            env=env_for(),
            timeout=30,
        )
        r = type("R", (), {"rc": p.returncode, "out": p.stdout})
    assert r.rc == 1
    assert "the passphrase is 11 characters; at least" in json.loads(r.out)["error"]


def test_unseal_a_missing_passphrase_file_is_an_error(scratch):
    r = unseal(scratch, "--name", "hftest-one", "--passphrase-file", "absent")
    assert r.rc == 1 and json.loads(r.out)["error"].startswith(
        "cannot read the passphrase file absent: "
    )
