"""The image CLI dispatch decides what runs, and as whom.

`docker run <image> show` must not become `docker run <image> setup` with root's
privileges, and `setup` must not be demoted to the tor user -- it writes into a
host-owned key bind mount and has to be able to chown it. That decision is four
lines in `dispatch_subcommand`, and before this file existed the only thing the
suite asserted about them was that a non-subcommand falls through and a missing
CLI reports an error.

Mutation testing made the gap concrete: inverting `argv[0] in AS_TOR` -- which
swaps the privilege of every subcommand, running `show`/`doctor` as root and
`setup`/`backup`/`restore` as the tor user -- survived the entire suite, as did
uppercasing the `su-exec` and `tor` argv entries so the privilege drop would not
happen at all. These tests pin the exact argv, because the argv IS the security
boundary here.
"""
import os

import pytest

import entrypoint as e


@pytest.fixture
def cli(tmp_path, monkeypatch):
    """A present HF_CLI, so dispatch gets past its existence check."""
    path = tmp_path / "hiddenforge"
    path.write_text("#!/bin/sh\n")
    monkeypatch.setattr(e, "HF_CLI", str(path))
    return str(path)


@pytest.fixture
def execs(monkeypatch):
    """Record os.execvp instead of replacing this process."""
    calls = []

    def fake_execvp(file, args):
        calls.append((file, args))

    monkeypatch.setattr(e.os, "execvp", fake_execvp)
    return calls


def _as_root(monkeypatch):
    monkeypatch.setattr(e.os, "geteuid", lambda: 0)


def _as_tor_user(monkeypatch):
    monkeypatch.setattr(e.os, "geteuid", lambda: 100)


# ─────────────────────────────────────────────────────────────────────────────
# Which tool runs
# ─────────────────────────────────────────────────────────────────────────────

def test_vanity_runs_the_generator_with_its_own_arguments(cli, execs, monkeypatch):
    _as_root(monkeypatch)
    assert e.dispatch_subcommand(["vanity", "--prefix", "abc"]) is None
    assert execs == [(
        "/usr/local/bin/vanity.py",
        ["/usr/local/bin/vanity.py", "--prefix", "abc"],
    )]


def test_vanity_with_no_arguments_is_not_an_index_error(cli, execs, monkeypatch):
    _as_root(monkeypatch)
    e.dispatch_subcommand(["vanity"])
    assert execs == [("/usr/local/bin/vanity.py", ["/usr/local/bin/vanity.py"])]


def test_every_other_subcommand_runs_the_operator_cli(cli, execs, monkeypatch):
    _as_root(monkeypatch)
    e.dispatch_subcommand(["setup", "--name", "app"])
    assert execs == [(cli, [cli, "setup", "--name", "app"])]


def test_doctor_is_the_only_subcommand_given_keys_only(cli, execs, monkeypatch):
    """--keys-only exists because there is no docker socket inside the image.

    Appending it to anything else would corrupt that command's argv: `backup
    --keys-only` is not a thing the CLI accepts.
    """
    _as_root(monkeypatch)
    e.dispatch_subcommand(["doctor"])
    e.dispatch_subcommand(["show"])
    e.dispatch_subcommand(["backup", "out.gpg"])
    assert execs == [
        ("su-exec", ["su-exec", "tor", cli, "doctor", "--keys-only"]),
        ("su-exec", ["su-exec", "tor", cli, "show"]),
        (cli, [cli, "backup", "out.gpg"]),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# As whom
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("subcommand", sorted(e.AS_TOR))
def test_read_only_key_commands_drop_to_the_tor_user(subcommand, cli, execs, monkeypatch):
    """show/doctor only read the 0700 tor-owned key dirs, which root cannot traverse
    under rootless Podman. They must go through su-exec, spelled exactly."""
    _as_root(monkeypatch)
    e.dispatch_subcommand([subcommand])
    file, argv = execs[0]
    assert file == "su-exec"
    assert argv[:3] == ["su-exec", "tor", cli]


@pytest.mark.parametrize("subcommand", sorted(e.SUBCOMMANDS - e.AS_TOR - {"vanity"}))
def test_key_writing_commands_stay_root(subcommand, cli, execs, monkeypatch):
    """setup/backup/restore/rotate/encrypt-key write into a host-owned bind mount
    and chown it; demoting them to the tor user breaks exactly that."""
    _as_root(monkeypatch)
    e.dispatch_subcommand([subcommand])
    file, argv = execs[0]
    assert file == cli
    assert "su-exec" not in argv


def test_no_su_exec_when_we_are_not_root(cli, execs, monkeypatch):
    """su-exec as a non-root uid cannot change user; wrapping would only add a
    failure. Under `docker run --user`, show must still run."""
    _as_tor_user(monkeypatch)
    e.dispatch_subcommand(["show"])
    assert execs == [(cli, [cli, "show"])]


# ─────────────────────────────────────────────────────────────────────────────
# Refusals and failures
# ─────────────────────────────────────────────────────────────────────────────

def test_unknown_argv_boots_tor_instead_of_dispatching(cli, execs):
    assert e.dispatch_subcommand([]) is None
    assert e.dispatch_subcommand(["tor", "-f", "/etc/tor/torrc"]) is None
    assert e.dispatch_subcommand(["Setup"]) is None      # case-sensitive by design
    assert execs == []


def test_a_failed_exec_names_the_tool_on_stderr_and_exits_2(cli, monkeypatch, capsys):
    """execvp only returns on failure. The operator needs to know which binary
    was missing, on stderr, with a usage-error exit code."""
    def boom(file, args):
        raise OSError(2, "No such file or directory")

    monkeypatch.setattr(e.os, "execvp", boom)
    _as_tor_user(monkeypatch)
    assert e.dispatch_subcommand(["show"]) == 2
    captured = capsys.readouterr()
    assert cli in captured.err
    assert "could not run" in captured.err
    assert captured.out == ""


def test_missing_cli_is_reported_before_any_exec(execs, monkeypatch):
    monkeypatch.setattr(e, "HF_CLI", "/nonexistent/hiddenforge")
    assert e.dispatch_subcommand(["show"]) == 2
    assert execs == []


def test_the_subcommand_set_is_the_contract():
    """A subcommand added to the CLI but not here silently boots Tor instead;
    one added here but not to the CLI exits 2 at runtime. Pin the set."""
    assert sorted(e.SUBCOMMANDS) == [
        "backup", "decrypt-key", "doctor", "encrypt-key", "info", "restore",
        "rotate", "setup", "show", "vanity", "version",
    ]
    assert sorted(e.AS_TOR) == ["doctor", "show"]
    assert e.AS_TOR < e.SUBCOMMANDS
    assert os.path.basename(e.HF_CLI) == "hiddenforge"
