#!/usr/bin/env python3
"""Turn a mutmut run into a pass/fail: every surviving mutant must be explained.

A kill rate is a number that drifts. What actually protects the code is the rule
that a mutant which survives is either killed by a new test or written down here
with a reason -- so the next survivor, the one nobody has looked at, fails the
build.

Run mutmut first (the console script, NOT `python -m mutmut`; see
review/MUTATION-2026-09-18.md for why), then this:

    .venv/bin/mutmut run
    python scripts/mutation_gate.py

Exit 0 if every non-killed mutant is accounted for, 1 otherwise.

## Why mutants are identified by their diff

mutmut names a mutant `x_<function>__mutmut_<n>`, where n is its position in the
generated list. Insert a line anywhere in a function and every number after it
moves, so an allowlist keyed on those names would be wrong after the next edit
and would quietly start accepting the wrong mutants. The key used here is the
function plus the one-line change itself, which is stable across renumbering,
survives unrelated edits elsewhere in the file, and -- unlike a name -- is
readable: the list below says what was accepted, not just that something was.

## Timeouts are not a verdict, so they are re-graded here

A mutant that really hangs is DETECTED: the suite noticed it, just not with an
assertion. But mutmut's bound is WALL clock -- (estimated_test_time + 1) * 15
seconds -- so on a loaded machine it also fires on mutants that hang not at all.
Counting the whole pile as detected was measured to be wrong: of 17 timeouts in
the 2026-09-18 run, re-grading found 3 real hangs, 7 kills, and **7 survivors**
that the gate was reporting as caught. Two of those seven had no allowlist entry,
which is to say the gate was green while hiding unexplained survivors.

So every timeout is re-run here on its own, against a fixed budget, and the
outcome decides: a kill counts as killed, a survivor goes through the same
allowlist as any other survivor, and a hang must be named in DOCUMENTED_HANGS
with the exit condition it removed. Anything else fails the build.

## Why this reads every mutant, not just the survivors

`mutmut results` prints only the mutants it did not kill, so an empty report means
either "everything was killed" or "nothing ever ran" -- and those must not look
the same. A gate that passes when the run it grades never happened is worse than
no gate. `--all` is therefore used, and the run is rejected outright if any mutant
is `not checked` (the pass did not finish), if any is `no tests` (code no test
reaches, which is not a weak test but no test), or if the total is implausibly
small for this repository.
"""
from __future__ import annotations

import ast
import difflib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MUTANTS = ROOT / "mutants"

# (function, removed, added) -> why this one cannot be killed.
#
# "Cannot", not "has not been": every entry is a mutant with no observable
# behavioural difference. A mutant that merely has no test yet does not belong
# here -- it belongs in a test.
ACCEPTED: dict[tuple[str, str, str], str] = {
    ('entrypoint._chown_r',
     'for root, dirs, files in os.walk(path, followlinks=False):',
     'for root, dirs, files in os.walk(path, followlinks=None):'):
        "False IS os.walk's default for followlinks, so the mutant asks for the behaviour that was already in force. The mutant that sets it to True is killed by tests/test_privileged_fs.py.",
    ('entrypoint._chown_r',
     'for root, dirs, files in os.walk(path, followlinks=False):',
     'for root, dirs, files in os.walk(path, ):'):
        "False IS os.walk's default for followlinks, so the mutant asks for the behaviour that was already in force. The mutant that sets it to True is killed by tests/test_privileged_fs.py.",
    ('entrypoint._chmod_dir_nofollow',
     '',
     ''):
        'Docstring text. No code changed.',
    ('entrypoint._kill_proc',
     '',
     ''):
        'Docstring text. No code changed.',
    ('entrypoint.signal_handler',
     '_kill_proc(_tor_process,       "Tor",       timeout=10)',
     '_kill_proc(_tor_process,       "Tor",       )'):
        "The omitted keyword's default is the same 10 seconds.",
    ('entrypoint.build_torrc_string',
     'sandbox = "1" if os.environ.get("TOR_SANDBOX", "1") != "0" else "0"',
     'sandbox = "1" if os.environ.get("TOR_SANDBOX", None) != "0" else "0"'):
        'Any default other than "0" yields Sandbox 1, which is what the expression is for.',
    ('entrypoint.build_torrc_string',
     'sandbox = "1" if os.environ.get("TOR_SANDBOX", "1") != "0" else "0"',
     'sandbox = "1" if os.environ.get("TOR_SANDBOX", ) != "0" else "0"'):
        'Any default other than "0" yields Sandbox 1, which is what the expression is for.',
    ('entrypoint.build_torrc_string',
     'sandbox = "1" if os.environ.get("TOR_SANDBOX", "1") != "0" else "0"',
     'sandbox = "1" if os.environ.get("TOR_SANDBOX", "XX1XX") != "0" else "0"'):
        'Any default other than "0" yields Sandbox 1, which is what the expression is for.',
    ('entrypoint.build_torrc_string',
     'found_any = False',
     'found_any = None'):
        'None and False are both falsy, and the value is only ever tested.',
    ('entrypoint.generate_basic_torrc',
     'TORRC_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640 )',
     'TORRC_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, )'):
        'The mode passed to os.open is only a request the umask narrows; this writer sets the mode outright with fchmod on the descriptor afterwards, so the value here cannot be observed.',
    ('entrypoint.generate_basic_torrc',
     'TORRC_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640',
     'TORRC_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 417'):
        'The mode passed to os.open is only a request the umask narrows; this writer sets the mode outright with fchmod on the descriptor afterwards, so the value here cannot be observed.',
    ('entrypoint._write_dropped_mappings',
     'fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)',
     'fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, )'):
        'The mode passed to os.open is only a request the umask narrows; this writer sets the mode outright with fchmod on the descriptor afterwards, so the value here cannot be observed.',
    ('entrypoint._write_dropped_mappings',
     'fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)',
     'fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 385)'):
        'The mode passed to os.open is only a request the umask narrows; this writer sets the mode outright with fchmod on the descriptor afterwards, so the value here cannot be observed.',
    ('entrypoint._service_reachable',
     "doc = json.loads(proc.stdout.decode('utf-8', 'replace'))",
     "doc = json.loads(proc.stdout.decode('UTF-8', 'replace'))"):
        'Codec names are normalised case-insensitively; this is the same codec.',
    ('entrypoint._publish_addresses',
     "onion = raw.decode('ascii').strip()",
     "onion = raw.decode('ASCII').strip()"):
        'Codec names are normalised case-insensitively; this is the same codec.',
    ('entrypoint._publish_addresses',
     "if _read_small_regular_file(target).decode('ascii').strip() == onion:",
     "if _read_small_regular_file(target).decode('ASCII').strip() == onion:"):
        'Codec names are normalised case-insensitively; this is the same codec.',
    ('entrypoint._publish_addresses',
     'fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)',
     'fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, )'):
        'The mode passed to os.open is only a request the umask narrows; this writer sets the mode outright with fchmod on the descriptor afterwards, so the value here cannot be observed.',
    ('entrypoint._publish_addresses',
     'fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)',
     'fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 421)'):
        'The mode passed to os.open is only a request the umask narrows; this writer sets the mode outright with fchmod on the descriptor afterwards, so the value here cannot be observed.',
    ('entrypoint._publish_addresses',
     "fh.write(onion.encode('ascii') + b'\\n')",
     "fh.write(onion.encode('ASCII') + b'\\n')"):
        'Codec names are normalised case-insensitively; this is the same codec.',
    ('entrypoint.wait_for_socket',
     '',
     ''):
        'Docstring text. No code changed.',
    ('entrypoint._permitted_capabilities',
     'header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, 0)',
     'header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, )'):
        'ctypes zero-fills an omitted field, and the omitted value was 0. The '
        'test that asserts pid == 0 passes either way because it IS 0 either way.',
    ('entrypoint._drop_setup_capabilities',
     'header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, 0)',
     'header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, )'):
        'ctypes zero-fills an omitted field, and the omitted value was 0.',
    ('entrypoint._drop_setup_capabilities',
     'data[0].inheritable = 0',
     'data[1].inheritable = 0'):
        "data[0].inheritable is already zero from the array's zero-initialisation, and data[1].inheritable is set to 0 on the next line regardless.",
    ('entrypoint._assert_process_dropped',
     '',
     ''):
        'Docstring text. No code changed.',
    ('entrypoint._assert_process_dropped',
     "status = Path(f'/proc/{proc.pid}/status').read_text(encoding='ascii')",
     "status = Path(f'/proc/{proc.pid}/status').read_text(encoding=None)"):
        'encoding=None takes the locale encoding, which is UTF-8 here and in the image, so the outcome is identical for every input this reads.',
    ('entrypoint._assert_process_dropped',
     "status = Path(f'/proc/{proc.pid}/status').read_text(encoding='ascii')",
     "status = Path(f'/proc/{proc.pid}/status').read_text(encoding='ASCII')"):
        'Codec names are normalised case-insensitively; this is the same codec.',
    ('entrypoint.main',
     'vanguards_last_start  = 0.0',
     'vanguards_last_start  = None'):
        'It is read only in the branch that handles a Vanguards exit, and every path that creates a Vanguards process assigns it first, so the initial value is never read.',
    ('entrypoint.main',
     'vanguards_last_start  = 0.0',
     'vanguards_last_start  = 1.0'):
        'An initialiser for a monotonic-clock comparison. time.monotonic() is far larger than any of these constants, so they all compare the same way.',
    ('entrypoint.main',
     'vanguards_next_attempt = 0.0',
     'vanguards_next_attempt = 1.0'):
        'An initialiser for a monotonic-clock comparison. time.monotonic() is far larger than any of these constants, so they all compare the same way.',
    ('entrypoint.main',
     'vanguards_given_up    = False',
     'vanguards_given_up    = None'):
        'None and False are both falsy, and the value is only ever tested.',
    ('entrypoint.main',
     'vanguards_next_attempt = 0.0',
     'vanguards_next_attempt = None'):
        'Two assignments share this text. At startup the mutant IS killed (a failed first start compares against it on the next tick). This survivor is the reset after a successful restart: it is never compared, because the next exit either gives up or assigns now + VANGUARDS_RETRY_DELAY before the comparison runs.',
    ('entrypoint._drop_setup_capabilities',
     'for b in range(64) if (mask >> b) & 1 and not (held >> b) & 1]',
     'for b in range(65) if (mask >> b) & 1 and not (held >> b) & 1]'):
        'The mask is a 64-bit integer, so bit 64 is always 0 and the extra step '
        'selects nothing.',
    ('entrypoint._drop_setup_capabilities',
     'for b in range(64) if (mask >> b) & 1) or "nothing"',
     'for b in range(65) if (mask >> b) & 1) or "nothing"'):
        'The mask is a 64-bit integer, so bit 64 is always 0 and the extra step '
        'selects nothing.',
    ('healthcheck._tor_running',
     'argv0 = cmdline.split(b"\\x00", 1)[0]',
     'argv0 = cmdline.split(b"\\x00", )[0]'):
        "Only element [0] is read, and it is the same first field at every maxsplit.",
    ('healthcheck._tor_running',
     'argv0 = cmdline.split(b"\\x00", 1)[0]',
     'argv0 = cmdline.split(b"\\x00", 2)[0]'):
        "Only element [0] is read, and it is the same first field at every maxsplit.",
    ('healthcheck._tor_running',
     'if argv0 and os.path.basename(argv0.decode("utf-8", "replace")) == TOR_ARGV0:',
     'if argv0 and os.path.basename(argv0.decode("UTF-8", "replace")) == TOR_ARGV0:'):
        'Codec names are normalised case-insensitively; this is the same codec.',
    ('healthcheck._query',
     'chunk = s.recv(65536)',
     'chunk = s.recv(65537)'):
        "recv's size is an upper bound on one read; the loop reads until the terminator either way.",
    ('healthcheck._hidden_service_dirs',
     'with open(TORRC, encoding="utf-8", errors="replace") as fh:',
     'with open(TORRC, encoding=None, errors="replace") as fh:'):
        'encoding=None takes the locale encoding, which is UTF-8 here and in the image, so the outcome is identical for every input this reads.',
    ('healthcheck._hidden_service_dirs',
     'with open(TORRC, encoding="utf-8", errors="replace") as fh:',
     'with open(TORRC, errors="replace") as fh:'):
        'encoding=None takes the locale encoding, which is UTF-8 here and in the image, so the outcome is identical for every input this reads.',
    ('healthcheck._hidden_service_dirs',
     'with open(TORRC, encoding="utf-8", errors="replace") as fh:',
     'with open(TORRC, encoding="UTF-8", errors="replace") as fh:'):
        'Codec names are normalised case-insensitively; this is the same codec.',
    ('healthcheck._circuit_status_lines',
     'lines = resp.decode("utf-8", "replace").splitlines()',
     'lines = resp.decode("UTF-8", "replace").splitlines()'):
        'Codec names are normalised case-insensitively; this is the same codec.',
    ('healthcheck._intro_points',
     'circuit_id = line.split(" ", 1)[0]',
     'circuit_id = line.split(None, 1)[0]'):
        'Every spelling still yields the first whitespace-delimited field, which is the circuit id.',
    ('healthcheck._intro_points',
     'circuit_id = line.split(" ", 1)[0]',
     'circuit_id = line.split(" ", )[0]'):
        'Every spelling still yields the first whitespace-delimited field, which is the circuit id.',
    ('healthcheck._intro_points',
     'circuit_id = line.split(" ", 1)[0]',
     'circuit_id = line.split(" ", 2)[0]'):
        'Every spelling still yields the first whitespace-delimited field, which is the circuit id.',
    ('vanity.derive_onion',
     'return base64.b32encode(pubkey + checksum + ONION_VERSION).decode("ascii").lower() + ".onion"',
     'return base64.b32encode(pubkey + checksum + ONION_VERSION).decode("ASCII").lower() + ".onion"'):
        'Codec names are normalised case-insensitively; this is the same codec.',
    ('vanity.read_hostname',
     'text = path.read_text(encoding="ascii").strip()',
     'text = path.read_text(encoding=None).strip()'):
        'encoding=None takes the locale encoding, which is UTF-8 here and in the image, so the outcome is identical for every input this reads.',
    ('vanity.read_hostname',
     'text = path.read_text(encoding="ascii").strip()',
     'text = path.read_text(encoding="ASCII").strip()'):
        'Codec names are normalised case-insensitively; this is the same codec.',
    ('vanity.generate',
     'proc = _run_mkp224o(prefix, tmpdir, threads, count=1)',
     'proc = _run_mkp224o(prefix, tmpdir, threads, )'):
        "_run_mkp224o's default count is 1, the value that was omitted.",
    ('vanity.generate',
     'f"mkp224o exited {proc.returncode}: {(stderr or \'\').strip()[-500:]}"',
     'f"mkp224o exited {proc.returncode}: {(stderr or \'\').strip()[-501:]}"'):
        'One character more of an already-truncated error tail.',
    ('vanity.generate',
     'archived = None',
     'archived = ""'):
        'Empty string and None are both falsy, and the value is only ever tested.',
    ('vanity._run_mkp224o',
     '',
     ''):
        'Docstring text. No code changed.',
    ('vanity.benchmark',
     'while time.monotonic() < deadline:',
     'while time.monotonic() <= deadline:'):
        'A boundary a real monotonic clock never lands on exactly.',
    ('vanity.benchmark',
     'proc.wait(timeout=5)',
     'proc.wait(timeout=6)'):
        'One second more before escalating from terminate to kill.',
    ('vanity.difficulty_table',
     'secs = attempts / rate if rate > 0 else float("inf")',
     'secs = attempts / rate if rate > 0 else float("INF")'):
        'float() parses the name case-insensitively.',
    ('vanity.build_parser',
     'ap.add_argument("--uid", type=int, default=None, help="chown output to this uid")',
     'ap.add_argument("--uid", type=int, help="chown output to this uid")'):
        "argparse's own default for an option's default is None, which is what was written.",
    ('vanity.build_parser',
     'ap.add_argument("--gid", type=int, default=None, help="chown output to this gid")',
     'ap.add_argument("--gid", type=int, help="chown output to this gid")'):
        "argparse's own default for an option's default is None, which is what was written.",
    ('vanity.main',
     'return _emit(0, True, payload, "")',
     'return _emit(0, True, payload, None)'):
        'The JSON arm of _emit serialises the payload and never reads the human text.',
    ('vanity.main',
     'return _emit(0, True, payload, "")',
     'return _emit(0, True, payload, "XXXX")'):
        'The JSON arm of _emit serialises the payload and never reads the human text.',
    ('vanity.main',
     'est = want / rate if rate > 0 else float("inf")',
     'est = want / rate if rate > 0 else float("INF")'):
        'float() parses the name case-insensitively.',
    ('vanity.main',
     'return _emit(0, False, payload, "\\n".join(out))',
     'return _emit(0, None, payload, "\\n".join(out))'):
        'None and False are both falsy, and as_json is only ever tested for truth.',
    ('vanity.main',
     'return _emit(0, False, payload, "\\n".join(out))',
     'return _emit(0, False, None, "\\n".join(out))'):
        'In human mode _emit prints the prepared text and never looks at the payload.',
}

# Mutants that really do remove a loop's exit condition. A hang IS detection, but
# it has to be a hang somebody looked at: the entry says which exit condition went
# missing, so a NEW hang cannot quietly join them.
#
# Not stale-checked, unlike ACCEPTED. Whether a given mutant lands in `timeout`
# rather than `killed` depends on how busy the machine was, so an entry that goes
# unseen for a run means nothing.
DOCUMENTED_HANGS: dict[tuple[str, str, str], str] = {
    ('entrypoint.main',
     'tor_rc = _tor_process.poll()',
     'tor_rc = None'):
        "The supervision loop exits when Tor's poll() stops returning None. Pinning "
        "it to None removes the only way out.",
    ('entrypoint.main',
     'if tor_rc is not None:',
     'if tor_rc is None:'):
        "The supervision loop leaves through the arm that runs when Tor's poll() "
        "returns an exit status. Inverting the test takes that arm while Tor is "
        "still running and never takes it once Tor is gone, so the loop has no exit. "
        "It lands in `killed` on an idle box and in `timeout` on a busy one; both are "
        "detection, and it is written here so the classification does not flap.",
    ('healthcheck._query',
     'if not chunk:',
     'if chunk:'):
        'The read loop ends on the empty chunk that means the control socket closed. '
        'Inverting it ends on the first byte instead and spins forever at EOF.',
    ('vanity._unique_archive_path',
     'n += 1',
     'n = 1'):
        'The suffix search advances until the name is free. Pinning the counter to 1 '
        'retries the same taken name forever.',
}

_MUTANT_RE = re.compile(r"^(?P<module>[A-Za-z_][\w.]*)\.(?P<name>x_.+?): (?P<status>[\w ]+)$")

# A floor, not a target. The three mutated files generated 2,166 mutants on
# 2026-09-18; anything near zero means the run did not do what it says. Deliberately
# far below the real number so ordinary edits do not trip it -- it exists to catch a
# run that collapsed, not one that shrank.
MINIMUM_MUTANTS = 1500

# The floor above is not enough on its own: drop healthcheck.py from
# paths_to_mutate and 1,784 mutants still come back, comfortably over 1,500, and
# the gate reports a clean run on code nothing mutated. So the set of modules that
# must appear in the results is written here as well.
#
# This is a deliberate second copy of pyproject's paths_to_mutate, and the point is
# that it is a copy: deleting a module from the build config is then not enough to
# make it stop being graded -- the gate fails until someone edits this line too and
# has to say why. Both directions are checked, so a module added to pyproject and
# never graded is caught as well.
EXPECTED_MODULES = frozenset({"entrypoint", "healthcheck", "vanity"})


def _configured_modules() -> frozenset[str]:
    """The module names pyproject actually points mutmut at."""
    with (ROOT / "pyproject.toml").open("rb") as fh:
        config = tomllib.load(fh)
    paths = config["tool"]["mutmut"]["paths_to_mutate"]
    return frozenset(Path(p).stem for p in paths)


TIMEOUT_BUDGET = 300
"""Seconds a single re-graded mutant gets, alone, before it is called a hang.

Measured: the slowest honest mutant in this repository finished in 59 seconds and
the three real hangs were still running at 240. 300 is well clear of both.
"""


def _tests_for(function: str) -> list[str]:
    """The tests mutmut's statistics pass mapped to this function.

    Written by `mutmut run`; a re-grade cannot be done without it, and guessing a
    test selection would re-grade against the wrong tests.
    """
    stats = MUTANTS / "mutmut-stats.json"
    if not stats.is_file():
        raise SystemExit(
            f"error: {stats} is missing, so the timeouts cannot be re-graded. "
            "Run `mutmut run` (a full pass -- it is what writes this file).")
    mapping = json.loads(stats.read_text())["tests_by_mangled_function_name"]
    return list(mapping.get(function, []))


def _regrade(full_name: str, tests: list[str]) -> str:
    """Run one mutant's own tests against a fixed budget: killed, survived or hang."""
    env = {**os.environ, "MUTANT_UNDER_TEST": full_name}
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider",
             "--", *tests],
            cwd=MUTANTS, env=env, capture_output=True, text=True,
            timeout=TIMEOUT_BUDGET, check=False)
    except subprocess.TimeoutExpired:
        return "hang"
    if proc.returncode == 0:
        return "survived"
    if proc.returncode == 1:
        return "killed"
    raise SystemExit(
        f"error: re-grading {full_name} did not run its tests (pytest exited "
        f"{proc.returncode}). The timeout is still ungraded, so this is not a "
        f"result.\n{proc.stdout[-2000:]}")


def _mutmut_results() -> list[tuple[str, str, str]]:
    """(module, mutant_name, status) for EVERY mutant, killed ones included."""
    # The console script beside the interpreter running this, so the gate reads
    # the results of the same venv's mutmut rather than whatever is on PATH.
    # `results` never touches the trampoline, so the module form is a safe
    # fallback here even though `run` is not (see the module docstring).
    console = Path(sys.executable).with_name("mutmut")
    base = [str(console)] if console.exists() else [sys.executable, "-m", "mutmut"]
    command = [*base, "results", "--all", "true"]
    proc = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, check=False, timeout=600,
    )
    out = []
    for line in proc.stdout.splitlines():
        match = _MUTANT_RE.match(line.strip())
        if match:
            out.append((match["module"], match["name"], match["status"].strip()))
    if not out:
        print("error: mutmut reported no mutants at all. Did `mutmut run` complete?\n"
              f"{proc.stderr.strip()}", file=sys.stderr)
        raise SystemExit(2)
    return out


class _Source:
    """The generated one-function-per-mutant module, parsed once."""

    def __init__(self, module: str):
        path = MUTANTS / f"{module}.py"
        self.lines = path.read_text(encoding="utf-8").splitlines()
        self.funcs = {
            node.name: node
            for node in ast.walk(ast.parse("\n".join(self.lines)))
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }

    def body(self, name: str) -> list[str]:
        node = self.funcs[name]
        # The def line differs between orig and mutant by name alone; blank it so
        # the diff is the body.
        body = self.lines[node.lineno - 1:node.end_lineno]
        return ["", *body[1:]]

    def diff(self, mutant: str) -> tuple[str, str]:
        base = mutant.rsplit("__mutmut_", 1)[0]
        orig = base + "__mutmut_orig"
        if mutant not in self.funcs or orig not in self.funcs:
            # The results and the generated tree disagree, which means one of them
            # is from a different run. Returning a placeholder would file every
            # such mutant under one allowlist key and let a stale pair look
            # accounted for -- the exact trap that wasted two runs here.
            raise SystemExit(
                f"error: {mutant} is in the results but not in mutants/. The "
                "results and the generated sources are from different runs; "
                "re-run `mutmut run` before grading.")
        removed, added = [], []
        for line in difflib.unified_diff(self.body(orig), self.body(mutant),
                                         n=0, lineterm=""):
            if line.startswith("-") and not line.startswith("---"):
                removed.append(line[1:].strip())
            elif line.startswith("+") and not line.startswith("+++"):
                added.append(line[1:].strip())
        return (" ".join(removed), " ".join(added))


def main() -> int:
    results = _mutmut_results()

    sources: dict[str, _Source] = {}
    unexplained: list[str] = []
    accepted_seen: set[tuple[str, str, str]] = set()
    timeouts: list[tuple[str, str]] = []
    regraded: dict[str, list[str]] = {"killed": [], "survived": [], "hang": []}
    undocumented_hangs: list[str] = []
    counts: dict[str, int] = {}
    incomplete: list[str] = []

    def key_for(module: str, mutant: str) -> tuple[str, str, str]:
        # NOT setdefault: its argument is evaluated every time, which re-parses a
        # 4.8 MB generated file once per mutant. Measured: the gate ran for five
        # minutes at 93% CPU and produced nothing.
        if module not in sources:
            sources[module] = _Source(module)
        function = mutant.rsplit("__mutmut_", 1)[0].removeprefix("x_")
        removed, added = sources[module].diff(mutant)
        return (f"{module}.{function}", removed, added)

    for module, mutant, status in sorted(results):
        counts[status] = counts.get(status, 0) + 1
        if status == "killed":
            continue
        if status in ("not checked", "no tests", "suspicious"):
            # "not checked": the run did not finish. "no tests": nothing exercises
            # this code, which an allowlist must never be allowed to paper over.
            incomplete.append(f"{module}.{mutant} ({status})")
            continue
        if status == "timeout":
            # Not graded here: mutmut's bound is wall clock, so this pile holds
            # hangs, kills and survivors indiscriminately. Re-run below.
            timeouts.append((module, mutant))
            continue
        key = key_for(module, mutant)
        if key in ACCEPTED:
            accepted_seen.add(key)
            continue
        _, removed, added = key
        unexplained.append(
            f"{module}.{mutant} ({status})\n"
            f"      - {removed}\n"
            f"      + {added}")

    if timeouts:
        print(f"re-grading {len(timeouts)} timeouts one at a time "
              f"({TIMEOUT_BUDGET}s each); mutmut's bound is wall clock, so this "
              "pile is not a verdict...", flush=True)
    for module, mutant in timeouts:
        key = key_for(module, mutant)
        function, removed, added = key
        # The statistics mapping is keyed by the MANGLED name -- module plus the
        # x_ function, without the mutant number.
        mangled = f"{module}.{mutant.rsplit('__mutmut_', 1)[0]}"
        tests = _tests_for(mangled)
        if not tests:
            raise SystemExit(
                f"error: no test is mapped to {mangled}, so its timeout cannot be "
                "re-graded. A mutant with no tests is not an allowlist question.")
        outcome = _regrade(f"{module}.{mutant}", tests)
        regraded[outcome].append(f"{module}.{mutant}")
        if outcome == "killed":
            counts["killed"] = counts.get("killed", 0) + 1
            counts["timeout"] -= 1
            continue
        if outcome == "hang":
            if key not in DOCUMENTED_HANGS:
                undocumented_hangs.append(
                    f"{module}.{mutant}\n      - {removed}\n      + {added}")
            continue
        counts["timeout"] -= 1
        counts["survived"] = counts.get("survived", 0) + 1
        if key in ACCEPTED:
            accepted_seen.add(key)
            continue
        unexplained.append(
            f"{module}.{mutant} (survived, re-graded from timeout)\n"
            f"      - {removed}\n"
            f"      + {added}")

    stale = sorted(set(ACCEPTED) - accepted_seen)
    killed = counts.get("killed", 0)
    total = len(results)

    graded_modules = {module for module, _, _ in results}
    configured = _configured_modules()
    ungraded = sorted(EXPECTED_MODULES - graded_modules)
    unconfigured = sorted(EXPECTED_MODULES - configured)
    unexpected = sorted(configured - EXPECTED_MODULES)

    print(f"{total} mutants: " + ", ".join(
        f"{status} {n}" for status, n in sorted(counts.items()) if n))
    if total:
        print(f"kill rate: {killed}/{total} = {100 * killed / total:.1f}%  "
              f"(explained survivors {len(accepted_seen)}, "
              f"unexplained {len(unexplained)})")

    if total < MINIMUM_MUTANTS:
        print(f"\nonly {total} mutants were graded, below the floor of "
              f"{MINIMUM_MUTANTS}. A run this small did not test what it claims to; "
              f"check that `mutmut run` completed and that pyproject's "
              f"paths_to_mutate still names every shipped module.")

    if ungraded:
        print(f"\nno mutant of {', '.join(ungraded)} was graded at all. The run "
              "covered less code than this gate claims to speak for.")
    if unconfigured:
        print(f"\npyproject's paths_to_mutate no longer names {', '.join(unconfigured)}. "
              "Restore it, or delete it from EXPECTED_MODULES here and say in the "
              "commit message why that module stopped needing to be graded.")
    if unexpected:
        print(f"\npyproject mutates {', '.join(unexpected)}, which EXPECTED_MODULES "
              "here does not list. Add it, so that dropping it later fails the gate.")

    if incomplete:
        print(f"\nNOT GRADED ({len(incomplete)}) -- the run is not a result until "
              "these are resolved:")
        # Capped: an aborted run leaves thousands of these, and a CI log that is
        # mostly one repeated line is a log nobody reads.
        for entry in incomplete[:20]:
            print(f"  {entry}")
        if len(incomplete) > 20:
            print(f"  ... and {len(incomplete) - 20} more")

    if timeouts:
        print(f"\n{len(timeouts)} mutants mutmut recorded as timeouts, re-graded "
              f"alone against {TIMEOUT_BUDGET}s: "
              f"{len(regraded['hang'])} really hang, "
              f"{len(regraded['killed'])} are killed, "
              f"{len(regraded['survived'])} survive. "
              "The counts above are after that re-grade.")
        for name in regraded["hang"]:
            print(f"  hangs (detection): {name}")

    if undocumented_hangs:
        print("\nHANGS NOBODY HAS LOOKED AT -- a hang is detection, but say which "
              "exit condition went missing by adding each to DOCUMENTED_HANGS:")
        for entry in undocumented_hangs:
            print(f"  {entry}")

    if stale:
        print("\nallowlisted but no longer surviving -- a test now kills these, so "
              "delete the entries:")
        for function, removed, added in stale:
            print(f"  {function}: {removed!r} -> {added!r}")

    if unexplained:
        print("\nUNEXPLAINED SURVIVORS -- write a test that kills each of these, or "
              "add it to ACCEPTED with the reason it cannot be killed:")
        for entry in unexplained:
            print(f"  {entry}")

    return 1 if (unexplained or stale or incomplete or ungraded
                 or unconfigured or unexpected or undocumented_hangs
                 or total < MINIMUM_MUTANTS) else 0


if __name__ == "__main__":
    sys.exit(main())
