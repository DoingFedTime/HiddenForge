"""Every subprocess call must be bounded or visibly justified.

Seven calls had no timeout. Most were correct by design -- vanity mining and
an interactive age prompt are *meant* to be unbounded, and the Tor/Vanguards
Popen calls are long-lived processes -- but a reader could not tell intent from
oversight. This asserts the distinction is written down at the call site, so that
the presence of neither a timeout nor a comment becomes a reviewable signal.
"""
import re

import pytest

from loader import repo_root

# This is a source-TEXT audit, so it must read the real sources, never a copy of
# the tree. mutmut runs the suite from `mutants/`, where entrypoint.py has been
# rewritten into one function-per-mutant with the call sites' justifying comments
# detached -- reading that copy fails the audit on an unmutated baseline, which
# aborts mutmut's stats phase (`-x`) and leaves every mutant with no tests to run.
# repo_root() walks up to the directory that actually holds scripts/hiddenforge.
REPO = repo_root(__file__)
FILES = [REPO / "entrypoint.py", REPO / "scripts" / "hiddenforge"]

CALL_RE = re.compile(r"subprocess\.(?:run|Popen)\(")


def _calls(text):
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if CALL_RE.search(line):
            call = "\n".join(lines[i:i + 12])
            preceding = "\n".join(lines[max(0, i - 3):i])
            yield i + 1, call, preceding


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_every_subprocess_call_is_bounded_or_justified(path):
    offenders = [
        lineno for lineno, call, preceding in _calls(path.read_text(encoding="utf-8"))
        if "timeout=" not in call and "#" not in preceding
    ]
    assert not offenders, (
        f"{path.name}: subprocess call(s) at line(s) {offenders} have neither a "
        "timeout= nor an adjacent justifying comment")


def test_the_audit_actually_finds_the_calls():
    """Guard against the check passing because the regex stopped matching."""
    total = sum(1 for p in FILES for _ in _calls(p.read_text(encoding="utf-8")))
    assert total >= 8, f"only {total} subprocess calls found; did the regex rot?"
