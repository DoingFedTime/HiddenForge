"""Static guard for a shell-precedence bug the Dockerfile shipped with.

`A && B || true && C` parses as `(A && B) || true && C`, so an `|| true` written
to tolerate one cleanup step also swallowed a --require-hashes mismatch in the
pip install before it: a corrupted hash built successfully (measured). Every
tolerated failure must be grouped -- `{ step || true; }` -- so it can only
excuse itself.
"""
import re

from loader import repo_root

DOCKERFILE = repo_root(__file__) / "Dockerfile"


def test_every_tolerated_failure_is_grouped():
    bare = []
    for n, line in enumerate(DOCKERFILE.read_text().splitlines(), 1):
        code = line.split("#", 1)[0] if line.lstrip().startswith("#") else line
        grouped = (code.strip().startswith("{")
                   and re.search(r"\|\| true;\s*\}", code) is not None)
        if "|| true" in code and not grouped:
            bare.append(f"{n}: {line.strip()}")
    assert not bare, "ungrouped `|| true` can excuse earlier steps:\n" + "\n".join(bare)
