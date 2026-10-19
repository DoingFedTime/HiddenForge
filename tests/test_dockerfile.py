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
        tolerated = re.search(r"\|\|\s*(true|:|exit 0)\b|\|\|\s*:", code)
        grouped = (code.strip().startswith("{")
                   and re.search(r"\|\|\s*(true|:|exit 0)\s*;\s*\}", code) is not None)
        if tolerated and not grouped:
            bare.append(f"{n}: {line.strip()}")
    assert not bare, "an ungrouped tolerated failure can excuse earlier steps:\n" + "\n".join(bare)


def test_cli_tor_version_matches_the_dockerfile_pin():
    """The CLI reports TOR_VERSION in `info` and manifest.json, but nothing tied it
    to the apk pin the image actually installs. When Alpine pruned 0.4.9.13 and
    the pin moved, the CLI kept advertising the old version. Read both and compare.
    """
    from loader import load_file

    pins = re.findall(r"^\s*tor=([0-9.]+)-r\d+\b", DOCKERFILE.read_text(), re.M)
    assert len(pins) == 1, f"expected exactly one tor apk pin, found {pins}"
    cli = load_file(repo_root(__file__) / "scripts" / "hiddenforge", "hf_cli_torpin")
    assert pins[0] == cli.TOR_VERSION
