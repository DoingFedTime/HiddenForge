"""Every place that states the release version must state the same one.

A release bumps the version in several files by hand: manifest.json, the CLI's
HIDDENFORGE_VERSION, the newest CHANGELOG heading, the CHANGELOG's "latest
release" line, and the golden output of `setup`. One missed file ships an image
whose parts disagree about what they are.

Standard library only, so CI can run it without a venv:

    python3 tests/test_version_consistency.py
"""
import json
import re
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# (label, path relative to the repo root, pattern whose group 1 is the version,
#  required). The CHANGELOG "latest release" sentence is optional: if it is
#  reworded away there is nothing to drift, but if it is present it must agree.
SOURCES = (
    ("scripts/hiddenforge HIDDENFORGE_VERSION", "scripts/hiddenforge",
     r'^HIDDENFORGE_VERSION = "([^"]+)"', True),
    ("CHANGELOG.md newest heading", "CHANGELOG.md",
     r"^## \[(\d+\.\d+\.\d+)\]", True),
    ("CHANGELOG.md latest-release line", "CHANGELOG.md",
     r"latest release is \*\*(\d+\.\d+\.\d+)\*\*", False),
    ("Dockerfile image label", "Dockerfile",
     r'org\.opencontainers\.image\.version="([^"]+)"', True),
    ("tests/golden_setup/compose.service.yml header", "tests/golden_setup/compose.service.yml",
     r"\(hiddenforge v(\d+\.\d+\.\d+), contract", True),
)


def collect(root: Path) -> dict:
    """Map each source to the version it states. A required source that states
    none maps to None, which never equals a version."""
    found = {"manifest.json version": json.loads((root / "manifest.json").read_text())["version"]}
    for label, rel, pattern, required in SOURCES:
        m = re.search(pattern, (root / rel).read_text(), re.MULTILINE)
        if m:
            found[label] = m.group(1)
        elif required:
            found[label] = None
    return found


def disagreement(found: dict) -> str:
    if len(set(found.values())) == 1 and None not in found.values():
        return ""
    return "versions disagree:\n" + "\n".join(f"  {v!s:>8}  {k}" for k, v in found.items())


def _need_full_tree() -> None:
    """mutmut runs the tests from a partial copy of the tree; skip there."""
    if not (REPO / "manifest.json").exists():
        import pytest

        pytest.skip("not a full checkout")


def test_every_source_states_the_same_version():
    _need_full_tree()
    found = collect(REPO)
    assert not disagreement(found), disagreement(found)


def _copy_sources(dst: Path) -> None:
    for rel in {"manifest.json", *(s[1] for s in SOURCES)}:
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, dst / rel)


def test_a_single_stale_source_is_caught(tmp_path):
    _need_full_tree()
    _copy_sources(tmp_path)
    path = tmp_path / "scripts" / "hiddenforge"
    text = path.read_text()
    stale = re.sub(r'^(HIDDENFORGE_VERSION = ")[^"]+"', r'\g<1>0.0.0"', text,
                   count=1, flags=re.MULTILINE)
    assert stale != text
    path.write_text(stale)
    assert "0.0.0" in disagreement(collect(tmp_path))


def test_a_source_that_loses_its_version_is_caught(tmp_path):
    _need_full_tree()
    _copy_sources(tmp_path)
    path = tmp_path / "tests" / "golden_setup" / "compose.service.yml"
    path.write_text(re.sub(r"hiddenforge v\d+\.\d+\.\d+", "hiddenforge", path.read_text()))
    assert "None" in disagreement(collect(tmp_path))


if __name__ == "__main__":
    found = collect(REPO)
    problem = disagreement(found)
    if problem:
        print(problem, file=sys.stderr)
        sys.exit(1)
    print(f"version {found['manifest.json version']} agrees across {len(found)} sources")
