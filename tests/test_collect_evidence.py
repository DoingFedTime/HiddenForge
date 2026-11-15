"""scripts/collect_evidence.py: the bundle is published, so it must not carry the
build machine's layout or identity."""

from __future__ import annotations

import getpass
import importlib.util
import socket
import sys
from pathlib import Path

import pytest

from loader import repo_root

SCRIPT = repo_root(__file__) / "scripts" / "collect_evidence.py"


@pytest.fixture(scope="module")
def ce():
    spec = importlib.util.spec_from_file_location("collect_evidence", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_the_repository_path_and_home_are_replaced(ce):
    text = f"{ce.REPO}/hiddenforge-rs/Cargo.toml {Path.home()}/.cargo/bin/cargo"
    assert ce._scrub(text) == "<repo>/hiddenforge-rs/Cargo.toml <home>/.cargo/bin/cargo"


def test_the_user_name_is_removed_from_paths_but_not_from_words(ce):
    user = getpass.getuser()
    out = ce._scrub(f"/tmp/user/1000/pytest-of-{user}/pytest-1/a /srv/{user}/x")  # noqa: S108
    assert out == "/tmp/user/<uid>/pytest-of-user/pytest-1/a /srv/user/x"  # noqa: S108
    # An ordinary word that merely contains the user name is left alone.
    assert ce._scrub(f"an {user}ple word, {user}-less") == f"an {user}ple word, {user}-less"


def test_the_host_name_is_replaced(ce):
    host = socket.gethostname()
    if len(host) < 2:
        pytest.skip("no usable host name")
    assert ce._scrub(f"running on {host} now") == "running on <host> now"


def test_text_without_any_of_it_is_unchanged(ce):
    text = "tests/test_cli.py::test_x PASSED [100%]\n$ cargo test --release --locked\n"
    assert ce._scrub(text) == text


def test_the_bundle_records_the_index_digest_of_the_built_archive(ce, tmp_path):
    """A release is signed before it is pushed, so the registry lookup returned
    None and build.json carried no digest at all."""
    import io
    import json
    import tarfile
    mod = ce
    archive = tmp_path / "out.tar"
    index = json.dumps({"manifests": [{"digest": "sha256:" + "ab" * 32}]}).encode()
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo("index.json")
        info.size = len(index)
        tar.addfile(info, io.BytesIO(index))
    out = tmp_path / "ev"
    out.mkdir()
    assert mod._archive_digest(str(archive), out) == "sha256:" + "ab" * 32
    assert "sha256:" + "ab" * 32 in (out / "image-digest.txt").read_text()
