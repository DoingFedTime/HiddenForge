"""scripts/bump_pins.py moves pruned pins and touches nothing else."""
import importlib.util
import pathlib
import shutil

REPO = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("bump_pins", REPO / "scripts" / "bump_pins.py")
bump = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bump)
cp = bump._load_check_pins()

DOCKERFILE = """FROM alpine:3.23.5
RUN apk add --no-cache \\
    tor=0.4.9.14-r0 \\
    python3=3.12.15-r0 \\
    openssl=3.5.9-r0 && \\
    rm -f /var/log/apk.log
"""
README = (
    "| `python3` apk | `3.12.15-r0` | runtime |\n"
    "use (`=3.12.15-r0`) and `python3=3.12.15-r0`\n"
)
INDEX = {
    "tor": ["0.4.9.14-r0", "0.4.9.15-r0"],
    "python3": ["3.12.16-r0"],
    "openssl": ["3.5.9-r0"],
}


def _tree(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "Dockerfile").write_text(DOCKERFILE)
    (tmp_path / "README.md").write_text(README)
    return tmp_path


def test_a_pruned_pin_moves_and_a_present_one_does_not(tmp_path):
    root = _tree(tmp_path)
    pins = cp.parse_pins((root / "Dockerfile").read_text())
    changes = bump.plan(pins, INDEX, cp._version_key, bump_all=False)
    assert changes == {"python3": ("3.12.15-r0", "3.12.16-r0")}
    touched = bump.apply(root, changes)
    assert "python3=3.12.16-r0" in (root / "Dockerfile").read_text()
    assert "tor=0.4.9.14-r0" in (root / "Dockerfile").read_text()
    assert touched == ["Dockerfile", "README.md"]
    readme = (root / "README.md").read_text()
    assert "3.12.15" not in readme and readme.count("3.12.16-r0") == 3


def test_all_also_moves_pins_that_still_exist(tmp_path):
    root = _tree(tmp_path)
    pins = cp.parse_pins((root / "Dockerfile").read_text())
    changes = bump.plan(pins, INDEX, cp._version_key, bump_all=True)
    assert set(changes) == {"python3", "tor"}


def test_nothing_to_do_changes_no_file(tmp_path):
    root = _tree(tmp_path)
    index = {"tor": ["0.4.9.14-r0"], "python3": ["3.12.15-r0"], "openssl": ["3.5.9-r0"]}
    pins = cp.parse_pins((root / "Dockerfile").read_text())
    assert bump.plan(pins, index, cp._version_key, bump_all=True) == {}


def test_the_shipped_dockerfile_parses_to_pins():
    assert "python3" in cp.parse_pins((REPO / "Dockerfile").read_text())
    assert shutil.which("python3")
