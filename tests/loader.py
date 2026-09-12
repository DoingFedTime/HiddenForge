"""Load repo files without the bytecode cache.

Shared by the host tests. scripts/hiddenforge has no .py extension, so a
SourceFileLoader caches it at scripts/__pycache__/hiddenforgecpython-312.pyc,
and that cache is validated on the source's second-resolution mtime AND its
size. A same-second, same-size edit is therefore served from stale bytecode --
which produced a wrong answer during the acceptance test for the manifest check.

Overriding get_code to compile the source directly removes the cache (and needs
no exec() for a scanner to flag). See scripts/check_manifest.py for the same
loader on the CI side.
"""
import importlib.machinery
import importlib.util
from pathlib import Path


def repo_root(from_file) -> Path:
    """Find the repository root by walking up to the directory with scripts/hiddenforge.

    Tests must not assume they run from the repo root: mutmut copies the tree
    into `mutants/` and runs the suite there, where `Path(__file__).parent.parent`
    is `mutants/` and `mutants/scripts/hiddenforge` does not exist. That made
    every test error at setup, which is why mutation testing reported 789
    mutants and 0 checked. Walking up finds the real root in both cases.
    """
    here = Path(from_file).resolve()
    for parent in here.parents:
        if (parent / "scripts" / "hiddenforge").is_file():
            return parent
    return here.parent


class NoCacheLoader(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        return compile(self.get_source(fullname), self.path, "exec", dont_inherit=True)


def load_file(path, name):
    loader = NoCacheLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module
