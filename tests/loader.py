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


class NoCacheLoader(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        return compile(self.get_source(fullname), self.path, "exec", dont_inherit=True)


def load_file(path, name):
    loader = NoCacheLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module
