"""The --watch-uploads switch in healthcheck.main.

The entrypoint starts the upload recorder as `healthcheck.py --watch-uploads`,
with no value, so the option must be a valueless switch. (Its --help text is
pinned in test_kill_healthcheck__leftovers.py.)
"""
import pytest

from loader import load_file, source_path

HEALTHCHECK_PATH = source_path(__file__, "healthcheck.py")


@pytest.fixture
def hc():
    return load_file(HEALTHCHECK_PATH, "healthcheck_main_flag")


def test_watch_uploads_is_a_valueless_flag(hc, monkeypatch, capsys):
    """An option that takes a value would make the entrypoint's bare
    `--watch-uploads` a usage error, and the recorder would never start."""
    called = []
    monkeypatch.setattr(hc, "watch_uploads", lambda *a, **k: called.append(True) or 0)
    assert hc.main(["--watch-uploads"]) == 0
    assert called == [True]
    assert capsys.readouterr().out == ""
