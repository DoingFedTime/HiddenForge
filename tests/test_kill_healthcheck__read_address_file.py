"""Pin the exact behaviour of healthcheck._read_address_file.

The function is the only thing between a hostile file in the Tor data directory
and the healthcheck: it must return at most `max_bytes` characters of ASCII
text, refuse files larger than that, refuse symlinks and FIFOs, and decode as
ASCII (so non-ASCII bytes are "no answer", not a crash).

Style follows test_healthcheck.py: load healthcheck.py through the shared
loader under the module name "healthcheck" (mutmut's trampoline depends on it).
"""
import os

import pytest

from loader import load_file, source_path

HEALTHCHECK_PATH = source_path(__file__, "healthcheck.py")


@pytest.fixture(scope="module")
def hc():
    return load_file(HEALTHCHECK_PATH, "healthcheck")


def _write(path, data):
    path.write_bytes(data)
    return str(path)


# ─────────────────────────────────────────────────────────────────────────────
# The size cap: max_bytes is readable, max_bytes + 1 is not
# ─────────────────────────────────────────────────────────────────────────────

def test_a_file_of_exactly_max_bytes_is_read_in_full(hc, tmp_path):
    """The boundary is inclusive: exactly `max_bytes` is a real answer.

    Reading only max_bytes-1 would truncate it; reading max_bytes+1 is what
    lets the next test see one byte too many and say None.
    """
    text = "a" * 32
    assert hc._read_address_file(_write(tmp_path / "f", text.encode()), 32) == text


def test_a_file_one_byte_over_max_bytes_is_refused(hc, tmp_path):
    """max_bytes+1 must be detected, not truncated to a valid-looking answer."""
    path = _write(tmp_path / "f", b"a" * 33)
    assert hc._read_address_file(path, 32) is None


def test_a_far_too_large_file_is_refused(hc, tmp_path):
    path = _write(tmp_path / "hs-uploaded", b"x" * 4096)
    assert hc._read_address_file(path, 256) is None


# ─────────────────────────────────────────────────────────────────────────────
# ASCII decoding
# ─────────────────────────────────────────────────────────────────────────────

def test_non_ascii_bytes_are_no_address(hc, tmp_path):
    """'ascii' is the codec: latin-1/utf-8 leniency would hand a bogus string
    back to the caller (bytes 0x80-0xff are not address characters)."""
    path = _write(tmp_path / "hostname", b"abc\xe9\n")
    assert hc._read_address_file(path) is None


def test_ascii_text_is_stripped(hc, tmp_path):
    path = _write(tmp_path / "hostname", b"  onion.onion \r\n")
    assert hc._read_address_file(path) == "onion.onion"


# ─────────────────────────────────────────────────────────────────────────────
# Never following, never blocking
# ─────────────────────────────────────────────────────────────────────────────

def test_a_symlink_is_refused_even_when_its_target_is_a_small_file(hc, tmp_path):
    """O_NOFOLLOW, not O_RDONLY alone: a symlink is never read through."""
    target = _write(tmp_path / "real", b"secret\n")
    link = tmp_path / "link"
    link.symlink_to(target)
    assert hc._read_address_file(str(link)) is None


def test_a_fifo_is_refused_without_blocking(hc, tmp_path):
    fifo = str(tmp_path / "hostname")
    os.mkfifo(fifo)
    assert hc._read_address_file(fifo) is None


def test_a_missing_file_is_none(hc, tmp_path):
    assert hc._read_address_file(str(tmp_path / "absent")) is None
