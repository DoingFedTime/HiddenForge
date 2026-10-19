"""Behavioural tests for entrypoint._read_small_regular_file.

The helper is the root-side read of the key volume. Each test pins one refusal
the operator relies on: what is refused, and the message that says why.
"""
import errno
import os

import pytest

import entrypoint as e


def test_reads_a_small_regular_file_whole(tmp_path):
    p = tmp_path / "hostname"
    p.write_bytes(b"abc\n")
    assert e._read_small_regular_file(str(p)) == b"abc\n"


def test_refuses_a_directory_as_not_a_regular_file(tmp_path):
    with pytest.raises(OSError) as ei:
        e._read_small_regular_file(str(tmp_path))
    assert ei.value.errno == errno.EINVAL
    assert f"{tmp_path} is not a regular file" in str(ei.value)


def test_refuses_a_fifo_without_blocking(tmp_path):
    p = tmp_path / "fifo"
    os.mkfifo(p)
    with pytest.raises(OSError) as ei:
        e._read_small_regular_file(str(p))
    assert ei.value.errno == errno.EINVAL
    assert f"{p} is not a regular file" in str(ei.value)


def test_a_file_of_exactly_max_bytes_is_read(tmp_path):
    p = tmp_path / "exact"
    p.write_bytes(b"x" * 8)
    assert e._read_small_regular_file(str(p), max_bytes=8) == b"x" * 8


def test_refuses_a_file_one_byte_over_max_with_its_size_in_the_message(tmp_path):
    p = tmp_path / "big"
    p.write_bytes(b"x" * 9)
    with pytest.raises(OSError) as ei:
        e._read_small_regular_file(str(p), max_bytes=8)
    assert ei.value.errno == errno.EFBIG
    assert f"{p} is larger than 8 bytes" in str(ei.value)


def test_refuses_a_planted_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_bytes(b"abc")
    link = tmp_path / "hostname"
    link.symlink_to(target)
    with pytest.raises(OSError) as ei:
        e._read_small_regular_file(str(link))
    assert ei.value.errno in (errno.ELOOP, errno.EINVAL)
