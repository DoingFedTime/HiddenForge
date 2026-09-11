"""Host unit tests for vanity.py (the in-image generator wrapper).

The end-to-end generation path is covered by tests/test_e2e_live.py (needs the
image and the vendored mkp224o). Everything here is the pure logic: address
derivation, Tor key-file parsing, the honest difficulty table, and file modes.
"""
import importlib.machinery
import importlib.util
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
VANITY_PATH = REPO / "vanity.py"

VECTOR_PUB_HEX = "04c6e8afdf77a1f03511d419b92f1c25de8de2d596973b6ecbeef24c9b0271f2"
VECTOR_ONION = "atdorl67o6q7anir2qm3sly4expi3ywvs2ltw3wl53zezgycohzi2zqd.onion"
PUBLIC_TAG = b"== ed25519v1-public: type0 =="


def _load(path: Path, name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def v():
    return _load(VANITY_PATH, "hf_vanity_unit")


def test_derive_onion_matches_mkp224o_vector(v):
    assert v.derive_onion(bytes.fromhex(VECTOR_PUB_HEX)) == VECTOR_ONION


def test_read_public_key_tagged(v, tmp_path):
    p = tmp_path / "pub"
    p.write_bytes(PUBLIC_TAG.ljust(32, b"\x00") + bytes.fromhex(VECTOR_PUB_HEX))
    assert v.read_public_key(p) == bytes.fromhex(VECTOR_PUB_HEX)


def test_read_public_key_bare(v, tmp_path):
    p = tmp_path / "pub"
    p.write_bytes(bytes.fromhex(VECTOR_PUB_HEX))
    assert v.read_public_key(p) == bytes.fromhex(VECTOR_PUB_HEX)


def test_read_public_key_rejects_garbage(v, tmp_path):
    p = tmp_path / "pub"
    p.write_bytes(b"x" * 10)
    with pytest.raises(ValueError):
        v.read_public_key(p)


def test_read_hostname_accepts_valid(v, tmp_path):
    p = tmp_path / "hostname"
    p.write_text(VECTOR_ONION + "\n")
    assert v.read_hostname(p) == VECTOR_ONION


@pytest.mark.parametrize("bad", ["", "notanonion", "a" * 56, VECTOR_ONION.replace(".onion", "")])
def test_read_hostname_rejects_bad(v, tmp_path, bad):
    p = tmp_path / "hostname"
    p.write_text(bad)
    assert v.read_hostname(p) is None


def test_difficulty_table_is_honest(v):
    table = v.difficulty_table(1_000_000.0, max_len=4)
    assert [r["prefix_len"] for r in table] == [1, 2, 3, 4]
    assert [r["average_attempts"] for r in table] == [32, 1024, 32768, 1048576]
    # expected_seconds == attempts / rate
    assert table[0]["estimated_seconds"] == pytest.approx(32 / 1_000_000)
    # Monotonically harder.
    secs = [r["estimated_seconds"] for r in table]
    assert secs == sorted(secs)


def test_human_duration_units(v):
    assert v.human_duration(0.5) == "<1s"
    assert v.human_duration(30) == "30s"
    assert v.human_duration(90) == "1.5m"
    assert v.human_duration(7200) == "2.0h"
    assert v.human_duration(86400 * 2) == "2.0d"


def test_rate_parser_reads_calc_per_sec(v):
    line = (">calc/sec:8315840.805724, succ/sec:0.000000, rest/sec:19.904261, "
            "elapsed:0.100481sec")
    assert v._rate_from_stats_line(line) == pytest.approx(8315840.805724)
    assert v._rate_from_stats_line("no stats here") is None


def test_validate_prefix_rejects_invalid_base32(v):
    # 0,1,8,9 are not in the base32 alphabet.
    for bad in ("a0", "a1", "a8", "a9", "A", "a" * 13, "", "a b"):
        assert not v.PREFIX_RE.fullmatch(bad), bad
    for good in ("a", "abc", "abcdefg", "a2b3c4d"):
        assert v.PREFIX_RE.fullmatch(good), good


def test_harden_sets_tor_file_modes(v, tmp_path):
    d = tmp_path / "svc"
    d.mkdir()
    (d / "hostname").write_text(VECTOR_ONION + "\n")
    (d / "hs_ed25519_public_key").write_bytes(b"\x00" * 64)
    (d / "hs_ed25519_secret_key").write_bytes(b"\x00" * 96)
    v._harden(d, None, None)
    assert os.stat(d).st_mode & 0o777 == 0o700
    assert os.stat(d / "hs_ed25519_secret_key").st_mode & 0o777 == 0o600
    assert os.stat(d / "hs_ed25519_public_key").st_mode & 0o777 == 0o600
    assert os.stat(d / "hostname").st_mode & 0o777 == 0o644


def test_onion_regex_rejects_wrong_length(v):
    assert v.ONION_RE.fullmatch(VECTOR_ONION)
    assert not v.ONION_RE.fullmatch(VECTOR_ONION[:-1])
    assert not v.ONION_RE.fullmatch(VECTOR_ONION.upper())
