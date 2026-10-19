"""Pin how the uploaded-descriptor list is read and split into addresses.

Two properties matter to an operator: the size cap actually reaches
_read_address_file (a file bigger than the cap must make the probe report the
service as NOT uploaded rather than trust a truncated prefix), and only
whole-line addresses count (an address glued to other text on the same line is
not an address Tor wrote).
"""
import random
import string

import pytest

from loader import load_file, source_path

# source_path, not repo_root: healthcheck.py is mutated in place under mutants/.
HEALTHCHECK_PATH = source_path(__file__, "healthcheck.py")

ONION = "atdorl67o6q7anir2qm3sly4expi3ywvs2ltw3wl53zezgycohzi2zqd"
OTHER = "b" * 56


@pytest.fixture(scope="module")
def hc():
    return load_file(HEALTHCHECK_PATH, "healthcheck")


def _records_cap(hc):
    """Spy on _read_address_file so the size cap passed to it is visible.

    Needed because os.read may return fewer bytes than requested (it does on a
    sparse tmpfs file at exactly the cap), so the result alone does not always
    reveal whether the cap or the address filter emptied the set."""
    calls = []
    real = hc._read_address_file

    def spy(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    return real, spy, calls


def test_a_uploads_file_over_the_size_cap_is_nothing_uploaded(hc, tmp_path):
    """The cap is passed through: a 200 KiB uploads file exceeds
    UPLOADS_MAX_BYTES and _read_address_file answers None, so no address is
    believed uploaded. Dropping the cap argument makes the read succeed."""
    path = tmp_path / "hs-uploaded"
    # Random ASCII, no newlines: a truncated prefix cannot accidentally contain
    # an address, so only the cap determines the answer.
    body = "".join(random.Random(1234).choice(string.ascii_letters)  # noqa: S311 (filler text, not a secret)
                   for _ in range(200000))
    path.write_text(ONION + "\n" + body + "\n")
    assert path.stat().st_size > hc.UPLOADS_MAX_BYTES
    real, spy, calls = _records_cap(hc)
    hc._read_address_file = spy
    try:
        assert hc._uploaded_addresses(str(path)) == set()
    finally:
        hc._read_address_file = real
    assert calls, "the uploads file must be read"
    assert calls[0][1] == hc.UPLOADS_MAX_BYTES


def test_an_address_sharing_a_line_with_junk_is_not_counted(hc, tmp_path):
    """Split on newlines only: whitespace-separated tokens inside a line are one
    line, and that line does not fullmatch an address."""
    path = tmp_path / "hs-uploaded"
    path.write_text(f"junk {ONION}\n{OTHER}\t{ONION}\n{ONION}\n")
    assert hc._uploaded_addresses(str(path)) == {ONION}


def test_one_address_per_line_is_read_including_surrounding_lines(hc, tmp_path):
    path = tmp_path / "hs-uploaded"
    path.write_text(f"{ONION}\nbogus\n{OTHER}\n")
    assert hc._uploaded_addresses(str(path)) == {ONION, OTHER}
