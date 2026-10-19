"""watch_uploads' line reassembly and failure exit, and healthcheck's --help text.

The event reader is driven through a scripted socket rather than a real one, so
each recv() returns exactly the chunk the test intends. A real socket may merge
two sends into one read, which would let a split-line test pass without ever
exercising the split.
"""
import pytest

from loader import load_file, source_path

HEALTHCHECK_PATH = source_path(__file__, "healthcheck.py")
ONION = "atdorl67o6q7anir2qm3sly4expi3ywvs2ltw3wl53zezgycohzi2zqd"
EVENT = f"650 HS_DESC UPLOADED {ONION} UNKNOWN $AAAA\r\n".encode()
HELP_TEXT = "record descriptor uploads until Tor exits (run by the entrypoint)"


@pytest.fixture
def hc():
    # The module MUST be loaded as "healthcheck": mutmut's trampoline picks the
    # mutant to run from the module's __name__, so under any other name these
    # tests silently run the original code and kill nothing.
    return load_file(HEALTHCHECK_PATH, "healthcheck")


class ScriptedSocket:
    """connect() succeeds; recv() returns the scripted chunks, then b"" (Tor gone).
    A chunk that is an exception instance is raised instead of returned."""

    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = b""

    def connect(self, path):
        return None

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        return chunk

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _run(hc, monkeypatch, tmp_path, chunks):
    sock = ScriptedSocket(chunks)
    monkeypatch.setattr(hc.socket, "socket", lambda *a, **k: sock)
    out = tmp_path / "hs-uploaded"
    rc = hc.watch_uploads(str(out), str(tmp_path / "control.sock"), connect_timeout=1)
    return rc, out


def test_an_event_line_split_across_two_reads_is_reassembled(hc, monkeypatch, tmp_path):
    """The first read ends mid-line with no CRLF. That partial line must be kept
    until the rest arrives, not discarded as junk."""
    rc, out = _run(hc, monkeypatch, tmp_path, [EVENT[:20], EVENT[20:]])
    assert rc == 0
    assert out.read_text() == f"{ONION}\n"


def test_after_an_overlong_line_is_dropped_the_next_event_still_counts(
        hc, monkeypatch, tmp_path):
    """Over 1 MiB with no CRLF is thrown away; the buffer must restart EMPTY, or
    whatever is left in it is glued to the front of the next event."""
    junk = b"x" * ((1 << 20) + 1)
    rc, out = _run(hc, monkeypatch, tmp_path, [junk, EVENT])
    assert rc == 0
    assert out.read_text() == f"{ONION}\n"


def test_a_failed_read_returns_exactly_1(hc, monkeypatch, tmp_path):
    """A control connection that breaks mid-stream is exit 1 (the entrypoint
    restarts the watcher); 0 is reserved for Tor closing it, 2 for never
    connecting."""
    rc, out = _run(hc, monkeypatch, tmp_path, [b"250 OK\r\n", OSError("reset")])
    assert rc == 1
    assert not out.exists()


def test_the_help_text_says_what_watch_uploads_does(hc, capsys):
    """Matched as a whole phrase between spaces, so a mangled sentence (extra
    characters glued to either end) does not pass as the same text."""
    with pytest.raises(SystemExit):
        hc.main(["--help"])
    words = " " + " ".join(capsys.readouterr().out.split()) + " "
    assert f" {HELP_TEXT} " in words


def test_the_junk_cap_applies_above_one_mebibyte_not_at_it(hc, monkeypatch, tmp_path):
    """The cap is "more than 1 MiB without a line break". A buffer of exactly
    1 MiB is still kept, so whatever arrives next is part of that same line and
    is not an event; one byte more and it is dropped, and the next event counts."""
    at_cap = b"x" * (1 << 20)
    rc, out = _run(hc, monkeypatch, tmp_path, [at_cap, EVENT])
    assert rc == 0
    assert not out.exists()


def test_a_big_read_that_ends_a_line_is_parsed_not_dropped(hc, monkeypatch, tmp_path):
    """The over-long rule is "more than 1 MiB AND no line break". One read that
    brings more than 1 MiB but does contain CRLF is ordinary input: the long
    line is skipped and the event after it is recorded."""
    big = b"x" * ((1 << 20) + 1) + b"\r\n" + EVENT
    rc, out = _run(hc, monkeypatch, tmp_path, [big])
    assert rc == 0
    assert out.read_text() == f"{ONION}\n"
