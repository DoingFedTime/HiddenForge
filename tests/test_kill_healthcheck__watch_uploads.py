"""Kill the surviving mutants of healthcheck.watch_uploads.

The control socket is SCRIPTED: each recv() returns exactly the chunk a test
lists. A real AF_UNIX socket may merge two sends into one read, which made the
split-line tests pass without ever splitting anything (measured: a "split"
event really arrived split in 306 of 400 runs). The clock is monkeypatched so
no test sleeps for real.

The line-length tests are deliberately shaped around how the watcher drains the
socket. The watcher is a line reader that appends every chunk and, once it has
something to parse, consumes the buffer up to the last CRLF and keeps the tail.
So an event only FAILS to be recorded when a truncated remnant of an earlier
line (junk that arrived with no CRLF) is left in the buffer ahead of it: the
merged "line" then never starts with `650`. That is what makes the 1 MiB cap
observable -- with the cap in place the junk is thrown away and the next event
parses; with the cap loosened (or removed) the junk stays and swallows it.
"""
import pytest

from loader import load_file, source_path

HEALTHCHECK_PATH = source_path(__file__, "healthcheck.py")

MIB = 1 << 20


@pytest.fixture(scope="module")
def hc():
    return load_file(HEALTHCHECK_PATH, "healthcheck")


ONION = "atdorl67o6q7anir2qm3sly4expi3ywvs2ltw3wl53zezgycohzi2zqd"
OTHER = "b" * 56


_SCRIPTS: dict[str, tuple[list, list]] = {}


class _ScriptedSocket:
    """Connects only to a path _fake_tor registered; recv() replays its chunks
    one per call, then b"" (Tor closing the connection)."""

    def __init__(self, *a, **k):
        self.chunks: list = []
        self.received: list = []

    def connect(self, path):
        if path not in _SCRIPTS:
            raise FileNotFoundError(2, "No such file or directory", path)
        chunks, self.received = _SCRIPTS[path]
        self.chunks = list(chunks)

    def sendall(self, data):
        self.received.append(data)

    def recv(self, n):
        return self.chunks.pop(0) if self.chunks else b""

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture(autouse=True)
def _scripted_control_socket(hc, monkeypatch):
    _SCRIPTS.clear()
    monkeypatch.setattr(hc.socket, "socket", _ScriptedSocket)
    yield
    _SCRIPTS.clear()


def _fake_tor(tmp_path, chunks, received=None):
    """Register a control socket that answers with `chunks`, then closes."""
    if received is None:
        received = []
    sock_path = str(tmp_path / "control.sock")
    _SCRIPTS[sock_path] = (list(chunks), received)
    return sock_path


def _events(**fields):
    """A real 650 HS_DESC UPLOADED line for each (name -> address)."""
    return {name: (f"650 HS_DESC UPLOADED {addr} UNKNOWN $AAAA\r\n").encode()
            for name, addr in fields.items()}


# ─────────────────────────────────────────────────────────────────────────────
# parsing the event stream
# ─────────────────────────────────────────────────────────────────────────────

def test_an_event_split_across_reads_is_still_recorded(hc, tmp_path):
    """Every chunk must be appended to the buffer: a 650 line delivered in three
    pieces is one event, and keeping only the latest piece loses it."""
    good = _events(one=ONION)["one"]
    out = tmp_path / "hs-uploaded"
    sock_path = _fake_tor(tmp_path, [b"250 OK\r\n", good[:10], good[10:25], good[25:]])
    assert hc.watch_uploads(str(out), sock_path, connect_timeout=5) == 0
    assert out.read_text() == f"{ONION}\n"


def test_only_the_fourth_field_is_the_uploaded_address(hc, tmp_path):
    """`650 HS_DESC UPLOADED <address> <auth> <hsdir>` -- the address is field
    3, not the address-shaped HSDir that follows it."""
    event = f"650 HS_DESC UPLOADED {ONION} UNKNOWN {OTHER}\r\n".encode()
    out = tmp_path / "hs-uploaded"
    sock_path = _fake_tor(tmp_path, [b"250 OK\r\n", event])
    assert hc.watch_uploads(str(out), sock_path, connect_timeout=5) == 0
    assert out.read_text() == f"{ONION}\n"


def test_the_shortest_uploaded_event_is_enough_to_record_an_address(hc, tmp_path):
    """Four fields (`650 HS_DESC UPLOADED <addr>`) is a real upload event, so
    it is recorded -- and an invalid fourth field records nothing."""
    short = f"650 HS_DESC UPLOADED {ONION}\r\n".encode()
    out = tmp_path / "hs-uploaded"
    (tmp_path / "a").mkdir()
    sock_path = _fake_tor(tmp_path / "a", [b"250 OK\r\n250 OK\r\n", short])
    assert hc.watch_uploads(str(out), sock_path, connect_timeout=5) == 0
    assert out.read_text() == f"{ONION}\n"

    (tmp_path / "b").mkdir()
    bad_out = tmp_path / "bad"
    bad = b"650 HS_DESC UPLOADED notanaddress-cccccccccccccccccccccccccccccccccccc\r\n"
    sock_path = _fake_tor(tmp_path / "b", [b"250 OK\r\n250 OK\r\n", bad])
    assert hc.watch_uploads(str(bad_out), sock_path, connect_timeout=5) == 0
    assert not bad_out.exists()


def test_a_non_ascii_byte_in_an_event_does_not_lose_the_stream(hc, tmp_path):
    """Events are decoded as ascii with errors='replace'; a stray byte must not
    abort the watcher before the next valid event is recorded."""
    bad = b"650 HS_DESC UPLOADED " + OTHER.encode() + b" UNKNOWN caf\xe9\r\n"
    good = _events(one=ONION)["one"]
    out = tmp_path / "hs-uploaded"
    sock_path = _fake_tor(tmp_path, [b"250 OK\r\n250 OK\r\n", bad, good])
    assert hc.watch_uploads(str(out), sock_path, connect_timeout=5) == 0
    assert out.read_text() == f"{ONION}\n{OTHER}\n"


# ─────────────────────────────────────────────────────────────────────────────
# the 1 MiB runaway-line cap
# ─────────────────────────────────────────────────────────────────────────────

def test_a_runaway_line_is_dropped_so_the_next_event_is_still_read(hc, tmp_path):
    """More than 1 MiB of junk followed by a line break is one long line that is
    skipped; the event in the next read still parses. (The 1 MiB cap itself is
    pinned in test_kill_healthcheck__leftovers.py: here the CRLF ends the junk
    line, so this input parses the same with or without the cap.)"""
    good = _events(one=ONION)["one"]
    out = tmp_path / "hs-uploaded"
    sock_path = _fake_tor(tmp_path, [
        b"250 OK\r\n", b"\r\n", b"X" * (MIB + 5000), b"\r\n", good])
    assert hc.watch_uploads(str(out), sock_path, connect_timeout=5) == 0
    assert out.read_text() == f"{ONION}\n"


def test_the_unterminated_tail_of_a_line_is_kept_not_dropped(hc, tmp_path):
    """A line still in progress must survive from one read to the next. If any
    read that terminates *something* threw the unterminated tail away (which is
    what a loosened/reset-always cap looks like), the 650 line completed by the
    next read would be lost."""
    good = _events(one=ONION)["one"]
    rc, out = _run(hc, tmp_path, [b"250 OK\r\n", b"\r\n", b"X" * 50000, b"\r\n" + good])
    assert rc == 0
    assert out.read_text() == f"{ONION}\n"


def test_a_huge_run_is_not_fatal(hc, tmp_path):
    """Several MiB of junk is thrown away continuation after continuation; the
    watcher survives and reports a clean exit when Tor closes."""
    good = _events(one=ONION)["one"]
    rc, out = _run(hc, tmp_path, [b"250 OK\r\n", b"X" * (3 * MIB), b"\r\n", good])
    assert rc == 0
    assert out.read_text() == f"{ONION}\n"


def _run(hc, tmp_path, chunks):
    """Run the watcher against a scripted socket; return (rc, output path)."""
    (tmp_path / "sock").mkdir()
    sock_path = _fake_tor(tmp_path / "sock", chunks)
    out = tmp_path / "hs-uploaded"
    return hc.watch_uploads(str(out), sock_path, connect_timeout=5), out


# ─────────────────────────────────────────────────────────────────────────────
# return codes
# ─────────────────────────────────────────────────────────────────────────────

def test_tor_closing_the_control_connection_is_a_clean_exit(hc, tmp_path):
    assert hc.watch_uploads(str(tmp_path / "out"), _fake_tor(tmp_path, [b"250 OK\r\n"]),
                            connect_timeout=5) == 0


# ─────────────────────────────────────────────────────────────────────────────
# the connect deadline
# ─────────────────────────────────────────────────────────────────────────────

def _clock(monkeypatch, hc):
    clock = [1000.0]
    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(hc.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(hc.time, "sleep", fake_sleep)
    return clock, sleeps


def test_the_deadline_is_a_budget_from_now_not_a_point_in_the_past(hc, tmp_path,
                                                                   monkeypatch):
    """The connect loop retries for connect_timeout; a deadline built with '-'
    has already expired and gives up at the first failure."""
    _clock(monkeypatch, hc)
    assert hc.watch_uploads(str(tmp_path / "out"), str(tmp_path / "none.sock"),
                            connect_timeout=3) == 2


def test_each_retry_pauses_half_a_second(hc, tmp_path, monkeypatch):
    """The retry pause is 0.5 s: long enough not to spin, short enough that a
    60 s budget buys 120 attempts rather than 40."""
    clock, sleeps = _clock(monkeypatch, hc)
    assert hc.watch_uploads(str(tmp_path / "out"), str(tmp_path / "none.sock"),
                            connect_timeout=3) == 2
    assert sleeps and set(sleeps) == {0.5}
    assert clock[0] >= 1003.0


def test_the_deadline_is_only_past_once_the_clock_moves_beyond_it(hc, tmp_path,
                                                                  monkeypatch):
    """A clock that lands exactly on the deadline still gets its last retry: the
    timeout is `>`, so a 1 s budget waits out the whole second."""
    clock, sleeps = _clock(monkeypatch, hc)
    assert hc.watch_uploads(str(tmp_path / "out"), str(tmp_path / "none.sock"),
                            connect_timeout=1) == 2
    assert clock[0] >= 1001.0
    assert len(sleeps) == 3
