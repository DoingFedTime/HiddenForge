"""The probe that decides whether an onion service is reachable.

healthcheck.py is what the container's HEALTHCHECK runs, what `hiddenforge
status` reports, and -- since the publication gate was added -- the only thing
standing between a dead service and a published .onion address that no client
can reach. It had no unit tests at all.

The failure it exists to catch is specific and was observed live: a container at
bootstrap 100%, with `circuit-established=1` and a valid hostname file, whose
onion-service circuits could not build. Every obvious check passed; a fetch over
real Tor returned SOCKS reply 6. The signal that separated the two was
established introduction circuits, so most of what follows is about parsing that
one control-port reply exactly, including the cases where a wrong parse would
INVENT circuits that are not there.

The control socket is real here: the tests speak Tor's protocol back over an
AF_UNIX socket rather than stubbing the function that reads it.
"""
import json
import os
import socket
import threading
import time

import pytest

from loader import load_file, source_path

# source_path, not repo_root: healthcheck.py is mutated in place under mutants/,
# and loading the original from the real repository root would report every one
# of its mutants as survived.
HEALTHCHECK_PATH = source_path(__file__, "healthcheck.py")


@pytest.fixture(scope="module")
def hc():
    # The module name is load-bearing under mutation testing: mutmut's trampoline
    # activates a mutant only when `orig.__module__` matches the name in
    # MUTANT_UNDER_TEST, so loading this as anything but "healthcheck" would run
    # the original body for every mutant and report the file as fully covered.
    return load_file(HEALTHCHECK_PATH, "healthcheck")


ONION = "atdorl67o6q7anir2qm3sly4expi3ywvs2ltw3wl53zezgycohzi2zqd"
OTHER = "b" * 56


def _intro_line(cid, addr, state="HSSI_ESTABLISHED", purpose="HS_SERVICE_INTRO"):
    return (f"{cid} BUILT $AAAA~guard,$BBBB~middle,$CCCC~intro "
            f"PURPOSE={purpose} HS_STATE={state} REND_QUERY={addr} "
            f"TIME_CREATED=2026-09-18T00:00:00.000000")


def _circuit_status(*lines):
    body = "".join(f"{line}\r\n" for line in lines)
    return ("250 OK\r\n"
            "250-status/circuit-established=1\r\n"
            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n"
            "250+circuit-status=\r\n"
            f"{body}"
            ".\r\n"
            "250 OK\r\n"
            "250 closing connection\r\n").encode()


# ─────────────────────────────────────────────────────────────────────────────
# _circuit_status_lines -- scope the parse to ONE reply
# ─────────────────────────────────────────────────────────────────────────────

def test_only_the_circuit_status_body_is_parsed(hc):
    """One control connection carries several replies back to back. Scanning the
    whole buffer lets any other reply's text be counted as a circuit if it
    happens to contain the right substrings."""
    resp = _circuit_status(_intro_line("7", ONION))
    assert hc._circuit_status_lines(resp) == [_intro_line("7", ONION)]


def test_a_reply_with_no_circuit_status_yields_nothing(hc):
    assert hc._circuit_status_lines(b"250 OK\r\n250 closing connection\r\n") == []


def test_a_body_that_never_terminates_yields_nothing_not_a_partial_count(hc):
    """A truncated reply is a failure to evaluate, not a low circuit count.
    Returning the lines seen so far would report a healthy service as unreachable
    the moment the read was short."""
    truncated = ("250+circuit-status=\r\n"
                 + _intro_line("7", ONION) + "\r\n").encode()
    assert hc._circuit_status_lines(truncated) == []


def test_a_dot_stuffed_body_line_is_unescaped(hc):
    """Tor dot-stuffs a body line that would otherwise start with a period."""
    resp = (b"250+circuit-status=\r\n"
            b"..leading dot\r\n"
            b"normal\r\n"
            b".\r\n")
    assert hc._circuit_status_lines(resp) == [".leading dot", "normal"]


def test_the_terminator_ends_the_body(hc):
    resp = (b"250+circuit-status=\r\n"
            b"one\r\n"
            b".\r\n"
            b"250 OK\r\n"
            b"two\r\n")
    assert hc._circuit_status_lines(resp) == ["one"]


# ─────────────────────────────────────────────────────────────────────────────
# _intro_points -- what counts as an introduction circuit
# ─────────────────────────────────────────────────────────────────────────────

def test_established_intro_circuits_are_counted_per_service(hc):
    """Per service, not in total: a bare total is satisfied by one healthy
    service holding every circuit while a second one has none."""
    resp = _circuit_status(
        _intro_line("1", ONION),
        _intro_line("2", ONION),
        _intro_line("3", OTHER),
    )
    assert hc._intro_points(resp) == {ONION: 2, OTHER: 1}


def test_a_circuit_that_is_built_but_not_established_does_not_count(hc):
    """HSSI_ESTABLISHED means the introduction point accepted ESTABLISH_INTRO and
    is willing to introduce clients. A circuit still CONNECTING or INTRO_SENT
    cannot yet receive an introduction, so counting it claims reachability the
    service does not have."""
    for state in ("HSSI_CONNECTING", "HSSI_INTRO_SENT"):
        resp = _circuit_status(_intro_line("1", ONION, state=state))
        assert hc._intro_points(resp) == {}, state


def test_other_circuit_purposes_do_not_count(hc):
    """A general client circuit, or an HSDIR circuit, is not an introduction
    point. HSDIR circuits in particular are torn down after the upload, so a
    healthy long-running service shows none of them."""
    for purpose in ("GENERAL", "HS_SERVICE_HSDIR", "HS_CLIENT_INTRO", "CONFLUX_LINKED"):
        resp = _circuit_status(_intro_line("1", ONION, purpose=purpose))
        assert hc._intro_points(resp) == {}, purpose


def test_the_same_circuit_is_counted_once(hc):
    """An inflated count is not evidence of anything."""
    line = _intro_line("9", ONION)
    assert hc._intro_points(_circuit_status(line, line)) == {ONION: 1}


def test_a_line_without_a_rend_query_is_not_attributed_to_anything(hc):
    resp = _circuit_status("5 BUILT $A~g PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED")
    assert hc._intro_points(resp) == {}


def test_a_rend_query_must_be_a_full_v3_address(hc):
    """The address is the key the count is looked up by; a partial match would
    file a circuit under a service that does not exist."""
    assert hc._intro_points(_circuit_status(_intro_line("1", "a" * 55))) == {}
    assert hc._intro_points(_circuit_status(_intro_line("1", "a" * 57))) == {}


def test_the_trigger_text_in_another_reply_invents_no_circuits(hc):
    """The whole reason the parse is scoped to one reply's body."""
    resp = (b"250-status/bootstrap-phase=NOTICE PURPOSE=HS_SERVICE_INTRO "
            b"HS_STATE=HSSI_ESTABLISHED REND_QUERY=" + ONION.encode() + b"\r\n"
            b"250 closing connection\r\n")
    assert hc._intro_points(resp) == {}


# ─────────────────────────────────────────────────────────────────────────────
# _hidden_service_dirs
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def torrc(tmp_path, monkeypatch, hc):
    path = tmp_path / "torrc"
    monkeypatch.setattr(hc, "TORRC", str(path))
    return path


def test_service_dirs_come_from_the_running_config(hc, torrc):
    """Read from the torrc, not the environment: the entrypoint is the only thing
    that turns *_TOR_SERVICE_HOSTS into directories, and it drops the ones it
    refused."""
    torrc.write_text(
        "SocksPort 0\n"
        "HiddenServiceDir     /var/lib/tor/hidden_service/app\n"
        "HiddenServicePort 80 127.0.0.1:8080\n"
        "HiddenServiceDir /var/lib/tor/hidden_service/web\n")
    assert hc._hidden_service_dirs() == ["/var/lib/tor/hidden_service/app",
                                         "/var/lib/tor/hidden_service/web"]


def test_duplicate_service_dirs_are_collapsed_in_order(hc, torrc):
    torrc.write_text("HiddenServiceDir /a\nHiddenServiceDir /b\nHiddenServiceDir /a\n")
    assert hc._hidden_service_dirs() == ["/a", "/b"]


def test_a_missing_torrc_is_unknown_not_no_services(hc, torrc):
    """An unreadable config says nothing about the services; reading it as "none"
    let every per-service check pass vacuously."""
    assert hc._hidden_service_dirs() is None


def test_a_directive_mentioned_in_a_comment_is_not_a_service(hc, torrc):
    """The generated torrc carries long explanatory comments; one that spelled out
    a directive would otherwise be indistinguishable from a real config line."""
    torrc.write_text("# HiddenServiceDir /not/a/service\nHiddenServiceDir /real\n")
    assert hc._hidden_service_dirs() == ["/real"]


# ─────────────────────────────────────────────────────────────────────────────
# _published_state
# ─────────────────────────────────────────────────────────────────────────────

def _hs(tmp_path, name, hostname):
    d = tmp_path / name
    d.mkdir(parents=True)
    if hostname is not None:
        d.joinpath("hostname").write_bytes(
            hostname if isinstance(hostname, bytes) else hostname.encode())
    return str(d)


def test_a_valid_hostname_file_is_published(hc, tmp_path):
    ok, details = hc._published_state([_hs(tmp_path, "app", ONION + ".onion\n")])
    assert ok is True
    assert details == [{"name": "app", "address": ONION + ".onion", "published": True}]


def test_a_missing_hostname_file_is_not_published(hc, tmp_path):
    ok, details = hc._published_state([_hs(tmp_path, "app", None)])
    assert ok is False
    assert details[0]["address"] is None


@pytest.mark.parametrize("content", [
    "not-an-onion\n",
    ONION[:-1] + ".onion\n",                 # too short
    "evil" + ONION + ".onion\n",             # prefixed
    ONION + ".onion.evil.com\n",             # suffixed
    b"\xff" + ONION.encode() + b".onion\n",  # not ASCII
    "\n",
])
def test_a_hostname_that_is_not_exactly_an_address_is_not_published(hc, tmp_path, content):
    """Anchored, and strict ASCII. An address reported here is copied into the key
    volume and handed to users."""
    ok, details = hc._published_state([_hs(tmp_path, "app", content)])
    assert ok is False
    assert details[0]["address"] is None


def test_one_unpublished_service_makes_the_whole_container_unpublished(hc, tmp_path):
    dirs = [_hs(tmp_path, "good", ONION + ".onion\n"), _hs(tmp_path, "bad", None)]
    ok, details = hc._published_state(dirs)
    assert ok is False
    assert [d["published"] for d in details] == [True, False]


def test_no_services_configured_is_not_published(hc):
    """Not vacuously true: a container with no onion service publishes nothing,
    and a status document saying "published" there would mislead anyone reading
    the field rather than the verdict."""
    assert hc._published_state([]) == (False, [])


# ─────────────────────────────────────────────────────────────────────────────
# _vanguards_running
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def procfs(tmp_path, monkeypatch, hc):
    root = tmp_path / "proc"
    root.mkdir()

    def add(pid, cmdline):
        d = root / str(pid)
        d.mkdir()
        d.joinpath("cmdline").write_bytes(cmdline)

    monkeypatch.setattr(hc, "PROC_ROOT", str(root))
    add.root = root
    return add


def test_vanguards_is_found_by_its_binary_path(hc, procfs):
    """The addon is exec'd through su-exec, so the parent is a shell-less wrapper
    and the binary path is what identifies it."""
    procfs(1, b"/usr/bin/python3\x00/entrypoint.py\x00")
    procfs(42, hc.VANGUARDS_BIN.encode() + b"\x00--control_socket\x00/x\x00")
    assert hc._vanguards_running() is True


def test_a_container_without_vanguards_says_so(hc, procfs):
    """Losing bandguards and rendguard -- both of which exist to detect an attack
    in progress -- is otherwise invisible: the entrypoint's warning goes to a
    stdout the shipped compose file discards."""
    procfs(1, b"/usr/bin/python3\x00/entrypoint.py\x00")
    procfs(99, b"tor\x00-f\x00/etc/tor/torrc\x00")
    assert hc._vanguards_running() is False


def test_non_numeric_proc_entries_are_skipped(hc, procfs):
    (procfs.root / "sys").mkdir()
    (procfs.root / "self").mkdir()
    procfs(7, hc.VANGUARDS_BIN.encode())
    assert hc._vanguards_running() is True


def test_a_process_that_exits_mid_scan_does_not_abort_the_scan(hc, procfs):
    (procfs.root / "1234").mkdir()          # no cmdline: reads as ENOENT
    procfs(7, hc.VANGUARDS_BIN.encode())
    assert hc._vanguards_running() is True


def test_an_unreadable_proc_is_not_a_running_vanguards(hc, monkeypatch):
    monkeypatch.setattr(hc, "PROC_ROOT", "/nonexistent")
    assert hc._vanguards_running() is False


# ─────────────────────────────────────────────────────────────────────────────
# _query -- against a real control socket
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def control_socket(tmp_path, monkeypatch, hc):
    """A real AF_UNIX server that replays a scripted reply."""
    path = tmp_path / "control.sock"
    monkeypatch.setattr(hc, "CONTROL_SOCKET", str(path))
    state = {"request": None, "thread": None}

    def serve(reply, close_early=False):
        server = socket.socket(socket.AF_UNIX)
        server.bind(str(path))
        server.listen(1)

        def run():
            conn, _ = server.accept()
            with conn:
                state["request"] = conn.recv(65536)
                if close_early:
                    return
                try:
                    for i in range(0, len(reply), 7):   # dribble it out in fragments
                        conn.sendall(reply[i:i + 7])
                except BrokenPipeError:
                    # The client stops reading the moment it sees the reply to
                    # QUIT, which can leave a few trailing bytes unsent. Real Tor
                    # closes its side there too.
                    pass
            server.close()

        state["thread"] = threading.Thread(target=run, daemon=True)
        state["thread"].start()
        return state

    yield serve
    if state["thread"]:
        state["thread"].join(timeout=5)


def test_the_query_authenticates_and_asks_for_all_four_facts(hc, control_socket):
    state = control_socket(_circuit_status(_intro_line("1", ONION)))
    resp = hc._query()
    request = state["request"]
    assert request.startswith(b"AUTHENTICATE\r\n")
    for wanted in (b"status/circuit-established", b"status/bootstrap-phase",
                   b"circuit-status"):
        assert wanted in request
    assert request.endswith(b"QUIT\r\n")
    assert hc._reply_complete(resp)


def test_the_query_reads_until_the_reply_to_quit_not_until_a_pause(hc, control_socket):
    """circuit-status grows with the circuit count and arrives in fragments.
    Stopping on the first short read would truncate it and undercount
    introduction circuits -- which reads as 'unreachable' on a healthy service."""
    lines = [_intro_line(str(i), ONION) for i in range(40)]
    control_socket(_circuit_status(*lines))
    resp = hc._query()
    assert hc._reply_complete(resp)
    assert hc._intro_points(resp) == {ONION: 40}


def test_a_connection_closed_early_is_an_incomplete_reply(hc, control_socket):
    control_socket(b"", close_early=True)
    assert hc._reply_complete(hc._query()) is False


def test_a_missing_control_socket_raises_for_the_caller_to_report(hc, tmp_path, monkeypatch):
    monkeypatch.setattr(hc, "CONTROL_SOCKET", str(tmp_path / "nope.sock"))
    with pytest.raises(OSError):
        hc._query()


# ─────────────────────────────────────────────────────────────────────────────
# evaluate -- the verdict
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def world(monkeypatch, hc, tmp_path):
    """Drive evaluate() with a scripted control reply and on-disk services."""
    def setup(reply, services=(), vanguards=True, uploaded=None):
        """`uploaded` defaults to every service's address: a healthy service's
        descriptor is on the network. Pass a set to say otherwise."""
        dirs = []
        for name, hostname in services:
            dirs.append(_hs(tmp_path, name, hostname))
        if uploaded is None:
            uploaded = set()
            for _name, hostname in services:
                text = hostname.decode("ascii", "replace") if isinstance(hostname, bytes) \
                    else (hostname or "")
                uploaded.add(text.strip().removesuffix(".onion"))
        monkeypatch.setattr(hc, "_query", lambda: reply)
        monkeypatch.setattr(hc, "_hidden_service_dirs", lambda: dirs)
        monkeypatch.setattr(hc, "_vanguards_running", lambda: vanguards)
        monkeypatch.setattr(hc, "_uploaded_addresses", lambda path=None: set(uploaded))
        return dirs

    return setup


def test_no_configured_service_is_never_ready(hc, world):
    """Measured: a backend that did not resolve at boot left Tor with no onion
    service; bootstrap, circuits and Vanguards were all fine and the container
    reported ready and healthy while serving nothing."""
    world(_circuit_status(*[_intro_line(str(i), ONION) for i in range(3)]),
          services=[])
    rc, doc = hc.evaluate()
    assert rc == 1
    assert doc["ready"] is False
    assert doc["hidden_service_published"] is False
    assert doc["hidden_service_reachable"] is False
    assert "no onion service is configured" in doc["reason"]


def test_an_unreadable_torrc_cannot_be_evaluated(hc, world, monkeypatch):
    world(_circuit_status(*[_intro_line(str(i), ONION) for i in range(3)]),
          services=[("app", ONION + ".onion\n")])
    monkeypatch.setattr(hc, "_hidden_service_dirs", lambda: None)
    rc, doc = hc.evaluate()
    assert rc == 2
    assert doc["ready"] is False
    assert "cannot read" in doc["reason"]


def test_a_healthy_container_is_ready(hc, world):
    world(_circuit_status(*[_intro_line(str(i), ONION) for i in range(3)]),
          services=[("app", ONION + ".onion\n")])
    rc, doc = hc.evaluate()
    assert rc == 0
    assert doc["ready"] is True
    assert doc["reason"] is None
    assert doc["services"][0]["intro_points"] == 3


def test_a_published_address_with_no_intro_points_is_not_ready(hc, world):
    """THE case this file exists for. Bootstrap 100%, circuit established, a
    valid hostname file -- and no client can reach it."""
    world(_circuit_status(), services=[("app", ONION + ".onion\n")])
    rc, doc = hc.evaluate()
    assert rc == 1
    assert doc["tor_bootstrapped"] is True
    assert doc["circuit_established"] is True
    assert doc["hidden_service_published"] is True
    assert doc["hidden_service_reachable"] is False
    assert "app" in doc["reason"]
    assert "NOT reachable" in doc["reason"]


def test_one_unreachable_service_is_not_hidden_by_a_healthy_sibling(hc, world):
    world(_circuit_status(*[_intro_line(str(i), ONION) for i in range(3)]),
          services=[("good", ONION + ".onion\n"), ("bad", OTHER + ".onion\n")])
    rc, doc = hc.evaluate()
    assert rc == 1
    assert doc["hidden_service_reachable"] is False
    assert "bad" in doc["reason"]
    assert "good" not in doc["reason"]


def test_an_unfinished_bootstrap_is_reported_first(hc, world):
    world(b"250-status/circuit-established=0\r\n"
          b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=45 TAG=conn\r\n"
          b"250 closing connection\r\n",
          services=[("app", ONION + ".onion\n")])
    rc, doc = hc.evaluate()
    assert rc == 1
    assert doc["reason"] == "bootstrap not at 100%"


def test_no_circuit_yet_is_reported_after_bootstrap(hc, world):
    world(b"250-status/circuit-established=0\r\n"
          b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n"
          b"250 closing connection\r\n",
          services=[("app", ONION + ".onion\n")])
    _rc, doc = hc.evaluate()
    assert doc["reason"] == "no circuit established yet"


def test_an_unpublished_service_names_itself(hc, world):
    world(_circuit_status(), services=[("app", None)])
    rc, doc = hc.evaluate()
    assert rc == 1
    assert "app" in doc["reason"]
    assert "not published yet" in doc["reason"]


def test_a_serving_container_without_vanguards_is_not_ready(hc, world):
    """Health status is the one channel that survives `logging: driver: none`."""
    world(_circuit_status(*[_intro_line(str(i), ONION) for i in range(3)]),
          services=[("app", ONION + ".onion\n")], vanguards=False)
    rc, doc = hc.evaluate()
    assert rc == 1
    assert doc["hidden_service_reachable"] is True
    assert "Vanguards addon is NOT running" in doc["reason"]


def test_an_unreachable_control_socket_cannot_evaluate(hc, monkeypatch):
    """Exit 2, not 1: "I could not tell" is not "the service is down"."""
    def boom():
        raise OSError("no socket")

    monkeypatch.setattr(hc, "_query", boom)
    rc, doc = hc.evaluate()
    assert rc == 2
    assert doc["ready"] is False
    assert "cannot reach control socket" in doc["reason"]


def test_a_truncated_reply_cannot_evaluate(hc, world):
    """Without the terminator the circuit count would be zero, which would report
    a healthy service as unreachable. Refuse instead."""
    world(b"250-status/circuit-established=1\r\n250+circuit-status=\r\n",
          services=[("app", ONION + ".onion\n")])
    rc, doc = hc.evaluate()
    assert rc == 2
    assert "truncated" in doc["reason"]
    assert "not a statement that the service is down" in doc["reason"]


# ─────────────────────────────────────────────────────────────────────────────
# main -- the two output modes
# ─────────────────────────────────────────────────────────────────────────────

def test_json_mode_emits_one_document_with_the_exit_code_in_it(hc, monkeypatch, capsys):
    """_service_reachable in the entrypoint parses this, and reads one field out
    of it. The field must be there whatever the exit code is."""
    monkeypatch.setattr(hc, "evaluate", lambda: (1, {"ready": False, "reason": "why",
                                                     "hidden_service_reachable": False,
                                                     "services": []}))
    assert hc.main(["--json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc == {"ok": False, "exit_code": 1, "ready": False, "reason": "why",
                   "hidden_service_reachable": False, "services": []}


def test_json_mode_reports_ok_only_for_exit_zero(hc, monkeypatch, capsys):
    monkeypatch.setattr(hc, "evaluate", lambda: (0, {"services": [], "reason": None}))
    assert hc.main(["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_human_mode_names_the_addresses_when_ready(hc, monkeypatch, capsys):
    monkeypatch.setattr(hc, "evaluate", lambda: (0, {
        "services": [{"address": ONION + ".onion"}], "reason": None}))
    assert hc.main([]) == 0
    out = capsys.readouterr().out
    assert out.startswith("healthcheck: ready")
    assert ONION + ".onion" in out


def test_human_mode_gives_the_reason_when_not_ready(hc, monkeypatch, capsys):
    monkeypatch.setattr(hc, "evaluate", lambda: (1, {"services": [], "reason": "because"}))
    assert hc.main([]) == 1
    assert capsys.readouterr().out.strip() == "healthcheck: not ready - because"


def test_the_paths_it_probes_are_the_ones_the_entrypoint_writes(hc):
    """Two files agreeing by coincidence is the failure mode: the healthcheck
    reading a different torrc or socket than the entrypoint wrote would report on
    a container that does not exist."""
    import entrypoint as e
    assert hc.CONTROL_SOCKET == e.CONTROL_SOCKET
    assert hc.TORRC == e.TORRC_PATH
    assert hc.VANGUARDS_BIN == e.VANGUARDS_BIN
    assert os.path.basename(e.HEALTHCHECK_BIN) == "healthcheck.py"


# ─────────────────────────────────────────────────────────────────────────────
# What mutation testing found still unheld
# ─────────────────────────────────────────────────────────────────────────────

def test_the_control_request_is_exactly_the_four_commands(hc, control_socket):
    """Byte for byte. AUTHENTICATE must come first (the connection is
    unauthenticated until it does, and every GETINFO after it would be refused
    with 514), and QUIT must come last so the reply this code waits for is
    actually sent."""
    state = control_socket(_circuit_status())
    hc._query()
    assert state["request"] == (
        b"AUTHENTICATE\r\n"
        b"GETINFO status/circuit-established\r\n"
        b"GETINFO status/bootstrap-phase\r\n"
        b"GETINFO circuit-status\r\n"
        b"QUIT\r\n")


def _query_in_a_thread(hc, limit=20):
    """Run _query() with a wall-clock bound, so a probe that never returns is a
    failure rather than a hung test run."""
    box = {}

    def run():
        try:
            box["resp"] = hc._query()
        except BaseException as exc:   # re-raised in the caller's thread
            box["exc"] = exc

    thread = threading.Thread(target=run, daemon=True)
    started = time.monotonic()
    thread.start()
    thread.join(timeout=limit)
    assert not thread.is_alive(), f"_query() did not return within {limit}s"
    if "exc" in box:
        raise box["exc"]
    return box["resp"], time.monotonic() - started


def test_the_control_socket_read_is_bounded(hc, tmp_path, monkeypatch):
    """A control socket that accepts and then says nothing must not hang the
    container's HEALTHCHECK for ever -- and, since the entrypoint's publication
    gate shells out to this, must not wedge the supervision loop either."""
    path = tmp_path / "control.sock"
    monkeypatch.setattr(hc, "CONTROL_SOCKET", str(path))
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(path))
    server.listen(1)

    timeouts = []
    real_socket = socket.socket

    class Recording:
        def __init__(self, *a, **k):
            self._s = real_socket(*a, **k)

        def settimeout(self, value):
            timeouts.append(value)
            self._s.settimeout(value)

        def __getattr__(self, name):
            return getattr(self._s, name)

    monkeypatch.setattr(hc.socket, "socket", Recording)
    try:
        resp, elapsed = _query_in_a_thread(hc)
    finally:
        server.close()
    assert timeouts == [5]
    assert 5 <= elapsed < 10, "one timeout window, not none and not several"
    assert hc._reply_complete(resp) is False


def test_the_read_stops_at_the_reply_to_quit_rather_than_at_the_timeout(hc, tmp_path,
                                                                        monkeypatch):
    """Tor does not always close the connection the instant it answers QUIT. If
    the loop only stopped on EOF or a timeout, every probe would cost the full
    socket timeout -- on a HEALTHCHECK interval, and inside the once-a-second
    publication gate."""
    path = tmp_path / "control.sock"
    monkeypatch.setattr(hc, "CONTROL_SOCKET", str(path))
    reply = _circuit_status(_intro_line("1", ONION))
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(path))
    server.listen(1)
    holder = {}

    def serve():
        conn, _ = server.accept()
        holder["conn"] = conn
        conn.recv(65536)
        conn.sendall(reply)
        # Deliberately stay open. Only the terminator can end the read.
        time.sleep(15)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        resp, elapsed = _query_in_a_thread(hc)
    finally:
        if "conn" in holder:
            holder["conn"].close()
        server.close()
    assert hc._reply_complete(resp)
    assert elapsed < 3, f"the probe waited {elapsed:.1f}s for a reply it already had"


def test_the_query_returns_exactly_what_the_socket_sent(hc, control_socket):
    """Nothing is prepended to the buffer. Every parse downstream is line-based,
    so a stray byte at the front silently merges into the first line."""
    reply = _circuit_status(_intro_line("1", ONION))
    control_socket(reply)
    resp, _elapsed = _query_in_a_thread(hc)
    assert resp == reply


def test_a_torrc_with_a_non_utf8_byte_does_not_crash_the_probe(hc, torrc):
    """torrc is 0640 tor:tor and Tor wrote it, but a probe that dies with a
    UnicodeDecodeError reports nothing at all -- strictly worse than reporting on
    the lines it could read."""
    torrc.write_bytes(b"# \xff\xfe\nHiddenServiceDir /real\n")
    assert hc._hidden_service_dirs() == ["/real"]


def test_a_control_reply_with_a_non_utf8_byte_does_not_crash_the_parse(hc):
    """Same property one layer down: the reply comes off a socket, and a strict
    decode here turns a degraded answer into no answer."""
    resp = (b"250+circuit-status=\r\n"
            b"1 BUILT \xff PURPOSE=GENERAL\r\n"
            + _intro_line("2", ONION).encode() + b"\r\n"
            b".\r\n250 closing connection\r\n")
    assert hc._intro_points(resp) == {ONION: 1}


def test_a_trailing_slash_on_a_service_dir_still_names_the_service(hc, tmp_path):
    """HiddenServiceDir in a torrc may carry a trailing slash; the name derived
    from it is what appears in the status document and in every reason string."""
    d = _hs(tmp_path, "app", ONION + ".onion\n")
    _ok, details = hc._published_state([d + "/"])
    assert details[0]["name"] == "app"


def test_a_non_matching_circuit_does_not_end_the_scan(hc):
    """`continue`, not `break`. A container's circuit-status is mostly GENERAL
    client circuits; stopping at the first one would report every service as
    unreachable and withhold its address for the life of the container."""
    resp = _circuit_status(
        _intro_line("1", ONION, purpose="GENERAL"),
        _intro_line("2", ONION, state="HSSI_CONNECTING"),
        "9 LAUNCHED $A~guard PURPOSE=GENERAL",
        _intro_line("4", ONION),
    )
    assert hc._intro_points(resp) == {ONION: 1}


def test_a_circuit_relisted_with_different_detail_is_still_one_circuit(hc):
    """Dedup is by circuit id -- the first field -- not by the whole line. The
    reply is read in fragments as it grows, and an inflated count is not evidence
    of anything."""
    first = _intro_line("77", ONION)
    relisted = first.replace("2026-09-18T00:00:00.000000", "2026-09-18T00:00:09.000000")
    assert relisted != first
    assert hc._intro_points(_circuit_status(first, relisted)) == {ONION: 1}


def test_one_established_introduction_point_is_enough(hc, world):
    """One is the documented floor, not the norm: Tor maintains three per service
    by default, but requiring more would mark a service unreachable during the
    seconds its other two are still being built."""
    world(_circuit_status(_intro_line("1", ONION)),
          services=[("app", ONION + ".onion\n")])
    rc, doc = hc.evaluate()
    assert rc == 0
    assert doc["services"][0]["intro_points"] == 1
    assert doc["hidden_service_reachable"] is True


def test_a_service_with_no_address_has_no_introduction_points(hc, world):
    world(_circuit_status(), services=[("app", None)])
    _rc, doc = hc.evaluate()
    assert doc["services"][0]["intro_points"] == 0


def test_the_status_document_keys_are_the_contract(hc, world):
    """entrypoint._service_reachable reads `hidden_service_reachable` out of this
    document by name, and `hiddenforge status` reads the rest. A renamed key is a
    silently absent field, which reads as "not reachable" for ever."""
    world(_circuit_status(*[_intro_line(str(i), ONION) for i in range(3)]),
          services=[("app", ONION + ".onion\n")])
    _rc, doc = hc.evaluate()
    assert sorted(doc) == [
        "circuit_established", "hidden_service_published", "hidden_service_reachable",
        "process_up", "ready", "reason", "services", "tor_bootstrapped", "vanguards",
    ]
    assert sorted(doc["services"][0]) == ["address", "descriptor_uploaded", "intro_points",
                                          "name", "published"]


def test_every_flag_starts_false_and_none_is_self_evident(hc, monkeypatch, procfs):
    """Every flag must be proven before it is reported, so an early return cannot
    leak an optimistic default into the status document."""
    def boom():
        raise OSError("no socket")

    procfs(99, b"tor\x00-f\x00/etc/tor/torrc\x00")
    monkeypatch.setattr(hc, "_query", boom)
    _rc, doc = hc.evaluate()
    assert doc["process_up"] is True
    for field in ("tor_bootstrapped", "circuit_established", "hidden_service_published",
                  "hidden_service_reachable", "vanguards", "ready"):
        assert doc[field] is False, field
    assert doc["services"] == []


def test_process_up_is_false_when_no_tor_is_running(hc, monkeypatch, procfs):
    """`process_up` was the literal constant True, documented as "always true if
    this executes". manifest.json advertises it to integrators beside fields that
    do mean something, so it read as a check on the Tor process and was not one.

    Measured against the real image: running the healthcheck in a container with
    no Tor at all reported `process_up: true`. A field in a machine contract that
    cannot ever be false is worse than an absent one -- anything keying on it is
    keying on a constant.
    """
    def boom():
        raise OSError("no socket")

    procfs(1, b"/usr/bin/python3\x00/entrypoint.py\x00")   # supervisor only
    monkeypatch.setattr(hc, "_query", boom)
    _rc, doc = hc.evaluate()
    assert doc["process_up"] is False
    assert doc["ready"] is False


def test_process_up_is_true_when_tor_is_running(hc, procfs, world):
    """The other side: a healthy container must be unchanged by that fix."""
    procfs(1, b"/usr/bin/python3\x00/entrypoint.py\x00")
    procfs(8, b"tor\x00-f\x00/etc/tor/torrc\x00")
    procfs(9, hc.VANGUARDS_BIN.encode())
    world(_circuit_status(*[_intro_line(str(i), ONION) for i in range(3)]),
          services=[("app", ONION + ".onion\n")])
    _rc, doc = hc.evaluate()
    assert doc["process_up"] is True


def test_tor_is_found_by_argv0_as_the_container_really_execs_it(hc, procfs):
    """`su-exec tor tor -f /etc/tor/torrc` leaves argv[0] as the bare name "tor".

    Read off a running container, not assumed. Matching an absolute
    "/usr/bin/tor" would have made `process_up` false on every healthy service,
    and the fixture that said otherwise would have blessed it.
    """
    procfs(1, b"/usr/bin/python3\x00/entrypoint.py\x00")
    assert hc._tor_running() is False
    procfs(8, b"tor\x00-f\x00/etc/tor/torrc\x00")
    assert hc._tor_running() is True


def test_vanguards_is_not_mistaken_for_the_tor_daemon(hc, procfs):
    """Vanguards runs with `--control_socket /var/lib/tor/control.sock`, so any
    substring test for "tor" finds the addon and reports the daemon as up."""
    procfs(1, b"/usr/bin/python3\x00/entrypoint.py\x00")
    procfs(11, hc.VANGUARDS_BIN.encode()
           + b"\x00--control_socket\x00/var/lib/tor/control.sock\x00")
    assert hc._vanguards_running() is True
    assert hc._tor_running() is False


def test_an_absolute_tor_path_is_still_recognised(hc, procfs):
    """A runtime that execs it by full path must not read as a dead daemon."""
    procfs(8, b"/usr/bin/tor\x00-f\x00/etc/tor/torrc\x00")
    assert hc._tor_running() is True


def test_the_truncated_reply_reason_says_what_it_does_not_mean(hc, world):
    world(b"250-status/circuit-established=1\r\n250+circuit-status=\r\n",
          services=[("app", ONION + ".onion\n")])
    _rc, doc = hc.evaluate()
    assert doc["reason"] == ("control socket reply was truncated - cannot evaluate "
                             "(this is not a statement that the service is down)")


def test_the_missing_vanguards_reason_names_what_was_lost(hc, world):
    world(_circuit_status(*[_intro_line(str(i), ONION) for i in range(3)]),
          services=[("app", ONION + ".onion\n")], vanguards=False)
    _rc, doc = hc.evaluate()
    assert doc["reason"] == ("Tor is serving but the Vanguards addon is NOT running - "
                             "bandguards and rendguard are gone. It is retried "
                             "automatically; restarting the container retries at once.")


def test_several_unpublished_services_are_listed_comma_separated(hc, world):
    world(_circuit_status(), services=[("aaa", None), ("bbb", None)])
    _rc, doc = hc.evaluate()
    assert doc["reason"] == "hidden service(s) not published yet: aaa, bbb"


def test_several_unreachable_services_are_listed_comma_separated(hc, world):
    world(_circuit_status(),
          services=[("aaa", ONION + ".onion\n"), ("bbb", OTHER + ".onion\n")])
    _rc, doc = hc.evaluate()
    assert doc["reason"].startswith(
        "hostname exists but Tor has no established introduction points for: aaa, bbb - ")


def test_the_json_document_is_key_sorted_for_a_stable_diff(hc, monkeypatch, capsys):
    """This is machine-readable output that gets diffed between boots and pasted
    into issue reports. Key order that follows insertion order changes whenever
    the code does."""
    monkeypatch.setattr(hc, "evaluate", lambda: (0, {"zebra": 1, "alpha": 2}))
    hc.main(["--json"])
    assert capsys.readouterr().out == '{"alpha": 2, "exit_code": 0, "ok": true, "zebra": 1}\n'


def test_human_mode_lists_every_address_comma_separated(hc, monkeypatch, capsys):
    monkeypatch.setattr(hc, "evaluate", lambda: (0, {"services": [
        {"address": "a" * 56 + ".onion"}, {"address": None}, {"address": "b" * 56 + ".onion"},
    ], "reason": None}))
    hc.main([])
    assert capsys.readouterr().out == (
        f"healthcheck: ready - {'a' * 56}.onion, {'b' * 56}.onion\n")


def test_human_mode_says_ready_with_nothing_after_it_when_there_are_no_services(
        hc, monkeypatch, capsys):
    monkeypatch.setattr(hc, "evaluate", lambda: (0, {"services": [], "reason": None}))
    hc.main([])
    assert capsys.readouterr().out == "healthcheck: ready\n"


def test_the_program_name_is_the_one_the_healthcheck_invokes(hc, capsys):
    """argparse prints it in every usage error, and the HEALTHCHECK line runs
    `python3 /usr/local/bin/healthcheck.py`, so argv[0] alone would print an
    absolute path that is not where an operator's copy lives."""
    with pytest.raises(SystemExit):
        hc.main(["--nope"])
    assert "usage: healthcheck.py" in capsys.readouterr().err


def test_an_intro_line_without_an_address_does_not_end_the_scan(hc):
    """`continue`, not `break`. A line that looks like an introduction circuit but
    carries no REND_QUERY cannot be attributed to a service -- and must not take
    the rest of the reply down with it."""
    resp = _circuit_status(
        "3 BUILT $A~g PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED",
        _intro_line("4", ONION),
    )
    assert hc._intro_points(resp) == {ONION: 1}


def test_a_repeated_circuit_id_does_not_end_the_scan(hc):
    """Same property at the dedup step: the reply is read as it grows, so a
    circuit appearing twice is ordinary, not a reason to stop counting."""
    first = _intro_line("5", ONION)
    resp = _circuit_status(first, first, _intro_line("6", ONION))
    assert hc._intro_points(resp) == {ONION: 2}


def test_the_circuit_id_is_the_first_field_not_the_rest_of_the_line(hc):
    """Dedup keys on the circuit id. Keying on anything else -- the line minus its
    last field, say -- counts one circuit twice whenever its path or flags change
    between reads, and an inflated count is not evidence of anything."""
    first = _intro_line("77", ONION)
    relisted = first.replace("$BBBB~middle", "$DDDD~middle")
    assert relisted != first
    assert hc._intro_points(_circuit_status(first, relisted)) == {ONION: 1}


def test_only_a_trailing_slash_is_stripped_from_a_service_directory(hc, tmp_path):
    """`rstrip("/")`. Stripping any other character would rename a service whose
    directory happens to end in one."""
    _ok, details = hc._published_state([str(tmp_path / "appX") + "/"])
    assert details[0]["name"] == "appX"


def test_the_json_flag_documents_itself(hc, monkeypatch, capsys):
    """`healthcheck.py --help` inside the container is how an operator discovers
    that there is a machine-readable mode at all."""
    monkeypatch.setenv("COLUMNS", "200")
    with pytest.raises(SystemExit):
        hc.main(["--help"])
    lines = [" ".join(line.split()) for line in capsys.readouterr().out.splitlines()]
    assert "--json emit a JSON status document" in lines


def test_an_unreadable_proc_entry_before_the_target_does_not_stop_the_scan(
        hc, procfs, monkeypatch):
    """`continue`, not `break`. /proc is full of entries this cannot read --
    other users' processes, and pids that exit between the listing and the open.
    Stopping at the first one would report a running daemon as dead whenever an
    unreadable entry happened to be enumerated first, which is a health flap
    nobody could reproduce.

    The listing order is pinned, because relying on the filesystem's order is
    how this passes by luck.
    """
    (procfs.root / "3").mkdir()                     # no cmdline: reads as ENOENT
    procfs(8, b"tor\x00-f\x00/etc/tor/torrc\x00")
    monkeypatch.setattr(hc.os, "listdir", lambda _p: ["3", "8"])
    assert hc._tor_running() is True
    assert list(hc._each_cmdline()) == [b"tor\x00-f\x00/etc/tor/torrc\x00"]


def test_a_cmdline_that_is_not_utf8_does_not_crash_the_scan(hc, procfs):
    """/proc/<pid>/cmdline is bytes and nothing guarantees it decodes. A strict
    decode here turns one odd process anywhere on the host into a healthcheck
    that raises, which docker reads as unhealthy and restarts the container."""
    procfs(5, b"/usr/bin/\xff\xfe-weird\x00arg\x00")
    procfs(8, b"tor\x00-f\x00/etc/tor/torrc\x00")
    assert hc._tor_running() is True


def test_a_process_whose_argv0_merely_ends_in_tor_is_not_the_daemon(hc, procfs):
    """`basename(argv0) == "tor"`, not "contains tor": /usr/bin/torsocks and
    /opt/monitor are not the Tor daemon."""
    procfs(4, b"/usr/bin/torsocks\x00curl\x00")
    procfs(5, b"/usr/local/bin/tor-controller\x00")
    assert hc._tor_running() is False
    procfs(8, b"/usr/bin/tor\x00-f\x00/etc/tor/torrc\x00")
    assert hc._tor_running() is True


def test_an_empty_cmdline_is_not_the_tor_daemon(hc, procfs):
    """Kernel threads have an empty cmdline; basename("") is "" and must not
    match anything."""
    procfs(2, b"")
    assert hc._tor_running() is False


def test_a_non_numeric_proc_entry_before_the_target_does_not_stop_the_scan(
        hc, procfs, monkeypatch):
    """`continue`, not `break`, on the non-pid entries.

    A real /proc is full of them -- self, sys, net, meminfo -- and they are not
    listed after the pids, they are mixed in with them. Stopping at the first one
    would make every scan return False on a real system: no Tor daemon, no
    Vanguards, a container that reports unhealthy for ever while serving fine.
    The existing test created two such entries and passed only because the
    filesystem happened to list them last, so the order is pinned here.
    """
    (procfs.root / "sys").mkdir()
    procfs(8, b"tor\x00-f\x00/etc/tor/torrc\x00")
    procfs(11, hc.VANGUARDS_BIN.encode())
    monkeypatch.setattr(hc.os, "listdir", lambda _p: ["sys", "8", "11"])
    assert hc._tor_running() is True
    assert hc._vanguards_running() is True
    assert len(list(hc._each_cmdline())) == 2


# ─────────────────────────────────────────────────────────────────────────────
# the hostname read cannot be turned into a hang or a crash
# ─────────────────────────────────────────────────────────────────────────────

def _hc_returns_promptly(fn, seconds=5):
    import threading
    done = threading.Event()
    box = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as exc:
            box["exc"] = exc
        done.set()

    threading.Thread(target=run, daemon=True).start()
    assert done.wait(seconds), "blocked until the engine's healthcheck timeout"
    if "exc" in box:
        raise box["exc"]
    return box["value"]


def test_a_fifo_hostname_is_not_published_and_does_not_block(hc, tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    os.mkfifo(d / "hostname")
    ok, details = _hc_returns_promptly(lambda: hc._published_state([str(d)]))
    assert ok is False and details[0]["published"] is False


def test_a_hostname_linked_to_an_endless_file_is_not_read(hc, tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    (d / "hostname").symlink_to("/dev/zero")
    ok, _details = _hc_returns_promptly(lambda: hc._published_state([str(d)]))
    assert ok is False


# ─────────────────────────────────────────────────────────────────────────────
# The descriptor has to be ON THE NETWORK before the service is reachable
# ─────────────────────────────────────────────────────────────────────────────
#
# Measured on a fresh service: ready and the address file at 11:17:58, the
# descriptor uploaded at 11:18:40-42, every client fetch in between failed.

def test_intro_points_without_an_uploaded_descriptor_are_not_reachable(hc, world):
    world(_circuit_status(*[_intro_line(str(i), ONION) for i in range(3)]),
          services=[("app", ONION + ".onion\n")], uploaded=set())
    rc, doc = hc.evaluate()
    assert rc == 1 and doc["ready"] is False
    assert doc["hidden_service_reachable"] is False
    assert doc["services"][0]["descriptor_uploaded"] is False
    assert doc["reason"].startswith("no descriptor uploaded to the network yet for: app")


def test_an_upload_for_one_service_does_not_vouch_for_another(hc, world):
    world(_circuit_status(*[_intro_line(str(i), a) for i, a in enumerate([ONION, OTHER] * 2)]),
          services=[("good", ONION + ".onion\n"), ("late", OTHER + ".onion\n")],
          uploaded={ONION})
    rc, doc = hc.evaluate()
    assert rc == 1
    assert [s["descriptor_uploaded"] for s in doc["services"]] == [True, False]
    assert "late" in doc["reason"] and "good" not in doc["reason"]


def test_missing_intro_points_are_reported_before_a_missing_upload(hc, world):
    """No introduction circuits is the deeper failure; say that one."""
    world(_circuit_status(), services=[("app", ONION + ".onion\n")], uploaded=set())
    _rc, doc = hc.evaluate()
    assert "NOT reachable" in doc["reason"]


def test_the_uploads_file_keeps_only_well_formed_addresses(hc, tmp_path):
    path = tmp_path / "hs-uploaded"
    path.write_text(f"{ONION}\nnot-an-address\n{OTHER}\n{ONION}.onion\n\n")
    assert hc._uploaded_addresses(str(path)) == {ONION, OTHER}


def test_a_missing_or_hostile_uploads_file_is_nothing_uploaded(hc, tmp_path):
    assert hc._uploaded_addresses(str(tmp_path / "absent")) == set()
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert hc._uploaded_addresses(str(fifo)) == set()
    (tmp_path / "link").symlink_to(tmp_path / "absent")
    assert hc._uploaded_addresses(str(tmp_path / "link")) == set()


def _fake_tor(tmp_path, chunks, received):
    """A control socket that answers with `chunks`, then closes (Tor exiting)."""
    import threading
    sock_path = str(tmp_path / "control.sock")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(sock_path)
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        received.append(conn.recv(4096))
        for c in chunks:
            conn.sendall(c)
        conn.close()
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return sock_path


def test_the_watcher_records_only_our_upload_confirmations(hc, tmp_path):
    received = []
    good = f"650 HS_DESC UPLOADED {ONION} UNKNOWN $AAAA~relay\r\n".encode()
    chunks = [
        b"250 OK\r\n250 OK\r\n",
        f"650 HS_DESC CREATED {OTHER} UNKNOWN UNKNOWN x\r\n".encode(),
        f"650 HS_DESC UPLOAD {OTHER} UNKNOWN $BBBB HSDIR_INDEX=1\r\n".encode(),
        good[:20], good[20:],                       # an event split across reads
        good,                                       # a second HSDir: no change
        b"650 HS_DESC UPLOADED notanaddress UNKNOWN $CCCC\r\n",
        b"650 HS_DESC FAILED " + OTHER.encode() + b" UNKNOWN $DDDD REASON=X\r\n",
    ]
    sock_path = _fake_tor(tmp_path, chunks, received)
    out = tmp_path / "hs-uploaded"
    assert hc.watch_uploads(str(out), sock_path, connect_timeout=5) == 0
    assert received[0] == b"AUTHENTICATE\r\nSETEVENTS HS_DESC\r\n"
    assert out.read_text() == f"{ONION}\n"
    assert (out.stat().st_mode & 0o777) == 0o600


def test_a_restarted_watcher_keeps_what_was_recorded(hc, tmp_path):
    out = tmp_path / "hs-uploaded"
    out.write_text(f"{OTHER}\n")
    sock_path = _fake_tor(tmp_path, [
        f"650 HS_DESC UPLOADED {ONION} UNKNOWN $AAAA\r\n".encode()], [])
    assert hc.watch_uploads(str(out), sock_path, connect_timeout=5) == 0
    assert out.read_text() == f"{ONION}\n{OTHER}\n"


def test_no_control_socket_is_a_bounded_wait_not_a_hang(hc, tmp_path, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(hc.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(hc.time, "sleep", lambda s: clock.__setitem__(0, clock[0] + s))
    assert hc.watch_uploads(str(tmp_path / "out"), str(tmp_path / "none.sock"),
                            connect_timeout=3) == 2
    assert not (tmp_path / "out").exists()
