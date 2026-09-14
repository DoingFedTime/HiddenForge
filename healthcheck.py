#!/usr/bin/env python3
"""HiddenForge container healthcheck.

Distinguishes four states, so a consumer never publishes an address that does not
exist yet:

    process_up              we are running (always true if this executes)
    tor_bootstrapped        the control socket reports bootstrap PROGRESS=100
    hidden_service_published every configured HiddenServiceDir has a valid hostname
    hidden_service_reachable Tor holds BUILT introduction circuits for the service
    ready                   all of the above AND the Vanguards addon is alive

`pidof tor` only proved the process existed. This probe queries Tor's control
socket and reports healthy only when Tor has finished bootstrapping, established a
usable circuit, has working onion-service introduction circuits, and still has the
Vanguards (guard-protection) addon running, so a Tor that is alive but wedged
(censored network, broken guard) reads as unhealthy.

`hidden_service_published` is a weaker check than its name suggests and must never
be the last word: Tor writes the `hostname` file at key-generation time, long
before any descriptor reaches a directory. A container whose onion-service
circuits could not build was observed with a valid hostname, bootstrap at 100%,
`circuit-established=1` and every one of those checks passing, while being
completely unreachable over Tor (SOCKS reply 6 - descriptor never published).
`hidden_service_reachable` is the check that catches that case; see
`_intro_circuits` for why it is the only control-port signal that does.

Run as the tor user (the control socket and torrc live in the 0700 DataDirectory):
    HEALTHCHECK CMD su-exec tor python3 /usr/local/bin/healthcheck.py

Authentication is null (ControlSocket with no cookie/password - file permissions
are the boundary), so AUTHENTICATE takes no argument.

    healthcheck.py            exit 0 = ready, 1 = not (human message)
    healthcheck.py --json     one JSON document on stdout, same exit code

Exit codes: 0 ready, 1 not ready, 2 cannot evaluate (control socket unreachable).
"""
import argparse
import json
import os
import re
import socket
import sys

CONTROL_SOCKET = "/var/lib/tor/control.sock"
TORRC = "/etc/tor/torrc"
VANGUARDS_BIN = "/opt/vanguards-venv/bin/vanguards"

ONION_RE = re.compile(r"^[a-z2-7]{56}\.onion$")
HSDIR_RE = re.compile(r"^\s*HiddenServiceDir\s+(\S+)\s*$")


def _vanguards_running():
    """True if the Vanguards addon process is alive.

    The entrypoint restarts Vanguards up to five times and then gives up,
    printing a warning and continuing with Tor alone. That warning goes to
    stdout - which the shipped compose file discards (`logging: driver: none`,
    to avoid a host-side log of onion activity). The result is that losing
    bandguards and rendguard, both of which exist to detect an attack in
    progress, is completely invisible to the operator.

    The health status is the one channel that survives a disabled log driver, so
    report it here. Scans /proc directly rather than shelling out to pgrep,
    which is not in the image.
    """
    try:
        entries = os.listdir("/proc")
    except OSError:
        return False
    for pid in entries:
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                if VANGUARDS_BIN.encode() in fh.read():
                    return True
        except OSError:
            continue          # process exited mid-scan, or not ours to read
    return False


def _query():
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(5)
    s.connect(CONTROL_SOCKET)
    s.sendall(
        b"AUTHENTICATE\r\n"
        b"GETINFO status/circuit-established\r\n"
        b"GETINFO status/bootstrap-phase\r\n"
        b"GETINFO circuit-status\r\n"
        b"QUIT\r\n"
    )
    # Read until Tor's reply to QUIT, not merely until EOF. circuit-status is a
    # multiline reply that grows with the circuit count; stopping on a timeout
    # would silently truncate it and undercount introduction circuits, which reads
    # as "unreachable" on a perfectly healthy service. A short read is a failure to
    # evaluate, not a negative result, so say so explicitly.
    data = b""
    try:
        while b"250 closing connection" not in data:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except TimeoutError:
        pass
    finally:
        s.close()
    return data


def _reply_complete(resp):
    """True if the control connection returned its full reply to QUIT."""
    return b"250 closing connection" in resp


def _hidden_service_dirs():
    """HiddenServiceDir paths from the running torrc.

    Read from the config rather than the environment: the container may have been
    started with the full <NAME>_TOR_SERVICE_HOSTS form, and the entrypoint is the
    only thing that turns those into directories. torrc is 0640 tor:tor, readable
    by this process.
    """
    dirs = []
    try:
        with open(TORRC, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = HSDIR_RE.match(line)
                if m:
                    dirs.append(m.group(1))
    except OSError:
        return []
    # De-duplicate, order-stable.
    seen = set()
    out = []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _published_state(dirs):
    """(all_published, details). No services configured counts as published."""
    if not dirs:
        return True, []
    details = []
    all_ok = True
    for d in dirs:
        name = os.path.basename(d.rstrip("/"))
        path = os.path.join(d, "hostname")
        onion = None
        try:
            with open(path, encoding="ascii", errors="strict") as fh:
                onion = fh.read().strip()
        except (OSError, UnicodeDecodeError):
            onion = None
        ok = bool(onion and ONION_RE.fullmatch(onion))
        all_ok = all_ok and ok
        details.append({"name": name, "address": onion if ok else None, "published": ok})
    return all_ok, details


REND_QUERY_RE = re.compile(r"\bREND_QUERY=([a-z2-7]{56})\b")
CIRCUIT_STATUS_HEADER = "250+circuit-status="


def _circuit_status_lines(resp):
    """The body lines of the circuit-status reply, and nothing else.

    One control connection carries several replies back to back, so scanning the
    whole buffer for circuit lines lets any other reply's text be counted as a
    circuit if it happens to contain the right substrings. Scoping to this one
    reply's body removes that whole class rather than arguing about whether any
    particular field could contain the trigger text.

    A multiline reply runs from its `250+<key>=` header to a line containing a
    single period; a body line that would otherwise start with a period is sent
    dot-stuffed, so a leading `..` is unescaped here. Verified against Tor
    0.4.9.12: header at the top, body lines beginning with the circuit id, then
    `.`, then `250 OK`.

    Returns [] if the terminator never arrives, so a truncated reply yields no
    count at all rather than a partial one. `evaluate` refuses to evaluate before
    it gets here in that case.
    """
    lines = resp.decode("utf-8", "replace").splitlines()
    try:
        start = lines.index(CIRCUIT_STATUS_HEADER)
    except ValueError:
        return []
    body = []
    for line in lines[start + 1:]:
        if line == ".":
            return body
        body.append(line[1:] if line.startswith("..") else line)
    return []


def _intro_points(resp):
    """Map onion address -> count of ESTABLISHED introduction circuits.

    Keyed per service. Each HS_SERVICE_INTRO line in a `GETINFO circuit-status`
    reply carries `REND_QUERY=<onion address>` (no .onion suffix), so circuits can
    be attributed to the service that owns them. Without that attribution a
    container serving several onion services could hide a completely broken one
    behind a healthy one: a bare total of "at least one circuit per service" is
    satisfied by one service holding all of them.

    Counts only `HS_STATE=HSSI_ESTABLISHED`, which is strictly stronger than the
    circuit being BUILT: it means the introduction point accepted the ESTABLISH_INTRO
    cell and is actually willing to introduce clients to us. A circuit that is BUILT
    but still HSSI_CONNECTING or HSSI_INTRO_SENT cannot yet receive an introduction.

    This is the only control-port signal that separates a reachable onion service
    from an unreachable one. Two more obvious candidates were tested against a
    known-broken container and both failed:

      * `GETINFO hs/service/desc/id/<addr>` returns a complete ~14KB descriptor
        even when the service never reached a directory, because the descriptor is
        generated and cached locally. The broken container's descriptor was
        byte-comparable to the healthy one's.
      * HS_SERVICE_HSDIR circuits are torn down once the upload completes, so a
        healthy service that has been up for thirty minutes shows zero of them.
        Gating on those would mark every long-running service unhealthy.

    Introduction circuits are the exception, and for a structural reason: a v3
    onion service is reached by clients connecting to its introduction points, so
    it maintains those circuits for its entire lifetime. No introduction circuits
    means no client can reach the service, whatever the hostname file says.

    Measured on two independent healthy containers at 30+ minutes uptime: 12
    established each. On a container whose onion-service circuits could not build: 0.

    Only the body of the circuit-status reply is scanned (see
    `_circuit_status_lines`), and each circuit is counted at most once by its id -
    the first field of the line. Counting the same circuit twice could not produce
    a false "unreachable" (a service with no circuits contributes no lines at all),
    but it could inflate a count, and an inflated count is not evidence of
    anything.
    """
    counts = {}
    seen = set()
    for raw in _circuit_status_lines(resp):
        line = raw.strip()
        if "PURPOSE=HS_SERVICE_INTRO" not in line:
            continue
        if "HS_STATE=HSSI_ESTABLISHED" not in line:
            continue
        m = REND_QUERY_RE.search(line)
        if not m:
            continue
        circuit_id = line.split(" ", 1)[0]
        if circuit_id in seen:
            continue
        seen.add(circuit_id)
        counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return counts


def evaluate():
    """Return (rc, doc). rc 0 ready, 1 not ready, 2 cannot evaluate."""
    doc = {
        "process_up": True,
        "tor_bootstrapped": False,
        "circuit_established": False,
        "hidden_service_published": False,
        "hidden_service_reachable": False,
        "vanguards": False,
        "ready": False,
        "services": [],
        "reason": None,
    }
    try:
        resp = _query()
    except OSError as exc:
        doc["reason"] = f"cannot reach control socket: {exc}"
        return 2, doc

    if not _reply_complete(resp):
        doc["reason"] = ("control socket reply was truncated - cannot evaluate "
                         "(this is not a statement that the service is down)")
        return 2, doc

    doc["circuit_established"] = b"circuit-established=1" in resp
    doc["tor_bootstrapped"] = b"PROGRESS=100" in resp
    doc["vanguards"] = _vanguards_running()

    dirs = _hidden_service_dirs()
    published, details = _published_state(dirs)
    doc["hidden_service_published"] = published
    doc["services"] = details

    # One established introduction point is the floor, not the norm - Tor maintains
    # three per service by default. Requiring the floor per service avoids guessing
    # at Tor's internal target while still catching a service with none, which is
    # the failure this check exists for.
    intro = _intro_points(resp)
    unreachable = []
    for svc in details:
        addr = svc["address"]
        svc["intro_points"] = intro.get(addr[:-len(".onion")], 0) if addr else 0
        if svc["published"] and svc["intro_points"] < 1:
            unreachable.append(svc["name"])
    doc["hidden_service_reachable"] = not unreachable

    if not doc["tor_bootstrapped"]:
        doc["reason"] = "bootstrap not at 100%"
    elif not doc["circuit_established"]:
        doc["reason"] = "no circuit established yet"
    elif not published:
        missing = [d["name"] for d in details if not d["published"]]
        doc["reason"] = f"hidden service(s) not published yet: {', '.join(missing)}"
    elif not doc["hidden_service_reachable"]:
        doc["reason"] = (
            f"hostname exists but Tor has no established introduction points for: "
            f"{', '.join(unreachable)} - NOT reachable by any client, whatever the "
            f"hostname file says. Check the Tor log for guard or circuit failures."
        )
    elif not doc["vanguards"]:
        doc["reason"] = ("Tor is serving but the Vanguards addon is NOT running - "
                         "bandguards and rendguard are gone. Restart the container.")
    else:
        doc["ready"] = True
        return 0, doc
    return 1, doc


def main(argv=None):
    ap = argparse.ArgumentParser(prog="healthcheck.py")
    ap.add_argument("--json", action="store_true", help="emit a JSON status document")
    args = ap.parse_args(argv)

    rc, doc = evaluate()
    if args.json:
        out = {"ok": rc == 0, "exit_code": rc, **doc}
        print(json.dumps(out, sort_keys=True))
    else:
        if rc == 0:
            addrs = ", ".join(s["address"] for s in doc["services"] if s["address"])
            print(f"healthcheck: ready{' - ' + addrs if addrs else ''}")
        else:
            print(f"healthcheck: not ready - {doc['reason']}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
