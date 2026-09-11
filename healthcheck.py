#!/usr/bin/env python3
"""HiddenForge container healthcheck.

Distinguishes four states, so a consumer never publishes an address that does not
exist yet:

    process_up              we are running (always true if this executes)
    tor_bootstrapped        the control socket reports bootstrap PROGRESS=100
    hidden_service_published every configured HiddenServiceDir has a valid hostname
    ready                   all of the above AND the Vanguards addon is alive

`pidof tor` only proved the process existed. This probe queries Tor's control
socket and reports healthy only when Tor has finished bootstrapping, established a
usable circuit, published every hidden service, and still has the Vanguards
(guard-protection) addon running, so a Tor that is alive but wedged (censored
network, broken guard) reads as unhealthy.

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
        b"QUIT\r\n"
    )
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except TimeoutError:
        pass
    finally:
        s.close()
    return data


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


def evaluate():
    """Return (rc, doc). rc 0 ready, 1 not ready, 2 cannot evaluate."""
    doc = {
        "process_up": True,
        "tor_bootstrapped": False,
        "circuit_established": False,
        "hidden_service_published": False,
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

    doc["circuit_established"] = b"circuit-established=1" in resp
    doc["tor_bootstrapped"] = b"PROGRESS=100" in resp
    doc["vanguards"] = _vanguards_running()

    dirs = _hidden_service_dirs()
    published, details = _published_state(dirs)
    doc["hidden_service_published"] = published
    doc["services"] = details

    if not doc["tor_bootstrapped"]:
        doc["reason"] = "bootstrap not at 100%"
    elif not doc["circuit_established"]:
        doc["reason"] = "no circuit established yet"
    elif not published:
        missing = [d["name"] for d in details if not d["published"]]
        doc["reason"] = f"hidden service(s) not published yet: {', '.join(missing)}"
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
