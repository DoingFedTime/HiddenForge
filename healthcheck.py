#!/usr/bin/env python3
"""HiddenForge container healthcheck.

`pidof tor` only proves the process exists — not that Tor bootstrapped or built
a circuit. This probe queries Tor's control socket and reports healthy only when
Tor has both finished bootstrapping (100%) AND established a usable circuit, so a
Tor that is alive but wedged (censored network, broken guard) reads as unhealthy.

Run as the tor user (the control socket lives in the 0700 DataDirectory):
    HEALTHCHECK CMD su-exec tor python3 /usr/local/bin/healthcheck.py

Authentication is null (ControlSocket with no cookie/password — file permissions
are the boundary), so AUTHENTICATE takes no argument. Exit 0 = healthy, 1 = not.
"""
import socket
import sys

CONTROL_SOCKET = "/var/lib/tor/control.sock"


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
    except socket.timeout:
        pass
    finally:
        s.close()
    return data


def main():
    try:
        resp = _query()
    except OSError as exc:
        print(f"healthcheck: cannot reach control socket: {exc}")
        return 1

    if b"circuit-established=1" not in resp:
        print("healthcheck: no circuit established yet")
        return 1
    # bootstrap-phase line contains PROGRESS=NN; require 100.
    if b"PROGRESS=100" not in resp:
        print("healthcheck: bootstrap not at 100%")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
