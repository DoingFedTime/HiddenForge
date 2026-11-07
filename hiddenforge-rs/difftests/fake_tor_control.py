"""A scripted Tor control port, for the guards differential test.

Answers what Vanguards 0.3.1 (via stem) and the Rust guards ask for at start
(PROTOCOLINFO, AUTHENTICATE, GETINFO version/ns/all/orconn-status/
network-liveness, GETCONF), waits until SETEVENTS covers every event both
subscribe to, replays a fixed event stream, records every CLOSECIRCUIT, then
closes the connection and writes the CLOSECIRCUIT sequence as JSON.

    python3 fake_tor_control.py <socket path> <data dir> <out.json>
"""
import base64
import json
import os
import socket
import sys
import time

SOCK, DATADIR, OUT = sys.argv[1:4]
G = "$" + "A" * 40 + "~guard"
M = "$" + "D" * 40 + "~middle"


def fp_b64(c):
    return base64.b64encode(bytes.fromhex(c * 40)).decode().rstrip("=")


# Two Fast+Valid relays: B carries 0.1% of the middle weight, C the rest.
NS = "\r\n".join([
    f"r relayB {fp_b64('B')} digest 2026-11-07 00:00:00 10.0.0.2 9001 0",
    "s Fast Running Stable Valid",
    "w Bandwidth=1",
    f"r relayC {fp_b64('C')} digest 2026-11-07 00:00:00 10.0.0.3 9001 0",
    "s Fast Running Stable Valid",
    "w Bandwidth=999",
    f"r relayD {fp_b64('D')} digest 2026-11-07 00:00:00 10.0.0.4 9001 0",
    "s Fast Guard Running Stable Valid",
    "w Bandwidth=500",
])
WEIGHTS = ("bandwidth-weights Wbd=0 Wbe=0 Wbg=0 Wbm=10000 Wdb=10000 Web=10000 Wed=10000 "
           "Wee=10000 Weg=10000 Wem=10000 Wgb=10000 Wgd=10000 Wgg=10000 Wgm=10000 Wmb=10000 "
           "Wmd=10000 Wme=10000 Wmg=10000 Wmm=10000\n")


def events():
    ev = []
    bw = lambda i, r, w, dr=0, orr=0: (
        f"650 CIRC_BW ID={i} READ={r} WRITTEN={w} TIME=2026-11-07T00:00:00.000000 "
        f"DELIVERED_READ={dr} OVERHEAD_READ={orr} DELIVERED_WRITTEN=0 OVERHEAD_WRITTEN=0")
    # 10: established intro point, 2 dropped cells -> close (bug #29699 path).
    ev.append(f"650 CIRC 10 BUILT {G},{M} PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED")
    ev.append(bw(10, 1018, 0))
    # 11: connecting rend circuit, 1 dropped cell is allowed -> no close.
    ev.append(f"650 CIRC 11 BUILT {G},{M} PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_CONNECTING")
    ev.append(bw(11, 509, 0))
    # 12: HSDIR circuit over 30 KB -> close.
    ev.append(f"650 CIRC 12 BUILT {G},{M} PURPOSE=HS_SERVICE_HSDIR")
    ev.append(bw(12, 0, 31745))
    # 13: general circuit, built, dropped cells -> WARN + close.
    ev.append(f"650 CIRC 13 BUILT {G},{M} PURPOSE=GENERAL")
    ev.append(bw(13, 2036, 0, 498, 0))
    # 14: not built yet, dropped cell -> INFO only.
    ev.append(f"650 CIRC 14 EXTENDED {G} PURPOSE=GENERAL")
    ev.append(bw(14, 1018, 0))
    # 15: client rend circuit (1 allowed) that then becomes PATH_BIAS_TESTING.
    ev.append(f"650 CIRC 15 BUILT {G},{M} PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_CONNECTING")
    ev.append(f"650 CIRC_MINOR 15 PURPOSE_CHANGED {G},{M} PURPOSE=PATH_BIAS_TESTING "
              "OLD_PURPOSE=HS_CLIENT_REND OLD_HS_STATE=HSCR_CONNECTING")
    ev.append(bw(15, 509, 0))
    # 16: properly delivered data, no dropped cells -> nothing.
    ev.append(f"650 CIRC 16 BUILT {G},{M} PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_JOINED")
    ev.append(bw(16, 1018, 0, 996, 0))
    # 17: closed circuit is forgotten; later bandwidth for it is ignored.
    ev.append(f"650 CIRC 17 BUILT {G},{M} PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED")
    ev.append(f"650 CIRC 17 CLOSED {G},{M} PURPOSE=HS_SERVICE_INTRO REASON=FINISHED")
    ev.append(bw(17, 50900, 0))
    ev.append("650 BW 0 0")
    # Rendguard: 1100 rend points, alternating the 0.1%-weight B and the heavy C.
    for i in range(1100):
        rp = "$" + ("B" if i % 2 == 0 else "C") * 40 + "~rp"
        ev.append(f"650 CIRC {1000 + i} BUILT {G},{M},{rp} PURPOSE=HS_SERVICE_REND "
                  "HS_STATE=HSSR_CONNECTING")
    # A rend point that is not in the consensus at all.
    ev.append(f"650 CIRC 5000 BUILT {G},{M},${'E' * 40}~x PURPOSE=HS_SERVICE_REND "
              "HS_STATE=HSSR_CONNECTING")
    return ev


WANT = {"CIRC", "BW", "ORCONN", "NETWORK_LIVENESS", "CIRC_BW", "CIRC_MINOR"}


def main():
    os.makedirs(DATADIR, exist_ok=True)
    with open(os.path.join(DATADIR, "cached-microdesc-consensus"), "w") as fh:
        fh.write("network-status-version 3 microdesc\n" + WEIGHTS)
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(SOCK)
    os.chmod(SOCK, 0o777)
    srv.listen(4)
    srv.settimeout(120)
    closes = []
    conn, _ = srv.accept()
    conn.settimeout(30)
    f = conn.makefile("rwb", buffering=0)
    subscribed = set()
    replayed = False

    def send(s):
        f.write(s.encode() + b"\r\n")

    def handle(line):
        nonlocal subscribed
        cmd = line.split(" ", 1)[0].upper()
        arg = line[len(cmd):].strip()
        if cmd == "PROTOCOLINFO":
            send("250-PROTOCOLINFO 1")
            send("250-AUTH METHODS=NULL")
            send('250-VERSION Tor="0.4.9.16"')
            send("250 OK")
        elif cmd in ("AUTHENTICATE", "RESETCONF", "SETCONF", "TAKEOWNERSHIP"):
            send("250 OK")
        elif cmd == "GETINFO":
            key = arg
            if key == "version":
                send("250-version=0.4.9.16")
                send("250 OK")
            elif key == "ns/all":
                send("250+ns/all=")
                for l in NS.split("\r\n"):
                    send(l)
                send(".")
                send("250 OK")
            elif key == "orconn-status":
                send(f"250-orconn-status={G} CONNECTED")
                send("250 OK")
            elif key == "network-liveness":
                send("250-network-liveness=up")
                send("250 OK")
            elif key.startswith("ip-to-country"):
                send(f"250-{key}=0")
                send("250 OK")
            else:
                send(f"552 Unrecognized key \"{key}\"")
        elif cmd == "GETCONF":
            out = []
            for k in arg.split():
                v = {"datadirectory": DATADIR}.get(k.lower())
                out.append(f"{k}={v}" if v else k)
            for i, l in enumerate(out):
                send(("250 " if i == len(out) - 1 else "250-") + l)
        elif cmd == "SETEVENTS":
            subscribed = set(arg.upper().split())
            send("250 OK")
        elif cmd == "CLOSECIRCUIT":
            closes.append(arg.split()[0])
            send("250 OK")
        elif cmd == "QUIT":
            send("250 closing connection")
        else:
            send(f"510 Unrecognized command \"{cmd}\"")

    buf = b""
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            chunk = conn.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        while b"\r\n" in buf:
            line, buf = buf.split(b"\r\n", 1)
            handle(line.decode())
        if not replayed and WANT <= subscribed:
            replayed = True
            time.sleep(1.0)
            for e in events():
                send(e)
            conn.settimeout(4)   # collect the CLOSECIRCUITs, then stop
    conn.close()
    srv.close()
    json.dump({"closes": closes, "subscribed": sorted(subscribed)}, open(OUT, "w"))


main()
