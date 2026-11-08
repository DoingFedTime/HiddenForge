#!/usr/bin/env python3
"""A stand-in for the vendored mkp224o, so vanity.py can be driven for real.

vanity.py's whole job is to run a generator and then refuse to install what it
produced unless the directory name, the hostname file and an independent
derivation from the public key all agree. Mocking the generator away tests none
of that. This script speaks the real command line instead --

    mkp224o -d <outdir> -t <threads> -n <count> [-S <secs> -T] <prefix>

-- and writes a real Tor key directory, so the checks either hold or they do not.

The key set is a FIXED, PUBLISHED test vector, not a secret: the same public key
tests/test_vanity.py derives its address from. The "secret" is 96 bytes of a
repeated pattern. Nothing here is usable as a hidden service identity, and
nothing generates real entropy.

Behaviour is steered by HF_FAKE_MKP224O:

    ok (default)  write one valid key directory for the vector address
    bench         a plain "generate normally" mode; the statistics come from
                  `-n 0`, which every mode honours the way the real binary does
    fail          exit 2 with a message on stderr, writing nothing
    empty         exit 0 having written nothing
    two           write two key directories
    silent        exit 0 writing nothing and printing nothing (bench with no stats)
    badname       write a directory whose name is not a valid onion address
    hostname      write a hostname file that disagrees with the directory name
    pubkey        write a public key that derives to a different address
    found_then_fail  write a valid key directory AND exit non-zero, which the real
                  generator can do; the caller must keep the key it produced
    fail_silent   exit 2 with nothing on stderr at all
    noise         write a valid key directory plus an unrelated directory beside it
    deaf          emit statistics and IGNORE SIGTERM, the way a wedged generator
                  would; only SIGKILL stops it. A closed stderr does not stop it
                  either: a caller that drops its end of the pipe is still waiting
                  on a live process

`-n <count>` is honoured: `-n 2` writes two key directories, so a caller that
asked for the wrong number gets the wrong number back.
"""
import argparse
import base64
import hashlib
import os
import signal
import sys
import time

# The published vector: tests/test_vanity.py derives VECTOR_ONION from this.
PUB_HEX = "04c6e8afdf77a1f03511d419b92f1c25de8de2d596973b6ecbeef24c9b0271f2"
OTHER_PUB_HEX = "0" * 64
PUBLIC_TAG = b"== ed25519v1-public: type0 =="
SECRET_TAG = b"== ed25519v1-secret: type0 =="


def derive(pub: bytes) -> str:
    checksum = hashlib.sha3_256(b".onion checksum" + pub + b"\x03").digest()[:2]
    return base64.b32encode(pub + checksum + b"\x03").decode("ascii").lower() + ".onion"


def write_keydir(outdir, pub_hex, dirname=None, hostname=None):
    pub = bytes.fromhex(pub_hex)
    onion = derive(pub)
    d = os.path.join(outdir, dirname if dirname is not None else onion)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "hostname"), "w", encoding="ascii") as fh:
        fh.write((onion if hostname is None else hostname) + "\n")
    with open(os.path.join(d, "hs_ed25519_public_key"), "wb") as fh:
        fh.write(PUBLIC_TAG.ljust(32, b"\x00") + pub)
    with open(os.path.join(d, "hs_ed25519_secret_key"), "wb") as fh:
        fh.write(SECRET_TAG.ljust(32, b"\x00") + bytes(range(64)))
    return d


def announce(keydir):
    """Print the found address on stdout, as the real generator does.

    It is the one place the directory holding a fresh secret key is named in
    plain text, which is why vanity.py sends this to DEVNULL.
    """
    print(os.path.basename(keydir), flush=True)
    return keydir


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-d", dest="outdir", required=True)
    ap.add_argument("-t", dest="threads", type=int, default=1)
    ap.add_argument("-n", dest="count", type=int, default=1)
    ap.add_argument("-S", dest="stats_every", type=int, default=None)
    ap.add_argument("-T", dest="wall_clock", action="store_true")
    ap.add_argument("prefix")
    args = ap.parse_args()

    # Record the invocation so a test can assert the argv without re-deriving it.
    record = os.environ.get("HF_FAKE_MKP224O_RECORD")
    if record:
        with open(record, "a", encoding="utf-8") as fh:
            fh.write(repr(sys.argv[1:]) + "\n")

    mode = os.environ.get("HF_FAKE_MKP224O", "ok")

    # `-n 0` means "never stop", which is how vanity.py asks for a measurement
    # rather than a search: statistics until killed. With any other count the
    # same mode does its search, so one configuration can benchmark and then
    # generate, exactly as the real binary does.
    if args.count == 0 and mode not in ("silent", "fail"):
        if mode == "deaf":
            # A generator that has stopped responding to a polite request to
            # stop. vanity.benchmark must escalate rather than wait for ever.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        rate = float(os.environ.get("HF_FAKE_MKP224O_RATE", "1000000"))
        elapsed = 0.0
        while True:
            elapsed += 1.0
            try:
                sys.stderr.write(
                    f">calc/sec:{rate:.6f}, succ/sec:0.000000, rest/sec:19.904261, "
                    f"elapsed:{elapsed:.6f}sec\n")
                sys.stderr.flush()
            except BrokenPipeError:
                if mode != "deaf":
                    raise
            time.sleep(0.05)
            # Bounded, unlike the real binary. A caller that asks for statistics
            # forever and then waits for an exit is a defect; letting this hang
            # would turn that into a test-suite hang instead of a failure.
            if elapsed > float(os.environ.get("HF_FAKE_MKP224O_MAX", "30")):
                return 0

    if mode == "silent":
        time.sleep(float(os.environ.get("HF_FAKE_MKP224O_SLEEP", "0.2")))
        return 0

    if mode == "fail":
        sys.stderr.write("fake mkp224o: exploded\n")
        return 2

    if mode == "fail_silent":
        return 2

    if mode == "found_then_fail":
        announce(write_keydir(args.outdir, PUB_HEX))
        sys.stderr.write("fake mkp224o: found one, then tripped over\n")
        return 2

    if mode == "noise":
        announce(write_keydir(args.outdir, PUB_HEX))
        os.makedirs(os.path.join(args.outdir, "not-a-key"), exist_ok=True)
        return 0

    if mode == "empty":
        return 0

    if mode == "two":
        announce(write_keydir(args.outdir, PUB_HEX))
        announce(write_keydir(args.outdir, OTHER_PUB_HEX))
        return 0

    if mode == "badname":
        # Ends in .onion so it survives the directory filter, but "0" and "1" are
        # not in the base32 alphabet, so it is not a v3 address.
        write_keydir(args.outdir, PUB_HEX, dirname="0" * 56 + ".onion")
        return 0

    if mode == "hostname":
        write_keydir(args.outdir, PUB_HEX, hostname="b" * 56 + ".onion")
        return 0

    if mode == "pubkey":
        # Directory name and hostname say one address; the public key derives to
        # another. Only the independent re-derivation catches this.
        onion = derive(bytes.fromhex(PUB_HEX))
        write_keydir(args.outdir, OTHER_PUB_HEX, dirname=onion, hostname=onion)
        return 0

    # -n says how many to find. Honouring it is what makes a caller that asks for
    # the wrong number visible.
    announce(write_keydir(args.outdir, PUB_HEX))
    if args.count > 1:
        announce(write_keydir(args.outdir, OTHER_PUB_HEX))
    return 0


if __name__ == "__main__":
    sys.exit(main())
