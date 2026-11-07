#!/usr/bin/env python3
"""Verify the HiddenForge build-input archive before a build uses it.

The image is built offline from this archive (`--build-context inputs=<dir>`),
so this is the check that what is in it is what its publishers signed:

  1. every file matches MANIFEST.sha256, and nothing unlisted is present;
  2. each APKINDEX carries a valid RSA signature from a key pinned in
     signatures/ (Docker's DHI apk key; Alpine's for the Alpine index);
  3. every .apk matches the checksum its signed index lists for it;
  4. the Tor tarball's SHA-256 file is signed by a Tor release key pinned in
     signatures/tor-release-keys.gpg, and the tarball matches it;
  5. the vendored libc crate matches the checksum Cargo.lock pins.

    python3 scripts/verify_inputs.py <inputs dir>     # exit 0 = all verified

Needs openssl and gpg on the host. Network: none.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SIG = REPO / "signatures"
TOR_TARBALL = "tor-0.4.9.16.tar.gz"
# Tor release-signing keys accepted (primary fingerprints, from Tor's own
# verification page): David Goulet, Alexander Faeroy, Nick Mathewson.
TOR_FPRS = {
    "B74417EDDF22AC9F9E90F49142E86A2A11F48D36",
    "1C1BC007A9F607AA8152C040BEA7B180B1491921",
    "2133BC600AB133E1D826D173FE43009C4607B1FB",
}


def gzip_members(b: bytes) -> list[tuple[bytes, bytes]]:
    out, off = [], 0
    while off < len(b):
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        data = d.decompress(b[off:])
        used = len(b) - off - len(d.unused_data)
        out.append((b[off : off + used], data))
        off += used
    return out


def verify_index(path: Path) -> dict[str, str]:
    """Check the index signature against a pinned key; return name-version -> C:."""
    m = gzip_members(path.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(m[0][1])) as sig_tar:
        member = next(x for x in sig_tar.getmembers() if x.name.startswith(".SIGN.RSA"))
        keyname = member.name[len(".SIGN.RSA.") :]
        sig = sig_tar.extractfile(member).read()
    if keyname.startswith("dhi-apk@"):
        keyname = "dhi-apk@docker-0F81AD7700D99184.rsa.pub"
    key = SIG / keyname
    if not key.is_file():
        raise SystemExit(
            f"FAIL {path.name}: signed by {keyname}, which is not pinned in signatures/"
        )
    signed = b"".join(x[0] for x in m[1:])
    with tempfile.TemporaryDirectory() as t:
        (Path(t) / "s").write_bytes(sig)
        (Path(t) / "d").write_bytes(signed)
        ok = any(
            subprocess.run(
                ["openssl", "dgst", f"-{h}", "-verify", str(key), "-signature", f"{t}/s", f"{t}/d"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            == "Verified OK"
            for h in ("sha1", "sha256")
        )
    if not ok:
        raise SystemExit(f"FAIL {path.name}: signature does not verify with {keyname}")
    with tarfile.open(fileobj=io.BytesIO(b"".join(x[1] for x in m[1:]))) as itar:
        raw = itar.extractfile("APKINDEX").read()
    idx = raw.decode()
    entries = {}
    for blk in idx.split("\n\n"):
        f = dict(line.split(":", 1) for line in blk.splitlines() if ":" in line)
        if "P" in f:
            entries[f"{f['P']}-{f['V']}"] = f["C"]
    print(f"ok   {path.name}: signed by {keyname}, {len(entries)} entries")
    return entries


def apk_checksum(path: Path) -> str:
    m = gzip_members(path.read_bytes())
    # SHA-1 is what the apk v2 index format records; the index itself is RSA-signed.
    return "Q1" + base64.b64encode(hashlib.sha1(m[1][0], usedforsecurity=False).digest()).decode()


def main(inputs: Path) -> int:
    # 1. manifest
    listed = {}
    for line in (inputs / "MANIFEST.sha256").read_text().splitlines():
        digest, name = line.split(None, 1)
        listed[name.lstrip("./").lstrip("*")] = digest
    present = {
        str(p.relative_to(inputs))
        for p in inputs.rglob("*")
        if p.is_file() and p.name != "MANIFEST.sha256"
    }
    if set(listed) != present:
        raise SystemExit(
            f"FAIL manifest: unlisted {sorted(present - set(listed))[:5]}, "
            f"missing {sorted(set(listed) - present)[:5]}"
        )
    for name, digest in listed.items():
        if hashlib.sha256((inputs / name).read_bytes()).hexdigest() != digest:
            raise SystemExit(f"FAIL manifest: {name} does not match")
    print(f"ok   MANIFEST.sha256: {len(listed)} files")
    # 2+3. indexes and packages
    for arch in ("x86_64", "aarch64"):
        for repo, index in (
            ("apk", f"APKINDEX-{arch}.tar.gz"),
            ("apk-alpine", f"APKINDEX-alpine-main-{arch}.tar.gz"),
        ):
            entries = verify_index(inputs / "index" / index)
            pkgs = sorted((inputs / repo / arch).glob("*.apk"))
            for p in pkgs:
                want = entries.get(p.name[:-4])
                try:
                    got = apk_checksum(p)
                except (zlib.error, IndexError):
                    got = None
                if want is None or got != want:
                    raise SystemExit(
                        f"FAIL {repo}/{arch}/{p.name}: not what the signed index lists"
                    )
            print(f"ok   {repo}/{arch}: {len(pkgs)} packages match the signed index")
    # 4. tor
    tor = inputs / "tor"
    with tempfile.TemporaryDirectory() as home:
        env = {**os.environ, "GNUPGHOME": home}
        subprocess.run(
            ["gpg", "-q", "--import", str(SIG / "tor-release-keys.gpg")],
            env=env,
            check=True,
            capture_output=True,
        )
        st = subprocess.run(
            [
                "gpg",
                "--status-fd",
                "1",
                "--verify",
                str(tor / f"{TOR_TARBALL}.sha256sum.asc"),
                str(tor / f"{TOR_TARBALL}.sha256sum"),
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        good = {
            line.split()[-1]
            for line in st.stdout.splitlines()
            if line.startswith("[GNUPG:] VALIDSIG")
        }
        # VALIDSIG ... <primary fingerprint> is the last field.
        if not good & TOR_FPRS:
            raise SystemExit("FAIL tor: no valid signature from a pinned Tor release key")
    want = (tor / f"{TOR_TARBALL}.sha256sum").read_text().split()[0]
    if hashlib.sha256((tor / TOR_TARBALL).read_bytes()).hexdigest() != want:
        raise SystemExit("FAIL tor: tarball does not match its signed SHA-256")
    print(
        f"ok   {TOR_TARBALL}: signed by {len(good & TOR_FPRS)} pinned Tor release key(s), "
        "hash matches"
    )
    # 5. cargo
    lock = (REPO / "hiddenforge-rs" / "Cargo.lock").read_text()
    want = lock.split('name = "libc"', 1)[1].split('checksum = "', 1)[1].split('"', 1)[0]
    got = json.loads((inputs / "cargo/vendor/libc/.cargo-checksum.json").read_text())["package"]
    if got != want:
        raise SystemExit("FAIL cargo: vendored libc does not match Cargo.lock")
    print("ok   cargo/vendor/libc: matches Cargo.lock")
    print("ALL INPUTS VERIFIED")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    sys.exit(main(Path(sys.argv[1])))
