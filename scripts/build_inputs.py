#!/usr/bin/env python3
"""The HiddenForge build-input archive: verify it, pack it, fetch it.

The image is built offline from this archive (`--build-context inputs=<dir>`).
`build-inputs.sha256` in this repository is the lock: the exact list of files a
release is built from, with their SHA-256. Nothing else is accepted.

  verify DIR       check DIR before a build uses it (exit 0 = all verified):
                     1. DIR holds exactly the files in the lock, with those hashes
                        (an older or substituted archive fails here, even if
                        everything in it is validly signed);
                     2. each APKINDEX carries a valid RSA signature from a key
                        pinned in signatures/ (Docker's DHI apk key; Alpine's);
                     3. every .apk matches the checksum its signed index lists;
                     4. the Tor tarball's SHA-256 file is signed by a pinned Tor
                        release key, and the tarball matches it;
                     5. the vendored libc crate matches Cargo.lock.
  pack DIR OUT     write DIR as one deterministic tar (same bytes every time),
                   after verifying it: the file published beside a release.
  fetch URL DIR    download that tar into the empty directory DIR, extract it
                   without trusting its paths, and verify it.

Needs openssl and gpg on the host. Network: only `fetch`.
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
import urllib.request
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SIG = REPO / "signatures"
LOCK = REPO / "build-inputs.sha256"
FETCH_MAX = 256 * 1024 * 1024
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


def read_manifest(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        digest, name = line.split(None, 1)
        out[name.lstrip("*").removeprefix("./")] = digest
    return out


def verify(inputs: Path) -> int:
    # 1. the lock
    locked = read_manifest(LOCK)
    if read_manifest(inputs / "MANIFEST.sha256") != locked:
        raise SystemExit(
            "FAIL lock: the archive's MANIFEST.sha256 is not build-inputs.sha256; "
            "this archive is not the one this source tree is built from"
        )
    present = {
        str(p.relative_to(inputs))
        for p in inputs.rglob("*")
        if p.is_file() and p.name != "MANIFEST.sha256"
    }
    if set(locked) != present:
        raise SystemExit(
            f"FAIL lock: unlisted {sorted(present - set(locked))[:5]}, "
            f"missing {sorted(set(locked) - present)[:5]}"
        )
    for p in inputs.rglob("*"):
        if p.is_symlink() or not (p.is_file() or p.is_dir()):
            raise SystemExit(f"FAIL lock: {p.relative_to(inputs)} is not a regular file")
    for name, digest in locked.items():
        if hashlib.sha256((inputs / name).read_bytes()).hexdigest() != digest:
            raise SystemExit(f"FAIL lock: {name} does not match")
    print(f"ok   build-inputs.sha256: {len(locked)} files, exactly as locked")
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
        # VALIDSIG ... <primary fingerprint> is the last field.
        good = {
            line.split()[-1]
            for line in st.stdout.splitlines()
            if line.startswith("[GNUPG:] VALIDSIG")
        }
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


def pack(inputs: Path, out: Path) -> int:
    verify(inputs)
    names = ["MANIFEST.sha256", *sorted(read_manifest(LOCK))]
    with (
        open(out, "wb") as raw,
        tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar,
    ):
        for name in names:
            data = (inputs / name).read_bytes()
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    print(f"wrote {out}: sha256 {hashlib.sha256(out.read_bytes()).hexdigest()}")
    return 0


def fetch(url: str, dest: Path) -> int:
    if not url.startswith("https://"):
        raise SystemExit("FAIL fetch: https only")
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise SystemExit(f"FAIL fetch: {dest} is not empty")
    with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 (https checked above)
        blob = r.read(FETCH_MAX + 1)
    if len(blob) > FETCH_MAX:
        raise SystemExit("FAIL fetch: archive larger than expected")
    allowed = {"MANIFEST.sha256", *read_manifest(LOCK)}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as tar:
        for m in tar.getmembers():
            # Only regular files the lock names: no links, devices, absolute or
            # parent paths, and nothing the lock does not list.
            if not m.isreg() or m.name not in allowed:
                raise SystemExit(f"FAIL fetch: unexpected entry {m.name!r} in the archive")
            target = dest / m.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(tar.extractfile(m).read())
    return verify(dest)


def main(argv: list[str]) -> int:
    match argv:
        case ["verify", d]:
            return verify(Path(d))
        case ["pack", d, out]:
            return pack(Path(d), Path(out))
        case ["fetch", url, d]:
            return fetch(url, Path(d))
    raise SystemExit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
