# Dependencies: what the image is built from

3.0 is built offline from a locked set of inputs. `build-inputs.sha256` lists
every file with its SHA-256; `scripts/build_inputs.py verify` refuses an archive
that differs from it in any file, then checks each file against its publisher's
signature. Every version below was checked against its publisher on
**2026-11-11** and is the newest available: Tor's release directory, the live
DHI and Alpine 3.23 package indexes for both architectures (all 54 locked
packages), crates.io and mkp224o's repository. The exceptions are the base and
builder images, noted after each table.

## In the image

| Component | Version | From | Why it is there |
|---|---|---|---|
| Base | `dhi.io/static:20261020-musl-alpine3.23` (by digest) | Docker Hardened Images | musl, CA bundle, tzdata, `/etc/passwd`. Used unchanged |
| Tor | 0.4.9.16 | Tor Project release tarball, compiled in the build | The whole point. Relay and directory-authority code compiled out |
| `hiddenforge` | 3.0.0 | `hiddenforge-rs/` in this repository | Entrypoint, supervisor, in-image CLI, healthcheck, guard monitors, 2.x compatibility names |
| mkp224o | commit `5172c0fd` | vendored source, `vendor/` | Vanity address generator. Static binary, CC0-1.0 |
| `libcrypto3`, `libssl3` | 3.5.9-r1 | DHI apk | Tor's OpenSSL; also the key-sealing cipher |
| `libevent` | 2.1.13-r0 | DHI apk | Tor's event loop |
| `zlib` | 1.4-r0 | Alpine main | Tor's directory decompression. Alpine's build: DHI's 1.3.2-r2 carries CVE-2026-4738 (fixed by backport, but scanners report it) |
| `zstd-libs` | 1.5.7-r2 | DHI apk | Tor's directory compression |
| `xz-libs` | 5.8.4-r0 | DHI apk | Tor's directory compression |
| `libseccomp` | 2.6.1-r0 | DHI apk | Tor's `Sandbox 1` |
| `libcap2` | 2.78-r0 | DHI apk | Tor's capability handling |

One newer build exists: Docker rebuilt the `static` base tag after this
digest was adopted. Compared file by file, two things differ: `tzdata` 2026f in
place of 2026e, and a rebuild of the same `musl` 1.2.5-r24 whose code and data
(`.text`, `.rodata`, `.data`) are byte-identical; only its ELF note order and
build ID changed. Neither build has a known vulnerability, and nothing in the
image uses the time zone data for a security decision, so the verified digest
stays until the next real change; adopting a new base means verifying Docker's
signed provenance for the new digest first.

That is everything. There is no shell, package manager, interpreter or
coreutils. The names `su-exec`, `python3`, `cat`, `sh`, `test` and `true` are
the `hiddenforge` binary answering the exact commands 2.x ran, nothing else
(`hiddenforge-rs/src/compat.rs`).

## Build only

| Component | Version | From | Used for |
|---|---|---|---|
| C builder | `dhi.io/python` dev (by digest) | DHI | A musl toolchain to compile Tor and mkp224o. Its Python is not used |
| Rust builder | `dhi.io/rust` 1.91.1 dev (by digest) | DHI | Compiles `hiddenforge` |
| `libc` crate | 0.2.191 | crates.io, vendored | The Rust binary's only dependency; checked against `Cargo.lock` |
| headers and tools | see `build-inputs.sha256` | DHI apk (zlib from Alpine) | `-dev` packages, `fortify-headers`, `make`, `autoconf`, `automake`, `m4`, `perl`, `pkgconf`, `libsodium` (mkp224o, linked statically) |

Both builder tags have newer digests than the pinned ones. The Rust builder's
packages are identical to the pinned build's. The C builder's update moves
`expat`, `krb5-libs`, `python` and its own `zlib`; none of them reaches the
image: Tor is compiled and runs against the locked `zlib` 1.4-r0 from the input
archive, and nothing built here links expat, krb5 or Python. A builder change
also changes the release digest, so it is adopted with the next real change.

## How each kind of input is checked

| Input | Check |
|---|---|
| Every file | SHA-256 against `build-inputs.sha256` |
| Package index | RSA signature against a key pinned in `signatures/`: Docker's DHI apk key, Alpine's x86_64 and aarch64 keys |
| `.apk` package | Its checksum in the signed index |
| Tor tarball | Its SHA-256 file is signed by a Tor release key pinned in `signatures/tor-release-keys.gpg`; the build checks the hash again |
| mkp224o source | SHA-256 in the `Dockerfile` |
| `libc` crate | The checksum `Cargo.lock` pins |
| Base and builder images | By digest. Docker's signed provenance was verified when each digest was adopted |

11 of the 25 DHI packages per architecture carry a package signature from one
of seven per-build `abuild-*` keys that Docker does not publish, so that
signature cannot be checked. They are accepted through the signed index
instead: it lists each package's checksum and is signed with Docker's published
key.

## Why Alpine pruning no longer breaks builds

Alpine removes superseded packages from its index, which broke 2.x builds every
time a security update landed. 3.0 never fetches from Alpine while building:
the packages are in the archive. DHI's own repository keeps old versions, and
the archive is kept for the current release and the one before it.

## Updating an input

Do not edit a version number alone.

1. Download the new file from its publisher.
2. Add it to the inputs directory, remove what it replaces, and regenerate the
   manifest: `find . -type f ! -name MANIFEST.sha256 | LC_ALL=C sort | xargs sha256sum > MANIFEST.sha256`.
3. Copy that manifest to `build-inputs.sha256`.
4. `python3 scripts/build_inputs.py verify <dir>` must pass.
5. Rebuild, scan with both scanners at every severity, run the live tests.

An input change is a release, not an edit.
