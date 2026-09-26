# Vendored sources

Everything here is build-time only. Nothing in this directory is copied into the
runtime image except the compiled binary produced from it.

## mkp224o

| | |
|---|---|
| Upstream | https://github.com/cathugger/mkp224o |
| Commit | `5172c0fd71740ca0b11da8149a2575dcf331d7ab` (2024-02-15) |
| Archive | `mkp224o-5172c0fd.tar.gz` |
| SHA256 | `1f951ed82577436fe2c160c01f7754170010137c2182eae7e47fce65f000dc8d` |
| Licence | **CC0-1.0** (public-domain dedication); see `COPYING.txt` inside the archive |

`mkp224o` is the vanity-address generator used by `hiddenforge vanity`. It is
vendored rather than fetched at build time so the image builds offline and
reproducibly; the `Dockerfile` verifies the SHA256 above before extracting, so a
corrupted or substituted archive fails the build loudly.

The archive is a deterministic `git archive` of the pinned commit:

```bash
git clone --depth 1 https://github.com/cathugger/mkp224o
cd mkp224o && git checkout 5172c0fd71740ca0b11da8149a2575dcf331d7ab
git archive --format=tar --prefix=mkp224o/ HEAD | gzip -n > mkp224o-5172c0fd.tar.gz
sha256sum mkp224o-5172c0fd.tar.gz   # must equal the value in the table above
```

`gzip -n` omits the timestamp and original filename, so the archive is
byte-identical across machines and re-runs. Re-verify the hash after any
regeneration; the `Dockerfile` will refuse to build otherwise.

### Why mkp224o and not a Python generator

A v3 `.onion` address is `base32(PUBKEY || CHECKSUM || 0x03)`. `mkp224o` is a
purpose-built, multithreaded Ed25519 brute-forcer that reaches millions of keys
per second; a pure-Python implementation is several orders of magnitude slower
and would make anything past a 3–4 character prefix impractical. It writes keys
in Tor's own on-disk format (64-byte `hs_ed25519_public_key`, 96-byte
`hs_ed25519_secret_key`, `hostname`), so the output drops straight into
`HiddenServiceDir`.

### Build notes (why the Dockerfile looks the way it does)

- Statically linked against `libsodium` (`libsodium-static` in the builder) so
  the runtime image needs **no** libsodium package: the binary is the only
  artefact that ships.
- `CFLAGS="-O3"` is passed explicitly. Upstream's `configure` otherwise injects
  `-march=native`, which both breaks bit-for-bit reproducibility (the binary
  differs per build host) and can emit instructions that fault on a different
  CPU than the one that built the image.
- Built in a separate `FROM` stage; the final image copies only the stripped
  binary.
