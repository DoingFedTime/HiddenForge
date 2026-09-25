# Production-readiness checklist

Every row here was re-run against **commit `7913514`** on **2026-09-12**, not
against an earlier commit. That matters: eight code commits landed after the
first pass, so the earlier
results were stale and had to be reproduced under the code that is actually here.

The raw output of the automatable rows is captured by `scripts/collect_evidence.py`
into the release **evidence bundle** (`signatures/README.md`), which is signed
alongside the image digest. A row marked "manual" is one whose output is a live
observation (an address, a memory curve) that the script records as a command and
result rather than reproducing.

| # | Claim | Command | Result |
|---|---|---|---|
| R1 | Image builds bit-for-bit reproducibly | two `buildx --output type=oci`, compare `index.json` digest | **pass** (`7913514`) - both builds `sha256:93c364a61b7f72a76d8bb4c5b9f9dc91a2691ab4bc6ef384a5afb6ce18fa22da` |
| R2 | Two onions from one container | two `*_TOR_SERVICE_HOSTS`, resolvable backend, read both `.onion` files | **pass** - distinct addresses published (`blog`, `tips`) |
| R3 | The committed `docker-compose.yml` boots | `docker compose up -d`, wait for the address file | **pass** - publishes in seconds; name is lowercased (`myapp`) |
| R4 | `sbom` emits a valid SPDX document | syft against the built image, validate JSON | **pass** - SPDX-2.3, 43 packages |
| R5 | `verify-image` resolves the registry digest | run without `--skip-registry` against `sambent.dev` | **pass (2.0.4)** - registry digest equals the signed digest, YubiKey signature valid. Unchanged by this branch; the branch image is not pushed |
| R6 | The arm64 image builds | `buildx --platform linux/arm64` | **blocked, partial** - no arm64 builder available; see below |
| R7 | The built image is clean | trivy image scan, HIGH/CRITICAL | **pass** (`7913514`) - 0 findings |
| R8 | Every in-image CLI subcommand works | `docker run <image> <cmd>` | **pass** - `version`/`info`/`doctor` behave; `doctor` fails closed with a named error when no engine is on PATH |
| R9 | Image contents are what they should be | inspect the built image | **pass** - 40 apk packages; no pip/gcc/cc/make/curl/sshd; no `hs_ed25519*` or `.onion` baked in |
| R10 | Tor accepts the generated torrc | `tor --verify-config` in the image, as `tor` | **pass** - "Configuration was valid" (Tor 0.4.9.12, OpenSSL 3.5.8) |
| R11 | Untrusted parsers survive fuzzing | `fuzz/fuzz_parsers.py` under atheris | **pass** - 162,177 runs in 900s, no crash, re-run 2026-09-18 after the target gained the key-path invariants. The older 325,460-run figure was over a weaker property set and is superseded; see "R11, re-run" below |
| R12 | The service is stable over time | soak, sample memory/PIDs/restarts | **pass** - 90s: memory plateaus ~156 MiB, PIDs steady at 37, 0 restarts |

Supporting detail for the rows that produced a finding, and the arm64 position,
follows.

## R1: why a fresh clone is required

`rewrite-timestamp` *clamps* mtimes to `SOURCE_DATE_EPOCH` (`min(mtime, epoch)`),
it does not set them equal. In a fresh clone every file's mtime is the checkout
time (newer than the commit), so all of them clamp to the same value. In a
working tree edited at different times, a file *older* than `SOURCE_DATE_EPOCH`
keeps its own mtime and lands in the layer verbatim, producing a digest only that
tree can generate. Reproduce from a pristine checkout (see `signatures/README.md`).

## R5: this branch is not the signed release

The published, signed digest is **2.0.4**. The `2.1.0` branch image is built and
verified here but not pushed and not signed. A digest mismatch against
`hiddenforge.digest` therefore means "not yet signed", not "tampered with".

## R6: blocked by the environment, not by the code

A full arm64 build needs an arm64 builder. No second engine was available, and this box has no
`binfmt_misc` qemu handler (`docker run --platform linux/arm64 alpine` fails
`exec format error`). What *was* verified:

- the pinned base digest `sha256:fd791d74...` is the multi-arch index
  (`linux/arm64/v8` present), so `--platform linux/arm64` resolves;
- every pinned apk version exists for aarch64 in the 3.23 index: tor
  `0.4.9.12-r0`, python3 `3.12.14-r0`, openssl `3.5.8-r0`, libsodium-static
  `1.0.20-r1`, build-base, autoconf, su-exec, py3-pip;
- the mkp224o builder uses plain `./configure` (no `--enable-amd64-*` flag), so
  there is no amd64 assumption in the build.

Run this once a builder exists:
`docker buildx build --platform linux/arm64,linux/amd64 .`

**Decision:** the release index advertises `linux/arm64`, and the arm64
manifest has never been reproduced. `signatures/README.md` now states this
plainly and marks arm64 unverified, rather than a document implying two verified
platforms when one has never been built.

## Findings from the first pass, each fixed and re-verified

- **R3 exposed a shipped bug:** `docker-compose.yml` and `podman-compose.yml` set
  `ulimits.nproc: 256`. RLIMIT_NPROC is per host uid, and the tor user is uid 100,
  shared with i2pforge's i2pd. With uid 100 already at high thread counts,
  `su-exec` `setuid()` returned EAGAIN and Tor never started, silently (the image
  logs to `/dev/null`, so it looked like a restart loop). Fixed: `nproc` removed,
  `pids_limit` remains the cap, and the entrypoint probes `su-exec tor true` and
  fails with a named error.
- **R7 exposed a vulnerable TLS stack:** the image shipped OpenSSL 3.5.7-r0
  (20 CVEs, 2 HIGH). The HIGH ones are QUIC-server issues and Tor has no QUIC,
  but the image should not ship a known-vulnerable OpenSSL. `openssl=3.5.8-r0` is
  now pinned explicitly rather than inherited from the base digest; rescan clean.
- **Fuzzing (R11) found a real crash:** a lone surrogate in an environment value
  reached a log line and aborted startup. Fixed.
- **R11, re-run (2026-09-18).** The target gained a third invariant when the key
  path turned out to be an input channel reaching two operator-executed files, so
  the old run was no longer evidence for what the target now asserts. The re-run
  found a crash on its second input, and the crash was in the invariant rather
  than the code: it compared LINE COUNTS, and `shlex.quote` puts a newline inside
  single quotes, which adds a line without adding a command. Checked by hand that
  the rendered script is still valid bash and that the payload never becomes a
  command word. The invariant now compares STRUCTURE -- the fragment's parsed YAML
  keys and volumes, and deploy.sh's shell words -- which is what it was always
  trying to say and which a newline cannot trip. 162,177 runs, no crash.
- **R9 key-material audit:** no `hs_ed25519*` or `.onion` material in any layer.

`docker network prune` is needed between runs: repeated stacks exhaust Docker's
default address pool.
