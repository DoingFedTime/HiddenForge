# Production-readiness checklist

Every row was re-run against **commit `d32e236`** on **2026-09-26**, the last
commit that changes what goes into the image. Where a row could not be re-run, it
says so and gives the date and commit of the result it does quote.

The raw output of the automatable rows is captured by `scripts/collect_evidence.py`
into the release **evidence bundle** (`signatures/README.md`), which is signed
alongside the image digest. A row marked "manual" is one whose output is a live
observation (an address, a memory curve) that the script records as a command and
result rather than reproducing.

| # | Claim | Command | Result |
|---|---|---|---|
| R1 | The image builds bit-for-bit reproducibly | two fresh clones, `--no-cache`, `buildx --platform linux/amd64,linux/arm64 --output type=oci`, compare `index.json` digests; plus CI `reproducibility` (amd64) | **pass** (`d32e236`) - both two-platform builds `sha256:ccad326b85767e8fea980257835609b1c1b1593b4571b11b9416aaa3eaec1e64`; CI job passed |
| R2 | Two onions from one container | the committed `docker-compose.yml` plus a second `*_TOR_SERVICE_HOSTS`; `status` and `show` for each | **pass** (`d32e236`) - both published, `ready` 13s after recreate; `show` agrees for each |
| R3 | The committed `docker-compose.yml` boots | `docker compose up -d` with only the image (and, on this host, the subnets) overridden | **pass** (`d32e236`) - `status` ready and `healthy` in 14s; host-side `doctor` ok with no failures or warnings |
| R4 | `sbom` emits a valid SPDX document | `hiddenforge sbom --image ...` | **pass** (`d32e236`) - SPDX-2.3, 43 packages |
| R5 | `verify-image` verifies a published release | run without `--skip-registry` against `sambent.dev`, with stock tools only (Alpine 3.23: OpenSSL 3.5.8, ssh-keygen, skopeo; no pqsign) | **pass (2.0.4)** - registry digest equals the signed digest; SSH-FIDO2 and ML-DSA-65 both verify against the pinned keys; `VERIFIED`, exit 0. `d32e236` is not pushed or signed |
| R6 | The arm64 image runs | build `linux/arm64` under qemu-aarch64, run the in-image checks | **pass** (`d32e236`) - `aarch64`, Tor 0.4.9.13, 17/17 torrc checks, CLI contract; its manifest is inside the R1 index that reproduced |
| R7 | The built image is clean | CI `security`: trivy image (HIGH/CRITICAL, fixable), trivy fs, semgrep, gitleaks over every commit | **pass** (`d32e236`) - every scan step passed, no leaks. Run locally with `forgejo-runner exec`, where the final artifact-upload step cannot run (no artifact server); that step is the only one that failed |
| R8 | Every in-image CLI subcommand works | CI `build-and-test` plus the documented `docker run <image> ...` forms | **pass** (`d32e236`) - `version`/`info` contract, in-image `vanity` produces a key matching its prefix (also run with `--network none`), `setup` writes its four files |
| R9 | Image contents are what they should be | inspect the built image | **pass** (`d32e236`) - 40 apk packages; no pip/gcc/cc/make/curl/sshd (BusyBox's `wget` applet is present, as in every Alpine image); no `hs_ed25519*` or `.onion` baked in; `setuptools` absent |
| R10 | Tor accepts the generated torrc | `tests/test_torrc.py` in the image | **pass** (`d32e236`) - 17/17 checks, Tor 0.4.9.13, on amd64 and arm64 |
| R11 | Untrusted parsers survive fuzzing | `fuzz/fuzz_parsers.py` under atheris | **pass** (`d32e236`) - 325,521 runs in 900s, no crash |
| R12 | The service is stable over time | 90s soak, sample memory/PIDs/restarts | **pass** (`d32e236`) - memory 194-199 MiB, PIDs steady at 38, 0 restarts, `healthy` |

Live E2E (`HIDDENFORGE_E2E=1`, the release gate in CI `build-and-test`) passed on
`d32e236`: 5 tests, including a real `.onion` published through the emitted
fragment and a posture check of the running container.

Behaviour added on this commit and measured live, not only by unit tests: a
backend that is not up when the container starts is configured once it resolves
(restart 39s after it came up, then HTTP 200 over Tor); Vanguards is paused and
retried, never given up (back 600s after six forced crashes, no container
restart); no DNS query leaves the container (0 packets upstream over 72s of
backend downtime, on Docker and rootless Podman).

Supporting detail for the rows that produced a finding follows.

## R1: why a fresh clone is required

`rewrite-timestamp` *clamps* mtimes to `SOURCE_DATE_EPOCH` (`min(mtime, epoch)`),
it does not set them equal. In a fresh clone every file's mtime is the checkout
time (newer than the commit), so all of them clamp to the same value. In a
working tree edited at different times, a file *older* than `SOURCE_DATE_EPOCH`
keeps its own mtime and lands in the layer verbatim, producing a digest only that
tree can generate. Reproduce from a pristine checkout (see `signatures/README.md`).

## R5: this commit is not the signed release

The published, signed digest is **2.0.4**. `d32e236` is built, tested and
reproducible here but not pushed and not signed. A digest mismatch against
`hiddenforge.digest` therefore means "not yet signed", not "tampered with".

## R6: how arm64 was verified

With qemu's `binfmt_misc` handler for aarch64 registered on the builder
(`docker run --privileged --rm tonistiigi/binfmt --install arm64`), buildx builds
`linux/arm64` directly. The pinned base digest is the multi-arch index, every
pinned apk exists for aarch64, and mkp224o's `./configure` carries no amd64
assumption. Two builds from a fresh clone produced the same index digest, and the
loaded image passed the same in-image checks as amd64.

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

On a host whose Docker default address pools are used up by other projects, do
not prune networks that are not yours: give the test stacks explicit subnets
(`HIDDENFORGE_E2E_SUBNETS=10.251.0.0/24,10.252.0.0/24` for the E2E suite).
