# Production-readiness checklist

Every row was re-run against **commit `390e2da`** on **2026-09-25**, the last
commit that changes what goes into the image (later commits touch only docs and
tests). Where a row could not be re-run, it says so and gives the date and commit
of the result it does quote.

The raw output of the automatable rows is captured by `scripts/collect_evidence.py`
into the release **evidence bundle** (`signatures/README.md`), which is signed
alongside the image digest. A row marked "manual" is one whose output is a live
observation (an address, a memory curve) that the script records as a command and
result rather than reproducing.

| # | Claim | Command | Result |
|---|---|---|---|
| R1 | amd64 image builds bit-for-bit reproducibly | CI `reproducibility`: two `buildx --output type=oci` builds, compare `index.json` digests | **pass** (`390e2da`) - both builds `sha256:60f41e94dfd14dcd930ed45977249e682406cf401ae13b9b54aee38ef848afd7` |
| R2 | Two onions from one container | the committed `docker-compose.yml` plus a second `*_TOR_SERVICE_HOSTS`; read both `.onion` files | **pass** (`390e2da`) - both published in 10s; `show` agrees for each |
| R3 | The committed `docker-compose.yml` boots | `docker compose up -d` with only the image overridden | **pass** (`390e2da`) - `healthy`, `status` ready, host-side `doctor` ok with no failures or warnings |
| R4 | `sbom` emits a valid SPDX document | `hiddenforge sbom --image ...` | **pass** (`390e2da`) - 43 packages |
| R5 | `verify-image` resolves the registry digest | run without `--skip-registry` against `sambent.dev` | **pass (2.0.4)** - the published, signed digest verifies against the pinned keys with both signatures. `390e2da` is not pushed or signed |
| R6 | The arm64 image builds reproducibly and runs | two `buildx --platform linux/arm64` OCI builds under qemu-aarch64, then run the image | **pass** (`390e2da`) - both builds `sha256:f472ee06b4949aad94212b035c6a730722e86c3a51b0c64e5599a91cabea7f6f`; runs as `aarch64`, 17/17 torrc checks, CLI contract, Tor 0.4.9.13 |
| R7 | The built image is clean | CI `security`: trivy image (HIGH/CRITICAL, fixable), trivy fs, semgrep, gitleaks over every commit | **pass** (`390e2da`) - 0 findings; 369 commits scanned, no leaks |
| R8 | Every in-image CLI subcommand works | CI `build-and-test` plus the documented `docker run <image> ...` forms | **pass** (`390e2da`) - `version`/`info` contract, in-image `vanity` produces a key matching its prefix, `setup` writes its four files |
| R9 | Image contents are what they should be | inspect the built image | **pass** (`390e2da`) - 40 apk packages; no pip/gcc/cc/make/curl/sshd (BusyBox's `wget` applet is present, as in every Alpine image); no `hs_ed25519*` or `.onion` baked in; `setuptools` absent |
| R10 | Tor accepts the generated torrc | `tests/test_torrc.py` in the image | **pass** (`390e2da`) - 17/17 checks, Tor 0.4.9.13, on amd64 and arm64 |
| R11 | Untrusted parsers survive fuzzing | `fuzz/fuzz_parsers.py` under atheris | **pass (2026-09-18)** - 162,177 runs in 900s, no crash. The target has not changed since; on 2026-09-25 it was driven directly (not coverage-guided) with 20,000 seeded random inputs (`random.Random(20260925)`) against the current code, no exception |
| R12 | The service is stable over time | 90s soak, sample memory/PIDs/restarts | **pass** (`390e2da`) - memory flat at 192-193 MiB, PIDs steady at 37, 0 restarts, `healthy` |

Live E2E (`HIDDENFORGE_E2E=1`, the release gate in CI `build-and-test`) passed on
`390e2da`: 4 tests in 46s, including a real `.onion` published through the emitted
fragment and a posture check of the running container.

Supporting detail for the rows that produced a finding follows.

## R1: why a fresh clone is required

`rewrite-timestamp` *clamps* mtimes to `SOURCE_DATE_EPOCH` (`min(mtime, epoch)`),
it does not set them equal. In a fresh clone every file's mtime is the checkout
time (newer than the commit), so all of them clamp to the same value. In a
working tree edited at different times, a file *older* than `SOURCE_DATE_EPOCH`
keeps its own mtime and lands in the layer verbatim, producing a digest only that
tree can generate. Reproduce from a pristine checkout (see `signatures/README.md`).

## R5: this commit is not the signed release

The published, signed digest is **2.0.4**. `390e2da` is built, tested and
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

`docker network prune` is needed between runs: repeated stacks exhaust Docker's
default address pool.
