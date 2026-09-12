# Production-readiness checklist

The code fixes are done; these are the claims that were still *unproven* when I
called the branch "not unconditionally production-ready". Each is a runnable
check, not a code change. Work top-down; record the evidence.

| # | Claim to prove | How | Status |
|---|---|---|---|
| R1 | The image builds **bit-for-bit reproducibly** | two `buildx` builds with the same `SOURCE_DATE_EPOCH`, compare the OCI index digest | **done** — identical `sha256:7c343d91…`, and re-verified after the OpenSSL pin (`sha256:6996b0f5…` twice) |
| R2 | **Multiple onions** from one container actually work | two-service fragment + real stack, wait for both address files, assert they differ | **done** — `blog` and `tips` both published, distinct, both reported by `show`/`status` |
| R3 | The **committed `docker-compose.yml`** boots end to end | `docker compose up -d` with the shipped file, wait for the address | **done** — but it first **failed**, exposing the `ulimits.nproc` bug below; after the fix it publishes in 6s |
| R4 | `sbom` really produces a valid SPDX document | run it against the built image (syft), validate JSON + package count | **done** — SPDX-2.3, 43 packages, normalised namespace |
| R5 | `verify-image` **resolves the registry digest** and compares it | run without `--skip-registry` against `sambent.dev` | **done** — registry digest equals the signed 2.0.4 digest; YubiKey signature valid |
| R6 | The **arm64** image builds (the Dockerfile claims multi-arch) | `buildx --platform linux/arm64` | **blocked, partial-verified** — no builder available; see below |
| R7 | The **built image** (not just the source) is clean | trivy/grype against the image, including the base layer | **done** — first scan 20 CVEs (2 HIGH, OpenSSL), fixed, rescan **0 findings** |
| R8 | Every **in-image CLI subcommand** works with the final image | `docker run <image> <cmd>` for each | **done** — version/info/show/doctor/vanity/encrypt-key/setup all behave; one cosmetic warning on a fresh anonymous volume |
| R9 | The final **image contents** are what they should be | inspect the built image | **done** — no pip/gcc/curl/sshd/setuptools, no key material, 40 packages |
| R10 | Tor accepts the generated torrc | `tor --verify-config` in the image | **done** — "Configuration was valid" |
| R11 | **Coverage-guided fuzzing** of the untrusted parsers | `fuzz/fuzz_parsers.py` under atheris | **done** — found a real crash (surrogate encoding), fixed; 388k runs clean |
| R12 | The service is **stable over time** (no leak, no restart loop) | soak the shipped compose, sample memory/PIDs/restarts | **done** — 3 min: memory plateaus ~190 MiB of 512, PIDs steady at 37, 0 restarts |

Anything a check turns up becomes a code fix plus a regression test, then the
row is re-verified.

## Findings so far

- **Image contents audit (R9, added):** the final image has no `pip`, `pip3`,
  `setuptools`, `gcc`, `cc`, `make`, `curl` or `sshd`; no `hs_ed25519*` or
  `.onion` material in any layer; 40 apk packages; `tor 0.4.9.12-r0`,
  `openssl 3.5.8-r0`, `python3 3.12.14-r0`. The Python stdlib `urllib`/`ssl`
  remain, which is documented and expected.
- **Tor accepts the generated config (R10, added):** `tor --verify-config` on the
  torrc the entrypoint writes reports **"Configuration was valid"** (Tor
  0.4.9.12, OpenSSL 3.5.8). Run it with `--security-opt seccomp=unconfined` and
  the real `0700`/`0751` directory modes; without those, Tor's own sandbox setup
  fails and the check is a false alarm.
- **Hardened during this pass:** image-reference validation in the CLI (flag and
  YAML injection), a fail-closed fork-PR guard on the host-mode CI runner, and
  the threat model in `docs/THREAT-MODEL.md`.
- **Fuzzing found a real bug:** a lone surrogate in an environment value (from a
  non-UTF-8 byte) reached a log line and aborted startup. Fixed; the target now
  runs 388k inputs clean in 152s. See the CHANGELOG entry.
- **Soak (R12):** 3 minutes on the shipped compose, sampled every 20s. Memory
  settles at ~190 MiB of the 512 MiB limit with no upward trend, PIDs steady at
  37, restart count 0.

- **R3 exposed a shipped bug:** `docker-compose.yml` and `podman-compose.yml` set
  `ulimits.nproc: 256`. RLIMIT_NPROC is per host uid, and the tor user is uid 100,
  shared with other containers (i2pforge's i2pd). With uid 100 already at 366
  threads on this host, `su-exec` `setuid()` returned EAGAIN and Tor never
  started -- a silent restart loop because the image logs to `/dev/null`. Fixed:
  `nproc` removed, `pids_limit` remains the cap, and the entrypoint now probes
  `su-exec tor true` and fails with a named error.
- `docker network prune` was needed between runs: repeated e2e stacks exhausted
  Docker's default address pool (40 networks, most from other projects).
- **R7 exposed a vulnerable TLS stack:** the image shipped OpenSSL 3.5.7-r0
  (20 CVEs, 2 HIGH). The HIGH ones are QUIC-server issues and Tor has no QUIC,
  but the image should not ship a known-vulnerable OpenSSL. `openssl=3.5.8-r0`
  is now pinned explicitly in the apk install instead of inherited from the
  base digest, and the image rescan is **0 findings**.
- **R6 is blocked by the environment, not the code.** A full arm64 build needs
  qemu or an arm64 builder: neither was available, and local has no `binfmt_misc` qemu handler (`docker run
  --platform linux/arm64 alpine` fails `exec format error`). Installing qemu on
  this box was not done. What *was* verified:
  - the pinned base digest `sha256:fd791d74…` **is the multi-arch index**
    (`linux/arm64/v8` present), so `--platform linux/arm64` resolves correctly;
  - **every pinned apk version exists for aarch64** in the 3.23 index:
    tor `0.4.9.12-r0`, python3 `3.12.14-r0`, openssl `3.5.8-r0`,
    libsodium-static `1.0.20-r1`, build-base, autoconf, su-exec, py3-pip;
  - the mkp224o builder uses plain `./configure` (no `--enable-amd64-*` flag),
    so there is no amd64 assumption in the build.

  Run this once a builder exists (an arm64 engine, or qemu installed): `docker buildx build --platform linux/arm64,linux/amd64 .`
