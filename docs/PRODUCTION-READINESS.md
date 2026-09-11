# Production-readiness checklist

The code fixes are done; these are the claims that were still *unproven* when I
called the branch "not unconditionally production-ready". Each is a runnable
check, not a code change. Work top-down; record the evidence.

| # | Claim to prove | How | Status |
|---|---|---|---|
| R1 | The image builds **bit-for-bit reproducibly** | two `buildx` builds with the same `SOURCE_DATE_EPOCH`, compare the OCI index digest | **done** — identical `sha256:7c343d91c21e5b0ecd89be0b256a78a1af0c940876530dc3abe5e1f42550d4a0` |
| R2 | **Multiple onions** from one container actually work | two-service fragment + real stack, wait for both address files, assert they differ | **done** — `blog` and `tips` both published, distinct, both reported by `show`/`status` |
| R3 | The **committed `docker-compose.yml`** boots end to end | `docker compose up -d` with the shipped file, wait for the address | **done** — but it first **failed**, exposing the `ulimits.nproc` bug below; after the fix it publishes in 6s |
| R4 | `sbom` really produces a valid SPDX document | run it against the built image (syft), validate JSON + package count | **done** — SPDX-2.3, 43 packages, normalised namespace |
| R5 | `verify-image` **resolves the registry digest** and compares it | run without `--skip-registry` against `sambent.dev` | **done** — registry digest equals the signed 2.0.4 digest; YubiKey signature valid |
| R6 | The **arm64** image builds (the Dockerfile claims multi-arch) | `buildx --platform linux/arm64` | **blocked** - no arm64 builder, no local qemu build (see below) |
| R7 | The **built image** (not just the source) is clean | trivy/grype against the image, including the base layer | **done** — first scan 20 CVEs (2 HIGH, OpenSSL), fixed, rescan **0 findings** |
| R8 | Every **in-image CLI subcommand** works with the final image | `docker run <image> <cmd>` for each | **done** — version/info/show/doctor/vanity/encrypt-key/setup all behave; one cosmetic warning on a fresh anonymous volume |

Anything a check turns up becomes a code fix plus a regression test, then the
row is re-verified.

## Findings so far

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
- **R6 is blocked, not skipped:** no arm64-capable builder was available, so the arm64 build has not been run
  yet. Run it on a machine that has one: `docker buildx build --platform linux/arm64 .`
