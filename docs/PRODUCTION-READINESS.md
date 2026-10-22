# Production-readiness checklist

Every image-bearing row was re-run against **commit `66dc20f`** on **2026-10-19**,
after the package pin refresh (tor 0.4.9.14, python3 3.12.15, openssl 3.5.9,
zlib 1.3.2-r1). `entrypoint.py`, `healthcheck.py` and both compose files are
unchanged since the previous full pass on `8d66c4d` (2026-09-26), so the reboot
and rootless rows (R13-R15) are carried forward from it and say so. Where a row
could not be re-run, it says so and gives the date and commit of the result it
does quote.

The raw output of the automatable rows is captured by `scripts/collect_evidence.py`
into the release **evidence bundle** (`signatures/README.md`), which is signed
alongside the image digest. A row marked "manual" is one whose output is a live
observation (an address, a memory curve) that the script records as a command and
result rather than reproducing.

| # | Claim | Command | Result |
|---|---|---|---|
| R1 | The image builds bit-for-bit reproducibly | two fresh clones (one under umask 007, one under 022), `--no-cache`, `buildx --platform linux/amd64,linux/arm64 --output type=oci`, compare `index.json` digests; plus CI `reproducibility` (amd64) | **pass (2.1.1)** (`0037c38`, tag `v2.1.1`) - both two-platform builds `sha256:889da0a9d21d7d3af87cba102e1c6ff5ea4b2618c46ea4cec26785a43ed89645`, byte-identical archives, one clone under umask 007 and one under 022 (buildx v0.19.3, BuildKit v0.30.0); the published index on both registries is that digest. 2.1.0 reproduced only under one umask: its `COPY` layers recorded the clone's file modes (fixed in 2.1.1). The digest moves with each commit's `SOURCE_DATE_EPOCH`, so the release tag's own pair of builds is compared again at publish time |
| R2 | Two onions from one container | the committed `docker-compose.yml` plus a second `*_TOR_SERVICE_HOSTS`; `status` and `show` for each | **pass** (`66dc20f`) - both ready after recreate; `show` agrees for each; both return HTTP 200 over Tor |
| R3 | The committed `docker-compose.yml` boots | `docker compose up -d` with only the image (and, on this host, the subnets) overridden | **pass** (`66dc20f`) - `status` ready 19s after `up` (fresh key); host-side `doctor` ok, 16 checks, no failures, no warnings |
| R4 | `sbom` emits a valid SPDX document | `hiddenforge sbom --image ...` | **pass (2.1.1)** - SPDX-2.3, 43 packages, from `sambent.dev/sam/hiddenforge:2.1.1` |
| R5 | `verify-image` verifies a published release | run without `--skip-registry` against `sambent.dev`, with stock tools only (Alpine 3.23: OpenSSL, ssh-keygen, skopeo; no pqsign) | **pass (2.1.1)** - in a stock `alpine:3.23.5` container (OpenSSL 3.5.9, ssh-keygen, skopeo; no pqsign), from a fresh clone of master (`fea0ff8`): the registry digest equals the signed `sha256:889da0a9...`; ML-DSA-65 verifies through OpenSSL against the pinned key; exit 0 with `--allow-pq-only` (`complete: false`), and exit 1 without it, because there is no SSH-FIDO2 signature. 2.0.4 passed with both halves |
| R6 | The arm64 image runs on an arm64 kernel | full-system arm64 VM (QEMU `virt`, Debian 13 arm64, real aarch64 kernel 6.12; emulated CPU), the shipped compose file | **pass** (`66dc20f`, Debian 13 arm64, kernel 6.12.113) - ready in 333s on the emulated CPU, descriptor uploaded, HTTP 200 over Tor (fetched from the host's Tor client, and from a fresh client inside the VM in 69s); Tor at uid 100 with `Seccomp: 2`, `Seccomp_filters: 2` (runtime profile + `Sandbox 1`, same as amd64); Tor killed, container restarted (restarts=1) with the same address and ready again; `doctor` no failures, no warnings. The VM's long-running system Tor client failed its first fetches (`No more HSDir available to query`) after slow circuit builds through one guard, and kept that failure cached; the host and a fresh in-VM client both reached the service. Not real ARM hardware |
| R7 | The built image is clean | CI `security`: trivy image (HIGH/CRITICAL, fixable), trivy fs, semgrep, gitleaks over every commit | **pass** - trivy on the `66dc20f` image: 0 vulnerabilities at any severity (pinned `aquasec/trivy@sha256:ab70a022...`, the CI image). The full CI `security` job on `8d66c4d`: every scan step passed, no leaks. Run locally with `forgejo-runner exec`, where the final artifact-upload step cannot run (no artifact server); that step is the only one that failed |
| R8 | Every in-image CLI subcommand works | CI `build-and-test` plus the documented `docker run <image> ...` forms | **pass** (`66dc20f`) - `version`/`info` contract (2.1.0, Tor 0.4.9.14), in-image `vanity` (also with `--network none`), `setup` writes its four files; live E2E 5/5 in 110s |
| R9 | Image contents are what they should be | inspect the built image | **pass** (`66dc20f`) - 40 apk packages (tor 0.4.9.14-r0, python3 3.12.15-r0, openssl 3.5.9-r0, zlib 1.3.2-r1, su-exec 0.3-r0); no pip/gcc/cc/make/curl/sshd (BusyBox's `wget` applet is present, as in every Alpine image); no `hs_ed25519*` or `.onion` baked in; `setuptools` absent |
| R10 | Tor accepts the generated torrc | `tests/test_torrc.py` in the image | **pass** (`66dc20f`) - 17/17 checks, Tor 0.4.9.14, on amd64 and arm64 |
| R11 | Untrusted parsers survive fuzzing | `fuzz/fuzz_parsers.py` under atheris (now both runtimes' `setup` files) | **pass** (`66dc20f`) - 168,320 runs in 600s, no crash (and 279,948 in 900s on `7f0287d`). The previous run, on `7c21c04`, found a command injection in a `deploy.sh` line added that day (see Findings) |
| R12 | The service is stable over time | 90s sample on the final image; plus a soak of several hours on earlier images of the same runtime code, with the backend moved to a new IP 20 times | **pass** (`66dc20f`): two services, memory flat 179-180 MiB, PIDs 39, 0 restarts, healthy. Soak: every backend move followed (torrc IP == backend IP in 42/42 samples), 0 unexplained restarts, memory flat |
| R13 | A real host reboot brings the onion back (Docker) | Debian 13 VM, Docker 26, the shipped compose file; `systemctl reboot` three times, each proven by a new `boot_id` | **pass** (earlier image, same runtime code and compose file) - back on its own every time, same address, backend mapping correct, ready 27-252s after boot (the slow one: a fresh directory fetch over emulated networking) |
| R14 | A real host reboot brings the onion back (rootless Podman) | Ubuntu 24.04 VM, Podman 4.9.3, linger + `podman-restart.service` enabled, real reboots | **pass with `restart: always`** (earlier image, same runtime code and compose file) (now shipped) - back ready with the same address. With the old `unless-stopped` both containers stayed Exited |
| R15 | Rootless Podman applies every declared limit | Docker Compose v2 (Ubuntu's `docker-compose-v2`, no Docker engine) on the rootless Podman socket, the shipped `podman-compose.yml` | **pass** (earlier image, same compose file) - `pids.max` 256, `memory.swap.max` 0, DNS isolated; Tor killed, restarted, same address, HTTP 200; `doctor` no failures, no warnings |
| R16 | "Ready" means clients can reach it | fresh key and restart; compare Tor's HS_DESC UPLOADED events with the moment of ready, fetch at that moment | **pass** (`66dc20f`) - ready 1s after the first upload (fresh) and in the same second (restart, fetched by a Tor client that had never seen the address); the fetch returned HTTP 200 both times. A client that fetched the descriptor *before* the restart holds stale introduction points: its first fetch at the ready moment timed out and its retry succeeded after 67s. That is the client's cache, not readiness, and it heals without action. Before the fix, ready came ~45s before the upload |

CI on the `v2.1.0` tag (`c5514b9`, sambent.dev Actions, 2026-10-21): lint, unit
(mutation spot-check 63/63; 99.03% coverage of `entrypoint.py`, re-measured on the
tag with the job's own command), mutation (the full mutmut run and gate),
build-and-test (live E2E), security (trivy, semgrep, gitleaks) and reproducibility
all pass. `pin-freshness` runs on schedule and dispatch only; it passed on the same
commit in a dispatch run that day.

CI on the `v2.1.1` tag (`0037c38`, 2026-10-22): lint, unit, mutation,
build-and-test (live E2E), security and reproducibility (now two clones under
umask 007 and 022) all pass; master at the same commit passed the same jobs.
2.1.1 changes the Dockerfile's `COPY` modes and CI only, so the image-bearing
rows above other than R1, R4 and R5 are carried forward from `66dc20f`.

Supporting detail for the rows that produced a finding follows.

## R1: why a fresh clone is required

`rewrite-timestamp` *clamps* mtimes to `SOURCE_DATE_EPOCH` (`min(mtime, epoch)`),
it does not set them equal. In a fresh clone every file's mtime is the checkout
time (newer than the commit), so all of them clamp to the same value. In a
working tree edited at different times, a file *older* than `SOURCE_DATE_EPOCH`
keeps its own mtime and lands in the layer verbatim, producing a digest only that
tree can generate. Reproduce from a pristine checkout (see `signatures/README.md`).

## R5: this commit is not the signed release

The published, signed digest is **2.0.4**. `66dc20f` is built, tested and
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

- **2026-09-26, R11 re-run: a command injection in `deploy.sh`,** in a line
  added that day, never released. A key path holding `"` closed the echo it
  was quoted inside and the rest ran as shell (measured: a crafted `--keys`
  made the script create a file). Fixed; a regression test executes the line
  with two payloads. CI had passed with it present -- its payloads were all
  newlines, which the validator refuses anyway -- so CI now carries a property
  test with the fuzz target's structure invariant, which on its first run found
  a second fault: non-BMP characters in the key path produced a fragment Docker
  Compose refused to parse. Fixed.
- **2026-09-26, R3: `doctor` failed for ever over a retired service's kept
  keys.** Now a warning that says so; a configured service still fails.

- **R3 exposed a shipped bug:** `docker-compose.yml` and `podman-compose.yml` set
  `ulimits.nproc: 256`. RLIMIT_NPROC is per host uid, and the tor user is uid 100,
  shared with i2pforge's i2pd. With uid 100 already at high thread counts,
  `su-exec` `setuid()` returned EAGAIN and Tor never started, silently (the image
  logs to `/dev/null`, so it looked like a restart loop). Fixed: `nproc` removed,
  `pids_limit` remains the cap, and the entrypoint probes `su-exec tor true` and
  fails with a named error.
- **R7 exposed a vulnerable TLS stack:** the image shipped OpenSSL 3.5.7-r0
  (20 CVEs, 2 HIGH). The HIGH ones are QUIC-server issues and Tor has no QUIC,
  but the image should not ship a known-vulnerable OpenSSL. OpenSSL is now
  pinned explicitly rather than inherited from the base digest (first 3.5.8-r0;
  3.5.9-r0 since Alpine pruned it); rescan clean.
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
