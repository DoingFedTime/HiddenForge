# Production readiness: 3.0.0

What was checked on 3.0.0, how, and what each check showed. It covers tag
`v3.0.0` (commit `56d13bc`) and the image built from it, whose index digest is
`sha256:5024c341017525b404882e4501c0181eeaddefa3ebab791129a4bb8c893b895b`. This
record is for 3.0.0 and has not been rewritten for 3.0.1. Everything below was measured on that image
on 2026-11-15 unless a row says otherwise. A sentence here is not evidence: the automatable rows are produced as raw output by
`scripts/collect_evidence.py` (see `signatures/README.md`), and the rest give the
command so you can repeat them.

Each row names what it does **not** show. The last section lists what was not
tested at all.

| # | Claim | How it was checked | Result |
|---|---|---|---|
| R1 | The image builds bit for bit reproducibly | Two fresh clones of the tag, one under umask 007 and one under 022, each built with `--no-cache --provenance=false --platform linux/amd64,linux/arm64` and `rewrite-timestamp=true`, BuildKit v0.30.0, buildx v0.19.3; the OCI index digest of each compared | **Pass.** Both give `sha256:5024c341017525b404882e4501c0181eeaddefa3ebab791129a4bb8c893b895b`, covering both platforms, and the two OCI archives are byte-for-byte identical. Both builds ran on one machine; no second, independent builder has reproduced it yet |
| R2 | The build inputs are exactly the locked set | `python3 scripts/build_inputs.py verify <inputs>` | **Pass.** `ALL INPUTS VERIFIED`: every file against `build-inputs.sha256`, every package index against its pinned key, every package against its signed index, the Tor tarball against Tor's release keys, the `libc` crate against `Cargo.lock` |
| R3 | The inputs are the newest available | Each version compared with its publisher on the day | **Pass, with notes.** Re-checked 2026-11-15: Tor 0.4.9.17 (released 2026-11-13), every locked package in the live DHI and Alpine indexes for both architectures, the `libc` crate and mkp224o are the newest. Docker rebuilt its `static` base tag with `tzdata` 2026f and a code-identical relink of the same musl; the two builder tags have newer builds whose changes do not reach the image. None was adopted (no security content in the image; a builder or base change is a new release digest). See `docs/DEPENDENCIES.md` |
| R4 | The image has no known vulnerabilities | trivy 0.76.2 and grype 0.121.2 at every severity, run on 2026-11-15 with that day's databases, each on the `linux/amd64` and the `linux/arm64` image extracted from the built archive | **Pass.** 0 findings from either scanner on either platform. dockle reports two items, both reviewed and recorded as false positives (an environment variable whose name contains `KEYS` but holds a directory path; Docker Content Trust, which is not used) |
| R5 | The image contains only what it should | Export of the amd64 image; run the documented refusals | **Pass.** 767 entries, 0 setuid or setgid files, 40.2 MB. No shell, package manager or interpreter: `sh -c id` and `python3 -c` are refused with a message naming the 3.0 command |
| R6 | Every process is confined as documented, under Docker | The release image, started with the options of the shipped `docker-compose.yml` (all capabilities dropped, five added back, `no-new-privileges`, read-only root, tmpfs, limits); `/proc/<pid>/status` read from the host | **Pass.** Supervisor: uid 0, `CapEff 0xc2` (DAC_OVERRIDE, SETGID, SETUID). Tor, the upload watcher and the guard monitor: uid 100, `CapEff 0`. All four: `NoNewPrivs 1`, `Seccomp 2`. The log reports Landlock enforced (ABI 8) and `Bootstrapped 100%` |
| R7 | The same under rootless Podman | The release image with the options of the shipped `podman-compose.yml` on Podman 4.9.3 | **Pass.** Supervisor `CapEff 0xc0` (SETGID, SETUID); Tor and helpers `CapEff 0`; NoNewPrivs, seccomp and Landlock (ABI 8) as above; the address was published 24 seconds after start; `hiddenforge show` run as root in the container works (2.1.6 raised a Python traceback there); the published `<name>.onion` file is written. Measured on the release image |
| R8 | Nothing leaves the container but Tor traffic | The release image, `tcpdump` on the container's bridge for 170 seconds from a cold start, with `dns: 127.0.0.1` as shipped | **Pass.** Counted by the container's own MAC address: 1,043 packets, 1,034 TCP to 4 public addresses and 9 ARP. Each address is a Tor relay and each port is that relay's published ORPort (443 and 9001), checked against Tor's relay directory (Onionoo). 0 UDP, 0 DNS, 0 IPv6, 0 packets to any private or LAN address. The bridge also carried the host's own mDNS and IPv6 announcements, which do not come from the container |
| R9 | The service comes up and is reachable | The same container: `hiddenforge status`, and Tor's own log | **Pass.** Over three cold starts under Docker `status` reported ready after 15 to 154 seconds (bootstrapped, descriptor uploaded); under Podman the address was published after 24 seconds. The README's "a few minutes" is the allowance for a slow network, not the measured time |
| R10 | Live end-to-end behaviour | `HIDDENFORGE_E2E=1 pytest tests/test_e2e_live.py` against the release image | **Pass, 5 of 5** (125 s, and 137 s in the CI `build-and-test` job on the tag). The compose fragment validates; a vanity search runs inside the image and the address starts with the prefix; the running container has the posture its fragment promises; a demo service publishes and `show` agrees with it; upgrading a 2.1.6 volume to 3.0 and rolling back both keep the address |
| R10a | A moved, stopped or late backend is handled as documented | The release image under the shipped Docker fragment and the demo backend: the backend stopped for 150 s; then moved to a new IP on the internal network; then removed and the container restarted without it, and the backend started again | **Pass.** Stopped: no restart. Moved: the container restarted 60 s after the move, the torrc names the new IP, the same address is served again at 71 s. Absent at start: the mapping is listed in `dropped_mappings` and the service is not ready; 48 s after the backend came up the container restarted and configured it, ready at 66 s |
| R11 | The Rust runtime is tested | `cargo test`; the differential tests; `cargo +nightly miri test`; `cargo llvm-cov`; mutation testing | **366 unit tests pass.** 512 binary-level tests (`tests/rust`) run the same inputs through the runtime and the 2.x reference and compare. **Miri:** the 195 tests that need no system call run clean, no undefined behaviour; 171 that need real syscalls or libc functions Miri cannot emulate are skipped under Miri. **Line coverage 80.7%**; the files that run only inside the container (supervisor loop 5%, Landlock set-up 12%) are covered by R10, not by unit tests. **Mutation testing** with cargo-mutants: every surviving mutant was reviewed; each is equivalent to the original, lives in container-only code, or has a written reason it is not worth a test. Several real defects were found and fixed this way (see the CHANGELOG) |
| R12 | The host tooling is tested | `pytest` (1,065 tests, plus the 512 in R11), `ruff`, `mypy` over sources and tests, `cargo fmt --check`, `cargo clippy -D warnings`, `scripts/check_manifest.py` | **Pass.** Coverage of the 2.x reference is 98.9% (the floor is 72%) |
| R13 | The release signature verifies | `pqsign verify`; stock OpenSSL 3.5.9; `hiddenforge verify-image` against the key pinned in the CLI; a deliberately altered digest | **Pass.** All three accept the signature; the altered digest is rejected by each. `complete: false` because there is no hardware signature (see `SECURITY.md`) |

## Not tested

- **Fuzzing, fault injection and long-duration soak testing.** None was done.
- **A second, independent builder.** R1 ran twice on one machine.
- **Real ARM hardware.** arm64 is built, scanned and reproduced, and was run in a
  full-system arm64 VM in an earlier pass; it has not run on real ARM hardware.
- **Host reboots under 3.0.** The reboot tests (Docker and rootless Podman) were
  run on 2.1.x. The 3.0 supervisor and restart behaviour are covered by R10 but a
  reboot was not repeated.
- **CI on the forge for this release.** Every job of the workflow (lint, unit,
  build-and-test, security, reproducibility) was run on the tagged commit with
  `forgejo-runner exec` on the runner's host and passed (for `security`, every
  scan step; its report upload needs the forge itself); the forge's own run on
  the tag happens when the tag is pushed.
- **A hardware-held signature.** The release carries the ML-DSA-65 signature only.
