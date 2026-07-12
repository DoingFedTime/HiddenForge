# Changelog

All notable changes to HiddenForge are documented here.

---

## [2.0.2] - 2026-07-12

### Added
- **Intro-point DoS defence**: `HiddenServiceEnableIntroDoSDefense 1`
  (rate 25/s, burst 200) per service. Complements PoW: PoW throttles the
  rendezvous stage, this throttles `INTRODUCE2` flooding at the intro points.
- **Bootstrap-aware healthcheck**: `healthcheck.py` queries the control socket
  for `status/circuit-established` + `bootstrap-phase=100`, replacing the old
  `pidof tor` check that passed for a process that was alive but wedged.
- **Container resource limits** (both compose files): `pids_limit`, `mem_limit`,
  `memswap_limit == mem_limit` (no swap → keys never paged to disk), `cpus`,
  and `nofile`/`nproc` ulimits.
- **tmpfs `nodev`** on every tmpfs mount; explicit `apparmor=docker-default`
  (Docker compose).
- **Test suite**: host unit tests for every validator (full injection/edge
  table), torrc-generation tests, an injection-proof property test, golden
  snapshots, and property-based fuzzing (Hypothesis). Verified to kill logic
  mutations of the security surface.
- **CI**: lint (ruff/bandit/hadolint/actionlint), unit+fuzz with coverage,
  Docker and rootless-Podman smoke tests, `tor --verify-config`, and a Trivy
  vulnerability scan.
- **Release pipeline** (`release.yml`): cosign signing (maintainer key), SBOM,
  SLSA build-provenance attestation, and publish-by-digest on version tags;
  README documents image verification.
- **CI supply-chain hardening**: every GitHub Actions dependency pinned to a full
  commit SHA (actionlint to an image digest); multi-arch release builds
  (`linux/amd64` + `linux/arm64`); Dependabot for actions, the base image, and
  pip; a coverage-floor gate; a scheduled rescan of the published image for
  newly-disclosed CVEs; and failure alerts via ntfy.

### Changed
- `validate_service_name` now caps length at 63 chars.
- `resolve_to_ip` strictly validates IPv4 (rejects `999.999.999.999`,
  leading-zero octets) instead of passing malformed dotted-quads through.
- torrc generation refactored into a pure, host-testable `build_torrc_string()`
  (output proven byte-identical to the previous implementation).
- The host test suite is no longer shipped inside the production image.

### Security
- **Patched OpenSSL** (`CVE-2026-45447`, HIGH — heap use-after-free in
  `PKCS7_verify()`): bumped the digest-pinned Alpine base `3.23.4 → 3.23.5`, which
  ships OpenSSL `3.5.7-r0`. Trivy now reports the image clean of HIGH/CRITICAL.

### Fixed
- **Build was broken**: the pinned `tor=0.4.9.8-r0` had been pruned from the
  Alpine 3.23 index, so `apk add` failed for anyone building the image. Re-pinned
  to **`tor=0.4.9.11-r0`** — verified it builds, keeps `pow: yes`, imports
  vanguards, serves a backend end-to-end over Tor, and an in-place upgrade from
  the prior version preserves the existing `.onion` key (same address, no loss).
- Dockerfile now fails the build if the vanguards `SafeConfigParser` patch does
  not apply (previously a silent no-op on a future vanguards change).
- Corrected documentation: version drift (Tor/Alpine/Python), the apk
  "not hash-verified" claim (apk verifies a signed index), and the "no
  HTTP-capable code" comment (the Python stdlib retains urllib/ssl).
- Documented the L2-only guard-protection limitation for long-lived services.

---

## [2.0.1] - 2026-05-21

### Upgraded (dependency bump)
- Base image: Alpine 3.23.3 → **3.23.4** (digest re-pinned)
- Tor: 0.4.9.6 → **0.4.9.8**
- Python: 3.12.12 → **3.12.13**

These are version/digest bumps only; no behavioural changes to the entrypoint
or torrc generation. Verified: `tor --list-modules` reports `pow: yes`, and the
generated torrc passes `tor --verify-config` on the new binary.

---

## [2.0.0] - 2026-04-03

Complete security hardening rewrite. Not backwards-compatible with v1.x
due to the addition of Vanguards, the Unix control socket, and the
seccomp sandbox requirement.

### Security improvements
- **Vanguards addon**: bandguards (bandwidth side-channel detection)
  and rendguard (rendezvous-point overuse detection) alongside Tor's
  built-in vanguards-lite guard rotation
- **Tor Sandbox 1**: seccomp-bpf syscall filter; requires
  `--security-opt seccomp=unconfined` at runtime
- **Unix ControlSocket**: replaces TCP control port; only processes
  running as the `tor` user can connect
- **Proof-of-work DoS defense**: `HiddenServicePoWDefensesEnabled 1`
  per service (Tor 0.4.8+)
- **ClientOnly 1**: container will never become a relay or exit node
- **ExitPolicy reject all**: belt-and-suspenders relay prevention
- **No telemetry surface**: pip, setuptools, urllib3, certifi stripped
  from the final image; only vanguards, stem, and the standard library
  remain at runtime
- **Input validation**: all env vars validated against strict regexes
  before being written to torrc
- **AvoidDiskWrites 1**, **DisableDebuggerAttachment 1**, **SafeLogging 1**,
  **HeartbeatPeriod 0** added to torrc

### Supply chain hardening
- Base image digest-pinned: alpine:3.23.3 with full SHA256
- All apk packages pinned: tor=0.4.9.6-r0, python3=3.12.12-r0, su-exec=0.3-r0
- py3-pip installed as --virtual .build-deps and removed post-build
- All pip packages pinned with exact versions and SHA256 hashes via
  --require-hashes in requirements.txt
- stem pinned to 1.8.2 (previously unbounded)

### Usability
- New docker-compose.yml with all security flags pre-configured
- Network isolation: backend on internal: true network, no ports mapping
- logging: driver: none prevents host-side JSON log files

### Bug fixes
- Fixed HiddenServicePoWDefensesEnabled placement (must follow HiddenServiceDir)
- Fixed HiddenServiceNumIntroductionPoints option name
- Fixed rootless podman volume permission issue on parent hidden_service dir
- Replaced subprocess chown calls with native os.chown / pwd.getpwnam
- Removed dead CMD ["tor"] from Dockerfile

### Upgraded
- Base image: Alpine 3.22 to Alpine 3.23.3
- Tor: 0.4.8.17 to 0.4.9.6

---

## [1.0.0] - 2024 (original release)

Initial release. Basic hidden service support via environment variables.
Alpine base, no Vanguards, no Sandbox, no pinned dependencies.
