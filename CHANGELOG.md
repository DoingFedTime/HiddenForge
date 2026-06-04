# Changelog

All notable changes to HiddenForge are documented here.

---

## [2.0.1] — 2026-05-21

### Upgraded (dependency bump)
- Base image: Alpine 3.23.3 → **3.23.4** (digest re-pinned)
- Tor: 0.4.9.6 → **0.4.9.8**
- Python: 3.12.12 → **3.12.13**

These are version/digest bumps only; no behavioural changes to the entrypoint
or torrc generation. Verified: `tor --list-modules` reports `pow: yes`, and the
generated torrc passes `tor --verify-config` on the new binary.

---

## [2.0.0] — 2026-04-03

Complete security hardening rewrite. Not backwards-compatible with v1.x
due to the addition of Vanguards, the Unix control socket, and the
seccomp sandbox requirement.

### Security improvements
- **Vanguards addon** — bandguards (bandwidth side-channel detection)
  and rendguard (rendezvous-point overuse detection) alongside Tor's
  built-in vanguards-lite guard rotation
- **Tor Sandbox 1** — seccomp-bpf syscall filter; requires
  `--security-opt seccomp=unconfined` at runtime
- **Unix ControlSocket** — replaces TCP control port; only processes
  running as the `tor` user can connect
- **Proof-of-work DoS defense** — `HiddenServicePoWDefensesEnabled 1`
  per service (Tor 0.4.8+)
- **ClientOnly 1** — container will never become a relay or exit node
- **ExitPolicy reject all** — belt-and-suspenders relay prevention
- **No telemetry surface** — pip, setuptools, urllib3, certifi stripped
  from the final image; only vanguards, stem, and the standard library
  remain at runtime
- **Input validation** — all env vars validated against strict regexes
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

## [1.0.0] — 2024 (original release)

Initial release. Basic hidden service support via environment variables.
Alpine base, no Vanguards, no Sandbox, no pinned dependencies.
