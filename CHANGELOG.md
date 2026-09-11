# Changelog

All notable changes to HiddenForge are documented here.

---

## [2.1.0] - 2026-09-11

Machine-first adoption: hiddenforge can now be integrated by a program, and the
vanity generator ships inside the image. Everything below is additive; the
existing `docker compose up -d` human path is unchanged.

### Added
- **`hiddenforge` operator CLI** (`scripts/hiddenforge`, stdlib-only): `setup`,
  `info`, `version`, `show`, `status`, `doctor`, `vanity`, `backup`, `restore`,
  `rotate`, `encrypt-key`, `decrypt-key`. Every command that matters supports
  `--json`, prints exactly one JSON document on stdout (narration on stderr),
  never prompts off a TTY, and uses the documented exit codes
  (`0/1/2/3/4/130`).
- **`setup` emits a mergeable fragment** (`compose.service.yml`) plus `deploy.sh`,
  `README.txt`, and `hiddenforge.json`, so a consumer runs
  `docker compose -f their.yml -f compose.service.yml up -d` without editing our
  files. `--backend service:port --name name` is the simple form; the native
  `{NAME}_TOR_SERVICE_HOSTS` is unchanged. `--image` is configurable, so no host
  is hard-coded.
- **`manifest.json`** (checked in and shipped in the image): name, version,
  contract version, image reference, env contract, ports, volumes (with
  `contains: ["keys","address"]`), tmpfs, health states and `ready_field`, the
  address command and file paths, key formats/modes, and exit codes.
  `info --json` prints the same bytes; `version --json` reports
  `contract_version`. A test asserts the file and the code cannot drift.
- **mkp224o is vendored and built into the image** (multi-stage, statically
  linked, SHA256-verified archive; CC0-1.0). `hiddenforge vanity --prefix p
  --name n` runs headless, writes a Tor-native key set, refuses to overwrite
  without `--force` (archiving instead of deleting), and never prints key
  material. `--bench` measures throughput and prints the honest difficulty table
  (`32^length`) for prefixes 1..8. A test proves the generated `.onion` starts
  with the requested prefix and that the address re-derives from the public key.
- **Programmatic address discovery**: the entrypoint publishes a world-readable
  `<keys>/<name>.onion` as soon as Tor writes the key, so a consumer can read the
  address from the mount with no docker exec and no hiddenforge installed.
  `show --json --name n` returns `onion`, `key_path`, and `name`.
- **Granular readiness**: `healthcheck.py --json` distinguishes `process_up`,
  `tor_bootstrapped`, `hidden_service_published`, and `vanguards` (Vanguards is
  the guard-protection addon; its loss is otherwise invisible with
  `logging: none`). `status --json` exposes the same plus `ready`, and never
  reports ready before the address exists.
- **Full key lifecycle, scriptable**: `backup`/`restore` (age preferred, gpg with
  AEAD; `openssl` refused for creation because it is unauthenticated), `rotate`
  requiring `--confirm ROTATE`, and `encrypt-key`/`decrypt-key`. Destructive
  operations archive rather than delete. Documented: the key IS the address and
  loss is permanent.
- **`doctor`** verifies the running container's hardening (caps, `cap_drop ALL`,
  `no-new-privileges`, read-only rootfs, `seccomp=unconfined`, AppArmor,
  `pids_limit`, swap disabled, no published ports) plus on-disk key modes, and
  has a `--keys-only` mode for use inside the container.
- **In-image CLI dispatch**: `docker run <image> show|vanity|doctor|...` runs the
  operator tools instead of booting Tor, so `docker pull` is the only install
  step.
- **`examples/demo`**: a throwaway nginx app published as a `.onion` by adding
  only the emitted fragment.
- **Multi-service `setup`**: `--service name:onionport:host:port` is repeatable,
  so several onions are emitted at once (each with its own env var, key
  directory, and address). `--runtime podman` emits a Podman-correct fragment
  and deploy script; `--force` is required to overwrite an existing output
  directory.
- **CI** (`.github/workflows/ci.yml`): lint, host unit tests with the coverage
  floor, an image build with smoke checks (CLI dispatch, the in-container torrc
  test, vanity generation), and the live acceptance suite. Actions are pinned by
  commit SHA.
- **Podman parity in the CLI**: `status`, `doctor`, and `vanity` use `docker` or
  `podman` (whichever is present; override with `HIDDENFORGE_ENGINE`), and
  container lookup also understands podman-compose's service label.
- **Golden snapshots** for the emitted `compose.service.yml`, `deploy.sh`, and
  `README.txt`, so the integration contract cannot drift silently.
- **`verify-image` and `sbom`**: `verify-image` resolves the registry digest with
  `skopeo`, compares it to `signatures/hiddenforge.digest`, and verifies the
  SSH-FIDO2 (and ML-DSA, when `pqsign` is present) signature; `sbom` runs a
  digest-pinned `anchore/syft` and writes normalised SPDX JSON. Both support
  `--json`.

### Changed
- **Refreshed the `tor` apk pin `0.4.9.11-r0` to `0.4.9.12-r0`.** Alpine pruned
  `0.4.9.11-r0` from the 3.23 index, so the image could not be built from source
  at all (the same failure mode documented for 2.0.2 and 2.0.4).
- The key volume remains `0751` (traverse, not list). Because that means neither
  the host user nor the `tor` user can enumerate it, `show`/`doctor` fall back to
  the in-container healthcheck and the torrc for service names; the CLI never
  regresses the 2.0.4 decision to withhold the service list.

### Fixed
- `emit_json` no longer drops null fields, so a polling consumer can tell
  `onion: null` (not generated yet) from a missing key.
- `status`/`doctor` now resolve Docker Compose service labels, so
  `--container tor` works when the real container is `<project>-tor-1`.
- Operator-supplied env values are escaped before being echoed at startup, so a
  value containing ANSI escapes or newlines cannot forge log lines.
- **Vanguards is now retried when it never started.** The supervisor previously
  only restarted it after an observed exit, so a `wait_for_socket` timeout or a
  raise on the first start left the addon permanently absent (healthcheck
  unhealthy, no recovery short of a container restart). It is now retried with a
  bounded budget and a backoff; a missing control socket does not consume the
  budget.
- **`doctor` verifies the generated torrc** still contains every hardening
  directive (`ClientOnly 1`, `SafeLogging 1`, `VanguardsLiteEnabled 1`, PoW,
  Intro-point DoS, ...), not just the Docker flags and on-disk key modes.

### Tests
- Host suite 169 → 245 tests: CLI contract, manifest equality, Tor v3 address
  derivation against a real mkp224o-generated vector, name/traversal rejection,
  compose-fragment emission, key modes, backup/restore round-trip (including
  fail-closed wrong passphrase).
- Live acceptance suite (`HIDDENFORGE_E2E=1`): validates the emitted fragment with
  `docker compose config`, publishes the demo app and asserts the address file
  parses and matches `show --json`, reaches `status.ready`, and runs a vanity
  search whose result matches the prefix.

---

## [2.0.5] - 2026-08-22

### Security
- **The Tor config is written through an `O_NOFOLLOW` descriptor**, and its mode
  and ownership are set with `fchmod`/`fchown` on that same descriptor. `open('w')`
  follows symlinks and the follow-up `chmod`/`chown` took a path, so a process able
  to write into the `/etc/tor` tmpfs before the entrypoint ran could have root
  truncate, chmod and chown an arbitrary file. Confirmed against 2.0.4: a symlinked
  `torrc` had the configuration written through it and the target transferred to the
  `tor` user. It now fails loudly instead.

  Reachability is low — the tmpfs starts empty and the entrypoint runs as PID 1 —
  so this is defence in depth rather than an urgent fix, but it is the same class of
  issue already closed for the hidden-service key directory.

- **The resolver's answer is re-parsed** through `ipaddress.IPv4Address` before it
  can reach the config. CPython builds that string with `inet_ntop` from a 4-byte
  struct, so a hostile DNS server cannot smuggle whitespace or a newline through it;
  this is not a reachable injection. It is, however, the only value written to the
  torrc that the entrypoint neither constructs nor validates, and enforcing the
  invariant locally means a future change of resolver cannot silently reintroduce
  the gap.

- **Two environment variables can no longer collapse into one hidden service.**
  Service names are lowercased and underscores become hyphens, so
  `MYAPP_TOR_SERVICE_HOSTS`, `myapp_TOR_SERVICE_HOSTS` and
  `MY_APP_TOR_SERVICE_HOSTS` all resolve to the same directory — and environment
  variable names are case-sensitive, so all of them can be set at once. The
  generator emitted a `HiddenServiceDir` block per variable, and Tor rejects a
  duplicated directory outright: `Another hidden service is already configured
  for directory ...` → `Reading config failed`. Confirmed live against 2.0.4: the
  container never starts, taking down every other onion with it. Colliding names
  are now skipped with an explicit error naming both variables, matching how a
  service with no valid ports is handled.

- **A failed Vanguards addon is no longer invisible.** The supervisor restarts
  Vanguards up to five times and then continues with Tor alone, printing a
  warning to stdout — which the shipped compose file discards
  (`logging: driver: none`, so no host-side record of onion activity exists).
  The container therefore kept reporting **healthy** while bandguards and
  rendguard, both of which exist to detect an attack in progress, were gone.
  The healthcheck now also verifies the addon is alive, so the degradation shows
  up in `docker ps` — the one channel that survives a disabled log driver.
  Verified by exhausting the restart budget: 2.0.4 reports `healthy`, this
  release reports `unhealthy` with the reason.

### Added
- Tests covering resolver **output** rather than only user input: unusable answers
  drop the mapping, whitespace-padded ones normalise, and nothing outside the
  allowed directive set can appear regardless of what comes back, plus service-name
  collision coverage. Suite: 145 → 169.
- Documentation of a long-standing operational trap: backend hostnames are resolved
  **once**, at startup, and the resulting IP is baked into the torrc. Recreating the
  backend container gives it a new IP and the onion then blackholes silently, with
  nothing logged. Restart the Tor container after recreating a backend.

### Unchanged (deliberately)
- A Tor process that exits **on its own** is still reported as a failure, including
  when its own exit code was 0. Measured: `restart: unless-stopped` restarts on any
  exit status, so passing 0 through prevents no restart loop, while under
  `restart: on-failure` it would leave a dead onion inside a container that reports
  success. An orderly shutdown already exits 0 via the signal handler.

---

## [2.0.4] - 2026-08-18

### Security
- **Python runtime patched** (`python3` apk `3.12.13-r0` → `3.12.14-r0`), clearing
  six HIGH CVEs Alpine disclosed against the version 2.0.3 shipped:
  `CVE-2026-11940`, `CVE-2026-15308`, `CVE-2026-3644`, `CVE-2026-4786`,
  `CVE-2026-6100`, `CVE-2026-7210`. None of the affected modules are on this
  image's attack surface — it runs only the entrypoint, the healthcheck and
  Vanguards/stem, none of which parse untrusted XML or HTML, extract tarballs,
  handle HTTP cookies, or open a browser — but a Tor hidden service should not
  ship a knowingly vulnerable runtime. Trivy reports the image clean at every
  severity.

- **`VanguardsLiteEnabled 1` is now pinned in the generated torrc.** The full
  Vanguards addon's layer-2/3 guard pinning cannot be used in this image: it
  applies guard sets via `SETCONF`, which Tor's seccomp sandbox rejects
  (`Failed to configure rendezvous options`). vanguards-lite is therefore the
  only guard-discovery defence present, and Tor's `auto` default delegates it to
  the `vanguards-lite-enabled` consensus parameter — placing the last line of
  defence against guard-discovery attacks under the directory authorities'
  control rather than the operator's. Pinning it locally removes that lever.

- **Privileged startup no longer follows symlinks out of the key directory.**
  The entrypoint runs as root over the operator-supplied `./tor-keys` bind mount
  and used `os.chown()`, which follows symlinks — an arbitrary-chown primitive
  for anyone able to write to that volume (a restored backup, untrusted media, a
  second host user). On the previous image a symlink placed in the key directory
  transfers `/etc/tor` to the `tor` user, which would let a compromised Tor
  process rewrite its own configuration and persist. All privileged filesystem
  operations now refuse symlinks (`follow_symlinks=False`,
  `os.walk(followlinks=False)`, and `O_NOFOLLOW` descriptor-based chmod, as Linux
  has no `lchmod`).

- **Hidden-service parent directory tightened `0755` → `0751`.** Tor needs only
  the traverse bit to open a service directory by path; the read bit additionally
  allowed any non-owner process in the container to enumerate the names of every
  configured hidden service.

### Fixed
- **A single misconfigured service no longer takes down every other service.**
  When all of a service's port mappings failed validation, the entrypoint logged
  "Skipping invalid mapping" and still emitted a `HiddenServiceDir` with no
  `HiddenServicePort` — a state in which Tor refuses to start at all
  (`Hidden service ... with no ports configured` → `Reading config failed`). One
  typo therefore killed every onion in the container while the logs implied
  graceful degradation. Such services are now dropped with an explicit error and
  no key directory is created for them.

- **The in-image smoke test is non-destructive.** `tests/test_torrc.py` ships in
  the image and its docstring directs you to run it inside the container, where
  it called the privileged `generate_basic_torrc()` — overwriting the running
  `/etc/tor/torrc` and creating a stray hidden-service directory in the
  operator's key volume. It now exercises the pure `build_torrc_string()`, which
  has no filesystem side effects, and asserts that it created nothing.

- **Reading your `.onion` address works under rootless Podman.**
  `podman-compose ... exec tor cat .../hostname` failed with `Permission denied`,
  because that compose file correctly drops `DAC_OVERRIDE` and the exec'd root
  cannot traverse the `0700` tor-owned DataDirectory. Documented as
  `su-exec tor cat ...`, with a warning not to work around the error by re-adding
  the capability or loosening the key directory.

- **Build restored.** Alpine pruned the pinned `python3=3.12.13-r0` from the 3.23
  index when the security update landed, so `apk add` failed and the image could
  not be built from source at all.

### Changed
- **Published to the maintainer's own registry as well as Docker Hub**
  (`sambent.dev/sam/hiddenforge` and `doingfedtime/hiddenforge`). Both serve the
  identical digest and the same signatures verify either, so the mirror cannot
  serve different bytes under the same tag without detection.

- **Reproducible builds are now genuinely reproducible**, and the requirements are
  documented in `signatures/README.md`. Two things break bit-for-bit
  reproducibility and both are now handled: release images are built with
  `--provenance=false`, because buildx embeds wall-clock timestamps in the SLSA
  provenance attestation and that attestation lives inside the image index; and
  releases are built from a pristine checkout, because `rewrite-timestamp`
  *clamps* file mtimes to `SOURCE_DATE_EPOCH` rather than normalising them, so a
  working tree's older mtimes are baked into the layer verbatim.

- **The `.build-deps` virtual apk package was removed.** apk assigns virtual
  packages a self-generated checksum that was observed to differ between builds
  of identical source. `py3-pip` is installed by name and `apk del py3-pip`
  reclaims it along with the seven packages it pulls in.

- **Release signing uses the maintainer's identity key.** Releases through 2.0.3
  were signed with a per-project key; from 2.0.4 a single per-identity key signs
  every project. `signatures/allowed-signers` retains every key that has ever
  signed a release, so earlier releases remain independently verifiable. cosign
  is no longer used — the ML-DSA-65 and YubiKey signatures are the attestation —
  and `cosign.pub` is kept so releases up to 2.0.3 stay verifiable.

### Added
- **Operator guidance on what HiddenForge cannot protect you from** — a README
  section on application-layer deanonymization: the backend making outbound
  clearnet requests, emitting absolute URLs or its real hostname, leaking
  framework banners and ETags matchable against a clearnet scan, serving
  identical content on both networks, and leaking the server's timezone.

- **`tests/test_privileged_fs.py`** covering the symlink-refusal property of the
  privileged startup path, plus guard-pinning and portless-service tests. Suite:
  129 → 145 tests.

---

## [2.0.3] - 2026-07-16

### Added
- **Reproducible builds.** The image now builds bit-for-bit reproducibly: two
  builds of the same source commit produce an identical image digest, on any
  machine. Three sources of build-date nondeterminism were removed: the apk
  virtual build-deps package is pinned (it was auto-versioned with the build
  timestamp), the timestamped `/var/log/apk.log` is dropped, and every
  `/etc/shadow` last-change field is normalized to `SOURCE_DATE_EPOCH`. You can
  now rebuild from source and confirm the published image matches it.

### Changed
- Published to the maintainer's own registry (`sambent.dev/sam/hiddenforge`)
  alongside the Docker Hub mirror.
- User documentation moved to the project wiki.

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
- **Patched OpenSSL** (`CVE-2026-45447`, HIGH, heap use-after-free in
  `PKCS7_verify()`): bumped the digest-pinned Alpine base `3.23.4 → 3.23.5`, which
  ships OpenSSL `3.5.7-r0`. Trivy now reports the image clean of HIGH/CRITICAL.

### Fixed
- **Build was broken**: the pinned `tor=0.4.9.8-r0` had been pruned from the
  Alpine 3.23 index, so `apk add` failed for anyone building the image. Re-pinned
  to **`tor=0.4.9.11-r0`**, verified it builds, keeps `pow: yes`, imports
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
