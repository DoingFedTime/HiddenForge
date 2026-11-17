# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 3.0.x | Yes |
| 2.1.x | No. Upgrade to 3.0: it is a drop-in replacement (same compose files, keys, address and commands). 2.1.x images cannot be rebuilt from source any more, because their pinned Alpine packages have been pruned |
| 2.0.x | No. 2.0.4's image carries known CVEs that 2.1.0 fixed; see the [CHANGELOG](CHANGELOG.md) |
| 1.x | No |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately by email to the maintainer; contact details are on the
[maintainer's profile](https://sambent.dev/sam). Encrypt sensitive reports with
the maintainer's published key where possible.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

**Response timeline:**
- Acknowledgement on a best-effort basis
- Assessment and severity rating within 7 days
- Patch and coordinated disclosure within 30 days for confirmed issues

## Scope

In scope:
- The Dockerfile, the build inputs and their verification (`scripts/build_inputs.py`)
- The runtime binary (`hiddenforge-rs/`): torrc generation, the supervisor,
  the guard monitors, key sealing, the 2.x compatibility names
- The operator CLI (`scripts/hiddenforge`): `setup`'s generated files, key
  handling in `backup`/`restore`/`encrypt-key`/`decrypt-key`/`unseal-keys`/`vanity`/`client-auth`,
  and `verify-image`'s signature checking
- The offline setup wizard (`wizard/`)
- Tor configuration hardening gaps
- Container escape via misconfiguration

Out of scope:
- Vulnerabilities in Tor itself (report to the [Tor Project](https://gitlab.torproject.org/tpo/core/tor/-/issues))
- Vulnerabilities in Docker Hardened Images packages (report to Docker)
- Social engineering
- Physical attacks on the host

## Accepted findings (and why)

Static scanners flag a few things here that are deliberate. They are recorded so
a future reader does not "fix" them into a regression.

**The image starts as root by default.** `hadolint`/Trivy DS-0002 want a non-root
`USER`. At start-up the supervisor needs root for one job: handing the
operator's key bind mount to the `tor` user (uid 100) and dropping to it before
Tor and the guard monitors run. After that it keeps only what republishing the
address needs. Measured: `CapEff 0xc2` (`DAC_OVERRIDE`, `SETUID`, `SETGID`) under
the Docker compose file and `0xc0` under the Podman one; Tor and the monitors hold
no capabilities at all, and the supervisor holds no `CAP_KILL`. It confines
itself with Landlock and never touches the network. If you can hand the key
directory to uid 100 yourself, `hiddenforge setup --no-root` starts the container
as uid 100 with no capabilities, and nothing ever runs as root.

**The image has no shell, no coreutils and no Python.** Every command it runs
is `hiddenforge <command>`. One other name exists, `/sbin/su-exec`, a link to the
same binary: compose files already on operators' hosts declare the healthcheck
as `su-exec tor python3 /usr/local/bin/healthcheck.py`, and an image update
cannot change them. That exact command (with or without `--json`) runs the
native healthcheck as the tor user; anything else under that name is refused
(`hiddenforge-rs/src/compat.rs`).

**`unsafe` in the Rust binary.** Every `unsafe` block in the shipped code is a
system call or an OpenSSL call through `libc`, with a `SAFETY:` comment (or, for
the two `unsafe fn`s, a `# Safety` section) saying why the arguments are valid.
The test modules contain a few more, all trivial. The binary depends on no
other crate, so there is no unsafe code it did not write itself.

## Limits of this release

What 3.0.0 does not have, so that nobody assumes it does:

- **One signature, one signer.** The release is signed with ML-DSA-65 only. The
  hardware-held (SSH-FIDO2) half of the hybrid signature is not present, so
  `hiddenforge verify-image` reports `complete: false`. The signing key is a
  file on the maintainer's workstation; anyone who copies it can sign as the
  maintainer. The reproducible build is the second check: do not rely on the
  signature alone, rebuild the tagged source from the published inputs and
  compare the digest.
- **Commits are not signed.** Only tagged, signed releases are meant to be run.
- **Not fuzzed, fault-injected or soak-tested.** The runtime has unit tests,
  differential tests against the 2.x reference, mutation testing, Miri over the
  tests that need no system call, and live end-to-end tests. The supervisor
  loop and the Landlock set-up are covered by the live tests only.
- **A vendor in the chain.** The base image and the Tor libraries are Docker's
  builds of Alpine packages (see [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)).
- **Tor's limits are Tor's limits.** A global passive adversary that can watch
  both ends of a connection, a compromised host, and an application that gives
  away where it lives are outside what this image can defend.

## Repository history

On 2026-10-30 the repository history was rewritten to remove working files.
Every release tag points to a commit with the same files as before, and no
image digest or signature changed.
