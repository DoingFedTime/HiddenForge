# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 2.1.x | Yes. Use 2.1.5: 2.1.1 ships `/opt/hiddenforge` and `/usr/local/bin/tests` as mode 0644, so no non-root user can enter them |
| 2.0.x | No, upgrade to 2.1. 2.0.4's image carries known CVEs that 2.1.0 fixed: python3 3.12.14 (CVE-2026-19445, CVE-2026-19553, CVE-2026-82049), OpenSSL 3.5.7 (CVE-2026-14456 and others) and zlib 1.3.2-r0 (CVE-2026-85091); see the 2.1.0 entry in the [CHANGELOG](CHANGELOG.md). Its pinned packages are gone from Alpine, so it cannot be rebuilt |
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
- Dockerfile / build process
- `entrypoint.py` logic and torrc generation
- The operator CLI (`scripts/hiddenforge`): `setup`'s generated files, key
  handling in `backup`/`restore`/`encrypt-key`/`decrypt-key`/`vanity`, and
  `verify-image`'s signature checking
- Tor configuration hardening gaps
- Supply chain / dependency issues
- Container escape via misconfiguration

Out of scope:
- Vulnerabilities in Tor itself (report to the [Tor Project](https://gitlab.torproject.org/tpo/core/tor/-/issues))
- Vulnerabilities in Vanguards (report to the [Vanguards repo](https://github.com/mikeperry-tor/vanguards))
- Social engineering
- Physical attacks on the host

## Accepted findings (and why)

Static scanners flag three things here that are deliberate. All are recorded so a
future reader does not "fix" them into a regression.

**The container starts as root.** `hadolint`/Trivy DS-0002 and
`semgrep dockerfile.security.missing-user-entrypoint` both want a `USER`
instruction. The entrypoint needs root for exactly two things at startup: it
chowns the operator's key bind mount to the `tor` user, and it uses `su-exec` to
drop to `tor` before Tor and Vanguards run. A non-root `USER` would make both
impossible. The processes that face the network (Tor, Vanguards) and the CLI
commands that only read keys (`show`, `doctor`) run as `tor`. The supervisor
itself stays root for the container's life, because it republishes the address
and restarts Vanguards, but it never touches the network, and once setup is done
it drops everything except what that needs: measured, it holds `DAC_OVERRIDE`,
`SETUID` and `SETGID` under the Docker compose file (`CapEff 0xc2`) and only
`SETUID` and `SETGID` under the Podman one (`0xc0`). Tor itself runs with no
capabilities at all. The mitigations that matter are that capability set and
`no-new-privileges`, which `hiddenforge doctor` verifies.

**`setuptools` is listed in `requirements.txt` with a CVE against it.** It is a
build-only dependency: `stem` is built from an sdist and needs it, and it is
listed so `--require-hashes` can verify every downloaded file. It is uninstalled
from the venv after the build (`pip uninstall -y pip setuptools wheel`), so it is
not in the final image. Verified:

```bash
docker run --rm --entrypoint python3 sambent.dev/sam/hiddenforge:latest -c \
  "import setuptools"    # ModuleNotFoundError: No module named 'setuptools'
```

A finding against a package that does not ship is not a finding against the
image, but the reason is written down rather than silently suppressed.

**semgrep's `dangerous-subprocess-use`, `dangerous-os-exec` and
`arbitrary-sleep` rules fire on this project.** All of them are structural false
positives, and each was reviewed rather than waved away:

- Every `subprocess` call uses a **fixed argv list** with `shell=False`, and no
  value reaches it that has not already been validated or checked against a
  fixed set. There is no string-built command anywhere.
- `os.execvp` in `dispatch_subcommand` is how `docker run <image> show` becomes
  the CLI instead of booting Tor. It execs a fixed in-image path with the
  operator's arguments and no shell. It is deliberate: replacing PID 1 keeps
  signals (`docker stop`) going straight to the CLI, which matters when a
  `vanity` search runs for hours.
- The `time.sleep` calls are the polling loops in `wait_for_socket` and the
  Vanguards supervisor. They are bounded and part of the control flow, not a
  delay primitive.

These are recorded per rule so a future run does not re-litigate them, and so
that nobody "fixes" the exec into a subprocess call and loses the signal
behaviour.
