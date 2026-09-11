# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 2.x (latest) | Yes |
| 1.x | No, upgrade to v2.0.0 |

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
- Acknowledgement within 48 hours
- Assessment and severity rating within 7 days
- Patch and coordinated disclosure within 30 days for confirmed issues

## Scope

In scope:
- Dockerfile / build process
- `entrypoint.py` logic and torrc generation
- Tor configuration hardening gaps
- Supply chain / dependency issues
- Container escape via misconfiguration

Out of scope:
- Vulnerabilities in Tor itself (report to the [Tor Project](https://gitlab.torproject.org/tpo/core/tor/-/issues))
- Vulnerabilities in Vanguards (report to the [Vanguards repo](https://github.com/mikeperry-tor/vanguards))
- Social engineering
- Physical attacks on the host

## Accepted findings (and why)

Static scanners flag two things here that are deliberate. Both are recorded so a
future reader does not "fix" them into a regression.

**The container starts as root.** `hadolint`/Trivy DS-0002 and
`semgrep dockerfile.security.missing-user-entrypoint` both want a `USER`
instruction. The entrypoint needs root for exactly two things at startup: it
chowns the operator's key bind mount to the `tor` user, and it uses `su-exec` to
drop to `tor` before Tor and Vanguards run. A non-root `USER` would make both
impossible. The processes that face the network (Tor, Vanguards, the CLI when it
reads keys) run as `tor`; nothing stays root. The mitigation that matters is the
capability set and `no-new-privileges`, which `hiddenforge doctor` verifies.

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
