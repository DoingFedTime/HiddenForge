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
