# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 2.x (latest) | Yes |
| 1.x | No, upgrade to v2.0.0 |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via GitHub's
[Security Advisories](https://github.com/DoingFedTime/HiddenForge/security/advisories/new)
feature, or by email to the address on the
[DoingFedTime GitHub profile](https://github.com/DoingFedTime).

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
