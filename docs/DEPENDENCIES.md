# Dependencies: pinned versions and upstream status

Every dependency is pinned. A pin has a shelf life, so this file records *why*
each one is acceptable and what happens when it moves. Statuses were checked
directly against the registries and upstream repositories on **2026-09-12**; they
are dated because they rot.

| Package | Pinned | Where | Upstream status (2026-09-12) | Why acceptable / plan |
|---|---|---|---|---|
| Alpine base | `3.23.5` (digest) | Dockerfile | Point releases ~quarterly | Digest-pinned so the bytes cannot move under the tag. **Alpine prunes superseded apk versions from its index**, so exact-version pins stop resolving when a security update lands and the build fails loudly. That has bitten this project twice (`tor`, `python3`); see `docs/CI.md` for the freshness job. |
| `tor` | `0.4.9.13-r0` | Dockerfile apk | Active (Tor Project) | The whole point of the image. Bumped from `0.4.9.11-r0` in 2.1.0 and from `0.4.9.12-r0` after 2.1.0, both times because Alpine pruned the old build. |
| `python3` | `3.12.14-r0` | Dockerfile apk | Active | Runs the entrypoint, the CLI, the healthcheck and Vanguards. 2.0.4 bumped it for six HIGH CVEs. |
| `openssl` | `3.5.8-r0` | Dockerfile apk | Active | Pinned explicitly rather than inherited from the base digest, after scanning the built image found 20 CVEs in the base's `3.5.7-r0`. |
| `su-exec` | `0.3-r0` | Dockerfile apk | Dormant (small, stable) | Performs the root -> `tor` privilege drop. ~200 lines of C, no network surface; a dormancy risk is negligible. |
| `vanguards` | `0.3.1` (SHA256) | pip | **Not abandoned.** Last PyPI release **2019-04-10**, but the GitHub repo `mikeperry-tor/vanguards` was **pushed 2024-07-06 and is not archived** (30 open issues). "package-abandoned" from the scanner means "no release in N months", which for a stable tool is normal. | Load-bearing: bandguards and rendguard are the guard-discovery detection. If upstream genuinely stops, the fallback is to vendor the exact commit (as is done for mkp224o), record its hash, and watch for a Tor protocol change that breaks it. Note the L2/L3 limitation in `docs/THREAT-MODEL.md`. |
| `stem` | `1.8.2` (SHA256) | pip | Active. PyPI **2023-06-06**; repo `torproject/stem` pushed **2024-05-15**, not archived. It is the official Tor controller library. | Vanguards' controller transport. Same fallback: vendor the commit if it stops. |
| `setuptools` | `82.0.1` (SHA256) | pip, build-only | Active | Needed to build `stem` from sdist, and listed so `--require-hashes` verifies it. **Uninstalled from the venv after the build** and absent from the final image (verified: `import setuptools` fails). Its CVE is accepted in `.trivyignore` on that basis. |
| `ipaddress` | **removed in 2.1.0** | pip | n/a | Was the Python 2 backport of a stdlib module. Nothing imported it and the stdlib already won; removed so it stops shadowing a stdlib name in a privacy tool's runtime. |
| `mkp224o` | commit `5172c0fd` (SHA256) | vendored source | Upstream `cathugger/mkp224o`, CC0-1.0 | Vendored so the build is offline and reproducible; the archive hash is checked in the Dockerfile. |

## What "pin" means per layer

- **Base image:** by digest, so the tag cannot be repointed.
- **apk:** exact version. apk authenticates the package against a signed index, but
  the index is fetched at build time, so a pinned version is only as available as
  Alpine's retention. Build failure, never silent drift.
- **pip:** version + SHA256 with `--require-hashes`; a compromised package with the
  right version number still fails the build.
- **vendored source:** SHA256 over a deterministic archive.

## Refreshing a pin

Do not change a version number alone. Verify the bytes first (see the README's
"Updating pinned versions"), rebuild, and re-run the security scan and the live
E2E. A pin bump is a release, not an edit.
