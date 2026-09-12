# Threat model

This is the in-repo threat model. It is deliberately concrete: every control
names where it lives in the code, and every limit says what it does not cover.
The wiki's Security Model page is the prose companion; this is the engineering
one.

## Assets, in priority order

1. **The hidden-service key.** It *is* the `.onion` address. Its theft lets
   someone impersonate the service; its loss destroys the address permanently.
2. **The host's real IP address.** Deanonymisation. This is the asset the whole
   project exists to protect.
3. **Service availability.** A hidden service that is down, or that leaks that it
   is up, is a different failure of the same goal.
4. **Client metadata.** Who talks to the service, when, and how much.

## Adversaries

| Adversary | Capability | Primary defence |
|---|---|---|
| Network adversary | Runs or observes relays; can force circuit rebuilds | Vanguards-lite (L2), bandguards, rendguard, 6 intro points |
| Backend application | Fully controls the thing behind the onion | **Nothing in this image.** See "What this cannot protect" |
| Local unprivileged process | Runs in the container or on the host | 0700/0600 keys, minimal caps, read-only rootfs, symlink-safe startup |
| Supply chain | Compromises a base image, an apk, a PyPI wheel, or the vendored generator | Digest-pinned base, pinned apk, hash-pinned pip, SHA256-verified vendor tarball |
| The operator | Makes a mistake | Validators, `doctor`, `status`, `dropped_mappings` |

## Trust boundaries and the control at each one

**Environment variables to torrc.** Every value that reaches the config goes
through `validate_service_name` / `validate_port` / `validate_hostname` /
`resolve_to_ip` (`entrypoint.py`). `resolve_to_ip` re-parses the resolver's answer
through `ipaddress.IPv4Address`, so the one value this module does not construct
itself cannot smuggle a newline into a directive. A property test asserts that no
environment value can emit a line outside the known-directive whitelist.

**The key volume (untrusted) to root.** `./tor-keys` is a bind mount and is
assumed hostile: restored from a backup, written by another host user, or
tampered. `_open_dir_nofollow`, `_chmod_dir_nofollow` and `_chown_r` refuse to
follow symlinks (`O_NOFOLLOW`, `fstat`+`fchmod` on one fd, `lchown`,
`os.walk(followlinks=False)`), and the chmod runs **before** the chown, which is
pinned by a regression test because the ordering is what makes the rejection
effective.

**Key files on disk.** Service directories are `0700`, the secret key `0600`, and
the parent volume `0751` (traverse, not list). `doctor` verifies the modes.

**The address file.** `<keys>/<name>.onion` is published atomically (`os.replace`)
at `0644`, contains only the public address, and is the one file a host user can
read without entering the `0700` service directory.

**The control socket.** A Unix socket inside the `0700` DataDirectory, with no
password: file permissions are the boundary, not an authentication secret.

**The CLI.** Every subprocess is a fixed argv list with `shell=False`. Image
references are validated (`validate_image_ref`) because they are handed to
`docker run` as argv (a leading `-` would be parsed as a flag) and interpolated
into generated YAML (a newline would inject keys). Output files are written
through `O_NOFOLLOW` descriptors. Key material is never read, printed, or copied:
`show` reads only the public address, and `vanity` never reads the secret key's
bytes.

**Startup privilege drop.** The container runs as root at PID 1 because it must
chown the operator's key mount and then `su-exec` to `tor`. It probes
`su-exec tor true` first and fails with a named error if it cannot, rather than
looping. See "Residual risks" for why root is not removed.

**The build.** Base image pinned by digest; apk pinned by exact version; pip
hash-pinned with `--require-hashes`; mkp224o vendored as a deterministic tarball
whose SHA256 the Dockerfile verifies before extraction. The build is bit-for-bit
reproducible (two `buildx` builds with the same `SOURCE_DATE_EPOCH` produce an
identical OCI index digest).

## What this cannot protect against

The Tor layer is almost never what gets an onion service found. The image does
nothing about: the backend making outbound clearnet requests, absolute URLs or the
real hostname in rendered output, framework banners and ETags matchable against a
clearnet scan, identical content on both networks, timezone and locale leaks,
third-party assets, or the onion address being published next to a clearnet
identity. The README has the operational version of this list.

## Residual risks and accepted trade-offs

- **Root at PID 1.** Required for the volume chown and the privilege drop. The
  network-facing processes (Tor, Vanguards) run as `tor`. Containment comes from
  the capability set, `no-new-privileges`, and `read_only`, all verified by
  `doctor`.
- **`seccomp=unconfined`.** Tor installs its own seccomp filter (`Sandbox 1`);
  disabling Docker's profile avoids a libseccomp conflict. The filter that
  matters is Tor's.
- **L2-only guard pinning.** The full Vanguards addon's L2/L3 sets need a
  `SETCONF` that `Sandbox 1` rejects. vanguards-lite covers L2; there is no L3.
  A long-lived service that needs L3 should run Vanguards without the sandbox on
  a dedicated host. This is a deliberate trade-off, not an oversight.
- **No at-rest key encryption by default.** Tor needs the plaintext secret key in
  `HiddenServiceDir`, which is the mount, so runtime encryption would be theatre.
  `encrypt-key`/`decrypt-key` exist for offline use.
- **`nproc` must not be set.** `RLIMIT_NPROC` is counted per host uid and uid 100
  is shared with other containers; a low limit makes `su-exec` fail `setuid()`
  with `EAGAIN`. `pids_limit` is the correct per-container cap, and the compose
  files carry a comment so the ulimit is not re-added.
- **Multi-arch.** The base digest is the multi-arch index and every pinned apk
  version exists for aarch64, but a full arm64 build was not executed in this
  environment (no qemu/builder). See `docs/PRODUCTION-READINESS.md`.
- **Host-mode CI runner.** Jobs run as the operator on the workstation, so the
  workflow guards against fork pull requests (fail-closed). A compromised
  collaborator with push rights could still run code on the host.

## How to check these claims

```bash
hiddenforge doctor --json                 # caps, read-only, modes, torrc directives
hiddenforge status --json                 # readiness + dropped_mappings
hiddenforge verify-image --json           # digest matches the signed digest
docker exec <c> su-exec tor tor --verify-config -f /etc/tor/torrc   # Tor accepts it
.venv/bin/pytest -q                       # 292 unit/property tests
HIDDENFORGE_E2E=1 .venv/bin/pytest tests/test_e2e_live.py   # live acceptance
```
