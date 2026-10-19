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

**DNS (the container to the host's resolver).** Backend names are resolved by
the engine's resolver (Docker's embedded DNS, Podman's aardvark-dns), which
answers names on the internal network itself and forwards anything else to the
host's upstream DNS. The supervisor re-resolves backend names every 30 seconds,
so a backend that is down or not up yet would be announced to that upstream
every 30 seconds, starting exactly when the onion loses it: a timing signal that
links the server's network identity to the onion's outages. Measured on Docker
and on rootless Podman: a name the engine could not answer reached the host
resolver (Podman: 78 packets for one dotted name). The shipped compose files and
the `setup` fragment set `dns: 127.0.0.1`, a server nothing listens on, and
measured with it: internal names resolve, no query leaves (0 packets over 72s of
backend downtime), Tor bootstraps and serves (Tor needs no DNS; it bootstraps
from relay IPs). `doctor` warns when a running container lacks it.

**Key files on disk.** Service directories are `0700`, the secret key `0600`, and
the parent volume `0751` (traverse, not list). `doctor` verifies the modes.

**The address file.** `<keys>/<name>.onion` is published atomically (`os.replace`)
at `0644`, contains only the public address, and is the one file a host user can
read without entering the `0700` service directory.

**The control socket.** A Unix socket inside the `0700` DataDirectory, with no
password: file permissions are the boundary, not an authentication secret. Its
clients all run as `tor`: Vanguards, the healthcheck, and the upload watcher
(`healthcheck.py --watch-uploads`), which subscribes to `HS_DESC` events and
records, in the tmpfs DataDirectory, each address whose descriptor this Tor
uploaded. It accepts only a 56-character base32 address from an `UPLOADED`
event and never writes anything else; the record only ever gates readiness in
the safe direction (no record, not ready).

**The CLI.** Every subprocess is a fixed argv list with `shell=False`. Image
references are validated (`validate_image_ref`) because they are handed to
`docker run` as argv (a leading `-` would be parsed as a flag) and interpolated
into generated YAML (a newline would inject keys). Output files are written
through `O_NOFOLLOW` descriptors. Key material is never printed: `show` reads
only the public address, and `vanity` never reads the secret key's
bytes.

**Image verification.** `verify-image` trusts the signer keys pinned in the CLI
(`PINNED_ALLOWED_SIGNERS`, `PINNED_MLDSA_PUB_SHA256`), never the keys shipped in
the signature directory it is checking: before this was fixed, a directory with a
substituted key and a matching signature verified as `VERIFIED`, complete. Both
halves of the hybrid signature are required unless the operator passes
`--allow-classical-only` or `--allow-pq-only` to accept one half missing; a
present-but-wrong signature is never excused, and both flags together still
refuse an image with no verified signature. The limit, stated plainly: a pin in the CLI protects
against a tampered signature directory, not against a tampered CLI. If both came
from the same compromised clone, the pin is compromised with them, so the key
fingerprints in `signatures/README.md` should also be checked against a copy
obtained another way.

**Startup privilege drop.** The container runs as root at PID 1 because it must
chown the operator's key mount and then `su-exec` to `tor`. It probes
`su-exec tor true` first and fails with a named error if it cannot, rather than
looping. See "Residual risks" for why root is not removed.

**The build.** Base image pinned by digest; runtime apk packages pinned by exact
version (the throwaway compiler stage that builds mkp224o is not); pip
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
- **Two stacked seccomp filters.** Tor installs its own in-process filter
  (`Sandbox 1`), which covers **Tor alone** -- not the root supervisor, not
  Vanguards. The runtime's default profile is therefore left in place and stacks
  underneath it: the Tor process runs under two filters, everything else under
  one. Earlier releases shipped `seccomp=unconfined` on the belief that Tor's
  sandbox conflicted with it. That was wrong -- it was never reproduced, and a
  discovery run with the profile in logging mode recorded zero syscalls outside
  the allow list -- and its real effect was to leave the root supervisor
  completely unfiltered.
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
- **Multi-arch.** The image is one two-platform index (amd64 and arm64). The
  arm64 half is built under qemu emulation, reproduces to the same index digest,
  and boots in a full-system arm64 VM, but it has not run on real ARM hardware.
  See `docs/PRODUCTION-READINESS.md` R1 and R6.
- **Host-mode CI runner.** Jobs run as the operator on the workstation, so the
  workflow guards against fork pull requests (fail-closed). A compromised
  collaborator with push rights could still run code on the host.

## Key backup and at-rest encryption

**The key IS the address.** Losing `hs_ed25519_secret_key` loses the `.onion`
permanently: there is no recovery, no reset, and no reissue. Everything below is
about protecting a copy of it, and none of it changes that sentence.

The backup path is `hiddenforge backup` and the offline envelope tools;
`backup`/`encrypt-key` write an authenticated encrypted tar of the key volume.

### What an attacker who obtains the encrypted backup can and cannot do

Can: run an offline passphrase search at whatever rate their hardware allows.
Cannot: read the keys without the passphrase, or tamper with the archive
undetected (AEAD authenticates it; a single flipped byte fails decryption and
nothing is written).

**The passphrase is the entire security of the backup, and the KDF does not help
as much as an operator might assume.** The default tool is gpg, and its
key-derivation parameters, read back out of a real ciphertext rather than assumed:

```
:symkey enc packet: version 5, cipher 9, aead 2, s2k 3, hash 10, ...
        salt E7765042CB511874, count 65011712 (255)
:aead encrypted packet: cipher=9 aead=2 cb=16
```

`cipher 9` is AES-256 and `aead 2` is OCB, so the cipher is not the weak link.
But `s2k 3` with `hash 10` is *iterated and salted SHA-512* at gpg's maximum
count: iteration only, with **no memory hardness at all**. Nothing there
penalises an attacker for moving the search onto GPUs or ASICs, and gpg offers
no memory-hard S2K to switch to. So the cost of a guess is low and the number of
guesses is the only thing standing between an attacker and the key.

Choose the passphrase accordingly: it needs real, measured entropy (a long
diceware phrase, not a memorable sentence). `--tool age` derives its key with
scrypt instead (`-> scrypt <salt> 18`, i.e. N=2^18), which *is* memory-hard, but
`age -p` prompts on a TTY and cannot
run unattended, so it is not the path a scripted backup takes. `docs/INTEGRATION.md`
says to encrypt backups; this says why, and what the encryption does not do for you.

### What a local attacker observes during `encrypt-key`

- **Process table / `argv`:** nothing. The passphrase is written to an anonymous
  pipe and passed as `--passphrase-fd`, never on the command line, so
  `/proc/<pid>/cmdline` never contains it.
- **`/proc/<pid>/fd`:** the pipe is not readable by another uid; a same-uid
  attacker can already read process memory and is out of scope.
- **Filesystem:** nothing. `_tar_keys` assembles the tar in `io.BytesIO`; the
  plaintext never lands on disk. The output is opened with `O_NOFOLLOW` at mode
  `0600`.
- **The environment:** nothing, beyond the operator-supplied
  `--passphrase-file` path they control.

### Why openssl is refused, as a written position

openssl's `enc` provides encryption without authentication. A backup whose
integrity is not verified can be modified by anyone who can write the archive;
on restore that is a silent substitution of attacker-chosen key material. The
tool refuses openssl for creation rather than offering it as a footgun. This is
a deliberate, permanent position, not a missing feature.

### Why `--passphrase-fd` and not an argument or an environment variable

Both alternatives leak the passphrase to any process that can read the target's
`argv` or environment, which on a shared host is any same-user process. A pipe fd
is visible only to the child.

### The CFB fallback, and what it costs

On a gpg too old for `--force-aead`, `backup` falls back to CFB+MDC. MDC is an
integrity check, not an AEAD construction; the guarantee is weaker and the
failure mode under a chosen-ciphertext attack differs. The fallback is not
silent: it prints a warning naming the mode, the `--json` output carries
`cipher_mode`, and `--require-aead` refuses to proceed at all. Restore reports
which mode it decrypted. Use `--require-aead` for a production key.

### Explicitly out of scope

- A compromised host, a malicious gpg/age binary, or an attacker who already has
  the passphrase.
- An attacker who can read process memory as the same user.
- `hiddenforge` does **not** decrypt at boot. Tor needs the plaintext secret key
  in `HiddenServiceDir`, which is the mount, so runtime encryption would be
  theatre. The envelope tools are offline and manual.

What the script does with the secret key's *contents*, precisely: `backup` and
`encrypt-key` read it into an in-memory tar and encrypt that; `backup` reports
the SHA-256 of that plaintext tar (a fingerprint of the key set, which confirms a
guessed key set but reveals nothing else); `--delete-plaintext` decrypts its own
output and compares that hash before deleting anything. It is never printed and
never written to disk unencrypted except by `restore`/`decrypt-key`, which put it
back where it came from. `show`, `status` and `doctor` read only public files.

### Standards, honestly

- **NIST SP 800-57** (key management) applies *partially*: keys live only in the
  mounted volume and generation is separate from storage, but there is no formal
  lifecycle policy, no HSM, and rotation is a manual, destructive, opt-in
  command. Stated as partial, not met.
- **NIST SP 800-190** (container security) applies *partially*: read-only rootfs,
  dropped capabilities and non-root runtime processes are followed; the container
  still starts as root to drop privileges, and that trade-off is above.
- **No SP 800-53, ISO 27001 or SOC 2 mapping is claimed.** A fabricated mapping
  is worse than no mapping.

## How to check these claims

```bash
hiddenforge doctor --json                 # caps, read-only, modes, torrc directives
hiddenforge status --json                 # readiness + dropped_mappings
hiddenforge verify-image --json           # both signatures, against the PINNED keys
docker exec <c> su-exec tor tor --verify-config -f /etc/tor/torrc   # Tor accepts it
.venv/bin/pytest -q                       # the host unit/property suite
HIDDENFORGE_E2E=1 .venv/bin/pytest tests/test_e2e_live.py   # live acceptance
```
