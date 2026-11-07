# Threat model

This is the in-repo threat model. It is deliberately concrete: every control
names where it lives in the code, and every limit says what it does not cover.
The wiki's Security Model page is the prose companion; this is the engineering
one. Last checked against release 2.1.6 on 2026-11-03.

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
| Network adversary | Runs or observes relays; can force circuit rebuilds | Vanguards-lite (L2), bandguards and rendguard detectors, 6 intro points |
| Backend application | Fully controls the thing behind the onion | **Nothing in this image.** See "What this cannot protect" |
| Local unprivileged process | Runs in the container or on the host | 0700/0600 keys, minimal caps, read-only rootfs, symlink-safe startup, Landlock, no core dumps |
| Code execution in the container | Gets a foothold through Tor or a monitor | No shell, interpreter or package manager to build on; uid 100 with no capabilities; seccomp twice over for Tor; Landlock with TCP denied for helpers |
| Supply chain | Compromises the base image, a package, the Tor tarball, the vendored crate or generator | DHI base by digest with provenance verified; offline build from the `build-inputs.sha256` lock; package indexes and Tor's signatures checked against pinned keys; SHA-256-verified vendor tarball |
| Base-image vendor | Docker Inc. builds the base image and rebuilds its packages (dhi.io/apk), so these binaries are Docker's builds, not Alpine's. One company, under one jurisdiction, that can be compelled | Digest pin, signature and provenance checks before adoption, a diff on every base update, an independent second scanner |
| The project's own registry | A compromised sambent.dev serves different blobs for the mirrored base or the archived inputs | Every input is consumed by a digest or hash pinned in the repository, so a swapped blob fails the build |
| A stolen release-signing key | Signs a malicious image as the maintainer | See "The release-signing key" below |
| A tampered wizard | Writes a malicious deploy script that the operator then runs | Check its hash against the signed release; the browser wizard cannot reach the network |
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

**Startup privilege drop.** By default the container starts as root at PID 1
because it must chown the operator's key mount before starting Tor and the
monitors as `tor`. It probes the drop first and fails with a named error if it
cannot, rather than looping. It then drops every capability it does not need,
confines itself with Landlock and gives up `CAP_KILL`. No-root mode (below)
removes root entirely.

**The build.** Base and builder images pinned by digest. Every other input
(packages, the Tor tarball, the vendored crate) comes from an archive locked by
`build-inputs.sha256`; `scripts/build_inputs.py verify` refuses any archive that
differs from the lock and checks every signature before the build runs, and the
build itself has no network. mkp224o is vendored as a deterministic tarball
whose SHA-256 the Dockerfile verifies. The build is bit-for-bit reproducible:
two clean two-platform builds with the same `SOURCE_DATE_EPOCH` produce an
identical OCI index.

## What this cannot protect against

The Tor layer is almost never what gets an onion service found. The image does
nothing about: the backend making outbound clearnet requests, absolute URLs or the
real hostname in rendered output, framework banners and ETags matchable against a
clearnet scan, identical content on both networks, timezone and locale leaks,
third-party assets, or the onion address being published next to a clearnet
identity. The README has the operational version of this list.

## Residual risks and accepted trade-offs

- **Root at PID 1 (default mode).** Required for the volume chown and the
  privilege drop. The network-facing processes (Tor, the monitors) run as `tor`.
  Containment comes from the capability set, `no-new-privileges`, `read_only` and
  Landlock, all but the last verified by `doctor`. No-root mode removes it.
- **Two stacked seccomp filters.** Tor installs its own in-process filter
  (`Sandbox 1`), which covers **Tor alone** -- not the supervisor, not the
  monitors. The runtime's default profile is therefore left in place and stacks
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
- **Key encryption at rest is opt-in.** Off by default because it needs a
  passphrase at every start, and HiddenForge restarts itself on purpose. See
  "Key encryption at rest" below for what it does and does not protect.
- **`nproc` must not be set.** `RLIMIT_NPROC` is counted per host uid and uid 100
  is shared with other containers; a low limit makes the drop to `tor` fail `setuid()`
  with `EAGAIN`. `pids_limit` is the correct per-container cap, and the compose
  files carry a comment so the ulimit is not re-added.
- **Multi-arch.** The image is one two-platform index (amd64 and arm64). The
  arm64 half is built under qemu emulation and reproduces to the same index
  digest. It boots and publishes an address under qemu user emulation with
  `TOR_SANDBOX=0` (qemu cannot load Tor's seccomp filter), but it has not run on
  real ARM hardware.
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
as much as an operator might assume.** For scripted use the tool is gpg (age
needs an interactive terminal), and its key-derivation parameters, read back out of a real ciphertext rather than assumed:

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

### Standards coverage

See [COMPLIANCE.md](COMPLIANCE.md): one row per control of NIST SP 800-190,
SP 800-218, selected SP 800-53r5, SP 800-57, SLSA and the CIS Docker Benchmark,
each with its evidence and an honest Met, Partial or Not met. "Mapped to",
never "certified": no assessor has reviewed it.

## The 3.0 trust boundaries

### The base image

3.0 uses Docker Hardened Images unchanged as the base: same layers, same
digest, so anyone can confirm the base is Docker's published image. The base is
adopted only by digest. A targeted image would have a new digest, and the pin
refuses it, so the only way a malicious base gets in is through an update this
project chooses to adopt. Before every adoption: verify Docker's signature and
provenance, diff the package list and the binaries against the previous base,
scan with two scanners, and record the result. The limit, stated plainly: a
reproducible build proves this project's build was not tampered with. It proves
nothing about a base that was malicious when it was signed. A vendor that is
compelled to ship a signed, malicious update and does so is not caught by any
control here, beyond the diff on update. The base digest is published with each
release, so others can watch it too.

### Tor

Tor is compiled from Tor Project's release tarball. Its SHA-256 file's
signature is checked against Tor's release-signing keys, which are pinned in
this repository, and the build checks the hash again; the compile is
deterministic (the reproducible build covers it). This
removes the wait for a distribution package when Tor ships a security fix. Trust
moves to Tor Project's signing keys, which a Tor user already trusts.

### The release-signing key

3.0 is signed with the existing ML-DSA-65 key only. The hardware (SSH-FIDO2)
half of the hybrid signature is not available for this release, and
`verify-image` reports the result as `complete: false`, as for 2.1.x. The key is
kept as a file on the maintainer's workstation (mode 0600). Anyone who obtains a
copy of that file can sign as the maintainer. The hybrid design exists to close
exactly this gap: with both halves, a stolen file alone is not enough. It stays
open until the hardware half is added over the same digest.

### Source authenticity

Commits are not signed. The source at a release tag is proven by the
reproducible build: rebuilding the tagged source must reproduce the signed
digest, and changed source would not. Commits between releases are not
authenticated by anything, so only tagged, signed releases are meant to be run.

### The wizards

- **Browser wizard:** one local HTML file, opened from disk, with no server. A
  Content-Security-Policy blocks every network request, so even tampered code
  inside it cannot send anything anywhere. Its output is a deploy script that
  the operator runs, so a tampered copy means a tampered script: check the
  file's hash against the signed release before using it.
- **Terminal wizard:** `hiddenforge setup`. The same command exists in the
  signed image (`docker run --rm --network none <image> setup ...`), where the
  image signature covers it, and as the host CLI in the tagged source.

### No-root mode (opt-in)

The container runs as `tor` (uid 100, gid 101) from the start, with every
capability dropped and none added, and with no chown at boot. The operator
makes the key directory owned by 100:101 once (`setup --no-root` writes a deploy
script that does it), and the entrypoint refuses to start if it is not. For
operators who choose it, this removes "Root at PID 1" from the residual risks.

### Key encryption at rest (opt-in)

The secret key is stored encrypted on the volume and decrypted into a tmpfs (RAM)
at every start. This replaces the earlier position that decrypt-at-boot is
theatre. That position is correct only when the passphrase sits next to the key.
What it protects: the volume, a disk or a backup taken while the service is not
running, as long as the passphrase is supplied from somewhere else. What it does
not protect: a running host, where the key is in memory, or a passphrase file
stored on the same disk. The passphrase is needed at every start, and
HiddenForge restarts itself on purpose (backend moves, Tor exits, reboots).
Swap must stay disabled, as the compose files already require, so the
plaintext never reaches disk. A container with a sealed key and no passphrase
refuses to start rather than generate a new address. `unseal-keys` turns it off:
it restores the plaintext key, checks it reads back as the sealed content, and
only then removes the sealed copy.

### Client authorization (opt-in)

By default anyone who learns the address can reach the service, and an address
leaks (screenshots, logs, a seized phone). With `client-auth`, Tor encrypts the
descriptor to the authorized clients' keys, so the address alone is useless:
without a key the service's introduction points cannot even be found. The
service holds only public keys, so its volume leaking does not let anyone in.
What it does not do: protect a client whose own key is stolen, or replace
authentication inside the application. A removed client keeps access until the
next restart.

### No shell in the image

The runtime image has no shell, no busybox and no package manager. Someone who
gets code execution in the container finds no tools to build on. The names 2.x
commands use (`sh`, `cat`, `su-exec`, `python3`, `test`, `true`) are the
`hiddenforge` binary, and each answers only the exact forms 2.x ran.

## How to check these claims

```bash
hiddenforge doctor --json                 # caps, read-only, modes, torrc directives
hiddenforge status --json                 # readiness + dropped_mappings
hiddenforge verify-image --json           # both signatures, against the PINNED keys
docker exec <c> su-exec tor tor --verify-config -f /etc/tor/torrc   # Tor accepts it
python3 scripts/build_inputs.py verify <inputs dir>   # the build inputs are the locked ones
.venv/bin/pytest -q                       # the host unit/property suite
HIDDENFORGE_E2E=1 .venv/bin/pytest tests/test_e2e_live.py   # live acceptance
```
