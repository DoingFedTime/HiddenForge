# Design decisions through 2.1.0

Historical record of the 2.1.0 branch, dated 2026-09-12 with later corrections.
It is not a description of the current release.

> **Superseded in five places (2026-09-25 and 2026-10-19).** This record is
> kept as written, but these lines are no longer true and the code wins: **E4**,
> the CLI now reads the secret key's bytes in `backup` and `encrypt-key`, to
> encrypt them, and never prints them; **C4**, the address file is written only
> once the service is reachable, not as soon as Tor writes the key; **I2**, the
> apk pins did move (tor, python3, openssl, zlib; see the CHANGELOG); **I3**, the
> compose file changed in ways an operator must act on (see "Upgrading from
> 2.0.4" in the README); and **R6 in OPEN**, now closed below.

**Closed 2026-09-12 at commit `7913514`.** This is a record of what this branch
changed and why, not a promise of future work. Sections A to I are the completed
ledger (each item is done `[x]` or a deliberate non-change `[-]` with its reason
recorded). The few genuinely open items are in **OPEN** at the end, each with the
reason it is open. If a claim here and the code disagree, the code wins.

The branch adopted the machine-first contract of the sibling project i2pforge for
Tor.

Status legend: `[x]` done on this branch · `[ ]` open (see OPEN) · `[-]`
deliberate decision not to do (reason given).

---

## A. Programmatic adoption (the i2pforge contract, for Tor)

- [x] **A1** Host CLI `scripts/hiddenforge`, stdlib-only, subcommands
  `setup · info · version · show · status · doctor · vanity · backup · restore ·
  rotate · encrypt-key · decrypt-key`, later joined by `verify-image · sbom`.
- [x] **A2** `setup` emits a mergeable `compose.service.yml` (service, both
  networks, key volume, caps, read-only/tmpfs/security-opt, env, healthcheck) so
  a consumer runs `docker compose -f their.yml -f compose.service.yml up -d`
  without editing our files.
- [x] **A3** `setup` also emits `deploy.sh`, `README.txt`, and
  `hiddenforge.json` (descriptor), like i2pforge.
- [x] **A4** `--backend service:port --name name` simple form in addition to the
  native `{NAME}_TOR_SERVICE_HOSTS`.
- [x] **A5** Configurable registry: `--image` everywhere, no hard-coded host a
  consumer must edit; documented.
- [x] **A6** `manifest.json` checked into the repo and shipped in the image;
  `info --json` prints it; `version --json` reports `contract_version`.
- [x] **A7** Non-interactive by default off-TTY; no prompts in `--json` mode.

## B. Vanity addresses (the biggest gap)

- [x] **B1** Vendor mkp224o (CC0) and build it into the image (multi-stage,
  static, hash-verified archive); see `vendor/README.md`.
- [x] **B2** `hiddenforge vanity --prefix <p> --name <n> [--threads N] [--keys DIR]`
  runs headless and writes a valid Tor key set
  (`hostname`, `hs_ed25519_public_key`, `hs_ed25519_secret_key`).
- [x] **B3** Refuses to overwrite an existing key without `--force`; never
  prints private key material.
- [x] **B4** `--bench` measures keys/sec on this machine and prints/returns the
  difficulty table (`32^L`, expected attempts and wall-clock) for
  prefixes 1..8.
- [x] **B5** `show --json` reports `onion`, `key_path`, `name`; vanity result is
  independently verified by deriving the address from the generated public key.
- [x] **B6** Documented path for long prefixes on a faster machine (run the same
  image's `vanity` on the fast box, copy the resulting key directory back).

## C. Truthful health & readiness

- [x] **C1** Healthcheck distinguishes *process up* → *Tor bootstrapped* →
  *hidden service published (address file exists)*, with bounded timeouts.
- [x] **C2** Never report ready before the address exists.
- [x] **C3** `status --json` exposes `running`, `healthy`, `tor_bootstrapped`,
  `hidden_service_published`, `ready`, `address(es)`, `restarts`; documented fields to poll.
- [x] **C4** Address file is written by the entrypoint once Tor publishes it, so
  a consumer can read it from the mount without docker exec.
- [x] **C5** Degraded Vanguards is surfaced (2.0.5 already; kept and extended to
  a machine-readable status file).

## D. Key lifecycle, scriptable

- [x] **D1** `show`, `backup`, `restore`, `rotate` support `--json`,
  `--non-interactive`, stable exit codes.
- [x] **D2** Safe on re-run; destructive ops need an explicit flag
  (`rotate --confirm ROTATE`, `restore --force`, `vanity --force`).
- [x] **D3** Docs state the key *is* the address, loss is permanent, backups must
  be encrypted.
- [x] **D4** `backup` refuses unauthenticated tools for creation (no openssl).
  (A round-trip check was planned for parity with i2pforge; only
  `encrypt-key --delete-plaintext` reads its output back before deleting.)
- [x] **D5** `encrypt-key` / `decrypt-key` with a documented at-rest envelope.
  They produce a real authenticated encrypted tar (age preferred, gpg with AEAD);
  a test asserts the blob does **not** contain tar member names (i.e. is actually
  encrypted). They require `age`/`gpg` on the host and fail closed without one;
  the image ships no crypto tooling.
  - [-] **D5a** Automatic decrypt-at-boot was **not** implemented: Tor requires
    the plaintext `hs_ed25519_secret_key` in `HiddenServiceDir`, which is the
    mount, so "plaintext only in tmpfs" cannot be true without writing it back to
    the mount and defeating the purpose. Envelope tools are offline-only and the
    limitation is documented. (Deliberate; reason recorded.)

## E. Security hardening of new surface

- [x] **E1** Service names (they become directories) validated: no traversal, no
  separators, no uppercase, ≤63, no NUL.
- [x] **E2** Key files 0600, key directories 0700; verified by `doctor`.
- [x] **E3** Symlink-resistant reads/writes for all new key-touching paths
  (`O_NOFOLLOW`, `lstat`, atomic rename).
- [x] **E4** No key material in stdout/stderr/`--json`/image layers; the secret
  file's bytes are never read by the CLI (only its size/mode for checks).
- [x] **E5** `doctor` verifies caps, `no-new-privileges`, read-only rootfs,
  AppArmor, pids/mem-swap caps, no published ports, and on-disk key modes.
- [x] **E6** Keep every existing hardening flag; new compose fragment uses the
  same minimal `cap_add` set.
- [x] **E7** Fail closed: invalid config or a failed generator exits non-zero and
  writes nothing.

## F. Supply chain

- [x] **F1** mkp224o archive hash-pinned and verified at build time; CC0 licence
  recorded.
- [x] **F2** New Python is stdlib-only (no new pip deps, no new attack surface).
- [x] **F3** New files covered by `.dockerignore` whitelist (no accidental
  context bloat, no secrets in layers).
- [ ] **F4** Regenerate release signatures/SBOM for the new image digest. The
  2.1.0 digest is signed with ML-DSA-65 and the SBOM ships with the release; the
  hardware (SSH-FIDO2) signature is still to come. See OPEN below.

## G. Docs

- [x] **G1** `docs/INTEGRATION.md`: "publish any app as a .onion", minimal
  merge, address retrieval, vanity, backup, JSON field reference.
- [x] **G2** Shell + Python consumer examples.
- [x] **G3** `CHANGELOG.md` entry.

## H. Code quality / efficiency (from the SME review)

- [x] **H1** The `_chmod_dir_nofollow(hs_dir)` → `_chown_r(hs_dir)` ordering is
  pinned by a source-order regression test in `test_privileged_fs.py` (the
  primitives were already covered; the order is what makes the symlink
  rejection effective).
- [x] **H2** Sanitise the "Service hosts:" startup echo (control characters from
  env could inject into logs/terminals).
- [-] **H3** Service-name collisions were already handled in `entrypoint.py`
  (2.0.5), so no extra rejection was added. (`setup` was single-service when this
  was written; it has since gained `--service`/`--services`, and the entrypoint's
  handling still covers collisions.)
- [x] **H4** The hardening directive set is documented in one place in the CLI
  (`HARDENING_DIRECTIVES`) and asserted by the generator tests/smoke test.
- [x] **H5** `pyproject.toml`'s coverage comment no longer states a measured
  percentage; the number is emitted by CI as `coverage.json` / `coverage.txt`
  (`scripts/coverage_summary.py`). The floor rationale is restated.
- [x] **H6** `ALLOWED_DIRECTIVES` now lives in one place (`tests/directives.py`)
  and is imported by both `test_torrc_gen.py` and `test_fuzz.py`.
- [x] **H7** Vanguards is retried when it never started: the supervisor now
  retries with a bounded budget and backoff instead of only reacting to an
  observed exit.

## I. Things deliberately NOT changed

- [-] **I1** `VanguardsLiteEnabled 1` pinning, `--disable_vanguards`, and the
  L2-only limitation stay exactly as they are; they are deliberate security
  tradeoffs with wiki documentation.
- [-] **I2** Tor/`su-exec`/Python apk pins unchanged; bumping them is a separate,
  CVE-driven decision.
- [-] **I3** The existing `docker-compose.yml` human path stays byte-compatible
  in spirit (`docker compose up -d` still works); the new contract is additive.

---

## OPEN (what this branch did not close, and why)

These are the only items in this document that are not DONE or a deliberate
non-change. Each is open for a stated reason, and none is silently implied to be
finished:

- **F4: the hardware half of the 2.1.0 signature.** 2.1.0 was released
  signed with ML-DSA-65 only, because the YubiKey that holds the SSH-FIDO2 key
  was not available. The hardware signature will be made over the same digest
  and added to `signatures/` and the release, with no rebuild and no new image.
  Until then `verify-image` refuses by default and accepts the ML-DSA half alone
  with `--allow-pq-only` (reported `complete: false`); `signatures/README.md` says so.
- **R6 (closed 2026-09-26).** The arm64 image is built in the same two-platform
  index as amd64, reproduces to the same digest, and boots in a full-system arm64
  VM (`docs/PRODUCTION-READINESS.md` R1, R6). It has not run on real ARM hardware.
- **Continuous pin-freshness (`scripts/check_pins.py`).** Pins are CVE-driven by
  hand today; the scheduled job reports when a pinned apk disappears from the
  Alpine index or a newer one exists, but bumping remains a reviewed decision.
