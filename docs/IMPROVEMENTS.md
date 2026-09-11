# HiddenForge — improvement backlog

Compiled from a full read of the codebase, the git history, the in-tree wiki that
was removed in `5d44a21`, and the sibling project i2pforge, whose machine-first
contract this branch adopts for Tor.

Status legend: `[x]` done on this branch · `[ ]` not yet · `[-]` deliberate
decision not to do (reason given).

---

## A. Programmatic adoption (the i2pforge contract, for Tor)

- [x] **A1** Host CLI `scripts/hiddenforge`, stdlib-only, subcommands
  `setup · info · version · show · status · doctor · vanity · backup · restore ·
  rotate · encrypt-key · decrypt-key`.
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
  static, hash-verified archive) — see `vendor/README.md`.
- [x] **B2** `hiddenforge vanity --prefix <p> --name <n> [--threads N] [--out]`
  runs headless and writes a valid Tor key set
  (`hostname`, `hs_ed25519_public_key`, `hs_ed25519_secret_key`).
- [x] **B3** Refuses to overwrite an existing key without `--force`; never
  prints private key material.
- [x] **B4** `--bench` measures keys/sec on this machine and prints/returns the
  honest difficulty table (`32^L`, expected attempts and wall-clock) for
  prefixes 1..8.
- [x] **B5** `show --json` reports `onion`, `key_path`, `name`; vanity result is
  independently verified by deriving the address from the generated public key.
- [x] **B6** Documented path for long prefixes on a faster machine (run the same
  image's `vanity` on the fast box, copy the resulting key directory back).

## C. Truthful health & readiness

- [x] **C1** Healthcheck distinguishes *process up* → *Tor bootstrapped* →
  *hidden service published (address file exists)*, with bounded timeouts.
- [x] **C2** Never report ready before the address exists.
- [x] **C3** `status --json` exposes `running`, `healthy`, `bootstrapped`,
  `published`, `ready`, `address(es)`, `restarts`; documented fields to poll.
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
- [x] **D4** `backup` refuses unauthenticated tools for creation (no openssl),
  in-memory round-trip verification (i2pforge parity).
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
- [ ] **F4** Regenerate release signatures/SBOM for the new image digest
  (outside this branch's scope; needs the signing hardware).

## G. Docs

- [x] **G1** `docs/INTEGRATION.md` — "publish any app as a .onion", minimal
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
  (2.0.5) and the CLI's `setup` is single-service by construction; no extra
  rejection needed.
- [x] **H4** The hardening directive set is documented in one place in the CLI
  (`HARDENING_DIRECTIVES`) and asserted by the generator tests/smoke test.
- [x] **H5** `pyproject.toml` coverage comment corrected to the measured ~49% and
  the floor rationale restated.
- [x] **H6** `ALLOWED_DIRECTIVES` now lives in one place (`tests/directives.py`)
  and is imported by both `test_torrc_gen.py` and `test_fuzz.py`.
- [x] **H7** Vanguards is retried when it never started: the supervisor now
  retries with a bounded budget and backoff instead of only reacting to an
  observed exit.

## I. Things deliberately NOT changed

- [-] **I1** `VanguardsLiteEnabled 1` pinning, `--disable_vanguards`, and the
  L2-only limitation stay exactly as they are; they are deliberate security
  tradeoffs with wiki documentation.
- [-] **I2** Tor/`su-exec`/Python apk pins unchanged — bumping them is a separate,
  CVE-driven decision.
- [-] **I3** The existing `docker-compose.yml` human path stays byte-compatible
  in spirit (`docker compose up -d` still works); the new contract is additive.
