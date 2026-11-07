# Standards mapping

How HiddenForge 3.0 lines up with the security standards that apply to a
container image and the project that builds it. Each row names the evidence and
gives a status:

- **Met**: the control's intent is fully covered, and the evidence is a test,
  a CI job, a file or a measurement you can check.
- **Partial**: some of it is covered. The row says what is missing.
- **Not met**: it is not covered. The row says why.
- **N/A**: the control is about something HiddenForge does not do.

This is a mapping, not a certification. No assessor has reviewed it. Where a
standard is written for an organisation (an agency, a vendor) rather than for
one image, the row covers the part an image and its build can satisfy, and says
so.

Evidence paths are relative to the repository root. "CI" means
`.forgejo/workflows/ci.yml`; "doctor" means `hiddenforge doctor`, which reads
the limits a running container really has.

---

## NIST SP 800-190, Application Container Security Guide

Section 4 lists the risks; section 5 the countermeasures. One row per risk.

| Risk | Status | What HiddenForge does | Evidence |
|---|---|---|---|
| 4.1.1 Image vulnerabilities | Met | Zero known vulnerabilities at every severity, from two scanners with independent databases. A build with any finding fails. A nightly watchdog rescans the published image and alerts on any severity. | CI `trivy` and `grype` steps (`--severity UNKNOWN,…,CRITICAL`, `--fail-on negligible`) |
| 4.1.2 Image configuration defects | Met | No shell, no package manager, no interpreter, no setuid or setgid file. Tor's relay code compiled out. Starts as root by default for two documented reasons; no-root mode removes even that. | `Dockerfile`; SECURITY.md "Accepted findings"; image file list (767 entries, none setuid/setgid) |
| 4.1.3 Embedded malware | Partial | Every input is checked against its publisher's signature before it enters the build, and the build is offline. No malware scanner is run over the image; integrity of the inputs is the control relied on. | `scripts/build_inputs.py verify` |
| 4.1.4 Embedded clear-text secrets | Met | The image holds no secret. Service keys live on the operator's volume, optionally sealed. gitleaks scans every commit and the working tree. | CI `gitleaks` step |
| 4.1.5 Use of untrusted images | Met | Base and builder images are Docker Hardened Images pinned by digest; Docker's signed provenance was verified before adoption. The release is signed over its digest. | `Dockerfile` `ARG` digests; `signatures/` |
| 4.2.1 Insecure registry connections | Met | Both registries are HTTPS only. | registry URLs in README |
| 4.2.2 Stale images in registries | Partial | The watchdog alerts when the published image gains a finding. Old releases stay pullable by design (pinned deployments depend on them); SECURITY.md says which are supported. | SECURITY.md "Supported Versions" |
| 4.2.3 Insufficient registry authentication | Met | Push needs an authenticated token on the maintainer's own registry. Pull is anonymous on purpose. | release procedure |
| 4.3 Orchestrator risks | N/A | HiddenForge ships compose files, not an orchestrator. The compose files isolate the backend on an `internal: true` network. | `docker-compose.yml`, `podman-compose.yml` |
| 4.4.1 Runtime software vulnerabilities | Met | Two stacked seccomp filters (engine default plus Tor's `Sandbox 1`), `no-new-privileges`, all capabilities dropped and only the needed ones added. | compose files; doctor |
| 4.4.2 Unbounded network access | Met | The backend has no route out (`internal: true`). Tor's container resolves only through itself (`dns: 127.0.0.1`). Helpers run under Landlock with TCP denied. | compose files; `hiddenforge-rs/src/landlock.rs` |
| 4.4.3 Insecure container runtime configuration | Met | `doctor` fails a container with `seccomp=unconfined`, missing `no-new-privileges`, extra capabilities or swap. | `scripts/hiddenforge` `cmd_doctor` |
| 4.4.4 App vulnerabilities | Met | Tor and the guard monitors run as uid 100 with no capabilities. The supervisor confines itself with Landlock and holds no `CAP_KILL`. No process can dump core or be ptrace-attached. | measured `CapEff` (README "Security Architecture") |
| 4.4.5 Rogue containers | N/A | A host concern. |  |
| 4.5 Host OS risks | Partial | Outside the image. README recommends rootless Podman, where a container escape lands in an unprivileged user, and documents time sync and swap. Nothing enforces the host's configuration. | README "Rootless Podman" |

## NIST SP 800-218, Secure Software Development Framework (SSDF) 1.1

| Practice | Status | What HiddenForge does | Evidence |
|---|---|---|---|
| PO.1 Security requirements | Met | A written threat model states the adversary, what is defended and what is not. | `docs/THREAT-MODEL.md` |
| PO.3 Supporting toolchains | Met | Builders pinned by digest (DHI python dev, DHI rust); CI tools pinned by digest. | `Dockerfile`; CI |
| PO.5 Secure build environments | Partial | Builds are offline (no network inside the build) and reproducible. The CI runner is the maintainer's own machine, not an isolated, ephemeral build service. | CI; reproducibility check |
| PS.1 Protect all forms of code from tampering | Partial | Code is on the maintainer's own Forgejo with authenticated push. Commits are not signed; the signed release digest and the reproducible build are what bind the published image to the source. | release procedure |
| PS.2 Provide a mechanism to verify release integrity | Met | Each release is signed over its image digest with ML-DSA-65 (FIPS 204). `hiddenforge verify-image` checks it against keys pinned in the CLI. The planned second, hardware-held signature is not present for 3.0; the CLI reports that. | `signatures/`; `scripts/hiddenforge` `cmd_verify_image` |
| PS.3.1 Archive each release's components | Met | The exact build inputs are locked by hash in `build-inputs.sha256` and kept as one archive per release, for the current release and the one before it. | `build-inputs.sha256`; `scripts/build_inputs.py pack` |
| PS.3.2 Collect and share provenance (SBOM) | Partial | An SPDX SBOM can be produced for any published digest (`hiddenforge sbom`). No signed build-provenance attestation is published: buildx's embeds timestamps that would make the digest unreproducible, so reproducibility is offered instead. | `scripts/hiddenforge` `cmd_sbom` |
| PW.4 Reuse well-secured software | Met | Hardened vendor base images; Tor from its developers' signed release; one Rust crate (`libc`). | `Dockerfile`; `hiddenforge-rs/Cargo.lock` |
| PW.6 Compiler and build hardening | Met | Tor: `-D_FORTIFY_SOURCE=3` with fortify-headers, `-fstack-clash-protection`. Rust: overflow checks on in release, `panic = "abort"`, LTO. Control-flow integrity (CET) is not available on musl. | `Dockerfile`; `hiddenforge-rs/Cargo.toml` |
| PW.7 Review and analyse code | Met | `cargo clippy -D warnings`, `cargo fmt --check`, ruff; the Rust runtime was checked against the 2.x Python reference by differential tests. | CI |
| PW.8 Test executable code | Met | Unit tests, differential tests (torrc, setup, wizard, guard decisions), live end-to-end tests on Docker and rootless Podman. Mutation testing runs on changed code. | `tests/`; CI |
| PW.9 Secure defaults | Met | The shipped compose files are the hardened configuration; nothing needs turning on. | compose files |
| RV.1 Identify vulnerabilities continuously | Met | Nightly rescan at every severity; SECURITY.md reporting channel. | watchdog; `SECURITY.md` |
| RV.2 Assess, prioritise and remediate | Met | Response timeline in SECURITY.md; a finding in the published image triggers a release. | `SECURITY.md` |
| RV.3 Analyse root causes | Partial | Root causes are recorded in the CHANGELOG (the 3.0 rebuild exists because of one). There is no formal post-incident process. | `CHANGELOG.md` |

## NIST SP 800-53 Rev. 5 (selected controls)

| Control | Status | What HiddenForge does | Evidence |
|---|---|---|---|
| AC-6 Least privilege | Met | Per-process capability sets measured and documented; Tor and monitors hold none. No-root mode: nothing ever runs as root. | README; `hiddenforge setup --no-root` |
| CM-2 Baseline configuration | Met | Image inputs locked by hash; base by digest; generated torrc identical for identical environment. | `build-inputs.sha256`; `tests/rust/test_torrc_diff.py` |
| CM-7 Least functionality | Met | No shell or tools in the image. The 2.x compatibility names answer only the exact forms 2.x ran and refuse everything else. Relay code compiled out. | `hiddenforge-rs/src/compat.rs`; `tor --list-modules` in the build |
| CM-14 Signed components | Met | Package indexes verified against pinned DHI and Alpine keys; Tor against Tor's release keys; the release image is signed. | `scripts/build_inputs.py`; `signatures/` |
| RA-5 Vulnerability monitoring and scanning | Met | Two scanners at build; nightly rescan of the published image. | CI; watchdog |
| SA-10 Developer configuration management | Met | All changes through version control; release tags; CHANGELOG. | repository |
| SA-11 Developer testing and evaluation | Met | See SSDF PW.7 and PW.8. | CI |
| SC-28 Protection of information at rest | Partial | Opt-in: service keys sealed with AES-256-GCM under an scrypt-derived key, decrypted only into RAM. Off by default, and it protects a stopped volume or a backup, not a running host or a passphrase kept beside the volume. | `hiddenforge-rs/src/keycrypt.rs`, `sealed.rs` |
| SC-39 Process isolation | Met | Separate users, Landlock domains per helper, seccomp, no ptrace. | `hiddenforge-rs/src/landlock.rs` |
| SI-2 Flaw remediation | Met | Tor is compiled from source, so a Tor security release ships without waiting for a distribution package. | `Dockerfile` |
| SI-7 Software, firmware and information integrity | Met | Inputs verified before every build; the image verifiable after pull. | `scripts/build_inputs.py`; `hiddenforge verify-image` |
| SR-3 Supply chain controls | Met | Offline build from a locked, verified input set; two independent scanners. | as above |
| SR-4 Provenance | Partial | Every input's origin and signature is checked and recorded. No signed provenance attestation is published for the image (see SSDF PS.3.2). | `scripts/build_inputs.py` |
| SR-11 Component authenticity | Met | DHI provenance verified at adoption; DHI and Alpine index signatures and Tor signatures checked on every build. | `signatures/` |

## NIST SP 800-57 Part 1, key management

For the onion service key (Ed25519, generated by Tor or offline by `vanity`).

| Topic | Status | What HiddenForge does |
|---|---|---|
| Generation | Met | By Tor, or offline in a container with no network (`hiddenforge vanity`). |
| Storage | Partial | Mode 0600 in a 0700 directory owned by the tor user; optionally sealed. Sealing is opt-in. |
| Backup | Met | `hiddenforge backup` produces an authenticated encrypted archive (age, or gpg with `--require-aead`). |
| Rotation | Met | `hiddenforge rotate --confirm ROTATE` archives the old identity and starts a new one. |
| Destruction | Partial | A migrated plaintext key is overwritten before removal. On copy-on-write filesystems and SSDs an overwrite cannot reach every copy; the documentation says so. |

Cryptography used:

| Use | Algorithm | Standard | Note |
|---|---|---|---|
| Release signature | ML-DSA-65 | FIPS 204 | Algorithm, not a FIPS 140 validated module claim |
| Key sealing cipher | AES-256-GCM | SP 800-38D | 96-bit random nonce, 128-bit tag, the header authenticated as additional data |
| Key sealing KDF | scrypt (N=2^17, r=8, p=1) | RFC 7914 | **Not a NIST-approved KDF.** SP 800-132 specifies PBKDF2. scrypt was chosen for its memory hardness against offline guessing; a deployment that must use only approved algorithms should not enable sealing |
| Randomness | OpenSSL `RAND_bytes` | SP 800-90A DRBG in OpenSSL 3 | |

## SLSA v1.0, build track

| Level | Status | Why |
|---|---|---|
| Build L1 (provenance exists) | Not met | No provenance attestation is published (see SSDF PS.3.2). |
| Build L2, L3 | Not met | Follow from L1, and L3 needs an isolated build service. |

What is offered instead: anyone can rebuild the image from the tagged source and
the locked inputs and compare the digest. A reproducible build proves the same
thing provenance asserts, without trusting the builder.

## CIS Docker Benchmark (image and runtime sections)

| Recommendation | Status | Note |
|---|---|---|
| 4.1 Create a user for the container | Partial | Starts as root by default to hand the key volume to the tor user, then drops; no-root mode starts as uid 100 |
| 4.2 Use trusted base images | Met | DHI by digest |
| 4.3 Do not install unnecessary packages | Met | Tor's libraries and one binary |
| 4.4 Scan and rebuild images | Met | Two scanners, nightly |
| 4.5 Enable content trust | Alternative | Docker Content Trust is not used; the release is signed with ML-DSA-65 and verified by `hiddenforge verify-image` |
| 4.6 Add HEALTHCHECK | Met | In the image. The Podman compose file disables it on purpose (README) |
| 4.8 Remove setuid and setgid permissions | Met | None in the image |
| 4.9 Use COPY instead of ADD | Met | No `ADD` |
| 4.10 Do not store secrets in Dockerfiles | Met | None |
| 5.3 Restrict Linux kernel capabilities | Met | `cap_drop: ALL` plus the minimum |
| 5.10 Limit memory | Met | `mem_limit` with swap disabled |
| 5.12 Mount the root filesystem read-only | Met | `read_only: true` |
| 5.21 Do not disable the default seccomp profile | Met | doctor fails a container that does |
| 5.25 Restrict privilege escalation | Met | `no-new-privileges` |
| 5.28 Use the PIDs cgroup limit | Met | `pids_limit: 256` |
