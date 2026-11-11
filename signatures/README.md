# Signatures for HiddenForge 3.0.0

Image digest: `sambent.dev/sam/hiddenforge@sha256:RELEASE-DIGEST`

The same index is served as `doingfedtime/hiddenforge@sha256:RELEASE-DIGEST`
on Docker Hub. It covers `linux/amd64` and `linux/arm64`.

**What is signed:** 3.0.0 carries the **ML-DSA-65** signature
(`hiddenforge.digest.mldsa`) only. There is no hardware **SSH-FIDO2** signature
(`hiddenforge.digest.sig`) for this release. One may be added later over the same
digest, which would not need a new image. `hiddenforge verify-image` refuses a
release without it by default, and accepts with `--allow-pq-only`, reporting
`complete: false`.

**Files in this directory:**

| File | What it is |
|---|---|
| `hiddenforge.digest` | The signed text: the 3.0.0 image index digest |
| `hiddenforge.digest.mldsa` | ML-DSA-65 signature over `hiddenforge.digest` |
| `sambent-mldsa.pub` | The maintainer's ML-DSA-65 public key (pinned in `scripts/hiddenforge`) |
| `allowed-signers` | Every SSH key that has signed a release, for `ssh-keygen -Y verify` |
| `tor-release-keys.gpg` | Tor Project's release-signing keys; the Tor tarball's signature must verify against one |
| `dhi-apk@docker-0F81AD7700D99184.rsa.pub` | Docker's DHI package-index key |
| `alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub`, `...-616ae350.rsa.pub` | Alpine's x86_64 and aarch64 index keys (zlib comes from Alpine) |

The last four are not release signatures: they are the keys
`scripts/build_inputs.py` checks the build inputs against. Each was compared with
its publisher's own copy before it was pinned.

`cosign.pub` at the repository root verifies releases up to 2.0.3 only. It is not
used for 2.0.4 or later.

**Verify from master, not from the tag.** Signing an image needs the tag to exist
first, so a release's signatures are committed after its tag. A checkout of
`v3.0.0` therefore still holds the 2.1.6 signature files, which do not match the
3.0.0 digest. That mismatch means "look on master", not "tampered with".

The 2.1.6 signature (digest `sha256:1127470c84f461004dbca2f35e45c20e5fb669dddde05b13d433ce040692979c`,
ML-DSA-65; superseded by 3.0.0) is in git history at the last commit before
3.0.0's signatures. The 2.1.5 signature (digest `sha256:6eb375ecdfd1c7fbbd08517308c15708668d890e81ced8729141190c57d24a1d`,
ML-DSA-65; superseded by 2.1.6, see the CHANGELOG) is in git history at commit
`dc46389`. The 2.1.4 signature (digest `sha256:7732c01f505ba7826b422e2579d56f20c3f5ae11950336fb83507c1a35419582`,
ML-DSA-65; superseded by 2.1.5) is in git history at commit
`2ad14fd`. The 2.1.3 signature (digest `sha256:a9c985da5ceffa601da5d6aab17a6bbdacb4bb9a3e301b1c157d4f2ff04f27ad`,
ML-DSA-65; superseded by 2.1.4) is in git history at commit
`f1dbf20`. The 2.1.2 signature (digest `sha256:cc6c215d0a85b94ff7724951b2d6176111f508030235733afbb40116a93c3f05`,
ML-DSA-65; superseded by 2.1.3) is in git history at commit
`634b461`. The 2.1.1 signature (digest `sha256:889da0a9d21d7d3af87cba102e1c6ff5ea4b2618c46ea4cec26785a43ed89645`,
ML-DSA-65; superseded by 2.1.2) is in git history at commit
`d97c46b`. The 2.1.0 signature (digest `sha256:183a5df347fcf0cb84136b1f1f79f5f8bd29ba6f236662e744e47d1ffc2d1190`,
ML-DSA-65) is in git history at the commit that adds it (`cbcc1a1`). The 2.0.4
signatures (digest `sha256:063d824c3e56205bea5a3bfeb3d2d991de7dea88439cf6ebda8bb4b17ecce0ca`,
both halves) remain in the `v2.0.4` tag and in git history.

### Which digest to compare

Compare the **OCI index digest** extracted from `index.json` inside the archive,
never `docker image inspect --format '{{.Id}}'`. They are different values: the
`.Id` is the image config digest, the index digest covers the manifest list. A
verification that compares `.Id` reports a false "NOT REPRODUCIBLE".

### Architecture: what is verified

This release index is **multi-platform** (`linux/amd64` + `linux/arm64`), and the
**whole index** was reproduced: two clean builds of `v3.0.0` from fresh clones,
one under umask 007 and one under 022, produced the same index digest, which
covers both platform manifests. Both ran on the maintainer's machine; a build on
another machine is the check that would remove that single point. The arm64
half was built under qemu emulation on an amd64 host and run on a full-system
arm64 VM, but not on real ARM hardware.
An amd64-only build produces a different index digest than the two-platform
index, and that is expected, not a failure: reproduce with the same
`--platform` value the release used.

Signatures over that digest. No transparency log, no external service, nothing
to phone home to:

1. **ML-DSA-65** (FIPS 204, post-quantum): `hiddenforge.digest.mldsa`, made
   with `pqsign`. Its files are a 16-byte header followed by the raw FIPS 204
   key or signature, so stock OpenSSL 3.5 or later verifies them (older OpenSSL
   has no ML-DSA):
   ```
   # ML-DSA-65 with stock OpenSSL 3.5 or later (strip pqsign's 16-byte headers,
   # wrap the raw key as a SubjectPublicKeyInfo, verify)
   tail -c +17 sambent-mldsa.pub > /tmp/mldsa.key
   tail -c +17 hiddenforge.digest.mldsa > /tmp/mldsa.sig
   { printf '\060\202\007\262\060\013\006\011\140\206\110\001\145\003\004\003\022\003\202\007\241\000'
     cat /tmp/mldsa.key; } > /tmp/mldsa.der
   openssl pkeyutl -verify -pubin -keyform DER -inkey /tmp/mldsa.der \
     -in hiddenforge.digest -sigfile /tmp/mldsa.sig
   ```
   With `pqsign` installed, the equivalent is
   `pqsign verify --pub sambent-mldsa.pub --sig hiddenforge.digest.mldsa --in hiddenforge.digest`.
2. **SSH-FIDO2** (YubiKey hardware key): `hiddenforge.digest.sig`, not published for
   3.0.0. When a release carries one:
   ```
   ssh-keygen -Y verify -f allowed-signers -I sam@sambent.com -n file \
     -s hiddenforge.digest.sig < hiddenforge.digest
   ```

Check the keys before trusting a result. Signature files verify against
whatever public key sits beside them, so the keys are the trust anchor and must
match these values, which are also pinned in `scripts/hiddenforge`:

```
ssh-keygen -lf allowed-signers   # SHA256:YcUo1tBtj+Mlnpv9QpsWnJcMt77B4SipyD6OWSMjMB4
                                 # SHA256:wL6piZbyXpTOzT7Z66f/Q+vegj0Ml0ZwVouGJ06+3Q0
sha256sum sambent-mldsa.pub      # 4ae873ade7ee596c815f55f3052c0f01020b1817f86eaf15ab67c8fc77cbfd22
```

Confirm the digest you verified is the one you actually pulled:

```
skopeo inspect --raw docker://sambent.dev/sam/hiddenforge:3.0.0 | sha256sum
docker buildx imagetools inspect sambent.dev/sam/hiddenforge:3.0.0 | head -3
```

## Reproducing the build

This release is bit-for-bit reproducible. Every package, the Tor tarball and the
vendored crate come from the release's input archive; the only other things
the build pulls are the three Docker Hardened Images (base and builders) and
the BuildKit image, each by digest. `dhi.io` refuses anonymous pulls, so log in
first with any Docker account (`docker login dhi.io`). **Build from a fresh
clone**; this is not optional, see the warning below. The release was built
with a `docker-container` builder running **BuildKit v0.30.0**; arm64 needs
qemu's `binfmt_misc` handler for aarch64 on the host.

```
docker login dhi.io
git clone --branch v3.0.0 https://sambent.dev/sam/HiddenForge.git /tmp/hf && cd /tmp/hf
python3 scripts/build_inputs.py fetch \
  https://sambent.dev/api/packages/sam/generic/hiddenforge-inputs/3.0.0/hiddenforge-inputs-3.0.0.tar /tmp/hf-inputs
docker buildx version   # record this; buildx behaviour here is version-sensitive
docker buildx create --name repro --driver docker-container \
  --driver-opt image=moby/buildkit@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct v3.0.0)
docker buildx build --builder repro --no-cache --platform linux/amd64,linux/arm64 \
  --build-context inputs=/tmp/hf-inputs \
  --build-arg SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \
  --provenance=false --output type=oci,dest=out.tar,rewrite-timestamp=true .
tar -xOf out.tar index.json | python3 -c 'import json,sys;print(json.load(sys.stdin)["manifests"][0]["digest"])'
```

Record the versions you build with: `--provenance=false` and `rewrite-timestamp`
behave differently across buildx and BuildKit releases, so an unattributable
digest mismatch is otherwise impossible to diagnose.

Two requirements are load-bearing:

**`--provenance=false` is required.** buildx puts wall-clock build timestamps in
the SLSA provenance attestation, and that attestation lives *inside* the image
index, so leaving it on changes the index digest on every build and makes the
published digest impossible to reproduce.

**A fresh clone is required.** `rewrite-timestamp` *clamps* file mtimes to
`SOURCE_DATE_EPOCH` (`min(mtime, epoch)`); it does not set them equal. In a
fresh clone every file's mtime is the checkout time, which is newer than the
commit time, so all of them clamp to the same value and the build is
deterministic. In a working tree where files were edited at different times,
anything *older* than `SOURCE_DATE_EPOCH` keeps its own mtime and lands in the
layer verbatim, producing a digest only that particular tree can generate.
Releases are therefore built from a pristine checkout.

**Your umask does not matter from 2.1.1 on.** A clone takes its file modes from
the cloner's umask, and up to 2.1.0 every `COPY` recorded those modes in its
layer, so 2.1.0 reproduces only from a clone made under the same umask as the
one it was released from. From 2.1.1 every `COPY` states its mode with `--chmod`; clones
under umask 007 and 022 build the same digest, and CI checks exactly that.

**2.x tags no longer build; 3.0 tags do.** 2.x pinned exact Alpine package
versions, and Alpine prunes superseded builds from its index, so `v2.0.4` and
`v2.1.6` now fail at `apk add`. 3.0 builds from an archive of its inputs, which
`build-inputs.sha256` locks and `fetch` verifies. That archive is kept for the
current release and the one before it.

## Signing key rotation (as of 2.0.4)

Releases up to 2.0.3 were signed with a per-project key. From 2.0.4 the
maintainer signs with a single per-identity key (currently `SHA256:wL6piZbyXpTOzT7Z66f/Q+vegj0Ml0ZwVouGJ06+3Q0`).

`allowed-signers` retains every key that has ever signed a release, so older
releases remain independently verifiable. A signing key changing without
explanation is indistinguishable from a compromise, hence this note.

Nothing here depends on Sigstore (Fulcio, Rekor) or on cosign.

## Evidence bundle (what makes the readiness claims checkable)

`PRODUCTION-READINESS.md` states results; a reader cannot check a sentence. Each
release therefore ships an **evidence bundle** produced by
`scripts/collect_evidence.py`, containing the raw, unedited output of every gate
(unit tests, type check, mutation spot-check, manifest drift, lint), the coverage
JSON, the SBOM if present, and `build.json` binding all of it to the commit, its
tree hash and the image index digest. `MANIFEST.sha256` covers the rest:

```
python3 scripts/collect_evidence.py --out evidence --image sambent.dev/sam/hiddenforge:3.0.0
( cd evidence && sha256sum -c MANIFEST.sha256 )
```

No value in the bundle is typed by hand; a gate that cannot run records its own
failure rather than being omitted. The bundle was published for 2.1.0, 2.1.1 and
2.1.2 as `hiddenforge-<version>-evidence.tar.gz` on this forge's package registry
(<https://sambent.dev/sam/-/packages/generic/hiddenforge-release/>), with its
`MANIFEST.sha256` signed by the same ML-DSA-65 key. 2.1.3 to 2.1.6 have no bundle: each is the previous image with packages updated, and the record of its checks
is the CI run on its tag. 3.0.0 has one. A bundle is never committed (it would be stale
the next commit).
