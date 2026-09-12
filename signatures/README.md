# Signatures for HiddenForge 2.0.4

Image digest: `sambent.dev/sam/hiddenforge@sha256:063d824c3e56205bea5a3bfeb3d2d991de7dea88439cf6ebda8bb4b17ecce0ca`

These signatures cover the **2.0.4** release. The `2.1.0` branch is **not signed**
yet: `hiddenforge.digest` still holds the 2.0.4 digest, so a build from `2.1.0`
will not match it. That mismatch means "not yet signed", not "tampered with" --
but a verifier must not be left to guess which. See `docs/IMPROVEMENTS.md`.

### Which digest gets compared (this cost a full build cycle)

Compare the **OCI index digest** extracted from `index.json` inside the archive,
never `docker image inspect --format '{{.Id}}'`. They are different values: the
`.Id` is the image config digest, the index digest covers the manifest list. A
verification that compares `.Id` reports a false "NOT REPRODUCIBLE".

### Architecture: what is verified, and what is not

This release index is **multi-platform** (`linux/amd64` + `linux/arm64`). The
reproduction below is run on an amd64 builder, so **only the amd64 manifest has
been reproduced**; the arm64 manifest has not. An amd64-only build produces a
different index digest than the two-platform index, and that is expected, not a
failure -- reproduce with the same `--platform` value the release used. A
consumer on arm64 needs the arm64 manifest digest, which is not published here.
Until an arm64 build is reproduced on a builder that can run it, treat arm64 as
unverified.

Two independent signatures over that digest. No transparency log, no external
service, nothing to phone home to:

1. **ML-DSA-65** (FIPS 204, post-quantum) — `hiddenforge.digest.mldsa`
   ```
   pqsign verify --pub sambent-mldsa.pub --sig hiddenforge.digest.mldsa --in hiddenforge.digest
   ```
2. **SSH-FIDO2** (YubiKey hardware key) — `hiddenforge.digest.sig`
   ```
   ssh-keygen -Y verify -f allowed-signers -I sam@sambent.com -n file \
     -s hiddenforge.digest.sig < hiddenforge.digest
   ```

Confirm the digest you verified is the one you actually pulled:

```
skopeo inspect --raw docker://sambent.dev/sam/hiddenforge:2.0.4 | sha256sum
docker buildx imagetools inspect sambent.dev/sam/hiddenforge:2.0.4 | head -3
```

## Reproducing the build

This release is bit-for-bit reproducible. **Build from a fresh clone** — this is
not optional, see the warning below:

```
git clone https://sambent.dev/sam/HiddenForge.git /tmp/hf && cd /tmp/hf
git checkout v2.0.4
docker buildx version   # record this; buildx behaviour here is version-sensitive
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct v2.0.4)
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \
  --provenance=false --output type=oci,dest=out.tar,rewrite-timestamp=true .
tar -xOf out.tar index.json | python3 -c 'import json,sys;print(json.load(sys.stdin)["manifests"][0]["digest"])'
```

The verified amd64 reproduction was done with **buildx v0.19.3** (docker driver).
Record the version you build with: `--provenance=false` and `rewrite-timestamp`
behave differently across buildx releases, so an unattributable digest mismatch
is otherwise impossible to diagnose.

Two flags are load-bearing, and both were learned the hard way:

**`--provenance=false` is required.** buildx puts wall-clock build timestamps in
the SLSA provenance attestation, and that attestation lives *inside* the image
index — so leaving it on changes the index digest on every build and makes the
published digest impossible to reproduce.

**A fresh clone is required.** `rewrite-timestamp` *clamps* file mtimes to
`SOURCE_DATE_EPOCH` (`min(mtime, epoch)`) — it does not set them equal. In a
fresh clone every file's mtime is the checkout time, which is newer than the
commit time, so all of them clamp to the same value and the build is
deterministic. In a working tree where files were edited at different times,
anything *older* than `SOURCE_DATE_EPOCH` keeps its own mtime and lands in the
layer verbatim, producing a digest only that particular tree can generate.
Releases are therefore built from a pristine checkout.

## Signing key rotation (as of 2.0.4)

Releases up to 2.0.3 were signed with a per-project key. From 2.0.4 the
maintainer signs with a single per-identity key (currently `SHA256:wL6piZbyXpTOzT7Z66f/Q+vegj0Ml0ZwVouGJ06+3Q0`).

`allowed-signers` retains every key that has ever signed a release, so older
releases remain independently verifiable. A signing key changing without
explanation is indistinguishable from a compromise — hence this note.

No Sigstore, no Fulcio, no Rekor, no cosign.
