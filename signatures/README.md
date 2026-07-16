# Signatures for HiddenForge 2.0.3

Image digest: `doingfedtime/hiddenforge@sha256:2808baadbfd36bac856855067ef15413054b4b93fcacfc149fbb032ae35adc82`
(also at `sambent.dev/sam/hiddenforge@sha256:2808baad...`, same digest)

Three independent signatures over that digest, none using any transparency log:
1. **cosign** (own key), attached to the image. Verify:
   `cosign verify --key ../cosign.pub --insecure-ignore-tlog=true doingfedtime/hiddenforge@sha256:<digest>`
2. **ML-DSA-65** (FIPS 204, post-quantum): `hiddenforge.digest.mldsa`
   `pqsign verify --pub hiddenforge-mldsa.pub --sig hiddenforge.digest.mldsa --in hiddenforge.digest`
3. **SSH-FIDO2** (YubiKey): `hiddenforge.digest.sig`
   `ssh-keygen -Y verify -f allowed-signers -I sam@sambent.com -n file -s hiddenforge.digest.sig < hiddenforge.digest`

This release is reproducible: rebuild from the `v2.0.3` source with `SOURCE_DATE_EPOCH`
set to the commit time and buildx `rewrite-timestamp=true`, and you get this same digest.

No Sigstore, no Rekor, no transparency log.
