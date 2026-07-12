# Signatures for HiddenForge 2.0.2

Image digest: `doingfedtime/hiddenforge@sha256:0608533fb8a55a66a5308bf855f3f7a3576ab07a6ef24250846744a9766367d8`

Three independent signatures over that digest:
1. **cosign** (own key) — attached to the image on Docker Hub. Verify:
   `cosign verify --key ../cosign.pub --insecure-ignore-tlog=true doingfedtime/hiddenforge@sha256:<digest>`
2. **ML-DSA-65** (FIPS 204, post-quantum): `hiddenforge.digest.mldsa`
   `pqsign verify --pub hiddenforge-mldsa.pub --sig hiddenforge.digest.mldsa --in hiddenforge.digest`
3. **SSH-FIDO2** (YubiKey): `hiddenforge.digest.sig`
   `ssh-keygen -Y verify -f allowed-signers -I sam@sambent.com -n file -s hiddenforge.digest.sig < hiddenforge.digest`

No Sigstore, no Rekor, no transparency log.
