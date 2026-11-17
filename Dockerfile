# HiddenForge 3.0
#
# Every input is pinned and comes from places this project controls or verifies:
#   * base and build images: Docker Hardened Images, by digest, used UNCHANGED
#     (Docker's signed provenance verified before adoption; copies kept on
#     sambent.dev). The runtime base is dhi.io/static (musl): no shell, no
#     package manager, no Python.
#   * packages: the exact .apk files, verified against Docker's signed APKINDEX
#     (and, for zlib, Alpine's), installed with --no-network from the
#     `inputs` build context. Every RUN step has --network=none, so nothing
#     can be fetched while building, whatever a tool inside it tries.
#   * Tor: compiled here from Tor Project's release tarball (signature checked
#     against Tor's release keys before archiving; SHA-256 pinned below).
#   * the runtime: one Rust binary (hiddenforge-rs/), whose only crate is libc
#     (vendored, checked against Cargo.lock); it links the image's libcrypto.
#
# Build (reproducible):
#   docker buildx build --builder reprobuilder --no-cache --provenance=false \
#     --build-context inputs=<inputs dir> \
#     --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
#     --output type=oci,dest=hf.tar,rewrite-timestamp=true .

# Where the three images come from. By default Docker's registry; our own
# builds pass --build-arg BASES=sambent.dev/sambent/dhi- to take the same
# digests from the copies on sambent.dev. A digest names fixed bytes, so the
# image built is the same either way.
ARG BASES=dhi.io/
ARG C_BUILDER=${BASES}python@sha256:11c956fbc326c0aab95d9b913e77d25280855a494029bc63dac1824101b48766
ARG RUST_BUILDER=${BASES}rust@sha256:cd4666a1b76c2a8a9c9e01282183e25703fe8c81a42e208be1a44f50467362b6
ARG RUNTIME=${BASES}static@sha256:36ef09f98be60351289f3aaf36a4328e2121821dce7f8f85ba099efef43bd329

FROM ${RUNTIME} AS runtime

# ── C builds: Tor and mkp224o ───────────────────────────────────────────────
FROM ${C_BUILDER} AS cbuild
ARG SOURCE_DATE_EPOCH=0
SHELL ["/bin/sh", "-eu", "-o", "pipefail", "-c"]
COPY --from=inputs apk /repo
COPY --from=inputs apk-alpine /repo-alpine
COPY --from=inputs index/APKINDEX-x86_64.tar.gz /repo/x86_64/APKINDEX.tar.gz
COPY --from=inputs index/APKINDEX-aarch64.tar.gz /repo/aarch64/APKINDEX.tar.gz
COPY --from=inputs index/APKINDEX-alpine-main-x86_64.tar.gz /repo-alpine/x86_64/APKINDEX.tar.gz
COPY --from=inputs index/APKINDEX-alpine-main-aarch64.tar.gz /repo-alpine/aarch64/APKINDEX.tar.gz
COPY --from=inputs tor/tor-0.4.9.17.tar.gz /src/tor.tar.gz
COPY --chmod=0644 vendor/mkp224o-5172c0fd.tar.gz /src/mkp224o.tar.gz
# Offline, from the verified local repositories only.
RUN --network=none printf '/repo\n/repo-alpine\n' > /etc/apk/repositories; \
    apk add --no-cache --no-network \
        make fortify-headers libevent-dev openssl-dev zlib-dev=1.4-r0 zlib=1.4-r0 zstd-dev xz-dev \
        libseccomp-dev libcap-dev autoconf automake libsodium-dev libsodium-static; \
    rm -f /var/log/apk.log
# Tor: relay and directory-authority code compiled out (an onion service never
# runs it); --enable-gpl is required for the proof-of-work DoS defence.
# (`cd` inside RUN: the SHELL has -e, so a failed cd stops the build. DL4006:
# hadolint accepts pipefail only for bash/ash/zsh by name; this sh honours it.)
# hadolint ignore=DL3003,DL4006,SC2164
RUN --network=none echo "ff372c41ee7013557fe5b7acd96c909950b27a7959c59fcb87c02591682fabe2  /src/tor.tar.gz" | sha256sum -c -; \
    mkdir /src/tor && tar -xzf /src/tor.tar.gz -C /src/tor --strip-components=1; \
    cd /src/tor; \
    CFLAGS="-O2 -D_FORTIFY_SOURCE=3 -fstack-clash-protection -ffile-prefix-map=/src/tor=. -fno-ident" \
    LDFLAGS="-Wl,--build-id=none" \
      ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
        --enable-gpl --disable-module-relay --disable-asciidoc --disable-html-manual \
        --disable-manpage --disable-unittests >/dev/null; \
    make -j"$(nproc)" >/dev/null; \
    strip src/app/tor; \
    mkdir -p /out/usr/bin /out/usr/share/tor; \
    cp src/app/tor /out/usr/bin/tor; \
    cp src/config/geoip src/config/geoip6 /out/usr/share/tor/; \
    /out/usr/bin/tor --list-modules
# mkp224o: the vanity-address generator, one static binary (CC0-1.0).
# hadolint ignore=DL3003,DL4006,SC2164
RUN --network=none echo "1f951ed82577436fe2c160c01f7754170010137c2182eae7e47fce65f000dc8d  /src/mkp224o.tar.gz" | sha256sum -c -; \
    mkdir /src/mkp && tar -xzf /src/mkp224o.tar.gz -C /src/mkp --strip-components=1; \
    cd /src/mkp; ./autogen.sh; \
    CFLAGS="-O3 -ffile-prefix-map=/src/mkp=. -fno-ident" ./configure LDFLAGS="-static -Wl,--build-id=none" >/dev/null; \
    make -j"$(nproc)" >/dev/null; strip mkp224o; \
    mkdir -p /out/usr/local/bin; cp mkp224o /out/usr/local/bin/mkp224o

# ── Rust build: the runtime binary ──────────────────────────────────────────
FROM ${RUST_BUILDER} AS rbuild
ARG SOURCE_DATE_EPOCH=0
SHELL ["/bin/sh", "-eu", "-o", "pipefail", "-c"]
COPY --from=inputs apk /repo
COPY --from=inputs index/APKINDEX-x86_64.tar.gz /repo/x86_64/APKINDEX.tar.gz
COPY --from=inputs index/APKINDEX-aarch64.tar.gz /repo/aarch64/APKINDEX.tar.gz
COPY --from=inputs cargo/vendor /cargo/vendor
COPY --from=inputs cargo/config.toml /root/.cargo/config.toml
WORKDIR /build
COPY --chmod=0644 hiddenforge-rs/Cargo.toml hiddenforge-rs/Cargo.lock /build/
COPY --chmod=0644 hiddenforge-rs/src /build/src
# Linked against the image's own libcrypto (the one Tor uses, from the same
# verified package), so there is one OpenSSL in the image and a CVE scan of
# the libcrypto3 package covers the key-encryption code too.
RUN --network=none echo /repo > /etc/apk/repositories; \
    apk add --no-cache --no-network openssl-dev; \
    RUSTFLAGS="--remap-path-prefix=/build=. --remap-path-prefix=/cargo/vendor=vendor -C link-arg=-Wl,--build-id=none" \
      cargo build --release --locked --offline; \
    install -D -m 0755 target/release/hiddenforge /out/usr/local/bin/hiddenforge

# ── Assemble: the extra runtime libraries, installed into a copy of the base ─
FROM cbuild AS assemble
ARG SOURCE_DATE_EPOCH=0
SHELL ["/bin/sh", "-eu", "-o", "pipefail", "-c"]
COPY --from=runtime / /rt
COPY --from=rbuild /out/ /stage/
# The directories first: a COPY --chmod=0644 that creates its destination
# directory gives the directory 0644 too, and nobody but root can enter it
# (2.1.1 shipped exactly that).
RUN --network=none mkdir -p /stage/opt/hiddenforge /stage/usr/share/licenses/hiddenforge
COPY --chmod=0644 manifest.json /stage/opt/hiddenforge/manifest.json
COPY --chmod=0644 LICENSE /stage/usr/share/licenses/hiddenforge/LICENSE
# hadolint ignore=DL3003,DL4006,SC2164
RUN --network=none cp -a /out/. /stage/; \
    # Installed through apk into the copy, so the base's package database
    # records them and every scanner sees exactly what the image holds.
    apk --root /rt --keys-dir /etc/apk/keys --repositories-file /etc/apk/repositories \
        add --no-cache --no-network --no-scripts \
        libevent libssl3 libcrypto3 zlib=1.4-r0 zstd-libs xz-libs libseccomp libcap2; \
    mkdir /delta; \
    for p in libevent libssl3 libcrypto3 zlib zstd-libs xz-libs libseccomp libcap2; do \
      apk --root /rt --no-network info -q -L "$p" | grep -v '^$' | while read -r f; do \
        mkdir -p "/delta/$(dirname "$f")"; cp -a "/rt/$f" "/delta/$f"; \
      done; \
    done; \
    mkdir -p /delta/lib/apk/db; cp -a /rt/lib/apk/db/installed /delta/lib/apk/db/installed; \
    cp -a /stage/. /delta/; \
    # The tor user: uid 100, gid 101, as in every earlier release (live key volumes depend on it).
    mkdir -p /delta/etc; \
    { cat /rt/etc/passwd; echo 'tor:x:100:101:tor:/var/lib/tor:/sbin/nologin'; } > /delta/etc/passwd; \
    { cat /rt/etc/group; echo 'tor:x:101:tor'; } > /delta/etc/group; \
    chmod 0644 /delta/etc/passwd /delta/etc/group; \
    # One other name for the binary: su-exec, only because compose files
    # already on operators' hosts declare the healthcheck as
    # `su-exec tor python3 /usr/local/bin/healthcheck.py`, which an image update
    # cannot change. That exact command runs the native healthcheck; nothing
    # else answers to it (hiddenforge-rs/src/compat.rs).
    cd /delta; \
    mkdir -p sbin; ln -s /usr/local/bin/hiddenforge sbin/su-exec; \
    mkdir -p var/lib/tor/hidden_service etc/tor tmp; \
    chown 100:101 var/lib/tor; chmod 0700 var/lib/tor; chmod 1777 tmp; \
    # Every directory must be enterable by the tor user, except the two that
    # are meant not to be. Fail the build otherwise.
    bad="$(find /delta -type d ! -perm -0005 ! -path /delta/var/lib/tor)"; \
    if [ -n "$bad" ]; then echo "directories the tor user cannot enter: $bad" >&2; exit 1; fi; \
    find /delta -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

# ── The image: DHI static, unchanged, plus one layer ────────────────────────
FROM runtime
ARG SOURCE_DATE_EPOCH=0
LABEL org.opencontainers.image.title="HiddenForge" \
      org.opencontainers.image.description="Hardened Tor v3 onion service container" \
      org.opencontainers.image.version="3.0.1" \
      org.opencontainers.image.source="https://sambent.dev/sam/HiddenForge" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.base.name="dhi.io/static:20261020-musl-alpine3.23" \
      org.opencontainers.image.base.digest="sha256:36ef09f98be60351289f3aaf36a4328e2121821dce7f8f85ba099efef43bd329"
COPY --from=assemble /delta/ /
ENV HOME=/var/lib/tor \
    HIDDENFORGE_KEYS_DIR=/var/lib/tor/hidden_service \
    HIDDENFORGE_IN_CONTAINER=1 \
    PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
# Root at start (default mode) only to hand the key volume to tor and drop;
# Tor and the guards run as uid 100 with no capabilities. No-root mode: start
# the container as 100:101 (see `hiddenforge setup --no-root`). SECURITY.md,
# "Accepted findings", records why.
# hadolint ignore=DL3002
USER 0
VOLUME ["/var/lib/tor/hidden_service/"]
HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
    CMD ["hiddenforge", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/hiddenforge", "run"]
