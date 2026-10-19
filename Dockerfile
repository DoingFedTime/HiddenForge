# ── Stage 1: mkp224o, the vanity-address generator ──────────────────────────
# Vendored and built here so the runtime image ships one static, self-contained
# binary and needs no libsodium. The generator source is a deterministic
# `git archive` of cathugger/mkp224o @ 5172c0fd, verified by SHA256 before use;
# see vendor/README.md (licence: CC0-1.0).
FROM alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS mkp224o-build
ARG SOURCE_DATE_EPOCH=0
# pipefail, so a failing `sha256sum -c` in the pipeline cannot be masked.
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
WORKDIR /src
COPY vendor/mkp224o-5172c0fd.tar.gz /tmp/mkp224o.tar.gz
# DL3018: these are BUILD-ONLY dependencies and are deliberately not
# version-pinned. Alpine prunes superseded versions from its index (which has
# repeatedly broken this image's pinned runtime packages), and none of them
# ship in the final image -- the static mkp224o binary is the only artefact that
# does. The runtime stage's apk add IS pinned, because those packages ship.
# hadolint ignore=DL3018
RUN echo "1f951ed82577436fe2c160c01f7754170010137c2182eae7e47fce65f000dc8d  /tmp/mkp224o.tar.gz" \
      | sha256sum -c - && \
    apk add --no-cache build-base autoconf libsodium-dev libsodium-static && \
    tar -xzf /tmp/mkp224o.tar.gz -C /src --strip-components=1 && \
    ./autogen.sh && \
    # CFLAGS pinned to -O3: upstream configure otherwise injects -march=native,
    # which breaks bit-for-bit reproducibility and can emit instructions that
    # fault on a different CPU than the build host.
    CFLAGS="-O3" ./configure LDFLAGS="-static" && \
    make -j"$(nproc)" && \
    strip mkp224o && \
    cp mkp224o /mkp224o && \
    rm -f /var/log/apk.log

# ── Stage 2: the runtime image ────────────────────────────────────────────
FROM alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

# SOURCE_DATE_EPOCH: a UNIX timestamp (set by the build to the source commit
# time) used to make the image reproducible. Consumed below to pin the one
# clock-derived field apk writes into /etc/shadow when it creates the tor user.
ARG SOURCE_DATE_EPOCH=0

ENV HOME=/var/lib/tor
ENV PYTHONUNBUFFERED=1
# Default key volume used by the in-image CLI (scripts/hiddenforge).
ENV HIDDENFORGE_KEYS_DIR=/var/lib/tor/hidden_service
# Lets the CLI give host-specific guidance when a command needs tooling that the
# image deliberately does not ship (age/gpg for backup/encrypt-key).
ENV HIDDENFORGE_IN_CONTAINER=1
# Suppress .pyc file generation — no bytecode debris on disk
ENV PYTHONDONTWRITEBYTECODE=1
# Silence the pip self-update check at build time
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Install Tor and Python runtime with pinned package versions.
# py3-pip is a build-only dep — removed after the venv is bootstrapped, leaving
# no pip/installer tooling in the final image. (The Python stdlib still ships
# urllib/ssl; what we remove are the third-party package manager and HTTP
# clients, not the language's built-in modules.)
#
# py3-pip is installed DIRECTLY, not via `apk add --virtual .build-deps`.
# A virtual package would be the conventional way to drop a build dep and its
# orphans in one go, but apk assigns every virtual package a self-generated
# checksum in /lib/apk/db/installed, and that checksum was observed to differ
# between two builds of identical source — producing different image digests
# and silently breaking the reproducible-build guarantee (the failure looks
# exactly like image tampering to anyone verifying it). Installing py3-pip by
# name removes that record entirely; `apk del py3-pip` below still reclaims all
# eight packages (py3-pip plus the py3-packaging/py3-parsing/py3-setuptools
# tree it pulls in), because apk already tracks auto-installed dependencies —
# verified: nothing is left behind versus the pre-pip package set.
#
# rm apk.log because it records wall-clock operation times, which would also
# break reproducibility.
# openssl is pinned EXPLICITLY rather than inherited from the base digest. The
# base image ships 3.5.7-r0, against which Alpine's index now carries 3.5.9-r0
# (3.5.8-r0 was pruned; it was the first pin here for CVE-2026-14456 and a batch
# of other OpenSSL issues). Pin the fix so the image
# does not silently depend on whichever OpenSSL the base happens to contain.
# zlib is pinned for the same reason: the base ships 1.3.2-r0, which carries
# CVE-2026-85091 (heap buffer overflow), and Tor links it to decompress directory
# documents it receives from relays, so the bug is reachable from the network.
RUN apk add --no-cache \
    tor=0.4.9.14-r0 \
    python3=3.12.15-r0 \
    su-exec=0.3-r0 \
    py3-pip=25.1.1-r1 \
    openssl=3.5.9-r0 \
    zlib=1.3.2-r1 && \
    rm -f /var/log/apk.log && \
    # apk stamps a new account's shadow "last-change" field with the current day
    # (days since 1970) when it creates the tor user. Pin every account's field
    # to the SOURCE_DATE_EPOCH day so /etc/shadow is byte-identical regardless of
    # build date. Applied to all rows (not just tor) so a future package that
    # adds a user cannot silently reintroduce nondeterminism. Only affects
    # reproducibility; these are locked system accounts with no login.
    sed -i "s#^\([^:]*:[^:]*\):[0-9]*:#\1:$(( SOURCE_DATE_EPOCH / 86400 )):#" /etc/shadow

# Install Vanguards guard-protection addon in an isolated venv.
# vanguards 0.3.1 (PyPI) uses the removed SafeConfigParser API from Python
# 3.12 — upstream PR #105 has been unmerged since 2024, so we patch it here.
#
# All packages are installed with --require-hashes so pip will abort if any
# downloaded file does not match the SHA256 recorded in requirements.txt.
#
# After install we strip pip, setuptools, and any test / cache artefacts from
# the venv so no third-party installer or HTTP-client packages remain in the
# final image (the Python stdlib's urllib/ssl cannot be removed and still ship).
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/vanguards-venv && \
    /opt/vanguards-venv/bin/pip install \
      --no-cache-dir \
      --no-deps \
      --require-hashes \
      -r /tmp/requirements.txt && \
    sed -i \
      's/from configparser import SafeConfigParser/from configparser import RawConfigParser as SafeConfigParser/' \
      /opt/vanguards-venv/lib/python3.12/site-packages/vanguards/config.py && \
    # Fail the build loudly if the patch did not apply (sed exits 0 even on no
    # match). A future vanguards release that changes this import would otherwise
    # ship a broken venv silently.
    grep -q 'from configparser import RawConfigParser as SafeConfigParser' \
      /opt/vanguards-venv/lib/python3.12/site-packages/vanguards/config.py && \
    # Each tolerated failure is GROUPED. Written bare, `A && B || true && C`
    # parses as `(A && B) || true && C`, so the `|| true` meant for one cleanup
    # step also swallowed a --require-hashes mismatch in the pip install and the
    # grep above: the build succeeded and shipped a broken venv.
    { /opt/vanguards-venv/bin/pip uninstall -y pip setuptools wheel 2>/dev/null || true; } && \
    { find /opt/vanguards-venv -type d -name 'test'  -exec rm -rf {} + 2>/dev/null || true; } && \
    { find /opt/vanguards-venv -type d -name 'tests' -exec rm -rf {} + 2>/dev/null || true; } && \
    { find /opt/vanguards-venv -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true; } && \
    find /opt/vanguards-venv -name '*.pyc' -delete && \
    find /opt/vanguards-venv -name '*.pyo' -delete && \
    rm /tmp/requirements.txt && \
    apk del py3-pip && \
    rm -f /var/log/apk.log

# Set up Tor data directory and config directory.
# DataDirectory must be mode 700 — Tor refuses to create a ControlSocket in a
# world-readable directory (it validates this before starting).
RUN mkdir -p ${HOME}/.tor /etc/tor && \
    chown -R tor:tor ${HOME} && \
    chmod 700 ${HOME}

# Copy entrypoint, healthcheck, the operator CLI, the vanity wrapper, the
# machine contract, and the in-container smoke test only.
# The host unit suite runs on the build host / in CI - it is deliberately NOT
# shipped in the image.
COPY --from=mkp224o-build /mkp224o /usr/local/bin/mkp224o
COPY entrypoint.py /usr/local/bin/entrypoint.py
COPY healthcheck.py /usr/local/bin/healthcheck.py
COPY vanity.py /usr/local/bin/vanity.py
COPY scripts/hiddenforge /usr/local/bin/hiddenforge
COPY manifest.json /opt/hiddenforge/manifest.json
COPY tests/test_torrc.py /usr/local/bin/tests/test_torrc.py
# 0755 so the unprivileged tor user can read+execute the healthcheck and CLI (the
# build context files are 0660; COPY preserves that, leaving 'other' unable to
# read). These scripts contain no secrets.
RUN chmod 755 /usr/local/bin/entrypoint.py /usr/local/bin/healthcheck.py \
              /usr/local/bin/vanity.py /usr/local/bin/hiddenforge \
              /usr/local/bin/mkp224o

# Persist hidden service keys across container restarts
VOLUME ["/var/lib/tor/hidden_service/"]

# Health check — Tor must have bootstrapped (100%) AND established a circuit,
# not merely be running. Queried over the control socket as the tor user (the
# socket lives in the 0700 DataDirectory). No pidof fallback: a pidof check
# would report healthy the instant the process exists, masking a Tor that is
# alive but wedged — which is exactly the failure this probe must catch.
# start-period is 120s: circuit-establish + descriptor publish with PoW and 6
# intro points can exceed the previous 90s; failures during it don't count.
HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
    CMD ["su-exec", "tor", "python3", "/usr/local/bin/healthcheck.py"]

# NO `USER` INSTRUCTION, DELIBERATELY. This container MUST start as root: the
# entrypoint chowns the operator's key bind mount to the tor user and then drops
# privileges with su-exec. A non-root USER would make both impossible. Everything
# that faces the network (Tor, Vanguards) runs as `tor`; the entrypoint asserts
# the drop actually happened by reading the child's uid from /proc before it
# trusts the process with the onion key. Scanners flag DS-0002 /
# missing-user-entrypoint here; .trivyignore and the semgrep exclusion carry the
# same reason, and SECURITY.md explains it. The cap set is dropped to ALL then
# re-added minimally in the compose files, and `hiddenforge doctor` verifies it.
# The same reason inline, for scanners run without this repo's ignore files.
# (Trivy reports DS002 against the whole file, with no line an inline comment
# could name; a plain `trivy config .` from the repo root reads .trivyignore.)
# checkov:skip=CKV_DOCKER_3:starts as root to chown the key mount, then su-exec tor
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
ENTRYPOINT ["python3", "/usr/local/bin/entrypoint.py"]
