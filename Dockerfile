FROM alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

# SOURCE_DATE_EPOCH: a UNIX timestamp (set by the build to the source commit
# time) used to make the image reproducible. Consumed below to pin the one
# clock-derived field apk writes into /etc/shadow when it creates the tor user.
ARG SOURCE_DATE_EPOCH=0

ENV HOME=/var/lib/tor
ENV PYTHONUNBUFFERED=1
# Suppress .pyc file generation — no bytecode debris on disk
ENV PYTHONDONTWRITEBYTECODE=1
# Silence the pip self-update check at build time
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Install Tor and Python runtime with pinned package versions.
# py3-pip is a build-only dep — added as .build-deps and removed after the
# venv is bootstrapped, leaving no pip/installer tooling in the final image.
# (The Python stdlib still ships urllib/ssl; what we remove are the third-party
# package manager and HTTP clients, not the language's built-in modules.)
# .build-deps is pinned to =0 (not the default auto-version): apk stamps a
# virtual package with the build-time clock (e.g. 20260715.235608), which would
# leak a timestamp into /etc/apk/world and /lib/apk/db/installed and break
# reproducible builds. rm apk.log for the same reason (it records wall-clock op
# times). Together these make this layer byte-identical across rebuilds.
RUN apk add --no-cache \
    tor=0.4.9.11-r0 \
    python3=3.12.13-r0 \
    su-exec=0.3-r0 && \
    apk add --no-cache --virtual .build-deps=0 \
    py3-pip=25.1.1-r1 && \
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
    /opt/vanguards-venv/bin/pip uninstall -y pip setuptools wheel 2>/dev/null || true && \
    find /opt/vanguards-venv -type d -name 'test'  -exec rm -rf {} + 2>/dev/null || true && \
    find /opt/vanguards-venv -type d -name 'tests' -exec rm -rf {} + 2>/dev/null || true && \
    find /opt/vanguards-venv -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true && \
    find /opt/vanguards-venv -name '*.pyc' -delete && \
    find /opt/vanguards-venv -name '*.pyo' -delete && \
    rm /tmp/requirements.txt && \
    apk del .build-deps && \
    rm -f /var/log/apk.log

# Set up Tor data directory and config directory.
# DataDirectory must be mode 700 — Tor refuses to create a ControlSocket in a
# world-readable directory (it validates this before starting).
RUN mkdir -p ${HOME}/.tor /etc/tor && \
    chown -R tor:tor ${HOME} && \
    chmod 700 ${HOME}

# Copy entrypoint, healthcheck, and the in-container smoke test only.
# The host unit suite (test_validators/test_torrc_gen/conftest/golden) runs on
# the build host / in CI — it is deliberately NOT shipped in the image.
COPY entrypoint.py /usr/local/bin/entrypoint.py
COPY healthcheck.py /usr/local/bin/healthcheck.py
COPY tests/test_torrc.py /usr/local/bin/tests/test_torrc.py
# 0755 so the unprivileged tor user can read+execute the healthcheck (the build
# context files are 0660; COPY preserves that, leaving 'other' unable to read).
# These scripts contain no secrets.
RUN chmod 755 /usr/local/bin/entrypoint.py /usr/local/bin/healthcheck.py

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
    CMD su-exec tor python3 /usr/local/bin/healthcheck.py || exit 1

ENTRYPOINT ["python3", "/usr/local/bin/entrypoint.py"]
