FROM alpine:3.23.3@sha256:59855d3dceb3ae53991193bd03301e082b2a7faa56a514b03527ae0ec2ce3a95

ENV HOME=/var/lib/tor
ENV PYTHONUNBUFFERED=1
# Suppress .pyc file generation — no bytecode debris on disk
ENV PYTHONDONTWRITEBYTECODE=1
# Silence the pip self-update check at build time
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Install Tor and Python runtime with pinned package versions.
# py3-pip is a build-only dep — added as .build-deps and removed after the
# venv is bootstrapped, leaving no HTTP-capable code in the final image.
RUN apk add --no-cache \
    tor=0.4.9.6-r0 \
    python3=3.12.12-r0 \
    su-exec=0.3-r0 && \
    apk add --no-cache --virtual .build-deps \
    py3-pip=25.1.1-r1

# Install Vanguards guard-protection addon in an isolated venv.
# vanguards 0.3.1 (PyPI) uses the removed SafeConfigParser API from Python
# 3.12 — upstream PR #105 has been unmerged since 2024, so we patch it here.
#
# All packages are installed with --require-hashes so pip will abort if any
# downloaded file does not match the SHA256 recorded in requirements.txt.
#
# After install we strip pip, setuptools, and any test / cache artefacts from
# the venv so no network-capable Python code remains in the final image.
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
    /opt/vanguards-venv/bin/pip uninstall -y pip setuptools wheel 2>/dev/null || true && \
    find /opt/vanguards-venv -type d -name 'test'  -exec rm -rf {} + 2>/dev/null || true && \
    find /opt/vanguards-venv -type d -name 'tests' -exec rm -rf {} + 2>/dev/null || true && \
    find /opt/vanguards-venv -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true && \
    find /opt/vanguards-venv -name '*.pyc' -delete && \
    find /opt/vanguards-venv -name '*.pyo' -delete && \
    rm /tmp/requirements.txt && \
    apk del .build-deps

# Set up Tor data directory and config directory.
# DataDirectory must be mode 700 — Tor refuses to create a ControlSocket in a
# world-readable directory (it validates this before starting).
RUN mkdir -p ${HOME}/.tor /etc/tor && \
    chown -R tor:tor ${HOME} && \
    chmod 700 ${HOME}

# Copy entrypoint and tests
COPY entrypoint.py /usr/local/bin/entrypoint.py
COPY tests/ /usr/local/bin/tests/
RUN chmod +x /usr/local/bin/entrypoint.py

# Persist hidden service keys across container restarts
VOLUME ["/var/lib/tor/hidden_service/"]

# Health check — tor process must be alive
# NOTE: start-period increased to 90s to allow Tor to bootstrap and for
# Vanguards to initialise before the first health check fires.
HEALTHCHECK --interval=60s --timeout=10s --start-period=90s --retries=3 \
    CMD pidof tor || exit 1

ENTRYPOINT ["python3", "/usr/local/bin/entrypoint.py"]
