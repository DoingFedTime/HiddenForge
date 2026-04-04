FROM alpine:3.22@sha256:e0baf8c394150ac5a14925e179100519f5e37c53547f647acbd9f8eb3e5c4528

ENV HOME=/var/lib/tor
ENV PYTHONUNBUFFERED=1

# Install Tor and Python runtime
RUN apk add --no-cache \
    tor \
    python3 \
    py3-pip \
    su-exec

# Install Vanguards guard-protection addon in an isolated venv.
# vanguards 0.3.1 (PyPI) uses the removed SafeConfigParser API from Python
# 3.12 — upstream PR #105 has been unmerged since 2024, so we patch it here.
RUN python3 -m venv /opt/vanguards-venv && \
    /opt/vanguards-venv/bin/pip install --no-cache-dir vanguards && \
    sed -i \
      's/from configparser import SafeConfigParser/from configparser import RawConfigParser as SafeConfigParser/' \
      /opt/vanguards-venv/lib/python3.12/site-packages/vanguards/config.py

# Set up Tor data directory and config directory.
# DataDirectory must be mode 700 — Tor refuses to create a ControlSocket in a
# world-readable directory (it validates this before starting).
RUN mkdir -p ${HOME}/.tor /etc/tor && \
    chown -R tor:tor ${HOME} && \
    chmod 700 ${HOME}

# Copy entrypoint
COPY entrypoint.py /usr/local/bin/entrypoint.py
RUN chmod +x /usr/local/bin/entrypoint.py

# Persist hidden service keys across container restarts
VOLUME ["/var/lib/tor/hidden_service/"]

# Health check — tor process must be alive
# NOTE: start-period increased to 90s to allow Tor to bootstrap and for
# Vanguards to initialise before the first health check fires.
HEALTHCHECK --interval=60s --timeout=10s --start-period=90s --retries=3 \
    CMD pidof tor || exit 1

ENTRYPOINT ["python3", "/usr/local/bin/entrypoint.py"]
CMD ["tor"]
