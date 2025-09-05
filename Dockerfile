FROM alpine:3.22

ENV HOME /var/lib/tor

# Install latest Tor from Alpine packages (automatically gets the latest stable version)
RUN apk add --no-cache \
    tor \
    python3 \
    su-exec

# Set up directories and permissions for existing tor user
RUN mkdir -p ${HOME}/.tor /etc/tor && \
    chown -R tor:tor ${HOME}

# Copy custom entrypoint
COPY entrypoint.py /usr/local/bin/entrypoint.py
RUN chmod +x /usr/local/bin/entrypoint.py

# Volume for hidden services
VOLUME ["/var/lib/tor/hidden_service/"]

# Health check to ensure Tor is running
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD pidof tor || exit 1

# Entry point and command
ENTRYPOINT ["python3", "/usr/local/bin/entrypoint.py"]
CMD ["tor"]