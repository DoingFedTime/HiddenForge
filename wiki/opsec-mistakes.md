# Operational Security — Common Mistakes

HiddenForge handles the container hardening. The mistakes that expose operators happen outside the container. These are the ones that have burned people.

---

## Exposing the backend port

The backend service must have no `ports:` entry in the compose file. If you add one for testing and forget to remove it, your service is reachable directly by IP — bypassing Tor entirely.

```yaml
# WRONG — exposes your server IP
web:
  ports:
    - "80:80"

# CORRECT — no ports entry at all
web:
  networks:
    - tor-internal
```

Verify with `docker compose ps` — the web service should list no port mappings.

---

## Generating keys on the production host

By default the container generates hidden service keys on first run. Those keys are created in plaintext on the production machine's disk. Any attacker who can read the host filesystem before the container runs can capture the key material.

Generate keys offline instead:
- Use mkp224o on an air-gapped machine if you want a vanity address
- Or run Tor once on an air-gapped machine, copy the key directory out, wipe the machine
- Mount the pre-generated keys via the `./tor-keys` volume before starting the container

See the [Offline Key Generation](../README.md#offline-key-generation-recommended-for-high-risk-deployments) section in the README.

---

## Not backing up the private key

The `hs_ed25519_secret_key` file is the only thing that ties your service to its `.onion` address. There is no recovery mechanism. If the host fails and you haven't backed it up, the address is gone permanently.

Back up `./tor-keys` before the service goes live, and again after every key rotation. Store the backup offline, encrypted, separate from the production host.

---

## Running on a VPS with a known IP

A VPS has a public IP address on record with the provider. If your threat model includes state-level actors, they can compel the provider to disclose who rents that IP. The Tor hidden service hides the IP from the network, but the provider record still exists.

For high-risk deployments: dedicated hardware, residential or colocation internet with payment methods not tied to your identity, and jurisdictions with stronger data protection laws.

---

## Metadata in your content

Tor hides your IP. It does not hide:

- **File metadata** — documents with embedded author names, GPS coordinates in photos, timestamps that match your timezone
- **Writing style** — stylometric analysis can identify authors across pseudonymous and real-name writing
- **Operational patterns** — publishing at the same hours every day, the same day of the week
- **Referrer links** — linking to resources that log access (your own clearnet site, image hosts, analytics services)
- **Software fingerprints** — default software configurations, error messages with version strings, headers that identify your stack

Strip metadata from all files before publishing. Use tools like `mat2` for documents and images.

---

## Not synchronising the clock

Tor requires the host clock to be within roughly 30 minutes of real time. A misconfigured or drifting clock causes Tor to fail building circuits — and the failure mode isn't always obvious. The container exits cleanly but Tor never bootstraps.

Run `systemd-timesyncd` or NTP on the host. Check with `timedatectl status` before starting the container.

---

## Running as rootful Docker on a shared host

If other users or processes run on the same host with root access, they can access the container's memory and network traffic. Running rootless Podman limits a container escape to your user account. Rootful Docker on a shared host provides much weaker isolation.

For a state-level adversary threat model: dedicated host, rootless Podman, no other services.

---

## Leaving debug logging enabled in production

The compose file ships with `logging: driver: none` for a reason. Docker's default JSON log driver writes everything to disk on the host — including Tor's output. Even with `SafeLogging 1` inside Tor (which scrubs IPs from log messages), circuit timing information and connection counts in the log are still metadata.

Remove the `logging: driver: none` block only when actively debugging. Put it back before the service goes live.

---

## Reusing a `.onion` address across different contexts

If you run the same `.onion` address for a long time and then change what you publish there, an adversary who monitored the address during the original use period still has that association. Operational compartmentalisation means different activities use different identities — different key pairs, different `.onion` addresses.

Don't reuse a `.onion` address that was ever associated with your real identity for a pseudonymous operation, and vice versa.
