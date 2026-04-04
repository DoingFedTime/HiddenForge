# HiddenForge

[![Docker Hub](https://img.shields.io/docker/pulls/doingfedtime/hiddenforge)](https://hub.docker.com/r/doingfedtime/hiddenforge)
[![GitHub](https://img.shields.io/github/stars/DoingFedTime/HiddenForge)](https://github.com/DoingFedTime/HiddenForge)

**Available on Docker Hub:** https://hub.docker.com/r/doingfedtime/hiddenforge

[![hiddenforge.png](https://i.postimg.cc/fR4BJ54k/hiddenforge.png)](https://postimg.cc/ykPFGm8z)

A hardened Tor hidden service container. Runs Tor 0.4.9.6 with the Vanguards
guard-protection addon on Alpine 3.23 with a minimal, telemetry-free runtime.

## Features

- **Tor 0.4.9.6** from Alpine 3.23 packages (digest-pinned base image)
- **Vanguards addon** — bandguards (bandwidth side-channel detection) and
  rendguard (rendezvous-point overuse detection) run alongside Tor's built-in
  vanguards-lite guard rotation
- **Proof-of-work DoS defense** enabled per service (`HiddenServicePoWDefensesEnabled`)
- **seccomp-bpf sandbox** (`Sandbox 1`) — syscall filtering via Linux seccomp
- **No telemetry surface** — pip, setuptools, urllib3, certifi, and requests
  are stripped from the image; only vanguards, stem, and the standard library
  remain at runtime
- **Input validation** — all `*_TOR_SERVICE_HOSTS` env vars are validated
  before being written to torrc; no shell injection possible
- **ClientOnly** — will never volunteer as a relay or exit node
- **Runs as non-root** — Tor and Vanguards both run as the `tor` user (UID 100)
  via `su-exec`

## Quick Start

```bash
docker pull doingfedtime/hiddenforge
docker run -d \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=unconfined \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v ./tor-data:/var/lib/tor/hidden_service \
  -e SERVICE_TOR_SERVICE_HOSTS="80:nginx:80" \
  doingfedtime/hiddenforge:latest
```

> **`--security-opt seccomp=unconfined` is required** for `Sandbox 1` (Tor's
> seccomp-bpf filter). If your platform cannot pass this flag, set
> `TOR_SANDBOX=0` in the environment to disable Tor's internal sandbox and
> remove `seccomp=unconfined`.

## Environment Variables

- `{NAME}_TOR_SERVICE_HOSTS` — defines hidden service port mappings
  - Format: `"hs_port:backend_host:backend_port"` (comma-separated for multiple ports)
  - Three-part: `"80:nginx:80"` — route onion port 80 to `nginx:80`
  - Two-part: `"80:80"` — route onion port 80 to `127.0.0.1:80`
- `TOR_SANDBOX` — set to `0` to disable `Sandbox 1` (default: `1`)

## Docker Compose — Hardened Example

```yaml
networks:
  # Isolated internal network: Tor reaches the backend, nothing else can.
  tor-internal:
    internal: true   # no outbound internet access from this network
  # Tor needs internet to reach the Tor network.
  tor-external:

services:
  tor:
    image: doingfedtime/hiddenforge:latest
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
      - seccomp=unconfined     # required for Tor Sandbox 1
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
    environment:
      MYAPP_TOR_SERVICE_HOSTS: "80:web:80"
    volumes:
      - ./tor-data:/var/lib/tor/hidden_service
    networks:
      - tor-internal
      - tor-external
    depends_on:
      - web

  web:
    image: nginx:alpine
    # No 'ports:' — the backend is NOT exposed to the internet.
    # Only the tor container on tor-internal can reach it.
    networks:
      - tor-internal
```

> The backend service has **no `ports:` mapping** and is on an `internal`
> network. This means it is unreachable from the internet and unreachable from
> any other Docker network — only the Tor container can talk to it.

## Offline Key Generation (Recommended)

By default the container generates new hidden service keys on first run. For a
state-level adversary threat model, keys should be generated **offline** on an
air-gapped machine and mounted in, so the private key never touches the
production host in plaintext.

**Generate keys offline (using mkp224o or Tor itself):**

```bash
# Option A: use Tor on an air-gapped machine — start it once with the same
# config, let it generate keys, then copy the directory out.

# Option B: use mkp224o to generate a vanity .onion address:
#   https://github.com/cathugger/mkp224o
mkp224o -d ./keys prefix1 prefix2
```

**Mount pre-generated keys:**

```bash
# The service directory must contain:
#   hostname              (the .onion address, text file)
#   hs_ed25519_secret_key (binary, keep this secret)
#   hs_ed25519_public_key (binary)

mkdir -p ./tor-data/myapp
cp /path/to/offline/keys/* ./tor-data/myapp/
chmod 700 ./tor-data/myapp
chmod 600 ./tor-data/myapp/hs_ed25519_secret_key

# The container will use the existing keys instead of generating new ones.
docker run -d \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=unconfined \
  -v ./tor-data:/var/lib/tor/hidden_service \
  -e MYAPP_TOR_SERVICE_HOSTS="80:web:80" \
  doingfedtime/hiddenforge:latest
```

**Back up your keys before the container ever runs in production.** If you lose
`hs_ed25519_secret_key` your .onion address is gone permanently.

## Log Handling

Tor logs to stdout with `SafeLogging 1` (IPs and .onion addresses are scrubbed
from output). The container also sets `AvoidDiskWrites 1` inside Tor to
minimise on-disk forensic footprint.

However, Docker and podman write stdout to a JSON log file on the host by
default, which undermines `AvoidDiskWrites`. For production deployments,
suppress host-side logging or use a non-persistent log driver:

```bash
# Discard all container logs (no log file written to host disk):
docker run --log-driver none ...

# Or use journald (in-memory, controlled retention):
docker run --log-driver journald ...
```

## Time Synchronisation

Tor is sensitive to clock skew. If the host clock is more than ~30 minutes
off, Tor will fail to build circuits. Ensure `ntpd` or `systemd-timesyncd` is
running and synced on the host before starting the container. The container
inherits the host's clock directly.

## Generated Files

The container creates or expects under the mounted volume:

```
{service_name}/
  hostname                 — your .onion address (v3, 56 chars + .onion)
  hs_ed25519_secret_key    — private key (keep offline backups, never share)
  hs_ed25519_public_key    — public key
```

## Security Architecture

| Layer | Mechanism |
|---|---|
| Syscall filtering | `Sandbox 1` (seccomp-bpf) |
| Privilege drop | `su-exec tor` for Tor and Vanguards |
| Debugger blocking | `DisableDebuggerAttachment 1` |
| Disk minimisation | `AvoidDiskWrites 1` |
| Log scrubbing | `SafeLogging 1` |
| DoS defence | `HiddenServicePoWDefensesEnabled 1` per service |
| Circuit overload | `HiddenServiceMaxStreams 100`, `HiddenServiceMaxStreamsCloseCircuit 1` |
| Guard protection | Vanguards addon (bandguards + rendguard) + built-in vanguards-lite |
| No relay/exit | `ClientOnly 1`, `ExitPolicy reject *:*` |
| No telemetry | pip/setuptools/urllib3 stripped from image |
| Input validation | All env vars validated before torrc write |
| Base image | Alpine 3.23.3 digest-pinned |

**Tor version: 0.4.9.6**
