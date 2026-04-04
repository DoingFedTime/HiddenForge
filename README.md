# HiddenForge

[![Docker Hub](https://img.shields.io/docker/pulls/doingfedtime/hiddenforge)](https://hub.docker.com/r/doingfedtime/hiddenforge)
[![GitHub](https://img.shields.io/github/stars/DoingFedTime/HiddenForge)](https://github.com/DoingFedTime/HiddenForge)

**Available on Docker Hub:** https://hub.docker.com/r/doingfedtime/hiddenforge

[![hiddenforge.png](https://i.postimg.cc/fR4BJ54k/hiddenforge.png)](https://postimg.cc/ykPFGm8z)

A hardened Tor hidden service container. Runs Tor 0.4.9.6 with the Vanguards
guard-protection addon on Alpine 3.23. Every dependency is pinned and
hash-verified at build time. Designed for a state-level adversary threat model.

---

## Quick Start (3 steps)

```bash
# 1. Download the compose file
curl -O https://raw.githubusercontent.com/DoingFedTime/HiddenForge/main/docker-compose.yml

# 2. Edit the two lines marked <-- EDIT in docker-compose.yml
#    (your service name and backend image)

# 3. Start it
mkdir -p ./tor-keys
docker compose up -d

# Your .onion address appears here once Tor bootstraps (~60s):
docker compose exec tor cat /var/lib/tor/hidden_service/myapp/hostname
```

All security flags are pre-configured in the compose file. The backend service
is network-isolated and never exposed to the internet.

---

## What the Compose File Does

The included `docker-compose.yml` is ready to use as-is. It handles everything:

| What | How |
|---|---|
| Drops all Linux capabilities | `cap_drop: ALL` |
| Prevents privilege escalation | `security_opt: no-new-privileges:true` |
| Enables Tor's seccomp sandbox | `security_opt: seccomp=unconfined` |
| Read-only container filesystem | `read_only: true` |
| No host-side log file | `logging: driver: none` |
| Network-isolated backend | `internal: true` network, no `ports:` on backend |
| Key persistence | `./tor-keys` volume mount |

The only two lines you need to edit are flagged with `<-- EDIT`.

---

## Environment Variables

- `{NAME}_TOR_SERVICE_HOSTS` — hidden service port mappings

  > **Important:** Tor requires IP addresses in port mappings — Docker service
  > names (e.g. `web`) are not resolved. Use a static IP assigned in the
  > compose `networks` section (see the included `docker-compose.yml`).

  - Three-part: `"80:172.20.0.2:80"` — route onion port 80 to backend at `172.20.0.2:80`
  - Two-part: `"80:8080"` — route onion port 80 to `127.0.0.1:8080` (same container only)
  - Multiple ports: `"80:172.20.0.2:80,443:172.20.0.2:443"`
  - `NAME` is lowercased and used as the service directory name (`hyphens ok, underscores converted`)

- `TOR_SANDBOX` — set to `0` to disable `Sandbox 1` (default: `1`)

---

## Supply Chain Security

Recent supply chain attacks (xz-utils, PyPI package hijacks, compromised npm
packages) have made dependency pinning essential for any security-sensitive
software. HiddenForge pins every dependency at every layer.

**What is pinned and why:**

| Dependency | Pinned to | Why it matters |
|---|---|---|
| Alpine base image | `alpine:3.23.3@sha256:...` | Digest pinning means the exact OS bytes are locked — a tag like `latest` or even `3.23.3` can be silently updated on the registry |
| `tor` apk | `0.4.9.6-r0` | A tampered Tor binary could de-anonymise every circuit |
| `python3` apk | `3.12.12-r0` | The Python runtime executes the entrypoint and Vanguards |
| `su-exec` apk | `0.3-r0` | This binary performs the privilege drop to the `tor` user |
| `py3-pip` apk | `25.1.1-r1` | Build-only; pinned so it can't be updated to a version that silently ignores `--require-hashes` |
| `vanguards` pip | `0.3.1` + SHA256 | Guard protection addon; a compromised version could leak circuit topology |
| `stem` pip | `1.8.2` + SHA256 | Tor controller library; underpins all Vanguards communication |
| `ipaddress` pip | `1.0.23` + SHA256 | Transitive dep of vanguards |
| `setuptools` pip | `82.0.1` + SHA256 | Build dep for stem; uninstalled post-build but listed for hash verification completeness |

**How hash verification works:**

pip's `--require-hashes` flag makes the build abort with a clear error if any
downloaded file's SHA256 does not match what is recorded in `requirements.txt`.
This means a compromised PyPI package — even one with the correct version number
— cannot enter the image silently. The build simply fails.

**What is NOT protected:**

apk packages are version-pinned but not hash-verified — Alpine does not expose
per-package SHA256 hashes in a format easily consumable at build time. The
digest-pinned base image mitigates this partially: the Alpine package index
inside that specific image layer is fixed, so `apk add tor=0.4.9.6-r0` will
always pull from that locked index.

**Updating pinned versions:**

When you want to upgrade, do not just change version numbers — verify the new
hashes first:

```bash
# Get the new SHA256 for a pip package:
pip download vanguards==0.3.2 -d /tmp/dl --no-deps
sha256sum /tmp/dl/vanguards-0.3.2*.whl

# Then update requirements.txt with the new version and hash,
# rebuild, and verify the build passes before deploying.
```

---

## Offline Key Generation (Recommended for High-Risk Deployments)

By default the container generates hidden service keys on first run on the
production host. For a state-level adversary threat model, generate keys
**offline** on an air-gapped machine so the private key never touches the
production host in plaintext.

```bash
# Option A: mkp224o (generates vanity .onion addresses)
#   https://github.com/cathugger/mkp224o
mkp224o -d ./keys myprefix

# Option B: run Tor once on an air-gapped machine, let it generate
# keys, copy the service directory out, then wipe the machine.
```

**Mount pre-generated keys:**

```bash
# Service directory must contain:
#   hostname                (your .onion address, plaintext)
#   hs_ed25519_secret_key   (binary — keep offline backups, never share)
#   hs_ed25519_public_key   (binary)

mkdir -p ./tor-keys/myapp
cp /path/to/offline/keys/* ./tor-keys/myapp/
chmod 700 ./tor-keys/myapp
chmod 600 ./tor-keys/myapp/hs_ed25519_secret_key

docker compose up -d
```

**Back up `hs_ed25519_secret_key` before the container runs.** Losing it means
losing your .onion address permanently — there is no recovery.

---

## Log Handling

Inside the container, Tor runs with `SafeLogging 1` (IPs and .onion addresses
scrubbed from output) and `AvoidDiskWrites 1` (no log files written to disk).

The compose file sets `logging: driver: none` so Docker does not write a JSON
log file on the host either. Remove that block if you need logs for debugging:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "1"
```

---

## Time Synchronisation

Tor is sensitive to clock skew. If the host clock is more than ~30 minutes
off, Tor will fail to build circuits. Ensure `ntpd` or `systemd-timesyncd` is
running and synced on the host before starting the container.

```bash
timedatectl status   # check sync status on systemd hosts
```

---

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
| No telemetry | pip/setuptools/urllib3 stripped from final image |
| Input validation | All env vars validated before torrc write |
| Supply chain | Every dep pinned by version + SHA256 hash |
| Base image | Alpine 3.23.3 digest-pinned |

**Tor version: 0.4.9.6**
