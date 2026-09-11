# Publish any app as a `.onion`

hiddenforge is a sidecar. You keep your application exactly as it is, attach it to
one network, and hiddenforge gives it a Tor v3 address. There is no wizard and no
`.onion` toolchain to install: the address generator ships in the image.

This document is the integration contract. Every command here is tested
(`tests/test_cli.py`, `tests/test_e2e_live.py`, `examples/demo`).

---

## 1. The minimal merge (3 commands)

```bash
# 1. Emit a compose fragment next to your compose file.
hiddenforge setup --backend web:80 --name myapp --out ./deploy
#    (--backend is YOUR service name and port; --name is the service/dir name)

# 2. Merge it and start. Do not edit the fragment.
docker compose -f compose.yml -f ./deploy/compose.service.yml up -d

# 3. Read the address once it is ready.
hiddenforge show --keys ./tor-keys --name myapp --json
```

`setup` writes four files and edits none of yours:

| File | What it is |
|---|---|
| `compose.service.yml` | the merge fragment: `tor` service, both networks, key volume, caps, hardening, env, healthcheck |
| `deploy.sh` | the same three steps as a script |
| `README.txt` | human summary of what was generated |
| `hiddenforge.json` | machine descriptor (name, env var, merge command, address command) |

Your app **must**:
- join the `tor-internal` network (`networks: [tor-internal]`),
- publish **no** ports (`ports:` must be absent),
- be reachable from the `tor` container by the service name you passed to
  `--backend`.

That is the entire contract. The shipped `examples/demo` is a working consumer.

### What `--backend` produces

`--backend web:80 --name myapp` emits:

```yaml
environment:
  MYAPP_TOR_SERVICE_HOSTS: "80:web:80"
```

The native form is `{NAME}_TOR_SERVICE_HOSTS=onion_port:backend_host:backend_port[,...]`.
You can set it by hand instead of using `setup`; that is the same contract the
existing `docker-compose.yml` uses.

> **Backend hostnames are resolved once, at container start**, and the IP is
> written into the torrc. If you recreate your backend container it may come back
> on a different IP and the onion will silently blackhole. After recreating a
> backend, run `docker compose restart tor`.

---

## 2. Reading the address from a program

Two ways, both stable:

**A. The mounted file (no hiddenforge installed):**

```
<keys>/<name>.onion          # e.g. ./tor-keys/myapp.onion, one line, mode 0644
```

hiddenforge publishes this as soon as Tor writes the key, so any process that can
read the mount can read the address. (The service directory itself is `0700`
owned by the container's `tor` user, so other files inside it are not readable by
your host user — `<name>.onion` is the readable copy.)

**B. `show --json`:**

```bash
hiddenforge show --keys ./tor-keys --name myapp --json
```
```json
{"address_path":"./tor-keys/myapp.onion",
 "key_path":"./tor-keys/myapp/hs_ed25519_secret_key",
 "name":"myapp",
 "onion":"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion",
 "public_key_path":"./tor-keys/myapp/hs_ed25519_public_key",
 "source":"published",
 "ok":true,"exit_code":0}
```

- `--name` → a single object with `onion`, `key_path`, `name` (plus extras).
- no `--name` → `{"addresses":[...],"address":"<first or null>"}`.
- exit code `4` means the address is not published yet; `onion` is `null`.
- `source` is `hostname` | `published` | `derived` — how the address was obtained.

The `key_path` is the **secret** key path; `show` never reads its contents.

---

## 3. Readiness: poll `ready`

```bash
hiddenforge status --container tor --keys ./tor-keys --json
```
```json
{"container":"tor","running":true,"healthy":true,"health_status":"healthy",
 "tor_bootstrapped":true,"vanguards":true,"hidden_service_published":true,
 "addresses":[{"name":"myapp","onion":"....onion"}],
 "address":"....onion","ready":true,"restarts":0,"exit_code":0}
```

Publish nothing until **`ready` is true**. It is the AND of:

| field | meaning |
|---|---|
| `running` | the container is up |
| `healthy` | Docker healthcheck passes (control socket reachable) |
| `tor_bootstrapped` | Tor reports `PROGRESS=100` |
| `hidden_service_published` | the address file exists |
| `vanguards` | the guard-protection addon is alive |

`status --json` exits `0` when ready, `4` when not. Inside the container the same
state is available granularly:

```bash
docker exec <container> su-exec tor python3 /usr/local/bin/healthcheck.py --json
```

---

## 4. Vanity addresses

```bash
# In the image, headless, writes ./tor-keys/<name>/{hostname,hs_ed25519_*}
hiddenforge vanity --prefix myapp --name myapp --keys ./tor-keys --threads 8 --json
```
```json
{"name":"myapp","onion":"myapp....onion","address_matches_prefix":true,
 "key_path":"./tor-keys/myapp/hs_ed25519_secret_key","key_dir":"./tor-keys/myapp",
 "threads":8,"ok":true,"exit_code":0}
```

- Prefix characters are base32: `a-z` and `2-7` (no `0`, `1`, `8`, `9`).
- Refuses to overwrite an existing identity without `--force`; with `--force` the
  old key directory is **archived** (`.replaced-<epoch>`), never deleted.
- Never prints or copies the secret key bytes.

**Estimate the cost first:**

```bash
hiddenforge vanity --prefix myapp --bench --seconds 5 --json
```
```json
{"keys_per_sec": 6200000.0, "threads": 8,
 "difficulty":[{"prefix_len":1,"average_attempts":32,"estimated_seconds":5.2e-06,"estimated_human":"<1s"},
               {"prefix_len":2,"average_attempts":1024,...}, ...]}
```

Expected attempts is exactly `32^length`; the time is that divided by the
measured throughput of *this machine*. Roughly: 4 chars is seconds, 5 is a
minute, 6 is ~40 minutes, 7 is ~20 hours, 8 is weeks.

**Long prefixes on a faster machine.** The generator is stateless: run the same
image on the fast box, then copy the key directory back.

```bash
# on the fast machine
docker run --rm -v "$PWD/keys:/keys" <image> vanity \
  --prefix myapp --name myapp --out /keys --threads 32 --uid "$(id -u)" --gid "$(id -g)"
# then, on the production host
rsync -a fastbox:keys/myapp ./tor-keys/myapp
chmod 700 ./tor-keys/myapp; chmod 600 ./tor-keys/myapp/hs_ed25519_secret_key
```

---

## 5. Key lifecycle

> The key **is** the address. Losing it loses the address permanently. There is no
> recovery and no reset. Encrypt your backups.

```bash
hiddenforge backup  --keys ./tor-keys --out ./keys.tar.gpg --tool gpg --passphrase-file ./pp --json
hiddenforge restore --keys ./tor-keys --input ./keys.tar.gpg --tool gpg --passphrase-file ./pp --json
hiddenforge rotate  --keys ./tor-keys --confirm ROTATE --json     # DESTRUCTIVE
```

- `backup` prefers `age`, then `gpg`; both are authenticated. **`openssl` is
  refused** for creation (it has no authentication). gpg uses AEAD (OCB) when the
  local gpg supports it.
- `restore` refuses to overwrite existing files unless `--force`; with `--force`
  the replaced files are archived, not deleted.
- `rotate` refuses without the literal `--confirm ROTATE` and archives the old
  identity to `tor-keys.rotated-<epoch>`.
- `encrypt-key` / `decrypt-key` wrap a single service key directory using the
  same tools. hiddenforge does **not** decrypt at boot: Tor needs the plaintext
  secret key in `HiddenServiceDir`, which is the mount, so at-rest encryption is
  an offline/manual step, not runtime.

All five accept `--json` and never prompt when stdin is not a TTY.

---

## 6. Verify the hardening of a running deployment

```bash
hiddenforge doctor --container tor --keys ./tor-keys --json
```
```json
{"ok":true,"failures":[],"warnings":[],
 "checks":[{"check":"cap_drop includes ALL","ok":true,"detail":"CapDrop=['ALL']","severity":"fail"}, ...]}
```

FAIL-level checks: `cap_drop` includes `ALL`, `cap_add` stays within
`{CHOWN,DAC_OVERRIDE,FOWNER,SETUID,SETGID}`, `no-new-privileges`, read-only
rootfs, `seccomp=unconfined`, AppArmor applied, `pids_limit ≤ 512`, swap disabled
(`MemorySwap == Memory`), no published ports, key dir `0700`, secret key `0600`.
`logging: none` is a warning (you may have disabled it deliberately). Exit `1` on
any failure, `0` otherwise, `2` if the container cannot be inspected.

Inside the container (no docker socket):

```bash
docker exec <container> su-exec tor hiddenforge doctor --keys-only --json
```

---

## 7. Machine contract

```bash
hiddenforge info --json        # the full contract (same bytes as manifest.json)
hiddenforge version --json     # {"name","version","contract_version","ok","exit_code"}
```

`manifest.json` describes the image: env vars, ports (`[]`), volumes (with
`contains: ["keys","address"]`), tmpfs, health command + `ready_field`, the
address command and file paths, the key file formats/modes, and the exit codes.
Pin `contract_version`; it only changes if a field is removed or changes meaning.

### Exit codes

| code | meaning |
|---|---|
| 0 | success |
| 1 | refused or failed (see stderr / the `error` field) |
| 2 | usage, validation, or environment error |
| 3 | a key appeared at the output path while a search was running |
| 4 | not ready yet (`status`/`show` before the address exists) |
| 130 | aborted at a prompt (no TTY) |

### Using the image directly (no host CLI)

Every key command is also a subcommand of the image, so `docker pull` is enough:

```bash
docker run --rm <image> version --json
docker run --rm <image> info --json
docker run --rm -v "$PWD/tor-keys:/keys" <image> vanity --prefix hi --name myapp --out /keys
docker run --rm <image> setup --backend web:80 --name myapp -o /out -v "$PWD/out:/out"
```

---

## 8. Consumer examples

**Shell**

```bash
#!/usr/bin/env bash
set -euo pipefail
mkdir -p ./tor-keys
docker compose -f compose.yml -f ./deploy/compose.service.yml up -d
until [ "$(hiddenforge status --container tor --keys ./tor-keys --json \
          | python3 -c 'import json,sys;print(json.load(sys.stdin)["ready"])')" = "True" ]; do
  sleep 5
done
onion=$(hiddenforge show --keys ./tor-keys --name myapp --json \
        | python3 -c 'import json,sys;print(json.load(sys.stdin)["onion"])')
echo "published at http://$onion"
```

**Python (stdlib only)**

```python
import json, subprocess, time

def ready(container="tor", keys="./tor-keys"):
    out = subprocess.check_output(
        ["hiddenforge", "status", "--container", container, "--keys", keys, "--json"])
    return json.loads(out)["ready"]

while not ready():
    time.sleep(5)

addr = json.loads(subprocess.check_output(
    ["hiddenforge", "show", "--keys", "./tor-keys", "--name", "myapp", "--json"]))
print(addr["onion"], addr["key_path"])
```

---

## 9. Troubleshooting

- **`show --json` exits 4 / `onion: null`** — the key is not generated yet. Poll
  `status --json` until `ready`. First boot can take 60–120 s.
- **`status` says `container not found`** — pass `--container <your-compose-service>`;
  hiddenforge resolves Compose service labels automatically.
- **The onion was reachable, then stopped after a redeploy** — your backend was
  recreated and got a new IP. `docker compose restart tor`.
- **`show` says the key volume cannot be enumerated** — that is intentional: the
  volume is `0751` (traverse, not list). Pass `--name <service>`.
- **rootless Podman** — use `podman-compose.yml`, and read the `.onion` with
  `podman-compose exec tor su-exec tor cat /var/lib/tor/hidden_service/<name>/hostname`
  (the `su-exec tor` is required; see the rootless notes in the README).
