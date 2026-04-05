# Troubleshooting

## Tor won't bootstrap

**Symptom:** The container starts but you never see a `.onion` address, or logs show `Bootstrapped 0%` stuck for more than 5 minutes.

Check logs (if you haven't disabled them):
```bash
docker compose logs tor
```

If you set `logging: driver: none`, attach directly:
```bash
docker compose exec tor cat /etc/tor/torrc   # verify the torrc generated correctly
```

Common causes:

**Clock skew** — Tor requires the host clock to be within ~30 minutes of real time. If it's off, Tor will fail to build circuits silently.
```bash
timedatectl status
# Look for: "System clock synchronized: yes"
# If no: systemctl start systemd-timesyncd
```

**Firewall blocking outbound 9001/9030** — Tor needs outbound TCP on ports 9001 and 9030 to reach the directory authorities and guard relays. If you're behind a restrictive firewall:
```bash
# Test from the host
curl -s https://check.torproject.org/api/ip
# Or test outbound connectivity to a known relay
```

**No internet on the tor container** — The tor container must be on `tor-external` (the default bridge network). If you misconfigured networking and only have `tor-internal`, Tor has no outbound path.

**`seccomp=unconfined` missing** — Some managed container platforms strip this security option. Without it, Tor's `Sandbox 1` will crash immediately. Set `TOR_SANDBOX=0` as a workaround, or confirm the host supports the flag:
```bash
docker info | grep -i seccomp
```

---

## Vanguards didn't start

**Symptom:** Logs show `Warning: Tor control socket not found after 120s. Continuing without Vanguards.`

This means Tor started but never created its control socket, usually because:

- Tor crashed before finishing bootstrap (check for `[err]` lines in output)
- The `/var/lib/tor` tmpfs wasn't writable (permissions issue on startup)

You still have Tor's built-in vanguards-lite running. The full Vanguards addon (bandguards + rendguard) adds additional protection but the service is still functional without it.

To confirm whether Vanguards is running:
```bash
docker compose exec tor ps aux
# Look for a vanguards process owned by the tor user
```

If Vanguards crashed more than 5 times in quick succession, the entrypoint disables it automatically. Restart the container to reset the counter:
```bash
docker compose restart tor
```

---

## .onion address not found

**Symptom:** `docker compose exec tor cat /var/lib/tor/hidden_service/myapp/hostname` returns "No such file or directory".

The service name in the command must match the `NAME` part of your `NAME_TOR_SERVICE_HOSTS` env var, lowercased with underscores converted to hyphens.

Examples:
| Env var | Directory name | Command |
|---|---|---|
| `MYAPP_TOR_SERVICE_HOSTS` | `myapp` | `...hidden_service/myapp/hostname` |
| `MY_BLOG_TOR_SERVICE_HOSTS` | `my-blog` | `...hidden_service/my-blog/hostname` |
| `TIPSITE_TOR_SERVICE_HOSTS` | `tipsite` | `...hidden_service/tipsite/hostname` |

Also confirm the `./tor-keys` volume mounted correctly:
```bash
ls -la ./tor-keys/
# Should show a subdirectory named after your service
```

---

## Backend service not reachable through Tor

**Symptom:** The `.onion` address exists and Tor bootstrapped, but the site times out in Tor Browser.

Check that the backend resolved correctly at startup:
```bash
docker compose logs tor | grep "Resolved"
# Should show: Resolved 'web' → 172.x.x.x
```

If the backend wasn't running when `tor` started, the DNS resolution fails and no `HiddenServicePort` line gets written to torrc. Fix: ensure `depends_on` is set and restart:
```bash
docker compose up -d
```

Verify the generated torrc has the correct IP:
```bash
docker compose exec tor cat /etc/tor/torrc | grep HiddenServicePort
# Should show an IP, not a hostname
```

---

## Permission errors on startup (Podman)

**Symptom:** Container exits immediately with permission denied errors touching `/var/lib/tor`.

Rootless Podman doesn't support the `uid=/gid=/mode=` tmpfs mount options that Docker uses. The entrypoint handles this by chowning `/var/lib/tor` at startup. If you're seeing permission errors it usually means the `CHOWN` capability was dropped.

Check your `cap_add` list — the Podman compose file requires `CHOWN`, `SETUID`, and `SETGID`. Unlike the Docker version, it does NOT need `DAC_OVERRIDE` or `FOWNER`.

Also confirm you're actually running rootless:
```bash
podman info --format '{{.Host.Security.Rootless}}'
# Expected: true
```

---

## Container exits immediately with exit code 1

The entrypoint exits with code 1 if:
- The `NAME_TOR_SERVICE_HOSTS` env var contains an invalid service name (non-alphanumeric characters other than hyphens)
- A port mapping has an out-of-range port number
- Torrc generation fails for any other reason

Run without `-d` to see the error:
```bash
docker compose up
```

Look for lines starting with `Error generating configuration:` or `Skipping invalid`.
