# Verifying Your Setup

After starting HiddenForge, run through these checks before considering the service live.

---

## 1. Confirm Tor bootstrapped

```bash
docker compose logs tor 2>&1 | grep -i "bootstrapped 100"
# Expected: [notice] Bootstrapped 100% (done): Done
```

If you have logging disabled (`driver: none`), temporarily re-enable it for initial setup, then disable again for production.

Bootstrap takes 60-90 seconds on a normal connection. If it hasn't completed after 3 minutes, see [Troubleshooting](troubleshooting.md).

---

## 2. Confirm your .onion address exists

```bash
# Replace "myapp" with your service name
docker compose exec tor cat /var/lib/tor/hidden_service/myapp/hostname
# Expected: something like abc123...xyz.onion
```

The address file is created when Tor first generates keys. If the file doesn't exist yet, Tor hasn't finished bootstrapping or the service name doesn't match.

---

## 3. Confirm Vanguards is running

```bash
docker compose exec tor ps aux
# Look for a line containing "vanguards" owned by user "tor"
```

If Vanguards is not running, the service still works. Tor's built-in vanguards-lite provides basic guard protection. The full Vanguards addon adds bandguards (bandwidth side-channel detection) and rendguard (rendezvous-point monitoring). See [What Is Vanguards](what-is-vanguards.md) for details.

---

## 4. Confirm the backend has no internet exposure

This is the most important security check. Your backend container must not be reachable from the internet — only from Tor inside the isolated network.

```bash
# Confirm the backend has no port mappings on the host
docker compose ps
# The "web" service should show no ports listed (no "0.0.0.0:80->80/tcp")
# The "tor" service should also show no ports listed
```

```bash
# Confirm the backend is not on tor-external
# The network name is prefixed with your compose project name (default: directory name)
docker network ls | grep tor-external
# Then inspect the result — e.g. if your project is "hiddenforge":
docker network inspect hiddenforge_tor-external
# The "web" container should NOT appear in the Containers section
# Only "tor" should be on this network
```

---

## 5. Reach your .onion address

Open Tor Browser and navigate to your `.onion` address. First connection can take 30-60 seconds while Tor builds the rendezvous circuit.

If you're testing from the same machine running the container, you need a separate Tor Browser instance — not `curl` on the host, which doesn't route through Tor.

For automated testing from a machine that has `torsocks` installed:
```bash
torsocks curl http://youronionaddress.onion
```

---

## 6. Confirm no traffic is leaking from the backend

The backend must only be reachable via Tor. Verify:

```bash
# From outside the Docker network, the backend port should be unreachable
# (assuming your backend listens on port 80)
curl -m 3 http://localhost:80
# Expected: connection refused or timeout — NOT your site content
```

If you can reach your backend directly from the host, you have a `ports:` mapping that needs to be removed from the compose file.

---

## 7. Verify key persistence across restarts

```bash
# Note your .onion address
docker compose exec tor cat /var/lib/tor/hidden_service/myapp/hostname

# Restart the container
docker compose restart tor

# Wait for bootstrap (~90s), then check the address again
docker compose exec tor cat /var/lib/tor/hidden_service/myapp/hostname
# Must be the same address — if it changed, the ./tor-keys volume isn't persisting
```

If the address changed after restart, the volume mount isn't working. Check that `./tor-keys` exists on the host and that the path in the compose file matches.

---

## 8. Back up your keys

Once you've confirmed everything works, back up the key directory immediately:

```bash
cp -r ./tor-keys /path/to/secure/offline/backup
```

The `hs_ed25519_secret_key` file inside is the only thing that ties your service to its `.onion` address. It cannot be recovered if lost.
