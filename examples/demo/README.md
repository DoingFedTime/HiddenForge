# hiddenforge demo: publish a throwaway app as a .onion

This is the smallest possible consumer. The app (`web`, an nginx serving
`./site`) publishes **nothing** to the host and has **no** internet access. It
is reachable only through hiddenforge's Tor sidecar.

`app.yml` is an illustration of the smallest consumer, not a hardened production
file. For a production starting point use [`docker-compose.yml`](../../docker-compose.yml)
or [`podman-compose.yml`](../../podman-compose.yml).

Three commands, no file editing in the hiddenforge repo:

```bash
# 1. Emit the merge fragment (writes compose.service.yml, deploy.sh, README.txt,
#    hiddenforge.json)
../../scripts/hiddenforge setup --backend web:80 --name demo --out .

# 2. Bring the merged stack up
docker compose -f app.yml -f compose.service.yml up -d

# 3. Read the address (retry until `ready` is true; first boot takes a few minutes, up to about 6)
../../scripts/hiddenforge status --keys ./tor-keys --container tor --json
../../scripts/hiddenforge show   --keys ./tor-keys --name demo --json
```

`show --json` prints:

```json
{"name":"demo","onion":"<56 chars>.onion","key_path":"./tor-keys/demo/hs_ed25519_secret_key", ...}
```

Once the service is reachable, the address is also written to
`./tor-keys/demo.onion`, so a consumer with no hiddenforge installed can just
read that file from the mount.

Tear down:

```bash
docker compose -f app.yml -f compose.service.yml down
```

The `./tor-keys` directory is the identity. Back it up; losing it loses the
address permanently.
