# Multi-Service Example

HiddenForge can expose multiple independent hidden services from a single container, each with its own `.onion` address.

---

## When to use multiple services

- Separate `.onion` addresses for different purposes (e.g. a public blog and a private admin interface)
- Exposing multiple ports on the same backend (HTTP + a separate API port)
- Running completely different backends under the same Tor instance

---

## Example: blog + tip submission

This example runs two hidden services:
- `blog`: a public-facing site on port 80
- `tips`: a separate tip submission form on a different backend

```yaml
networks:
  tor-internal:
    internal: true
  tor-external:

services:
  tor:
    image: doingfedtime/hiddenforge:latest
    restart: unless-stopped
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - DAC_OVERRIDE
      - FOWNER
      - SETUID
      - SETGID
    security_opt:
      - no-new-privileges:true
      - seccomp=unconfined
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
      - /etc/tor:rw,noexec,nosuid,size=8m
      - /var/lib/tor:rw,noexec,nosuid,size=64m,uid=100,gid=101,mode=0700
    logging:
      driver: none
    environment:
      BLOG_TOR_SERVICE_HOSTS: "80:blog:80"
      TIPS_TOR_SERVICE_HOSTS: "80:tips:8080"
    volumes:
      - ./tor-keys:/var/lib/tor/hidden_service
    networks:
      - tor-internal
      - tor-external
    depends_on:
      - blog
      - tips

  blog:
    image: nginx:alpine
    restart: unless-stopped
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
      - DAC_OVERRIDE
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=32m
      - /var/cache/nginx:rw,noexec,nosuid,size=32m
      - /var/run:rw,noexec,nosuid,size=8m
    networks:
      - tor-internal

  tips:
    image: your-tipsite-image:latest
    restart: unless-stopped
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=32m
    networks:
      - tor-internal
```

Start it:
```bash
mkdir -p ./tor-keys
docker compose up -d
```

Read both `.onion` addresses:
```bash
docker compose exec tor cat /var/lib/tor/hidden_service/blog/hostname
docker compose exec tor cat /var/lib/tor/hidden_service/tips/hostname
```

Each service gets its own address. They're independent — knowing one doesn't reveal the other.

---

## Example: multiple ports on one backend

If you need to expose ports 80 and 8443 on the same backend, use a comma-separated mapping:

```yaml
environment:
  MYAPP_TOR_SERVICE_HOSTS: "80:web:80,8443:web:8443"
```

This creates one hidden service directory (`myapp`) with two `HiddenServicePort` lines in torrc. Both ports share the same `.onion` address.

---

## Env var naming rules

The `NAME` prefix in `NAME_TOR_SERVICE_HOSTS` becomes the hidden service directory name:

- Lowercased: `BLOG` → `blog`
- Underscores converted to hyphens: `MY_BLOG` → `my-blog`
- Must be alphanumeric + hyphens only
- Must start with a letter or digit

Invalid names are skipped with a warning at startup — check logs if a service doesn't appear.

---

## Key storage layout

With multiple services, `./tor-keys` will contain a subdirectory for each:

```
./tor-keys/
├── blog/
│   ├── hostname
│   ├── hs_ed25519_public_key
│   └── hs_ed25519_secret_key
└── tips/
    ├── hostname
    ├── hs_ed25519_public_key
    └── hs_ed25519_secret_key
```

Back up the entire `./tor-keys` directory. Each `hs_ed25519_secret_key` is the permanent identity of its respective service.
