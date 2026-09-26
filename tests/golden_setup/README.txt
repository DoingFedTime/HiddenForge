hiddenforge, your setup
=========================

Services:
  blog: BLOG_TOR_SERVICE_HOSTS="80:web:80"
Image:     sambent.dev/sam/hiddenforge:latest
Keys:      ./tor-keys

How to bring it up
------------------
1. Make sure every backend service joins the `tor-internal` network and has no
   published ports.
2. ./deploy.sh   (or: docker compose -f compose.yml -f compose.service.yml up -d)

Where the addresses live
------------------------
  ./tor-keys/<service>/hostname   <- Tor's own hostname file
  ./tor-keys/<service>.onion      <- world-readable copy written at startup

Read one any time:
  hiddenforge show --keys ./tor-keys --name <service> --json

Services: blog

BACK UP THE ENTIRE ./tor-keys DIRECTORY. A key IS a .onion address.
Losing it loses that address permanently.

If a backend is recreated on a different IP, hiddenforge notices and restarts
itself to follow it (this needs the restart policy the fragment sets).
