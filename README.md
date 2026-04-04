# HiddenForge

[![Docker Hub](https://img.shields.io/docker/pulls/doingfedtime/hiddenforge)](https://hub.docker.com/r/doingfedtime/hiddenforge)
[![GitHub](https://img.shields.io/github/stars/DoingFedTime/HiddenForge)](https://github.com/DoingFedTime/HiddenForge)

**Available on Docker Hub:** https://hub.docker.com/r/doingfedtime/hiddenforge

![HiddenForge Logo](https://i.ibb.co/7bSchz5/hiddenforge.png)

A modern, lightweight Tor hidden service Docker image. Forge .onion services with the latest Tor (0.4.8.17) and minimal dependencies.

## Quick Start

```bash
docker pull doingfedtime/hiddenforge
docker run -d \
  -v ./tor-data:/var/lib/tor/hidden_service \
  -e SERVICE_TOR_SERVICE_HOSTS="80:nginx:80" \
  doingfedtime/hiddenforge:latest
```

## Features

- **Latest Tor Version**: Uses Tor 0.4.8.17 from Alpine packages
- **Minimal Size**: Pure Alpine base with only essential components  
- **Simple & Fast**: No compilation, builds in seconds
- **Easy Configuration**: Environment variable-based hidden service setup
- **Secure**: Runs as non-root tor user with proper permissions

## How It Works

The `entrypoint.py` script automatically:
1. Reads your environment variables (like `SERVICE_TOR_SERVICE_HOSTS`)
2. Generates the proper torrc configuration
3. Creates hidden service directories with correct permissions
4. Starts Tor securely as the tor user

## Environment Variables

The image uses the same environment variable format as goldy/tor-hidden-service:

- `{NAME}_TOR_SERVICE_HOSTS`: Defines hidden service mappings
  - Format: `"port:host:port,port2:host2:port2"`
  - Example: `"80:nginx:80,443:nginx:443"`

## Docker Compose Example

```yaml
version: '3.8'
services:
  tor:
    image: doingfedtime/hiddenforge:latest
    environment:
      MYAPP_TOR_SERVICE_HOSTS: "80:web:80"
    volumes:
      - ./tor-data:/var/lib/tor/hidden_service
    depends_on:
      - web
  
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
```

## Key Improvements Over Original

1. **Latest Tor Version**: Uses Tor 0.4.8.17 from Alpine packages (vs older compiled versions)
2. **Minimal Size**: Pure Alpine base - no Python bloat, no complex dependencies
3. **No Compilation**: Zero build complexity or failure points
4. **Fast & Reliable**: Builds in seconds, not minutes
5. **Clean Architecture**: Only essential components, no legacy compatibility code

## Generated Files

The container creates:
- `{service_name}/hostname` - Your .onion address
- `{service_name}/hs_ed25519_*` - Hidden service keys

**Tor version: 0.4.8.17**
