# HiddenForge

A modern, lightweight Tor hidden service Docker image. Forge .onion services with the latest Tor (0.4.8.17) and minimal dependencies.

## Features

- **Latest Tor Version**: Uses Tor 0.4.8.17 from Alpine packages
- **Minimal Size**: Pure Alpine base with only essential components  
- **Simple & Fast**: No compilation, builds in seconds
- **Easy Configuration**: Environment variable-based hidden service setup
- **Secure**: Runs as non-root tor user with proper permissions

## Usage

### Basic Usage

```bash
docker run -d \
  -v ./tor-data:/var/lib/tor/hidden_service \
  -e SERVICE_TOR_SERVICE_HOSTS="80:nginx:80" \
  hiddenforge:latest
```

### Environment Variables

The image uses the same environment variable format as goldy/tor-hidden-service:

- `{NAME}_TOR_SERVICE_HOSTS`: Defines hidden service mappings
  - Format: `"port:host:port,port2:host2:port2"`
  - Example: `"80:nginx:80,443:nginx:443"`

### Docker Compose Example

```yaml
version: '3.8'
services:
  tor:
    image: hiddenforge:latest
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
