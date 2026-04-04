#!/usr/bin/env python3
import os
import re
import sys
import subprocess
import signal
import time
from pathlib import Path

# Module-level reference so signal_handler can terminate the child cleanly
_tor_process = None


def signal_handler(signum, frame):
    """Handle shutdown signals — terminate Tor child before exiting."""
    print(f"Received signal {signum}, shutting down...")
    if _tor_process is not None:
        try:
            _tor_process.terminate()
            _tor_process.wait(timeout=10)
        except Exception:
            _tor_process.kill()
    sys.exit(0)


def validate_service_name(name):
    """Allow only alphanumeric and hyphens; reject anything else."""
    if not re.fullmatch(r'[a-z0-9][a-z0-9\-]*', name):
        raise ValueError(f"Invalid service name '{name}': only lowercase alphanumeric and hyphens allowed")
    return name


def validate_port(value, label):
    """Ensure value is a valid port number string."""
    if not re.fullmatch(r'\d{1,5}', value.strip()):
        raise ValueError(f"Invalid port '{value}' in {label}")
    port = int(value.strip())
    if not 1 <= port <= 65535:
        raise ValueError(f"Port {port} out of range in {label}")
    return str(port)


def validate_hostname(value, label):
    """Allow hostnames, Docker service names, and IPv4 addresses."""
    v = value.strip()
    if not re.fullmatch(r'[a-zA-Z0-9._\-]{1,253}', v):
        raise ValueError(f"Invalid hostname '{v}' in {label}")
    return v


def generate_basic_torrc():
    """Generate a hardened torrc configuration with hidden services."""
    torrc_content = """# Basic Tor configuration
# ControlPort intentionally omitted — not needed for hidden-service-only use
SocksPort 0
DataDirectory /var/lib/tor
Log notice stdout

# Hidden service configuration
"""

    # Ensure the parent hidden_service directory is traversable by the tor user.
    # In rootless podman the bind-mounted host dir may have restrictive permissions
    # (e.g. 770 root:root inside the container) which prevents the tor user from
    # entering it at all — even though it owns the 700 subdirs within.
    parent_hs = Path('/var/lib/tor/hidden_service')
    if parent_hs.exists():
        os.chmod(parent_hs, 0o755)

    # Check for environment variables that define hidden services
    for env_var in os.environ:
        if not env_var.endswith('_TOR_SERVICE_HOSTS'):
            continue

        service_hosts = os.environ[env_var]
        raw_name = env_var.replace('_TOR_SERVICE_HOSTS', '').lower()

        try:
            service_name = validate_service_name(raw_name)
        except ValueError as e:
            print(f"Skipping invalid service name from {env_var}: {e}")
            continue

        print(f"Configuring hidden service: {service_name}")
        print(f"Service hosts: {service_hosts}")

        # Create hidden service directory with correct permissions
        hs_dir = f"/var/lib/tor/hidden_service/{service_name}"
        Path(hs_dir).mkdir(parents=True, exist_ok=True)
        os.chmod(hs_dir, 0o700)
        subprocess.run(['chown', '-R', 'tor:tor', hs_dir], check=True)

        torrc_content += f"\n# Hidden service: {service_name}\n"
        torrc_content += f"HiddenServiceDir {hs_dir}\n"
        torrc_content += "HiddenServiceVersion 3\n"

        for host_mapping in service_hosts.split(','):
            if ':' not in host_mapping:
                continue
            parts = host_mapping.strip().split(':')
            try:
                if len(parts) == 3:
                    hs_port     = validate_port(parts[0], host_mapping)
                    target_host = validate_hostname(parts[1], host_mapping)
                    target_port = validate_port(parts[2], host_mapping)
                    torrc_content += f"HiddenServicePort {hs_port} {target_host}:{target_port}\n"
                elif len(parts) == 2:
                    hs_port     = validate_port(parts[0], host_mapping)
                    target_port = validate_port(parts[1], host_mapping)
                    torrc_content += f"HiddenServicePort {hs_port} 127.0.0.1:{target_port}\n"
                else:
                    print(f"Skipping malformed mapping: '{host_mapping}'")
            except ValueError as e:
                print(f"Skipping invalid mapping '{host_mapping}': {e}")
                continue

    # Write torrc and lock down permissions
    torrc_path = '/etc/tor/torrc'
    with open(torrc_path, 'w') as f:
        f.write(torrc_content)
    os.chmod(torrc_path, 0o640)

    print("Generated Tor configuration at /etc/tor/torrc")
    return True


def main():
    global _tor_process

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        print("Generating Tor configuration...")
        generate_basic_torrc()
        print("Tor configuration generated successfully")
    except Exception as e:
        print(f"Error generating configuration: {e}")
        sys.exit(1)

    print("Starting Tor as tor user...")
    cmd = sys.argv[1:] if len(sys.argv) > 1 else ['tor', '-f', '/etc/tor/torrc']

    subprocess.run(['chown', 'tor:tor', '/etc/tor/torrc'], check=True)

    try:
        full_cmd = ['su-exec', 'tor'] + cmd
        _tor_process = subprocess.Popen(full_cmd)
        _tor_process.wait()
    except KeyboardInterrupt:
        print("Received interrupt, shutting down...")
        _tor_process.terminate()
        _tor_process.wait()
    except Exception as e:
        print(f"Error starting process: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
