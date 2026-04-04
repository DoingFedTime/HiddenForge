#!/usr/bin/env python3
import os
import sys
import subprocess
import signal
import time
from pathlib import Path

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print(f"Received signal {signum}, shutting down...")
    sys.exit(0)

def generate_basic_torrc():
    """Generate a basic torrc configuration with hidden services"""
    torrc_content = """# Basic Tor configuration
ControlPort 9051
DataDirectory /var/lib/tor

# Hidden service configuration
"""
    
    # Check for environment variables that define hidden services
    # Following the same pattern as goldy's image
    for env_var in os.environ:
        if env_var.endswith('_TOR_SERVICE_HOSTS'):
            service_hosts = os.environ[env_var]
            service_name = env_var.replace('_TOR_SERVICE_HOSTS', '').lower()
            
            print(f"Configuring hidden service: {service_name}")
            print(f"Service hosts: {service_hosts}")
            
            # Create hidden service directory with correct permissions
            hs_dir = f"/var/lib/tor/hidden_service/{service_name}"
            Path(hs_dir).mkdir(parents=True, exist_ok=True)
            os.chmod(hs_dir, 0o700)  # Tor requires 700 permissions
            # Change ownership to tor user
            subprocess.run(['chown', '-R', 'tor:tor', hs_dir], check=True)
            
            # Parse service hosts (format: "port:host:port,port2:host2:port2")
            torrc_content += f"\n# Hidden service: {service_name}\n"
            torrc_content += f"HiddenServiceDir {hs_dir}\n"
            
            for host_mapping in service_hosts.split(','):
                if ':' in host_mapping:
                    parts = host_mapping.strip().split(':')
                    if len(parts) == 3:
                        # Format: hs_port:target_host:target_port
                        hs_port = parts[0]
                        target_host = parts[1]
                        target_port = parts[2]
                        torrc_content += f"HiddenServicePort {hs_port} {target_host}:{target_port}\n"
                    elif len(parts) == 2:
                        # Format: hs_port:target_port (assume localhost)
                        hs_port = parts[0]
                        target_port = parts[1]
                        torrc_content += f"HiddenServicePort {hs_port} 127.0.0.1:{target_port}\n"
    
    # Write torrc file
    with open('/etc/tor/torrc', 'w') as f:
        f.write(torrc_content)
    
    print("Generated Tor configuration at /etc/tor/torrc")
    return True

def main():
    # Setup signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Generate basic Tor configuration
    try:
        print("Generating Tor configuration...")
        generate_basic_torrc()
        print("Tor configuration generated successfully")
    except Exception as e:
        print(f"Error generating configuration: {e}")
        sys.exit(1)
    
    # Start Tor as tor user
    print("Starting Tor as tor user...")
    cmd = sys.argv[1:] if len(sys.argv) > 1 else ['tor', '-f', '/etc/tor/torrc']
    
    # Change ownership of config file
    subprocess.run(['chown', 'tor:tor', '/etc/tor/torrc'], check=True)
    
    try:
        # Execute the command as tor user
        full_cmd = ['su-exec', 'tor'] + cmd
        process = subprocess.Popen(full_cmd)
        process.wait()
    except KeyboardInterrupt:
        print("Received interrupt, shutting down...")
        process.terminate()
        process.wait()
    except Exception as e:
        print(f"Error starting process: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()