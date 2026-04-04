#!/usr/bin/env python3
"""
HiddenForge entrypoint — generates a hardened torrc, starts Tor, and
monitors the Vanguards guard-protection addon alongside it.
"""
import os
import pwd
import re
import socket
import sys
import subprocess
import signal
import time
from pathlib import Path

# Module-level process references so the signal handler can terminate both.
_tor_process = None
_vanguards_process = None

VANGUARDS_BIN    = '/opt/vanguards-venv/bin/vanguards'
CONTROL_SOCKET   = '/var/lib/tor/control.sock'
VANGUARDS_STATE  = '/var/lib/tor/vanguards.state'


def _chown_r(path, uid, gid):
    """Recursively chown path without shelling out to chown(1)."""
    os.chown(path, uid, gid)
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            os.chown(os.path.join(root, name), uid, gid)


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

def _kill_proc(proc, name, timeout=10):
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"{name} did not stop in time, killing...")
        proc.kill()
    except Exception:
        pass


def signal_handler(signum, frame):
    """Graceful shutdown: stop Vanguards first, then Tor."""
    print(f"Received signal {signum}, shutting down...")
    _kill_proc(_vanguards_process, "Vanguards", timeout=5)
    _kill_proc(_tor_process,       "Tor",       timeout=10)
    sys.exit(0)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def validate_service_name(name):
    """Allow only lowercase alphanumeric and hyphens."""
    if not re.fullmatch(r'[a-z0-9][a-z0-9\-]*', name):
        raise ValueError(
            f"Invalid service name '{name}': only lowercase alphanumeric "
            "and hyphens allowed"
        )
    return name


def validate_port(value, label):
    """Ensure value is a valid 1-65535 port number."""
    stripped = value.strip()
    if not re.fullmatch(r'\d{1,5}', stripped):
        raise ValueError(f"Invalid port '{value}' in {label}")
    port = int(stripped)
    if not 1 <= port <= 65535:
        raise ValueError(f"Port {port} out of range in {label}")
    return str(port)


def validate_hostname(value, label):
    """Allow hostnames, Docker service names, and IPv4 addresses."""
    v = value.strip()
    if not re.fullmatch(r'[a-zA-Z0-9._\-]{1,253}', v):
        raise ValueError(f"Invalid hostname '{v}' in {label}")
    return v


def resolve_to_ip(host, label):
    """
    Return an IPv4 address string for the given host.

    If host is already a dotted-quad IP it is returned unchanged.
    Otherwise Docker's embedded DNS is queried (this resolves Compose service
    names like 'web' to their container IP at startup time, so Tor never sees
    a hostname in HiddenServicePort — it only accepts IPs).
    """
    stripped = host.strip()
    if re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', stripped):
        return stripped
    try:
        resolved = socket.gethostbyname(stripped)
        print(f"Resolved '{stripped}' → {resolved}")
        return resolved
    except socket.gaierror as exc:
        raise ValueError(
            f"Cannot resolve '{stripped}' in {label}: {exc}. "
            "Is the backend container running and on the same network?"
        )


# ---------------------------------------------------------------------------
# Tor configuration generation
# ---------------------------------------------------------------------------

def generate_basic_torrc():
    """Build a hardened torrc and write it to /etc/tor/torrc."""

    # Tor's own seccomp sandbox can be disabled via env var for environments
    # that cannot pass --security-opt seccomp=unconfined (e.g. some managed
    # container platforms).  Default is enabled.
    sandbox = "1" if os.environ.get("TOR_SANDBOX", "1") != "0" else "0"

    torrc_content = f"""# HiddenForge — hardened Tor configuration
# Generated at container startup. Do not edit by hand.

# ── Control socket (required for Vanguards addon) ──────────────────────────
# Unix socket inside DataDirectory, 0600 owned by tor.  Not reachable from
# other containers.  No password needed; file permissions are the boundary.
ControlSocket /var/lib/tor/control.sock

# ── Network ────────────────────────────────────────────────────────────────
SocksPort 0
DataDirectory /var/lib/tor
ClientOnly 1          # never volunteer as a relay or exit node
ExitPolicy reject *:* # belt-and-suspenders: refuse all exit traffic

# ── Logging ────────────────────────────────────────────────────────────────
Log notice stdout
SafeLogging 1         # scrub IPs / .onion addresses from log output
HeartbeatPeriod 0     # suppress periodic heartbeat log spam

# ── Security hardening ─────────────────────────────────────────────────────
Sandbox {sandbox}             # seccomp-bpf syscall filter (needs --security-opt seccomp=unconfined)
DisableDebuggerAttachment 1   # block ptrace / debugger attachment
AvoidDiskWrites 1             # minimise forensic footprint on disk
FetchUselessDescriptors 0     # do not fetch relay descriptors we won't use (default, explicit)

# ── Hidden services ────────────────────────────────────────────────────────
"""

    # Ensure the parent hidden_service directory is traversable by the tor user.
    # In rootless podman the bind-mounted host dir may appear as root:root 770
    # inside the container, blocking tor (UID 100) from entering subdirs.
    parent_hs = Path('/var/lib/tor/hidden_service')
    if parent_hs.exists():
        os.chmod(parent_hs, 0o755)

    found_any = False
    for env_var in sorted(os.environ):          # sorted for deterministic torrc output
        if not env_var.endswith('_TOR_SERVICE_HOSTS'):
            continue

        service_hosts = os.environ[env_var]
        # Underscores are valid in env var names but not in service directory names;
        # convert them to hyphens so MY_APP_TOR_SERVICE_HOSTS → my-app.
        raw_name = env_var.replace('_TOR_SERVICE_HOSTS', '').lower().replace('_', '-')

        try:
            service_name = validate_service_name(raw_name)
        except ValueError as e:
            print(f"Skipping invalid service name from {env_var}: {e}")
            continue

        print(f"Configuring hidden service: {service_name}")
        print(f"Service hosts: {service_hosts}")

        hs_dir = f"/var/lib/tor/hidden_service/{service_name}"
        Path(hs_dir).mkdir(parents=True, exist_ok=True)
        # chmod requires owning the directory (CAP_FOWNER not assumed).
        # If the dir already exists from a previous run it will be owned by
        # the tor user, so skip chmod — it will already be 0700 from when
        # it was first created.  We always chown so newly-created dirs are
        # transferred to the tor user regardless of the calling uid.
        if os.stat(hs_dir).st_uid == 0:
            os.chmod(hs_dir, 0o700)
        tor_pw = pwd.getpwnam('tor')
        _chown_r(hs_dir, tor_pw.pw_uid, tor_pw.pw_gid)

        torrc_content += f"\n# ── Service: {service_name} ──\n"
        torrc_content += f"HiddenServiceDir     {hs_dir}\n"
        torrc_content += "HiddenServiceVersion 3\n"
        torrc_content += "HiddenServiceNumIntroductionPoints 6\n"   # default 3; more = harder to attack
        torrc_content += "HiddenServiceMaxStreams 100\n"             # rate-limit per circuit
        torrc_content += "HiddenServiceMaxStreamsCloseCircuit 1\n"   # drop circuit on overrun
        # PoW options are per-service in Tor 0.4.8+ (must follow HiddenServiceDir)
        torrc_content += "HiddenServicePoWDefensesEnabled 1\n"
        torrc_content += "HiddenServicePoWQueueRate  250\n"
        torrc_content += "HiddenServicePoWQueueBurst 2500\n"

        for host_mapping in service_hosts.split(','):
            if ':' not in host_mapping:
                continue
            parts = host_mapping.strip().split(':')
            try:
                if len(parts) == 3:
                    hs_port     = validate_port(parts[0],     host_mapping)
                    target_host = validate_hostname(parts[1], host_mapping)
                    target_host = resolve_to_ip(target_host,  host_mapping)
                    target_port = validate_port(parts[2],     host_mapping)
                    torrc_content += f"HiddenServicePort {hs_port} {target_host}:{target_port}\n"
                elif len(parts) == 2:
                    hs_port     = validate_port(parts[0], host_mapping)
                    target_port = validate_port(parts[1], host_mapping)
                    torrc_content += f"HiddenServicePort {hs_port} 127.0.0.1:{target_port}\n"
                else:
                    print(f"Skipping malformed mapping: '{host_mapping}'")
            except ValueError as e:
                print(f"Skipping invalid mapping '{host_mapping}': {e}")

        found_any = True

    if not found_any:
        print("Warning: no *_TOR_SERVICE_HOSTS env vars found — "
              "Tor will start but no hidden services will be configured.")

    torrc_path = '/etc/tor/torrc'
    with open(torrc_path, 'w') as f:
        f.write(torrc_content)
    os.chmod(torrc_path, 0o640)

    print("Generated Tor configuration at /etc/tor/torrc")
    return True


# ---------------------------------------------------------------------------
# Vanguards management
# ---------------------------------------------------------------------------

def wait_for_socket(timeout=120):
    """Block until Tor's control Unix socket appears."""
    print("Waiting for Tor control socket...")
    start = time.monotonic()
    while not Path(CONTROL_SOCKET).exists():
        if time.monotonic() - start > timeout:
            raise TimeoutError(
                f"Tor control socket not found after {timeout}s"
            )
        time.sleep(0.5)
    # Give Tor a moment to finish setting socket permissions.
    time.sleep(0.5)
    print("Control socket ready.")


def start_vanguards():
    """Launch the Vanguards addon as the tor user via the control socket.

    --disable_vanguards: suppress the NumEntryGuards SETCONF call that
      triggers Tor config re-validation — which Sandbox 1 blocks.
      Guard-layer rotation is handled by Tor's built-in vanguards-lite.
      We still gain bandguards (bandwidth side-channel detection) and
      rendguard (rendezvous-point overuse detection).
    """
    cmd = [
        VANGUARDS_BIN,
        '--control_socket',  CONTROL_SOCKET,
        '--state',           VANGUARDS_STATE,
        '--loglevel',        'NOTICE',
        '--disable_vanguards',   # avoid SETCONF conflict with Sandbox 1
    ]
    print(f"Starting Vanguards: {' '.join(cmd)}")
    return subprocess.Popen(['su-exec', 'tor'] + cmd)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _tor_process, _vanguards_process

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT,  signal_handler)

    tor_pw = pwd.getpwnam('tor')

    # ── Generate torrc ──────────────────────────────────────────────────────
    try:
        print("Generating Tor configuration...")
        generate_basic_torrc()
        print("Tor configuration generated successfully.")
    except Exception as e:
        print(f"Error generating configuration: {e}")
        sys.exit(1)

    os.chown('/etc/tor/torrc', tor_pw.pw_uid, tor_pw.pw_gid)

    # ── Fix DataDirectory ownership ─────────────────────────────────────────
    # Docker's tmpfs uid=/gid= mount options pre-set ownership at mount time,
    # but Podman does not support those options.  We explicitly chown the
    # DataDirectory here so the same image works under both runtimes.
    #
    # This must happen AFTER generate_basic_torrc() creates hidden_service
    # subdirs: once /var/lib/tor is owned by the tor user (mode 0700), root
    # without CAP_DAC_OVERRIDE cannot traverse into it.
    data_dir = Path('/var/lib/tor')
    if data_dir.exists():
        # Podman does not support the uid=/gid=/mode= tmpfs mount options that
        # Docker uses.  When running under Podman the tmpfs starts root-owned;
        # we set the mode and transfer ownership here so Tor can access it.
        #
        # When running under Docker the tmpfs is already tor:tor 0700 via the
        # mount options, so we skip chmod (root can't chmod a file it doesn't
        # own without CAP_FOWNER) and the chown is a harmless no-op.
        if os.stat(data_dir).st_uid == 0:
            os.chmod(data_dir, 0o700)   # safe: we own the dir, no FOWNER needed
        os.chown(data_dir, tor_pw.pw_uid, tor_pw.pw_gid)

    # ── Start Tor ───────────────────────────────────────────────────────────
    print("Starting Tor...")
    _tor_process = subprocess.Popen(
        ['su-exec', 'tor', 'tor', '-f', '/etc/tor/torrc']
    )

    # ── Start Vanguards once the control socket exists ──────────────────────
    try:
        wait_for_socket(timeout=120)
        _vanguards_process = start_vanguards()
        print("Vanguards addon started.")
    except TimeoutError as e:
        print(f"Warning: {e}. Continuing without Vanguards.")
    except Exception as e:
        print(f"Warning: could not start Vanguards: {e}. Continuing without it.")

    # ── Process supervision loop ────────────────────────────────────────────
    vanguards_restarts    = 0
    vanguards_last_start  = time.monotonic()

    while True:
        time.sleep(1)

        # Tor is the primary process — exit if it dies.
        tor_rc = _tor_process.poll()
        if tor_rc is not None:
            print(f"Tor exited with code {tor_rc}, shutting down.")
            _kill_proc(_vanguards_process, "Vanguards", timeout=5)
            sys.exit(tor_rc if tor_rc != 0 else 1)

        # Restart Vanguards if it crashes (up to 5 times, then give up).
        if _vanguards_process is not None:
            vg_rc = _vanguards_process.poll()
            if vg_rc is not None:
                now = time.monotonic()
                # Reset counter if the last restart was more than 60s ago.
                if now - vanguards_last_start > 60:
                    vanguards_restarts = 0

                vanguards_restarts   += 1
                vanguards_last_start  = now

                if vanguards_restarts > 5:
                    print(
                        f"Vanguards exited (code {vg_rc}) too many times "
                        "in quick succession — disabling addon."
                    )
                    _vanguards_process = None
                else:
                    print(
                        f"Vanguards exited (code {vg_rc}), "
                        f"restarting (attempt {vanguards_restarts}/5)..."
                    )
                    try:
                        _vanguards_process = start_vanguards()
                    except Exception as e:
                        print(f"Could not restart Vanguards: {e}")
                        _vanguards_process = None


if __name__ == '__main__':
    main()
