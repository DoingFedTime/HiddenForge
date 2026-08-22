#!/usr/bin/env python3
"""
HiddenForge entrypoint — generates a hardened torrc, starts Tor, and
monitors the Vanguards guard-protection addon alongside it.
"""
import ipaddress
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
    """Recursively chown path without shelling out to chown(1).

    SECURITY: this runs as root (PID 1) over the operator-supplied key bind
    mount, so every entry it touches is attacker-influenceable if that volume is
    ever restored from untrusted media or is writable by another host user.

    ``os.chown`` follows symlinks by default, which turns this function into a
    root-privileged arbitrary-chown primitive: a symlink placed inside the key
    directory pointing anywhere else in the container would have its *target*
    chowned to the tor user.  We therefore use ``follow_symlinks=False``
    (lchown) so the link itself is retargeted and never its destination, and
    pass ``followlinks=False`` to ``os.walk`` so symlinked directories are not
    descended into.  Tor has no legitimate use for symlinks inside a
    HiddenServiceDir, so nothing is lost by refusing to follow them.
    """
    os.chown(path, uid, gid, follow_symlinks=False)
    for root, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            os.chown(os.path.join(root, name), uid, gid, follow_symlinks=False)


def _open_dir_nofollow(path):
    """Open a directory, refusing to traverse a final-component symlink.

    Returns a file descriptor the caller must close.  Linux has no ``lchmod``,
    so the only way to chmod a directory without a symlink race is to hold an
    ``O_NOFOLLOW`` descriptor to it and use ``fchmod``/``fstat`` on that fd.

    Raises ``OSError(ENOTDIR)`` if ``path`` is a symlink, a regular file, or any
    other non-directory.  (Verified kernel behaviour: with ``O_DIRECTORY`` set,
    a symlink yields ENOTDIR rather than the ELOOP that ``O_NOFOLLOW`` alone
    would give — ``O_DIRECTORY`` is evaluated first.  We keep ``O_DIRECTORY``
    deliberately: it also makes opening a FIFO or device node fail immediately
    instead of blocking, which a bare ``O_NOFOLLOW`` open would not.)  Either
    way the open is refused, which is the correct loud failure for a key
    directory that has been tampered with.
    """
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _chmod_dir_nofollow(path, mode, only_if_root_owned=False):
    """chmod a directory via an O_NOFOLLOW fd; never follows a symlink.

    If ``only_if_root_owned`` is set, the mode is applied only when the
    directory is still owned by uid 0 — preserving the existing logic that
    avoids chmod'ing a directory we do not own (which would need CAP_FOWNER).
    The ownership test is done with ``fstat`` on the same descriptor we chmod,
    so there is no TOCTOU window between the check and the change.
    """
    fd = _open_dir_nofollow(path)
    try:
        if only_if_root_owned and os.fstat(fd).st_uid != 0:
            return False
        os.fchmod(fd, mode)
        return True
    finally:
        os.close(fd)


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
    """Allow only lowercase alphanumeric and hyphens, max 63 chars.

    The name is interpolated into a filesystem path
    (/var/lib/tor/hidden_service/<name>), so it is length-capped at 63 — the
    DNS-label limit and a comfortable bound below any filesystem name limit.
    """
    if not re.fullmatch(r'[a-z0-9][a-z0-9\-]*', name) or len(name) > 63:
        raise ValueError(
            f"Invalid service name '{name}': only lowercase alphanumeric "
            "and hyphens allowed, max 63 chars"
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
    # If it has the shape of a dotted-quad, require it to be a VALID IPv4
    # address (reject e.g. 999.999.999.999 and leading-zero octets) rather than
    # passing the malformed value through to the torrc.
    if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', stripped):
        try:
            return str(ipaddress.IPv4Address(stripped))
        except ipaddress.AddressValueError as exc:
            raise ValueError(
                f"Invalid IPv4 address '{stripped}' in {label}"
            ) from exc
    try:
        resolved = socket.gethostbyname(stripped)
    except socket.gaierror as exc:
        raise ValueError(
            f"Cannot resolve '{stripped}' in {label}: {exc}. "
            "Is the backend container running and on the same network?"
        ) from exc

    # Re-parse the resolver's answer instead of trusting its formatting.
    #
    # This is defence in depth, not a patch for a reachable attack: CPython builds
    # this string itself with inet_ntop from a 4-byte struct, so a hostile DNS
    # server cannot smuggle whitespace or a newline through it (verified: it
    # normalises 0177.0.0.1 and 2130706433 to 127.0.0.1 rather than echoing input).
    # The value is nonetheless the ONLY thing reaching the torrc that this module
    # did not construct or validate itself, and anything with an embedded newline
    # would split a HiddenServicePort line and stop Tor from starting at all. That
    # invariant is worth enforcing rather than inheriting from CPython's internals,
    # so a future change of resolver cannot silently reintroduce the gap.
    try:
        validated = str(ipaddress.IPv4Address(resolved.strip()))
    except (ipaddress.AddressValueError, ValueError, AttributeError) as exc:
        raise ValueError(
            f"Resolver returned a non-IPv4 value {resolved!r} for '{stripped}' "
            f"in {label} — refusing to write it to the torrc"
        ) from exc

    print(f"Resolved '{stripped}' → {validated}")
    return validated


# ---------------------------------------------------------------------------
# Tor configuration generation
# ---------------------------------------------------------------------------

def build_torrc_string():
    """Validate env vars and assemble the torrc text — PURE, no filesystem side effects.

    Returns a tuple ``(torrc_content, hs_dirs)`` where ``hs_dirs`` is the list of
    hidden-service directory paths (in deterministic order) that the caller must
    create and chown.  This function performs NO ``mkdir``/``chmod``/``chown`` and
    does not touch ``pwd`` — that makes it host-testable without the ``tor`` user
    or write access to ``/etc/tor`` and keeps the security-critical string
    assembly isolated from privileged operations.  The bytes it produces are
    identical to what the previous monolithic generator wrote.
    """

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

# ── Guard-discovery protection ─────────────────────────────────────────────
# vanguards-lite (Tor proposal 333) pins a small set of layer-2 guards so an
# adversary cannot enumerate our position by forcing circuit rebuilds.  This is
# our PRIMARY defence against guard discovery: the full Vanguards addon's
# layer-2/3 pinning cannot be used here because it applies its guard sets via
# SETCONF, which the seccomp sandbox rejects when enabled ("Failed to configure
# rendezvous options"). We keep the sandbox and rely on vanguards-lite instead.
#
# Pinned to 1, NOT left at the "auto" default.  Per the Tor manual, "auto" means
# "do what the vanguards-lite-enabled consensus parameter tells them to do" —
# which puts our only guard-discovery defence under the control of the directory
# authorities rather than the operator.  An adversary able to influence the
# consensus could otherwise disable it for every deployment simultaneously,
# silently.  Setting it explicitly makes that impossible.
VanguardsLiteEnabled 1

# ── Hidden services ────────────────────────────────────────────────────────
"""

    found_any = False
    hs_dirs = []
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

        # The service block is assembled separately and only committed if at
        # least one port mapping survives validation.  Tor REFUSES TO START AT
        # ALL on a HiddenServiceDir with no HiddenServicePort ("Hidden service
        # with no ports configured" -> "Reading config failed"), so emitting a
        # portless block would let one typo in one service take down every other
        # service in the container.  Skipping invalid mappings while still
        # emitting the block would be graceful in appearance only.
        service_block = f"\n# ── Service: {service_name} ──\n"
        service_block += f"HiddenServiceDir     {hs_dir}\n"
        service_block += "HiddenServiceVersion 3\n"
        service_block += "HiddenServiceNumIntroductionPoints 6\n"   # default 3; max 20
        service_block += "HiddenServiceMaxStreams 100\n"             # rate-limit per circuit
        service_block += "HiddenServiceMaxStreamsCloseCircuit 1\n"   # drop circuit on overrun
        # PoW options are per-service in Tor 0.4.8+ (must follow HiddenServiceDir).
        # PoW throttles the RENDEZVOUS stage (prioritises clients by puzzle effort).
        service_block += "HiddenServicePoWDefensesEnabled 1\n"
        service_block += "HiddenServicePoWQueueRate  250\n"
        service_block += "HiddenServicePoWQueueBurst 2500\n"
        # Intro-point DoS defence throttles the INTRODUCE2 stage at the intro
        # points — a different choke point from PoW, complementary not redundant.
        # Default-off in torrc and in the consensus; we enable it explicitly with
        # Tor's documented default rate/burst (25/sec, 200 burst). Burst must be
        # non-zero or the defence is disabled. (Tor onion-service DoS guidelines.)
        service_block += "HiddenServiceEnableIntroDoSDefense 1\n"
        service_block += "HiddenServiceEnableIntroDoSRatePerSec 25\n"
        service_block += "HiddenServiceEnableIntroDoSBurstPerSec 200\n"

        port_lines = []
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
                    port_lines.append(f"HiddenServicePort {hs_port} {target_host}:{target_port}\n")
                elif len(parts) == 2:
                    hs_port     = validate_port(parts[0], host_mapping)
                    target_port = validate_port(parts[1], host_mapping)
                    port_lines.append(f"HiddenServicePort {hs_port} 127.0.0.1:{target_port}\n")
                else:
                    print(f"Skipping malformed mapping: '{host_mapping}'")
            except ValueError as e:
                print(f"Skipping invalid mapping '{host_mapping}': {e}")

        if not port_lines:
            # Drop the service entirely rather than emit a portless block that
            # would abort Tor's startup and take every other service with it.
            print(
                f"ERROR: service '{service_name}' has no valid port mappings "
                f"(from {env_var}='{service_hosts}') — skipping it. Tor cannot "
                "start a hidden service with no ports, so emitting it would "
                "take down every other service too. Fix this mapping."
            )
            continue

        torrc_content += service_block + "".join(port_lines)
        hs_dirs.append(hs_dir)
        found_any = True

    if not found_any:
        print("Warning: no *_TOR_SERVICE_HOSTS env vars found — "
              "Tor will start but no hidden services will be configured.")

    return torrc_content, hs_dirs


def generate_basic_torrc():
    """Build the torrc, create/own the hidden-service dirs, and write /etc/tor/torrc.

    Thin wrapper around the pure :func:`build_torrc_string`: it performs only the
    privileged filesystem side effects (parent-dir traversal fix, per-service
    ``mkdir``/``chmod``/``chown``, and writing the config file).  Behaviour and
    output bytes are identical to the previous single-function implementation.
    """

    # Ensure the parent hidden_service directory is traversable by the tor user.
    # In rootless podman the bind-mounted host dir may appear as root:root 770
    # inside the container, blocking tor (UID 100) from entering subdirs.
    #
    # 0o751, not 0o755: Tor only ever opens its HiddenServiceDir by full path, so
    # it needs the execute (traverse) bit on this parent and nothing else. The
    # read bit would additionally let any non-owner enumerate the names of every
    # hidden service configured on the host, which is information a compromised
    # in-container process should not get for free. Grant traverse, withhold list.
    # (The per-service directories below remain 0700, owned by tor.)
    parent_hs = Path('/var/lib/tor/hidden_service')
    if parent_hs.exists():
        # nosec B103 - 0o751 is the minimum that works: Tor (uid 100) is "other"
        # relative to this root-owned bind mount and must be able to traverse it.
        # The alternative, chowning the operator's host directory to uid 100, is
        # more surprising and no more secure. Keys stay in 0700 subdirectories.
        _chmod_dir_nofollow(parent_hs, 0o751)

    torrc_content, hs_dirs = build_torrc_string()

    tor_pw = pwd.getpwnam('tor')
    for hs_dir in hs_dirs:
        Path(hs_dir).mkdir(parents=True, exist_ok=True)
        # chmod requires owning the directory (CAP_FOWNER not assumed).
        # If the dir already exists from a previous run it will be owned by
        # the tor user, so skip chmod — it will already be 0700 from when
        # it was first created.  We always chown so newly-created dirs are
        # transferred to the tor user regardless of the calling uid.
        #
        # mkdir(exist_ok=True) succeeds if hs_dir is a symlink to a directory,
        # so the O_NOFOLLOW open below is what actually rejects a tampered key
        # volume: it raises ELOOP rather than letting a root chmod/chown escape
        # the hidden_service tree.
        _chmod_dir_nofollow(hs_dir, 0o700, only_if_root_owned=True)
        _chown_r(hs_dir, tor_pw.pw_uid, tor_pw.pw_gid)

    # Write the config through an O_NOFOLLOW descriptor and set its metadata on
    # that same descriptor.
    #
    # open('w') follows symlinks, and the chmod/chown that used to follow took a
    # PATH — so a process that could write into the /etc/tor tmpfs before this
    # point could replace torrc with a symlink and have root truncate, chmod and
    # chown an arbitrary file. The window is small (this runs early, as PID 1, on
    # a tmpfs that starts empty) but it costs nothing to close, and it is the same
    # class of bug already fixed for the hidden-service key directory.
    #
    # fchmod/fchown operate on a DUPLICATE of the write descriptor: os.fdopen()
    # takes ownership of the original and closes it when the with-block exits, so
    # using it afterwards raises EBADF.
    torrc_path = '/etc/tor/torrc'
    torrc_fd = os.open(
        torrc_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640
    )
    meta_fd = None
    try:
        with os.fdopen(torrc_fd, 'w') as f:
            f.write(torrc_content)
            f.flush()
            meta_fd = os.dup(f.fileno())
        os.fchmod(meta_fd, 0o640)
        os.fchown(meta_fd, tor_pw.pw_uid, tor_pw.pw_gid)
    finally:
        if meta_fd is not None:
            os.close(meta_fd)

    print("Generated Tor configuration at /etc/tor/torrc")
    return True


# ---------------------------------------------------------------------------
# Vanguards management
# ---------------------------------------------------------------------------

def wait_for_socket(timeout=120):
    """Block until Tor's control Unix socket appears.

    The socket lives inside /var/lib/tor (tor:tor 0700).  Root without
    CAP_DAC_OVERRIDE (rootless Podman) cannot traverse that directory, so
    Path.exists() would raise PermissionError.  We instead poll by running
    'test -S <socket>' as the tor user via su-exec, which has full access to
    its own DataDirectory.
    """
    print("Waiting for Tor control socket...")
    start = time.monotonic()
    while True:
        result = subprocess.run(
            ['su-exec', 'tor', 'test', '-S', CONTROL_SOCKET],
            capture_output=True,
        )
        if result.returncode == 0:
            break
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

    # torrc ownership is set by fchown on the write descriptor inside
    # generate_basic_torrc(); doing it again here by PATH would reopen the
    # symlink race that descriptor exists to close.

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
        # safe: we own the dir, no FOWNER needed. O_NOFOLLOW-based so a symlinked
        # DataDirectory cannot redirect the root chmod/chown elsewhere.
        _chmod_dir_nofollow(data_dir, 0o700, only_if_root_owned=True)
        os.chown(data_dir, tor_pw.pw_uid, tor_pw.pw_gid, follow_symlinks=False)

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
            # A Tor that exits ON ITS OWN is a failure even when its exit code is
            # 0, so report non-zero. Reaching this loop at all means nobody asked
            # us to stop: an orderly `docker stop` is handled by signal_handler,
            # which exits 0 without coming through here.
            #
            # Do NOT "preserve the real exit code" here. Measured behaviour:
            # restart:unless-stopped restarts on ANY exit status (exit 0 still
            # produced 7 restarts in 12s), so passing 0 through prevents no
            # restart loop; and under restart:on-failure exit 0 means the
            # container stays DOWN with a success status, leaving a dead onion
            # that looks healthy in `docker ps`.
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
