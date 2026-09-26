#!/usr/bin/env python3
"""
HiddenForge entrypoint — generates a hardened torrc, starts Tor, and
monitors the Vanguards guard-protection addon alongside it.
"""
import contextlib
import ctypes
import errno
import ipaddress
import json
import os
import pwd
import re
import secrets
import socket
import stat
import sys
import subprocess
import signal
import threading
import time
from pathlib import Path

# Module-level process references so the signal handler can terminate both.
_tor_process = None
_vanguards_process = None

VANGUARDS_BIN    = '/opt/vanguards-venv/bin/vanguards'
CONTROL_SOCKET   = '/var/lib/tor/control.sock'
VANGUARDS_STATE  = '/var/lib/tor/vanguards.state'
VANGUARDS_MAX_RESTARTS = 5     # failed starts/exits in quick succession before giving up
VANGUARDS_RETRY_DELAY  = 10    # seconds between (re)start attempts
HF_CLI           = '/usr/local/bin/hiddenforge'
DATA_DIR         = '/var/lib/tor'
# The key volume's mount point inside the container, and the parent of every
# per-service HiddenServiceDir. Named once: it was spelled out literally in four
# places, so a change to the layout had four chances to be missed, and none of
# the code that used it could be exercised anywhere but inside the container.
KEYS_ROOT        = '/var/lib/tor/hidden_service'
TORRC_PATH       = '/etc/tor/torrc'
DROPPED_MAPPINGS = '/var/lib/tor/dropped-mappings'
ONION_RE         = re.compile(r'[a-z2-7]{56}\.onion')

# Subcommands the image CLI (`docker run <image> <cmd>`) dispatches to an
# operator tool instead of booting Tor. Mirrors the sibling i2pforge contract.
# `vanity` runs the vendored generator directly; every key-facing command runs as
# root so it can write into (and chown) a host-owned key bind mount. `show` and
# `doctor` run as the tor user because they only read the 0700 tor-owned key
# directories, which root cannot traverse under rootless Podman.
SUBCOMMANDS     = {'setup', 'show', 'doctor', 'version', 'info', 'vanity',
                   'encrypt-key', 'decrypt-key', 'backup', 'restore', 'rotate'}
AS_TOR          = {'show', 'doctor'}


def _safe(value):
    """Escape control characters before echoing operator-supplied values.

    Env-var values reach the start-up log verbatim. A value containing ANSI
    escapes or bare newlines could forge log lines or move the cursor when an
    operator re-enables the json-file log driver, so non-printable characters
    are escaped instead of emitted.
    """
    return ''.join(
        ch if ch.isprintable() else f'\\x{ord(ch):02x}'
        for ch in str(value)
    )


def dispatch_subcommand(argv):
    """Run the operator CLI for a known subcommand, else return None (boot Tor).

    Returns the process exit code, or None when argv does not name a subcommand
    and normal container start-up should proceed.
    """
    if not argv or argv[0] not in SUBCOMMANDS:
        return None
    if not os.path.exists(HF_CLI):
        print(f"error: {HF_CLI} not found in this image", file=sys.stderr)
        return 2
    if argv[0] == 'vanity':
        tool = ['/usr/local/bin/vanity.py', *argv[1:]]
    else:
        tool = [HF_CLI, *argv]
        if argv[0] == 'doctor':
            # No docker socket inside the container; check on-disk key hygiene only.
            tool.append('--keys-only')
    if argv[0] in AS_TOR and os.geteuid() == 0:
        tool = ['su-exec', 'tor', *tool]
    try:
        os.execvp(tool[0], tool)
    except OSError as exc:  # pragma: no cover - exec replaces the process on success
        print(f"error: could not run {tool[0]}: {exc}", file=sys.stderr)
        return 2


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
            _chown_one(os.path.join(root, name), uid, gid)


def _chown_one(path, uid, gid):
    """chown one entry of the key volume without reaching any other inode.

    A symlink is lchown'ed (its own inode, never its target). Anything else is
    opened O_NOFOLLOW|O_NONBLOCK and chowned through that descriptor, after
    checking the descriptor's link count: a HARDLINK is the same inode as a file
    somewhere else, so chowning it chowns that file too -- and lchown does not
    help, because there is no link to not-follow. Tor never hard-links its own
    files, so a regular file with more than one link is refused, loudly, and left
    alone. Checking and chowning through one descriptor leaves no window to swap
    the file between the two. Device nodes are refused before any open: opening
    one can have side effects, and a key volume has no business holding one.
    """
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        os.chown(path, uid, gid, follow_symlinks=False)
        return
    if stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode) or stat.S_ISSOCK(st.st_mode):
        # A socket cannot be opened (ENXIO), and refusing to BOOT over one
        # planted file would turn it into a restart loop; neither it nor a
        # device node belongs in a key volume, so it is left alone and named.
        print(f"Warning: not taking ownership of {_safe(path)} in the key volume: "
              "it is a device node or socket, which does not belong there.")
        return
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) and st.st_nlink > 1:
            print(f"Warning: not taking ownership of {_safe(path)}: it has "
                  f"{st.st_nlink} hard links, so it is also a file outside this "
                  "directory. Tor never hard-links its key files; remove the "
                  "extra links.")
            return
        os.fchown(fd, uid, gid)
    finally:
        os.close(fd)


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
            f"Invalid service name '{_safe(name)}': only lowercase alphanumeric "
            "and hyphens allowed, max 63 chars"
        )
    return name


def validate_port(value, label):
    """Ensure value is a valid 1-65535 port number."""
    stripped = value.strip()
    if not re.fullmatch(r'\d{1,5}', stripped):
        raise ValueError(f"Invalid port '{_safe(value)}' in {_safe(label)}")
    port = int(stripped)
    if not 1 <= port <= 65535:
        raise ValueError(f"Port {port} out of range in {_safe(label)}")
    return str(port)


def validate_hostname(value, label):
    """Allow hostnames, Docker service names, and IPv4 addresses."""
    v = value.strip()
    if not re.fullmatch(r'[a-zA-Z0-9._\-]{1,253}', v):
        raise ValueError(f"Invalid hostname '{_safe(v)}' in {_safe(label)}")
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
                f"Invalid IPv4 address '{_safe(stripped)}' in {_safe(label)}"
            ) from exc
    try:
        resolved = socket.gethostbyname(stripped)
    except socket.gaierror as exc:
        raise ValueError(
            f"Cannot resolve '{_safe(stripped)}' in {_safe(label)}: {_safe(exc)}. "
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
            f"Resolver returned a non-IPv4 value {resolved!r} for '{_safe(stripped)}' "
            f"in {_safe(label)} — refusing to write it to the torrc"
        ) from exc

    print(f"Resolved '{_safe(stripped)}' → {validated}")
    return validated


# ---------------------------------------------------------------------------
# Tor configuration generation
# ---------------------------------------------------------------------------

def build_torrc_string(dropped=None, resolved=None):
    """Validate env vars and assemble the torrc text — PURE, no filesystem side effects.

    Returns a tuple ``(torrc_content, hs_dirs)`` where ``hs_dirs`` is the list of
    hidden-service directory paths (in deterministic order) that the caller must
    create and chown.  This function performs NO ``mkdir``/``chmod``/``chown`` and
    does not touch ``pwd`` — that makes it host-testable without the ``tor`` user
    or write access to ``/etc/tor`` and keeps the security-critical string
    assembly isolated from privileged operations.  The bytes it produces are
    identical to what the previous monolithic generator wrote.

    If ``dropped`` is a list, a human-readable reason is appended for every
    skipped or dropped service/mapping.  The entrypoint writes those to
    /var/lib/tor/dropped-mappings so ``hiddenforge status`` can surface a
    misconfiguration instead of failing silently.

    If ``resolved`` is a dict, every backend given by NAME (not by IP literal)
    is recorded in it as ``name -> the IP written into the torrc``, so the
    supervisor can notice when that name later points somewhere else.
    """

    # Tor's own seccomp sandbox can be disabled via env var for environments
    # whose kernel or container runtime refuses to install the filter at all.
    # It is NOT a workaround for a runtime seccomp profile: Tor's sandbox
    # stacks on top of one (measured -- two filters on the Tor process under
    # both docker-default and podman's default profile), so a profile being
    # present is not a reason to turn this off.  Default is enabled.
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
Sandbox {sandbox}             # Tor's in-process seccomp-bpf filter; covers Tor only, and
                      # stacks on top of the runtime's own profile (do NOT run unconfined)
DisableDebuggerAttachment 1   # block ptrace / debugger attachment
NoExec 1                      # Tor will never launch another executable, ever
AvoidDiskWrites 1             # minimise forensic footprint on disk
FetchUselessDescriptors 0     # do not fetch relay descriptors we won't use (default, explicit)

# ── Guard-discovery protection ─────────────────────────────────────────────
# vanguards-lite (Tor proposal 333) pins a small set of layer-2 guards so an
# adversary cannot enumerate our position by forcing circuit rebuilds.  It is our
# primary in-Tor defence against guard discovery, and the full Vanguards addon's
# layer-2/3 pinning is NOT running alongside it (see --disable_vanguards below).
#
# Why the addon's pinning is off: it applies its guard sets via SETCONF, and with
# the sandbox enabled EVERY SETCONF fails -- not just guard options.  SETCONF trips
# a full config re-validation, which re-reads the hidden-service directory, which
# the sandbox forbids ("Directory ... cannot be read: Operation not permitted").
# The error surfaces as "Failed to configure rendezvous options" only because that
# is the first check to fail; guard options were never the cause.  Confirmed by
# observing MaxCircuitDirtiness, NewCircuitPeriod and SafeLogging fail identically.
#
# Be honest about what this costs.  Proposal 333 states that vanguards-lite adds
# NO third guard layer, pins only 4 layer-2 guards, makes guard discovery EASIER
# than the full addon, and that long-lived high-risk services relying on it alone
# "might provide those services with a false sense of security" -- such services
# "should still use the vanguards addon".  This deployment is exactly that case.
# Static layer-2/3 node pins written straight into this torrc (no SETCONF) have
# been shown to work with the sandbox enabled, but static pins do not rotate, and
# rotation is the addon's actual design, so that is not a drop-in replacement.
#
# Keep prose in this block free of literal "<Directive> <value>" strings: the
# generated torrc is verified by raw substring matching, so a comment that spells
# one out is indistinguishable from a real config line to those checks.
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
    seen_names = {}   # service name -> the env var that first claimed it
    hs_dirs = []
    for env_var in sorted(os.environ):          # sorted for deterministic torrc output
        if not env_var.endswith('_TOR_SERVICE_HOSTS'):
            continue

        service_hosts = os.environ[env_var]
        # Env var names and values can hold lone surrogates (surrogateescape
        # decoding of non-UTF-8 bytes). Printing or writing one raises
        # UnicodeEncodeError, which aborts startup -- found by libFuzzer. Escape
        # them once and use the safe forms in every message and reason.
        safe_env = _safe(env_var)
        safe_hosts = _safe(service_hosts)
        # Underscores are valid in env var names but not in service directory names;
        # convert them to hyphens so MY_APP_TOR_SERVICE_HOSTS → my-app.
        raw_name = env_var.replace('_TOR_SERVICE_HOSTS', '').lower().replace('_', '-')

        try:
            service_name = validate_service_name(raw_name)
        except ValueError as e:
            print(f"Skipping invalid service name from {safe_env}: {e}")
            if dropped is not None:
                dropped.append(f"{safe_env}: invalid service name: {e}")
            continue

        # Two env vars can collapse to the same service name: names are
        # lowercased and underscores become hyphens, so MYAPP_TOR_SERVICE_HOSTS,
        # myapp_TOR_SERVICE_HOSTS and MY_APP_TOR_SERVICE_HOSTS all yield the same
        # directory. Environment variable names are case-sensitive, so all of
        # these can be set at once.
        #
        # Emitting the block twice does NOT merge the two services: Tor rejects
        # the whole configuration with "Another hidden service is already
        # configured for directory ..." and refuses to start, taking down every
        # other onion in the container. Keep the first and skip the rest, which
        # matches how a service with no valid ports is handled.
        if service_name in seen_names:
            print(
                f"ERROR: {safe_env} maps to service '{service_name}', which is "
                f"already defined by {_safe(seen_names[service_name])} — skipping it. "
                "Service names are lowercased and underscores become hyphens, so "
                "names that differ only in case or in _ vs - collide. Rename one."
            )
            if dropped is not None:
                dropped.append(
                    f"{safe_env}: service name '{service_name}' collides with "
                    f"{_safe(seen_names[service_name])}")
            continue
        seen_names[service_name] = env_var

        print(f"Configuring hidden service: {service_name}")
        print(f"Service hosts: {safe_hosts}")

        hs_dir = f"{KEYS_ROOT}/{service_name}"

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
                if host_mapping.strip() and dropped is not None:
                    dropped.append(
                        f"{safe_env}: malformed mapping '{_safe(host_mapping.strip())}'")
                continue
            parts = host_mapping.strip().split(':')
            try:
                if len(parts) == 3:
                    hs_port     = validate_port(parts[0],     host_mapping)
                    target_host = validate_hostname(parts[1], host_mapping)
                    backend_name = target_host
                    target_host = resolve_to_ip(target_host,  host_mapping)
                    if resolved is not None and backend_name != target_host:
                        resolved[backend_name] = target_host
                    target_port = validate_port(parts[2],     host_mapping)
                    port_lines.append(f"HiddenServicePort {hs_port} {target_host}:{target_port}\n")
                elif len(parts) == 2:
                    hs_port     = validate_port(parts[0], host_mapping)
                    target_port = validate_port(parts[1], host_mapping)
                    port_lines.append(f"HiddenServicePort {hs_port} 127.0.0.1:{target_port}\n")
                else:
                    print(f"Skipping malformed mapping: '{_safe(host_mapping)}'")
                    if dropped is not None:
                        dropped.append(
                            f"{safe_env}: malformed mapping '{_safe(host_mapping.strip())}'")
            except ValueError as e:
                print(f"Skipping invalid mapping '{_safe(host_mapping)}': {e}")
                if dropped is not None:
                    dropped.append(
                        f"{safe_env}: invalid mapping '{_safe(host_mapping.strip())}': {e}")

        if not port_lines:
            # Drop the service entirely rather than emit a portless block that
            # would abort Tor's startup and take every other service with it.
            print(
                f"ERROR: service '{service_name}' has no valid port mappings "
                f"(from {safe_env}='{safe_hosts}') — skipping it. Tor cannot "
                "start a hidden service with no ports, so emitting it would "
                "take down every other service too. Fix this mapping."
            )
            if dropped is not None:
                dropped.append(
                    f"{safe_env}: no valid port mappings; service dropped")
            continue

        torrc_content += service_block + "".join(port_lines)
        hs_dirs.append(hs_dir)
        found_any = True

    if not found_any:
        print("Warning: no *_TOR_SERVICE_HOSTS env vars found — "
              "Tor will start but no hidden services will be configured.")

    return torrc_content, hs_dirs


def _secure_service_dir(path):
    """Make a service directory exactly 0700, whoever created it, or say why not.

    Tor refuses a HiddenServiceDir anyone else can read ("Permissions on
    directory ... are too permissive") and does not start. The old guard only
    chmod'ed a directory root owned, so one the operator created -- the README's
    own offline-key steps do that -- kept its umask mode (0775): measured, Tor
    refused it and the container restart-looped with the reason in a log the
    shipped compose file discards. The chmod is done on an O_NOFOLLOW
    descriptor, so it cannot land on a symlink's target. Where it is not
    permitted (no FOWNER, and not the owner) this stops with the fix instead.
    """
    fd = _open_dir_nofollow(path)
    try:
        st = os.fstat(fd)
        mode = stat.S_IMODE(st.st_mode)
        if mode == 0o700:
            return
        try:
            os.fchmod(fd, 0o700)
        except PermissionError as exc:
            raise PermissionError(
                errno.EPERM,
                f"{path} is mode {oct(mode)}, which Tor refuses, and it cannot be "
                f"set to 0700 here (it belongs to uid {st.st_uid} and the runtime "
                "grants no FOWNER). Run `chmod 700` on it on the host.") from exc
    finally:
        os.close(fd)


def _prepare_hs_dir(hs_dir, tor_pw):
    """Create and secure one hidden-service directory: chmod first, then chown.

    The ordering is load-bearing. ``Path.mkdir(exist_ok=True)`` succeeds if
    hs_dir is a symlink to a directory, so the O_NOFOLLOW chmod is what actually
    rejects a tampered key volume before the recursive chown runs. This is split
    out of generate_basic_torrc so the ordering can be tested BEHAVIOURALLY: a
    test that read the source text passed in CI but broke mutation testing,
    because mutmut replaces the function body with a trampoline and the source
    no longer contains the call.
    """
    # Named before anything else touches it: mkdir(exist_ok=True) would pass
    # through a symlink, and the old failure for a link or a file here was a
    # bare "[Errno 17] File exists" that told the operator nothing.
    try:
        st = os.lstat(hs_dir)
    except FileNotFoundError:
        st = None
    if st is not None and not stat.S_ISDIR(st.st_mode):
        kind = "a symlink" if stat.S_ISLNK(st.st_mode) else "not a directory"
        raise RuntimeError(
            f"{hs_dir} in the key volume is {kind}; refusing to use it as a service "
            "directory. Replace it with the real directory (restore it from a backup).")
    Path(hs_dir).mkdir(parents=True, exist_ok=True)
    # 0700 first, then hand the tree to tor. Always chown so newly-created dirs
    # transfer to the tor user regardless of the calling uid.
    try:
        _secure_service_dir(hs_dir)
        _chown_r(hs_dir, tor_pw.pw_uid, tor_pw.pw_gid)
    except PermissionError:
        # Second and later starts under rootless Podman, as podman-compose.yml
        # ships it: root there has no DAC_OVERRIDE, so it cannot open a
        # directory a previous start handed to the tor user (0700). Measured:
        # every restart failed "Permission denied" here and the container
        # restart-looped, silently, under `logging: driver: none`.
        #
        # A directory that is already the tor user's and closed to everyone
        # else is exactly the state this function exists to produce, so there
        # is nothing to do. lstat needs no access to the directory's contents,
        # and it sees a symlink as a symlink, so a planted link is not excused:
        # anything but a real directory, owned by tor, mode 0700 or tighter,
        # still fails.
        st = os.lstat(hs_dir)
        if not (stat.S_ISDIR(st.st_mode) and st.st_uid == tor_pw.pw_uid
                and stat.S_IMODE(st.st_mode) & 0o077 == 0):
            raise
        print(f"{_safe(hs_dir)} is already the tor user's (prepared by a previous "
              "start); nothing to change.")


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
    parent_hs = Path(KEYS_ROOT)
    if parent_hs.exists():
        # 0o751 is the minimum that works: Tor (uid 100) is "other" relative to
        # this root-owned bind mount and must be able to traverse it. The
        # alternative, chowning the operator's host directory to uid 100, is more
        # surprising and no more secure. Keys stay in 0700 subdirectories.
        _chmod_dir_nofollow(parent_hs, 0o751)  # nosec B103

    dropped = []
    _backend_ips.clear()
    torrc_content, hs_dirs = build_torrc_string(dropped=dropped, resolved=_backend_ips)

    tor_pw = pwd.getpwnam('tor')
    for hs_dir in hs_dirs:
        _prepare_hs_dir(hs_dir, tor_pw)

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
    torrc_fd = os.open(
        TORRC_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640
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

    print(f"Generated Tor configuration at {TORRC_PATH}")
    return hs_dirs, dropped


def _write_dropped_mappings(reasons, tor_pw):
    """Record skipped/dropped mappings so `hiddenforge status` can surface them.

    Mirrors i2pforge's /var/lib/i2pd/dropped-mappings. Lives in the
    DataDirectory (a tmpfs, not the key volume), owned by tor, mode 0600, and is
    removed when there is nothing to report so a stale file cannot mislead.
    """
    path = Path(DROPPED_MAPPINGS)
    if not reasons:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            print(f"Warning: could not remove {DROPPED_MAPPINGS}: {exc}")
        return
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as fh:
            fh.write('\n'.join(reasons) + '\n')
            # The mode passed to os.open is a REQUEST: the kernel applies the
            # process umask to it, so 0o600 there guarantees "no more than 0600",
            # not "exactly 0600" -- and it silently does the right thing only
            # because every umask in use clears the bits we did not ask for.
            # This file records which services were refused and why; state it
            # outright, the way the torrc write and the address publisher already
            # do, rather than inheriting it from the runtime's umask.
            os.fchmod(fh.fileno(), 0o600)
            # fchown on the descriptor we just wrote, not lchown on the path.
            # A path-based chown re-resolves the name, so it is a second lookup
            # that can land on a different inode than the one O_NOFOLLOW opened;
            # the descriptor cannot be redirected. Same reasoning as the torrc
            # write in generate_basic_torrc and the fchmod in _publish_addresses.
            os.fchown(fh.fileno(), tor_pw.pw_uid, tor_pw.pw_gid)
        print(f"Recorded {len(reasons)} dropped mapping(s) in {DROPPED_MAPPINGS}")
    except OSError as exc:
        print(f"Warning: could not write {DROPPED_MAPPINGS}: {exc}")


HEALTHCHECK_BIN = '/usr/local/bin/healthcheck.py'


def _service_reachable():
    """True if Tor holds ESTABLISHED onion-service introduction circuits.

    Delegates to healthcheck.py instead of re-implementing the control-port query,
    so the image has exactly one definition of "reachable" and the address file can
    never disagree with the container's health status.

    Run through su-exec as the tor user, matching _control_socket_ready(): the
    control socket lives in a 0700 tor-owned DataDirectory owned by the tor user,
    so it is read by the user that owns it rather than by leaning on root's
    DAC_OVERRIDE.

    Fails closed. Any error -- socket missing, timeout, unparseable output --
    returns False, which withholds the address rather than publishing one that may
    not resolve.

    The child's EXIT CODE is deliberately ignored in favour of the one field this
    function is asking about. healthcheck.py exits non-zero for conditions that
    have nothing to do with whether clients can reach the service -- most notably a
    dead Vanguards addon, which exits 1 while `hidden_service_reachable` is
    perfectly true. Gating publication on the exit code would mean a container that
    lost Vanguards never published its address, which is a different and worse
    failure than the one this gate exists to prevent. Every exit code that does
    mean "not reachable" or "could not evaluate" already reports
    `hidden_service_reachable: false` in the same document, so reading the field is
    both narrower and stricter than reading the code.
    """
    try:
        proc = subprocess.run(
            ['su-exec', 'tor', 'python3', HEALTHCHECK_BIN, '--json'],
            capture_output=True, timeout=15, check=False,
        )
        doc = json.loads(proc.stdout.decode('utf-8', 'replace'))
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    if not isinstance(doc, dict):
        return False          # valid JSON, wrong shape -- still not an answer
    return doc.get('hidden_service_reachable') is True


ADDRESS_FILE_MAX = 256   # a v3 address line is 63 bytes; anything far larger is not one


def _read_small_regular_file(path, max_bytes=ADDRESS_FILE_MAX):
    """Read a small regular file without following, blocking on, or swallowing it.

    The supervisor reads two files per service once a second, as root, from the
    key volume -- which the threat model treats as untrusted. A plain
    read_bytes() there followed a symlink, BLOCKED FOR EVER on a FIFO (the
    supervision loop stopped: a dead Tor went unnoticed), and read a link to
    /dev/zero until MemoryError, which is not an OSError and killed PID 1.

    O_NOFOLLOW refuses the symlink, O_NONBLOCK makes opening a FIFO return at
    once, fstat on the descriptor refuses anything that is not a regular file,
    and the read is capped. Every failure is an OSError, which the caller
    already handles.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, f"{path} is not a regular file")
        data = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise OSError(errno.EFBIG, f"{path} is larger than {max_bytes} bytes")
    return data


GATE_RETRY_SECONDS = 10


class _ThrottledGate:
    """Ask the reachability gate at most once per GATE_RETRY_SECONDS after a no.

    _publish_addresses consults the gate on every one-second tick while an
    address is waiting, and each consultation starts a Python process under
    su-exec that opens a control connection. Measured: a new control connection
    about every second for the whole pre-publication window -- minutes on a
    slow network, and for ever on a broken one, inside a one-CPU container. A
    "no" is remembered for GATE_RETRY_SECONDS; a "yes" is never delayed.
    """

    def __init__(self, gate, retry=GATE_RETRY_SECONDS, clock=time.monotonic):
        self.gate, self.retry, self.clock = gate, retry, clock
        self._no_until = None

    def __call__(self):
        now = self.clock()
        if self._no_until is not None and now < self._no_until:
            return False
        if self.gate():
            self._no_until = None
            return True
        self._no_until = now + self.retry
        return False


_publish_warned: set[tuple[str, str, int]] = set()


def _warn_publish_once(name, action, exc):
    """Report a publication failure once per service, per error kind.

    _publish_addresses runs once a second, so an unconditional warning would
    produce 86,400 identical lines a day and bury the Tor log. Silence is worse:
    on rootless Podman the supervisor holds no CAP_DAC_OVERRIDE, so it cannot
    traverse the tor-owned 0700 DataDirectory that KEYS_ROOT lives inside, and
    every one of these calls failed with EACCES and said nothing at all. A
    healthy-looking container simply never grew its .onion file, with no clue
    anywhere as to why.

    ENOENT is excluded deliberately. Tor writes `hostname` at key-generation
    time, so a missing file is the ordinary state of affairs for the first few
    seconds of every container's life and is not a fault.
    """
    if exc.errno == errno.ENOENT:
        return
    key = (name, action.split()[0], exc.errno)
    if key in _publish_warned:
        return
    _publish_warned.add(key)
    print(f"Warning: cannot publish the .onion address for {name}: "
          f"{action} failed: {os.strerror(exc.errno)}. "
          f"The service itself is unaffected -- read the address with "
          f"'su-exec tor cat {KEYS_ROOT}/{name}/hostname' instead. "
          f"(Reported once; further identical failures are not repeated.)")


def _publish_addresses(hs_dirs, keys_root=KEYS_ROOT, gate=None):
    """Publish each service's .onion address as a readable file in the key volume.

    ``gate`` is an optional predicate that must return True before any address is
    written. It is evaluated lazily -- only when there is actually something new to
    publish -- so the steady-state cost of calling this once a second stays a
    56-byte read per service.

    The gate exists because writing the hostname file proves nothing about
    reachability: Tor creates it at key-generation time, before any descriptor
    reaches a directory. A container whose onion-service circuits could not build
    was observed publishing a valid-looking address, at bootstrap 100%, that no
    client could ever reach. Note that gating on bootstrap would NOT have caught
    that -- bootstrap was already at 100%. See _service_reachable().

    Tor writes ``hostname`` inside the 0700 service directory, which the host user
    cannot read once the entrypoint has chowned that directory to the ``tor``
    user.  We copy it to ``<keys_root>/<name>.onion`` (0644) so a consumer can
    discover the address straight from the mount, with no docker exec and no
    root, and without ever touching the secret key.

    The parent directory is 0751 (traverse, not list), so the address is readable
    only by a consumer that already knows the service name -- which is not
    sensitive.  Writes go through a same-directory temp file and os.replace, so a
    reader never sees a partial file and a symlink planted at the target is
    replaced, not followed.
    """
    root = Path(keys_root)

    # Collect first, write second. The gate is only consulted when there is
    # actually something new to publish, so the steady-state cost of being called
    # once a second stays a 56-byte read per service.
    pending = []
    for hs_dir in hs_dirs:
        name = Path(hs_dir).name
        try:
            raw = _read_small_regular_file(Path(hs_dir) / 'hostname')
        except OSError as exc:
            _warn_publish_once(name, 'read hostname', exc)
            continue
        # Decode STRICTLY. 'ignore' would delete any byte outside ASCII and then
        # match what was left, so a hostname file holding one stray byte beside a
        # valid address would publish an address that is not what the file says --
        # a sanitised answer to a question that should have been refused. A
        # non-ASCII byte in a file Tor wrote itself means the key volume is not in
        # the state we think it is. Skipping is the loud-enough failure: the
        # address simply never appears, and the operator can read the file.
        # (The decode is still guarded, not bare: an uncaught UnicodeDecodeError
        # here would kill the supervision loop that calls this once a second.)
        try:
            onion = raw.decode('ascii').strip()
        except UnicodeDecodeError:
            continue
        if not ONION_RE.fullmatch(onion):
            continue
        target = root / f'{name}.onion'
        try:
            if _read_small_regular_file(target).decode('ascii').strip() == onion:
                continue
        except (OSError, UnicodeDecodeError):
            # Unreadable or not ASCII: treat the published copy as absent and
            # rewrite it. A corrupted address file must not be left in place.
            pass
        pending.append((name, onion, target))

    if not pending:
        return
    if gate is not None and not gate():
        return

    for name, onion, target in pending:
        # A fresh, unguessable name created with O_EXCL. The old name was
        # predictable (`.<name>.onion.tmp.1`: the supervisor is PID 1) and opened
        # with O_TRUNC, and O_NOFOLLOW does not stop a HARDLINK: a key volume
        # arriving with that name hard-linked to hs_ed25519_secret_key had the
        # key truncated, overwritten with the address and fchmod'ed 0644 --
        # the identity destroyed and its file world-readable. O_EXCL creates a
        # new inode or fails; it never opens one that already exists.
        tmp = root / f'.{name}.onion.{secrets.token_hex(8)}.tmp'
        created = False
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            created = True
            with os.fdopen(fd, 'wb') as fh:
                fh.write(onion.encode('ascii') + b'\n')
                # fchmod, not chmod: chmod(tmp) re-resolves the name, so a
                # symlink planted between the open and the chmod would be
                # followed and have its target's mode changed -- exactly what
                # O_NOFOLLOW on the open was there to prevent. The descriptor
                # cannot be redirected, so it is the only safe subject.
                os.fchmod(fh.fileno(), 0o644)
            os.replace(tmp, target)
        except OSError as exc:
            # This loop is driven once a second from the supervision loop, which
            # does NOT wrap the call. An unhandled error here would take the
            # whole supervisor down over a convenience file.
            if created:           # only ever remove a temp this call made
                with contextlib.suppress(OSError):
                    tmp.unlink()
            _warn_publish_once(name, f'write {target}', exc)
            continue
        print(f"Published address for {name}: {onion}")


# ---------------------------------------------------------------------------
# Vanguards management
# ---------------------------------------------------------------------------

def _control_socket_ready():
    """True if Tor's control socket currently exists (non-blocking check)."""
    try:
        return subprocess.run(
            ['su-exec', 'tor', 'test', '-S', CONTROL_SOCKET],
            capture_output=True,
            check=False,
            timeout=10,
        ).returncode == 0
    except Exception:
        return False


def wait_for_socket(timeout=120, tor=None):
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
        if _control_socket_ready():
            break
        # A Tor that died at startup (a config it refused, a directory it
        # rejected) used to leave this waiting its full two minutes with the
        # container showing "running" over no Tor at all.
        if tor is not None and tor.poll() is not None:
            raise RuntimeError(f"Tor exited (code {tor.poll()}) before its control "
                               "socket appeared")
        if time.monotonic() - start > timeout:
            raise TimeoutError(
                f"Tor control socket not found after {timeout}s"
            )
        time.sleep(0.5)
    # Give Tor a moment to finish setting socket permissions.
    time.sleep(0.5)
    print("Control socket ready.")


_LINUX_CAPABILITY_VERSION_3 = 0x20080522

CAP_CHOWN        = 0
CAP_DAC_OVERRIDE = 1
CAP_FOWNER       = 3
CAP_SETGID       = 6
CAP_SETUID       = 7

# What the supervisor still needs once setup is finished, and nothing else.
#
#   DAC_OVERRIDE  /var/lib/tor is tor:tor 0700 and KEYS_ROOT lives inside it, so
#                 root cannot traverse into it to publish .onion files without
#                 this. _publish_addresses does exactly that once a second for
#                 the life of the container. Measured: dropping this turns every
#                 publish into EACCES, which would silently and permanently
#                 disable address publication - the same failure class the
#                 readiness gate was added to fix.
#   SETGID/SETUID su-exec, for the Vanguards restart budget and for the
#                 reachability gate's call into healthcheck.py.
#
# CHOWN and FOWNER are dropped: the last chown happens before Tor starts, and the
# code never chmods a file it does not already own (see _chmod_dir_nofollow).
POST_SETUP_CAPS = (1 << CAP_DAC_OVERRIDE) | (1 << CAP_SETGID) | (1 << CAP_SETUID)


class _CapHeader(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [('effective',   ctypes.c_uint32),
                ('permitted',   ctypes.c_uint32),
                ('inheritable', ctypes.c_uint32)]


_CAP_NAMES = {
    CAP_CHOWN: "CHOWN",
    CAP_DAC_OVERRIDE: "DAC_OVERRIDE",
    CAP_FOWNER: "FOWNER",
    CAP_SETGID: "SETGID",
    CAP_SETUID: "SETUID",
}


def _permitted_capabilities(libc):
    """The calling process's permitted capability set, or None if unreadable."""
    header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapData * 2)()
    if libc.capget(ctypes.byref(header), ctypes.byref(data)) != 0:
        return None
    return data[0].permitted | (data[1].permitted << 32)


def _drop_setup_capabilities(mask=POST_SETUP_CAPS):
    """Narrow the supervisor's capabilities to `mask`, permanently.

    Called once, after all ownership fixing is done and before Tor is started.
    Dropping from the PERMITTED set as well as the effective set is what makes it
    irreversible: a capability absent from permitted cannot be raised again.

    This shrinks the supervisor's window only. Tor itself already runs with no
    capabilities at all - su-exec's uid change clears the permitted and effective
    sets and the ambient set is empty - so this is defence in depth around the
    root process that outlives it, not a fix for an exposed Tor.

    The bounding set is deliberately left alone: PR_CAPBSET_DROP needs
    CAP_SETPCAP, which this container does not hold, and granting SETPCAP in order
    to drop two capabilities would be a net loss.

    Best effort. A kernel or runtime that refuses capset is a reason to log and
    carry on, not to refuse to serve: failing here would take down a container
    whose actual security posture is unchanged from the previous release.
    """
    libc = ctypes.CDLL('libc.so.6', use_errno=True)
    # capset REFUSES a permitted set that is not a subset of the current one, so
    # asking to keep a capability the runtime never granted fails the whole call
    # and drops NOTHING. Measured on the project's own podman-compose.yml, which
    # deliberately withholds DAC_OVERRIDE: the supervisor printed "could not drop
    # setup capabilities: Operation not permitted" and then kept CHOWN for the
    # life of the container, on the runtime the deployed instance actually uses.
    # Dropping what we can is strictly better than dropping nothing, so the
    # request is narrowed to what is held rather than sent whole and refused.
    held = _permitted_capabilities(libc)
    if held is not None:
        wanted = mask & held
        if wanted != mask:
            missing = [_CAP_NAMES.get(b, f"bit {b}")
                       for b in range(64) if (mask >> b) & 1 and not (held >> b) & 1]
            print(f"Note: this runtime did not grant {', '.join(missing)}; "
                  f"dropping everything else regardless.")
        mask = wanted
    header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapData * 2)()
    data[0].effective = data[0].permitted = mask & 0xFFFFFFFF
    data[0].inheritable = 0
    data[1].effective = data[1].permitted = data[1].inheritable = 0
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        err = ctypes.get_errno()
        print(f"Warning: could not drop setup capabilities: {os.strerror(err)}. "
              f"Continuing with the capabilities the runtime granted.")
        return False
    kept = ", ".join(_CAP_NAMES.get(b, f"bit {b}")
                     for b in range(64) if (mask >> b) & 1) or "nothing"
    print(f"Dropped setup capabilities; supervisor retains 0x{mask:02x} ({kept}).")
    return True


def _assert_can_drop_privileges():
    """Fail fast if su-exec cannot switch to the tor user.

    setuid() returns EAGAIN when the target uid is already at RLIMIT_NPROC.
    RLIMIT_NPROC is counted per HOST uid (containers share the host user
    namespace unless userns-remap is configured), and the tor user is uid 100 --
    shared with other containers such as i2pforge's i2pd. A compose file that
    sets a low ``ulimits.nproc`` therefore stops Tor from starting, and with
    ``logging: driver: none`` the only symptom is a silent restart loop. One
    probe turns that into a named error.
    """
    result = subprocess.run(
        ['su-exec', 'tor', 'true'], capture_output=True, check=False, timeout=10
    )
    if result.returncode != 0:
        detail = (result.stderr or b'').decode(errors='replace').strip()
        raise RuntimeError(
            "cannot switch to the tor user: "
            f"{detail or 'su-exec failed'}. If this deployment sets a low "
            "`ulimits.nproc`, remove it: RLIMIT_NPROC is counted per host uid, "
            "and uid 100 is shared with other containers (i2pforge's i2pd is "
            "also uid 100). Use `pids_limit` for process containment instead."
        )


def _uid_from_status(status_text):
    """The real uid from a /proc/<pid>/status body, or None."""
    match = re.search(r'^Uid:\s+(\d+)', status_text, re.M)
    return int(match.group(1)) if match else None


def _name_from_status(status_text):
    """The process name (comm) from a /proc/<pid>/status body, or None."""
    match = re.search(r'^Name:\s+(\S+)', status_text, re.M)
    return match.group(1) if match else None


def _assert_process_dropped(proc, name, timeout=5):
    """Confirm a child process is NOT running as root.

    The whole design rests on su-exec dropping to the tor user; a drop that
    silently fails would leave Tor (and Vanguards) running as root, which is
    strictly worse than never attempting one. Read the child's real uid from
    /proc and refuse to continue if it is still 0.

    The child is su-exec until it execs the target, and su-exec is root until it
    calls setuid() -- which is its job. Uid 0 while the process is still named
    `su-exec` is therefore "not yet", not "failed". Treating it as failed killed
    the container on a race: measured in the image, a read straight after Popen
    saw `su-exec` at uid 0 in 294 of 300 tries, and 4 of 16 concurrent rootless
    starts died with a false "Tor is running as root". A su-exec that never gets
    past setuid() exits, so waiting on it still ends in a refusal at the deadline.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status = Path(f'/proc/{proc.pid}/status').read_text(encoding='ascii')
        except OSError:
            time.sleep(0.1)
            continue
        uid = _uid_from_status(status)
        if uid == 0 and _name_from_status(status) == 'su-exec':
            time.sleep(0.01)
            continue
        if uid is not None:
            if uid == 0:
                print(f"FATAL: {name} (pid {proc.pid}) is running as root; the "
                      "privilege drop to the tor user failed. Refusing to continue.")
                return False
            return True
        time.sleep(0.1)
    print(f"FATAL: could not confirm {name} dropped privileges within {timeout}s.")
    return False


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
    # Long-lived by design (runs alongside Tor for the container's lifetime), so
    # it deliberately has no timeout; the supervisor watches it via poll().
    return subprocess.Popen(['su-exec', 'tor', *cmd])


# ---------------------------------------------------------------------------
# Backend moves
# ---------------------------------------------------------------------------

# name -> IP written into the torrc, for every backend given by name. Filled by
# generate_basic_torrc; read by the supervisor's _BackendWatch.
_backend_ips: dict[str, str] = {}

BACKEND_RECHECK_SECONDS = 30
BACKEND_MOVE_CONFIRMATIONS = 2


class _BackendWatch:
    """Notice when a backend name stops pointing where the torrc sends traffic.

    Names are resolved once, at start, into the torrc: Tor accepts only IPs in
    HiddenServicePort. A backend container that is recreated usually comes back
    on a different IP, and from then on the onion forwards every request to an
    address nobody listens on -- while the healthcheck stays green, because the
    introduction points are fine. The README used to tell the operator to
    restart by hand after every backend recreation; nobody should have to.

    A move is declared only on evidence: the recorded IP must be absent from
    ALL the addresses a SUCCESSFUL lookup returns (a scaled service answers with
    several, in any order), on BACKEND_MOVE_CONFIRMATIONS lookups in a row. A
    failed lookup -- the backend down, DNS briefly unavailable -- is not
    evidence and resets the count, so this cannot restart the container over a
    blip. Resolution runs on its own thread so a slow resolver never stalls the
    supervision loop.
    """

    def __init__(self, recorded, resolver=socket.gethostbyname_ex,
                 interval=BACKEND_RECHECK_SECONDS):
        self.recorded = dict(recorded)
        self.resolver = resolver
        self.interval = interval
        self.misses = dict.fromkeys(self.recorded, 0)
        self.moved = None           # (name, old_ip, [current ips]) once confirmed
        self._stop = threading.Event()

    def check_once(self):
        """One round of lookups; returns self.moved."""
        for name, old in self.recorded.items():
            try:
                _, _, addrs = self.resolver(name)
            except (OSError, UnicodeError):
                self.misses[name] = 0
                continue
            current = set()
            for a in addrs:
                try:
                    current.add(str(ipaddress.IPv4Address(a)))
                except (ipaddress.AddressValueError, ValueError):
                    continue
            if not current or old in current:
                self.misses[name] = 0
                continue
            self.misses[name] += 1
            if self.misses[name] >= BACKEND_MOVE_CONFIRMATIONS:
                self.moved = (name, old, sorted(current))
                break
        return self.moved

    def run(self):
        while not self._stop.wait(self.interval):
            if self.check_once():
                return

    def start(self):
        if self.recorded:
            threading.Thread(target=self.run, name="backend-watch", daemon=True).start()
        return self


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _tor_process, _vanguards_process

    # A lone surrogate (from a non-UTF-8 environment value or path) makes the
    # default UTF-8 stdout raise UnicodeEncodeError and would abort startup. The
    # fuzz target found that via a log line; _safe() escapes the values we know
    # about, and this backslash-escapes anything we did not think of.
    for _stream in (sys.stdout, sys.stderr):
        if hasattr(_stream, "reconfigure"):
            _stream.reconfigure(errors="backslashreplace")

    # In-image operator CLI: `docker run <image> show|vanity|doctor|...` runs the
    # hiddenforge CLI instead of starting Tor. Unknown args fall through to a
    # normal boot (Docker may pass a stray arg; we must not brick the container).
    dispatched = dispatch_subcommand(sys.argv[1:])
    if dispatched is not None:
        sys.exit(dispatched)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT,  signal_handler)

    tor_pw = pwd.getpwnam('tor')

    # Fail loudly if we cannot drop to the tor user, rather than looping on a Tor
    # that never starts (see _assert_can_drop_privileges).
    try:
        _assert_can_drop_privileges()
    except RuntimeError as e:
        print(f"FATAL: {e}")
        sys.exit(1)

    # ── Generate torrc ──────────────────────────────────────────────────────
    try:
        print("Generating Tor configuration...")
        hs_dirs, dropped = generate_basic_torrc()
        print("Tor configuration generated successfully.")
    except Exception as e:
        print(f"Error generating configuration: {e}")
        sys.exit(1)

    # torrc ownership is set by fchown on the write descriptor inside
    # generate_basic_torrc(); doing it again here by PATH would reopen the
    # symlink race that descriptor exists to close.

    # Record skipped/dropped mappings BEFORE /var/lib/tor is handed to the tor
    # user. Under rootless Podman container root has no DAC_OVERRIDE, so once the
    # directory is tor-owned 0700 it can no longer write there at all; writing it
    # afterwards silently failed and the status feature was dead on the exact
    # runtime the project recommends for high-risk deployments.
    _write_dropped_mappings(dropped, tor_pw)

    # ── Fix DataDirectory ownership ─────────────────────────────────────────
    # Docker's tmpfs uid=/gid= mount options pre-set ownership at mount time,
    # but Podman does not support those options.  We explicitly chown the
    # DataDirectory here so the same image works under both runtimes.
    #
    # This must happen AFTER generate_basic_torrc() creates hidden_service
    # subdirs: once /var/lib/tor is owned by the tor user (mode 0700), root
    # without CAP_DAC_OVERRIDE cannot traverse into it.
    data_dir = Path(DATA_DIR)
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

    # ── Give up the capabilities setup needed ───────────────────────────────
    # Everything that required CAP_CHOWN or CAP_FOWNER has now happened. Nothing
    # below this line, and nothing in the supervision loop, needs either of them
    # again, so drop them before starting any long-lived process. This must come
    # after the chown above and before Tor is spawned.
    _drop_setup_capabilities()

    # ── Start Tor ───────────────────────────────────────────────────────────
    print("Starting Tor...")
    # Long-lived by design: Tor is the primary process, not a bounded command.
    _tor_process = subprocess.Popen(
        ['su-exec', 'tor', 'tor', '-f', '/etc/tor/torrc']
    )
    # Verify the drop actually happened before trusting the process with the
    # onion key. A silent failure here would run Tor as root.
    if not _assert_process_dropped(_tor_process, 'Tor'):
        _kill_proc(_tor_process, 'Tor', timeout=5)
        sys.exit(1)

    # ── Start Vanguards once the control socket exists ──────────────────────
    # If it cannot start yet (socket slow, transient failure) the supervision
    # loop below keeps retrying with a bounded budget instead of leaving the
    # addon permanently absent after a single unlucky start.
    vanguards_restarts    = 0
    vanguards_last_start  = 0.0
    vanguards_next_attempt = 0.0
    vanguards_given_up    = False
    try:
        wait_for_socket(timeout=120, tor=_tor_process)
        _vanguards_process   = start_vanguards()
        vanguards_last_start = time.monotonic()
        print("Vanguards addon started.")
    except TimeoutError as e:
        print(f"Warning: {e}. Will keep retrying Vanguards.")
    except Exception as e:
        print(f"Warning: could not start Vanguards: {e}. Will keep retrying.")

    # Watch the backends' names from here on (see _BackendWatch).
    backend_watch = _BackendWatch(_backend_ips).start()
    publication_gate = _ThrottledGate(_service_reachable)

    # ── Process supervision loop ────────────────────────────────────────────
    while True:
        time.sleep(1)

        # Republish the .onion address file(s) once the service is actually
        # reachable -- NOT merely once Tor has written hostname, which it does at
        # key-generation time. Cheap: a 56-byte read per service, skipped once
        # already correct, and the gate only runs when a write is pending.
        _publish_addresses(hs_dirs, gate=publication_gate)

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

        # A backend that moved means every request is going to an address
        # nobody listens on. Exit non-zero so the restart policy starts the
        # container again and resolution runs afresh; the onion address is
        # unaffected, it lives in the key volume.
        if backend_watch.moved:
            name, old, current = backend_watch.moved
            print(f"Backend '{_safe(name)}' now resolves to {', '.join(current)}, "
                  f"but Tor is still forwarding to {old}. Restarting so the onion "
                  "follows it (the address itself does not change).")
            _kill_proc(_vanguards_process, "Vanguards", timeout=5)
            _kill_proc(_tor_process, "Tor", timeout=10)
            sys.exit(1)

        now = time.monotonic()

        # Detect a Vanguards exit and decide whether to retry.
        if _vanguards_process is not None:
            vg_rc = _vanguards_process.poll()
            if vg_rc is not None:
                _vanguards_process = None
                # Reset the budget if the addon ran healthily for a while.
                if now - vanguards_last_start > 60:
                    vanguards_restarts = 0
                vanguards_restarts += 1
                if vanguards_restarts > VANGUARDS_MAX_RESTARTS:
                    print(
                        f"Vanguards exited (code {vg_rc}) too many times "
                        "in quick succession — disabling addon."
                    )
                    vanguards_given_up = True
                else:
                    print(
                        f"Vanguards exited (code {vg_rc}), retrying in "
                        f"{VANGUARDS_RETRY_DELAY}s "
                        f"(attempt {vanguards_restarts}/{VANGUARDS_MAX_RESTARTS})..."
                    )
                    vanguards_next_attempt = now + VANGUARDS_RETRY_DELAY

        # (Re)start Vanguards when it is missing, if the socket is up and we
        # have budget left. A missing control socket is Tor still bootstrapping,
        # so it does not consume the restart budget.
        if (not vanguards_given_up and _vanguards_process is None
                and now >= vanguards_next_attempt):
            if not _control_socket_ready():
                vanguards_next_attempt = now + VANGUARDS_RETRY_DELAY
            else:
                try:
                    _vanguards_process = start_vanguards()
                    vanguards_last_start = now
                    vanguards_next_attempt = 0.0
                    print("Vanguards addon started.")
                except Exception as e:
                    vanguards_restarts += 1
                    print(f"Could not start Vanguards: {e}")
                    if vanguards_restarts > VANGUARDS_MAX_RESTARTS:
                        print("Vanguards could not be started — disabling addon.")
                        vanguards_given_up = True
                    else:
                        vanguards_next_attempt = now + VANGUARDS_RETRY_DELAY


if __name__ == '__main__':
    main()
