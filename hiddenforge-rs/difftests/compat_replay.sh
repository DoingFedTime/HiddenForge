#!/bin/bash
# Replay every in-container command that 2.x compose files, deploy scripts,
# documentation and CLIs ran (mined from v2.0.0..v2.1.6) against a running
# container, and print rc + output for each, so a 2.1.6 and a 3.0 container
# can be compared side by side.
#   compat_replay.sh <container> <service-name>
set -u
C=$1; N=$2
KS=/var/lib/tor/hidden_service
SCRIPT='echo "swap=$(cat /sys/fs/cgroup/memory.swap.max 2>/dev/null)"; echo "pids=$(cat /sys/fs/cgroup/pids.max 2>/dev/null)"; echo "capbnd=$(sed -n "s/^CapBnd:[[:space:]]*//p" /proc/1/status)"; echo "hostswap=$(tail -n +2 /proc/swaps 2>/dev/null | wc -l)"'
run() { local out rc; out=$(docker exec "$C" "$@" 2>/dev/null); rc=$?; printf '%s\t%s\t%s\n' "$rc" "$*" "$(printf '%s' "$out" | tr '\n' '|' | cut -c1-300)"; }
run su-exec tor python3 /usr/local/bin/healthcheck.py
run su-exec tor python3 /usr/local/bin/healthcheck.py --json
run python3 /usr/local/bin/healthcheck.py --json
run su-exec tor true
run su-exec tor test -S /var/lib/tor/control.sock
run su-exec tor cat $KS/$N/hostname
run cat $KS/$N/hostname
run su-exec tor cat /etc/tor/torrc
run cat /etc/tor/torrc
run su-exec tor cat /var/lib/tor/dropped-mappings
run su-exec tor tor --verify-config -f /etc/tor/torrc
run su-exec tor /usr/local/bin/hiddenforge doctor --keys-only --json
run su-exec tor hiddenforge doctor --keys-only --json
run hiddenforge doctor --keys-only
run su-exec tor hiddenforge show --name $N --json
run hiddenforge version --json
run hiddenforge info --json
run sh -c "$SCRIPT"
