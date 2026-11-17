#!/bin/bash
# Run, against a running, healthy container, every in-container command that
# earlier compose files, deploy scripts, documentation and CLIs used (mined
# from v2.0.0..v3.0.0), and check each one's outcome:
#   - the healthcheck that existing compose files declare still passes;
#   - every other old command is refused (the image has no shell, Python,
#     cat, test or su-exec to run it);
#   - the native commands that replace them all work.
#   compat_replay.sh <container> <service-name>
# Exits 1 if any command's outcome differs from the expected one.
set -u
C=$1; N=$2
KS=/var/lib/tor/hidden_service
fail=0
# expect <ok|refused> <command...>
expect() {
  local want=$1; shift
  local out rc got
  out=$(docker exec "$C" "$@" 2>&1); rc=$?
  if [ "$rc" -eq 0 ]; then got=ok; else got=refused; fi
  [ "$got" = "$want" ] || fail=1
  printf '%s\t%s\t%s\t%s\n' "$([ "$got" = "$want" ] && echo PASS || echo FAIL)" "$rc" "$*" \
    "$(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
}

# The one old command kept: compose files on operators' hosts declare it.
expect ok      su-exec tor python3 /usr/local/bin/healthcheck.py
expect ok      su-exec tor python3 /usr/local/bin/healthcheck.py --json

# Everything else from earlier releases is gone.
expect refused python3 /usr/local/bin/healthcheck.py --json
expect refused /usr/local/bin/entrypoint.py version
expect refused su-exec tor true
expect refused su-exec tor test -S /var/lib/tor/control.sock
expect refused su-exec tor cat "$KS/$N/hostname"
expect refused cat "$KS/$N/hostname"
expect refused cat /etc/tor/torrc
expect refused su-exec tor tor --verify-config -f /etc/tor/torrc
expect refused su-exec tor hiddenforge doctor --keys-only --json
expect refused sh -c 'echo hi'

# Their native replacements.
expect ok      hiddenforge healthcheck
expect ok      hiddenforge healthcheck --json
expect ok      hiddenforge show --name "$N"
expect ok      hiddenforge show --name "$N" --json
expect ok      hiddenforge doctor --keys-only
expect ok      hiddenforge doctor --keys-only --json
expect ok      hiddenforge inspect --json
expect ok      hiddenforge version --json
expect ok      hiddenforge info --json
exit "$fail"
