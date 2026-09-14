#!/usr/bin/env python3
"""
HiddenForge torrc generation tests.
Run inside the container: python3 /usr/local/bin/tests/test_torrc.py

NON-DESTRUCTIVE BY CONSTRUCTION.  This is safe to run against a LIVE container.

It used to call the privileged ``generate_basic_torrc()``, which overwrote the
running ``/etc/tor/torrc`` with this test's throwaway config and created a bogus
``service`` hidden-service directory inside the operator's persistent key
volume — so following the instruction in this very docstring could take down a
live onion service and litter the key volume with keys for a service nobody
asked for.  It now exercises the pure ``build_torrc_string()`` instead, which
performs no filesystem side effects at all.  ``build_torrc_string()`` produces
exactly the bytes that ``generate_basic_torrc()`` writes, so coverage is
unchanged.
"""
import sys
import os

sys.path.insert(0, '/usr/local/bin')

import subprocess as _sp
_orig_run = _sp.run
# This guard covers subprocess.run ONLY. entrypoint chowns through
# os.chown(..., follow_symlinks=False) (lchown), which is the property that
# actually matters and is asserted directly in tests/test_privileged_fs.py;
# Popen, check_call, check_output and os.system are not intercepted here. The
# printed line at the end says exactly that, so it does not claim more than it
# proves.
def _guarded_run(args, **kw):
    if 'chown' in str(args):
        raise AssertionError(f'subprocess chown called: {args}')
    return _orig_run(args, **kw)
_sp.run = _guarded_run  # type: ignore[assignment]  # test double for subprocess.run

# Mock DNS resolution so the test works without a live Docker network.
# backend → 192.0.2.1 (TEST-NET, RFC 5737 — not a real address)
import socket as _socket
_orig_gethostbyname = _socket.gethostbyname
def _mock_gethostbyname(host):
    if host == 'backend':
        return '192.0.2.1'
    return _orig_gethostbyname(host)
_socket.gethostbyname = _mock_gethostbyname

import entrypoint

# Deliberately NOT a name a real deployment would use, so the "did this test
# create anything?" assertion below can never collide with an operator's own
# service directory (including one left behind by the old destructive version).
os.environ['HIDDENFORGE_SELFTEST_TOR_SERVICE_HOSTS'] = '80:backend:8080,443:backend:8443'

# Pure generator: returns the torrc text and the list of hidden-service dirs it
# WOULD have created. Nothing is written, nothing is chowned, no directory is
# created — the live config and the key volume are untouched.
torrc, hs_dirs = entrypoint.build_torrc_string()

# Guard the property this test now depends on: our throwaway service must have
# been *named* only, never created on disk. (Any OTHER entries in hs_dirs belong
# to the operator's real services, which legitimately already exist on a live
# container — we must not assert anything about those.)
_selftest_dir = '/var/lib/tor/hidden_service/hiddenforge-selftest'
if _selftest_dir not in hs_dirs:
    print(f'FAILED: expected {_selftest_dir} to be planned, got {hs_dirs}')
    sys.exit(1)
if os.path.exists(_selftest_dir):
    print(f'FAILED: test created a real hidden-service directory at {_selftest_dir} '
          '— the generator is no longer side-effect free')
    sys.exit(1)

checks = [
    ('ClientOnly 1',                   'ClientOnly 1 missing — container could become a relay'),
    ('ExitPolicy reject',              'ExitPolicy missing — container could exit traffic'),
    ('Sandbox',                        'Sandbox directive missing'),
    ('VanguardsLiteEnabled 1',         'VanguardsLiteEnabled not pinned to 1 — guard-discovery '
                                       'defence would fall back to consensus control'),
    ('HiddenServicePoWDefensesEnabled','PoW DoS defense missing'),
    ('FetchUselessDescriptors 0',      'FetchUselessDescriptors missing'),
    ('SafeLogging 1',                  'SafeLogging missing — logs may expose .onion addresses'),
    ('AvoidDiskWrites 1',              'AvoidDiskWrites missing'),
    ('DisableDebuggerAttachment 1',    'DisableDebuggerAttachment missing'),
    ('HiddenServiceDir',               'No HiddenServiceDir — service not configured'),
    ('HiddenServiceVersion 3',         'HiddenServiceVersion 3 missing'),
    ('HiddenServiceNumIntroductionPoints', 'NumIntroductionPoints missing'),
    ('HiddenServicePoWQueueRate',      'PoW queue rate missing'),
    ('HiddenServicePort 80 192.0.2.1:8080',  'Port 80 mapping missing or wrong'),
    ('HiddenServicePort 443 192.0.2.1:8443', 'Port 443 mapping missing or wrong'),
    ('ControlSocket',                  'ControlSocket missing — Vanguards cannot connect'),
    ('SocksPort 0',                    'SocksPort should be 0 — no SOCKS exposure'),
]

failed = []
for check, message in checks:
    if check not in torrc:
        failed.append(message)

if failed:
    print('FAILED:')
    for f in failed:
        print(f'  - {f}')
    print('\n--- generated torrc ---')
    print(torrc)
    sys.exit(1)

# Verify chown was never shelled out
print(f'All {len(checks)} torrc checks passed.')
print('subprocess.run chown: not called (this guard covers subprocess.run only)')
