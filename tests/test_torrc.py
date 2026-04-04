#!/usr/bin/env python3
"""
HiddenForge torrc generation tests.
Run inside the container: python3 /usr/local/bin/tests/test_torrc.py
"""
import sys
import os

sys.path.insert(0, '/usr/local/bin')

import subprocess as _sp
_orig_run = _sp.run
def _guarded_run(args, **kw):
    if 'chown' in str(args):
        raise AssertionError(f'subprocess chown called: {args}')
    return _orig_run(args, **kw)
_sp.run = _guarded_run

import entrypoint

os.environ['SERVICE_TOR_SERVICE_HOSTS'] = '80:backend:8080,443:backend:8443'
entrypoint.generate_basic_torrc()

torrc = open('/etc/tor/torrc').read()

checks = [
    ('ClientOnly 1',                   'ClientOnly 1 missing — container could become a relay'),
    ('ExitPolicy reject',              'ExitPolicy missing — container could exit traffic'),
    ('Sandbox',                        'Sandbox directive missing'),
    ('HiddenServicePoWDefensesEnabled','PoW DoS defense missing'),
    ('FetchUselessDescriptors 0',      'FetchUselessDescriptors missing'),
    ('SafeLogging 1',                  'SafeLogging missing — logs may expose .onion addresses'),
    ('AvoidDiskWrites 1',              'AvoidDiskWrites missing'),
    ('DisableDebuggerAttachment 1',    'DisableDebuggerAttachment missing'),
    ('HiddenServiceDir',               'No HiddenServiceDir — service not configured'),
    ('HiddenServiceVersion 3',         'HiddenServiceVersion 3 missing'),
    ('HiddenServiceNumIntroductionPoints', 'NumIntroductionPoints missing'),
    ('HiddenServicePoWQueueRate',      'PoW queue rate missing'),
    ('HiddenServicePort 80 backend:8080', 'Port 80 mapping missing or wrong'),
    ('HiddenServicePort 443 backend:8443','Port 443 mapping missing or wrong'),
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
print('subprocess chown: not called (good)')
