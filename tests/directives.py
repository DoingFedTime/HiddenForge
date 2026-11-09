"""Single source of truth for the torrc directive whitelist.

Used by tests/test_torrc_gen.py (golden + presence tests). Keeping the list in
one module means adding a directive to the generator updates every test that
checks it, instead of drifting silently.
"""

# Every directive token that may legitimately begin a non-comment torrc line.
ALLOWED_DIRECTIVES = {
    "ControlSocket", "SocksPort", "DataDirectory", "ClientOnly", "ExitPolicy",
    "Log", "SafeLogging", "HeartbeatPeriod", "Sandbox",
    "DisableDebuggerAttachment", "NoExec", "AvoidDiskWrites",
    "FetchUselessDescriptors",
    "VanguardsLiteEnabled",
    "HiddenServiceDir", "HiddenServiceVersion", "HiddenServiceNumIntroductionPoints",
    "HiddenServiceMaxStreams", "HiddenServiceMaxStreamsCloseCircuit",
    "HiddenServicePoWDefensesEnabled", "HiddenServicePoWQueueRate",
    "HiddenServicePoWQueueBurst", "HiddenServicePort",
    "HiddenServiceEnableIntroDoSDefense", "HiddenServiceEnableIntroDoSRatePerSec",
    "HiddenServiceEnableIntroDoSBurstPerSec",
}
