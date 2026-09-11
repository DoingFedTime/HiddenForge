"""Single source of truth for the torrc directive whitelist.

Shared by tests/test_torrc_gen.py (golden + presence tests) and tests/test_fuzz.py
(the injection-proof property). Keeping one copy means adding a directive to the
generator updates both, instead of drifting silently.
"""

# Every directive token that may legitimately begin a non-comment torrc line.
ALLOWED_DIRECTIVES = {
    "ControlSocket", "SocksPort", "DataDirectory", "ClientOnly", "ExitPolicy",
    "Log", "SafeLogging", "HeartbeatPeriod", "Sandbox",
    "DisableDebuggerAttachment", "AvoidDiskWrites", "FetchUselessDescriptors",
    "VanguardsLiteEnabled",
    "HiddenServiceDir", "HiddenServiceVersion", "HiddenServiceNumIntroductionPoints",
    "HiddenServiceMaxStreams", "HiddenServiceMaxStreamsCloseCircuit",
    "HiddenServicePoWDefensesEnabled", "HiddenServicePoWQueueRate",
    "HiddenServicePoWQueueBurst", "HiddenServicePort",
    "HiddenServiceEnableIntroDoSDefense", "HiddenServiceEnableIntroDoSRatePerSec",
    "HiddenServiceEnableIntroDoSBurstPerSec",
}
