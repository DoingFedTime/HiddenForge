# What Is Vanguards

HiddenForge runs the Vanguards addon alongside Tor.

---

## The problem Vanguards solves

Running a Tor hidden service exposes you to a class of attacks called **guard discovery attacks**. The goal of these attacks is to learn the IP address of the server running the hidden service.

Tor protects your IP by routing traffic through a chain of relays before it reaches the Tor network. The first relay in that chain, your **guard relay**, is the only relay that sees your real IP address. Every other relay only sees the previous hop.

If an attacker can figure out which guard relay you're using, they can watch that relay's traffic and eventually de-anonymise your server. Hidden services are particularly vulnerable because:

- Introduction points and rendezvous points are chosen from the full relay pool every time a client connects
- An adversary who runs enough relays can manipulate which relays get chosen
- Over time, patterns in circuit construction leak information about which guard you're using

---

## What Vanguards does

Vanguards restricts which relays can be used for different positions in hidden service circuits. Instead of choosing randomly from the full relay pool, it maintains small fixed sets of relays for each layer and rotates them slowly.

The full Vanguards addon provides two protection modules:

**Bandguards** monitors your Tor connection for bandwidth side-channel attacks. Some attacks work by watching how much data flows through specific relays at specific times. Bandguards detects anomalous bandwidth patterns and tears down suspicious circuits before an attacker can complete the correlation.

**Rendguard** watches which relays are being used as rendezvous points across connections. If one relay is being selected far more often than it should be by chance, that's a sign an adversary is trying to force your hidden service to build circuits through relays they control. Rendguard detects this and rejects the suspicious rendezvous points.

---

## Tor's built-in vanguards-lite

Tor 0.4.7+ includes a simplified version of the guard-layer rotation called vanguards-lite, which is always active. HiddenForge has this automatically, it's in the Tor binary itself.

The full Vanguards addon runs on top of vanguards-lite and adds the active monitoring (bandguards + rendguard). HiddenForge runs both.

---

## How HiddenForge runs Vanguards

The entrypoint starts Vanguards with one non-default flag: `--disable_vanguards`. The flag disables only the guard-layer rotation inside Vanguards, because that function uses a Tor control command (`SETCONF NumEntryGuards`) that Tor's `Sandbox 1` blocks. Since vanguards-lite already handles guard-layer rotation inside the Tor process itself, this is the correct tradeoff: you get bandguards and rendguard from the addon, guard rotation from the built-in vanguards-lite, and Sandbox 1 stays active.

Vanguards runs as the `tor` user via `su-exec`, not as root. It communicates with Tor over a Unix control socket at `/var/lib/tor/control.sock`. The socket is only accessible inside the container.

---

## Known limitation: L2-only guard protection (read this)

Be precise about what you actually get, because the difference matters for a
**long-lived** service:

- Tor's built-in **vanguards-lite** pins only the **second-layer (L2)** guards.
  It uses **no third layer (L3)**, does not persist its guard set to disk
  (topology resets on restart), and, per Tor's own design proposal (prop 333)
 , is explicitly intended for **short-lived** services (uptime up to ~1 month,
  e.g. OnionShare). The proposal states that long-lived services are *not* well
  protected by vanguards-lite alone and should run the full addon's guard layer.
- The full Vanguards addon's guard-layer component (which would add **L3** guards
  and a longer-lived, disk-persisted L2 set) is the part HiddenForge disables
  with `--disable_vanguards`, because enabling it requires a runtime `SETCONF`
  that Tor's `Sandbox 1` blocks.

So for a **persistent** .onion you currently have: bandguards + rendguard (full),
**L2** guard pinning (vanguards-lite), and **no L3** pinning. That is a real,
deliberate tradeoff. We chose to keep `Sandbox 1` (a strong, always-on syscall
filter) over the addon's L3 layer, rather than ship a fragile workaround that
could take your service offline when relays leave the network. If your threat
model requires full L2+L3 guard-discovery resistance for a long-lived service,
the correct answer today is to run the vanguards addon **without** Tor's
Sandbox, on a dedicated, otherwise-hardened host. That is a different set of
tradeoffs you should weigh deliberately, not a flag we can safely flip for you.

If Vanguards crashes, the entrypoint restarts it automatically up to 5 times. If it keeps crashing, it's disabled for that session and Tor continues running with vanguards-lite only. Restart the container to reset.

---

## Threat model context

Vanguards is specifically designed to defend against a **network-level adversary**, an attacker who controls a significant number of Tor relays or can observe large portions of the Tor network. This includes:

- State-level actors running covert Tor relays
- Adversaries performing traffic analysis across multiple relays
- Attackers attempting to force circuit construction through relays they control

Vanguards does not protect against:
- Vulnerabilities in your backend application
- Metadata leaks from your content (file modification times, writing style, etc.)
- Host compromise, if the server is rooted, the .onion address is the least of your problems
- Timing correlation attacks by an attacker who can observe both your server and the destination simultaneously (global passive adversary)

Against a state-level adversary, Vanguards covers one attack surface. Pair it with offline key generation, rootless Podman, a dedicated host, and discipline around what metadata your content exposes.
