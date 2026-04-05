# What Is Vanguards

HiddenForge runs the Vanguards addon alongside Tor.

---

## The problem Vanguards solves

Running a Tor hidden service exposes you to a class of attacks called **guard discovery attacks**. The goal of these attacks is to learn the IP address of the server running the hidden service.

Tor protects your IP by routing traffic through a chain of relays before it reaches the Tor network. The first relay in that chain — your **guard relay** — is the only relay that sees your real IP address. Every other relay only sees the previous hop.

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

Tor 0.4.7+ includes a simplified version of the guard-layer rotation called vanguards-lite, which is always active. HiddenForge has this automatically — it's in the Tor binary itself.

The full Vanguards addon runs on top of vanguards-lite and adds the active monitoring (bandguards + rendguard). HiddenForge runs both.

---

## How HiddenForge runs Vanguards

The entrypoint starts Vanguards with one non-default flag: `--disable_vanguards`. This is not disabling Vanguards — it's disabling the guard-layer rotation inside Vanguards, because that function uses a Tor control command (`SETCONF NumEntryGuards`) that Tor's `Sandbox 1` blocks. Since vanguards-lite already handles guard-layer rotation inside the Tor process itself, this is the correct tradeoff: you get bandguards and rendguard from the addon, guard rotation from the built-in vanguards-lite, and Sandbox 1 stays active.

Vanguards runs as the `tor` user via `su-exec`, not as root. It communicates with Tor over a Unix control socket at `/var/lib/tor/control.sock`. The socket is only accessible inside the container.

If Vanguards crashes, the entrypoint restarts it automatically up to 5 times. If it keeps crashing, it's disabled for that session and Tor continues running with vanguards-lite only. Restart the container to reset.

---

## Threat model context

Vanguards is specifically designed to defend against a **network-level adversary** — an attacker who controls a significant number of Tor relays or can observe large portions of the Tor network. This includes:

- State-level actors running covert Tor relays
- Adversaries performing traffic analysis across multiple relays
- Attackers attempting to force circuit construction through relays they control

Vanguards does not protect against:
- Vulnerabilities in your backend application
- Metadata leaks from your content (file modification times, writing style, etc.)
- Host compromise — if the server is rooted, the .onion address is the least of your problems
- Timing correlation attacks by an attacker who can observe both your server and the destination simultaneously (global passive adversary)

For a state-level adversary threat model, Vanguards is a necessary but not sufficient protection layer. Pair it with: offline key generation, rootless Podman, a dedicated host, and operational discipline around what content and metadata you publish.
