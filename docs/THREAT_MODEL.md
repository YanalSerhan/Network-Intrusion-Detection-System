# Threat model

Network Defender watches a network for attacks. This document is about the
other direction: what an attacker gains from Network Defender itself, and what
it does about that.

A sensor is an unusually attractive target. It sits where it can see all the
traffic, it holds a searchable history of what has happened, and it is trusted
by the people who would notice an intrusion. Compromising it is worth more
than compromising a typical host on the same segment.

## What it defends

Reconnaissance (port and SYN scans), volumetric attacks (SYN, UDP and ICMP
floods), credential guessing (SSH and HTTP), command and control (beaconing,
DNS tunnelling, connections to known-bad ports), and post-compromise movement
(internal fan-out, bulk outbound transfer). Each has a detector, a synthetic
capture that exercises it end to end, and a golden file pinning what it
reports. See `docs/PRD_detection_engine.md`.

## What it does not defend

Stated plainly, because a control someone believes in and does not have is
worse than one they know they lack.

- **Encrypted payloads.** TLS metadata only — SNI and offered ciphers. No
  interception, no decryption, by explicit PRD non-goal. An attacker who
  operates entirely inside TLS to an unremarkable destination is not visible
  here.
- **Traffic it cannot see.** A passive sensor on a span port sees what is
  mirrored to it. Host-to-host traffic on a switch that is not mirrored, or
  anything on a segment it is not attached to, does not exist as far as it is
  concerned.
- **Host-level compromise.** No agent, no file integrity monitoring, no
  process visibility. An attacker who is already on a host and stays quiet on
  the wire is out of scope.
- **Novel attacks.** Every detector is a threshold or a heuristic tuned to a
  known shape. An attacker who stays under the thresholds — a slow scan, a
  jittered beacon, exfiltration paced below the byte limit — evades it. The
  thresholds are configuration precisely so a defender can trade false
  positives for that margin.
- **In the shipped configuration, considerably more than that.** Milestone 19
  measured it: five of the twelve tunable detectors have a recall of **0.00**
  on live traffic as shipped, and three more sit at or below 0.5. An attacker
  does not need to stay under the beaconing, DNS-tunnelling, HTTP-brute-force,
  exfiltration or lateral-movement thresholds, because none of those detectors
  can reach its threshold at all. The cause is a single defect — every
  detector runs on a five-second window while nine are configured for sixty
  seconds or more — and it is quantified in
  [DETECTION_TUNING.md](DETECTION_TUNING.md) and open under Milestone 21.
  Until it is fixed, treat this system's coverage as the four detectors in
  that document with a non-zero measured recall.
- **Availability of the monitored network.** It reports floods; it does not
  stop them. There is no blocking, no RST injection, no firewall integration.

## Trust boundaries

```
  ┌────────────────────────────────────────────────────────────┐
  │ UNTRUSTED: the monitored network                           │
  │   Packets. Attacker-controlled by definition.              │
  └───────────────────────┬────────────────────────────────────┘
                          │ raw frames (read-only, NET_RAW)
  ┌───────────────────────▼────────────────────────────────────┐
  │ SENSOR PROCESS                                             │
  │   capture → parser → detectors → alerts → database         │
  │   Elevated: needs a raw socket. Writes.                    │
  └───────────┬──────────────────────────────┬─────────────────┘
              │ SQL (write)                  │ HTTPS (outbound)
  ┌───────────▼───────────┐      ┌───────────▼─────────────────┐
  │ DATABASE              │      │ THREAT INTEL PROVIDERS      │
  │   The alert history.  │      │   Third parties. Untrusted  │
  │   Sensitive.          │      │   input, metered access.    │
  └───────────▲───────────┘      └─────────────────────────────┘
              │ SQL (read)
  ┌───────────┴───────────┐      ┌─────────────────────────────┐
  │ API PROCESS           │◄─────┤ ANALYST BROWSER             │
  │   Read-only. No raw   │ HTTP │   Trusted user, untrusted   │
  │   socket.             │  WS  │   network position.         │
  └───────────────────────┘      └─────────────────────────────┘
```

The split between the sensor and the API is the main structural control: the
process holding a raw socket does not serve HTTP, and the process serving HTTP
cannot capture. Compromising the API gets an attacker reads, not the wire.

## Attack surface, and what is done about it

### 1. Malformed packets (the largest surface)

Every packet is attacker-controlled and arrives before any authentication.
Parsing untrusted binary is where sensors historically fall over — Wireshark's
CVE history is mostly dissectors.

- Parsing is Scapy's, not hand-rolled, except the TLS ClientHello walk, which
  is bounds-checked at every offset and returns `(None, None)` on anything
  unexpected. It exists because Scapy's TLS layer is optional and raises on
  truncated handshakes, which a sensor sees constantly.
- `parse_safe()` swallows any exception, so one malformed frame costs its own
  packet and nothing else. `tests/unit/parser/` feeds truncated and corrupt
  records deliberately.
- **Residual risk:** a memory-safety bug in Scapy or libpcap. Mitigated by
  running the sensor unprivileged after socket setup and by the dependency
  audit in CI, not by anything in this codebase.

### 2. Detector state exhaustion

Detectors hold per-source state. An attacker who forges source addresses can
create an entry per address.

- Windows are cleared on every evaluation cycle, so state is bounded by traffic
  in one interval rather than growing forever.
- Alert deduplication is bounded (`DEDUP_MAX_TRACKED_KEYS`).
- **Residual risk:** a spoofing burst inside one window still allocates. The
  bound is the evaluation interval, which is configuration — and lengthening
  that interval is exactly what [DETECTION_TUNING.md](DETECTION_TUNING.md)
  recommends for detection quality. The two pull against each other: a longer
  window detects more and holds more forged state at once. Sixty seconds of
  one interface's traffic is the quantity to size for.

### 3. Alert flooding as cover

Generating alerts is free for an attacker and expensive for a defender. A
storm buries the one alert that matters.

- Deduplication collapses repeats into one record with an occurrence count.
- Enrichment runs on a bounded queue and drops rather than blocks, so a storm
  cannot stall detection.
- The gatekeeper sheds callers past its queue depth instead of piling up.
- **Residual risk:** the analyst's attention. Nothing here solves that.
- **Known amplifier.** A threshold rule fires once for *every* matching packet
  after its threshold is reached, not once per window, and deduplication only
  collapses repeats that share a source *and* a destination. An attacker who
  crosses a rule threshold and then rotates destinations gets one alert per
  packet — `lateral_movement.pcap` produces twelve alerts for one behaviour
  without trying. That turns a cheap action into an alert multiplier, which is
  precisely the shape this section is about. Open under Milestone 21; see
  [EXAMPLE_ATTACKS.md](EXAMPLE_ATTACKS.md).

### 4. The REST API

- Authentication is a single API key, all-or-nothing, and **off when unset** —
  a deployment that forgets it is open. `/config` reports whether a key is
  configured so this is visible rather than silent.
- The key is compared in constant time (`shared/credentials.py`). It was not
  until Milestone 16; `==` on a secret is a timing oracle.
- The API process is read-only apart from triage status.
- Inputs are typed — enums, bounded ints, UUIDs — and queries are parameterised
  through SQLAlchemy. See `tests/unit/security/test_input_hardening.py`.
- **Residual risk:** no rate limiting on failed authentication, so the key can
  be brute-forced given enough time. Put the API behind a proxy that rate
  limits, and prefer a long random key.

### 5. Threat intel providers

Outbound requests to third parties, whose responses are untrusted input.

- All of it goes through the gatekeeper. Nothing else in the codebase makes an
  outbound HTTP call; `tests/` asserts that.
- Private addresses are never sent, so a compromised provider learns nothing
  about internal topology.
- Responses are parsed into Pydantic models; a provider that returns nonsense
  produces a failed lookup, not a crash.
- A failing provider trips a circuit breaker rather than retrying forever.
- **Residual risk:** a provider that returns *plausible* wrong answers can
  mislead an analyst. There is no cross-provider corroboration beyond
  aggregation.

### 6. Rule files

Rules are loaded from disk and hot-reloaded, so anyone who can write to
`rules/` can change what is detected — including disabling detection.

- Field paths cannot reach private attributes, so a rule cannot walk out of
  the packet into the interpreter.
- Regexes are compiled at load, length-bounded, and run against a bounded
  subject, so a bad pattern cannot hang the detection thread.
- **Residual risk:** write access to `rules/` is equivalent to disabling
  detection. Treat the directory as a protected artifact; ship it from version
  control, not by editing in place.

### 7. The stored history

The database is the most sensitive thing here. It is a map of the monitored
network: which hosts exist, what services they run, what is noisy.

- Only alert-linked packets are retained (ADR 5); full traffic stays in PCAP.
- Retention prunes on a schedule, configurable per table.
- Credentials never reach it: redaction runs at the logging handler, so no
  call site can forget.
- **Residual risk:** it is unencrypted at rest. Use disk encryption, and give
  the API its own read-only account (`docs/CREDENTIALS.md`).

### 8. Supply chain

- `uv.lock` pins every dependency; CI installs `--frozen`, so a drifted lock
  fails rather than resolving something new.
- gitleaks scans tree and history on every push and weekly.
- A dependency audit runs in CI.
- **Residual risk:** a compromised upstream release that the audit has not yet
  learned about.

## Deployment assumptions

The model above assumes:

1. The capture interface is a mirror/span port, not a routed path.
2. The sensor host is not reachable from the monitored network — traffic flows
   in, nothing flows back.
3. The API is behind a reverse proxy terminating TLS and rate-limiting.
4. `rules/` and `config/` are deployed from version control, not edited live.
5. The database is on encrypted storage.

Breaking any of these invalidates the corresponding section. Assumption 2 is
the important one: a sensor reachable from the network it watches is a sensor
an attacker can attack with the traffic it is trying to inspect.

## Reviewing this document

It is written to be falsifiable. Every "residual risk" above names something
that is *not* handled, and each control claims something testable rather than
something reassuring — the constant-time comparison, the bounded dedup, the
single outbound call site are all things a reader can check in the code or in
`tests/unit/security/`.

Two of the entries here were added after the fact, by measurement rather than
by review: the shipped-configuration coverage gap in "What it does not defend"
and the alert amplifier in §3. Both were found by running the system and
reading the output, which is the failure mode a threat model written once at
design time has — it describes the system someone intended to build.
