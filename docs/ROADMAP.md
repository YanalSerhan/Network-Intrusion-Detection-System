# Roadmap and known limitations

What is not built, what is built and wrong, and what would be worth building
next. The limitations come first, because they are the part a reader needs
before deciding whether to run this.

Everything here is either measured or scoped. Nothing is aspirational.

## Known limitations

### Detection

**Five detectors have a measured recall of 0.00 as shipped.** Beaconing, DNS
tunnelling, HTTP brute force, data exfiltration and lateral movement detect
none of their own attacks on live traffic; TCP port scan catches one case in
four; ARP spoofing and SSH brute force catch the loud half of theirs. One
cause: every detector runs on a five-second evaluation interval while nine of
them are configured for sixty seconds or more, because the per-detector
`time_window_seconds` is declared, validated, reported by `GET /config` — and
read by nothing. Measured across 777 grid points in
[DETECTION_TUNING.md](DETECTION_TUNING.md).

**Windows are tumbling and anchored to process start.** Whether a burst falls
inside one window or astride two depends on when the sensor was started. On
the composed timeline a once-a-second ping lands astride a boundary in six of
nine appearances, and a 120-query DNS tunnel splits 97/24 — taking a detection
that needed 100 down to 97. Identical traffic, different verdict.

**Some benign traffic is not separable from an attack by any threshold.** The
corpus shows five detectors whose benign and malicious ranges overlap:
encoded reputation lookups against a DNS tunnel, a nightly backup against a
staged archive, duplicate-address detection against a light ARP poisoner, and
both long-window flood detectors against a busy server. Each needs a signal
the detector does not currently use, not a better number.

**The shipped `tcp_port_scan.yaml` rule is wrong.** It counts SYN packets
where the detector counts unique destination ports, so it labels a SYN flood,
an SSH brute force, a bulk transfer and lateral movement as port scans. And a
threshold rule fires once per matching packet after its threshold rather than
once per window, so one behaviour can produce a dozen alerts.

**No baselining, no correlation.** Every threshold is absolute rather than
learned from the segment, so a quiet office and a datacentre span get the same
numbers. A scan followed by a brute force followed by lateral movement is
three unrelated alerts; nothing assembles them into an incident.

**Encrypted payloads are metadata only.** TLS SNI and offered ciphers, by
explicit PRD non-goal. An attacker operating entirely inside TLS to an
unremarkable destination is not visible.

### Operations

**No container images.** Milestone 17 is not implemented, so there is no
Dockerfile and no Compose file. [ARCHITECTURE.md](ARCHITECTURE.md) has the
topology they should express. Run it from a checkout for now.

**No blocking, ever.** This is a detection system. It reports floods; it does
not stop them. There is no RST injection and no firewall integration, and
adding one would change the threat model — an inline device is a device an
attacker can use to deny service by triggering it.

**Single-node.** One sensor writing to one database. No clustering, no
sensor-to-sensor correlation, no multi-tenancy.

**SQLite by default.** Fine for a single sensor; PostgreSQL is configured
through the same `DATABASE_URL` and is what a real deployment should use.
Retention is time-based only — see [CONFIGURATION.md](CONFIGURATION.md).

**Authentication is one API key, all-or-nothing, and off when unset.** No
users, no roles, no audit of who triaged what. `/config` reports whether a key
is configured so a deployment that forgot is visible rather than silent, but
there is no rate limiting on failed authentication; put it behind a proxy.

### Scope

**IPv4 and IPv6 addresses are parsed; the detectors are IPv4-shaped.** Private
address classification handles IPv6 unique-local space correctly, but no
detector reasons about IPv6-specific behaviour such as neighbour discovery.

**Synthetic evaluation only.** Every number in this repository comes from
generated traffic. The corpus contains the confusions its author thought of
and cannot report a false positive nobody imagined.

## Planned

Ordered by what the evidence says matters, not by what is easiest.

### Next — correctness of what already exists

1. **Make `time_window_seconds` real.** Each detector expires its own state on
   its own window. The corpus shows three distinct regimes — one second for
   floods, sixty for breadth and count detectors, an hour for beaconing — and
   no single interval serves all three. This is the highest-value change in
   the project.
2. **Sliding windows instead of tumbling ones**, so detection stops depending
   on when the process started.
3. **Fix the port-scan rule and the once-per-packet firing.** Either give the
   rule schema a distinct-value threshold or retire a rule the detector
   already covers correctly.
4. **Apply the recommended defaults** in [DETECTION_TUNING.md](DETECTION_TUNING.md)
   §2 once the window work lands.

All four are tracked under Milestone 21 in [TODO.md](TODO.md).

### Then — deployment

5. **Containers** (Milestone 17): multi-stage build, non-root, `NET_RAW`
   scoped to the sensor only, a Compose file for development and a hardened
   PostgreSQL overlay for production.
6. **Finish CI** (Milestone 18): lint, types, tests with the coverage gate,
   dependency audit and secrets scanning already run on every push; what is
   missing is the Docker build, a matrix across 3.12 and 3.13, and branch
   protection.

### Then — extensibility

7. **A documented plugin interface** for detectors and providers, so an
   extension does not require a fork. The discovery mechanism already
   supports it — the registry imports whatever is in `detectors/impl/` — but
   the packaging story and the lifecycle hooks are not defined.

### Later — detection quality

8. **Signals the thresholds cannot supply.** A registered-domain allowlist for
   DNS tunnelling and destination classification for exfiltration are the two
   the corpus names specifically; both turn an unwinnable threshold choice
   into a winnable one.
9. **Alert correlation into incidents**, so a scan, a brute force and lateral
   movement from one source arrive as one story.
10. **Evaluation against labelled real captures.** The single biggest
    improvement available to the sensitivity analysis, and the thing that
    would tell us which of these limitations actually bite.
11. **Per-segment baselining**, so thresholds adapt to what normal looks like
    on the network being watched rather than on the one this was tuned on.

## Explicitly not planned

- **Inline blocking or prevention.** Detection and prevention have different
  failure modes, and a system that can drop traffic is a system whose bugs
  drop traffic.
- **TLS interception.** A PRD non-goal, and the reason is not technical: a
  sensor that can decrypt is a sensor worth attacking for its keys.
- **Agent-based host visibility.** A different product.
