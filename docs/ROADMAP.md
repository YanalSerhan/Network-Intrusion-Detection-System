# Roadmap and known limitations

What is not built, what is built and wrong, and what would be worth building
next. The limitations come first, because they are the part a reader needs
before deciding whether to run this.

Everything here is either measured or scoped. Nothing is aspirational.

## Known limitations

### Detection

**Mean recall is 0.74, and half the detectors still miss the quiet half of
their own attack.** Data exfiltration, DNS tunnelling, HTTP brute force, SSH
brute force and lateral movement each catch the loud case and miss the subtle
one; SYN scan catches two cases in three. Measured across 791 grid points in
[DETECTION_TUNING.md](DETECTION_TUNING.md). Until Milestone 21 the figure was
0.41 with five detectors at 0.00, because no detector read the
`time_window_seconds` its own configuration declared — every one of them ran
on the shared five-second evaluation interval. That is fixed; what is left is
the part a window cannot fix.

**Some benign traffic is not separable from an attack by any threshold.** The
corpus shows five detectors whose benign and malicious ranges overlap at their
own window: a ten-second health check against a beacon, encoded reputation
lookups against a DNS tunnel, a nightly backup against a staged archive,
duplicate-address detection against a light ARP poisoner, and a monitoring
server's fan-out against a contained lateral sweep. Each needs a signal the
detector does not currently use, not a better number.

**The shipped `tcp_port_scan.yaml` rule is wrong.** It counts SYN packets
where the detector counts unique destination ports, so it labels a SYN flood,
an SSH brute force, a bulk transfer and lateral movement as port scans — one
alert each now that firing is edge-triggered, but still four things that are
not port scans called port scans.

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

1. ~~**Make `time_window_seconds` real.**~~ Done in Milestone 21. Each
   detector now slides its own window over capture time, and the corpus's
   three regimes — one second for floods, ten to sixty for breadth and count
   detectors, an hour for beaconing — are each served by the configuration
   that always declared them.
2. ~~**Sliding windows instead of tumbling ones.**~~ Done in Milestone 21, and
   with them a burst is one alert rather than one per evaluation.
3. **Fix the port-scan rule.** Either give the rule schema a distinct-value
   threshold or retire a rule the detector already covers correctly. The
   once-per-packet firing beside it is fixed: rules are edge-triggered.
4. **Give the five unseparable detectors the signal they need** rather than a
   different number: a registered-domain allowlist for DNS tunnelling, a
   destination classification for exfiltration, and destination reputation for
   beaconing. [DETECTION_TUNING.md](DETECTION_TUNING.md) §4 names each.

All four are tracked under Milestone 21 in [TODO.md](TODO.md).

### Then — deployment

5. **Containers** (Milestone 17): multi-stage build, non-root, `NET_RAW`
   scoped to the sensor only, a Compose file for development and a hardened
   PostgreSQL overlay for production.
6. **Finish CI** (Milestone 18). The test suite with its coverage gate, the
   dependency audit and the secrets scan run on every push. Missing: **ruff
   and mypy**, which today run only in the pre-commit hooks and so are
   enforced on whoever installed them; the Docker build; a matrix across 3.12
   and 3.13; and branch protection.

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
