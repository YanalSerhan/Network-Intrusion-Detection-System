# How detections work

Thirteen heuristic detectors, plus a YAML signature engine. This explains what
each one measures, what it deliberately ignores, and where it is known to be
wrong — the last of those measured rather than guessed, from the corpus in
[SENSITIVITY_ANALYSIS.md](SENSITIVITY_ANALYSIS.md).

Signature rules are a separate mechanism and are documented in
[RULE_SCHEMA.md](RULE_SCHEMA.md). The difference is worth stating once: a rule
matches *one packet* against a condition an analyst wrote; a detector
accumulates state across many packets and decides on a timer. A rule can say
"this packet went to port 4444". Only a detector can say "this host touched
forty ports in three seconds".

## The shape they all share

Every detector implements three methods — `ingest`, `evaluate`, `name` — and
the split between the first two is the whole performance design.

`ingest` runs on every packet in every enabled detector. It updates a counter
or adds to a set and returns; it decides nothing. `evaluate` makes the
decision, clears the window and returns alerts, and it runs on a timer. That
is why ingest measures around 95 000 packets a second while the expensive part
runs a few times a minute.

**Clearing the window in `evaluate` is mandatory.** A detector that does not
clear grows without bound and, worse, re-alerts forever on traffic already
reported.

> **The window is not what the configuration says.** Each detector declares a
> `time_window_seconds`; no code reads it. The real window is
> `detection.evaluation_interval_seconds` from `config/setup.json`, shared by
> all of them, and it ships at 5 seconds. Every "measured" figure below is at
> that shipped configuration, which is why several of them are 0.00.
> [DETECTION_TUNING.md](DETECTION_TUNING.md) has the full account; it is open
> under Milestone 21.

## Reconnaissance

### TcpPortScanDetector

**Measures** distinct destination ports touched by one source.
**Threshold** `unique_ports_threshold: 15`. **Severity** HIGH.

Counts *unique* ports rather than packets, and the distinction is the
detector: a client retrying one port is not scanning however many times it
retries, while a scanner touching a thousand ports once each is. Flag-agnostic
on purpose — it sees connect scans, half-open scans and anything else that
fans out — at the cost of also seeing a load balancer.

**Confuses with** a monitoring agent taking a service inventory (14 ports) and
a load balancer health-checking a backend (10 ports). Both sit just below the
threshold, which is where 15 came from.
**Measured recall as shipped: 0.25** — it catches only the loudest of the four
scan cases, because five seconds is not long enough to accumulate a slow one.

### SynScanDetector

**Measures** the same breadth, but only over bare SYNs.
**Threshold** `unique_ports_threshold: 10`. **Severity** HIGH.

A SYN with no ACK is a handshake never completed, which is what tells an
analyst the scanner was trying not to be logged. Counting SYN-ACKs would
report every busy server as a scanner, so it does not. Its threshold is lower
than the port-scan detector's because the signal is more specific: less of it
is needed before the finding is worth raising.

A half-open scan satisfies both detectors, and raises two alerts on purpose —
one saying "this host is scanning", one adding "and without completing
handshakes".

**Confuses with** the same two cases as above, both of which reach exactly 10.
The corpus supports raising this to 12.
**Measured recall as shipped: 0.67.**

## Impact — volumetric floods

All three key on the **destination**, not the source. A flood is usually
distributed, so per-source tallies never individually reach a threshold, while
the victim is what every packet has in common. The cost of that choice is that
a busy server is shaped like a victim.

### SynFloodDetector

**Measures** bare SYNs per destination. **Threshold** `syn_count_threshold:
100`. **Severity** CRITICAL — each one consumes a connection-table entry.

Counts bare SYNs only: a SYN-ACK is a server answering and established traffic
carries ACK, so counting either would make every busy server look attacked.

**Confuses with** a web server taking 300 new connections a minute. Separable
by *rate* at the one-second window the configuration declares, not by volume
at a longer one.
**Measured recall as shipped: 1.00.**

### UdpFloodDetector

**Measures** UDP datagrams per destination. **Threshold**
`udp_count_threshold: 200`. **Severity** HIGH.

The highest threshold of the three, because normal UDP is the chattiest
traffic on a network: DNS, NTP and every discovery protocol run over it.

**Confuses with** an RTP media stream. Same rate-versus-volume problem as the
SYN flood.
**Measured recall as shipped: 1.00.**

### IcmpFloodDetector

**Measures** ICMP packets per destination. **Threshold**
`icmp_count_threshold: 50`. **Severity** MEDIUM — usually noise.

The lowest threshold of the three: sustained ICMP at any real rate is already
abnormal, because nothing legitimate pings in bulk.

**Confuses with** availability monitoring that pings once a second. At a
one-second window the two are an order of magnitude apart; stretched to a
minute they are indistinguishable, and on the composed timeline the ping
alerts six times in half an hour.
**Measured recall as shipped: 1.00.**

## Credential access

Both brute-force detectors key on the **source** — the opposite of the floods.
Guessing credentials is one attacker working through a list, and the attacker
is the identity an analyst needs named.

Neither sees whether a login succeeded. SSH is encrypted from the second
packet, and parsing an HTTP response body is not something a passive sensor
should do. What both measure is attempt *rate*, which is what separates
someone guessing from someone who mistyped their password.

### SshBruteForceDetector

**Measures** new connections to the SSH port, per source. **Threshold**
`connection_count_threshold: 10`, `ssh_port: 22`. **Severity** HIGH.

Counts connection *openings* — bare SYNs — not packets. An established SSH
session carries thousands of packets, so counting those would report every
long-running session as an attack. The port is configurable because moving
sshd off 22 is common hardening advice, and a hardcoded port would blind this
detector on exactly the hosts whose operators took it.

**Confuses with** configuration management opening one session per managed
host — 14 sessions from one address, which reaches exactly the threshold. The
corpus supports raising this to 12.
**Measured recall as shipped: 0.50** — the fast case, not the low-and-slow one.

### HttpBruteForceDetector

**Measures** requests to authentication-looking paths, per source.
**Threshold** `connection_count_threshold: 20`. **Severity** MEDIUM.

Only paths containing `login`, `auth`, `signin` or `admin` count. A web server
serves hundreds of requests a minute to one visitor without anything being
wrong; the concentration on the login path is the signal. Its threshold is
higher than SSH's because a single page load can issue several requests to the
same path, and because clear-text HTTP auth is less immediately valuable to an
attacker than a shell.

**Confuses with** an office behind one NAT address signing in to a portal —
the textbook cause of this false positive, and no packet field separates it
from one attacker with a word list.
**Measured recall as shipped: 0.00.**

### ArpSpoofingDetector

**Measures** ARP packets per claimed source. **Threshold**
`gratuitous_arp_threshold: 5`. **Severity** HIGH.

A simplification of full MAC-to-IP mapping surveillance: it counts ARP traffic
per claimed source rather than tracking which MAC currently owns which
address. That catches the flood of gratuitous replies a poisoner sends to keep
its mapping cached — the noisy part of the attack — and misses a single
well-timed reply, which is the quiet part.

**Confuses with** duplicate-address detection after a lease renewal, which
reaches 8 packets against a light poisoner's 6. The ranges genuinely overlap;
no threshold separates them, and the fix is the mapping surveillance the
detector simplified away.
**Measured recall as shipped: 0.50.**

## Command and control

### DnsTunnelingDetector

**Measures** query volume *and* the fraction of query names with high Shannon
entropy, per source. **Thresholds** `query_count_threshold: 50`,
`entropy_threshold: 4.5`. **Severity** HIGH.

Two signals together, because neither alone is enough. A real hostname is a
word or two and scores low on entropy; base32-encoded tunnel payload is close
to uniform over its alphabet and scores high. Volume alone would flag a busy
resolver; entropy alone would flag the random subdomains CDNs generate. An
alert requires the volume threshold *and* a majority of names above the
entropy threshold.

Both halves of that claim are tested: a 300-query resolver with ordinary names
is correctly ignored, and so are hexadecimal CDN cache keys.

**Confuses with** an endpoint agent doing encoded reputation lookups, which is
byte for byte the shape of a tunnel. Not separable by volume or entropy; needs
a registered-domain allowlist.
**Measured recall as shipped: 0.00.**

### BeaconingDetector

**Measures** the coefficient of variation of intervals between one source
contacting one destination. **Thresholds** `connection_count_threshold: 10`,
`interval_variance_tolerance: 0.1`. **Severity** HIGH.

Regularity, not volume, is the finding: malware calling home runs on a
schedule and human-driven traffic is bursty. The tolerance is a *ratio*
(standard deviation over mean) rather than an absolute, so a beacon every hour
and one every ten seconds are held to the same standard of regularity.
Timestamps are sorted before differencing — out-of-order arrivals produce
negative intervals, which inflate the deviation and mask real beacons.

The window matters more here than anywhere else. A sixty-second beacon needs a
window of at least ten minutes before there are ten intervals to measure,
which is why the configuration asks for an hour.

**Confuses with** telemetry agents and health checks, which are exactly as
regular and differ only in destination — which this detector does not look at.
**Measured recall as shipped: 0.00.** At the hour-long window it declares, all
three beacon cases are caught.

### SuspiciousPortDetector

**Measures** connections to a configured port list. **Configuration**
`suspicious_ports: [6667, 31337, 4444, 4445]`. **Severity** MEDIUM.

The only detector with no numeric threshold — its operating point is a set,
which is why it is absent from the sensitivity sweep. Deduplicates by
`(source, destination, port)` so a chatty connection is one finding rather
than one per packet.

**Confuses with** an IRC client on 6667. That is a policy question about the
list, not a tuning question about a number.

## Exfiltration and lateral movement

### DataExfiltrationDetector

**Measures** total bytes sent per source. **Threshold**
`bytes_out_threshold: 50000000` (50 MB). **Severity** CRITICAL.

Volume alone, with no opinion on destination. A backup to cloud storage and a
staged archive leaving for an attacker look identical on the wire, and
deciding between them needs context a passive sensor does not have. The
threshold is high on purpose: this detector earns its place by rarely firing.

**Confuses with** exactly that backup — 50 MB against a staged archive's 30
MB. The ranges overlap and no threshold separates them; it needs destination
classification.
**Measured recall as shipped: 0.00.**

### LateralMovementDetector

**Measures** distinct *internal* destinations reached by one internal source.
**Threshold** `internal_connection_threshold: 20`. **Severity** HIGH.

Fan-out is the signal, not volume: a workstation talks to a handful of
servers, a compromised host looking for somewhere to go next talks to
everything. Both endpoints must be private, which is what separates this from
a port scan arriving from outside. Privacy is decided by the stdlib address
parser rather than by string prefixes — prefix matching raised on malformed
input, misread `172.5.0.1`, and ignored IPv6 unique-local space entirely.

**Confuses with** a monitoring server polling 18 devices, and with
configuration management reaching 14 hosts. Fan-out is their job.
**Measured recall as shipped: 0.00.**

## What every detector shares by omission

- **No payload inspection beyond metadata.** DNS query names, HTTP request
  lines and TLS SNI, and nothing else. No response bodies, no decryption.
- **No cross-detector correlation.** A scan followed by a brute force followed
  by lateral movement is three unrelated alerts. Correlation into incidents is
  on the [roadmap](ROADMAP.md).
- **No baselining.** Every threshold is absolute, not learned from the
  segment. A quiet office network and a datacentre span get the same numbers.
- **Tumbling windows anchored to process start.** Whether a burst falls inside
  one window or astride two depends on when the sensor started, which means
  identical traffic can detect or not. Measured, and open under Milestone 21.
