# Example attacks

How to make each detector fire, on your own machine, without a network and
without root. Every command below was run to produce the output shown; where a
capture produces something surprising, the surprise is documented rather than
edited out.

## The fastest possible start

```bash
uv run network-defender replay tests/data/pcaps/tcp_port_scan.pcap
```

```
3 alert(s) from tcp_port_scan.pcap:

  high     TcpPortScanDetector        confidence 0.75  45.155.205.233
           TCP Port Scan detected: 40 unique ports scanned.
  high     SynScanDetector            confidence 0.83  45.155.205.233
           SYN Scan detected: 40 unique ports targeted.
  medium   TCP Port Scan              confidence 0.85  45.155.205.233
           Rule 'TCP Port Scan' matched: 3 condition(s) satisfied.
```

Three alerts from one capture, which is correct and worth understanding. A
half-open scan satisfies both breadth detectors — one says "this host is
scanning", the other adds "and without completing handshakes" — and the third
is the YAML signature rule, a separate mechanism. `--settle` controls how long
the replay waits after the last packet, because the detectors decide on a
timer and a replay that exits immediately reads an empty database.

## The captures

Thirteen files in `tests/data/pcaps/`, one per scenario, each tuned to cross
exactly one detector's threshold and stay clear of every other's. They are
generated, seeded and committed — `scripts/pcap_scenarios/` builds them and
`scripts/generate_test_pcaps.py` writes them:

```bash
uv run python scripts/generate_test_pcaps.py
```

Committed rather than generated at test time, so a change in Scapy's defaults
arrives as a diff to review instead of as traffic that quietly stopped
resembling the attack it is named after.

| Capture | Simulates | Fires |
|---|---|---|
| `tcp_port_scan` | 40 SYNs across 40 ports from one source | TcpPortScan, SynScan |
| `syn_flood` | 150 SYNs at one port, spoofed sources | SynFlood |
| `udp_flood` | 250 datagrams at a non-DNS port | UdpFlood |
| `icmp_flood` | 60 echo requests | IcmpFlood |
| `arp_spoofing` | 8 gratuitous ARP replies claiming the gateway | ArpSpoofing |
| `dns_tunneling` | 60 queries with encoded, high-entropy labels | DnsTunneling |
| `ssh_brute_force` | 15 SSH connection attempts | SshBruteForce |
| `http_brute_force` | 25 POSTs to `/admin/login` | HttpBruteForce |
| `beaconing` | 15 connections at an exact 60-second cadence | Beaconing |
| `suspicious_port` | 3 connections to port 4444 | SuspiciousPort |
| `data_exfiltration` | 40 full-size outbound packets | *nothing — see below* |
| `lateral_movement` | one host reaching 25 internal peers over SMB | LateralMovement |
| `benign` | a DNS lookup, a page load, a TLS connection, a ping | nothing |

`benign.pcap` is as much a part of the set as the attacks. Without it, a
detector that fires on everything looks identical to one that works:

```bash
uv run network-defender replay tests/data/pcaps/benign.pcap
# 0 alert(s) from benign.pcap:
```

## Walkthroughs

### Reconnaissance — a port scan

```bash
uv run network-defender replay tests/data/pcaps/tcp_port_scan.pcap
```

Forty bare SYNs to forty ports on one host, jittered so the run does not also
read as a beacon. Both breadth detectors fire; the SYN-scan alert has the
higher confidence (0.83 against 0.75) because 40 ports is further past its
threshold of 10 than past the other's 15.

### Denial of service — SYN, UDP and ICMP floods

```bash
uv run network-defender replay tests/data/pcaps/syn_flood.pcap
```

```
  critical SynFloodDetector           confidence 0.73  -
           SYN Flood detected: 150 SYN packets to destination.
```

The source column is empty on purpose. Flood detectors key on the
**destination**, because a flood is usually distributed and the victim is what
every packet has in common. The UDP and ICMP captures behave the same way at
HIGH and MEDIUM severity — a SYN consumes a connection-table entry, a datagram
consumes bandwidth, and an echo request is mostly noise.

### Credential access — brute force and ARP poisoning

```bash
uv run network-defender replay tests/data/pcaps/ssh_brute_force.pcap
uv run network-defender replay tests/data/pcaps/http_brute_force.pcap
uv run network-defender replay tests/data/pcaps/arp_spoofing.pcap
```

```
  high     SshBruteForceDetector      confidence 0.68  45.155.205.233
           Possible SSH Brute Force: 15 connection attempts.
  medium   HttpBruteForceDetector     confidence 0.61  45.155.205.233
           Possible HTTP Brute Force: 25 login endpoint requests.
  high     ArpSpoofingDetector        confidence 0.69  192.168.1.1
           Possible ARP Spoofing detected: 8 ARP packets.
```

These name the **source**, the opposite of the floods: one host is doing the
work and the attacker is the identity an analyst needs. The ARP alert names
`192.168.1.1` because that is the address being *claimed* — the poisoner's own
MAC is in the evidence, not the alert header.

### Command and control — tunnelling, beaconing, backdoor ports

```bash
uv run network-defender replay tests/data/pcaps/dns_tunneling.pcap
uv run network-defender replay tests/data/pcaps/beaconing.pcap
uv run network-defender replay tests/data/pcaps/suspicious_port.pcap
```

```
  high     DnsTunnelingDetector       confidence 0.66  192.168.1.50
           Possible DNS Tunneling: high frequency of high-entropy DNS queries.
  high     BeaconingDetector          confidence 0.68  192.168.1.50
           Possible Beaconing detected: regular connections to same destination.
  medium   SuspiciousPortDetector     confidence 0.60  192.168.1.50
           Connection to suspicious port: 4444
```

The beacon fires here because a replay flushes the detectors once at the end,
so the whole capture is one window. **On a live sensor it would not** — see
"Why beaconing does not fire live" below.

### Lateral movement

```bash
uv run network-defender replay tests/data/pcaps/lateral_movement.pcap
```

```
  high     LateralMovementDetector    confidence 0.67  192.168.1.50
           Suspicious Lateral Movement: connected to 25 internal hosts.
```

Fan-out is the signal, not volume. Both endpoints must be private, which is
what separates this from a scan arriving from outside.

## Three things that look wrong, and are

A walkthrough that only shows the tidy cases is a demo. These are real, they
are reproducible with the commands above, and each is filed.

### `data_exfiltration.pcap` raises no exfiltration alert

```
  medium   TCP Port Scan              confidence 0.85  192.168.1.50
           Rule 'TCP Port Scan' matched: 3 condition(s) satisfied.
```

The shipped threshold is 50 MB, and a 50 MB fixture in a git repository is not
worth it. The capture keeps the *shape* — one internal host pushing bulk data
to one external address — and the end-to-end test lowers the threshold rather
than the fixture growing to meet it. This is the one capture whose name
promises more than it delivers on its own.

### The "TCP Port Scan" rule fires on four captures that are not port scans

It appears above under `ssh_brute_force`, `syn_flood`, `data_exfiltration` and
`lateral_movement`. The rule counts **SYN packets** — 15 from one source in 60
seconds — while `TcpPortScanDetector` counts **unique destination ports**. Its
own comment claims the two thresholds match; they measure different things,
and any burst of fifteen connections satisfies the rule.

This is why the heuristic detector exists and the rule does not replace it.
Open under Milestone 21.

### One rule match can produce a dozen alerts

`lateral_movement.pcap` raises twelve, eleven of them repeats of that same
rule. A threshold rule fires once for **every** matching packet after the
threshold is reached, rather than once per window: `hits >= threshold` stays
true for the rest of the window. Deduplication hides it only when the source
*and* destination repeat, and lateral movement is by definition a rotating
destination.

Open under Milestone 21.

## Why beaconing does not fire live

Every detector declares a `time_window_seconds` and no code reads it. The real
window is `detection.evaluation_interval_seconds`, shared by every detector
and shipping at 5 seconds, so a beacon with a 60-second interval never
accumulates two samples, let alone ten.

A replay flushes once at the end, which is why `beaconing.pcap` fires here.
That is a property of replay, not of the sensor. Five detectors have a recall
of 0.00 on live traffic as shipped;
[DETECTION_TUNING.md](DETECTION_TUNING.md) measures all of it, and it is open
under Milestone 21.

## Building your own

The scenarios are ordinary Scapy, and short. This is the whole port scan:

```python
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from .common import ATTACKER_IP, VICTIM_IP, at_intervals


def tcp_port_scan() -> list[Any]:
    """40 SYNs across 40 ports from one source."""
    return at_intervals(
        [
            Ether() / IP(src=ATTACKER_IP, dst=VICTIM_IP) / TCP(dport=port, flags="S")
            for port in range(1000, 1040)
        ],
        step=0.05,
        jitter=0.1,
    )
```

To add one: write the builder in `scripts/pcap_scenarios/`, register it in
that package's `SCENARIOS` dict, and run the generator. Two rules learned the
hard way:

- **Give it jitter.** A fixed interval to one destination is exactly what the
  beaconing detector looks for, so an un-jittered scan raises a beacon alert
  too — which the end-to-end assertions correctly fail on.
- **Seed anything random.** `common.RANDOM_SEED` and `common.BASE_TIME` are
  what make the committed files byte-identical between runs, which is what
  lets them be committed at all.

## Replaying a real capture

The same command takes any `.pcap`:

```bash
uv run network-defender replay ~/captures/incident-2026-08-19.pcap --settle 30
```

Give `--settle` more than the default six seconds for a long capture: the
whole file is replayed as fast as it can be read, but the detectors still
decide on a timer, and packets ingested after the last evaluation are only
counted by the final flush.

Nothing is sent to the network, and nothing needs privileges — the replay path
feeds the same packet callback the live sniffer does, which is also why the
end-to-end tests exercise the code that runs in production.
