# Rule YAML Schema

The Network Defender Rule Engine uses declarative YAML files to define network intrusion detection rules. These rules are hot-reloaded automatically when modified in the `rules/` directory.

## Schema Structure

Each rule file must contain a single YAML dictionary representing one rule.

```yaml
name: "Example Rule"
severity: "medium"
enabled: true
window: 0
conditions:
  - field: "protocol"
    operator: "equals"
    value: "tcp"
```

### Top-Level Fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | Yes | - | A unique name for the rule. |
| `severity` | string | Yes | - | Alert severity if triggered (`info`, `low`, `medium`, `high`, `critical`). |
| `enabled` | boolean | No | `true` | Whether the rule is actively evaluated. |
| `window` | integer | No | `0` | Time window in seconds for aggregation-based rules (0 means single-packet match). |
| `threshold` | integer | No | `1` | Matches required within `window` before the rule fires. `1` means every matching packet fires immediately. |
| `group_by` | string | No | `src_ip` | The `ParsedPacket` field the window aggregates on (e.g. `src_ip`, `dst_ip`). |
| `distinct_field` | string | No | - | Count *distinct* values of this `ParsedPacket` field inside the window instead of counting matches. |
| `conditions` | list | Yes | - | A list of conditions. ALL conditions must be met (logical AND) to trigger. |

### Single-packet vs aggregation rules

A rule is an **aggregation rule** when `window > 0` **and** `threshold > 1`.
Anything else is a single-packet rule that fires on every match.

This distinction matters. A rule describing a volume event — a flood, a scan, a
brute-force attempt — is only meaningful with a threshold: `window` alone does
nothing, and the rule will fire on the very first matching packet. Set both.

### Volume or breadth

`threshold` counts matches by default. With `distinct_field` set it counts
distinct values of that field instead, which is the difference between a flood
and a scan:

- `SYN Flood` groups by `dst_ip` and counts matches. A hundred SYNs to one
  host is a flood however many ports they went to.
- `TCP Port Scan` groups by `src_ip` and counts distinct `dst_port`. Fifteen
  SYNs to one port is a client retrying; the same fifteen across fifteen ports
  is reconnaissance.

Without this the two rules are the same rule with different numbers, which is
what the shipped `tcp_port_scan.yaml` was until Milestone 21 — it labelled a
SYN flood, an SSH brute force, a bulk transfer and lateral movement as port
scans, because each of them is fifteen connections.

A packet that does not carry the `distinct_field` contributes nothing, not
even a match.

**An aggregation rule fires once per episode, not once per packet past the
threshold.** `threshold: 15` means the fifteenth match raises an alert and the
sixteenth does not; the rule re-arms only once enough matches have aged out of
the window for the count to fall back under the threshold, which is the point
at which the behaviour has stopped. This is per `group_by` value, so two
sources scanning at once are two alerts.

The alternative — alerting on every match once the count is high enough — is
what the engine used to do, and it turned one twenty-five packet behaviour
into eleven alerts. Deduplication downstream is not a substitute: its window
is not the rule's window and its key is not the rule's `group_by`, so an
attacker who crosses a threshold and then rotates destination gets an alert
per packet.

```yaml
# WRONG: fires on every single SYN packet, so ordinary traffic raises a flood alert
name: "SYN Flood"
severity: "high"
window: 10
conditions: [...]

# RIGHT: fires only after 100 SYNs to the same host within 10 seconds
name: "SYN Flood"
severity: "high"
window: 10
threshold: 100
group_by: "dst_ip"
conditions: [...]
```

Aggregation state is windowed and memory-bounded: counts outside `window` are
discarded, and the engine tracks a capped number of `(rule, group)` series with
LRU eviction. Packets whose `group_by` field is absent (e.g. `src_ip` on an ARP
packet) never fire an aggregation rule.

### Condition Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `field` | string | Yes | The field from the `ParsedPacket` to evaluate. Supports dot-notation for nested fields (e.g., `tcp_flags.syn`, `dns.query_name`). |
| `operator` | string | Yes | The comparison operator (`equals`, `not_equals`, `greater_than`, `less_than`, `regex`). |
| `value` | any | Yes | The expected value to compare against. |

## Supported Packet Fields

The engine evaluates rules against the normalized `ParsedPacket`. The exact fields available depend on the protocols detected in the packet.

### Common Fields (Available on all packets)
- `timestamp` (datetime)
- `src_ip` (string)
- `dst_ip` (string)
- `src_port` (integer)
- `dst_port` (integer)
- `protocol` (string - `tcp`, `udp`, `icmp`, `dns`, `http`, `tls`, etc.)
- `length` (integer)
- `raw_summary` (string)

### Protocol-Specific Fields

**TCP** (`tcp_flags.*`)
- `tcp_flags.syn` (boolean)
- `tcp_flags.ack` (boolean)
- `tcp_flags.fin` (boolean)
- `tcp_flags.rst` (boolean)
- `tcp_flags.psh` (boolean)
- `tcp_flags.urg` (boolean)

**DNS** (`dns.*`)
- `dns.query_name` (string)
- `dns.record_type` (integer)

**HTTP** (`http.*`)
- `http.method` (string)
- `http.path` (string)
- `http.host` (string)
- `http.user_agent` (string)

**TLS** (`tls.*`)
- `tls.sni` (string)
- `tls.cipher_suites` (list of integers)

## Examples

### TCP Port Scan
```yaml
name: "TCP Port Scan"
severity: "medium"
enabled: true
window: 60
threshold: 15
group_by: "src_ip"
distinct_field: "dst_port"
conditions:
  - field: "protocol"
    operator: "equals"
    value: "tcp"
  - field: "tcp_flags.syn"
    operator: "equals"
    value: true
  - field: "tcp_flags.ack"
    operator: "equals"
    value: false
```
