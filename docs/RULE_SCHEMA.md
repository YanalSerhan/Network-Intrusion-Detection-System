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
| `conditions` | list | Yes | - | A list of conditions. ALL conditions must be met (logical AND) to trigger. |

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
