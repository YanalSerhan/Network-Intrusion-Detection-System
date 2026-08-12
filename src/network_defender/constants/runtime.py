"""
Runtime constants: protocols, capture defaults, alerting thresholds.
"""

from enum import Enum, StrEnum

# ---------------------------------------------------------------------------
# Network protocol identifiers
# ---------------------------------------------------------------------------


class Protocol(StrEnum):
    """Layer-2/3/4/7 protocols recognised by the capture and parser layers."""

    ETHERNET = "ethernet"
    ARP = "arp"
    IP = "ipv4"
    IPV6 = "ipv6"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"
    UNKNOWN = "unknown"


class TlsHandshakeType(int, Enum):
    """TLS handshake message types (RFC 5246 §7.4)."""

    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02


# ---------------------------------------------------------------------------
# Packet capture defaults (used when config is absent; never hardcoded inline)
# ---------------------------------------------------------------------------
DEFAULT_SNAPLEN = 65535
DEFAULT_BUFFER_SIZE_KB = 4096
DEFAULT_PACKETS_PER_SECOND = 10_000  # token-bucket refill rate

# ---------------------------------------------------------------------------
# Alert deduplication window
# ---------------------------------------------------------------------------
DEDUP_WINDOW_SECONDS = 60
DEDUP_MAX_TRACKED_KEYS = 10_000  # bound dedup state to prevent unbounded growth

# ---------------------------------------------------------------------------
# Alert confidence scoring
# ---------------------------------------------------------------------------
CONFIDENCE_MIN = 0.0
CONFIDENCE_MAX = 1.0
CONFIDENCE_BASE = 0.5  # starting score before evidence-based adjustments
CONFIDENCE_SEVERITY_WEIGHT = 0.05  # added per severity level above INFO
CONFIDENCE_EVIDENCE_WEIGHT = 0.30  # maximum contribution from evidence ratios
CONFIDENCE_RULE_ENGINE = 0.95  # signature matches are near-deterministic

# ---------------------------------------------------------------------------
# Alert repository defaults
# ---------------------------------------------------------------------------
ALERT_QUERY_DEFAULT_LIMIT = 100
ALERT_STORE_MAX_RECORDS = 100_000  # in-memory store ring-buffer bound
