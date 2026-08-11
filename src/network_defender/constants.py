"""
Immutable project-wide constants.

All values that would otherwise be hardcoded across the codebase live here.
No URLs, ports, thresholds, or timeouts may appear as literals in source code.
"""

from enum import Enum, StrEnum

# ---------------------------------------------------------------------------
# Project metadata
# ---------------------------------------------------------------------------
PROJECT_NAME = "Network Defender"
PROJECT_VERSION = "1.00"

# ---------------------------------------------------------------------------
# Config file names (relative to config/ directory)
# ---------------------------------------------------------------------------
CONFIG_FILE_SETUP = "setup.json"
CONFIG_FILE_RATE_LIMITS = "rate_limits.json"
CONFIG_FILE_LOGGING = "logging_config.json"
CONFIG_FILE_DETECTORS = "detectors.json"

# ---------------------------------------------------------------------------
# Severity levels (used by Alert model and detectors)
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    """Alert severity levels ordered from lowest to highest."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[str, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# ---------------------------------------------------------------------------
# Alert lifecycle (used by the Alert System)
# ---------------------------------------------------------------------------


class AlertStatus(StrEnum):
    """Triage status of an alert as it moves through the SOC workflow."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertSource(StrEnum):
    """Subsystem that raised an alert."""

    DETECTOR = "detector"
    RULE_ENGINE = "rule_engine"


# ---------------------------------------------------------------------------
# MITRE ATT&CK tactic identifiers (used by detector → alert mapping)
# ---------------------------------------------------------------------------


class MitreTactic(StrEnum):
    """MITRE ATT&CK tactic IDs relevant to network-based detections."""

    RECONNAISSANCE = "TA0043"
    INITIAL_ACCESS = "TA0001"
    LATERAL_MOVEMENT = "TA0008"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    CREDENTIAL_ACCESS = "TA0006"
    IMPACT = "TA0040"


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
