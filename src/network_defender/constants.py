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
