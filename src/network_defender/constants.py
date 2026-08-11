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
# Threat intelligence enrichment
# ---------------------------------------------------------------------------


class ProviderStatus(StrEnum):
    """Outcome of a single threat intel provider lookup."""

    OK = "ok"
    ERROR = "error"
    SKIPPED = "skipped"
    CIRCUIT_OPEN = "circuit_open"


class ThreatVerdict(StrEnum):
    """Aggregated reputation verdict for an IP address."""

    UNKNOWN = "unknown"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


REPUTATION_MIN = 0.0
REPUTATION_MAX = 100.0
#: Aggregated score at or above which an IP is deemed suspicious / malicious.
REPUTATION_SUSPICIOUS_THRESHOLD = 25.0
REPUTATION_MALICIOUS_THRESHOLD = 60.0

#: Response cache: how long a lookup stays fresh, and how many entries are kept.
TI_CACHE_TTL_SECONDS = 86_400  # 24h — IP reputation moves slowly
TI_CACHE_MAX_ENTRIES = 10_000

#: Circuit breaker: consecutive failures before a provider is cut out, and how
#: long it stays cut out before a single trial request is allowed through.
TI_BREAKER_FAILURE_THRESHOLD = 5
TI_BREAKER_RESET_SECONDS = 300.0

#: Background enrichment worker.
TI_QUEUE_MAX_DEPTH = 1_000
TI_WORKER_POLL_SECONDS = 0.5

#: Outbound HTTP.
TI_HTTP_TIMEOUT_SECONDS = 10.0

#: Environment variable names holding provider API keys. Keys live in .env only.
ENV_ABUSEIPDB_API_KEY = "ABUSEIPDB_API_KEY"

# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------
API_TITLE = "Network Defender API"
API_VERSION = "v1"
API_PREFIX = "/api/v1"

#: Environment variable holding the API key. Authentication is disabled when
#: this is unset, so local development needs no configuration.
ENV_API_KEY = "API_KEY"

# ---------------------------------------------------------------------------
# Live dashboard feed
# ---------------------------------------------------------------------------
#: How often the server polls for new alerts. One poller serves every client,
#: so this is the total added database load regardless of viewer count.
LIVE_POLL_SECONDS = 2.0
#: Cap on alerts carried in one frame, so an alert storm cannot produce a
#: multi-megabyte message that stalls the browser.
LIVE_RECENT_ALERT_LIMIT = 50

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
