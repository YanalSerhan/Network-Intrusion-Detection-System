"""
Immutable project-wide constants.

All values that would otherwise be hardcoded across the codebase live here.
No URLs, ports, thresholds, or timeouts may appear as literals in source code.
"""

from enum import Enum

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


class Severity(str, Enum):
    """Alert severity levels ordered from lowest to highest."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# MITRE ATT&CK tactic identifiers (used by detector → alert mapping)
# ---------------------------------------------------------------------------


class MitreTactic(str, Enum):
    """MITRE ATT&CK tactic IDs relevant to network-based detections."""

    RECONNAISSANCE = "TA0043"
    INITIAL_ACCESS = "TA0001"
    LATERAL_MOVEMENT = "TA0008"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    CREDENTIAL_ACCESS = "TA0006"
    IMPACT = "TA0040"


# ---------------------------------------------------------------------------
# Packet capture defaults (used when config is absent; never hardcoded inline)
# ---------------------------------------------------------------------------
DEFAULT_SNAPLEN = 65535
DEFAULT_BUFFER_SIZE_KB = 4096

# ---------------------------------------------------------------------------
# Alert deduplication window
# ---------------------------------------------------------------------------
DEDUP_WINDOW_SECONDS = 60
