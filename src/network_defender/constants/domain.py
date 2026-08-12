"""
Domain constants: project metadata, severities, alert lifecycle, MITRE tactics.

No URLs, ports, thresholds or timeouts may appear as literals in source code —
they live here or in configuration.
"""

from enum import StrEnum

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


