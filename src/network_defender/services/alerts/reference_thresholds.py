"""
Where confidence scoring gets each detector's "just over threshold" magnitude.

Data Setup:  Reads config/detectors.json once, on first use.
Data Input:  A detector class name.
Data Output: The magnitude at which that detector starts alerting.

Confidence is a ratio: how far past its own threshold did this detector fire?
Answering that needs the threshold, and the threshold is configuration — it
lives in config/detectors.json and an operator is expected to tune it.

It used to be a second copy of those numbers in source, and the two copies had
already drifted: exfiltration scored against 100 MB while the detector fired
at 50 MB, and lateral movement scored against 10 destinations while the
detector fired at 20. Every confidence score for those two was computed from a
threshold that no longer existed, and nothing failed, because a plausible
number is indistinguishable from a correct one.

What stays in code is the *mapping* — which evidence key holds the magnitude,
and which configuration field is the threshold for it. That is a fact about
the detector's implementation, not something an operator tunes.
"""

from typing import Any

from ...constants import CONFIG_FILE_DETECTORS
from ...shared.config_errors import load_json_file
from ...shared.paths import CONFIG_DIR

#: Detector name -> (evidence key holding the observed magnitude,
#:                   configuration field holding that detector's threshold).
DETECTOR_EVIDENCE_KEYS: dict[str, tuple[str, str]] = {
    "TcpPortScanDetector": ("unique_ports", "unique_ports_threshold"),
    "SynScanDetector": ("unique_ports", "unique_ports_threshold"),
    "SynFloodDetector": ("syn_count", "syn_count_threshold"),
    "UdpFloodDetector": ("udp_count", "udp_count_threshold"),
    "IcmpFloodDetector": ("icmp_count", "icmp_count_threshold"),
    "ArpSpoofingDetector": ("arp_count", "gratuitous_arp_threshold"),
    "DnsTunnelingDetector": ("count", "query_count_threshold"),
    "SshBruteForceDetector": ("connection_count", "connection_count_threshold"),
    "HttpBruteForceDetector": ("request_count", "connection_count_threshold"),
    "BeaconingDetector": ("connection_count", "connection_count_threshold"),
    "DataExfiltrationDetector": ("bytes_out", "bytes_out_threshold"),
    "LateralMovementDetector": (
        "unique_internal_destinations",
        "internal_connection_threshold",
    ),
}

_cache: dict[str, dict[str, Any]] | None = None


def _detector_config() -> dict[str, dict[str, Any]]:
    """
    Return the parsed detector configuration, loading it once.

    A missing or malformed file is not fatal here: the detectors themselves
    fall back to their own defaults in that case, and an alert scored on
    severity alone is better than no alert.

    Returns:
        The parsed contents of config/detectors.json, or an empty mapping.
    """
    global _cache
    if _cache is None:
        try:
            _cache = load_json_file(CONFIG_DIR / CONFIG_FILE_DETECTORS)
        except Exception:  # noqa: BLE001 - see docstring; scoring must not fail
            _cache = {}
    return _cache


def reset_cache() -> None:
    """Drop the cached configuration, so a test can vary it."""
    global _cache
    _cache = None


def evidence_key(detector_name: str) -> str | None:
    """
    Return the evidence field holding this detector's observed magnitude.

    Args:
        detector_name: Detector class name.

    Returns:
        The evidence key, or None for a detector that reports no magnitude.
    """
    profile = DETECTOR_EVIDENCE_KEYS.get(detector_name)
    return profile[0] if profile else None


def reference_magnitude(detector_name: str) -> float | None:
    """
    Return the magnitude at which this detector begins to alert.

    Args:
        detector_name: Detector class name.

    Returns:
        The configured threshold, or None when the detector is unknown or its
        threshold is not configured — in which case scoring falls back to
        severity alone rather than inventing a reference.
    """
    profile = DETECTOR_EVIDENCE_KEYS.get(detector_name)
    if profile is None:
        return None

    raw = _detector_config().get(detector_name, {}).get(profile[1])
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return None
    return float(raw)
