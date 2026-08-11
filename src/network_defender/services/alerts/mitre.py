"""
MITRE ATT&CK tactic/technique mapping for every detector.

Data Setup:  Static lookup table; no external dependencies or I/O.
Data Input:  A detector name (e.g. "TcpPortScanDetector") or rule name.
Data Output: The (tactic, technique) pair describing the adversary behaviour,
             attached to every Alert for SOC triage and reporting.

Extension point: adding a new detector only requires adding one entry here.
Unmapped detectors degrade gracefully to (None, None) rather than raising, so
a third-party detector never breaks the alert pipeline.
"""

from network_defender.constants import MitreTactic

# Technique IDs follow the MITRE ATT&CK Enterprise matrix (v14).
TECHNIQUE_NETWORK_SERVICE_DISCOVERY = "T1046"
TECHNIQUE_NETWORK_DOS = "T1498"
TECHNIQUE_ENDPOINT_DOS = "T1499"
TECHNIQUE_ADVERSARY_IN_THE_MIDDLE = "T1557"
TECHNIQUE_ARP_CACHE_POISONING = "T1557.002"
TECHNIQUE_DNS_C2 = "T1071.004"
TECHNIQUE_PROTOCOL_TUNNELING = "T1572"
TECHNIQUE_BRUTE_FORCE = "T1110"
TECHNIQUE_NON_STANDARD_PORT = "T1571"
TECHNIQUE_EXFIL_OVER_C2 = "T1041"
TECHNIQUE_REMOTE_SERVICES = "T1021"

#: Detector class name -> (MITRE tactic, MITRE technique ID).
DETECTOR_MITRE_MAP: dict[str, tuple[MitreTactic, str]] = {
    "TcpPortScanDetector": (
        MitreTactic.RECONNAISSANCE,
        TECHNIQUE_NETWORK_SERVICE_DISCOVERY,
    ),
    "SynScanDetector": (
        MitreTactic.RECONNAISSANCE,
        TECHNIQUE_NETWORK_SERVICE_DISCOVERY,
    ),
    "SynFloodDetector": (MitreTactic.IMPACT, TECHNIQUE_ENDPOINT_DOS),
    "UdpFloodDetector": (MitreTactic.IMPACT, TECHNIQUE_NETWORK_DOS),
    "IcmpFloodDetector": (MitreTactic.IMPACT, TECHNIQUE_NETWORK_DOS),
    "ArpSpoofingDetector": (
        MitreTactic.CREDENTIAL_ACCESS,
        TECHNIQUE_ARP_CACHE_POISONING,
    ),
    "DnsTunnelingDetector": (MitreTactic.COMMAND_AND_CONTROL, TECHNIQUE_DNS_C2),
    "SshBruteForceDetector": (MitreTactic.CREDENTIAL_ACCESS, TECHNIQUE_BRUTE_FORCE),
    "HttpBruteForceDetector": (MitreTactic.CREDENTIAL_ACCESS, TECHNIQUE_BRUTE_FORCE),
    "BeaconingDetector": (
        MitreTactic.COMMAND_AND_CONTROL,
        TECHNIQUE_PROTOCOL_TUNNELING,
    ),
    "SuspiciousPortDetector": (
        MitreTactic.COMMAND_AND_CONTROL,
        TECHNIQUE_NON_STANDARD_PORT,
    ),
    "DataExfiltrationDetector": (MitreTactic.EXFILTRATION, TECHNIQUE_EXFIL_OVER_C2),
    "LateralMovementDetector": (MitreTactic.LATERAL_MOVEMENT, TECHNIQUE_REMOTE_SERVICES),
}

#: Fallback tactics used when a YAML rule name matches one of these substrings.
RULE_NAME_KEYWORD_MAP: dict[str, tuple[MitreTactic, str]] = {
    "scan": (MitreTactic.RECONNAISSANCE, TECHNIQUE_NETWORK_SERVICE_DISCOVERY),
    "flood": (MitreTactic.IMPACT, TECHNIQUE_NETWORK_DOS),
    "brute": (MitreTactic.CREDENTIAL_ACCESS, TECHNIQUE_BRUTE_FORCE),
    "tunnel": (MitreTactic.COMMAND_AND_CONTROL, TECHNIQUE_PROTOCOL_TUNNELING),
    "beacon": (MitreTactic.COMMAND_AND_CONTROL, TECHNIQUE_PROTOCOL_TUNNELING),
    "exfil": (MitreTactic.EXFILTRATION, TECHNIQUE_EXFIL_OVER_C2),
    "spoof": (MitreTactic.CREDENTIAL_ACCESS, TECHNIQUE_ADVERSARY_IN_THE_MIDDLE),
    "lateral": (MitreTactic.LATERAL_MOVEMENT, TECHNIQUE_REMOTE_SERVICES),
}


def lookup_mitre(source_name: str) -> tuple[MitreTactic | None, str | None]:
    """
    Resolve the MITRE ATT&CK tactic and technique for a detector or rule name.

    Resolution order:
      1. Exact detector-class match in DETECTOR_MITRE_MAP.
      2. Case-insensitive keyword match against RULE_NAME_KEYWORD_MAP, so YAML
         rules such as "TCP Port Scan" inherit a sensible tactic.
      3. (None, None) when nothing matches.

    Args:
        source_name: Detector class name or YAML rule name.

    Returns:
        Tuple of (tactic, technique_id); either element may be None.
    """
    exact = DETECTOR_MITRE_MAP.get(source_name)
    if exact is not None:
        return exact

    lowered = source_name.lower()
    for keyword, mapping in RULE_NAME_KEYWORD_MAP.items():
        if keyword in lowered:
            return mapping

    return None, None
