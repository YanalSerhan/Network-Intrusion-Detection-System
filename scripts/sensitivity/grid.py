"""
What the sweep varies, and over what range.

Data Setup:  Nothing.
Data Input:  None.
Data Output: The two axes of the experiment.

Each detector contributes one threshold, chosen because it is the parameter an
operator actually turns. Ranges are centred on the shipped value and stretched
far enough either side that the curve reaches both ends of its behaviour —
a range that stops before recall flattens cannot show whether the shipped
value is on a cliff or on a plateau, which is the question being asked.

The window axis is shared. It is the *evaluation interval*, the real control
over how much traffic a detector accumulates before it decides, and it is
listed here as an experimental variable because per-detector
`time_window_seconds` is not read by any detector — see docs/SENSITIVITY_ANALYSIS.md.
"""

#: Evaluation intervals in seconds. 5.0 is the shipped default in
#: config/setup.json; 3600 is the longest per-detector window any
#: configuration asks for.
WINDOWS: tuple[float, ...] = (1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 3600.0)

#: Detector -> (configuration field, values to try).
THRESHOLDS: dict[str, tuple[str, tuple[int, ...]]] = {
    "TcpPortScanDetector": ("unique_ports_threshold", (5, 8, 10, 12, 15, 20, 25, 30, 40, 60)),
    "SynScanDetector": ("unique_ports_threshold", (5, 8, 10, 12, 15, 20, 25, 30, 40, 60)),
    "SynFloodDetector": ("syn_count_threshold", (20, 40, 60, 80, 100, 150, 200, 300, 500, 800)),
    "UdpFloodDetector": ("udp_count_threshold", (50, 100, 150, 200, 250, 300, 400, 600, 900)),
    "IcmpFloodDetector": ("icmp_count_threshold", (10, 20, 30, 40, 50, 75, 100, 150, 250)),
    "SshBruteForceDetector": ("connection_count_threshold", (3, 5, 8, 10, 12, 15, 20, 30, 45)),
    "HttpBruteForceDetector": ("connection_count_threshold", (5, 10, 12, 15, 20, 25, 30, 45, 70)),
    "ArpSpoofingDetector": ("gratuitous_arp_threshold", (2, 3, 4, 5, 6, 8, 10, 15, 25)),
    "DnsTunnelingDetector": ("query_count_threshold", (10, 20, 30, 40, 50, 75, 100, 150, 250)),
    "BeaconingDetector": ("connection_count_threshold", (4, 6, 8, 10, 12, 15, 20, 30, 45)),
    "DataExfiltrationDetector": (
        "bytes_out_threshold",
        (10_000_000, 20_000_000, 30_000_000, 40_000_000, 50_000_000,
         70_000_000, 100_000_000, 150_000_000, 250_000_000),
    ),
    "LateralMovementDetector": (
        "internal_connection_threshold",
        (5, 8, 10, 12, 15, 20, 25, 30, 45),
    ),
}

#: `SuspiciousPortDetector` is deliberately absent: its operating point is a
#: port list, not a number, so there is no axis to sweep. It is still measured
#: at its shipped configuration in the default-configuration table.
UNSWEPT: tuple[str, ...] = ("SuspiciousPortDetector",)
