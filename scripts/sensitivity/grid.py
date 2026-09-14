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

The window axis is each detector's own `time_window_seconds`. Until Milestone
21 no detector read that field and the axis had to be the shared evaluation
interval instead — which meant the sweep could measure a knob but not the one
an operator turns. Now the two are separate: the window is how much traffic a
detector considers, and the interval is only how often it is asked.

That separation also means the recommendation is per detector. A single shared
interval had to serve every detector at once; a window does not.
"""

#: Per-detector windows in seconds, the `time_window_seconds` axis. One second
#: is what the floods ask for, an hour what beaconing asks for, and the rest
#: sit between.
WINDOWS: tuple[float, ...] = (1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 3600.0)

#: How often every detector is evaluated, from `detection.evaluation_interval_seconds`.
#: Held fixed: it is no longer a detection parameter, only a latency one — an
#: alert cannot surface sooner than the next evaluation, and cannot be missed
#: by a later one.
EVALUATION_INTERVAL = 5.0

#: Detector -> (configuration field, values to try).
THRESHOLDS: dict[str, tuple[str, tuple[int, ...]]] = {
    "TcpPortScanDetector": ("unique_ports_threshold", (5, 8, 10, 12, 15, 20, 25, 30, 40, 60)),
    "SynScanDetector": ("unique_ports_threshold", (5, 8, 10, 12, 15, 20, 25, 30, 40, 60)),
    "SynFloodDetector": ("syn_count_threshold", (20, 40, 60, 80, 100, 150, 200, 300, 500, 800)),
    # Finer between 50 and 100 than the others: at the one-second window a
    # VoIP stream peaks at 40 datagrams and a moderate flood at 83, so the
    # whole decision lives in a range the original step size stepped over.
    "UdpFloodDetector": (
        "udp_count_threshold",
        (50, 60, 75, 100, 150, 200, 250, 300, 400, 600, 900),
    ),
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
