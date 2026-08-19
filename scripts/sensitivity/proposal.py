"""
The configuration this analysis actually recommends.

Data Setup:  Nothing; a decision, written down.
Data Input:  None.
Data Output: One evaluation interval and the threshold changes worth making.

`recommendation.py` computes two operating points from the data, and neither
is the answer on its own. The F1 optimum is measured on a corpus that is half
attacks, so it systematically favours a lowered threshold — replayed over the
composed timeline it raises twenty-three alerts in half an hour, sixteen of
them about nothing. The zero-false-positive point is fitted to twenty-three
benign cases and over-claims in the other direction.

What is here is the judgement between them, kept in code rather than only in
prose so the timeline chart and docs/DETECTION_TUNING.md draw on the same
numbers. The argument for each entry is in that document; the short version is
that the thresholds are mostly right and the window is wrong.
"""

#: Seconds between evaluations — `detection.evaluation_interval_seconds` in
#: config/setup.json, currently 5.0.
#:
#: This is a workaround, not the fix. The corpus shows three window regimes
#: and no single interval serves them: the flood detectors want one second,
#: where they score a perfect F1 and where a flood is still distinguishable
#: from a busy server by *rate*; the breadth and count detectors want sixty;
#: beaconing wants an hour. All three numbers are already written down, in
#: each detector's `time_window_seconds`, and no code reads any of them.
#: Sixty is the best compromise available while that stays true.
PROPOSED_INTERVAL = 60.0

#: Threshold changes the corpus supports at that interval. Everything absent
#: keeps its shipped value — at sixty seconds most of them already clear every
#: benign case in the corpus, which is the part of this result that was not
#: expected.
PROPOSED_THRESHOLDS: dict[str, int] = {
    # Benign port fanout tops out at ten: a load balancer probing ten service
    # ports, a monitoring agent taking a fourteen-port inventory. Ten is
    # exactly the shipped threshold, so both alert today. Twelve clears them
    # with a margin and still catches the twenty-five and sixty-port scans.
    "SynScanDetector": 12,
    # Configuration management reaches ten SSH sessions from one host, again
    # exactly the shipped threshold. Twelve clears it; the forty-attempt
    # attack registers thirty and is unaffected.
    "SshBruteForceDetector": 12,
    # Only while the interval is sixty seconds. Fifty ICMP packets per
    # *second* is a flood; fifty per minute is a host pinged once a second,
    # which is ordinary availability monitoring — and on the composed timeline
    # that ping alerts six times in half an hour. Revert this to 50 the moment
    # the detector gets the one-second window it already asks for, because at
    # one second the two are an order of magnitude apart and no compensation
    # is needed.
    "IcmpFloodDetector": 100,
}

#: Detectors where the corpus shows the benign and malicious ranges
#: *overlapping*, so no threshold separates them. Each maps to the signal that
#: would, which is a change to the detector rather than to its configuration.
#: Recorded here so a future tuning pass does not rediscover them by fitting a
#: threshold to one benign case's volume.
UNSEPARABLE_BY_THRESHOLD: dict[str, str] = {
    "DnsTunnelingDetector": (
        "Encoded reputation lookups reach 75 queries; the tunnel reaches 100. "
        "Needs a registered-domain allowlist, not a higher count."
    ),
    "DataExfiltrationDetector": (
        "A nightly backup moves 50 MB and a staged archive 30 MB. Needs the "
        "destination — internal, known-good, or neither — which the detector "
        "documents itself as not looking at."
    ),
    "ArpSpoofingDetector": (
        "Duplicate-address detection after a lease renewal reaches 8 packets "
        "and a light poisoner 6. Needs MAC-to-IP mapping surveillance, which "
        "the detector's own docstring names as the thing it simplified away."
    ),
    "SynFloodDetector": (
        "At a minute-long window a busy web server reaches 300 new "
        "connections and a moderate flood 150. Separable by rate at the "
        "one-second window the configuration already declares."
    ),
    "UdpFloodDetector": (
        "Same shape: an RTP stream reaches 400 datagrams a minute and a "
        "moderate flood 250. Separable by rate at one second."
    ),
}
