"""
The configuration this analysis recommends, and why each number is that number.

Data Setup:  Nothing; a decision, written down.
Data Input:  None.
Data Output: A window and a threshold per detector.

Kept in code rather than only in prose so the timeline chart and
docs/DETECTION_TUNING.md are drawn from the same numbers.

The headline, now that the windows work: **the windows were right and the
thresholds were set for a broken one.** Every detector keeps the window its
own configuration has always declared — one second for the floods, ten for the
scans, a minute for most, an hour for beaconing — because with those live,
mean recall across the twelve tunable detectors rises from 0.41 to 0.62 with
no threshold change at all. Four thresholds then move, and only four.

The rule for moving one: it must buy recall, and it must leave visible
headroom over the busiest benign case in the corpus. The margin is quoted for
each, because a threshold fitted to one fixture's volume is not a
recommendation, it is a coincidence.
"""

#: Seconds between evaluations — `detection.evaluation_interval_seconds`.
#: Unchanged at five, and no longer a detection parameter at all: it decides
#: how soon an alert can surface, not whether it is found. Milestone 20
#: recommended raising this to sixty as an interim while the window was broken;
#: with the window fixed that trade is gone, and a shorter interval is now
#: strictly better because it only costs latency.
PROPOSED_INTERVAL = 5.0

#: Threshold changes, at each detector's own window. Everything absent keeps
#: its shipped value — which is most of them, and is the part of this result
#: that was not expected.
PROPOSED_THRESHOLDS: dict[str, int] = {
    # 1-second window. The busiest benign second in the corpus is twenty SYNs
    # to one destination — a web server taking three hundred connections over
    # ten seconds, and an aggressive port scan. Forty leaves a 2.0x margin
    # over that and takes recall from 0.5 to 1.0, because a moderate flood
    # runs at fifty a second and a hundred never saw it.
    "SynFloodDetector": 40,
    # 1-second window. The busiest benign second is ten echo requests, from a
    # traceroute. Twenty leaves a 2.0x margin and takes recall from 0.5 to 1.0.
    "IcmpFloodDetector": 20,
    # 1-second window. No benign case reaches even the grid floor of fifty;
    # the busiest is a VoIP stream, 400 datagrams over ten seconds by
    # construction, so forty a second. Seventy-five leaves a 1.9x margin over
    # that and takes recall from 0.5 to 1.0: a moderate flood runs at
    # eighty-three a second, so two hundred only ever saw the heavy one. This
    # is the one threshold the original grid could not have recommended — its
    # step went 50 then 100, and the whole decision lives between them.
    "UdpFloodDetector": 75,
    # 60-second window. Configuration management opening one SSH session per
    # managed host reaches exactly ten, which is the shipped threshold, so it
    # alerts today. Twelve clears it; recall is unchanged, because the
    # low-and-slow attack is below both.
    "SshBruteForceDetector": 12,
}

#: What those three were before, so the timeline can still show the change
#: after it has been applied. Without this the "shipped" row reads the current
#: configuration and compares the recommendation against itself.
PREVIOUS_THRESHOLDS: dict[str, int] = {
    "SynFloodDetector": 100,
    "IcmpFloodDetector": 50,
    "UdpFloodDetector": 200,
    "SshBruteForceDetector": 10,
}

#: Detectors whose benign and malicious ranges *overlap* at their own window,
#: so no threshold separates them. Each maps to the signal that would — a
#: change to the detector rather than to its configuration. Recorded so a
#: future tuning pass does not rediscover them by fitting a threshold to one
#: benign case's volume.
UNSEPARABLE_BY_THRESHOLD: dict[str, str] = {
    "BeaconingDetector": (
        "A health check every ten seconds is as regular as a beacon and "
        "reaches the same count. Needs destination reputation or a "
        "known-good list, not a different count."
    ),
    "DnsTunnelingDetector": (
        "Encoded reputation lookups reach 75 queries a minute; the tunnel "
        "reaches 100. The detector now takes a registered-domain allowlist, "
        "which closes this with one entry — but it ships empty, because the "
        "names worth trusting are a given site's own, so the overlap stands "
        "until an operator fills it in."
    ),
    "DataExfiltrationDetector": (
        "Narrower than it was. The detector now counts only bytes that leave "
        "the estate, so the 50 MB nightly backup to an internal server is out "
        "and a 30 MB staged archive is separable from it. What remains is a "
        "video call, which reaches 20 MB a minute against the archive's 30: "
        "a threshold of 30 MB would catch both attacks with a 1.5x margin, "
        "and 30 MB a minute is four megabits a second, which an ordinary "
        "call or a software update reaches. One corpus case is not enough "
        "evidence for that trade; `allowed_destinations` is."
    ),
    "ArpSpoofingDetector": (
        "Duplicate-address detection after a lease renewal reaches 8 packets "
        "and a light poisoner 6. The shipped threshold of 5 alerts on both, "
        "and is kept: ARP poisoning is worth a false positive that one MAC "
        "allowlist entry removes, and raising it to clear the overlap would "
        "lose the quiet half of the attack."
    ),
    "LateralMovementDetector": (
        "A monitoring server polls 15 hosts and a contained lateral sweep "
        "reaches 12. The shipped threshold of 20 is clean but misses the "
        "smaller sweep; closing that needs to know which hosts are supposed "
        "to fan out."
    ),
}
