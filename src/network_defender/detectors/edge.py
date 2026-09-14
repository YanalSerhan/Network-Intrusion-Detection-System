"""
Raising a finding once, rather than once per evaluation.

Data Setup:  A set of keys already reported.
Data Input:  A key and whether it currently crosses its threshold.
Data Output: Whether to raise an alert now.

Split from the detector lifecycle because it answers a different question.
That decides what a detector measures; this decides when a measurement
becomes an alert, and the two change for unrelated reasons.

It exists because the windows slide. While state was cleared on every
evaluation, "report everything over the threshold" raised each finding once by
construction. A window that does not clear would raise it again at every
interval — one alert per five seconds for a single burst — which downstream
deduplication would collapse into one row with a wildly inflated occurrence
count, and `occurrences` is supposed to mean "times this was observed".
"""


class EdgeTriggeredMixin:
    """Tracks which keys have already been reported."""

    #: Keys currently over their threshold and already alerted on. Owned here
    #: rather than by each detector so the re-arm rule is written once.
    _reported: set[str]

    def report_once(self, key: str, over_threshold: bool) -> bool:
        """
        Return True only the first time a key crosses its threshold.

        A key re-arms when its measurement falls back below the threshold, so
        a burst that stops and starts again is two findings, which is what an
        analyst would call it.

        The trade is that a *sustained* attack is reported once, at onset,
        rather than heartbeating. That is the right default for a console; a
        periodic reminder while a condition holds belongs in the alert layer
        as a deliberate feature rather than arriving as a side effect of how
        detector state happens to be cleared.

        Args:
            key:            What the finding is about — usually an address.
            over_threshold: Whether it currently crosses.

        Returns:
            True to raise an alert now.
        """
        if not over_threshold:
            self._reported.discard(key)
            return False
        if key in self._reported:
            return False
        self._reported.add(key)
        return True

    def forget_absent(self, live_keys: set[str]) -> None:
        """
        Re-arm keys whose observations have all expired from the window.

        Without this, a host that crossed a threshold and then went silent
        stays marked as reported forever — so when it comes back an hour
        later, the second attack raises nothing.

        Args:
            live_keys: Keys still holding an observation in the window.
        """
        self._reported.intersection_update(live_keys)

    # A key re-arms only when the detector is *asked* while the condition is
    # clear. The service asks every few seconds, so in practice any real gap
    # between two attacks is observed — but if the evaluation loop stalls for
    # longer than the gap, two separate bursts from one host merge into a
    # single alert. Detecting a discontinuity nobody looked at would mean
    # keeping the time of each report and comparing it against the age of the
    # oldest surviving observation, which is more state than the failure is
    # worth while the loop is a timer that cannot silently stop.
