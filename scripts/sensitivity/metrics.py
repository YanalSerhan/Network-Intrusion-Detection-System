"""
Turning fired/did-not-fire counts into the rates the milestone asks for.

Data Setup:  Nothing.
Data Input:  Counts of the four outcomes.
Data Output: Precision, recall, F1 and false-positive rate.

Each rate is `None` rather than `0.0` when its denominator is empty, and the
distinction is load-bearing. A detector configured so high that it never fires
has no precision — there is nothing it claimed to be right about — and
recording that as zero puts it on a chart next to a detector that fired
constantly and was always wrong. They are opposite failures, and a reader
choosing a threshold needs to tell them apart.
"""

from dataclasses import dataclass


def _ratio(numerator: int, denominator: int) -> float | None:
    """Return the ratio, or None when the denominator is empty."""
    return numerator / denominator if denominator else None


@dataclass(frozen=True)
class Confusion:
    """One detector's outcomes over the whole corpus at one grid point."""

    #: Cases labelled for this detector on which it fired.
    true_positives: int = 0

    #: Cases not labelled for it on which it fired anyway.
    false_positives: int = 0

    #: Cases labelled for it on which it stayed silent.
    false_negatives: int = 0

    #: Cases not labelled for it on which it correctly stayed silent.
    true_negatives: int = 0

    def record(self, expected: bool, fired: bool) -> "Confusion":
        """
        Return a copy with one more observation folded in.

        Args:
            expected: Whether this case is labelled for the detector.
            fired:    Whether the detector raised an alert on it.

        Returns:
            A new Confusion; the type is frozen so a partially-updated
            tally cannot be read by mistake.
        """
        return Confusion(
            true_positives=self.true_positives + (expected and fired),
            false_positives=self.false_positives + (not expected and fired),
            false_negatives=self.false_negatives + (expected and not fired),
            true_negatives=self.true_negatives + (not expected and not fired),
        )

    @property
    def precision(self) -> float | None:
        """Share of alerts that were correct; None when it never fired."""
        return _ratio(self.true_positives, self.true_positives + self.false_positives)

    @property
    def recall(self) -> float | None:
        """Share of attacks caught; None when the corpus has no positives."""
        return _ratio(self.true_positives, self.true_positives + self.false_negatives)

    @property
    def false_positive_rate(self) -> float | None:
        """Share of benign cases alerted on; None when there are none."""
        return _ratio(self.false_positives, self.false_positives + self.true_negatives)

    @property
    def f1(self) -> float | None:
        """
        Harmonic mean of precision and recall.

        Returns:
            The score, or None when either input is undefined or both are
            zero — a detector that caught nothing has no balance to strike.
        """
        precision, recall = self.precision, self.recall
        if precision is None or recall is None or precision + recall == 0:
            return None
        return 2 * precision * recall / (precision + recall)
