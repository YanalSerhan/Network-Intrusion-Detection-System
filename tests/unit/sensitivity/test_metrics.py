"""
Tests for the confusion tally the sweep reports through.

Proves the part that is easy to get quietly wrong: an undefined rate must stay
undefined rather than collapsing to zero, because a detector that never fires
and one that fires and is always wrong are opposite failures.
"""

import pytest
from sensitivity.metrics import Confusion


def test_recording_an_outcome_returns_a_new_tally() -> None:
    original = Confusion()

    updated = original.record(expected=True, fired=True)

    assert original.true_positives == 0
    assert updated.true_positives == 1


def test_each_outcome_lands_in_its_own_bucket() -> None:
    tally = Confusion()

    tally = tally.record(expected=True, fired=True)
    tally = tally.record(expected=False, fired=True)
    tally = tally.record(expected=True, fired=False)
    tally = tally.record(expected=False, fired=False)

    assert (tally.true_positives, tally.false_positives) == (1, 1)
    assert (tally.false_negatives, tally.true_negatives) == (1, 1)


def test_precision_is_none_when_the_detector_never_fired() -> None:
    tally = Confusion(false_negatives=3, true_negatives=5)

    assert tally.precision is None


def test_precision_is_zero_when_every_alert_was_wrong() -> None:
    tally = Confusion(false_positives=4, false_negatives=1)

    assert tally.precision == 0.0


def test_recall_is_none_when_the_corpus_has_no_positives() -> None:
    tally = Confusion(false_positives=2, true_negatives=8)

    assert tally.recall is None


def test_false_positive_rate_counts_only_negative_cases() -> None:
    tally = Confusion(true_positives=5, false_positives=1, true_negatives=3)

    assert tally.false_positive_rate == 0.25


def test_f1_is_the_harmonic_mean() -> None:
    tally = Confusion(true_positives=6, false_positives=2, false_negatives=4)

    assert tally.precision == 0.75
    assert tally.recall == 0.6
    assert tally.f1 == pytest.approx(2 * 0.75 * 0.6 / (0.75 + 0.6))


def test_f1_is_none_when_nothing_was_caught() -> None:
    tally = Confusion(false_positives=3, false_negatives=3)

    assert tally.f1 is None

