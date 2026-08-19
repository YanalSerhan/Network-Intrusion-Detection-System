"""
Tests that the labelled corpus stays a corpus rather than becoming a fixture set.

Every check here guards a failure that is invisible in the results. A label
naming a detector that no longer exists is counted as a permanent false
negative; a detector with no benign case that competes with it scores a
precision of 1.0 for free; and a positive case nothing could ever miss makes a
recall curve flat. In all three the numbers stay plausible while measuring
progressively less.
"""

import pytest
from sensitivity.corpus import CORPUS, check_labels
from sensitivity.detectors import detector_names
from sensitivity.grid import THRESHOLDS, UNSWEPT


def test_every_label_names_a_detector_the_registry_loads() -> None:
    check_labels(CORPUS, set(detector_names()))


def test_an_unknown_label_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown detectors"):
        check_labels(CORPUS, {"TcpPortScanDetector"})


def test_case_names_are_unique() -> None:
    names = [case.name for case in CORPUS]

    assert len(names) == len(set(names))


def test_the_corpus_has_both_positive_and_negative_cases() -> None:
    positives = [case for case in CORPUS if case.is_positive]
    negatives = [case for case in CORPUS if not case.is_positive]

    assert len(positives) >= 20
    assert len(negatives) >= 20


@pytest.mark.parametrize("detector", sorted(THRESHOLDS))
def test_every_swept_detector_has_at_least_two_positive_cases(detector: str) -> None:
    positives = [case for case in CORPUS if detector in case.expected]

    assert len(positives) >= 2, (
        f"{detector} has {len(positives)} positive cases. A recall curve drawn "
        f"from fewer than two intensities cannot show where it starts to miss."
    )


def test_every_detector_the_registry_loads_is_either_swept_or_named_unswept() -> None:
    covered = set(THRESHOLDS) | set(UNSWEPT)

    assert set(detector_names()) == covered


def test_every_case_explains_why_it_is_in_the_corpus() -> None:
    unexplained = [case.name for case in CORPUS if len(case.note) < 40]

    assert not unexplained, f"Cases with no stated purpose: {unexplained}"
