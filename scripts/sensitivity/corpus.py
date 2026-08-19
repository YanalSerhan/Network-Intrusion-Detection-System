"""
The whole labelled corpus, assembled.

Data Setup:  Nothing.
Data Input:  None.
Data Output: Every case, checked for duplicate names and unknown labels.

Assembly is the place the corpus is validated, because the failure it guards
against is silent: a label naming a detector that does not exist counts as a
false negative in every row forever, and the metrics stay plausible while
measuring nothing.
"""

from . import (
    corpus_arp,
    corpus_baseline,
    corpus_beaconing,
    corpus_credentials,
    corpus_dns,
    corpus_exfil,
    corpus_floods,
    corpus_recon,
)
from .case import Case

MODULES = (
    corpus_recon,
    corpus_floods,
    corpus_credentials,
    corpus_arp,
    corpus_beaconing,
    corpus_dns,
    corpus_exfil,
    corpus_baseline,
)


def build_corpus() -> list[Case]:
    """
    Return every case in the corpus.

    Returns:
        All cases, ordered by module.

    Raises:
        ValueError: If two cases share a name.
    """
    cases: list[Case] = []
    for module in MODULES:
        cases.extend(module.cases())

    names = [case.name for case in cases]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"Duplicate case names in the corpus: {duplicates}")
    return cases


def check_labels(cases: list[Case], known_detectors: set[str]) -> None:
    """
    Fail if any case is labelled with a detector that does not exist.

    Args:
        cases:            The corpus.
        known_detectors:  Names the registry actually loaded.

    Raises:
        ValueError: Naming the unknown labels and the case they came from.
    """
    unknown = sorted(
        f"{case.name} -> {label}"
        for case in cases
        for label in case.expected
        if label not in known_detectors
    )
    if unknown:
        raise ValueError(f"Cases labelled with unknown detectors: {unknown}")


CORPUS = build_corpus()
