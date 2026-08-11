"""
Reputation aggregation across providers.

Data Setup:  Thresholds from constants; no state.
Data Input:  The ProviderResults collected for one IP address.
Data Output: A single ThreatIntelResult with a merged verdict and attribution.

Scoring
-------
The aggregate score is the **maximum** across providers that expressed an
opinion, not the mean. Threat intel sources have very different coverage: an
address flagged 95/100 by one feed and unknown to three others is still
dangerous, and averaging would dilute that to 24 and hide it. Taking the max
biases toward surfacing the alert and letting the analyst judge — the provider
breakdown is retained so they can see who said what.

Attribution fields (geo, ASN, WHOIS) are merged first-wins, since providers are
consulted in priority order and the first to answer is the most authoritative
for that field.
"""

from network_defender.constants import (
    REPUTATION_MALICIOUS_THRESHOLD,
    REPUTATION_SUSPICIOUS_THRESHOLD,
    ThreatVerdict,
)

from .models import ProviderResult, ThreatIntelResult


def classify(score: float | None) -> ThreatVerdict:
    """
    Turn an aggregate reputation score into a verdict.

    Args:
        score: Aggregate score in [0, 100], or None if nobody had an opinion.

    Returns:
        The corresponding ThreatVerdict.
    """
    if score is None:
        return ThreatVerdict.UNKNOWN
    if score >= REPUTATION_MALICIOUS_THRESHOLD:
        return ThreatVerdict.MALICIOUS
    if score >= REPUTATION_SUSPICIOUS_THRESHOLD:
        return ThreatVerdict.SUSPICIOUS
    return ThreatVerdict.CLEAN


def aggregate(ip: str, results: list[ProviderResult]) -> ThreatIntelResult:
    """
    Merge every provider result for one address into a single record.

    Args:
        ip:      The enriched address.
        results: All ProviderResults gathered for it, successful or not.

    Returns:
        A ThreatIntelResult with the merged verdict, score and attribution.
    """
    aggregated = ThreatIntelResult(ip=ip)
    scores: list[float] = []

    for result in results:
        aggregated.providers_queried.append(result.provider)

        if not result.succeeded:
            aggregated.providers_failed.append(result.provider)
            continue

        if result.reputation_score is not None:
            scores.append(result.reputation_score)

        # First provider to supply a field wins; later ones do not overwrite.
        if result.geo is not None and aggregated.geo is None:
            aggregated.geo = result.geo
        if result.asn is not None and aggregated.asn is None:
            aggregated.asn = result.asn
        if result.whois is not None and aggregated.whois is None:
            aggregated.whois = result.whois

    aggregated.reputation_score = max(scores) if scores else None
    aggregated.verdict = classify(aggregated.reputation_score)
    return aggregated
