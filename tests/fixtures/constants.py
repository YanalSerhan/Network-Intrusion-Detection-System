"""
Addresses and identifiers shared across the test suite.

Tests that talk about "an external attacker" or "a host on the LAN" should use
these rather than inventing an address inline: threat intel eligibility,
lateral-movement detection and enrichment all branch on whether an address is
private, so an ad-hoc literal silently changes what a test exercises.
"""

#: A public address outside every special-purpose range (RFC 6890), so threat
#: intel enrichment considers it eligible for lookup.
PUBLIC_IP = "45.155.205.233"

#: An RFC 1918 address, treated as internal by the detectors and refused by the
#: threat intel eligibility check.
INTERNAL_IP = "10.0.0.5"

#: A second internal address, for internal-to-internal traffic scenarios.
INTERNAL_PEER_IP = "10.0.0.9"
