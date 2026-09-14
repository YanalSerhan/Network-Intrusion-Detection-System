"""
Widths for the ORM's string columns.

Named because the same number appearing in six places is
six chances to widen five of them: 45 is the longest possible textual IPv6
address (RFC 4291 §2.2, with an embedded IPv4 suffix), and the rest are
sized to the enums and identifiers they store.
"""

from network_defender.constants import RULE_NAME_MAX_LENGTH

IP_ADDRESS_LENGTH = 45
ENUM_LENGTH = 16
STATUS_LENGTH = 24
GROUP_BY_LENGTH = 32
PROVIDER_LENGTH = 64

#: Sized to the domain limit rather than restating it: how long a rule name
#: may be is a rule about rules, not about storage, and the API bounds its
#: path parameter with the same constant.
RULE_NAME_LENGTH = RULE_NAME_MAX_LENGTH
