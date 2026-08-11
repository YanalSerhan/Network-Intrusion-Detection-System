"""
RDAP registration-data (WHOIS) provider.

Data Setup:  Keyless; uses the 'whois' gatekeeper bucket.
Data Input:  A public IP address.
Data Output: ProviderResult carrying network registration details.

Endpoint: GET https://rdap.org/ip/{ip}
Docs:     https://rdap.org / RFC 9083

RDAP is used in preference to port-43 WHOIS: it returns structured JSON over
HTTPS, so it can share the same gatekeeper-mediated HTTP path as every other
provider, whereas classic WHOIS needs a raw TCP socket and free-text parsing
that differs per registry.
"""

from typing import Any

from network_defender.constants import ProviderStatus

from ..base import ThreatIntelProvider
from ..http import get_json
from ..models import ProviderResult, WhoisInfo

RDAP_URL = "https://rdap.org/ip/{ip}"


class RdapWhoisProvider(ThreatIntelProvider):
    """Looks up the registered network block containing an address."""

    @property
    def name(self) -> str:
        """Provider name; matches the 'whois' key in config/rate_limits.json."""
        return "whois"

    def lookup(self, ip: str) -> ProviderResult:
        """
        Fetch registration data for an address.

        Args:
            ip: A public IP address.

        Returns:
            ProviderResult with `whois` populated, or status ERROR on failure.
        """
        try:
            payload = self.gatekeeper.execute(get_json, RDAP_URL.format(ip=ip))
        except Exception as exc:  # noqa: BLE001 - providers must never raise
            return self._error(str(exc))

        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            whois=WhoisInfo(
                network_name=payload.get("name"),
                cidr=self._cidr(payload),
                registry=(payload.get("port43") or "").split(".")[-2:][0] or None,
                registrant=self._registrant(payload),
                abuse_email=self._abuse_email(payload),
                registered_on=self._event_date(payload, "registration"),
            ),
        )

    @staticmethod
    def _cidr(payload: dict[str, Any]) -> str | None:
        """Extract the allocated CIDR block, preferring the explicit cidr0 form."""
        blocks = payload.get("cidr0_cidrs")
        if isinstance(blocks, list) and blocks:
            first = blocks[0]
            if isinstance(first, dict):
                prefix = first.get("v4prefix") or first.get("v6prefix")
                length = first.get("length")
                if prefix and length is not None:
                    return f"{prefix}/{length}"

        start, end = payload.get("startAddress"), payload.get("endAddress")
        return f"{start} - {end}" if start and end else None

    @staticmethod
    def _registrant(payload: dict[str, Any]) -> str | None:
        """Return the first entity's organisation name, if present."""
        for entity in payload.get("entities", []) or []:
            if isinstance(entity, dict) and entity.get("handle"):
                return str(entity["handle"])
        return None

    @staticmethod
    def _abuse_email(payload: dict[str, Any]) -> str | None:
        """Find the abuse contact address in the vCard of an abuse-role entity."""
        for entity in payload.get("entities", []) or []:
            if not isinstance(entity, dict) or "abuse" not in (entity.get("roles") or []):
                continue
            vcard = entity.get("vcardArray")
            if not (isinstance(vcard, list) and len(vcard) > 1):
                continue
            for field in vcard[1]:
                if isinstance(field, list) and len(field) >= 4 and field[0] == "email":
                    return str(field[3])
        return None

    @staticmethod
    def _event_date(payload: dict[str, Any], action: str) -> str | None:
        """Return the date of the named RDAP event (e.g. 'registration')."""
        for event in payload.get("events", []) or []:
            if isinstance(event, dict) and event.get("eventAction") == action:
                date = event.get("eventDate")
                return str(date) if date else None
        return None
