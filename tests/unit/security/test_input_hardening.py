"""
Tests for the request-supplied values that reach a lookup, a log or a browser.

The API's typed parameters do most of this work already — a severity is an
enum, a page size is a bounded int, an alert ID is a UUID — so FastAPI rejects
malformed input before a route body runs. What is tested here is the handful
of places that took free text, plus the headers that limit the damage if
something else fails.
"""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from network_defender.api.security_headers import SECURITY_HEADERS
from network_defender.parser.models import ParsedPacket
from network_defender.rules.evaluator import _get_field_value
from network_defender.rules.models import MAX_PATTERN_LENGTH, RuleCondition
from tests.fixtures.builders import make_packet

ALERTS = "/api/v1/alerts"
RULES = "/api/v1/rules"


def test_a_rule_cannot_name_a_private_attribute() -> None:
    """
    Field paths are resolved with getattr, so `__class__` walks out of the packet.

    A rule file is exactly the kind of thing someone copies from a blog post,
    which makes this a real way in rather than a theoretical one.
    """
    with pytest.raises(ValidationError, match="private attribute"):
        RuleCondition(field="__class__.__init__.__globals__", operator="equals", value="x")


def test_the_evaluator_refuses_private_attributes_on_its_own_terms() -> None:
    """
    Belt and braces: the lookup is safe even if a caller skipped validation.

    This is the function that turns a string from a file into an attribute
    access, so it should not be safe only because something else checked.
    """
    packet: ParsedPacket = make_packet()

    assert _get_field_value(packet, "__class__") is None
    assert _get_field_value(packet, "src_ip") is not None


def test_a_broken_regex_fails_when_the_rule_loads_not_when_a_packet_arrives() -> None:
    """
    Compile at load time, not at match time.

    A pattern that only fails on a matching packet fails on the detection
    thread, mid-traffic, once per packet.
    """
    with pytest.raises(ValidationError, match="Invalid regex"):
        RuleCondition(field="http.path", operator="regex", value="(unclosed")


def test_an_absurdly_long_pattern_is_refused() -> None:
    """A pattern this long is far likelier to be a mistake than an intention."""
    with pytest.raises(ValidationError, match="exceeds"):
        RuleCondition(field="http.path", operator="regex", value="a" * (MAX_PATTERN_LENGTH + 1))


def test_a_valid_regex_rule_still_loads() -> None:
    """The guards must not have made the operator unusable."""
    condition = RuleCondition(field="http.path", operator="regex", value=r"/admin/\d+")

    assert condition.operator == "regex"


def test_an_over_long_rule_name_is_rejected(client: TestClient) -> None:
    """
    Unbounded free text is reflected in a 404 body and written to a log line.

    Neither is an injection — the response is JSON and the log is
    JSON-encoded — but both are work an caller should not be able to request
    by the megabyte.
    """
    response = client.get(f"{RULES}/{'x' * 5000}")

    assert response.status_code == 422


@pytest.mark.parametrize("header", sorted(SECURITY_HEADERS))
def test_security_headers_are_present(client: TestClient, header: str) -> None:
    """Defence in depth: what a browser will do with our output, constrained."""
    response = client.get(ALERTS)

    assert response.headers.get(header) == SECURITY_HEADERS[header]


def test_the_content_security_policy_forbids_inline_script(client: TestClient) -> None:
    """
    A policy permitting `unsafe-inline` permits the thing it exists to stop.

    Worse than no policy, because it reads like protection. The dashboard is
    built into hashed bundles with no inline script, so it does not need it.
    """
    policy = client.get(ALERTS).headers["Content-Security-Policy"]

    assert "unsafe-inline" not in policy.split("script-src")[-1].split(";")[0]
    assert "default-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy


def test_a_malformed_alert_id_is_rejected_before_any_lookup(client: TestClient) -> None:
    """The path type is the validation; nothing hand-parses an identifier."""
    response = client.get(f"{ALERTS}/not-a-uuid")

    assert response.status_code == 422
