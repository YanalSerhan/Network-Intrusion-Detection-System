"""
Pydantic models for the rule engine schema.

Data Setup:  Loaded from YAML files.
Data Input:  Raw dicts parsed from YAML.
Data Output: Validated Rule objects.
"""

from typing import Any

from pydantic import BaseModel, Field

from network_defender.constants import Severity


class RuleCondition(BaseModel):
    """
    A single condition to evaluate against a parsed packet.
    """
    field: str = Field(
        description="The packet field to evaluate (e.g. 'protocol', 'tcp_flags.syn')."
    )
    operator: str = Field(
        description="The comparison operator (equals, not_equals, greater_than, less_than, regex)."
    )
    value: Any = Field(description="The value to compare against.")

class Rule(BaseModel):
    """
    A complete detection rule.
    """
    name: str = Field(description="Unique name of the rule.")
    severity: Severity = Field(description="Severity if this rule matches.")
    enabled: bool = Field(default=True, description="Whether the rule is actively evaluated.")
    window: int = Field(
        default=0,
        ge=0,
        description="Time window in seconds for aggregation (0 means single-packet match).",
    )
    threshold: int = Field(
        default=1,
        ge=1,
        description=(
            "Matches required within `window` before the rule fires. "
            "1 (the default) means every matching packet fires immediately."
        ),
    )
    group_by: str = Field(
        default="src_ip",
        description="ParsedPacket field the window aggregates on (e.g. 'src_ip', 'dst_ip').",
    )
    conditions: list[RuleCondition] = Field(
        min_length=1, description="List of conditions that must ALL be true (AND logic)."
    )

    @property
    def is_aggregated(self) -> bool:
        """True if this rule only fires after repeated matches inside a window."""
        return self.window > 0 and self.threshold > 1
