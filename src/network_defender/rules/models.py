"""
Pydantic models for the rule engine schema.

Data Setup:  Loaded from YAML files.
Data Input:  Raw dicts parsed from YAML.
Data Output: Validated Rule objects.
"""

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

from network_defender.constants import Severity

#: Longest regex a rule may carry. Not a security boundary on its own — it
#: bounds how much work one pattern can describe, and a pattern this long is
#: far likelier to be a mistake than an intention.
MAX_PATTERN_LENGTH = 512

#: Longest string a regex condition will be run against. Catastrophic
#: backtracking is superlinear in subject length, so capping the subject caps
#: the damage a badly-written rule can do to the detection thread — and the
#: fields rules match on (hostnames, paths, user agents) are all far shorter.
MAX_REGEX_SUBJECT_LENGTH = 4096


class RuleCondition(BaseModel):
    """A single condition to evaluate against a parsed packet."""

    field: str = Field(
        description="The packet field to evaluate (e.g. 'protocol', 'tcp_flags.syn')."
    )
    operator: str = Field(
        description="The comparison operator (equals, not_equals, greater_than, less_than, regex)."
    )
    value: Any = Field(description="The value to compare against.")

    @field_validator("field")
    @classmethod
    def _reject_private_attributes(cls, value: str) -> str:
        """
        Refuse field paths that reach into an object's internals.

        The evaluator resolves a dotted path with getattr, so without this a
        rule naming `__class__.__init__.__globals__` walks out of the packet
        and into the interpreter. Rule files are exactly the kind of thing
        someone copies from a blog post, so this is a real path in.
        """
        if any(part.startswith("_") for part in value.split(".")):
            raise ValueError(
                f"Field path '{value}' reaches a private attribute. Rules may only "
                f"name public fields of ParsedPacket."
            )
        return value

    @field_validator("value")
    @classmethod
    def _validate_pattern(cls, value: Any, info: Any) -> Any:
        """
        Compile a regex condition's pattern at load time.

        A pattern that only fails when a matching packet arrives fails on the
        detection thread, mid-traffic, once per packet. Compiling here means a
        broken rule is a startup error naming the rule instead.
        """
        if info.data.get("operator") != "regex":
            return value
        pattern = str(value)
        if len(pattern) > MAX_PATTERN_LENGTH:
            raise ValueError(f"Regex exceeds {MAX_PATTERN_LENGTH} characters.")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid regex '{pattern}': {exc}") from exc
        return value

class Rule(BaseModel):
    """A complete detection rule, as loaded from one YAML file."""

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
