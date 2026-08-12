"""
Type coercion for environment variable overrides.

Data Setup:  None; pure functions driven by the target model's annotations.
Data Input:  A raw environment string and the declared type of its field.
Data Output: A value of that type, or the original string when no rule applies.

Environment variables are always strings. Handing them to Pydantic unchanged
would make `ND__API__PORT=9000` the string "9000" and, worse,
`ND__CAPTURE__PROMISCUOUS_MODE=false` a truthy string — silently enabling what
an operator meant to switch off.

Unparseable values are returned as-is rather than defaulted, so validation
reports the bad input against the field the operator actually set.
"""

import json
from typing import Any

from pydantic import BaseModel

TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def coerce(raw: str, annotation: Any) -> Any:
    """
    Convert an environment string to the type the model expects.

    Args:
        raw:        The environment value.
        annotation: The field's declared type, or None if unknown.

    Returns:
        The coerced value; the original string when no rule applies.
    """
    text = raw.strip()

    if annotation is bool:
        lowered = text.lower()
        if lowered in TRUE_VALUES:
            return True
        if lowered in FALSE_VALUES:
            return False
        return text

    if annotation is int:
        return int(text) if _looks_numeric(text) else text
    if annotation is float:
        return float(text) if _looks_numeric(text) else text

    if annotation in (list, dict) or str(annotation).startswith(("list", "dict")):
        return _coerce_collection(text)

    return text


def _coerce_collection(text: str) -> Any:
    """
    Parse a list or dict value, accepting JSON or a comma-separated list.

    JSON is tried first because it is the only form that can express a dict or
    nested values; the comma fallback exists because `a,b,c` is far easier to
    type in a shell than `["a","b","c"]` with its quoting.
    """
    try:
        return json.loads(text)
    except ValueError:
        return [item.strip() for item in text.split(",") if item.strip()]


def _looks_numeric(text: str) -> bool:
    """Return True if the text parses as a number."""
    try:
        float(text)
    except ValueError:
        return False
    return True


def field_annotation(model: type[BaseModel], section: str, key: str) -> Any:
    """
    Return the declared type of `section.key`, or None if unknown.

    Args:
        model:   The top-level config model.
        section: Name of the nested section, e.g. "capture".
        key:     Field name within that section.

    Returns:
        The annotation, or None when either level does not exist.
    """
    section_field = model.model_fields.get(section)
    if section_field is None:
        return None

    nested = section_field.annotation
    if isinstance(nested, type) and issubclass(nested, BaseModel):
        field = nested.model_fields.get(key)
        return field.annotation if field else None
    return None
