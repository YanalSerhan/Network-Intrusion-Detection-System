"""
Rule-related SDK operations.

Data Setup:  Expects the composing class to own `_detection_service` and
             `_database_service`.
Data Input:  Rule names and desired enabled state.
Data Output: Rule snapshots as plain dicts for the API layer.

Toggling is a runtime override. It updates the rule in the running engine (when
this process has one) and the database snapshot, but never rewrites the YAML
file: a service that edits its own config fights hot-reload and diverges from
what an operator committed. The override is cleared by a reload.
"""

from typing import Any

from ..database.mappers_rules import rule_record_to_dict
from ..services.database import DatabaseService
from ..services.detection import DetectionService
from ..shared.base import LoggableMixin


class RuleOperationsMixin(LoggableMixin):
    """Rule inspection and runtime-toggle surface of the SDK."""

    _detection_service: DetectionService
    _database_service: DatabaseService

    def get_rule(self, name: str) -> dict[str, Any] | None:
        """
        Return one rule from the snapshot.

        Args:
            name: The rule name.

        Returns:
            The rule as a dict, or None if it is not loaded.
        """
        record = self._database_service.rules.get(name)
        if record is None:
            return None
        return rule_record_to_dict(record)

    def set_rule_enabled(self, name: str, enabled: bool) -> dict[str, Any] | None:
        """
        Enable or disable a rule at runtime.

        Args:
            name:    The rule to toggle.
            enabled: Desired state.

        Returns:
            The updated rule, or None if it is not loaded.
        """
        record = self._database_service.rules.get(name)
        if record is None:
            return None

        self._database_service.rules.set_enabled(name, enabled)
        self._apply_to_engine(name, enabled)

        updated = self._database_service.rules.get(name)
        return rule_record_to_dict(updated) if updated is not None else None

    def reload_rules(self) -> int:
        """
        Re-read rules from disk and refresh the snapshot.

        Clears runtime overrides, since the files are the source of truth.

        Returns:
            Number of rules loaded.
        """
        engine = self._detection_service.rule_engine
        if engine is None:
            return self._database_service.rules.count()

        engine.stop()
        engine.start()
        rules = engine.loader.registry.get_all_enabled_rules()
        self._database_service.rules.sync(rules)
        return len(rules)

    def _apply_to_engine(self, name: str, enabled: bool) -> None:
        """Mirror a toggle onto the in-memory rule set, when one is running."""
        engine = self._detection_service.rule_engine
        if engine is None:
            return
        for rule in engine.loader.registry.get_all_rules():
            if rule.name == name:
                rule.enabled = enabled

