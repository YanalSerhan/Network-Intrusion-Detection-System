"""
Rule discovery and hot-reloading.

Data Setup:  Reads rules from YAML files in the configured directory.
             Uses watchdog to listen for file system changes.
Data Input:  YAML file paths.
Data Output: Active Rule objects accessible via a thread-safe registry.
"""

import logging
import threading
from pathlib import Path
from typing import Optional

import yaml
from pydantic import ValidationError
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from network_defender.rules.models import Rule

logger = logging.getLogger(__name__)


class RuleRegistry:
    """Thread-safe registry for active rules."""

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}
        self._lock = threading.Lock()

    def set_rule(self, filepath: str, rule: Rule) -> None:
        """Add or update a rule in the registry."""
        with self._lock:
            self._rules[filepath] = rule

    def remove_rule(self, filepath: str) -> None:
        """Remove a rule from the registry."""
        with self._lock:
            self._rules.pop(filepath, None)

    def get_all_enabled_rules(self) -> list[Rule]:
        """Return a snapshot of all currently enabled rules."""
        with self._lock:
            return [r for r in self._rules.values() if r.enabled]


def _load_rule_file(filepath: str, registry: RuleRegistry) -> None:
    """Parse a YAML file and register the rule if valid."""
    try:
        with open(filepath, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            logger.error(f"Rule file {filepath} must contain a YAML dictionary.")
            return

        rule = Rule.model_validate(data)
        registry.set_rule(filepath, rule)
        logger.info(f"Successfully loaded rule '{rule.name}' from {filepath}")
    except ValidationError as e:
        logger.error(f"Schema validation failed for {filepath}: {e}")
    except Exception as e:
        logger.error(f"Failed to load rule from {filepath}: {e}")


class RuleFileHandler(FileSystemEventHandler):
    """Watchdog handler that reloads rules on file changes."""

    def __init__(self, registry: RuleRegistry) -> None:
        super().__init__()
        self.registry = registry

    def _get_src_path(self, event: FileSystemEvent) -> str:
        """Ensure src_path is a string."""
        return event.src_path.decode("utf-8") if isinstance(event.src_path, bytes) else event.src_path

    def on_created(self, event: FileSystemEvent) -> None:
        """Handle new rule file."""
        src_path = self._get_src_path(event)
        if not event.is_directory and src_path.endswith(".yaml"):
            _load_rule_file(src_path, self.registry)

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle modified rule file."""
        src_path = self._get_src_path(event)
        if not event.is_directory and src_path.endswith(".yaml"):
            _load_rule_file(src_path, self.registry)

    def on_deleted(self, event: FileSystemEvent) -> None:
        """Handle deleted rule file."""
        src_path = self._get_src_path(event)
        if not event.is_directory and src_path.endswith(".yaml"):
            logger.info(f"Rule file deleted: {src_path}")
            self.registry.remove_rule(src_path)


class RuleLoader:
    """Discovers rules and watches for changes."""

    def __init__(self, rules_dir: str) -> None:
        self.rules_dir = Path(rules_dir)
        self.registry = RuleRegistry()
        self._observer: Optional[BaseObserver] = None

    def start(self) -> None:
        """Load initial rules and start watching for changes."""
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory {self.rules_dir} does not exist. Creating it.")
            self.rules_dir.mkdir(parents=True, exist_ok=True)

        # Initial load
        for filepath in self.rules_dir.glob("*.yaml"):
            _load_rule_file(str(filepath), self.registry)

        # Start watchdog
        handler = RuleFileHandler(self.registry)
        self._observer = Observer()
        self._observer.schedule(handler, str(self.rules_dir), recursive=False)
        self._observer.start()
        logger.info(f"Started watching {self.rules_dir} for rule changes.")

    def stop(self) -> None:
        """Stop watching for file changes."""
        if self._observer:
            self._observer.stop()
            self._observer.join()
            logger.info("Stopped watching rules directory.")
