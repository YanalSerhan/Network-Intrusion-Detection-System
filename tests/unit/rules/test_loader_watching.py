"""
Tests for hot reload: what the filesystem watcher does with each event.

Rules are edited on a live sensor, so the watcher sees every kind of event a
directory produces — creations, saves, deletions, directories, editor swap
files. Only YAML files may be acted on, and a broken one must cost its own
rule rather than the running rule set.
"""

from pathlib import Path

import pytest
from watchdog.events import DirCreatedEvent, FileCreatedEvent, FileDeletedEvent, FileModifiedEvent

from network_defender.rules.loader import RuleFileHandler, RuleLoader, RuleRegistry

VALID_RULE = """
name: Test Rule
severity: high
enabled: true
conditions:
  - field: protocol
    operator: equals
    value: tcp
"""


@pytest.fixture()
def watched(tmp_path: Path) -> tuple[RuleRegistry, RuleFileHandler, Path]:
    """A registry, a handler over it, and the directory they are watching."""
    registry = RuleRegistry()
    return registry, RuleFileHandler(registry), tmp_path


def test_a_new_rule_file_is_loaded(watched: tuple[RuleRegistry, RuleFileHandler, Path]) -> None:
    registry, handler, directory = watched
    path = directory / "new.yaml"
    path.write_text(VALID_RULE)

    handler.on_created(FileCreatedEvent(str(path)))

    assert [rule.name for rule in registry.get_all_enabled_rules()] == ["Test Rule"]


def test_an_edited_rule_file_is_reloaded(
    watched: tuple[RuleRegistry, RuleFileHandler, Path],
) -> None:
    registry, handler, directory = watched
    path = directory / "edit.yaml"
    path.write_text(VALID_RULE)
    handler.on_created(FileCreatedEvent(str(path)))

    path.write_text(VALID_RULE.replace("Test Rule", "Renamed Rule"))
    handler.on_modified(FileModifiedEvent(str(path)))

    assert [rule.name for rule in registry.get_all_enabled_rules()] == ["Renamed Rule"]


def test_a_deleted_rule_file_stops_matching(
    watched: tuple[RuleRegistry, RuleFileHandler, Path],
) -> None:
    """A rule deleted on disk must stop firing without a restart."""
    registry, handler, directory = watched
    path = directory / "gone.yaml"
    path.write_text(VALID_RULE)
    handler.on_created(FileCreatedEvent(str(path)))

    handler.on_deleted(FileDeletedEvent(str(path)))

    assert registry.get_all_enabled_rules() == []


def test_non_yaml_files_are_ignored(watched: tuple[RuleRegistry, RuleFileHandler, Path]) -> None:
    """Editors litter the directory with swap and backup files."""
    registry, handler, directory = watched
    path = directory / "rule.yaml.swp"
    path.write_text(VALID_RULE)

    handler.on_created(FileCreatedEvent(str(path)))
    handler.on_modified(FileModifiedEvent(str(path)))
    handler.on_deleted(FileDeletedEvent(str(path)))

    assert registry.get_all_enabled_rules() == []


def test_directory_events_are_ignored(
    watched: tuple[RuleRegistry, RuleFileHandler, Path],
) -> None:
    registry, handler, directory = watched
    subdirectory = directory / "nested.yaml"
    subdirectory.mkdir()

    handler.on_created(DirCreatedEvent(str(subdirectory)))

    assert registry.get_all_enabled_rules() == []


def test_byte_paths_are_decoded(watched: tuple[RuleRegistry, RuleFileHandler, Path]) -> None:
    """Watchdog reports bytes on some platforms; the handler must cope."""
    registry, handler, directory = watched
    path = directory / "bytes.yaml"
    path.write_text(VALID_RULE)

    handler.on_created(FileCreatedEvent(str(path).encode()))

    assert [rule.name for rule in registry.get_all_enabled_rules()] == ["Test Rule"]


def test_a_missing_rules_directory_is_created(tmp_path: Path) -> None:
    """A fresh install has no rules/; starting must not fail on that."""
    rules_dir = tmp_path / "rules"
    loader = RuleLoader(str(rules_dir))

    loader.start()
    try:
        assert rules_dir.is_dir()
        assert loader.registry.get_all_enabled_rules() == []
    finally:
        loader.stop()
