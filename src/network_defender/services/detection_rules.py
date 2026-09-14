"""
The signature-rule half of detection.

Data Setup:  A rules directory and the callback matches are delivered through.
Data Input:  Parsed packets.
Data Output: Rule matches, dispatched into the alert pipeline.

Two pipelines run over every packet and they have nothing in common but the
packet: YAML signature rules decide per packet and immediately, while
heuristic detectors accumulate over a window and decide when asked. Holding
both in one class meant its lifecycle methods each carried an `if
self.rule_engine is not None` clause, and the file grew past the limit the
moment anything else was added to either half.

`None` for the rules directory stays meaningful: rule evaluation is optional,
and a service constructed without one runs detectors alone.
"""

import logging
from collections.abc import Callable
from pathlib import Path

from network_defender.parser.models import ParsedPacket
from network_defender.rules.engine import RuleEngine
from network_defender.rules.models import Rule
from network_defender.services.detection_dispatch import dispatch_rule_match

RuleCallback = Callable[[Rule, ParsedPacket], None]


class RuleEvaluation:
    """
    Owns the rule engine's lifecycle and the per-packet evaluation.

    Usage:
        rules = RuleEvaluation(Path("rules"), logger, callback)
        rules.start()
        rules.evaluate(packet)
    """

    def __init__(
        self,
        rules_dir: Path,
        logger: logging.Logger,
        callback: RuleCallback | None = None,
    ) -> None:
        """
        Initialise with a rules directory.

        Args:
            rules_dir: Directory holding YAML signature rules, already resolved.
            logger:    The detection service's logger, so failures appear
                       under the service a reader is looking at.
            callback:  Invoked for each (Rule, ParsedPacket) match.
        """
        self.engine = RuleEngine(str(rules_dir))
        self.callback = callback
        self._logger = logger

    @property
    def rules_loaded(self) -> int:
        """How many enabled rules the loader currently holds."""
        return len(self.engine.loader.registry.get_all_enabled_rules())

    def start(self) -> None:
        """Load the rules and begin watching the directory for changes."""
        self.engine.start()

    def stop(self) -> None:
        """Stop watching and discard aggregation state."""
        self.engine.stop()

    def evaluate(self, packet: ParsedPacket) -> None:
        """
        Evaluate one packet against every enabled rule and dispatch matches.

        A rule is a file an operator edits while the sensor runs, so a broken
        one is an operational event rather than a bug: it is logged and the
        packet moves on, because a bad rule must not stall the pipeline.

        Args:
            packet: The normalised packet emitted by the parser service.
        """
        try:
            matches = self.engine.evaluate(packet)
        except Exception as exc:  # noqa: BLE001 - a bad rule must not stall the pipeline
            self._logger.error("Rule evaluation failed: %s", exc)
            return
        if self.callback is None:
            return
        for rule in matches:
            dispatch_rule_match(rule, packet, self.callback)
