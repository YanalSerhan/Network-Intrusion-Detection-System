# Naming conventions

Enforced where a linter can (ruff's `N` rules cover casing; `D` rules cover
docstrings). The rest is here because it is the part a reviewer has to hold,
and an unwritten convention lasts until the first person who has not read the
codebase.

## One word per concept

The point is not that any particular word is better. It is that searching for
a concept should find all of it.

| Concept | Word | Not |
|---|---|---|
| A packet, raw or parsed | `packet` | `pkt`, `p`, `frame` |
| Configuration object | `config` | `cfg`, `conf`, `settings` |
| Threat intelligence | `threat_intel` | `ti`, `intel` |
| A timestamp | `timestamp` | `ts`, `time` (which is also a module) |
| Database session factory | `session_factory` | `sessionmaker`, `factory` |

`packet` covers both the Scapy packet and the `ParsedPacket` it becomes. The
types already distinguish them; a second name for the same idea only makes the
grep incomplete.

## Verbs mean specific things

| Prefix | Returns | Example |
|---|---|---|
| `get_` | One thing, or `None` | `get_alert(alert_id)` |
| `list_` | Many things, possibly empty | `list_alerts(severity=...)` |
| `load_` | Something read from disk or environment | `load_app_config()` |
| `build_` | A constructed object, no I/O | `build_snapshot_payload(...)` |
| `start_` / `stop_` | Nothing; changes lifecycle state | `start_capture()` |
| `record_` | Nothing; writes an observation | `record_statistics_snapshot()` |

A `get_` that returns a list, or a `list_` that raises when empty, is the kind
of thing nobody notices until they are debugging at two in the morning.

## Names say what, not how

`_src_dst_timestamps` says what it holds. `_data`, `_map`, `_tmp` and `_obj`
say only that the author had not decided yet. Abbreviations are acceptable
where the domain uses them — `ip`, `dns`, `tcp`, `arp`, `sni`, `pcap` — and
nowhere else.

Private helpers take a leading underscore. Anything without one is API that
something outside the module may be relying on.

## Detector naming

A detector class ends in `Detector` and its configuration ends in `Config`,
sharing the stem: `SynFloodDetector` and `SynFloodConfig`. This is not
cosmetic — the registry resolves a detector's config class by that convention
when the type annotation cannot be read directly, which is what happens when a
family of detectors inherits one generic `__init__`. Breaking the convention
un-registers the detector silently.

## Tests

A test's name is its claim: `test_syn_ack_replies_are_not_a_syn_scan` states
what must be true. `test_syn_scan_2` states nothing, and when it fails nobody
can tell whether the code or the test is wrong. See `docs/TESTING.md`.

## File length

ADR 4 caps a source file at 150 lines, and `tests/unit/test_file_length_limit.py`
enforces it — one parametrised case per file, so a failure names the file and
its length rather than reporting "something is too long".

The number is a proxy. A file past a screen and a half is usually holding two
concerns, and splitting it is easy at 160 lines and miserable at 600. When a
file trips the limit, split it by concern; do not raise the limit.

Migrations are exempt. A migration is a historical record of what the schema
was, and reformatting one to satisfy a rule adopted later would falsify it.
