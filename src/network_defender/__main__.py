"""
`python -m network_defender`, equivalent to the `network-defender` command.

Exists so the CLI is reachable from a checkout without installing the console
script, which is what a contributor running `uv run python -m network_defender`
expects and what CI uses.
"""

import sys

from .cli.main import main

if __name__ == "__main__":
    sys.exit(main())
