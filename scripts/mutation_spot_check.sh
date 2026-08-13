#!/usr/bin/env bash
#
# Mutation spot check over the detector implementations.
#
# Mutation testing answers the question coverage cannot: the suite executed
# this line, but would it have noticed if the line were wrong? It is scoped to
# detectors/ because that is where a weakened test is most expensive — a
# detector that quietly stops detecting still satisfies every assertion about
# the alerts it does raise.
#
# This is a spot check, not a gate: it takes minutes, not seconds, and a
# surviving mutant is a question to answer rather than a build to fail. See
# docs/TESTING.md for how to read the output.
#
# Usage:
#   scripts/mutation_spot_check.sh            # run, then list survivors
#   scripts/mutation_spot_check.sh <mutant>   # show one mutant's diff

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ $# -gt 0 ]]; then
    exec uv run mutmut show "$1"
fi

uv run mutmut run --max-children "${MUTMUT_CHILDREN:-4}"

echo
echo "Surviving mutants (each is a change no test objected to):"
uv run mutmut results
