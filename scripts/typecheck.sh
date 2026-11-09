#!/bin/sh
# Type-check the sources AND the tests, including the extensionless CLI.
#
# mypy only reads .py files by name, so scripts/hiddenforge is copied to a
# temp .py first. Run from the repository root:
#
#     sh scripts/typecheck.sh
#     MYPY=/path/to/mypy sh scripts/typecheck.sh     # or point at a venv
#
# The checked set is deliberately wide: the project's old invocation covered
# three files and passed while the tests carried real arg-type errors.
set -eu

MYPY="${MYPY:-mypy}"
tmp="${TMPDIR:-/tmp}/hiddenforge-cli-typecheck.py"
cp scripts/hiddenforge "$tmp"

MYPYPATH=. exec "$MYPY" \
    entrypoint.py \
    healthcheck.py \
    vanity.py \
    scripts/build_inputs.py \
    scripts/check_manifest.py \
    scripts/coverage_summary.py \
    scripts/mutation_spotcheck.py \
    tests/ \
    "$tmp"
