#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Fortran
# binding: builds the utility with the binding's Makefile (a no-op
# when it is up to date; libitb3.so and the binding's module tree are
# assumed built by build.sh) and execs it with every argument passed
# through.
#
# The build output is captured rather than discarded: gfortran reports
# on stderr, and a redirect of stdout alone would let its lines join
# the utility's own output. Nothing is printed unless the build fails,
# in which case everything it said is.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

if ! build_output="$(make loop 2>&1)"; then
    printf '%s\n' "$build_output" >&2
    exit 1
fi

exec ./loop/loop "$@"
