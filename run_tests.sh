#!/usr/bin/env bash
#
# run_tests.sh -- discover and run every tests/test_*.f90 binary.
#
# Each tests/test_*.f90 is compiled to its own standalone executable
# under tests/build/ (see Makefile). The runner iterates the binaries,
# invokes each in turn, and accumulates a pass / fail count.
#
# Per-binary process isolation gives every test a fresh libitb3 global
# state; tests run sequentially.
#
# Usage:
#   ./run_tests.sh           # summary-only output
#   ./run_tests.sh -v        # also print per-test stdout / stderr

set -eu
set -o pipefail

cd "$(dirname "$0")"

verbose=0
case "${1:-}" in
    -v|--verbose) verbose=1 ;;
    "")           ;;
    *)            echo "unknown option: $1" >&2; exit 2 ;;
esac

# Build through build.sh, which wipes every artefact this binding owns
# before compiling, so the binaries executed below are the ones this
# invocation produced. Quiet on stdout unless -v; compiler diagnostics
# reach stderr either way.
if [ "$verbose" -eq 1 ]; then
    ./build.sh
else
    ./build.sh >/dev/null
fi

TEST_BIN_DIR="tests/build"

# Embedded RPATH should already point at libitb3.so, but export
# LD_LIBRARY_PATH as a fallback for cases where the Linux loader
# doesn't honour the RPATH (e.g. some hardened distro defaults).
LIBITB3_DIR="${LIBITB3_DIR:-../../dist/linux-amd64}"
LIBITB3_DIR_ABS="$(cd "$LIBITB3_DIR" 2>/dev/null && pwd || echo "$LIBITB3_DIR")"
export LD_LIBRARY_PATH="$LIBITB3_DIR_ABS${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

fail=0
pass=0
total=0
for bin in "$TEST_BIN_DIR"/test_*; do
    [ -x "$bin" ] || continue
    case "$bin" in
        *.o|*.mod) continue ;;
    esac
    name="$(basename "$bin")"
    total=$((total + 1))
    if [ "$verbose" -eq 1 ]; then
        if "$bin"; then
            pass=$((pass + 1))
        else
            echo "  FAIL: $name"
            fail=$((fail + 1))
        fi
    else
        if out="$("$bin" 2>&1)"; then
            pass=$((pass + 1))
            echo "  ok   $name"
        else
            fail=$((fail + 1))
            echo "  FAIL $name"
            printf '%s\n' "$out" | sed 's/^/      /'
        fi
    fi
done

echo
echo "  $pass passed / $fail failed of $total (FC=${FC:-gfortran})"
exit "$fail"
