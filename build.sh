#!/usr/bin/env bash
#
# build.sh -- one-step build for the ITB Fortran binding.
#
# Ensures the libitb3.so c-shared artefact exists at
# dist/linux-amd64/libitb3.so (rebuilds it if absent), then dispatches
# to the Makefile to compile the binding's src/ module tree, the
# tests/ harness, the bench binaries, and the eitb CLI in one pass.
#
# Fortran module builds are order-sensitive (.mod files must exist
# before dependents compile); the Makefile's hand-coded dependency
# chain sequences that. A stale .mod cache from an interrupted build
# is the classic failure mode, so every artefact this binding owns is
# removed before the compiler runs.
#
# Usage:
#   ./build.sh                       # gfortran build
#   FCFLAGS=... ./build.sh           # custom flags
#   ITB_SKIP_CLEAN=1 ./build.sh      # keep existing artefacts

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd -P)"
REPO_ROOT="$(cd ../.. && pwd -P)"

# ---- Clean ----------------------------------------------------------
# Artefacts this binding owns, including the alternate compiler and
# sanitizer trees the Makefile's own clean target does not list. The
# Go shared library under dist/linux-amd64/ is shared by every binding
# and stays untouched.
CLEAN_TARGETS=(
    build                 # gfortran .mod / .o tree
    tests/build           # per-test binaries + the helper object
    bench/build           # bench objects
    bench/bin             # bench binaries
    bench/results         # bench output
    eitb/build            # eitb objects
    eitb/eitb             # eitb CLI
    coverage              # gcov report tree
)
CLEAN_GLOBS=(
    'build_*'             # ifx / fpm / lint / asan / tsan / check trees
    'bench/build_*'       # alternate-compiler bench trees
)

clean_artefacts() {
    local rel abs tracked pat match

    # Expand the globs into the literal list so every match passes the
    # same validation as a hand-written entry.
    shopt -s nullglob
    for pat in "${CLEAN_GLOBS[@]}"; do
        for match in $pat; do
            CLEAN_TARGETS+=("$match")
        done
    done
    shopt -u nullglob

    # A build artefact is never tracked, so a hit here means the list
    # above is wrong. Abort rather than delete a source file.
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        tracked="$(git ls-files -- "${CLEAN_TARGETS[@]}")"
        if [ -n "$tracked" ]; then
            echo "clean: tracked files inside the clean scope:" >&2
            printf '%s\n' "$tracked" | sed 's/^/    /' >&2
            exit 1
        fi
    fi

    for rel in "${CLEAN_TARGETS[@]}"; do
        abs="$(readlink -m -- "$SCRIPT_DIR/$rel")"
        case "$abs" in
            "$SCRIPT_DIR"/?*) ;;
            *) echo "clean: '$rel' escapes $SCRIPT_DIR ($abs)" >&2; exit 1;;
        esac
        [ -e "$abs" ] || continue
        echo "[clean] rm -rf $abs"
        rm -rf -- "$abs"
    done
}

if [ "${ITB_SKIP_CLEAN:-0}" = "1" ]; then
    echo "==> ITB_SKIP_CLEAN=1 -- keeping existing artefacts"
else
    echo "==> cleaning previous artefacts"
    clean_artefacts
fi

if [ ! -f "$REPO_ROOT/dist/linux-amd64/libitb3.so" ]; then
    echo "==> building libitb3.so (c-shared)"
    cd "$REPO_ROOT"
    go build -trimpath -buildmode=c-shared \
        -o dist/linux-amd64/libitb3.so ./cmd/cshared
    cd "$SCRIPT_DIR"
fi

echo "==> building Fortran binding (FC=${FC:-gfortran})"
make tests bench eitb

echo "==> ready: ./run_tests.sh"
