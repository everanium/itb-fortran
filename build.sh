#!/usr/bin/env bash
#
# build.sh -- one-step build for the ITB Fortran binding.
#
# Ensures the libitb.so c-shared artefact exists at
# dist/linux-amd64/libitb.so (rebuilds it if absent), then dispatches
# to the Makefile to compile the binding's src/ module tree and the
# tests/ harness in one pass.
#
# Pass FC=ifx (or any FCFLAGS=...) on the command line / env to drive
# Intel's compiler; gfortran is the default.
#
# Usage:
#   ./build.sh              # gfortran build
#   FC=ifx ./build.sh       # ifx build (re-uses build_ifx/ tree)

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"

if [ ! -f "$REPO_ROOT/dist/linux-amd64/libitb.so" ]; then
    echo "==> building libitb.so (c-shared)"
    cd "$REPO_ROOT"
    go build -trimpath -buildmode=c-shared \
        -o dist/linux-amd64/libitb.so ./cmd/cshared
    cd "$SCRIPT_DIR"
fi

echo "==> cleaning previous build artefacts (make clean)"
make clean
mkdir -p build build_ifx tests/build bench/build bench/build_ifx bench/bin
echo "==> building Fortran binding (FC=${FC:-gfortran})"
make tests

echo "==> ready: ./run_tests.sh"
