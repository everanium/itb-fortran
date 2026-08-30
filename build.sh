#!/usr/bin/env bash
#
# build.sh -- one-step build for the ITB Fortran binding.
#
# Ensures the libitb.so c-shared artefact exists at
# dist/linux-amd64/libitb.so (rebuilds it if absent), then dispatches
# to the Makefile to compile the binding's src/ module tree, the
# tests/ harness, the bench binaries, and the eitb CLI in one pass.
#
# Fortran module builds are order-sensitive (.mod files must exist
# before dependents compile); the Makefile's hand-coded dependency
# chain sequences that. A stale .mod cache from an interrupted build
# is the classic failure mode -- `make clean` runs first to preclude
# it.
#
# Usage:
#   ./build.sh                       # gfortran build
#   FCFLAGS=... ./build.sh           # custom flags

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
echo "==> building Fortran binding (FC=${FC:-gfortran})"
make tests bench eitb

echo "==> ready: ./run_tests.sh"
