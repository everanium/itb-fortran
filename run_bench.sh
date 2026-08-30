#!/usr/bin/env bash
#
# run_bench.sh -- micro-benchmark runner for the Fortran binding.
# Builds the bench binaries if absent, then runs bench_message,
# bench_stream, and bench_stream_one_shot: Single Message encrypt,
# stream-pump encrypt, and whole-buffer stream one-shot encrypt
# throughput at 1 MiB / 16 MiB / 64 MiB.
#
# Usage:
#   ./run_bench.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

if [[ ! -f "$DIST_DIR/libitb.so" ]]; then
    echo "error: libitb.so not found at $DIST_DIR" >&2
    echo "       run ./build.sh first" >&2
    exit 1
fi

BENCH_BIN_DIR="bench/bin"
# Always invoke `make bench` so timestamp-driven rebuilds pick up any
# bench source changes; make itself no-ops when everything is fresh.
echo "==> building bench binaries (FC=${FC:-gfortran})"
make bench

# Embedded RPATH should already point at libitb.so, but export
# LD_LIBRARY_PATH as a fallback for cases where the Linux loader
# does not honour the RPATH (e.g. some hardened distro defaults).
export LD_LIBRARY_PATH="$DIST_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# Go-runtime pacing defaults for bench-scale allocation churn; the
# `:-` form respects any override set by the caller. The bench mains
# apply the same caps programmatically.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-512MiB}"
export ITB_GOGC="${ITB_GOGC:-20}"

# Bench-shape defaults -- match the root Go BENCH3.md pin so the
# throughput numbers are directly comparable to the shipped Go
# baseline. Override any of these before calling the script to
# change the shape. ITB_PROFILE is left to the per-binary fallback
# (singlemsg-triple-nomac-v1 for message, streaming-noaead-triple-v1
# for stream) unless the caller sets it.
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-1024}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_BENCH_MIN_SEC="${ITB_BENCH_MIN_SEC:-5}"

# ITB_WITH_MAC=true derives MAC/AEAD profile counterparts. When
# ITB_PROFILE is set explicitly by the caller, it wins over the
# derivation and applies to both shapes (expert override).
: "${ITB_WITH_MAC:=false}"
if [ -n "${ITB_PROFILE:-}" ]; then
    ITB_MSG_PROFILE_DEFAULT="${ITB_PROFILE}"
    ITB_STREAM_PROFILE_DEFAULT="${ITB_PROFILE}"
elif [ "${ITB_WITH_MAC}" = "true" ]; then
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-mac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-aead-triple-mac-v1"
else
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-nomac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-noaead-triple-v1"
fi

export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"
"./$BENCH_BIN_DIR/bench_message"
export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
"./$BENCH_BIN_DIR/bench_stream"
"./$BENCH_BIN_DIR/bench_stream_one_shot"
