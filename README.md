# ITB Fortran Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). Fortran 2008 modules over `ISO_C_BINDING` that
**link against `libitb.so` at compile time** (`-litb` with an
embedded RPATH) — no runtime symbol loading. Every hash-name /
MAC-name / cipher-name / profile-name is an opaque `character(*)`
passed through to Go for validation; the binding carries no ITB
construction logic. The public surface is one `itb_pipeline_t`
handle (init / open / rekey / close / free, Single Message encrypt /
decrypt, whole-buffer stream pumps, incremental `itb_stream_t`
sessions with write / end / read), an `itb_opts_t` query-string
builder, `itb_register_profile`, and the Go runtime knobs.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc-fortran make
```

Generic Linux: a Go toolchain, gfortran (GCC 12+), and GNU make.

## Build the shared library

The convenience driver builds `libitb.so` (if absent), the binding's
module tree, every test binary, the bench binaries, and the eitb CLI
in one step:

```bash
./bindings/fortran/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/fortran && make tests bench eitb
```

Fortran module builds are order-sensitive: every `use`d module's
`.mod` file must exist before the dependent source compiles. The
Makefile's hand-coded dependency chain sequences the build; a stale
`.mod` cache from an interrupted build is the classic failure mode,
so `build.sh` runs `make clean` first.

## Module structure

- `src/itb.f90` — root module; `use itb` re-exports the whole
  public surface (plus the interop kinds it uses).
- `src/itb_status.f90` — status-code constants + labels.
- `src/itb_error.f90` — `itb_error_t` record + `ITB_LastError`
  capture.
- `src/itb_opts.f90` — `itb_opts_t` URL-query builder (opaque
  key/value pass-through).
- `src/itb_pipeline.f90` — `itb_pipeline_t` lifecycle + the
  buffer-in / buffer-out cipher paths + `itb_register_profile`.
- `src/itb_stream.f90` — incremental `itb_stream_t` sessions +
  whole-buffer pumps.
- `src/itb_runtime.f90` — Go runtime knobs, library version, hash
  registry accessors.
- `src/itb_ffi.f90` — internal `bind(C)` interface declarations +
  C-string marshalling.

## Lifetime discipline

Fortran has no destructors. Every successful `itb_pipeline_init` /
`itb_pipeline_open` must be paired with exactly one
`itb_pipeline_free` call (libitb zeroes key material on free);
`itb_pipeline_close` zeroes early without releasing the handle, and
subsequent cipher calls return `ITB_STATUS_TRIPLE_CLOSED`. Every
successful `itb_encrypt_stream_begin` / `itb_decrypt_stream_begin`
must be paired with exactly one `itb_stream_free` call, which
cancels the session from any state; a session must not outlive its
parent Pipeline.

## Usage example

```fortran
program round_trip
  use itb
  implicit none
  type(itb_opts_t)     :: opts
  type(itb_pipeline_t) :: sender, receiver
  type(itb_error_t)    :: err
  integer(c_int8_t), allocatable :: plain(:), wire(:), back(:)

  call itb_pipeline_init(sender, "singlemsg-triple-mac-v1", opts, err)
  if (.not. itb_ok(err)) stop 1
  call itb_pipeline_open(receiver, "singlemsg-triple-mac-v1", &
      sender%blob, opts, err)
  if (.not. itb_ok(err)) stop 1

  plain = [integer(c_int8_t) :: 104, 101, 108, 108, 111]
  call itb_encrypt_message(sender, plain, wire, err)
  if (.not. itb_ok(err)) stop 1
  call itb_decrypt_message(receiver, wire, back, err)
  if (.not. itb_ok(err)) stop 1
  if (.not. all(back == plain)) stop 1

  call itb_pipeline_free(receiver)
  call itb_pipeline_free(sender)
end program
```

`itb_opts_t` overrides the profile default per call (chunk size,
outer cipher, parallax on/off, wrapper on/off, MAC name, palette);
every setter goes through `itb_opts_set(opts, key, value)`:

```fortran
call itb_opts_set(opts, "chunkSize", "65536")
call itb_opts_set(opts, "withWrapper", "false")
call itb_pipeline_init(sender, "singlemsg-triple-mac-v1", opts, err)
call itb_pipeline_open(receiver, "singlemsg-triple-mac-v1", &
    sender%blob, opts, err)
```

`itb_pipeline_rekey` rotates the parallax + wrapper masters
mid-session (the eight ITB seeds and MAC key are fixed for the
session lifetime by design); the receiver picks up the new masters
through a fresh `sender%blob` handshake:

```fortran
integer(c_int8_t) :: perm(32), wrap(32)
perm = 17_c_int8_t; wrap = 34_c_int8_t
call itb_pipeline_rekey(sender, perm, wrap, err)
call itb_pipeline_open(receiver, "singlemsg-triple-mac-v1", &
    sender%blob, opts, err)
```

Bytes cross the surface as `integer(c_int8_t)` arrays; output arrays
are allocated by the callee to the exact produced length. For
bounded-Go-side-spooling streaming, `itb_encrypt_stream_pump` /
`itb_decrypt_stream_pump` move a whole in-memory buffer through an
incremental session in 1 MiB slices; the explicit session API
(`itb_encrypt_stream_begin` / `itb_stream_write` / `itb_stream_end`
/ `itb_stream_read` / `itb_stream_drain_all`) covers caller-driven
loops over file or socket I/O.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as an `itb_error_t` carrying
the status code plus the `ITB_LastError` diagnostic
(`itb_error_text(err)` renders both).

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```fortran
prev_limit = itb_set_memory_limit(int(512, c_int64_t) * 1024 * 1024)
prev_gc = itb_set_gc_percent(20_c_int)
```

## Testing

```bash
./bindings/fortran/run_tests.sh
```

Each `tests/test_*.f90` compiles to a standalone binary under
`tests/build/`; the runner executes them sequentially with
per-binary process isolation. The suite covers Single Message round
trips per shipped profile, stream pumps, incremental sessions with
pathological batch sizes, tampered-wire failure stickiness,
mid-flight cancellation, rekey, profile registration, and error
mapping — surface parity checks; the deep suite lives in Go under
the shipped tree.

## Benchmarking

```bash
./bindings/fortran/run_bench.sh
```

`bench_message` (Single Message encrypt) and `bench_stream`
(stream-pump encrypt) throughput at 1 MiB / 16 MiB / 64 MiB.
Wall-clock via `system_clock`; plaintext is CSPRNG-filled via
`getrandom(2)` outside the timing loop. Shape env vars
(`ITB_INNER_HASH`, `ITB_KEY_BITS`, `ITB_NONCE_BITS`,
`ITB_WITH_PARALLAX`, `ITB_WITH_WRAPPER`, `ITB_PROFILE`,
`ITB_BENCH_MIN_SEC`) default to the fleet-canonical pin inside
`run_bench.sh`.

## eitb utility

A small CLI under `bindings/fortran/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
cd bindings/fortran && make eitb
./eitb/eitb version
./eitb/eitb hashes
./eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `itb_error_t` may belong to a different
  call under concurrent FFI use. The status code is always
  attributable.
- `itb_pipeline_rekey` must not run concurrently with cipher calls
  or open stream sessions on the same Pipeline.
- The stream pumps hold both the source and the accumulated output
  in memory; caller-driven session loops are the path for inputs
  that must not be fully buffered on the Fortran side.
- libitb.so must be reachable at runtime (embedded RPATH points at
  `dist/linux-amd64`; `LD_LIBRARY_PATH` is the fallback).
