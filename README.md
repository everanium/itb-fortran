# ITB Fortran Binding

Fortran 2003+ wrapper over the libitb shared library (`cmd/cshared`)
for HPC chunked encryption — NetCDF / HDF5 / MPI-IO archive
workloads. Link-time C ABI integration via `iso_c_binding`
(`bind(C)`, `c_loc`, `c_funloc`, `c_f_pointer`); per-instance
deterministic lifecycle via explicit `destroy()` plus a `final ::`
safety net. Two-layer architecture: `itb_sys` (raw FFI,
audit-friendly) plus a per-concept module set (`itb_seed`,
`itb_mac`, `itb_cipher`, `itb_encryptor`, `itb_blob`, `itb_streams`,
`itb_library`).

**Path placeholder.** `<itb>` denotes the path to the local ITB
repository checkout (or this binding's mirror clone) — for example,
`/home/you/go/src/itb` or `~/projects/itb-fortran`. Substitute the
literal token in the recipes below.

## At a glance

| | |
|---|---|
| Language standard | Fortran 2018 (compiles clean as Fortran 2003 / 2008) |
| Source modules | 11 (`src/itb_*.f90`) |
| Source LOC | ~5.5k |
| Test programs | 31 (`tests/test_*.f90`) — Single + Triple Ouroboros, mixed primitives, plain + authenticated paths, blob round-trip, streaming chunked I/O, error paths, lockSeed lifecycle, persistence, per-instance configuration overrides, plain + authenticated stream variants |
| Wall-clock test run | ~5 s |
| Compilers exercised | gfortran 16+ (default), Intel ifx 2025+ |
| Build systems | POSIX Makefile (primary), fpm (developer onboarding) |
| Runtime deps | libitb shared library only |

## Prerequisites (Arch Linux)

```bash
sudo pacman -S gcc-fortran                          # gfortran 16+
yay -S intel-oneapi-hpckit                          # ifx 2025+ (AUR; ~20-25 GB)
curl -L -o ~/.local/bin/fpm \
  https://github.com/fortran-lang/fpm/releases/download/v0.13.0/fpm-0.13.0-linux-x86_64-gcc-12 \
  && chmod +x ~/.local/bin/fpm

# Activate Intel toolchain (per shell, before invoking ifx)
source /opt/intel/oneapi/setvars.sh
```

`gcc-fortran` ships gfortran from the system toolchain; `ifx` lives
under `/opt/intel/oneapi/compiler/<version>/bin/` once the AUR
package lands. Other distributions can fetch `ifx` through Intel's
oneAPI apt / dnf repositories or installer; the Fortran sources are
toolchain-agnostic and the Makefile picks up `FC=ifx` without
further configuration.

## Library lookup order

1. `ITB_LIBRARY_PATH` environment variable (absolute path), if
   set, takes precedence over both subsequent steps.
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved from the
   binding directory. The Makefile bakes
   `-Wl,-rpath,../../dist/linux-amd64` into every test binary;
   the linker's RPATH resolves `libitb.so` without
   `LD_LIBRARY_PATH` for installed binaries.
3. System loader path (`ld.so.cache`, `LD_LIBRARY_PATH`,
   `DYLD_LIBRARY_PATH`, `PATH`).

OS / arch mapping: `Linux/linux`, `Darwin/macos→darwin`,
`Windows/windows`, `FreeBSD/freebsd` × `amd64` / `arm64`. The
Fortran binding uses the platform's native dynamic linker; no
`dlopen` shim is performed at startup.

## Tests

```bash
cd bindings/fortran
./build.sh             # builds libitb.so (if missing) + the Fortran
                       # binding's src/ modules + every tests/test_*
                       # binary under tests/build/
./run_tests.sh         # runs every test binary; one line per file
```

`build.sh` defaults to `gfortran`. To build with Intel's compiler:

```bash
make clean
FC=ifx ./build.sh
FC=ifx ./run_tests.sh
```

The `.mod` cache is per-compiler (`build/` for gfortran,
`build_ifx/` for ifx) so the two toolchains coexist without
collisions.

The Fortran Package Manager (`fpm`) is supported as a secondary
developer-onboarding path. `fpm.toml` enumerates the binding's
library + 31 test programs; `fpm test --compiler gfortran` builds
and runs the suite, picking up `libitb.so` through `FPM_LDFLAGS`:

```bash
export FPM_LDFLAGS="-L$PWD/../../dist/linux-amd64 -Wl,-rpath,$PWD/../../dist/linux-amd64"
fpm test --compiler gfortran          # 31 PASS
fpm test --compiler ifx               # 31 PASS
```

The Makefile remains the primary build entry point — fpm exists
for developer ergonomics, not as the binding's release surface.

# Quick Start

A minimal "encrypt one buffer in memory" snippet:

```fortran
program demo_encrypt
  use, intrinsic :: iso_c_binding, only: c_int8_t
  use itb_encryptor, only: itb_encryptor_t, new_itb_encryptor
  use itb_wrapper,   only: itb_wrap_in_place, itb_unwrap_in_place,            &
                           itb_wrapper_generate_key,                            &
                           ITB_WRAPPER_CIPHER_AES_128_CTR
  use itb_kinds,     only: itb_byte_kind, itb_status_kind
  use itb_errors,    only: STATUS_OK
  implicit none
  type(itb_encryptor_t)               :: enc
  integer(c_int8_t), allocatable      :: ct(:), pt(:), wire(:)
  integer(itb_byte_kind), allocatable, target :: outerKey(:), nonce(:)
  character(*), parameter             :: msg = "hello, archive"
  integer :: i, body_first, nlen, ct_len
  integer(itb_status_kind) :: status

  allocate (pt(len(msg)))
  do i = 1, len(msg)
    pt(i) = transfer(msg(i:i), 0_c_int8_t)
  end do

  call new_itb_encryptor(enc, "blake3", 1024, "hmac-blake3", 1)
  ct = enc%encrypt_auth(pt)
  ct_len = size(ct)

  ! Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
  call itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_AES_128_CTR, outerKey, status)

  ! Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
  call itb_wrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR, outerKey, ct, nonce, status)
  nlen = size(nonce)
  allocate (wire(nlen + ct_len))
  wire(1:nlen) = nonce(:)
  wire(nlen + 1 : nlen + ct_len) = ct(:)

  ! Receiver: strip nonce + XOR-decrypt the body in place; body_first
  ! marks the first decrypted-payload byte (1-based).
  call itb_unwrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR, outerKey, wire,    &
                           body_first, status)
  pt = enc%decrypt_auth(wire(body_first : size(wire)))
  call enc%destroy()
  if (allocated(outerKey)) deallocate (outerKey)
  if (allocated(nonce))    deallocate (nonce)
  if (allocated(wire))     deallocate (wire)
end program
```

**Build + run** the snippet above. The compile / link recipe matches
every later Quick Start example in this README — `-I` against the
`build/` directory holding the binding's `.mod` cache, the `.o` files
linked in directly, the libitb shared library resolved via `-L /
-litb` plus `-Wl,-rpath`:

```sh
gfortran -O2 -I <itb>/bindings/fortran/build \
    -o main main.f90 \
    <itb>/bindings/fortran/build/*.o \
    -L <itb>/dist/linux-amd64 -litb \
    -Wl,-rpath,<itb>/dist/linux-amd64
./main
```

The Intel toolchain accepts the same recipe with `ifx` substituted for
`gfortran` and `build_ifx/` substituted for `build/`.

## Memory

Two process-wide knobs constrain Go runtime arena pacing. Both readable at libitb load time via env vars:

- `ITB_GOMEMLIMIT=512MiB` — soft memory limit in bytes; supports `B` / `KiB` / `MiB` / `GiB` / `TiB` suffixes.
- `ITB_GOGC=20` — GC trigger percentage; default `100`, lower triggers GC more aggressively.

Programmatic setters override env-set values at any time. Pass `-1` to either setter to query the current value without changing it.

```fortran
prev = itb_set_memory_limit(int(512 * 1024 * 1024, c_int64_t))
prev = itb_set_gc_percent(20)
```

## Streaming AEAD

**Streaming AEAD** authenticates a chunked stream end-to-end while
preserving the deniability of the per-chunk MAC-Inside-Encrypt
container. Each chunk's MAC binds the encrypted payload to a 32-byte
CSPRNG stream anchor (written as a once-per-stream wire prefix), the
cumulative pixel offset of preceding chunks, and a final-flag bit —
defending against chunk reorder, replay within or across streams
sharing the PRF / MAC key, silent mid-stream drop, and truncate-tail.
The wire format adds 32 bytes of stream prefix plus one byte of
encrypted trailing flag per chunk; no externally visible MAC tag.

**Low-Level Mode:**

Free subroutines `itb_stream_encrypt_auth` / `itb_stream_decrypt_auth`
take three `itb_seed_t` records plus an `itb_mac_t` (32-byte key from
`/dev/urandom`) and stream through the chunked-AEAD construction. The
`read_fn` / `write_fn` callbacks match `itb_stream_read_fn` /
`itb_stream_write_fn`; both receive an opaque `c_ptr` user_ctx that
the binding does not interpret.

```fortran
type(itb_seed_t)         :: noise, data, start
type(itb_mac_t)          :: mac
type(itb_wrap_stream_writer_t)  :: ww
integer(itb_byte_kind), target  :: mac_key(32)
integer(itb_byte_kind), allocatable, target :: outerKey(:), nonce(:)
integer(itb_byte_kind), allocatable, target :: inner_buf(:), wire(:)
integer(itb_status_kind) :: status

call new_itb_seed(noise, "areion512", 1024)
call new_itb_seed(data,  "areion512", 1024)
call new_itb_seed(start, "areion512", 1024)
call random_mac_key(mac_key)              ! 32 bytes from /dev/urandom
call new_itb_mac(mac, "hmac-blake3", mac_key)

! Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
call itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_AES_128_CTR, outerKey, status)

! Encrypt the inner ITB stream into an in-memory buffer first, then
! wrap the entire transcript end-to-end through one keystream session.
src_fp = c_fopen("/tmp/64mb.src" // c_null_char, "rb" // c_null_char)
call itb_stream_encrypt_auth(noise, data, start, mac,                    &
      rfn, src_fp, mem_wfn, c_loc(inner_sink),                            &
      16777216_itb_size_kind, status)

! Format-deniability ITB masking via outer-cipher streaming wrapper (AES-128-CTR) - same ~0% overhead in stream mode (Recommended in every case).
call itb_wrap_stream_writer_new(ITB_WRAPPER_CIPHER_AES_128_CTR, outerKey, &
                                  ww, nonce, status)
allocate (wire(size(nonce) + size(inner_buf)))
wire(1:size(nonce)) = nonce(:)
call ww%update(inner_buf, wire(size(nonce) + 1 : ), status)
call ww%destroy()

dst_fp = c_fopen("/tmp/64mb.enc" // c_null_char, "wb" // c_null_char)
call write_to_fp(dst_fp, wire, size(wire))   ! caller-side libc fwrite helper
```

**Build + run:**

```sh
gfortran -O2 -I <itb>/bindings/fortran/build \
    -o main main.f90 \
    <itb>/bindings/fortran/build/*.o \
    -L <itb>/dist/linux-amd64 -litb \
    -Wl,-rpath,<itb>/dist/linux-amd64
./main
```

**Output (verified):**

```
Low-Level src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Low-Level dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Low-Level Mode: 64 MiB roundtrip via stream-auth verified
```

---

**Easy Mode:**

`itb_encryptor_stream_encrypt_auth` consumes plaintext via a `read_fn`
procedure pointer matching `itb_stream_read_fn` and emits the on-wire
transcript via a `write_fn` matching `itb_stream_write_fn`. The example
wires the opaque `c_ptr` user_ctx to a libc `FILE *` opened via `fopen`,
with the callbacks forwarding into `fread` / `fwrite`. The MAC key is
allocated CSPRNG-fresh inside the encryptor at constructor time.

```fortran
use, intrinsic :: iso_c_binding
use itb_kinds
use itb_encryptor
use itb_streams
use itb_wrapper
use itb_errors, only: STATUS_OK

! libc bindings used for file I/O (declared in main_mod, omitted here).
! file_read / file_write callbacks forward to fread / fwrite via user_ctx.

type(c_ptr) :: src_fp, dst_fp
procedure(itb_stream_read_fn),  pointer :: rfn => null()
procedure(itb_stream_write_fn), pointer :: wfn => null(), mem_wfn => null()
type(itb_encryptor_t)           :: enc
type(itb_wrap_stream_writer_t)  :: ww
integer(itb_byte_kind), allocatable, target :: outerKey(:), nonce(:)
integer(itb_byte_kind), allocatable, target :: inner_buf(:), wire(:)
integer(itb_status_kind) :: status

rfn => file_read
wfn => file_write
mem_wfn => mem_write   ! fills inner_buf via grow-buffer ctx

call new_itb_encryptor(enc, "areion512", 1024, "hmac-blake3", 1)

! Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
call itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_AES_128_CTR, outerKey, status)

! Encrypt the inner ITB stream into an in-memory buffer first.
src_fp = c_fopen("/tmp/64mb.src" // c_null_char, "rb" // c_null_char)
call itb_encryptor_stream_encrypt_auth(enc, rfn, src_fp, mem_wfn,        &
                                       c_loc(inner_sink),                 &
                                       16777216_itb_size_kind, status)
if (status /= STATUS_OK) error stop "encrypt failed"

! Format-deniability ITB masking via outer-cipher streaming wrapper (AES-128-CTR) - same ~0% overhead in stream mode (Recommended in every case).
call itb_wrap_stream_writer_new(ITB_WRAPPER_CIPHER_AES_128_CTR, outerKey, &
                                  ww, nonce, status)
allocate (wire(size(nonce) + size(inner_buf)))
wire(1:size(nonce)) = nonce(:)
call ww%update(inner_buf, wire(size(nonce) + 1 : ), status)
call ww%destroy()

dst_fp = c_fopen("/tmp/64mb.enc" // c_null_char, "wb" // c_null_char)
call write_to_fp(dst_fp, wire, size(wire))   ! caller-side libc fwrite helper
```

**Build + run:**

```sh
gfortran -O2 -I <itb>/bindings/fortran/build \
    -o main main.f90 \
    <itb>/bindings/fortran/build/*.o \
    -L <itb>/dist/linux-amd64 -litb \
    -Wl,-rpath,<itb>/dist/linux-amd64
./main
```

**Output (verified):**

```
Easy Mode src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Easy Mode dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Easy Mode: 64 MiB roundtrip via stream-auth verified
```

Linking pulls in the binding's compiled object files
(`bindings/fortran/build/*.o`) plus the shared Go-built library
(`-litb`). The Fortran binding does not currently package a static
`.a` archive — the `.o` set is link-included directly.

## HPC streaming — chunked I/O over caller-owned read / write callbacks

Fortran's typical ITB use case is petabyte-scale archive workloads
where the caller already owns chunk granularity (Lustre / GPFS
stripe-aligned reads, NetCDF / HDF5 dataset slabs, MPI-IO
collective writes). The free-function stream surface
(`itb_stream_encrypt` / `itb_stream_decrypt` plus their
authenticated and Triple Ouroboros variants) is the hot path for
this class of work — the binding takes Seeds (and an optional MAC)
plus a `(read_fn, read_ctx)` source and a `(write_fn, write_ctx)`
sink, and slices the input into `chunk_size`-byte blocks at the
binding layer. ITB ciphertexts cap at ~64 MB plaintext per chunk,
so streaming larger payloads is the canonical way to encrypt one
multi-gigabyte HDF5 dataset in one call. Memory peak is bounded by
`chunk_size` regardless of total payload length. The caller MUST
pass `chunk_size > 0` — zero is rejected with `STATUS_BAD_INPUT`.

The free-function surface is the only stream API the binding ships
— there is no object-based `stream_encryptor_t` /
`stream_decryptor_t` type. HPC consumers already structure their
I/O around chunked driver state (`netcdf-fortran` dataset IDs,
HDF5 file / dataset / dataspace handles, MPI file handles), so the
free-function shape integrates directly.

Callbacks are `bind(C)` — same shape reachable from Fortran-only
callers and from cross-language consumers passing a C function
pointer through the FFI. Both callback contracts:

- `read_fn (user_ctx, buf, cap, out_n) → rc`: write up to `cap`
  bytes into `buf`, set `out_n` to the bytes actually written,
  return `0` on success or non-zero on I/O error. Setting
  `out_n = 0` and returning `0` signals end-of-stream.
- `write_fn (user_ctx, buf, n) → rc`: consume the full `n` bytes
  from `buf` before returning. Return `0` on success or non-zero
  on I/O error.

The `user_ctx` `c_ptr` is forwarded verbatim on every callback
invocation. A Fortran caller wraps its I/O state in a `bind(C)`
derived type and passes `c_loc(state)`; the callback recovers the
state via `c_f_pointer(user_ctx, state)`.

```fortran
program hdf5_encrypt_archive
  use, intrinsic :: iso_c_binding
  use itb_seed,    only: itb_seed_t, new_itb_seed
  use itb_mac,     only: itb_mac_t, new_itb_mac
  use itb_streams, only: itb_stream_encrypt_auth
  use itb_wrapper, only: itb_wrap_stream_writer_t,                            &
                          itb_wrap_stream_writer_new,                          &
                          itb_wrapper_generate_key,                            &
                          ITB_WRAPPER_CIPHER_AES_128_CTR
  use itb_kinds,   only: itb_byte_kind, itb_status_kind
  use itb_errors,  only: STATUS_OK
  implicit none

  type, bind(C) :: nc_source_state
    integer(c_int)     :: dataset_id
    integer(c_int64_t) :: bytes_remaining
  end type
  type, bind(C) :: h5_sink_state
    integer(c_int)     :: dataset_id
    integer(c_int64_t) :: offset
    type(c_ptr)        :: ww_handle      ! WrapStreamWriter handle (opaque c_ptr)
  end type

  type(nc_source_state), target :: src
  type(h5_sink_state),   target :: dst
  type(itb_seed_t)              :: noise, data, start
  type(itb_mac_t)               :: mac
  type(itb_wrap_stream_writer_t):: ww
  integer(c_int8_t)             :: mac_key(32)
  integer(itb_byte_kind), allocatable, target :: outerKey(:), nonce(:)
  procedure(itb_stream_read_fn),  pointer :: rd
  procedure(itb_stream_write_fn), pointer :: wr
  integer(c_size_t), parameter :: chunk_size = 16_c_size_t * 1024 * 1024
  integer(itb_status_kind)     :: status

  ! Fill mac_key from /dev/urandom in real code; zero key here is
  ! illustrative only.
  mac_key = 0_c_int8_t

  call new_itb_seed(noise, "blake3", 1024)
  call new_itb_seed(data,  "blake3", 1024)
  call new_itb_seed(start, "blake3", 1024)
  call new_itb_mac (mac,   "hmac-blake3", mac_key)

  ! src: handle to the NetCDF source variable + remaining byte count
  ! dst: handle to the HDF5 sink dataset + write cursor
  src%dataset_id = open_netcdf_var("input.nc",  "temperature")
  src%bytes_remaining = netcdf_var_byte_count(src%dataset_id)
  dst%dataset_id = create_h5_dataset("output.h5.itb")
  dst%offset     = 0_c_int64_t

  ! Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
  call itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_AES_128_CTR, outerKey, status)

  ! Format-deniability ITB masking via outer-cipher streaming wrapper (AES-128-CTR) - same ~0% overhead in stream mode (Recommended in every case).
  call itb_wrap_stream_writer_new(ITB_WRAPPER_CIPHER_AES_128_CTR, outerKey,   &
                                    ww, nonce, status)
  call hdf5_write_raw(dst%dataset_id, dst%offset, nonce, size(nonce))
  dst%offset = dst%offset + int(size(nonce), c_int64_t)
  dst%ww_handle = ww%raw_handle()    ! sink callback feeds bytes through ww%update

  rd => netcdf_read_chunk
  wr => hdf5_write_chunk

  call itb_stream_encrypt_auth(noise, data, start, mac,                &
                                rd, c_loc(src), wr, c_loc(dst),         &
                                chunk_size, status)
  if (status /= STATUS_OK) call halt_on_status(status)

  call ww%destroy()
  call mac%destroy()
  call start%destroy()
  call data%destroy()
  call noise%destroy()
  if (allocated(outerKey)) deallocate (outerKey)
  if (allocated(nonce))    deallocate (nonce)
contains

  function netcdf_read_chunk(user_ctx, buf, cap, out_n) bind(C) result(rc)
    type(c_ptr),       value :: user_ctx
    type(c_ptr),       value :: buf
    integer(c_size_t), value :: cap
    integer(c_size_t)        :: out_n
    integer(c_int)           :: rc
    type(nc_source_state), pointer :: state
    integer(c_size_t) :: take

    call c_f_pointer(user_ctx, state)
    take = min(cap, int(state%bytes_remaining, c_size_t))
    if (take == 0) then
      out_n = 0_c_size_t
      rc    = 0_c_int
      return
    end if
    rc = nc_get_var_into_ptr(state%dataset_id, buf, take)   ! NetCDF call
    state%bytes_remaining = state%bytes_remaining - int(take, c_int64_t)
    out_n = take
  end function

  function hdf5_write_chunk(user_ctx, buf, n) bind(C) result(rc)
    type(c_ptr),       value :: user_ctx
    type(c_ptr),       value :: buf
    integer(c_size_t), value :: n
    integer(c_int)           :: rc
    type(h5_sink_state), pointer :: state
    call c_f_pointer(user_ctx, state)
    rc = h5_dataset_write(state%dataset_id, state%offset, buf, n)   ! HDF5 call
    if (rc == 0) state%offset = state%offset + int(n, c_int64_t)
  end function
end program
```

`netcdf_read_chunk` and `hdf5_write_chunk` are caller-owned and
opaque to the binding — the binding only sees a `c_funloc` plus a
`c_ptr` user context. Substitute the placeholder calls
(`nc_get_var_into_ptr`, `h5_dataset_write`) with the real
NetCDF / HDF5 / MPI-IO entry points; the binding's chunk loop
invokes them once per chunk.

The plain (no-MAC) entry point `itb_stream_encrypt` swaps the
authenticated `itb_stream_encrypt_auth` for one without the MAC
parameter; reverse direction uses `itb_stream_decrypt_auth` /
`itb_stream_decrypt`. Triple Ouroboros (3× security) takes seven
seeds via the `_triple` counterparts:
`itb_stream_encrypt_triple`, `itb_stream_decrypt_triple`,
`itb_stream_encrypt_auth_triple`,
`itb_stream_decrypt_auth_triple`.

## Easy Mode — `type(itb_encryptor_t)` + HMAC-BLAKE3 (MAC Authenticated)

The Easy Mode encryptor (mirroring the
`github.com/everanium/itb/easy` Go sub-package) replaces the
seven-line setup ceremony of the lower-level seed /
`itb_encrypt` / `itb_decrypt` path with one constructor call: the
encryptor allocates its own three (Single) or seven (Triple) seeds
plus MAC closure, snapshots the global configuration into a
per-instance Config, and exposes setters that mutate only its own
state without touching the process-wide `itb_set_*` accessors.
Two encryptors with different settings can run side-by-side without
cross-contamination.

The MAC primitive is bound at construction time — the third
constructor argument selects one of the registry names
(`hmac-blake3` — recommended default, `hmac-sha256`, `kmac256`).
The encryptor allocates a fresh 32-byte CSPRNG MAC key alongside
the per-seed PRF keys; `enc%export_state()` carries all of them in
a single JSON blob. On the receiver side,
`dec%import_state(blob)` restores the MAC key together with the
seeds, so the encrypt-today / decrypt-tomorrow flow is one method
call per side.

When the `mac_name` argument is the empty string `""` the binding
substitutes `hmac-blake3` rather than forwarding through to
libitb's own default — HMAC-BLAKE3 measures the lightest
authenticated-mode overhead across the Easy Mode bench surface.

```fortran
program demo_easy
  use, intrinsic :: iso_c_binding, only: c_int8_t
  use itb_encryptor, only: itb_encryptor_t, new_itb_encryptor
  use itb_wrapper,   only: itb_wrap_in_place, itb_unwrap_in_place,            &
                           itb_wrapper_generate_key,                            &
                           ITB_WRAPPER_CIPHER_AES_128_CTR
  use itb_kinds,     only: itb_byte_kind, itb_status_kind
  implicit none
  type(itb_encryptor_t)         :: enc, dec
  integer(c_int8_t), allocatable :: blob(:), ct(:), pt(:), wire(:)
  integer(itb_byte_kind), allocatable, target :: outerKey(:), nonce(:)
  character(*), parameter        :: msg = "any text or binary data"
  integer :: i, body_first, nlen, ct_len
  integer(itb_status_kind) :: status

  allocate (pt(len(msg)))
  do i = 1, len(msg); pt(i) = transfer(msg(i:i), 0_c_int8_t); end do

  ! mode = 1 = Single Ouroboros (3 seeds);
  ! mode = 3 = Triple Ouroboros (7 seeds).
  call new_itb_encryptor(enc, "areion512", 2048, "hmac-blake3", 1)
  call enc%set_nonce_bits   (512)        ! 512-bit nonce (default 128)
  call enc%set_barrier_fill (4)          ! CSPRNG fill margin (default 1)
  call enc%set_bit_soup     (1)          ! optional bit-level split (bit-soup; default 0 = byte-level)
  call enc%set_lock_soup    (1)          ! optional Insane Interlocked Mode

  blob = enc%export_state()              ! persistence: keys + components + MAC key
  ct   = enc%encrypt_auth(pt)            ! 32-byte tag embedded inside the container
  ct_len = size(ct)

  ! Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
  call itb_wrapper_generate_key(ITB_WRAPPER_CIPHER_AES_128_CTR, outerKey, status)

  ! Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
  call itb_wrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR, outerKey, ct, nonce, status)
  nlen = size(nonce)
  allocate (wire(nlen + ct_len))
  wire(1:nlen) = nonce(:)
  wire(nlen + 1 : nlen + ct_len) = ct(:)

  ! Receiver -- strip nonce + XOR-decrypt body in place; construct a
  ! matching encryptor and import the blob.
  call itb_unwrap_in_place(ITB_WRAPPER_CIPHER_AES_128_CTR, outerKey, wire,    &
                           body_first, status)
  call new_itb_encryptor(dec, "areion512", 2048, "hmac-blake3", 1)
  call dec%import_state(blob)            ! restores keys + per-instance config
  pt = dec%decrypt_auth(wire(body_first : size(wire)))

  call dec%destroy()
  call enc%destroy()
  if (allocated(outerKey)) deallocate (outerKey)
  if (allocated(nonce))    deallocate (nonce)
  if (allocated(wire))     deallocate (wire)
end program
```

The `set_lock_seed (1)` option requests a dedicated lockSeed for
the bit-permutation derivation channel; it must precede the first
encrypt (mid-session activation surfaces as
`STATUS_EASY_LOCKSEED_AFTER_ENCRYPT`) and auto-couples
`set_lock_soup (1)` + `set_bit_soup (1)`. Mixed-primitive variants
are reachable via `itb_encryptor_mixed_single` (Single Ouroboros,
3 + 1 slots) and `itb_encryptor_mixed_triple` (Triple Ouroboros,
7 + 1 slots). The optional `prim_l` argument lives at the trailing
keyword position because Fortran's `optional` arguments must
follow non-optional ones; the C ABI's positional ordering for
`primL` between `prim_s` and `key_bits` is preserved on the FFI
side via keyword call.

## MPI + OpenMP safety

A single `type(itb_encryptor_t)` is **not** safe for concurrent
use across OpenMP threads or across MPI ranks sharing a memory
space — cipher methods, per-instance setters, and persistence
calls all mutate per-instance state without locking. The right
pattern is one encryptor per thread / rank.

```fortran
! RIGHT — one Encryptor per OpenMP thread; each thread owns its
!         own per-instance state and runs independently against
!         the libitb worker pool.
type(itb_encryptor_t) :: enc
integer :: i

!$omp parallel private(enc)
  call new_itb_encryptor(enc, "blake3", 1024, "hmac-blake3", 1)
  !$omp do
  do i = 1, n_chunks
    out_chunks(:, i) = enc%encrypt_auth(input_chunks(:, i))
  end do
  !$omp end do
  call enc%destroy()
!$omp end parallel
```

Sharing one encryptor across threads requires external
synchronisation (a critical section wrapping every cipher call)
and is generally a sign that the design wants per-thread
encryptors instead.

```fortran
! WRONG — shared Encryptor under !$omp parallel do races on the
!         per-instance handle state (libitb handle, closed flag,
!         per-instance Config snapshot). Behaviour is undefined.
type(itb_encryptor_t) :: shared_enc
call new_itb_encryptor(shared_enc, "blake3", 1024, "hmac-blake3", 1)
!$omp parallel do
do i = 1, n_chunks
  out_chunks(:, i) = shared_enc%encrypt_auth(input_chunks(:, i))
end do
```

For MPI: each rank owns its own encryptor; no shared handles
across ranks (the libitb handle table is process-local). The
process-wide setters (`itb_set_max_workers`, `itb_set_bit_soup`,
`itb_set_lock_soup`, `itb_set_nonce_bits`,
`itb_set_barrier_fill`) must be invoked identically on every rank
at startup before any worker tasks dispatch. Mid-run mutation
while a cipher call is in flight on any rank corrupts that
running operation, because the cipher snapshots its configuration
at call entry.

## Architecture

The binding splits along concept boundaries to keep each module
focused and to let the `.mod` cache turn over per-module without
re-compiling unrelated translation units.

| Module | Public surface |
|---|---|
| `itb_kinds` | KIND aliases re-exported from `iso_c_binding` (`itb_status_kind`, `itb_handle_kind`, `itb_byte_kind`, `itb_u64_kind`, `itb_size_kind`, `itb_int32_kind`, `itb_null_handle`) |
| `itb_sys` | Raw `interface ... bind(C)` declarations for ~93 ITB_* exports — audit-friendly, kept dependency-free below the safe wrappers |
| `itb_strings` | C-string ↔ Fortran-string helpers (`make_c_string`, `c_buffer_to_fortran_string`); uniform NUL-strip discipline on every libitb string getter |
| `itb_errors` | 24 status-code constants + `raise_itb_error` halt path + `itb_last_error_message` accessor |
| `itb_library` | Library-level info + process-wide setters / getters (`itb_version`, `itb_list_hashes`, `itb_list_macs`, `itb_set_*` / `itb_get_*`) |
| `itb_seed` | `itb_seed_t` RAII wrapper + CSPRNG / from-components constructors + `attach_lock_seed` |
| `itb_mac` | `itb_mac_t` RAII wrapper + `new_itb_mac` constructor |
| `itb_cipher` | Free-function `itb_encrypt` / `itb_decrypt` / `itb_encrypt_auth` / `itb_decrypt_auth` (Single + Triple) |
| `itb_encryptor` | `itb_encryptor_t` Easy Mode handle + Mixed Single / Triple constructors + persistence + per-instance setters |
| `itb_blob` | `itb_blob128_t` / `itb_blob256_t` / `itb_blob512_t` width-typed persistence containers |
| `itb_streams` | Free-function chunked stream helpers (Single + Triple, plain + authenticated) |

Two-layer split: `itb_sys` carries the raw `bind(C)` declarations
verbatim from the libitb C ABI; everything above it adds NUL-strip,
two-call probe, defensive copies, closed-state preflight, and the
per-instance lifecycle. The libitb C ABI exported by
`dist/<os>-<arch>/libitb.h` is the behavioural source of truth;
the wrapper layer mirrors its semantics without adding
binding-side validation beyond what language idiom requires.

## Public API reference

Per-module summary of the exported types / subroutines / functions.
One line per entry, grouped by module, in source-declaration order.

### `itb_kinds`

- `itb_status_kind`, `itb_handle_kind`, `itb_byte_kind`,
  `itb_u64_kind`, `itb_size_kind`, `itb_int32_kind` — KIND
  parameters re-exported from `iso_c_binding`.
- `itb_null_handle` — sentinel zero handle for closed-state
  detection.

### `itb_errors`

- 24 `STATUS_*` constants — see [Status codes](#status-codes).
- `raise_itb_error (status)` — halt with diagnostic via Fortran
  2018 `error stop 1`; every wrapper method funnels its non-OK
  return through this helper. The free-function stream
  subroutines deviate by accepting an `intent(out) :: status`
  argument and returning the raw status code instead of halting.
- `itb_status_to_string (status) → name` — pure status-to-name
  lookup.
- `itb_last_error_message () → message` — two-call probe of
  `ITB_LastError`.

### `itb_library`

- `itb_version () → string`, `itb_max_key_bits () → int`,
  `itb_channels () → int`, `itb_header_size () → int`.
- `itb_hash_count`, `itb_hash_name (i)`, `itb_hash_width (i)`,
  `itb_list_hashes ()`.
- `itb_mac_count`, `itb_mac_name (i)`, `itb_mac_key_size (i)`,
  `itb_mac_tag_size (i)`, `itb_mac_min_key_bytes (i)`,
  `itb_list_macs ()`.
- `itb_set_bit_soup`, `itb_set_lock_soup`, `itb_set_max_workers`,
  `itb_set_nonce_bits`, `itb_set_barrier_fill` and their
  `itb_get_*` counterparts.

### `itb_seed`

- `type :: itb_seed_t` with type-bound procedures `destroy`,
  `raw_handle`, `is_closed`, `width`, `hash_name`, `components`,
  `hash_key`, `attach_lock_seed`, plus the `final ::
  itb_seed_final` safety-net hook.
- `new_itb_seed (s, hash_name, key_bits)` — CSPRNG-keyed
  constructor.
- `itb_seed_from_components (s, hash_name, components, hash_key)`
  — deterministic persistence-restore constructor.

### `itb_mac`

- `type :: itb_mac_t` with `destroy`, `raw_handle`, `is_closed`
  type-bound procedures + `final :: itb_mac_final` hook.
- `new_itb_mac (m, mac_name, key)` — single constructor.

### `itb_cipher`

- `itb_encrypt (noise, data, start, plaintext) → ciphertext`,
  `itb_decrypt (noise, data, start, ciphertext) → plaintext`.
- `itb_encrypt_auth (noise, data, start, mac, plaintext) → ciphertext`,
  `itb_decrypt_auth (noise, data, start, mac, ciphertext) → plaintext`.
- Triple counterparts (7 seeds): `itb_encrypt_triple`,
  `itb_decrypt_triple`, `itb_encrypt_auth_triple`,
  `itb_decrypt_auth_triple`.

### `itb_encryptor`

- `type :: itb_encryptor_t` with `encrypt`, `decrypt`,
  `encrypt_auth`, `decrypt_auth`, `close`, `destroy`,
  `set_lock_seed`, `set_bit_soup`, `set_lock_soup`,
  `set_chunk_size`, `set_nonce_bits`, `set_barrier_fill`,
  `primitive`, `primitive_at`, `mac_name`, `key_bits`, `mode`,
  `seed_count`, `nonce_bits`, `header_size`, `has_prf_keys`,
  `is_mixed`, `mac_key`, `prf_key`, `seed_components`,
  `export_state`, `import_state`, `parse_chunk_len`,
  `raw_handle`, `is_closed` type-bound procedures + `final ::
  itb_enc_final` hook.
- `new_itb_encryptor (e, primitive, key_bits, mac_name, mode)` —
  single-primitive constructor.
- `itb_encryptor_mixed_single (e, prim_n, prim_d, prim_s,
  key_bits, mac_name [, prim_l])` — Mixed Single Ouroboros.
- `itb_encryptor_mixed_triple (e, prim_n, prim_d1..3, prim_s1..3,
  key_bits, mac_name [, prim_l])` — Mixed Triple Ouroboros.
- `itb_encryptor_peek_config (blob, primitive, key_bits, mode,
  mac_name)` — inspect a saved blob without constructing a
  matching encryptor.
- `itb_last_mismatch_field () → field_name` — read the offending
  JSON field name from the most recent `STATUS_EASY_MISMATCH`
  on this thread.

### `itb_blob`

- `type :: itb_blob128_t` / `itb_blob256_t` / `itb_blob512_t`
  with `width`, `mode`, `set_key`, `get_key`, `set_components`,
  `get_components`, `set_mac_key`, `get_mac_key`, `set_mac_name`,
  `get_mac_name`, `export`, `export_3`, `import`, `import_3`,
  `destroy`, `raw_handle`, `is_closed` type-bound procedures +
  `final ::` hook.
- `new_itb_blob128 (b)` / `new_itb_blob256 (b)` /
  `new_itb_blob512 (b)` — width-typed constructors.
- `ITB_BLOB_OPT_LOCKSEED` (`1 << 0`), `ITB_BLOB_OPT_MAC`
  (`1 << 1`) — `opts` bitmask constants for `export` /
  `export_3`.

### `itb_streams`

- `abstract interface itb_stream_read_fn (user_ctx, buf, cap,
  out_n) → rc` and `itb_stream_write_fn (user_ctx, buf, n) →
  rc` — `bind(C)` callback shapes for source / sink.
- `itb_stream_encrypt`, `itb_stream_decrypt` — Single Ouroboros
  plain.
- `itb_stream_encrypt_triple`, `itb_stream_decrypt_triple` —
  Triple Ouroboros plain.
- `itb_stream_encrypt_auth`, `itb_stream_decrypt_auth` — Single
  Ouroboros authenticated.
- `itb_stream_encrypt_auth_triple`, `itb_stream_decrypt_auth_triple`
  — Triple Ouroboros authenticated.

### `itb_sys`, `itb_strings`, `itb_kinds` (raw layer)

`itb_sys` carries the raw `interface ... bind(C)` declarations for
every libitb FFI export — direct consumers should reach for the
safe wrappers in the modules above. `itb_strings` exposes the
NUL-strip / NUL-append helpers (`make_c_string`,
`c_buffer_to_fortran_string`) used by every higher-level wrapper
that touches a libitb string boundary; consumers writing their own
extensions on top of `itb_sys` use these helpers verbatim to keep
the string discipline uniform.

## Lifecycle discipline

Every owning derived type carries both a `final ::` safety-net
hook AND an explicit `destroy ()` type-bound procedure. The
canonical lifecycle release is `call h%destroy()`; the `final`
hook is shipped as a safety net for short-running programs that
let the variable fall out of scope without an explicit release.

The split exists because `final` invocation timing is **not**
deterministic across major Fortran compilers — gfortran, ifx, and
nvfortran differ on temporaries-during-reallocation, end-of-scope
deferral, and re-entry behaviour. Production code that wants a
predictable release point calls `destroy ()` explicitly. Errors
raised inside `final` are swallowed because the hook may fire at
unpredictable program scopes; errors raised inside `destroy ()`
propagate via `raise_itb_error`, halting through `error stop` if
the underlying libitb free returns a status the wrapper cannot
recover from (which in practice never happens for the free path —
libitb's `*_Free` returns OK or `STATUS_BAD_HANDLE`).

`destroy ()` is **idempotent**. Calling it twice is a no-op; the
second call sees the closed flag and returns without entering
libitb. The closed-state preflight applies the same flag check
across every type-bound method on `itb_encryptor_t`: subsequent
cipher / setter / getter calls on a closed encryptor raise with
`STATUS_EASY_CLOSED` (raised via error stop) directly, without
round-tripping libitb. Blob types follow the same pattern with
`STATUS_BAD_HANDLE` (the libitb registry has no
`STATUS_BLOB_CLOSED` discriminator).

The Easy Mode encryptor has two release paths:
`enc%close ()` wipes PRF / MAC / seed material on the Go side via
`ITB_Easy_Close` and marks the wrapper closed; `enc%destroy ()`
releases the underlying libitb handle via `ITB_Easy_Free`. Both
are idempotent. Production code calls `destroy ()` at the end of
the encryptor's lifetime; `close ()` is for paths that want to
zero the keying material early while keeping the wrapper struct
alive (e.g. before serialising state and immediately re-importing
into a fresh encryptor).

Constructors are subroutines with `intent (out)`, not functions.
Subroutine-with-`intent (out)` is the canonical Fortran idiom for
handle-owning derived types: the destination is initialised in
place, no function-result temporary is created, no premature
finalisation runs on a value that has just been "moved" into the
caller's variable. Calls take the `call new_itb_X (h, ...)` form
across every constructor in the binding.

## Threading model

A single `type(itb_encryptor_t)` is **not safe** for concurrent
use from multiple threads — cipher methods (`encrypt` / `decrypt`
/ `encrypt_auth` / `decrypt_auth`), per-instance setters, and
`close` / `destroy` / `import_state` all mutate per-instance
state without locking. Sharing one encryptor across threads
requires external synchronisation; distinct encryptor handles,
each owned by one thread, run independently against the libitb
worker pool.

By contrast, the low-level cipher free functions (`itb_encrypt` /
`itb_decrypt` / `itb_encrypt_auth` / `itb_decrypt_auth` plus the
Triple-Ouroboros counterparts) take read-only Seed pointers and
allocate output per call — they are thread-safe under concurrent
invocation when each thread holds distinct seed handles and a
distinct MAC handle. Process-wide `itb_set_*` setters
(`itb_set_nonce_bits`, `itb_set_barrier_fill`,
`itb_set_max_workers`, `itb_set_bit_soup`, `itb_set_lock_soup`)
are **atomic individually** and safe to call from any thread; the
caveat is logical, not atomic — changing a knob WHILE an encrypt
/ decrypt call is in flight can corrupt that operation, since
the cipher snapshots the configuration at call entry and a
mid-flight change breaks the running invariants.

`itb_seed_t%attach_lock_seed` mutates seed state (not a single
atomic counter) and is **not thread-safe** — call it outside any
in-flight cipher operation on the same noise seed.

The textual diagnostic surfaced by `itb_last_error_message ()`
reflects the calling thread's most recent libitb error
(libitb's `ITB_LastError` lives in TLS), so concurrent threads do
not race on it. The structural status code returned by every
entry point is unaffected by thread interleaving.

A single stream call (`itb_stream_encrypt` /
`itb_stream_encrypt_auth` / `_decrypt` / `_decrypt_auth` plus
Triple counterparts) is not thread-safe internally — its state
lives on the call stack and is single-threaded. Distinct stream
calls, each on its own thread with its own seed handles and (for
authenticated variants) MAC handle, run independently against
the libitb worker pool. The free-function-only stream surface
makes the threading contract the same as the rest of the
free-function cipher path.

## Persistence

Two persistence surfaces are exposed.

**Easy Mode**: `enc%export_state ()` returns a JSON blob carrying
PRF keys, seed components, MAC key, and the dedicated lockSeed
material when active. `enc%import_state (blob)` on a matching
encryptor restores the keying material — the receiver constructs
the encryptor with the same `primitive` / `key_bits` /
`mac_name` / `mode` arguments, calls `import_state`, and proceeds
with `decrypt_auth`. Per-instance configuration knobs
(`nonce_bits`, `barrier_fill`, `bit_soup`, `lock_soup`,
`chunk_size`) are NOT carried in the v1 blob; the lockSeed flag
IS carried because activating it changes the structural seed
count. Mismatches on `primitive` / `key_bits` / `mode` /
`mac_name` surface as `STATUS_EASY_MISMATCH`; the offending JSON
field name is reachable via `itb_last_mismatch_field ()`.

**Pre-construction inspection** of a saved blob is reachable via
`itb_encryptor_peek_config (blob, primitive, key_bits, mode,
mac_name)`. Useful when the receiver multiplexes blobs of
different shapes (different primitive / mode / MAC choices). The
peek path conflates "version too new" with "malformed" and
surfaces both as `STATUS_EASY_MALFORMED`; only `import_state`
differentiates the two via the dedicated
`STATUS_EASY_VERSION_TOO_NEW` status.

**Native Blob**: `itb_blob128_t` / `itb_blob256_t` /
`itb_blob512_t` wrap the libitb Native Blob C ABI — width-specific
containers that pack the low-level encryptor material (per-seed
hash key + components + optional dedicated lockSeed + optional MAC
key + name) plus the captured process-wide configuration into one
self-describing JSON blob. Used on the lower-level encrypt /
decrypt path where each seed slot may carry a different primitive.
The width is fixed at construction (128 / 256 / 512); mismatching
the wire blob's width against the receiving Blob's width surfaces
as `STATUS_BLOB_MODE_MISMATCH`.

Slot indexing follows the libitb convention: 0 = noise, 1 = data,
2 = start (Single mode), 3 = optional dedicated lockSeed (any
mode), 4..6 = data1 / data2 / data3, 7..9 = start1 / start2 /
start3 (Triple mode).

Export option bitmask (`opts` parameter on `b%export ()` /
`b%export_3 ()`):

| Constant | Value | Meaning |
|---|---|---|
| `ITB_BLOB_OPT_LOCKSEED` | `1` | emit `l` slot (KeyL + components) |
| `ITB_BLOB_OPT_MAC` | `2` | emit MAC key + name |

Combine via `ior` to opt into multiple sections in one export
call. The default of `0` emits the base seed material only.

## Hash primitives

Names match the canonical libitb registry. Listed below in the
binding-side canonical PRF-only ordering.

| Primitive | FFI name | Native width (bits) | Family |
|---|---|---|---|
| **Areion-SoEM-256** | `areion256` | 256 | Areion |
| **Areion-SoEM-512** | `areion512` | 512 | Areion |
| **BLAKE2b-256** | `blake2b256` | 256 | BLAKE |
| **BLAKE2b-512** | `blake2b512` | 512 | BLAKE |
| **BLAKE2s** | `blake2s` | 256 | BLAKE |
| **BLAKE3** | `blake3` | 256 | BLAKE |
| **AES-CMAC** | `aescmac` | 128 | AES-CMAC |
| **SipHash-2-4** | `siphash24` | 128 | SipHash |
| **ChaCha20** | `chacha20` | 256 | ChaCha20 |

SipHash-2-4 is the one primitive without an internal fixed key —
its keying material is the seed components themselves.
`itb_seed_t%hash_key ()` returns an empty array for a
SipHash-2-4 seed; check `enc%has_prf_keys ()` before calling
`enc%prf_key (slot)` on the per-slot encryptor accessor.

All seeds passed to one cipher call must share the same native
hash width. Mixing widths surfaces `STATUS_SEED_WIDTH_MIX`.

## MAC primitives

Names match the libitb MAC registry; ordering matches that
registry's declaration order.

| MAC | Key bytes | Tag bytes | Underlying primitive |
|---|---|---|---|
| `kmac256` | 32 | 32 | KMAC256 (Keccak-derived) |
| `hmac-sha256` | 32 | 32 | HMAC over SHA-256 |
| `hmac-blake3` | 32 | 32 | HMAC over BLAKE3 |

`kmac256` and `hmac-sha256` accept keys 16 bytes and longer; the
Fortran binding's tests and examples use 32 bytes uniformly across
primitives for cross-binding consistency. `hmac-blake3` requires
exactly 32 bytes by construction.

## Process-wide configuration

Every setter takes effect for all subsequent encrypt / decrypt
calls in the process. Out-of-range values surface as
`STATUS_BAD_INPUT` rather than crashing.

| Procedure | Accepted values | Default |
|---|---|---|
| `itb_set_max_workers (n)` | non-negative integer | 0 (auto) |
| `itb_set_nonce_bits (n)` | 128, 256, 512 | 128 |
| `itb_set_barrier_fill (n)` | 1, 2, 4, 8, 16, 32 | 1 |
| `itb_set_bit_soup (mode)` | 0 (off), non-zero (on) | 0 |
| `itb_set_lock_soup (mode)` | 0 (off), non-zero (on) | 0 |

Mutating these affects every encryptor constructed AFTER the
call; pre-existing `itb_encryptor_t` instances snapshot the
configuration at construction time and continue to use their
per-instance Config unaffected.

Read-only library metadata: `itb_max_key_bits ()`,
`itb_channels ()`, `itb_header_size ()`, `itb_version ()`. For
low-level chunk parsing (e.g. when implementing custom file
formats around ITB chunks): `itb_parse_chunk_len_c (header,
header_len, out)` (raw-layer entry through `itb_sys`) inspects
the fixed-size chunk header and returns the chunk's total
on-the-wire length; `itb_header_size ()` returns the active
header byte count (20 / 36 / 68 for nonce sizes 128 / 256 / 512
bits). The Easy Mode encryptor exposes `enc%parse_chunk_len
(header)` as a per-instance counterpart that snapshots the
encryptor's own nonce_bits.

Three rules govern the BitSoup / LockSoup / LockSeed overlay.
libitb owns the cascade; the binding forwards each setter call
verbatim:

1. **Setter-level: LockSoup → BitSoup** (always, both modes).
   `itb_set_lock_soup (1)` auto-engages `BitSoup = 1`;
   `enc%set_lock_seed (1)` auto-engages `BitSoup = 1` +
   `LockSoup = 1` (the dedicated lockSeed has no wire effect
   without the overlay).
2. **Mode-dependent dispatch: Single Ouroboros activates the
   overlay if EITHER flag is set.** In `mode = 1`, the Go-side
   dispatch engages the lock-soup overlay if either
   `BitSoup == 1` OR `LockSoup == 1`. In Triple Ouroboros
   (`mode = 3`), bit-soup and lock-soup are independently
   meaningful — bit-soup alone splits payload bits without the
   PRF-keyed permutation overlay.
3. **Off-direction coercion while LockSeed active.** If the
   dedicated lockSeed is wired in, calling `enc%set_bit_soup (0)`
   or `enc%set_lock_soup (0)` is silently coerced to `1` to keep
   the overlay engaged on the dedicated lockSeed channel; call
   `enc%set_lock_seed (0)` first to detach the lockSeed and
   fully disengage.

The low-level `itb_seed_t%attach_lock_seed` does **not**
auto-couple any flag — explicitly call `itb_set_bit_soup (1)` or
`itb_set_lock_soup (1)` before encrypt, otherwise the build-PRF
guard fires on encrypt-time.

## Status codes

Mirror the constants in `cmd/cshared/internal/capi/errors.go`
bit-identically.

| Code | Name | Description |
|---|---|---|
| 0 | `STATUS_OK` | Success — the only non-failure return value |
| 1 | `STATUS_BAD_HASH` | Unknown hash primitive name |
| 2 | `STATUS_BAD_KEY_BITS` | ITB key width invalid for the chosen primitive |
| 3 | `STATUS_BAD_HANDLE` | FFI handle invalid or already freed |
| 4 | `STATUS_BAD_INPUT` | Generic shape / range / domain violation on a call argument |
| 5 | `STATUS_BUFFER_TOO_SMALL` | Output buffer cap below required size; probe-then-allocate idiom |
| 6 | `STATUS_ENCRYPT_FAILED` | Encrypt path raised on the Go side (rare; structural / OOM / empty input) |
| 7 | `STATUS_DECRYPT_FAILED` | Decrypt path raised on the Go side (corrupt ciphertext shape) |
| 8 | `STATUS_SEED_WIDTH_MIX` | Seeds passed to one call do not share the same native hash width |
| 9 | `STATUS_BAD_MAC` | Unknown MAC name or key-length violates the primitive's `min_key_bytes` |
| 10 | `STATUS_MAC_FAILURE` | MAC verification failed — tampered ciphertext or wrong MAC key |
| 11 | `STATUS_EASY_CLOSED` | Easy Mode encryptor call after `close` / `destroy` |
| 12 | `STATUS_EASY_MALFORMED` | Easy Mode `import_state` blob fails JSON parse / structural check |
| 13 | `STATUS_EASY_VERSION_TOO_NEW` | Easy Mode blob version field higher than this build supports |
| 14 | `STATUS_EASY_UNKNOWN_PRIMITIVE` | Easy Mode blob references a primitive this build does not know |
| 15 | `STATUS_EASY_UNKNOWN_MAC` | Easy Mode blob references a MAC this build does not know |
| 16 | `STATUS_EASY_BAD_KEY_BITS` | Easy Mode blob's `key_bits` invalid for its primitive |
| 17 | `STATUS_EASY_MISMATCH` | Easy Mode blob disagrees with the receiver on `primitive` / `key_bits` / `mode` / `mac`; field name via `itb_last_mismatch_field ()` |
| 18 | `STATUS_EASY_LOCKSEED_AFTER_ENCRYPT` | `enc%set_lock_seed (1)` called after the first encrypt — must precede the first ciphertext |
| 19 | `STATUS_BLOB_MODE_MISMATCH` | Native Blob importer received a Single blob into a Triple receiver (or vice versa) |
| 20 | `STATUS_BLOB_MALFORMED` | Native Blob payload fails JSON parse / magic / structural check |
| 21 | `STATUS_BLOB_VERSION_TOO_NEW` | Native Blob version field higher than this libitb build supports |
| 22 | `STATUS_BLOB_TOO_MANY_OPTS` | Native Blob export opts mask carries unsupported bits |
| 23 | `STATUS_STREAM_TRUNCATED` | Streaming AEAD transcript truncated before the terminator chunk; surfaced by the binding's stream loop helpers |
| 24 | `STATUS_STREAM_AFTER_FINAL` | Streaming AEAD transcript carries chunk bytes after the terminator; surfaced by the binding's stream loop helpers |
| 99 | `STATUS_INTERNAL` | Generic "internal" sentinel for paths the caller cannot recover from at the binding layer |

Empty plaintext / ciphertext is rejected by libitb itself with
`STATUS_ENCRYPT_FAILED` ("itb: empty data") on every cipher entry
point. The binding propagates the rejection verbatim — pass at
least one byte.

## Constraints

- **Fortran 2018 minimum.** The wrapper layer uses
  `error stop <status>` (Fortran 2018), `class(...)` /
  `type-bound procedure` (Fortran 2003), `final ::` (Fortran 2003),
  `iso_c_binding` (Fortran 2003), and `move_alloc` (Fortran
  2003). Earlier dialects do not support the safety-net hook.
- **Two-layer architecture.** All consumer-facing types and
  procedures live under the per-concept modules (`itb_seed`,
  `itb_mac`, `itb_cipher`, `itb_encryptor`, `itb_blob`,
  `itb_streams`, `itb_library`, `itb_errors`, `itb_kinds`,
  `itb_strings`); `itb_sys` is the raw-FFI substrate kept
  separate so audits can read it independently.
- **No external runtime deps.** The wrapper imports only
  `iso_c_binding` and `iso_fortran_env` from the standard
  library; the libitb shared library is the only non-stdlib
  runtime dependency.
- **Frozen C ABI.** The `ITB_*` exports in
  `dist/<os>-<arch>/libitb.h` define the contract; the Fortran
  binding does not extend or reshape them.
- **No `dlopen`.** Symbols are bound at link time via
  `-litb` plus an embedded RPATH. Consumers wanting
  runtime-resolved FFI loading can wrap the binding's shared
  library list in their own `dlopen` shim.

## In-place encrypt / decrypt — future enhancement

The current C ABI's `ITB_Encrypt` / `ITB_EncryptAuth` family takes
distinct input / output buffers, copying input to output through
the cipher. An in-place ABI extension
(`ITB_EncryptInline` / `ITB_DecryptInline` plus authenticated
counterparts) is on the libitb-side roadmap; once it lands, the
Fortran binding will expose the same surface as `inline` /
`encrypt_inline` overloads alongside the existing copy-based
entry points. HPC consumers driving in-memory encryption against
chunk buffers larger than the L3 cache stand to benefit from the
reduced bandwidth pressure. No timeline; the surface here remains
copy-based until libitb's roadmap entry lands.

## API Overview

A concise module-by-module roll-up of the public surface. The
[Public API reference](#public-api-reference) section above carries
the per-symbol breakdown; this overview groups the same symbols by
concern for quick scanning. Every entry is a `public ::` export
from the named module.

### Library metadata (`itb_library`)

| Symbol | Purpose |
|---|---|
| `itb_version () → string` | Library version `"<major>.<minor>.<patch>"` |
| `itb_max_key_bits () → int` | Max supported ITB key width in bits |
| `itb_channels () → int` | Number of native channel slots |
| `itb_header_size () → int` | Current chunk header size in bytes |
| `itb_hash_count / itb_hash_name (i) / itb_hash_width (i) / itb_list_hashes ()` | Hash catalogue accessors |
| `itb_mac_count / itb_mac_name (i) / itb_mac_key_size (i) / itb_mac_tag_size (i) / itb_mac_min_key_bytes (i) / itb_list_macs ()` | MAC catalogue accessors |

### Process-wide configuration (`itb_library`)

| Symbol | Purpose |
|---|---|
| `itb_set_bit_soup / itb_get_bit_soup` | Bit Soup mode toggle |
| `itb_set_lock_soup / itb_get_lock_soup` | Lock Soup mode toggle |
| `itb_set_max_workers / itb_get_max_workers` | Worker pool cap |
| `itb_set_nonce_bits / itb_get_nonce_bits` | Nonce width (128 / 256 / 512) |
| `itb_set_barrier_fill / itb_get_barrier_fill` | Barrier-fill factor |
| `function itb_set_memory_limit (limit) result (prev)` | Go runtime heap soft limit in bytes; pass negative to query only |
| `function itb_set_gc_percent (pct) result (prev)` | Go GC trigger percentage; pass negative to query only |

### Seeds and MAC (`itb_seed`, `itb_mac`)

| Symbol | Purpose |
|---|---|
| `type :: itb_seed_t` | CSPRNG-keyed Seed handle |
| `new_itb_seed (s, hash_name, key_bits)` | CSPRNG-fresh constructor |
| `itb_seed_from_components (s, hash_name, components, hash_key)` | Reconstruct from explicit components |
| `s%width / s%hash_name / s%components / s%hash_key / s%attach_lock_seed (lock)` | Seed introspection + lock-seed attachment |
| `type :: itb_mac_t` | MAC handle |
| `new_itb_mac (m, mac_name, key)` | Construct MAC handle |

### Low-level cipher (`itb_cipher`)

| Symbol | Purpose |
|---|---|
| `itb_encrypt (noise, data, start, plaintext) → ciphertext` / `itb_decrypt (...)` | Single Message |
| `itb_encrypt_auth (noise, data, start, mac, plaintext)` / `itb_decrypt_auth (...)` | MAC-authenticated counterparts |
| `itb_encrypt_triple (noise, d1, d2, d3, s1, s2, s3, plaintext)` / `itb_decrypt_triple (...)` | Triple Ouroboros |
| `itb_encrypt_auth_triple (...)` / `itb_decrypt_auth_triple (...)` | Triple Ouroboros MAC-authenticated |

### Easy Mode encryptor (`itb_encryptor`)

| Symbol | Purpose |
|---|---|
| `type :: itb_encryptor_t` | Easy Mode encryptor handle |
| `new_itb_encryptor (e, primitive, key_bits, mac_name, mode)` | Single-primitive constructor |
| `itb_encryptor_mixed_single (e, prim_n, prim_d, prim_s, key_bits, mac_name [, prim_l])` | Mixed Single Ouroboros |
| `itb_encryptor_mixed_triple (e, prim_n, prim_d1..3, prim_s1..3, key_bits, mac_name [, prim_l])` | Mixed Triple Ouroboros |
| `e%encrypt / e%decrypt / e%encrypt_auth / e%decrypt_auth` | Cipher entry points |
| `e%set_lock_seed / set_bit_soup / set_lock_soup / set_chunk_size / set_nonce_bits / set_barrier_fill` | Per-instance setters |
| `e%primitive / primitive_at / mac_name / key_bits / mode / seed_count / nonce_bits / header_size / has_prf_keys / is_mixed` | Accessors |
| `e%mac_key / prf_key / seed_components / parse_chunk_len` | Key-material + per-instance chunk-length parser |
| `e%export_state / import_state` | State-blob persistence |
| `itb_encryptor_peek_config (blob, primitive, key_bits, mode, mac_name)` | Pre-import discriminator |
| `itb_last_mismatch_field () → field_name` | Read offending JSON field name after `STATUS_EASY_MISMATCH` |
| `e%close / e%destroy` | Release encryptor |

### Streaming AEAD (`itb_streams`)

| Symbol | Purpose |
|---|---|
| `abstract interface itb_stream_read_fn / itb_stream_write_fn` | `bind(C)` source / sink callback shapes |
| `itb_stream_encrypt / itb_stream_decrypt` | Single Low-Level streams |
| `itb_stream_encrypt_triple / itb_stream_decrypt_triple` | Triple Low-Level streams |
| `itb_stream_encrypt_auth / itb_stream_decrypt_auth` | Single Low-Level Streaming AEAD |
| `itb_stream_encrypt_auth_triple / itb_stream_decrypt_auth_triple` | Triple Low-Level Streaming AEAD |
| `itb_encryptor_stream_encrypt_auth / itb_encryptor_stream_decrypt_auth` | Easy Mode Streaming AEAD |

### Native Blob (`itb_blob`)

| Symbol | Purpose |
|---|---|
| `type :: itb_blob128_t / itb_blob256_t / itb_blob512_t` | Width-specific Native Blob handles |
| `new_itb_blob128 / new_itb_blob256 / new_itb_blob512` | Constructors |
| `b%width / b%mode` | Width + mode accessors |
| `b%set_key / set_components / set_mac_key / set_mac_name (...)` | Field setters |
| `b%get_key / get_components / get_mac_key / get_mac_name (...)` | Field getters |
| `b%export / export_3 / import / import_3` | Serialisation |
| `ITB_BLOB_OPT_LOCKSEED / ITB_BLOB_OPT_MAC` | Export opt-in flag bits |

### Wrapper (`itb_wrapper`)

| Symbol | Purpose |
|---|---|
| `ITB_WRAPPER_CIPHER_AES_128_CTR / ITB_WRAPPER_CIPHER_CHACHA20 / ITB_WRAPPER_CIPHER_SIPHASH24` | Cipher enum constants |
| `itb_wrapper_cipher_name (cipher) → name` | Canonical FFI name |
| `itb_wrapper_key_size (cipher) → bytes` / `itb_wrapper_nonce_size (cipher) → bytes` | Cipher dimension accessors |
| `itb_wrapper_generate_key (cipher, key, status)` | CSPRNG-fresh wrapper key |
| `itb_wrap (cipher, key, blob, wire, status)` / `itb_unwrap (cipher, key, wire, blob, status)` | Single Message Wrap / Unwrap |
| `itb_wrap_in_place (cipher, key, buf, nonce, status)` / `itb_unwrap_in_place (cipher, key, wire, nonce, status)` | In-place Wrap / Unwrap |
| `type(itb_wrap_stream_writer_t)` / `type(itb_unwrap_stream_reader_t)` | Streaming wrap writer / unwrap reader |
| `itb_wrap_stream_writer_new (...) / itb_unwrap_stream_reader_new (...)` | Streamer constructors |

### Errors and kinds (`itb_errors`, `itb_kinds`, `itb_strings`, `itb_sys`)

| Symbol | Purpose |
|---|---|
| 24 `STATUS_*` constants + `STATUS_INTERNAL` | Status-code surface |
| `raise_itb_error (status)` | Halt-on-error helper (`error stop 1`) — used by every wrapper method |
| `itb_status_to_string (status) → name` | Pure status-to-name lookup |
| `itb_last_error_message () → message` | Per-thread last-error retrieval |
| `itb_status_kind / itb_handle_kind / itb_byte_kind / itb_u64_kind / itb_size_kind / itb_int32_kind` | `iso_c_binding` re-exports |
| `itb_null_handle` | Sentinel zero handle for closed-state detection |
| `c_buffer_to_fortran_string / make_c_string / fortran_string_to_c_buffer` | String-boundary helpers |
| `itb_sys` module | Raw `bind(C)` FFI declarations — direct consumers should prefer the safe wrappers above |
