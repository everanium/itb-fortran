! itb_wrapper.f90 -- format-deniability wrapper module over libitb's
! ITB_Wrap* / ITB_Unwrap* / ITB_WrapStream* / ITB_UnwrapStream* /
! ITB_WrapperKeySize / ITB_WrapperNonceSize FFI exports.
!
! The wrap layer seals an ITB ciphertext under one of three outer
! keystream ciphers (AES-128-CTR / ChaCha20 / SipHash-2-4 in CTR
! mode) so the on-wire bytes carry no ITB-specific format pattern.
! ITB still provides content-deniability unconditionally; the wrap
! adds **format-deniability** on top so a passive observer cannot
! pattern-match the wire against the known ITB envelope. The wrap
! is **not an integrity layer** -- adding a MAC at this layer would
! defeat the format-deniability goal. Use ITB's MAC Authenticated
! path when integrity is required.
!
! Three flavours of helpers, picked per use case:
!
!   1. `itb_wrap` / `itb_unwrap` -- Single Message. Whole ITB ciphertext
!      treated as one opaque blob. Wire = nonce || keystream-XOR(blob).
!      Allocates a fresh `wire` / `blob` on the caller's behalf via
!      the Fortran `allocatable, intent(out)` convention.
!   2. `itb_wrap_in_place` / `itb_unwrap_in_place` -- no output-buffer allocation.
!      Mutates the caller's blob / wire buffer; emits the per-stream
!      nonce into a separate caller-supplied buffer (wrap) or returns
!      the body-first index into the wire (unwrap).
!   3. `itb_wrap_stream_writer_t` / `itb_unwrap_stream_reader_t`
!      derived types -- continuous bytestream. Each `update` advances
!      a per-handle keystream counter; pair with one `_destroy` /
!      `_free` call. Suitable for User-Driven Loop framing where
!      caller-side `u32_LE` length prefixes are written through the
!      wrap-writer alongside chunk bodies, so neither length nor body
!      appears in cleartext on the wire.
!
! Cipher selector. `itb_wrapper_cipher_*` integer parameters identify
! the outer cipher; `cipher_short_name(cipher)` returns the canonical
! NUL-terminated short name passed to the FFI. Out-of-range cipher
! values raise `STATUS_BAD_INPUT` via the standard error pipeline.
!
! Status reporting. The Single Message helpers and the stream
! constructors / `update` calls receive a final status code through
! an `intent(out) :: status` argument rather than raising via
! `raise_itb_error` -- the caller may want to recover from a bad
! cipher identifier or short wire without halting. `STATUS_OK`
! indicates success. On any non-OK code the binding's process-wide
! `itb_last_error_message()` carries the libitb diagnostic.
!
! Threading. The Single Message helpers are thread-safe -- every call
! constructs an outer cipher session of its own and the libitb
! keystream constructor draws a fresh CSPRNG nonce per call. Stream
! handles are **single-feeder**: every `update` advances the
! underlying keystream counter; concurrent `update` calls on the
! same handle race. Distinct handles run independently against the
! libitb worker pool.

module itb_wrapper
  use itb_kinds
  use itb_sys, only: itb_wrapper_key_size_c, itb_wrapper_nonce_size_c,    &
                       itb_wrapper_derive_key_c,                               &
                       itb_wrap_c, itb_unwrap_c,                              &
                       itb_wrap_in_place_c, itb_unwrap_in_place_c,           &
                       itb_wrap_stream_writer_init_c,                          &
                       itb_wrap_stream_writer_update_c,                        &
                       itb_wrap_stream_writer_free_c,                          &
                       itb_unwrap_stream_reader_init_c,                        &
                       itb_unwrap_stream_reader_update_c,                      &
                       itb_unwrap_stream_reader_free_c
  use itb_strings, only: make_c_string
  use itb_errors,  only: STATUS_OK, STATUS_BAD_INPUT, STATUS_BAD_HANDLE,    &
                          STATUS_INTERNAL
  implicit none
  private

  ! Public cipher identifiers (matching the C binding's
  ! itb_wrapper_cipher_t integer values: AES-128-CTR = 0,
  ! ChaCha20 = 1, SipHash-2-4 = 2, Areion-SoEM-256 = 3,
  ! Areion-SoEM-512 = 4, BLAKE2b-256 = 5, BLAKE2b-512 = 6,
  ! BLAKE2s = 7, BLAKE3 = 8).
  public :: ITB_WRAPPER_CIPHER_AES_128_CTR
  public :: ITB_WRAPPER_CIPHER_CHACHA20
  public :: ITB_WRAPPER_CIPHER_SIPHASH24
  public :: ITB_WRAPPER_CIPHER_AREION_256
  public :: ITB_WRAPPER_CIPHER_AREION_512
  public :: ITB_WRAPPER_CIPHER_BLAKE2B_256
  public :: ITB_WRAPPER_CIPHER_BLAKE2B_512
  public :: ITB_WRAPPER_CIPHER_BLAKE2S
  public :: ITB_WRAPPER_CIPHER_BLAKE3

  ! Single Message + size helpers.
  public :: itb_wrapper_cipher_name
  public :: itb_wrapper_key_size
  public :: itb_wrapper_nonce_size
  public :: itb_wrapper_generate_key
  public :: itb_wrapper_derive_key
  public :: itb_wrap
  public :: itb_unwrap
  public :: itb_wrap_in_place
  public :: itb_unwrap_in_place

  ! Streaming handle types + their lifecycle / update procedures.
  public :: itb_wrap_stream_writer_t
  public :: itb_unwrap_stream_reader_t
  public :: itb_wrap_stream_writer_new
  public :: itb_unwrap_stream_reader_new

  integer, parameter :: ITB_WRAPPER_CIPHER_AES_128_CTR = 0
  integer, parameter :: ITB_WRAPPER_CIPHER_CHACHA20    = 1
  integer, parameter :: ITB_WRAPPER_CIPHER_SIPHASH24   = 2
  integer, parameter :: ITB_WRAPPER_CIPHER_AREION_256  = 3
  integer, parameter :: ITB_WRAPPER_CIPHER_AREION_512  = 4
  integer, parameter :: ITB_WRAPPER_CIPHER_BLAKE2B_256 = 5
  integer, parameter :: ITB_WRAPPER_CIPHER_BLAKE2B_512 = 6
  integer, parameter :: ITB_WRAPPER_CIPHER_BLAKE2S     = 7
  integer, parameter :: ITB_WRAPPER_CIPHER_BLAKE3      = 8

  ! ----------------------------------------------------------------
  ! Streaming derived types
  !
  ! Each carries an opaque libitb stream-handle (`uintptr_t` on the
  ! C side, `c_intptr_t` here) plus a `closed` flag so the wrapper
  ! can short-circuit subsequent `update` / `_free` calls after a
  ! `destroy` without round-tripping libitb. The `final ::` hook is
  ! a safety-net only -- production code calls `obj%destroy()`
  ! deterministically.
  ! ----------------------------------------------------------------

  type :: itb_wrap_stream_writer_t
    private
    integer(itb_handle_kind) :: handle = itb_null_handle
    logical                  :: closed = .true.
  contains
    procedure :: update  => wrap_stream_writer_update
    procedure :: destroy => wrap_stream_writer_destroy
    final     :: wrap_stream_writer_final
  end type

  type :: itb_unwrap_stream_reader_t
    private
    integer(itb_handle_kind) :: handle = itb_null_handle
    logical                  :: closed = .true.
  contains
    procedure :: update  => unwrap_stream_reader_update
    procedure :: destroy => unwrap_stream_reader_destroy
    final     :: unwrap_stream_reader_final
  end type

contains

  ! ----------------------------------------------------------------
  ! Cipher-name dispatch
  ! ----------------------------------------------------------------

  ! Map a public cipher integer to the canonical short name passed
  ! across the FFI boundary. The empty allocatable result signals an
  ! out-of-range cipher value to the caller.
  pure function itb_wrapper_cipher_name(cipher) result(name)
    integer, intent(in) :: cipher
    character(:), allocatable :: name
    select case (cipher)
    case (ITB_WRAPPER_CIPHER_AES_128_CTR); name = "aescmac"
    case (ITB_WRAPPER_CIPHER_CHACHA20);    name = "chacha20"
    case (ITB_WRAPPER_CIPHER_SIPHASH24);   name = "siphash24"
    case (ITB_WRAPPER_CIPHER_AREION_256);  name = "areion256"
    case (ITB_WRAPPER_CIPHER_AREION_512);  name = "areion512"
    case (ITB_WRAPPER_CIPHER_BLAKE2B_256); name = "blake2b256"
    case (ITB_WRAPPER_CIPHER_BLAKE2B_512); name = "blake2b512"
    case (ITB_WRAPPER_CIPHER_BLAKE2S);     name = "blake2s"
    case (ITB_WRAPPER_CIPHER_BLAKE3);      name = "blake3"
    case default;                          name = ""
    end select
  end function

  ! ----------------------------------------------------------------
  ! Size accessors
  ! ----------------------------------------------------------------

  ! Reports the byte length of the keystream-cipher key for the named
  ! outer cipher. `status` carries the libitb status; on non-OK
  ! `out_size` is set to zero.
  subroutine itb_wrapper_key_size(cipher, out_size, status)
    integer,                  intent(in)  :: cipher
    integer,                  intent(out) :: out_size
    integer(itb_status_kind), intent(out) :: status
    character(:), allocatable :: cn
    character(kind=c_char), allocatable, target :: c_name(:)
    integer(itb_size_kind) :: n
    integer(c_int) :: rc

    out_size = 0
    cn = itb_wrapper_cipher_name(cipher)
    if (len(cn) == 0) then
      status = STATUS_BAD_INPUT
      return
    end if
    call make_c_string(cn, c_name)
    n = 0_itb_size_kind
    rc = itb_wrapper_key_size_c(c_loc(c_name), n)
    status = rc
    if (rc == STATUS_OK) out_size = int(n)
  end subroutine

  ! Reports the on-wire nonce length the named outer cipher emits per
  ! stream. `status` carries the libitb status; on non-OK `out_size`
  ! is set to zero.
  subroutine itb_wrapper_nonce_size(cipher, out_size, status)
    integer,                  intent(in)  :: cipher
    integer,                  intent(out) :: out_size
    integer(itb_status_kind), intent(out) :: status
    character(:), allocatable :: cn
    character(kind=c_char), allocatable, target :: c_name(:)
    integer(itb_size_kind) :: n
    integer(c_int) :: rc

    out_size = 0
    cn = itb_wrapper_cipher_name(cipher)
    if (len(cn) == 0) then
      status = STATUS_BAD_INPUT
      return
    end if
    call make_c_string(cn, c_name)
    n = 0_itb_size_kind
    rc = itb_wrapper_nonce_size_c(c_loc(c_name), n)
    status = rc
    if (rc == STATUS_OK) out_size = int(n)
  end subroutine

  ! ----------------------------------------------------------------
  ! CSPRNG helpers
  !
  ! Reads from /dev/urandom on POSIX hosts. Mirrors the C binding's
  ! convention -- the libitb FFI does not expose a generic "fill N
  ! random bytes" entry point, so the binding satisfies the contract
  ! locally. Fortran-only callers get a portable Unix path; the
  ! Fortran intrinsic `random_number` is intentionally NOT used here
  ! because its default seeding is not cryptographic strength on
  ! every compiler / runtime.
  ! ----------------------------------------------------------------

  ! Fills `out` with `n` CSPRNG bytes drawn from /dev/urandom. The
  ! file is opened, read, and closed inline; on read short / open
  ! failure `status` carries STATUS_INTERNAL and the partial buffer
  ! contents are undefined.
  subroutine fill_csprng(out, n, status)
    integer(itb_byte_kind),   intent(out) :: out(:)
    integer,                  intent(in)  :: n
    integer(itb_status_kind), intent(out) :: status
    integer :: u, ios
    if (n <= 0) then
      status = STATUS_OK
      return
    end if
    open (newunit=u, file="/dev/urandom", access="stream", &
          form="unformatted", action="read", iostat=ios)
    if (ios /= 0) then
      status = STATUS_INTERNAL
      return
    end if
    read (u, iostat=ios) out(1:n)
    close (u)
    if (ios /= 0) then
      status = STATUS_INTERNAL
      return
    end if
    status = STATUS_OK
  end subroutine

  ! Allocates and fills a fresh CSPRNG outer cipher key for the named
  ! cipher. The returned `key(:)` is sized to the cipher's exact key
  ! length. Caller owns the allocation; no de-allocation helper is
  ! needed since Fortran allocatables release at end-of-scope.
  subroutine itb_wrapper_generate_key(cipher, key, status)
    integer,                             intent(in)  :: cipher
    integer(itb_byte_kind), allocatable, intent(out) :: key(:)
    integer(itb_status_kind),            intent(out) :: status
    integer :: klen
    integer(itb_status_kind) :: rc

    call itb_wrapper_key_size(cipher, klen, rc)
    if (rc /= STATUS_OK) then
      status = rc
      return
    end if
    if (klen <= 0) then
      status = STATUS_INTERNAL
      return
    end if
    allocate (key(klen))
    call fill_csprng(key, klen, rc)
    if (rc /= STATUS_OK) then
      deallocate (key)
      status = rc
      return
    end if
    status = STATUS_OK
  end subroutine

  ! Deterministically derives the outer cipher key for `cipher` from a
  ! caller-supplied `master` secret (e.g. an ML-KEM shared secret). The
  ! result is a deterministic function of `(cipher, master)`, so both
  ! endpoints derive the same key from a shared master. `master` must
  ! be at least 32 bytes (the wrapper's uniform security floor); `key`
  ! is allocated to the cipher's key length (16 / 32 / 16 bytes for
  ! AES / ChaCha / SipHash).
  ! Returns STATUS_BAD_INPUT when `master` is shorter than 32 bytes.
  subroutine itb_wrapper_derive_key(cipher, master, key, status)
    integer,                                     intent(in)  :: cipher
    integer(itb_byte_kind), target, contiguous,  intent(in)  :: master(:)
    integer(itb_byte_kind), allocatable, target, intent(out) :: key(:)
    integer(itb_status_kind),                    intent(out) :: status
    character(:), allocatable :: cn
    character(kind=c_char), allocatable, target :: c_name(:)
    integer :: klen
    integer(itb_size_kind) :: out_len
    integer(c_int) :: rc
    type(c_ptr) :: master_ptr

    call itb_wrapper_key_size(cipher, klen, status)
    if (status /= STATUS_OK) return
    if (klen <= 0) then
      status = STATUS_INTERNAL
      return
    end if

    cn = itb_wrapper_cipher_name(cipher)
    call make_c_string(cn, c_name)

    allocate (key(klen))
    master_ptr = c_null_ptr
    if (size(master) > 0) master_ptr = c_loc(master)

    out_len = 0_itb_size_kind
    rc = itb_wrapper_derive_key_c(c_loc(c_name), master_ptr,                 &
                                    int(size(master), itb_size_kind),         &
                                    c_loc(key), int(klen, itb_size_kind),     &
                                    out_len)
    if (rc /= STATUS_OK) then
      deallocate (key)
      status = rc
      return
    end if
    status = STATUS_OK
  end subroutine

  ! ----------------------------------------------------------------
  ! Internal -- common preflight on key length
  ! ----------------------------------------------------------------

  ! Validates the caller-supplied key length against the cipher's
  ! requirement. Returns the looked-up nonce length on success so the
  ! caller does not have to repeat the FFI round-trip.
  subroutine validate_key_and_nonce(cipher, key_len, nonce_len, status)
    integer,                  intent(in)  :: cipher, key_len
    integer,                  intent(out) :: nonce_len
    integer(itb_status_kind), intent(out) :: status
    integer :: need_key
    integer(itb_status_kind) :: rc

    nonce_len = 0
    call itb_wrapper_key_size(cipher, need_key, rc)
    if (rc /= STATUS_OK) then
      status = rc
      return
    end if
    if (key_len /= need_key) then
      status = STATUS_BAD_INPUT
      return
    end if
    call itb_wrapper_nonce_size(cipher, nonce_len, rc)
    status = rc
  end subroutine

  ! ----------------------------------------------------------------
  ! Single Message wrap / unwrap
  ! ----------------------------------------------------------------

  ! Seals one ITB ciphertext blob under the named outer cipher.
  ! `wire` is allocated to `nonce_len + size(blob)` bytes; the
  ! returned content is `nonce || keystream-XOR(blob)`. Empty `blob`
  ! is allowed -- the result is just the nonce.
  subroutine itb_wrap(cipher, key, blob, wire, status)
    integer,                                       intent(in)  :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: key(:)
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: blob(:)
    integer(itb_byte_kind), allocatable, target,   intent(out) :: wire(:)
    integer(itb_status_kind),                      intent(out) :: status
    character(:), allocatable :: cn
    character(kind=c_char), allocatable, target :: c_name(:)
    integer :: nlen
    integer(itb_size_kind) :: out_len, cap
    integer(c_int) :: rc
    type(c_ptr) :: blob_ptr, key_ptr

    call validate_key_and_nonce(cipher, size(key), nlen, status)
    if (status /= STATUS_OK) return

    cn = itb_wrapper_cipher_name(cipher)
    call make_c_string(cn, c_name)

    cap = int(nlen, itb_size_kind) + int(size(blob), itb_size_kind)
    if (cap == 0_itb_size_kind) cap = 1_itb_size_kind
    allocate (wire(cap))

    blob_ptr = c_null_ptr
    if (size(blob) > 0) blob_ptr = c_loc(blob)
    key_ptr = c_null_ptr
    if (size(key) > 0) key_ptr = c_loc(key)

    out_len = 0_itb_size_kind
    rc = itb_wrap_c(c_loc(c_name), key_ptr, int(size(key), itb_size_kind),     &
                      blob_ptr, int(size(blob), itb_size_kind),                  &
                      c_loc(wire), cap, out_len)
    if (rc /= STATUS_OK) then
      deallocate (wire)
      status = rc
      return
    end if

    ! Truncate the over-allocated `wire` to the exact returned length
    ! via `move_alloc` -- mirrors the truncate pattern used by
    ! itb_encryptor's encrypt/decrypt helpers.
    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = wire(1:out_len)
      call move_alloc(trimmed, wire)
    end block
    status = STATUS_OK
  end subroutine

  ! Reverses `itb_wrap`. Reads the leading `nonce_len` bytes of `wire`
  ! as the per-stream nonce; XOR-decrypts the remainder under
  ! `(key, nonce)` into a fresh `blob(:)`. `wire_len < nonce_len`
  ! returns STATUS_BAD_INPUT.
  subroutine itb_unwrap(cipher, key, wire, blob, status)
    integer,                                       intent(in)  :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: key(:)
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: wire(:)
    integer(itb_byte_kind), allocatable, target,   intent(out) :: blob(:)
    integer(itb_status_kind),                      intent(out) :: status
    character(:), allocatable :: cn
    character(kind=c_char), allocatable, target :: c_name(:)
    integer :: nlen
    integer(itb_size_kind) :: cap, body, out_len
    integer(c_int) :: rc
    type(c_ptr) :: wire_ptr, key_ptr

    call validate_key_and_nonce(cipher, size(key), nlen, status)
    if (status /= STATUS_OK) return

    if (size(wire) < nlen) then
      status = STATUS_BAD_INPUT
      return
    end if

    cn = itb_wrapper_cipher_name(cipher)
    call make_c_string(cn, c_name)

    body = int(size(wire), itb_size_kind) - int(nlen, itb_size_kind)
    cap = body
    if (cap == 0_itb_size_kind) cap = 1_itb_size_kind
    allocate (blob(cap))

    wire_ptr = c_null_ptr
    if (size(wire) > 0) wire_ptr = c_loc(wire)
    key_ptr = c_null_ptr
    if (size(key) > 0) key_ptr = c_loc(key)

    out_len = 0_itb_size_kind
    rc = itb_unwrap_c(c_loc(c_name), key_ptr, int(size(key), itb_size_kind),   &
                        wire_ptr, int(size(wire), itb_size_kind),                &
                        c_loc(blob), cap, out_len)
    if (rc /= STATUS_OK) then
      deallocate (blob)
      status = rc
      return
    end if

    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = blob(1:out_len)
      call move_alloc(trimmed, blob)
    end block
    status = STATUS_OK
  end subroutine

  ! XORs `blob` in place under a fresh outer cipher keystream and
  ! writes the per-stream nonce into `nonce(1:nonce_len)`. `blob`
  ! is MUTATED. The caller emits `nonce` then `blob` to compose the
  ! wire; the return path is `itb_unwrap_in_place`.
  subroutine itb_wrap_in_place(cipher, key, blob, nonce, status)
    integer,                                       intent(in)    :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)    :: key(:)
    integer(itb_byte_kind), target,    contiguous, intent(inout) :: blob(:)
    integer(itb_byte_kind), allocatable, target,   intent(out)   :: nonce(:)
    integer(itb_status_kind),                      intent(out)   :: status
    character(:), allocatable :: cn
    character(kind=c_char), allocatable, target :: c_name(:)
    integer :: nlen
    integer(c_int) :: rc
    type(c_ptr) :: blob_ptr, key_ptr

    call validate_key_and_nonce(cipher, size(key), nlen, status)
    if (status /= STATUS_OK) return

    cn = itb_wrapper_cipher_name(cipher)
    call make_c_string(cn, c_name)

    allocate (nonce(nlen))
    blob_ptr = c_null_ptr
    if (size(blob) > 0) blob_ptr = c_loc(blob)
    key_ptr = c_null_ptr
    if (size(key) > 0) key_ptr = c_loc(key)

    rc = itb_wrap_in_place_c(c_loc(c_name), key_ptr,                            &
                               int(size(key), itb_size_kind),                    &
                               blob_ptr, int(size(blob), itb_size_kind),         &
                               c_loc(nonce), int(nlen, itb_size_kind))
    if (rc /= STATUS_OK) then
      deallocate (nonce)
      status = rc
      return
    end if
    status = STATUS_OK
  end subroutine

  ! Strips the leading nonce-length bytes from `wire` and XORs the
  ! remainder in place. `wire` is MUTATED. `body_first` returns the
  ! one-based index of the first decrypted-payload byte (i.e.
  ! `nonce_len + 1`); the caller slices `wire(body_first : size(wire))`
  ! to recover the plaintext blob. `size(wire) < nonce_len` returns
  ! STATUS_BAD_INPUT.
  subroutine itb_unwrap_in_place(cipher, key, wire, body_first, status)
    integer,                                       intent(in)    :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)    :: key(:)
    integer(itb_byte_kind), target,    contiguous, intent(inout) :: wire(:)
    integer,                                       intent(out)   :: body_first
    integer(itb_status_kind),                      intent(out)   :: status
    character(:), allocatable :: cn
    character(kind=c_char), allocatable, target :: c_name(:)
    integer :: nlen
    integer(c_int) :: rc
    type(c_ptr) :: wire_ptr, key_ptr

    body_first = 0
    call validate_key_and_nonce(cipher, size(key), nlen, status)
    if (status /= STATUS_OK) return

    if (size(wire) < nlen) then
      status = STATUS_BAD_INPUT
      return
    end if

    cn = itb_wrapper_cipher_name(cipher)
    call make_c_string(cn, c_name)

    wire_ptr = c_null_ptr
    if (size(wire) > 0) wire_ptr = c_loc(wire)
    key_ptr = c_null_ptr
    if (size(key) > 0) key_ptr = c_loc(key)

    rc = itb_unwrap_in_place_c(c_loc(c_name), key_ptr,                          &
                                 int(size(key), itb_size_kind),                  &
                                 wire_ptr, int(size(wire), itb_size_kind))
    if (rc /= STATUS_OK) then
      status = rc
      return
    end if
    body_first = nlen + 1
    status = STATUS_OK
  end subroutine

  ! ----------------------------------------------------------------
  ! Streaming wrap-encrypt
  ! ----------------------------------------------------------------

  ! Allocates a streaming wrap-encrypt handle, draws a fresh nonce
  ! from libitb's CSPRNG, and writes that nonce into the caller-side
  ! `nonce(:)` allocatable (sized to the cipher's exact nonce length).
  ! The caller must emit those nonce bytes once at stream start
  ! (typically as the wire prefix) and feed subsequent body bytes
  ! through `writer%update(...)`. Pair with exactly one
  ! `writer%destroy()` call.
  subroutine itb_wrap_stream_writer_new(cipher, key, writer, nonce, status)
    integer,                                       intent(in)  :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: key(:)
    type(itb_wrap_stream_writer_t),                intent(out) :: writer
    integer(itb_byte_kind), allocatable, target,   intent(out) :: nonce(:)
    integer(itb_status_kind),                      intent(out) :: status
    character(:), allocatable :: cn
    character(kind=c_char), allocatable, target :: c_name(:)
    integer :: nlen
    integer(c_int) :: rc
    integer(c_intptr_t) :: handle
    type(c_ptr) :: key_ptr

    writer%handle = itb_null_handle
    writer%closed = .true.

    call validate_key_and_nonce(cipher, size(key), nlen, status)
    if (status /= STATUS_OK) return

    cn = itb_wrapper_cipher_name(cipher)
    call make_c_string(cn, c_name)

    allocate (nonce(nlen))
    key_ptr = c_null_ptr
    if (size(key) > 0) key_ptr = c_loc(key)

    handle = 0_c_intptr_t
    rc = itb_wrap_stream_writer_init_c(c_loc(c_name), key_ptr,                  &
                                         int(size(key), itb_size_kind),          &
                                         c_loc(nonce), int(nlen, itb_size_kind),&
                                         handle)
    if (rc /= STATUS_OK) then
      deallocate (nonce)
      status = rc
      return
    end if
    writer%handle = handle
    writer%closed = .false.
    status = STATUS_OK
  end subroutine

  ! XORs `src(1:n)` into `dst(1:n)` under the writer's keystream,
  ! advancing the per-stream cipher counter. `src` and `dst` MAY
  ! alias (in-place mutation); `size(dst) >= size(src)` is required.
  subroutine wrap_stream_writer_update(self, src, dst, status)
    class(itb_wrap_stream_writer_t),               intent(inout) :: self
    integer(itb_byte_kind), target,    contiguous, intent(in)    :: src(:)
    integer(itb_byte_kind), target,    contiguous, intent(inout) :: dst(:)
    integer(itb_status_kind),                      intent(out)   :: status
    integer(c_int) :: rc
    type(c_ptr) :: src_ptr, dst_ptr

    if (self%closed .or. self%handle == itb_null_handle) then
      status = STATUS_BAD_HANDLE
      return
    end if
    if (size(src) == 0) then
      status = STATUS_OK
      return
    end if
    if (size(dst) < size(src)) then
      status = STATUS_BAD_INPUT
      return
    end if
    src_ptr = c_loc(src)
    dst_ptr = c_loc(dst)
    rc = itb_wrap_stream_writer_update_c(self%handle, src_ptr,                  &
                                           int(size(src), itb_size_kind),        &
                                           dst_ptr,                              &
                                           int(size(dst), itb_size_kind))
    status = rc
  end subroutine

  ! Releases the underlying libitb stream handle and marks the wrapper
  ! closed. Idempotent. Canonical lifecycle release path; final-hook
  ! timing is non-deterministic across Fortran compilers.
  subroutine wrap_stream_writer_destroy(self)
    class(itb_wrap_stream_writer_t), intent(inout) :: self
    integer(c_int) :: rc
    if (self%closed) then
      self%handle = itb_null_handle
      return
    end if
    if (self%handle /= itb_null_handle) then
      rc = itb_wrap_stream_writer_free_c(self%handle)
      ! Best-effort: ignore STATUS_BAD_HANDLE on a stale handle.
      if (rc /= STATUS_OK .and. rc /= STATUS_BAD_HANDLE) then
        ! Non-fatal: leave the wrapper marked closed regardless.
        continue
      end if
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  ! Safety-net hook -- non-deterministic across compilers. Errors
  ! are swallowed because the hook may fire at unpredictable program
  ! scopes (temporaries during reallocation, end-of-program-unit
  ! deferral, re-entry from another final).
  subroutine wrap_stream_writer_final(self)
    type(itb_wrap_stream_writer_t), intent(inout) :: self
    if (self%closed) return
    if (self%handle /= itb_null_handle) then
      block
        integer(c_int) :: rc
        rc = itb_wrap_stream_writer_free_c(self%handle)
      end block
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  ! ----------------------------------------------------------------
  ! Streaming unwrap-decrypt
  ! ----------------------------------------------------------------

  ! Allocates a streaming unwrap-decrypt handle keyed by the leading
  ! nonce-length bytes of the wire (passed as `wire_nonce(:)`). The
  ! returned reader XOR-decrypts subsequent body bytes back to
  ! plaintext under the keystream advancing from counter zero. Pair
  ! with exactly one `reader%destroy()` call.
  subroutine itb_unwrap_stream_reader_new(cipher, key, wire_nonce, reader, status)
    integer,                                       intent(in)  :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: key(:)
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: wire_nonce(:)
    type(itb_unwrap_stream_reader_t),              intent(out) :: reader
    integer(itb_status_kind),                      intent(out) :: status
    character(:), allocatable :: cn
    character(kind=c_char), allocatable, target :: c_name(:)
    integer :: nlen
    integer(c_int) :: rc
    integer(c_intptr_t) :: handle
    type(c_ptr) :: key_ptr, nonce_ptr

    reader%handle = itb_null_handle
    reader%closed = .true.

    call validate_key_and_nonce(cipher, size(key), nlen, status)
    if (status /= STATUS_OK) return

    if (size(wire_nonce) /= nlen) then
      status = STATUS_BAD_INPUT
      return
    end if

    cn = itb_wrapper_cipher_name(cipher)
    call make_c_string(cn, c_name)

    key_ptr = c_null_ptr
    if (size(key) > 0) key_ptr = c_loc(key)
    nonce_ptr = c_loc(wire_nonce)

    handle = 0_c_intptr_t
    rc = itb_unwrap_stream_reader_init_c(c_loc(c_name), key_ptr,                &
                                           int(size(key), itb_size_kind),        &
                                           nonce_ptr,                            &
                                           int(size(wire_nonce), itb_size_kind), &
                                           handle)
    if (rc /= STATUS_OK) then
      status = rc
      return
    end if
    reader%handle = handle
    reader%closed = .false.
    status = STATUS_OK
  end subroutine

  ! XORs `src(1:n)` into `dst(1:n)` under the reader's keystream,
  ! advancing the per-stream cipher counter. Mirror of
  ! `wrap_stream_writer_update` with identical aliasing semantics.
  subroutine unwrap_stream_reader_update(self, src, dst, status)
    class(itb_unwrap_stream_reader_t),             intent(inout) :: self
    integer(itb_byte_kind), target,    contiguous, intent(in)    :: src(:)
    integer(itb_byte_kind), target,    contiguous, intent(inout) :: dst(:)
    integer(itb_status_kind),                      intent(out)   :: status
    integer(c_int) :: rc
    type(c_ptr) :: src_ptr, dst_ptr

    if (self%closed .or. self%handle == itb_null_handle) then
      status = STATUS_BAD_HANDLE
      return
    end if
    if (size(src) == 0) then
      status = STATUS_OK
      return
    end if
    if (size(dst) < size(src)) then
      status = STATUS_BAD_INPUT
      return
    end if
    src_ptr = c_loc(src)
    dst_ptr = c_loc(dst)
    rc = itb_unwrap_stream_reader_update_c(self%handle, src_ptr,                &
                                             int(size(src), itb_size_kind),      &
                                             dst_ptr,                            &
                                             int(size(dst), itb_size_kind))
    status = rc
  end subroutine

  ! Releases the underlying libitb stream handle and marks the wrapper
  ! closed. Idempotent.
  subroutine unwrap_stream_reader_destroy(self)
    class(itb_unwrap_stream_reader_t), intent(inout) :: self
    integer(c_int) :: rc
    if (self%closed) then
      self%handle = itb_null_handle
      return
    end if
    if (self%handle /= itb_null_handle) then
      rc = itb_unwrap_stream_reader_free_c(self%handle)
      if (rc /= STATUS_OK .and. rc /= STATUS_BAD_HANDLE) then
        continue
      end if
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  subroutine unwrap_stream_reader_final(self)
    type(itb_unwrap_stream_reader_t), intent(inout) :: self
    if (self%closed) return
    if (self%handle /= itb_null_handle) then
      block
        integer(c_int) :: rc
        rc = itb_unwrap_stream_reader_free_c(self%handle)
      end block
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

end module itb_wrapper
