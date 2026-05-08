! itb_streams.f90 -- chunked encrypt / decrypt over caller-owned
! read / write callbacks.
!
! ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
! container size limit); streaming larger payloads slices the input
! into `chunk_size`-sized blocks at the binding layer, encrypts each
! through the regular `ITB_Encrypt` / `ITB_EncryptAuth` (or `_3` /
! `Auth3`) FFI path, and concatenates the results. The reverse
! operation walks a concatenated chunk stream by reading the chunk
! header, calling `ITB_ParseChunkLen` to learn the chunk's body
! length, reading that many bytes, and decrypting the single chunk.
!
! Free-function shape. The streams take Seeds (and an optional MAC
! for the `_auth` variants), NOT an `itb_encryptor_t` handle --
! matching the canonical cross-binding stream contract. Bindings
! that wrap an Easy Mode encryptor expose stream methods on the
! encryptor type separately; that path is not in scope here.
!
! Authenticated variants. `itb_stream_encrypt_auth` and
! `itb_stream_decrypt_auth` (Single + Triple counterparts) are pure
! binding-side additions. The chunk loop dispatches per chunk
! through `itb_encrypt_auth` / `itb_decrypt_auth` instead of plain
! `itb_encrypt` / `itb_decrypt`. The MAC parameter is mandatory --
! there is no nil-sentinel that degrades the call to a plain
! stream.
!
! Callback shape. The caller supplies a `(read_fn, read_ctx)` pair
! for the input source and a `(write_fn, write_ctx)` pair for the
! output sink. Both callbacks are `bind(C)` functions implementing
! the abstract interfaces `itb_stream_read_fn` /
! `itb_stream_write_fn` declared below. The opaque `user_ctx`
! `c_ptr` is forwarded verbatim on every callback invocation -- a
! Fortran caller typically wraps the I/O state in a `bind(C)`
! derived type and passes its `c_loc(state)` as the context. The
! callback recovers the state via `c_f_pointer(user_ctx, state)`.
!
! Callback contracts:
!
!   * `read_fn`: write up to `cap` bytes into `buf`, set `out_n` to
!     the number of bytes actually written, return 0 on success or
!     a non-zero status code on I/O error. Setting `out_n = 0` and
!     returning 0 signals end-of-stream.
!   * `write_fn`: consume the full `n` bytes from `buf` before
!     returning. Return 0 on success or a non-zero status code on
!     I/O error.
!
! Either callback returning a non-zero status code aborts the
! stream operation; the binding surfaces `STATUS_INTERNAL` through
! the wrapper's `status` argument and the caller's own `user_ctx`
! retains the precise error context.
!
! Memory peak. Bounded by `chunk_size` plus a transient
! ciphertext / plaintext buffer per chunk on the encrypt side, plus
! one accumulator (grows up to one chunk-on-the-wire) on the
! decrypt side. The caller picks `chunk_size` explicitly; values
! larger than ~64 MB will be rejected by libitb's per-chunk
! container size limit at the encrypt-call boundary.
!
! `chunk_size > 0` preflight. The wrapper validates `chunk_size > 0`
! before invoking libitb and returns `STATUS_BAD_INPUT` on a zero
! value. libitb itself has no stream concept; the binding owns
! this preflight.
!
! Process-wide setters and the chunk header. The decrypt loop
! snapshots the chunk-header size at call entry via
! `itb_header_size()`; mutating
! `itb_set_nonce_bits` mid-stream invalidates this snapshot and
! produces undefined behaviour. Treat the process-wide
! configuration knobs as set-once-at-startup before any stream
! call begins.
!
! Status reporting. Stream subroutines receive a final status code
! through an `intent(out) :: status` argument rather than raising
! via `raise_itb_error`. The user-callback context makes the
! status-by-arg ergonomic the saner choice -- the caller's own
! state pointer is the natural home for any I/O-specific error
! detail and the wrapper hands back a single canonical status
! code so the caller decides whether to halt or recover.
! `STATUS_OK` indicates a clean stream; any other code carries the
! precise libitb status (or `STATUS_INTERNAL` when the failure was
! a callback I/O error).
!
! Threading. A single stream call is not thread-safe internally --
! its state lives on the call stack and is single-threaded.
! Distinct stream calls, each on its own thread with its own seed
! handles and (for authenticated variants) MAC handle, run
! independently against the libitb worker pool.

module itb_streams
  use itb_kinds
  use itb_sys
  use itb_seed,      only: itb_seed_t
  use itb_mac,       only: itb_mac_t
  use itb_encryptor, only: itb_encryptor_t
  use itb_cipher,    only: itb_encrypt, itb_decrypt,                    &
                              itb_encrypt_triple, itb_decrypt_triple
  use itb_errors,    only: STATUS_OK, STATUS_BAD_INPUT, STATUS_INTERNAL, &
                              STATUS_BUFFER_TOO_SMALL,                       &
                              STATUS_STREAM_TRUNCATED,                        &
                              STATUS_STREAM_AFTER_FINAL,                       &
                              STATUS_EASY_CLOSED
  implicit none
  private

  public :: itb_stream_read_fn
  public :: itb_stream_write_fn

  public :: itb_stream_encrypt
  public :: itb_stream_decrypt
  public :: itb_stream_encrypt_triple
  public :: itb_stream_decrypt_triple

  public :: itb_stream_encrypt_auth
  public :: itb_stream_decrypt_auth
  public :: itb_stream_encrypt_auth_triple
  public :: itb_stream_decrypt_auth_triple

  public :: itb_encryptor_stream_encrypt_auth
  public :: itb_encryptor_stream_decrypt_auth

  ! Stream-id wire-prefix length (32 bytes CSPRNG anchor).
  integer(itb_size_kind), parameter, private :: STREAM_ID_LEN = 32_itb_size_kind

  ! Abstract interfaces for the caller-supplied stream callbacks.
  ! Both are `bind(C)` so the same callback shape is reachable from
  ! Fortran-only callers (where the implementation is a Fortran
  ! function flagged `bind(C)`) and from cross-language consumers
  ! that pass a C function pointer through the FFI.
  abstract interface
    function itb_stream_read_fn(user_ctx, buf, cap, out_n) bind(C) result(rc)
      import :: c_ptr, c_size_t, c_int
      type(c_ptr),       value :: user_ctx
      type(c_ptr),       value :: buf
      integer(c_size_t), value :: cap
      integer(c_size_t)        :: out_n
      integer(c_int)           :: rc
    end function

    function itb_stream_write_fn(user_ctx, buf, n) bind(C) result(rc)
      import :: c_ptr, c_size_t, c_int
      type(c_ptr),       value :: user_ctx
      type(c_ptr),       value :: buf
      integer(c_size_t), value :: n
      integer(c_int)           :: rc
    end function
  end interface

contains

  ! ----------------------------------------------------------------
  ! Internal helpers (shared across all eight stream entry points)
  ! ----------------------------------------------------------------

  ! Concatenates two byte slices into a freshly-allocated array.
  ! Used by the decrypt accumulator to append a freshly-read chunk
  ! to the buffered tail.
  pure subroutine concat_bytes(prefix, suffix, n, result)
    integer(itb_byte_kind), intent(in)  :: prefix(:)
    integer(itb_byte_kind), intent(in)  :: suffix(:)
    integer(itb_size_kind), intent(in)  :: n          ! visible bytes from suffix
    integer(itb_byte_kind), allocatable, intent(out) :: result(:)
    integer :: i, p, s

    p = size(prefix)
    s = int(n)
    allocate (result(p + s))
    do i = 1, p
      result(i) = prefix(i)
    end do
    do i = 1, s
      result(p + i) = suffix(i)
    end do
  end subroutine

  ! Drops the consumed prefix of length `n` from the accumulator,
  ! returning a freshly-allocated tail. Caller assigns over the
  ! existing accumulator; the previous storage is released by the
  ! Fortran allocatable assignment semantics.
  pure subroutine slice_tail(buf, n, result)
    integer(itb_byte_kind), intent(in)  :: buf(:)
    integer(itb_size_kind), intent(in)  :: n
    integer(itb_byte_kind), allocatable, intent(out) :: result(:)
    integer :: i, ns, total

    total = size(buf)
    ns = int(n)
    if (ns >= total) then
      allocate (result(0))
      return
    end if
    allocate (result(total - ns))
    do i = 1, total - ns
      result(i) = buf(ns + i)
    end do
  end subroutine

  ! Snapshots the chunk-header size at stream-call entry. Returns
  ! zero on a non-positive header size from libitb (which would
  ! itself indicate process-wide misconfiguration). The decrypt
  ! loop uses this to find the chunk-length prefix in the
  ! accumulator.
  function snapshot_header_size() result(hsz)
    integer(itb_size_kind) :: hsz
    integer(c_int) :: raw
    raw = itb_header_size_c()
    if (raw <= 0) then
      hsz = 0_itb_size_kind
    else
      hsz = int(raw, itb_size_kind)
    end if
  end function

  ! ----------------------------------------------------------------
  ! Encrypt direction -- Single Ouroboros (plain)
  ! ----------------------------------------------------------------

  ! Reads the input stream in `chunk_size`-byte units, encrypts each
  ! chunk via `itb_encrypt` (Single Ouroboros, 3-seed), and writes
  ! the resulting ciphertext to the output sink. EOF is detected
  ! when `read_fn` returns zero bytes; any partial trailing chunk
  ! is encrypted as its own (smaller) wire chunk before the loop
  ! terminates.
  subroutine itb_stream_encrypt(noise, data, start, &
                                 read_fn, read_ctx, write_fn, write_ctx, &
                                 chunk_size, status)
    type(itb_seed_t),                  intent(in)  :: noise, data, start
    procedure(itb_stream_read_fn),  pointer, intent(in)  :: read_fn
    type(c_ptr),                       value, intent(in) :: read_ctx
    procedure(itb_stream_write_fn), pointer, intent(in)  :: write_fn
    type(c_ptr),                       value, intent(in) :: write_ctx
    integer(itb_size_kind),            intent(in)  :: chunk_size
    integer(itb_status_kind),          intent(out) :: status
    integer(itb_byte_kind), allocatable, target :: buf(:)
    integer(itb_byte_kind), allocatable, target :: ct(:)
    integer(itb_size_kind) :: buffered, got, take
    integer(c_int) :: rrc, wrc

    if (chunk_size <= 0) then
      status = STATUS_BAD_INPUT
      return
    end if

    allocate (buf(chunk_size))
    buffered = 0_itb_size_kind

    do
      ! Fill `buf` up to chunk_size by repeatedly invoking read_fn.
      ! On EOF (got == 0), flush any partial chunk and return.
      if (buffered < chunk_size) then
        got = 0_itb_size_kind
        rrc = read_fn(read_ctx, c_loc(buf(buffered + 1)), &
                       chunk_size - buffered, got)
        if (rrc /= 0) then
          buf = 0_itb_byte_kind
          status = STATUS_INTERNAL
          return
        end if
        if (got == 0) then
          ! EOF -- emit any buffered tail then stop.
          if (buffered > 0) then
            ct = itb_encrypt(noise, data, start, buf(1:int(buffered)))
            wrc = write_fn(write_ctx, c_loc(ct), int(size(ct), c_size_t))
            if (wrc /= 0) then
              buf = 0_itb_byte_kind
              status = STATUS_INTERNAL
              return
            end if
          end if
          ! Zero the plaintext working buffer before scope exit so
          ! the auto-deallocation does not leave it on the heap.
          buf = 0_itb_byte_kind
          status = STATUS_OK
          return
        end if
        buffered = buffered + got
        cycle
      end if

      ! `buf` is full -- emit one chunk and reset.
      take = chunk_size
      ct = itb_encrypt(noise, data, start, buf(1:int(take)))
      wrc = write_fn(write_ctx, c_loc(ct), int(size(ct), c_size_t))
      if (wrc /= 0) then
        buf = 0_itb_byte_kind
        status = STATUS_INTERNAL
        return
      end if
      ! Zero the consumed plaintext between chunks.
      buf = 0_itb_byte_kind
      buffered = 0_itb_size_kind
    end do
  end subroutine

  ! ----------------------------------------------------------------
  ! Encrypt direction -- Triple Ouroboros (plain)
  ! ----------------------------------------------------------------

  ! Triple-Ouroboros plain stream encrypt. Routes per-chunk through
  ! `itb_encrypt_triple` with the seven-seed argument set; otherwise
  ! identical to `itb_stream_encrypt`.
  subroutine itb_stream_encrypt_triple(noise, data1, data2, data3,    &
                                        start1, start2, start3,        &
                                        read_fn, read_ctx,              &
                                        write_fn, write_ctx,            &
                                        chunk_size, status)
    type(itb_seed_t),                  intent(in)  :: noise
    type(itb_seed_t),                  intent(in)  :: data1, data2, data3
    type(itb_seed_t),                  intent(in)  :: start1, start2, start3
    procedure(itb_stream_read_fn),  pointer, intent(in)  :: read_fn
    type(c_ptr),                       value, intent(in) :: read_ctx
    procedure(itb_stream_write_fn), pointer, intent(in)  :: write_fn
    type(c_ptr),                       value, intent(in) :: write_ctx
    integer(itb_size_kind),            intent(in)  :: chunk_size
    integer(itb_status_kind),          intent(out) :: status
    integer(itb_byte_kind), allocatable, target :: buf(:)
    integer(itb_byte_kind), allocatable, target :: ct(:)
    integer(itb_size_kind) :: buffered, got, take
    integer(c_int) :: rrc, wrc

    if (chunk_size <= 0) then
      status = STATUS_BAD_INPUT
      return
    end if

    allocate (buf(chunk_size))
    buffered = 0_itb_size_kind

    do
      if (buffered < chunk_size) then
        got = 0_itb_size_kind
        rrc = read_fn(read_ctx, c_loc(buf(buffered + 1)), &
                       chunk_size - buffered, got)
        if (rrc /= 0) then
          buf = 0_itb_byte_kind
          status = STATUS_INTERNAL
          return
        end if
        if (got == 0) then
          if (buffered > 0) then
            ct = itb_encrypt_triple(noise, data1, data2, data3,    &
                                      start1, start2, start3,        &
                                      buf(1:int(buffered)))
            wrc = write_fn(write_ctx, c_loc(ct), int(size(ct), c_size_t))
            if (wrc /= 0) then
              buf = 0_itb_byte_kind
              status = STATUS_INTERNAL
              return
            end if
          end if
          buf = 0_itb_byte_kind
          status = STATUS_OK
          return
        end if
        buffered = buffered + got
        cycle
      end if

      take = chunk_size
      ct = itb_encrypt_triple(noise, data1, data2, data3,    &
                                start1, start2, start3,        &
                                buf(1:int(take)))
      wrc = write_fn(write_ctx, c_loc(ct), int(size(ct), c_size_t))
      if (wrc /= 0) then
        buf = 0_itb_byte_kind
        status = STATUS_INTERNAL
        return
      end if
      buf = 0_itb_byte_kind
      buffered = 0_itb_size_kind
    end do
  end subroutine

  ! ----------------------------------------------------------------
  ! Streaming AEAD shared helpers
  ! ----------------------------------------------------------------

  ! Generates a CSPRNG-fresh 32-byte Streaming AEAD anchor by
  ! piggybacking on libitb's own CSPRNG: ITB_NewSeedFromComponents
  ! with hash_key == NULL triggers a CSPRNG draw on the Go side, and
  ! ITB_GetSeedHashKey reads back the 32-byte fixed key under the
  ! blake3 primitive. The seed handle is freed before the function
  ! returns.
  subroutine auth_generate_stream_id(out_sid, status)
    integer(itb_byte_kind), target, intent(out) :: out_sid(:)
    integer(itb_status_kind),       intent(out) :: status
    character(kind=c_char), target              :: c_name(7)
    integer(itb_u64_kind), target               :: components(8)
    integer(c_intptr_t)                         :: handle
    integer(itb_size_kind)                      :: out_len
    integer                                     :: i
    integer(c_int)                              :: rc, free_rc

    if (size(out_sid, kind=itb_size_kind) /= STREAM_ID_LEN) then
      status = STATUS_INTERNAL
      return
    end if

    c_name = (/ 'b', 'l', 'a', 'k', 'e', '3', c_null_char /)
    do i = 1, 8
      components(i) = int(i, itb_u64_kind)
    end do

    handle = 0_c_intptr_t
    rc = itb_new_seed_from_components_c(c_loc(c_name),                 &
                                          c_loc(components),            &
                                          8_c_int,                      &
                                          c_null_ptr,                    &
                                          0_c_int,                       &
                                          handle)
    if (rc /= STATUS_OK) then
      status = rc
      return
    end if

    out_len = 0_itb_size_kind
    rc = itb_get_seed_hash_key_c(handle, c_loc(out_sid),               &
                                   STREAM_ID_LEN, out_len)
    free_rc = itb_free_seed_c(handle)
    if (rc /= STATUS_OK) then
      status = rc
      return
    end if
    if (free_rc /= STATUS_OK) then
      status = free_rc
      return
    end if
    if (out_len /= STREAM_ID_LEN) then
      status = STATUS_INTERNAL
      return
    end if

    status = STATUS_OK
  end subroutine

  ! Discovers the seed's native hash width (128 / 256 / 512). Used by
  ! the auth-stream dispatcher to route per-chunk calls through the
  ! matching ITB_*StreamAuthenticated* ABI export.
  subroutine auth_seed_width(seed, out_width, status)
    type(itb_seed_t),         intent(in)  :: seed
    integer(c_int),           intent(out) :: out_width
    integer(itb_status_kind), intent(out) :: status
    integer(c_int) :: st

    st = STATUS_OK
    out_width = itb_seed_width_c(seed%raw_handle(), st)
    status = st
  end subroutine

  ! Reads a big-endian uint16 from `buf(off+1:off+2)`, returned as a
  ! c_size_t for arithmetic with the cumulative pixel offset.
  pure function read_be16_at(buf, off) result(v)
    integer(itb_byte_kind), intent(in) :: buf(:)
    integer(itb_size_kind), intent(in) :: off
    integer(itb_size_kind)             :: v
    integer(itb_size_kind) :: hi, lo
    hi = iand(int(buf(off + 1), itb_size_kind), 255_itb_size_kind)
    lo = iand(int(buf(off + 2), itb_size_kind), 255_itb_size_kind)
    v = ior(ishft(hi, 8), lo)
  end function

  ! Extracts the per-chunk pixel count W * H from a chunk-on-the-wire
  ! whose header begins at `buf` offset 0. The header layout is
  ! (nonce ... || W (BE16) || H (BE16)) with W and H sitting at
  ! offsets header_size-4 and header_size-2.
  pure function pixels_from_header(buf, header_size) result(pixels)
    integer(itb_byte_kind), intent(in) :: buf(:)
    integer(itb_size_kind), intent(in) :: header_size
    integer(c_int64_t)                 :: pixels
    integer(itb_size_kind) :: w, h
    if (size(buf, kind=itb_size_kind) < header_size) then
      pixels = 0_c_int64_t
      return
    end if
    w = read_be16_at(buf, header_size - 4_itb_size_kind)
    h = read_be16_at(buf, header_size - 2_itb_size_kind)
    pixels = int(w, c_int64_t) * int(h, c_int64_t)
  end function

  ! Per-chunk encrypt dispatcher routing via hash width to the
  ! matching ITB_EncryptStreamAuthenticated{128,256,512} ABI export.
  ! Allocates and returns the produced ciphertext via `ct_out`.
  !
  ! Capacity is pre-allocated from the same formula
  ! `max(131072, plen + plen / 4 + 131072)` used by the Easy Mode
  ! single-shot encrypt at `itb_enc_encrypt`. The 1.25x multiplier
  ! plus 128 KiB pad covers every cell in the mode / nonce-bits /
  ! barrier-fill matrix; the rare `STATUS_BUFFER_TOO_SMALL` from the
  ! first call surfaces the libitb-reported required size in `need`,
  ! and a single resize-and-retry recovers without invoking the
  ! explicit two-call probe shape.
  subroutine auth_emit_chunk_single(width, noise, data, start, mac,    &
                                       plaintext, plen,                  &
                                       sid, cum, final_flag,             &
                                       ct_out, status)
    integer(c_int),                 intent(in)  :: width
    type(itb_seed_t),               intent(in)  :: noise, data, start
    type(itb_mac_t),                intent(in)  :: mac
    integer(itb_byte_kind), target, intent(in)  :: plaintext(:)
    integer(itb_size_kind),         intent(in)  :: plen
    integer(itb_byte_kind), target, intent(in)  :: sid(:)
    integer(c_int64_t),             intent(in)  :: cum
    integer(c_int),                 intent(in)  :: final_flag
    integer(itb_byte_kind), allocatable, target, intent(out) :: ct_out(:)
    integer(itb_status_kind),       intent(out) :: status
    type(c_ptr)              :: pt_ptr
    integer(itb_size_kind)   :: cap, need, written
    integer(c_int)           :: rc

    if (plen == 0_itb_size_kind) then
      pt_ptr = c_null_ptr
    else
      pt_ptr = c_loc(plaintext)
    end if

    cap = max(131072_itb_size_kind, &
               plen + plen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (ct_out(cap))
    need = 0_itb_size_kind
    written = 0_itb_size_kind
    select case (width)
    case (128)
      rc = itb_encrypt_stream_authenticated128_c(                       &
              noise%raw_handle(), data%raw_handle(), start%raw_handle(), mac%raw_handle(),      &
              pt_ptr, plen,                                              &
              c_loc(sid), cum, final_flag,                                &
              c_loc(ct_out), cap, written)
    case (256)
      rc = itb_encrypt_stream_authenticated256_c(                       &
              noise%raw_handle(), data%raw_handle(), start%raw_handle(), mac%raw_handle(),      &
              pt_ptr, plen,                                              &
              c_loc(sid), cum, final_flag,                                &
              c_loc(ct_out), cap, written)
    case (512)
      rc = itb_encrypt_stream_authenticated512_c(                       &
              noise%raw_handle(), data%raw_handle(), start%raw_handle(), mac%raw_handle(),      &
              pt_ptr, plen,                                              &
              c_loc(sid), cum, final_flag,                                &
              c_loc(ct_out), cap, written)
    case default
      deallocate (ct_out)
      status = STATUS_INTERNAL
      return
    end select
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      ! Pre-allocation was too tight (small payloads through Triple /
      ! authenticated variants can exceed the 1.25x bulk-rate bound).
      ! `written` carries the libitb-reported required size; resize
      ! exactly and retry once.
      need = written
      deallocate (ct_out)
      allocate (ct_out(need))
      written = 0_itb_size_kind
      select case (width)
      case (128)
        rc = itb_encrypt_stream_authenticated128_c(                     &
                noise%raw_handle(), data%raw_handle(), start%raw_handle(), mac%raw_handle(),    &
                pt_ptr, plen,                                            &
                c_loc(sid), cum, final_flag,                              &
                c_loc(ct_out), need, written)
      case (256)
        rc = itb_encrypt_stream_authenticated256_c(                     &
                noise%raw_handle(), data%raw_handle(), start%raw_handle(), mac%raw_handle(),    &
                pt_ptr, plen,                                            &
                c_loc(sid), cum, final_flag,                              &
                c_loc(ct_out), need, written)
      case (512)
        rc = itb_encrypt_stream_authenticated512_c(                     &
                noise%raw_handle(), data%raw_handle(), start%raw_handle(), mac%raw_handle(),    &
                pt_ptr, plen,                                            &
                c_loc(sid), cum, final_flag,                              &
                c_loc(ct_out), need, written)
      end select
    end if
    if (rc /= STATUS_OK) then
      deallocate (ct_out)
      status = rc
      return
    end if
    if (written == 0_itb_size_kind) then
      deallocate (ct_out)
      allocate (ct_out(0))
      status = STATUS_OK
      return
    end if
    ! Trim the trailing slack -- the pre-allocation is intentionally
    ! larger than the actual output for almost every input size.
    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(written))
      trimmed = ct_out(1:int(written))
      call move_alloc(trimmed, ct_out)
    end block
    status = STATUS_OK
  end subroutine

  ! Triple-Ouroboros counterpart of auth_emit_chunk_single. Same
  ! capacity-formula + retry-once shape; the wider primitive matrix
  ! produces a strictly larger expansion ratio than Single, so the
  ! retry path activates more often at the smallest payloads, but
  ! the bulk regime still pre-allocates correctly.
  subroutine auth_emit_chunk_triple(width, noise,                       &
                                       data1, data2, data3,              &
                                       start1, start2, start3, mac,      &
                                       plaintext, plen,                   &
                                       sid, cum, final_flag,               &
                                       ct_out, status)
    integer(c_int),                 intent(in)  :: width
    type(itb_seed_t),               intent(in)  :: noise
    type(itb_seed_t),               intent(in)  :: data1, data2, data3
    type(itb_seed_t),               intent(in)  :: start1, start2, start3
    type(itb_mac_t),                intent(in)  :: mac
    integer(itb_byte_kind), target, intent(in)  :: plaintext(:)
    integer(itb_size_kind),         intent(in)  :: plen
    integer(itb_byte_kind), target, intent(in)  :: sid(:)
    integer(c_int64_t),             intent(in)  :: cum
    integer(c_int),                 intent(in)  :: final_flag
    integer(itb_byte_kind), allocatable, target, intent(out) :: ct_out(:)
    integer(itb_status_kind),       intent(out) :: status
    type(c_ptr)              :: pt_ptr
    integer(itb_size_kind)   :: cap, need, written
    integer(c_int)           :: rc

    if (plen == 0_itb_size_kind) then
      pt_ptr = c_null_ptr
    else
      pt_ptr = c_loc(plaintext)
    end if

    cap = max(131072_itb_size_kind, &
               plen + plen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (ct_out(cap))
    need = 0_itb_size_kind
    written = 0_itb_size_kind
    select case (width)
    case (128)
      rc = itb_encrypt_stream_authenticated3x128_c(                     &
              noise%raw_handle(), data1%raw_handle(), data2%raw_handle(), data3%raw_handle(),   &
              start1%raw_handle(), start2%raw_handle(), start3%raw_handle(), mac%raw_handle(),  &
              pt_ptr, plen, c_loc(sid), cum, final_flag,                  &
              c_loc(ct_out), cap, written)
    case (256)
      rc = itb_encrypt_stream_authenticated3x256_c(                     &
              noise%raw_handle(), data1%raw_handle(), data2%raw_handle(), data3%raw_handle(),   &
              start1%raw_handle(), start2%raw_handle(), start3%raw_handle(), mac%raw_handle(),  &
              pt_ptr, plen, c_loc(sid), cum, final_flag,                  &
              c_loc(ct_out), cap, written)
    case (512)
      rc = itb_encrypt_stream_authenticated3x512_c(                     &
              noise%raw_handle(), data1%raw_handle(), data2%raw_handle(), data3%raw_handle(),   &
              start1%raw_handle(), start2%raw_handle(), start3%raw_handle(), mac%raw_handle(),  &
              pt_ptr, plen, c_loc(sid), cum, final_flag,                  &
              c_loc(ct_out), cap, written)
    case default
      deallocate (ct_out)
      status = STATUS_INTERNAL
      return
    end select
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      need = written
      deallocate (ct_out)
      allocate (ct_out(need))
      written = 0_itb_size_kind
      select case (width)
      case (128)
        rc = itb_encrypt_stream_authenticated3x128_c(                   &
                noise%raw_handle(), data1%raw_handle(), data2%raw_handle(), data3%raw_handle(), &
                start1%raw_handle(), start2%raw_handle(), start3%raw_handle(), mac%raw_handle(),&
                pt_ptr, plen, c_loc(sid), cum, final_flag,                &
                c_loc(ct_out), need, written)
      case (256)
        rc = itb_encrypt_stream_authenticated3x256_c(                   &
                noise%raw_handle(), data1%raw_handle(), data2%raw_handle(), data3%raw_handle(), &
                start1%raw_handle(), start2%raw_handle(), start3%raw_handle(), mac%raw_handle(),&
                pt_ptr, plen, c_loc(sid), cum, final_flag,                &
                c_loc(ct_out), need, written)
      case (512)
        rc = itb_encrypt_stream_authenticated3x512_c(                   &
                noise%raw_handle(), data1%raw_handle(), data2%raw_handle(), data3%raw_handle(), &
                start1%raw_handle(), start2%raw_handle(), start3%raw_handle(), mac%raw_handle(),&
                pt_ptr, plen, c_loc(sid), cum, final_flag,                &
                c_loc(ct_out), need, written)
      end select
    end if
    if (rc /= STATUS_OK) then
      deallocate (ct_out)
      status = rc
      return
    end if
    if (written == 0_itb_size_kind) then
      deallocate (ct_out)
      allocate (ct_out(0))
      status = STATUS_OK
      return
    end if
    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(written))
      trimmed = ct_out(1:int(written))
      call move_alloc(trimmed, ct_out)
    end block
    status = STATUS_OK
  end subroutine

  ! Per-chunk decrypt dispatcher routing via hash width to the
  ! matching ITB_DecryptStreamAuthenticated{128,256,512} ABI export.
  ! Same capacity-formula + retry-once shape as the encrypt direction;
  ! plaintext output is bounded by `ctlen`, so the formula is
  ! conservative on the upper end.
  subroutine auth_consume_chunk_single(width, noise, data, start, mac,  &
                                          ciphertext, ctlen,              &
                                          sid, cum,                       &
                                          pt_out, final_flag, status)
    integer(c_int),                 intent(in)  :: width
    type(itb_seed_t),               intent(in)  :: noise, data, start
    type(itb_mac_t),                intent(in)  :: mac
    integer(itb_byte_kind), target, intent(in)  :: ciphertext(:)
    integer(itb_size_kind),         intent(in)  :: ctlen
    integer(itb_byte_kind), target, intent(in)  :: sid(:)
    integer(c_int64_t),             intent(in)  :: cum
    integer(itb_byte_kind), allocatable, target, intent(out) :: pt_out(:)
    integer(c_int),                 intent(out) :: final_flag
    integer(itb_status_kind),       intent(out) :: status
    type(c_ptr)              :: ct_ptr
    integer(itb_size_kind)   :: cap, need, written
    integer(c_int)           :: rc, ff

    if (ctlen == 0_itb_size_kind) then
      ct_ptr = c_null_ptr
    else
      ct_ptr = c_loc(ciphertext)
    end if

    cap = max(131072_itb_size_kind, &
               ctlen + ctlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (pt_out(cap))
    need = 0_itb_size_kind
    written = 0_itb_size_kind
    ff = 0_c_int
    select case (width)
    case (128)
      rc = itb_decrypt_stream_authenticated128_c(                       &
              noise%raw_handle(), data%raw_handle(), start%raw_handle(), mac%raw_handle(),      &
              ct_ptr, ctlen, c_loc(sid), cum,                             &
              c_loc(pt_out), cap, written, ff)
    case (256)
      rc = itb_decrypt_stream_authenticated256_c(                       &
              noise%raw_handle(), data%raw_handle(), start%raw_handle(), mac%raw_handle(),      &
              ct_ptr, ctlen, c_loc(sid), cum,                             &
              c_loc(pt_out), cap, written, ff)
    case (512)
      rc = itb_decrypt_stream_authenticated512_c(                       &
              noise%raw_handle(), data%raw_handle(), start%raw_handle(), mac%raw_handle(),      &
              ct_ptr, ctlen, c_loc(sid), cum,                             &
              c_loc(pt_out), cap, written, ff)
    case default
      deallocate (pt_out)
      status = STATUS_INTERNAL
      return
    end select
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      need = written
      deallocate (pt_out)
      allocate (pt_out(need))
      written = 0_itb_size_kind
      select case (width)
      case (128)
        rc = itb_decrypt_stream_authenticated128_c(                     &
                noise%raw_handle(), data%raw_handle(), start%raw_handle(), mac%raw_handle(),    &
                ct_ptr, ctlen, c_loc(sid), cum,                           &
                c_loc(pt_out), need, written, ff)
      case (256)
        rc = itb_decrypt_stream_authenticated256_c(                     &
                noise%raw_handle(), data%raw_handle(), start%raw_handle(), mac%raw_handle(),    &
                ct_ptr, ctlen, c_loc(sid), cum,                           &
                c_loc(pt_out), need, written, ff)
      case (512)
        rc = itb_decrypt_stream_authenticated512_c(                     &
                noise%raw_handle(), data%raw_handle(), start%raw_handle(), mac%raw_handle(),    &
                ct_ptr, ctlen, c_loc(sid), cum,                           &
                c_loc(pt_out), need, written, ff)
      end select
    end if
    if (rc /= STATUS_OK) then
      deallocate (pt_out)
      status = rc
      return
    end if
    if (written == 0_itb_size_kind) then
      deallocate (pt_out)
      allocate (pt_out(0))
      final_flag = ff
      status = STATUS_OK
      return
    end if
    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(written))
      trimmed = pt_out(1:int(written))
      call move_alloc(trimmed, pt_out)
    end block
    final_flag = ff
    status = STATUS_OK
  end subroutine

  ! Triple-Ouroboros counterpart of auth_consume_chunk_single. Same
  ! capacity-formula + retry-once shape.
  subroutine auth_consume_chunk_triple(width, noise,                    &
                                          data1, data2, data3,           &
                                          start1, start2, start3, mac,    &
                                          ciphertext, ctlen,               &
                                          sid, cum,                         &
                                          pt_out, final_flag, status)
    integer(c_int),                 intent(in)  :: width
    type(itb_seed_t),               intent(in)  :: noise
    type(itb_seed_t),               intent(in)  :: data1, data2, data3
    type(itb_seed_t),               intent(in)  :: start1, start2, start3
    type(itb_mac_t),                intent(in)  :: mac
    integer(itb_byte_kind), target, intent(in)  :: ciphertext(:)
    integer(itb_size_kind),         intent(in)  :: ctlen
    integer(itb_byte_kind), target, intent(in)  :: sid(:)
    integer(c_int64_t),             intent(in)  :: cum
    integer(itb_byte_kind), allocatable, target, intent(out) :: pt_out(:)
    integer(c_int),                 intent(out) :: final_flag
    integer(itb_status_kind),       intent(out) :: status
    type(c_ptr)              :: ct_ptr
    integer(itb_size_kind)   :: cap, need, written
    integer(c_int)           :: rc, ff

    if (ctlen == 0_itb_size_kind) then
      ct_ptr = c_null_ptr
    else
      ct_ptr = c_loc(ciphertext)
    end if

    cap = max(131072_itb_size_kind, &
               ctlen + ctlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (pt_out(cap))
    need = 0_itb_size_kind
    written = 0_itb_size_kind
    ff = 0_c_int
    select case (width)
    case (128)
      rc = itb_decrypt_stream_authenticated3x128_c(                     &
              noise%raw_handle(), data1%raw_handle(), data2%raw_handle(), data3%raw_handle(),   &
              start1%raw_handle(), start2%raw_handle(), start3%raw_handle(), mac%raw_handle(),  &
              ct_ptr, ctlen, c_loc(sid), cum,                             &
              c_loc(pt_out), cap, written, ff)
    case (256)
      rc = itb_decrypt_stream_authenticated3x256_c(                     &
              noise%raw_handle(), data1%raw_handle(), data2%raw_handle(), data3%raw_handle(),   &
              start1%raw_handle(), start2%raw_handle(), start3%raw_handle(), mac%raw_handle(),  &
              ct_ptr, ctlen, c_loc(sid), cum,                             &
              c_loc(pt_out), cap, written, ff)
    case (512)
      rc = itb_decrypt_stream_authenticated3x512_c(                     &
              noise%raw_handle(), data1%raw_handle(), data2%raw_handle(), data3%raw_handle(),   &
              start1%raw_handle(), start2%raw_handle(), start3%raw_handle(), mac%raw_handle(),  &
              ct_ptr, ctlen, c_loc(sid), cum,                             &
              c_loc(pt_out), cap, written, ff)
    case default
      deallocate (pt_out)
      status = STATUS_INTERNAL
      return
    end select
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      need = written
      deallocate (pt_out)
      allocate (pt_out(need))
      written = 0_itb_size_kind
      select case (width)
      case (128)
        rc = itb_decrypt_stream_authenticated3x128_c(                   &
                noise%raw_handle(), data1%raw_handle(), data2%raw_handle(), data3%raw_handle(), &
                start1%raw_handle(), start2%raw_handle(), start3%raw_handle(), mac%raw_handle(),&
                ct_ptr, ctlen, c_loc(sid), cum,                           &
                c_loc(pt_out), need, written, ff)
      case (256)
        rc = itb_decrypt_stream_authenticated3x256_c(                   &
                noise%raw_handle(), data1%raw_handle(), data2%raw_handle(), data3%raw_handle(), &
                start1%raw_handle(), start2%raw_handle(), start3%raw_handle(), mac%raw_handle(),&
                ct_ptr, ctlen, c_loc(sid), cum,                           &
                c_loc(pt_out), need, written, ff)
      case (512)
        rc = itb_decrypt_stream_authenticated3x512_c(                   &
                noise%raw_handle(), data1%raw_handle(), data2%raw_handle(), data3%raw_handle(), &
                start1%raw_handle(), start2%raw_handle(), start3%raw_handle(), mac%raw_handle(),&
                ct_ptr, ctlen, c_loc(sid), cum,                           &
                c_loc(pt_out), need, written, ff)
      end select
    end if
    if (rc /= STATUS_OK) then
      deallocate (pt_out)
      status = rc
      return
    end if
    if (written == 0_itb_size_kind) then
      deallocate (pt_out)
      allocate (pt_out(0))
      final_flag = ff
      status = STATUS_OK
      return
    end if
    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(written))
      trimmed = pt_out(1:int(written))
      call move_alloc(trimmed, pt_out)
    end block
    final_flag = ff
    status = STATUS_OK
  end subroutine

  ! ----------------------------------------------------------------
  ! Encrypt direction -- Single Ouroboros (authenticated)
  ! ----------------------------------------------------------------

  ! Single-Ouroboros authenticated stream encrypt. Buffers plaintext
  ! in `chunk_size`-byte windows, dispatches per chunk through the
  ! ITB_EncryptStreamAuthenticated{128,256,512} ABI export with the
  ! Streaming AEAD binding components (32-byte CSPRNG stream_id
  ! prefix, running cumulative pixel offset, terminating-chunk flag),
  ! and writes the resulting wire transcript (stream_id || chunk_0 ||
  ! chunk_1 || ...) to the output sink.
  subroutine itb_stream_encrypt_auth(noise, data, start, mac,           &
                                       read_fn, read_ctx,                &
                                       write_fn, write_ctx,              &
                                       chunk_size, status)
    type(itb_seed_t),                  intent(in)  :: noise, data, start
    type(itb_mac_t),                   intent(in)  :: mac
    procedure(itb_stream_read_fn),  pointer, intent(in)  :: read_fn
    type(c_ptr),                       value, intent(in) :: read_ctx
    procedure(itb_stream_write_fn), pointer, intent(in)  :: write_fn
    type(c_ptr),                       value, intent(in) :: write_ctx
    integer(itb_size_kind),            intent(in)  :: chunk_size
    integer(itb_status_kind),          intent(out) :: status
    integer(itb_byte_kind), allocatable, target :: cur(:)
    integer(itb_byte_kind), allocatable, target :: ct(:)
    integer(itb_byte_kind), target              :: sid(int(STREAM_ID_LEN))
    integer(itb_byte_kind), target              :: peek_byte(1)
    integer(itb_size_kind)                      :: cur_len, got, peek_got, hsz
    integer(c_int64_t)                          :: cum
    integer(c_int)                              :: rrc, wrc
    integer(c_int)                              :: width, is_final
    integer(itb_status_kind)                    :: emit_st, sid_st
    logical                                     :: eof
    integer                                     :: any_emitted

    if (chunk_size <= 0) then
      status = STATUS_BAD_INPUT
      return
    end if

    hsz = snapshot_header_size()
    if (hsz == 0) then
      status = STATUS_INTERNAL
      return
    end if

    width = 0_c_int
    call auth_seed_width(noise, width, status)
    if (status /= STATUS_OK) return

    sid = 0_itb_byte_kind
    call auth_generate_stream_id(sid, sid_st)
    if (sid_st /= STATUS_OK) then
      status = sid_st
      return
    end if

    wrc = write_fn(write_ctx, c_loc(sid), STREAM_ID_LEN)
    if (wrc /= 0) then
      status = STATUS_INTERNAL
      return
    end if

    allocate (cur(chunk_size))
    cur = 0_itb_byte_kind
    cur_len = 0_itb_size_kind
    cum = 0_c_int64_t
    eof = .false.
    any_emitted = 0

    do while (.not. eof)
      ! Drain into cur until full or EOF.
      do while (cur_len < chunk_size .and. .not. eof)
        got = 0_itb_size_kind
        rrc = read_fn(read_ctx, c_loc(cur(cur_len + 1)),                 &
                       chunk_size - cur_len, got)
        if (rrc /= 0) then
          cur = 0_itb_byte_kind
          status = STATUS_INTERNAL
          return
        end if
        if (got == 0) then
          eof = .true.
          exit
        end if
        cur_len = cur_len + got
      end do

      ! Decide terminal-chunk bit via 1-byte look-ahead when full.
      is_final = 0_c_int
      peek_got = 0_itb_size_kind
      if (cur_len == chunk_size .and. .not. eof) then
        rrc = read_fn(read_ctx, c_loc(peek_byte), 1_itb_size_kind, peek_got)
        if (rrc /= 0) then
          cur = 0_itb_byte_kind
          status = STATUS_INTERNAL
          return
        end if
        if (peek_got == 0) then
          eof = .true.
          is_final = 1_c_int
        end if
      else
        is_final = 1_c_int
      end if

      call auth_emit_chunk_single(width, noise, data, start, mac,        &
                                    cur, cur_len, sid, cum, is_final,     &
                                    ct, emit_st)
      if (emit_st /= STATUS_OK) then
        cur = 0_itb_byte_kind
        status = emit_st
        return
      end if

      ! Cumulative pixel offset advances by W*H of the just-emitted
      ! chunk (read off the chunk's wire header).
      cum = cum + pixels_from_header(ct, hsz)

      wrc = write_fn(write_ctx, c_loc(ct), int(size(ct), c_size_t))
      if (wrc /= 0) then
        cur = 0_itb_byte_kind
        ct = 0_itb_byte_kind
        status = STATUS_INTERNAL
        return
      end if
      ct = 0_itb_byte_kind
      cur = 0_itb_byte_kind
      cur_len = 0_itb_size_kind
      any_emitted = 1

      if (is_final == 1) then
        status = STATUS_OK
        return
      end if
      ! peek_byte holds the first byte of the next chunk.
      cur(1) = peek_byte(1)
      cur_len = 1_itb_size_kind
    end do

    ! Edge case: empty stream - emit a single terminating empty chunk.
    if (any_emitted == 0) then
      call auth_emit_chunk_single(width, noise, data, start, mac,        &
                                    cur, 0_itb_size_kind, sid, cum,        &
                                    1_c_int, ct, emit_st)
      if (emit_st /= STATUS_OK) then
        status = emit_st
        return
      end if
      wrc = write_fn(write_ctx, c_loc(ct), int(size(ct), c_size_t))
      if (wrc /= 0) then
        ct = 0_itb_byte_kind
        status = STATUS_INTERNAL
        return
      end if
      ct = 0_itb_byte_kind
    end if

    status = STATUS_OK
  end subroutine

  ! ----------------------------------------------------------------
  ! Encrypt direction -- Triple Ouroboros (authenticated)
  ! ----------------------------------------------------------------

  ! Triple-Ouroboros authenticated stream encrypt. Routes per-chunk
  ! through the ITB_EncryptStreamAuthenticated3x{128,256,512} ABI
  ! export; otherwise identical to `itb_stream_encrypt_auth`.
  subroutine itb_stream_encrypt_auth_triple(noise, data1, data2, data3,  &
                                              start1, start2, start3,     &
                                              mac,                        &
                                              read_fn, read_ctx,          &
                                              write_fn, write_ctx,        &
                                              chunk_size, status)
    type(itb_seed_t),                  intent(in)  :: noise
    type(itb_seed_t),                  intent(in)  :: data1, data2, data3
    type(itb_seed_t),                  intent(in)  :: start1, start2, start3
    type(itb_mac_t),                   intent(in)  :: mac
    procedure(itb_stream_read_fn),  pointer, intent(in)  :: read_fn
    type(c_ptr),                       value, intent(in) :: read_ctx
    procedure(itb_stream_write_fn), pointer, intent(in)  :: write_fn
    type(c_ptr),                       value, intent(in) :: write_ctx
    integer(itb_size_kind),            intent(in)  :: chunk_size
    integer(itb_status_kind),          intent(out) :: status
    integer(itb_byte_kind), allocatable, target :: cur(:)
    integer(itb_byte_kind), allocatable, target :: ct(:)
    integer(itb_byte_kind), target              :: sid(int(STREAM_ID_LEN))
    integer(itb_byte_kind), target              :: peek_byte(1)
    integer(itb_size_kind)                      :: cur_len, got, peek_got, hsz
    integer(c_int64_t)                          :: cum
    integer(c_int)                              :: rrc, wrc
    integer(c_int)                              :: width, is_final
    integer(itb_status_kind)                    :: emit_st, sid_st
    logical                                     :: eof
    integer                                     :: any_emitted

    if (chunk_size <= 0) then
      status = STATUS_BAD_INPUT
      return
    end if

    hsz = snapshot_header_size()
    if (hsz == 0) then
      status = STATUS_INTERNAL
      return
    end if

    width = 0_c_int
    call auth_seed_width(noise, width, status)
    if (status /= STATUS_OK) return

    sid = 0_itb_byte_kind
    call auth_generate_stream_id(sid, sid_st)
    if (sid_st /= STATUS_OK) then
      status = sid_st
      return
    end if

    wrc = write_fn(write_ctx, c_loc(sid), STREAM_ID_LEN)
    if (wrc /= 0) then
      status = STATUS_INTERNAL
      return
    end if

    allocate (cur(chunk_size))
    cur = 0_itb_byte_kind
    cur_len = 0_itb_size_kind
    cum = 0_c_int64_t
    eof = .false.
    any_emitted = 0

    do while (.not. eof)
      do while (cur_len < chunk_size .and. .not. eof)
        got = 0_itb_size_kind
        rrc = read_fn(read_ctx, c_loc(cur(cur_len + 1)),                 &
                       chunk_size - cur_len, got)
        if (rrc /= 0) then
          cur = 0_itb_byte_kind
          status = STATUS_INTERNAL
          return
        end if
        if (got == 0) then
          eof = .true.
          exit
        end if
        cur_len = cur_len + got
      end do

      is_final = 0_c_int
      peek_got = 0_itb_size_kind
      if (cur_len == chunk_size .and. .not. eof) then
        rrc = read_fn(read_ctx, c_loc(peek_byte), 1_itb_size_kind, peek_got)
        if (rrc /= 0) then
          cur = 0_itb_byte_kind
          status = STATUS_INTERNAL
          return
        end if
        if (peek_got == 0) then
          eof = .true.
          is_final = 1_c_int
        end if
      else
        is_final = 1_c_int
      end if

      call auth_emit_chunk_triple(width, noise,                         &
                                    data1, data2, data3,                 &
                                    start1, start2, start3, mac,         &
                                    cur, cur_len, sid, cum, is_final,    &
                                    ct, emit_st)
      if (emit_st /= STATUS_OK) then
        cur = 0_itb_byte_kind
        status = emit_st
        return
      end if

      cum = cum + pixels_from_header(ct, hsz)

      wrc = write_fn(write_ctx, c_loc(ct), int(size(ct), c_size_t))
      if (wrc /= 0) then
        cur = 0_itb_byte_kind
        ct = 0_itb_byte_kind
        status = STATUS_INTERNAL
        return
      end if
      ct = 0_itb_byte_kind
      cur = 0_itb_byte_kind
      cur_len = 0_itb_size_kind
      any_emitted = 1

      if (is_final == 1) then
        status = STATUS_OK
        return
      end if
      cur(1) = peek_byte(1)
      cur_len = 1_itb_size_kind
    end do

    if (any_emitted == 0) then
      call auth_emit_chunk_triple(width, noise,                         &
                                    data1, data2, data3,                 &
                                    start1, start2, start3, mac,         &
                                    cur, 0_itb_size_kind, sid, cum,      &
                                    1_c_int, ct, emit_st)
      if (emit_st /= STATUS_OK) then
        status = emit_st
        return
      end if
      wrc = write_fn(write_ctx, c_loc(ct), int(size(ct), c_size_t))
      if (wrc /= 0) then
        ct = 0_itb_byte_kind
        status = STATUS_INTERNAL
        return
      end if
      ct = 0_itb_byte_kind
    end if

    status = STATUS_OK
  end subroutine

  ! ----------------------------------------------------------------
  ! Decrypt direction -- Single Ouroboros (plain)
  ! ----------------------------------------------------------------

  ! Reads ciphertext bytes into an accumulator buffer, parses the
  ! chunk header on each pass to learn the announced chunk length,
  ! and decrypts whole chunks via `itb_decrypt` (Single Ouroboros,
  ! 3-seed) as soon as enough bytes have arrived. EOF on the input
  ! with a non-empty accumulator is a half-chunk error and surfaces
  ! as `STATUS_BAD_INPUT`.
  subroutine itb_stream_decrypt(noise, data, start, &
                                 read_fn, read_ctx, write_fn, write_ctx, &
                                 chunk_size, status)
    type(itb_seed_t),                  intent(in)  :: noise, data, start
    procedure(itb_stream_read_fn),  pointer, intent(in)  :: read_fn
    type(c_ptr),                       value, intent(in) :: read_ctx
    procedure(itb_stream_write_fn), pointer, intent(in)  :: write_fn
    type(c_ptr),                       value, intent(in) :: write_ctx
    integer(itb_size_kind),            intent(in)  :: chunk_size
    integer(itb_status_kind),          intent(out) :: status
    integer(itb_byte_kind), allocatable, target :: read_buf(:)
    integer(itb_byte_kind), allocatable, target :: accum(:)
    integer(itb_byte_kind), allocatable :: tmp(:)
    integer(itb_byte_kind), allocatable, target :: hdr(:)
    integer(itb_byte_kind), allocatable, target :: pt(:)
    integer(itb_size_kind) :: header_size, got, chunk_len
    integer(c_int) :: rrc, wrc
    integer(itb_status_kind) :: rc
    integer :: i

    if (chunk_size <= 0) then
      status = STATUS_BAD_INPUT
      return
    end if

    header_size = snapshot_header_size()
    if (header_size == 0) then
      status = STATUS_INTERNAL
      return
    end if

    allocate (read_buf(chunk_size))
    allocate (accum(0))

    do
      got = 0_itb_size_kind
      rrc = read_fn(read_ctx, c_loc(read_buf), chunk_size, got)
      if (rrc /= 0) then
        status = STATUS_INTERNAL
        return
      end if
      if (got == 0) then
        if (size(accum) > 0) then
          status = STATUS_BAD_INPUT
        else
          status = STATUS_OK
        end if
        return
      end if

      ! Append the freshly-read bytes to the accumulator.
      call concat_bytes(accum, read_buf, got, tmp)
      call move_alloc(tmp, accum)

      ! Drain every full chunk currently sitting in the accumulator.
      do
        if (int(size(accum), itb_size_kind) < header_size) exit
        ! Copy the header prefix into a contiguous target so c_loc is
        ! valid on every compiler (some refuse c_loc on an array
        ! section descriptor).
        if (allocated(hdr)) deallocate (hdr)
        allocate (hdr(int(header_size)))
        do i = 1, int(header_size)
          hdr(i) = accum(i)
        end do
        chunk_len = 0_itb_size_kind
        rc = itb_parse_chunk_len_c(c_loc(hdr), header_size, chunk_len)
        if (rc /= STATUS_OK) then
          status = rc
          return
        end if
        if (chunk_len == 0_itb_size_kind .or. &
            int(size(accum), itb_size_kind) < chunk_len) exit
        pt = itb_decrypt(noise, data, start, accum(1:int(chunk_len)))
        if (size(pt) > 0) then
          wrc = write_fn(write_ctx, c_loc(pt), int(size(pt), c_size_t))
          if (wrc /= 0) then
            pt = 0_itb_byte_kind
            status = STATUS_INTERNAL
            return
          end if
          ! Zero recovered plaintext after the writer callback has
          ! consumed it (callback contract: full consume before
          ! return).
          pt = 0_itb_byte_kind
        end if
        call slice_tail(accum, chunk_len, tmp)
        call move_alloc(tmp, accum)
      end do
    end do
  end subroutine

  ! ----------------------------------------------------------------
  ! Decrypt direction -- Triple Ouroboros (plain)
  ! ----------------------------------------------------------------

  ! Triple-Ouroboros plain stream decrypt. Routes per-chunk through
  ! `itb_decrypt_triple`; otherwise identical to
  ! `itb_stream_decrypt`.
  subroutine itb_stream_decrypt_triple(noise, data1, data2, data3,    &
                                        start1, start2, start3,        &
                                        read_fn, read_ctx,              &
                                        write_fn, write_ctx,            &
                                        chunk_size, status)
    type(itb_seed_t),                  intent(in)  :: noise
    type(itb_seed_t),                  intent(in)  :: data1, data2, data3
    type(itb_seed_t),                  intent(in)  :: start1, start2, start3
    procedure(itb_stream_read_fn),  pointer, intent(in)  :: read_fn
    type(c_ptr),                       value, intent(in) :: read_ctx
    procedure(itb_stream_write_fn), pointer, intent(in)  :: write_fn
    type(c_ptr),                       value, intent(in) :: write_ctx
    integer(itb_size_kind),            intent(in)  :: chunk_size
    integer(itb_status_kind),          intent(out) :: status
    integer(itb_byte_kind), allocatable, target :: read_buf(:)
    integer(itb_byte_kind), allocatable, target :: accum(:)
    integer(itb_byte_kind), allocatable :: tmp(:)
    integer(itb_byte_kind), allocatable, target :: hdr(:)
    integer(itb_byte_kind), allocatable, target :: pt(:)
    integer(itb_size_kind) :: header_size, got, chunk_len
    integer(c_int) :: rrc, wrc
    integer(itb_status_kind) :: rc
    integer :: i

    if (chunk_size <= 0) then
      status = STATUS_BAD_INPUT
      return
    end if

    header_size = snapshot_header_size()
    if (header_size == 0) then
      status = STATUS_INTERNAL
      return
    end if

    allocate (read_buf(chunk_size))
    allocate (accum(0))

    do
      got = 0_itb_size_kind
      rrc = read_fn(read_ctx, c_loc(read_buf), chunk_size, got)
      if (rrc /= 0) then
        status = STATUS_INTERNAL
        return
      end if
      if (got == 0) then
        if (size(accum) > 0) then
          status = STATUS_BAD_INPUT
        else
          status = STATUS_OK
        end if
        return
      end if

      call concat_bytes(accum, read_buf, got, tmp)
      call move_alloc(tmp, accum)

      do
        if (int(size(accum), itb_size_kind) < header_size) exit
        if (allocated(hdr)) deallocate (hdr)
        allocate (hdr(int(header_size)))
        do i = 1, int(header_size)
          hdr(i) = accum(i)
        end do
        chunk_len = 0_itb_size_kind
        rc = itb_parse_chunk_len_c(c_loc(hdr), header_size, chunk_len)
        if (rc /= STATUS_OK) then
          status = rc
          return
        end if
        if (chunk_len == 0_itb_size_kind .or. &
            int(size(accum), itb_size_kind) < chunk_len) exit
        pt = itb_decrypt_triple(noise, data1, data2, data3,    &
                                  start1, start2, start3,        &
                                  accum(1:int(chunk_len)))
        if (size(pt) > 0) then
          wrc = write_fn(write_ctx, c_loc(pt), int(size(pt), c_size_t))
          if (wrc /= 0) then
            pt = 0_itb_byte_kind
            status = STATUS_INTERNAL
            return
          end if
          pt = 0_itb_byte_kind
        end if
        call slice_tail(accum, chunk_len, tmp)
        call move_alloc(tmp, accum)
      end do
    end do
  end subroutine

  ! ----------------------------------------------------------------
  ! Decrypt direction -- Single Ouroboros (authenticated)
  ! ----------------------------------------------------------------

  ! Single-Ouroboros authenticated stream decrypt. Reads the 32-byte
  ! stream_id wire prefix once at start, walks chunks via the
  ! ITB_DecryptStreamAuthenticated{128,256,512} ABI export with the
  ! running cumulative pixel offset, and surfaces end-of-stream
  ! failure modes through `status`:
  !
  !   * `STATUS_STREAM_TRUNCATED` -- input exhausted before the
  !     terminating chunk (`final_flag == 1`) was observed.
  !   * `STATUS_STREAM_AFTER_FINAL` -- extra bytes followed the
  !     terminator.
  !   * `STATUS_MAC_FAILURE` -- per-chunk MAC mismatch (reorder,
  !     replay, prefix tamper, body tamper).
  subroutine itb_stream_decrypt_auth(noise, data, start, mac,           &
                                       read_fn, read_ctx,                &
                                       write_fn, write_ctx,              &
                                       chunk_size, status)
    type(itb_seed_t),                  intent(in)  :: noise, data, start
    type(itb_mac_t),                   intent(in)  :: mac
    procedure(itb_stream_read_fn),  pointer, intent(in)  :: read_fn
    type(c_ptr),                       value, intent(in) :: read_ctx
    procedure(itb_stream_write_fn), pointer, intent(in)  :: write_fn
    type(c_ptr),                       value, intent(in) :: write_ctx
    integer(itb_size_kind),            intent(in)  :: chunk_size
    integer(itb_status_kind),          intent(out) :: status
    integer(itb_byte_kind), allocatable, target :: read_buf(:)
    integer(itb_byte_kind), allocatable, target :: accum(:)
    integer(itb_byte_kind), allocatable :: tmp(:)
    integer(itb_byte_kind), allocatable, target :: hdr(:)
    integer(itb_byte_kind), allocatable, target :: pt(:)
    integer(itb_byte_kind), target              :: sid(int(STREAM_ID_LEN))
    integer(itb_size_kind) :: header_size, got, chunk_len, sid_have
    integer(itb_size_kind) :: copy_off, append_n, take, sid_need
    integer(c_int64_t)     :: cum, pixels
    integer(c_int)         :: rrc, wrc
    integer(c_int)         :: width, ff
    integer(itb_status_kind) :: rc, drain_st
    logical                  :: seen_final
    integer                  :: i

    if (chunk_size <= 0) then
      status = STATUS_BAD_INPUT
      return
    end if

    header_size = snapshot_header_size()
    if (header_size == 0) then
      status = STATUS_INTERNAL
      return
    end if

    width = 0_c_int
    call auth_seed_width(noise, width, status)
    if (status /= STATUS_OK) return

    allocate (read_buf(chunk_size))
    allocate (accum(0))
    ! Allocate the per-iteration header scratch buffer once; the
    ! header size is fixed for this stream, so reusing the same
    ! buffer every drain iteration avoids `allocate` / `deallocate`
    ! churn.
    allocate (hdr(int(header_size)))
    sid = 0_itb_byte_kind
    sid_have = 0_itb_size_kind
    cum = 0_c_int64_t
    seen_final = .false.

    do
      got = 0_itb_size_kind
      rrc = read_fn(read_ctx, c_loc(read_buf), chunk_size, got)
      if (rrc /= 0) then
        status = STATUS_INTERNAL
        return
      end if
      if (got == 0) then
        ! EOF -- drain whole chunks left in accum.
        do while (size(accum) > 0 .and. .not. seen_final)
          if (int(size(accum), itb_size_kind) < header_size) exit
          do i = 1, int(header_size)
            hdr(i) = accum(i)
          end do
          chunk_len = 0_itb_size_kind
          rc = itb_parse_chunk_len_c(c_loc(hdr), header_size, chunk_len)
          if (rc /= STATUS_OK) then
            status = rc
            return
          end if
          if (chunk_len == 0_itb_size_kind .or.                          &
              int(size(accum), itb_size_kind) < chunk_len) exit
          pixels = pixels_from_header(accum, header_size)
          call auth_consume_chunk_single(width, noise, data, start, mac, &
                                            accum, chunk_len, sid, cum,    &
                                            pt, ff, drain_st)
          if (drain_st /= STATUS_OK) then
            status = drain_st
            return
          end if
          if (size(pt) > 0) then
            wrc = write_fn(write_ctx, c_loc(pt), int(size(pt), c_size_t))
            if (wrc /= 0) then
              pt = 0_itb_byte_kind
              status = STATUS_INTERNAL
              return
            end if
            pt = 0_itb_byte_kind
          end if
          cum = cum + pixels
          call slice_tail(accum, chunk_len, tmp)
          call move_alloc(tmp, accum)
          if (ff /= 0) then
            seen_final = .true.
            if (size(accum) > 0) then
              status = STATUS_STREAM_AFTER_FINAL
              return
            end if
          end if
        end do
        if (sid_have < STREAM_ID_LEN) then
          ! EOF before the 32-byte stream_id prefix landed: the wire
          ! is malformed at the protocol level rather than truncated
          ! mid-transcript. Surface as BAD_INPUT so the caller
          ! distinguishes "no header" from "no terminator".
          status = STATUS_BAD_INPUT
          return
        end if
        if (.not. seen_final) then
          status = STATUS_STREAM_TRUNCATED
          return
        end if
        status = STATUS_OK
        return
      end if

      ! Capture the 32-byte stream_id prefix once.
      copy_off = 0_itb_size_kind
      if (sid_have < STREAM_ID_LEN) then
        sid_need = STREAM_ID_LEN - sid_have
        if (got < sid_need) then
          take = got
        else
          take = sid_need
        end if
        do i = 1, int(take)
          sid(int(sid_have) + i) = read_buf(i)
        end do
        sid_have = sid_have + take
        copy_off = take
        if (got == take .and. sid_have < STREAM_ID_LEN) cycle
      end if

      append_n = got - copy_off
      if (append_n > 0) then
        call concat_bytes(accum, read_buf(int(copy_off) + 1:int(got)),  &
                            append_n, tmp)
        call move_alloc(tmp, accum)
      end if

      ! Drain whole chunks.
      do
        if (seen_final) then
          if (size(accum) > 0) then
            status = STATUS_STREAM_AFTER_FINAL
            return
          end if
          exit
        end if
        if (int(size(accum), itb_size_kind) < header_size) exit
        do i = 1, int(header_size)
          hdr(i) = accum(i)
        end do
        chunk_len = 0_itb_size_kind
        rc = itb_parse_chunk_len_c(c_loc(hdr), header_size, chunk_len)
        if (rc /= STATUS_OK) then
          status = rc
          return
        end if
        if (chunk_len == 0_itb_size_kind .or.                            &
            int(size(accum), itb_size_kind) < chunk_len) exit
        pixels = pixels_from_header(accum, header_size)
        call auth_consume_chunk_single(width, noise, data, start, mac,   &
                                          accum, chunk_len, sid, cum,     &
                                          pt, ff, drain_st)
        if (drain_st /= STATUS_OK) then
          status = drain_st
          return
        end if
        if (size(pt) > 0) then
          wrc = write_fn(write_ctx, c_loc(pt), int(size(pt), c_size_t))
          if (wrc /= 0) then
            pt = 0_itb_byte_kind
            status = STATUS_INTERNAL
            return
          end if
          pt = 0_itb_byte_kind
        end if
        cum = cum + pixels
        call slice_tail(accum, chunk_len, tmp)
        call move_alloc(tmp, accum)
        if (ff /= 0) seen_final = .true.
      end do
    end do
  end subroutine

  ! ----------------------------------------------------------------
  ! Decrypt direction -- Triple Ouroboros (authenticated)
  ! ----------------------------------------------------------------

  ! Triple-Ouroboros authenticated stream decrypt. Routes per-chunk
  ! through the ITB_DecryptStreamAuthenticated3x{128,256,512} ABI
  ! export; otherwise identical to `itb_stream_decrypt_auth`.
  subroutine itb_stream_decrypt_auth_triple(noise, data1, data2, data3,  &
                                              start1, start2, start3,     &
                                              mac,                        &
                                              read_fn, read_ctx,          &
                                              write_fn, write_ctx,        &
                                              chunk_size, status)
    type(itb_seed_t),                  intent(in)  :: noise
    type(itb_seed_t),                  intent(in)  :: data1, data2, data3
    type(itb_seed_t),                  intent(in)  :: start1, start2, start3
    type(itb_mac_t),                   intent(in)  :: mac
    procedure(itb_stream_read_fn),  pointer, intent(in)  :: read_fn
    type(c_ptr),                       value, intent(in) :: read_ctx
    procedure(itb_stream_write_fn), pointer, intent(in)  :: write_fn
    type(c_ptr),                       value, intent(in) :: write_ctx
    integer(itb_size_kind),            intent(in)  :: chunk_size
    integer(itb_status_kind),          intent(out) :: status
    integer(itb_byte_kind), allocatable, target :: read_buf(:)
    integer(itb_byte_kind), allocatable, target :: accum(:)
    integer(itb_byte_kind), allocatable :: tmp(:)
    integer(itb_byte_kind), allocatable, target :: hdr(:)
    integer(itb_byte_kind), allocatable, target :: pt(:)
    integer(itb_byte_kind), target              :: sid(int(STREAM_ID_LEN))
    integer(itb_size_kind) :: header_size, got, chunk_len, sid_have
    integer(itb_size_kind) :: copy_off, append_n, take, sid_need
    integer(c_int64_t)     :: cum, pixels
    integer(c_int)         :: rrc, wrc
    integer(c_int)         :: width, ff
    integer(itb_status_kind) :: rc, drain_st
    logical                  :: seen_final
    integer                  :: i

    if (chunk_size <= 0) then
      status = STATUS_BAD_INPUT
      return
    end if

    header_size = snapshot_header_size()
    if (header_size == 0) then
      status = STATUS_INTERNAL
      return
    end if

    width = 0_c_int
    call auth_seed_width(noise, width, status)
    if (status /= STATUS_OK) return

    allocate (read_buf(chunk_size))
    allocate (accum(0))
    sid = 0_itb_byte_kind
    sid_have = 0_itb_size_kind
    cum = 0_c_int64_t
    seen_final = .false.

    do
      got = 0_itb_size_kind
      rrc = read_fn(read_ctx, c_loc(read_buf), chunk_size, got)
      if (rrc /= 0) then
        status = STATUS_INTERNAL
        return
      end if
      if (got == 0) then
        do while (size(accum) > 0 .and. .not. seen_final)
          if (int(size(accum), itb_size_kind) < header_size) exit
          if (allocated(hdr)) deallocate (hdr)
          allocate (hdr(int(header_size)))
          do i = 1, int(header_size)
            hdr(i) = accum(i)
          end do
          chunk_len = 0_itb_size_kind
          rc = itb_parse_chunk_len_c(c_loc(hdr), header_size, chunk_len)
          if (rc /= STATUS_OK) then
            status = rc
            return
          end if
          if (chunk_len == 0_itb_size_kind .or.                          &
              int(size(accum), itb_size_kind) < chunk_len) exit
          pixels = pixels_from_header(accum, header_size)
          call auth_consume_chunk_triple(width, noise,                   &
                                            data1, data2, data3,           &
                                            start1, start2, start3, mac,    &
                                            accum, chunk_len, sid, cum,     &
                                            pt, ff, drain_st)
          if (drain_st /= STATUS_OK) then
            status = drain_st
            return
          end if
          if (size(pt) > 0) then
            wrc = write_fn(write_ctx, c_loc(pt), int(size(pt), c_size_t))
            if (wrc /= 0) then
              pt = 0_itb_byte_kind
              status = STATUS_INTERNAL
              return
            end if
            pt = 0_itb_byte_kind
          end if
          cum = cum + pixels
          call slice_tail(accum, chunk_len, tmp)
          call move_alloc(tmp, accum)
          if (ff /= 0) then
            seen_final = .true.
            if (size(accum) > 0) then
              status = STATUS_STREAM_AFTER_FINAL
              return
            end if
          end if
        end do
        if (sid_have < STREAM_ID_LEN) then
          ! EOF before the 32-byte stream_id prefix landed: the wire
          ! is malformed at the protocol level rather than truncated
          ! mid-transcript. Surface as BAD_INPUT so the caller
          ! distinguishes "no header" from "no terminator".
          status = STATUS_BAD_INPUT
          return
        end if
        if (.not. seen_final) then
          status = STATUS_STREAM_TRUNCATED
          return
        end if
        status = STATUS_OK
        return
      end if

      copy_off = 0_itb_size_kind
      if (sid_have < STREAM_ID_LEN) then
        sid_need = STREAM_ID_LEN - sid_have
        if (got < sid_need) then
          take = got
        else
          take = sid_need
        end if
        do i = 1, int(take)
          sid(int(sid_have) + i) = read_buf(i)
        end do
        sid_have = sid_have + take
        copy_off = take
        if (got == take .and. sid_have < STREAM_ID_LEN) cycle
      end if

      append_n = got - copy_off
      if (append_n > 0) then
        call concat_bytes(accum, read_buf(int(copy_off) + 1:int(got)),  &
                            append_n, tmp)
        call move_alloc(tmp, accum)
      end if

      do
        if (seen_final) then
          if (size(accum) > 0) then
            status = STATUS_STREAM_AFTER_FINAL
            return
          end if
          exit
        end if
        if (int(size(accum), itb_size_kind) < header_size) exit
        if (allocated(hdr)) deallocate (hdr)
        allocate (hdr(int(header_size)))
        do i = 1, int(header_size)
          hdr(i) = accum(i)
        end do
        chunk_len = 0_itb_size_kind
        rc = itb_parse_chunk_len_c(c_loc(hdr), header_size, chunk_len)
        if (rc /= STATUS_OK) then
          status = rc
          return
        end if
        if (chunk_len == 0_itb_size_kind .or.                            &
            int(size(accum), itb_size_kind) < chunk_len) exit
        pixels = pixels_from_header(accum, header_size)
        call auth_consume_chunk_triple(width, noise,                     &
                                          data1, data2, data3,             &
                                          start1, start2, start3, mac,      &
                                          accum, chunk_len, sid, cum,       &
                                          pt, ff, drain_st)
        if (drain_st /= STATUS_OK) then
          status = drain_st
          return
        end if
        if (size(pt) > 0) then
          wrc = write_fn(write_ctx, c_loc(pt), int(size(pt), c_size_t))
          if (wrc /= 0) then
            pt = 0_itb_byte_kind
            status = STATUS_INTERNAL
            return
          end if
          pt = 0_itb_byte_kind
        end if
        cum = cum + pixels
        call slice_tail(accum, chunk_len, tmp)
        call move_alloc(tmp, accum)
        if (ff /= 0) seen_final = .true.
      end do
    end do
  end subroutine

  ! ----------------------------------------------------------------
  ! Easy Mode auth-stream helpers
  ! ----------------------------------------------------------------

  ! Per-chunk encrypt dispatcher for the Easy Mode auth-stream
  ! surface, routing through ITB_Easy_EncryptStreamAuth and returning
  ! the produced ciphertext via `ct_out`. Same capacity-formula +
  ! retry-once shape as the Low-Level auth helpers.
  subroutine auth_emit_chunk_easy(handle, plaintext, plen,             &
                                     sid, cum, final_flag,                &
                                     ct_out, status)
    integer(c_intptr_t),            intent(in)  :: handle
    integer(itb_byte_kind), target, intent(in)  :: plaintext(:)
    integer(itb_size_kind),         intent(in)  :: plen
    integer(itb_byte_kind), target, intent(in)  :: sid(:)
    integer(c_int64_t),             intent(in)  :: cum
    integer(c_int),                 intent(in)  :: final_flag
    integer(itb_byte_kind), allocatable, target, intent(out) :: ct_out(:)
    integer(itb_status_kind),       intent(out) :: status
    type(c_ptr)              :: pt_ptr
    integer(itb_size_kind)   :: cap, need, written
    integer(c_int)           :: rc

    if (plen == 0_itb_size_kind) then
      pt_ptr = c_null_ptr
    else
      pt_ptr = c_loc(plaintext)
    end if

    cap = max(131072_itb_size_kind, &
               plen + plen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (ct_out(cap))
    need = 0_itb_size_kind
    written = 0_itb_size_kind
    rc = itb_easy_encrypt_stream_auth_c(handle, pt_ptr, plen,            &
                                          c_loc(sid), cum, final_flag,    &
                                          c_loc(ct_out), cap, written)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      need = written
      deallocate (ct_out)
      allocate (ct_out(need))
      written = 0_itb_size_kind
      rc = itb_easy_encrypt_stream_auth_c(handle, pt_ptr, plen,          &
                                            c_loc(sid), cum, final_flag,  &
                                            c_loc(ct_out), need, written)
    end if
    if (rc /= STATUS_OK) then
      deallocate (ct_out)
      status = rc
      return
    end if
    if (written == 0_itb_size_kind) then
      deallocate (ct_out)
      allocate (ct_out(0))
      status = STATUS_OK
      return
    end if
    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(written))
      trimmed = ct_out(1:int(written))
      call move_alloc(trimmed, ct_out)
    end block
    status = STATUS_OK
  end subroutine

  ! Per-chunk decrypt dispatcher for the Easy Mode auth-stream
  ! surface. Same capacity-formula + retry-once shape; plaintext
  ! output is bounded by `ctlen`, so the formula is conservative on
  ! the upper end.
  subroutine auth_consume_chunk_easy(handle, ciphertext, ctlen,        &
                                        sid, cum,                        &
                                        pt_out, final_flag, status)
    integer(c_intptr_t),            intent(in)  :: handle
    integer(itb_byte_kind), target, intent(in)  :: ciphertext(:)
    integer(itb_size_kind),         intent(in)  :: ctlen
    integer(itb_byte_kind), target, intent(in)  :: sid(:)
    integer(c_int64_t),             intent(in)  :: cum
    integer(itb_byte_kind), allocatable, target, intent(out) :: pt_out(:)
    integer(c_int),                 intent(out) :: final_flag
    integer(itb_status_kind),       intent(out) :: status
    type(c_ptr)              :: ct_ptr
    integer(itb_size_kind)   :: cap, need, written
    integer(c_int)           :: rc, ff

    if (ctlen == 0_itb_size_kind) then
      ct_ptr = c_null_ptr
    else
      ct_ptr = c_loc(ciphertext)
    end if

    cap = max(131072_itb_size_kind, &
               ctlen + ctlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (pt_out(cap))
    need = 0_itb_size_kind
    written = 0_itb_size_kind
    ff = 0_c_int
    rc = itb_easy_decrypt_stream_auth_c(handle, ct_ptr, ctlen,           &
                                          c_loc(sid), cum,                 &
                                          c_loc(pt_out), cap, written, ff)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      need = written
      deallocate (pt_out)
      allocate (pt_out(need))
      written = 0_itb_size_kind
      rc = itb_easy_decrypt_stream_auth_c(handle, ct_ptr, ctlen,         &
                                            c_loc(sid), cum,               &
                                            c_loc(pt_out), need, written, ff)
    end if
    if (rc /= STATUS_OK) then
      deallocate (pt_out)
      status = rc
      return
    end if
    if (written == 0_itb_size_kind) then
      deallocate (pt_out)
      allocate (pt_out(0))
      final_flag = ff
      status = STATUS_OK
      return
    end if
    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(written))
      trimmed = pt_out(1:int(written))
      call move_alloc(trimmed, pt_out)
    end block
    final_flag = ff
    status = STATUS_OK
  end subroutine

  ! Easy Mode authenticated stream encrypt. The encryptor's bound MAC
  ! closure is reused for every chunk; the helper supplies the
  ! Streaming AEAD binding components (32-byte CSPRNG stream_id
  ! prefix, running cumulative pixel offset, terminating-chunk flag)
  ! internally. Closed-state preflight surfaces as STATUS_EASY_CLOSED.
  subroutine itb_encryptor_stream_encrypt_auth(enc,                     &
                                                  read_fn, read_ctx,    &
                                                  write_fn, write_ctx,  &
                                                  chunk_size, status)
    type(itb_encryptor_t),             intent(in)  :: enc
    procedure(itb_stream_read_fn),  pointer, intent(in)  :: read_fn
    type(c_ptr),                       value, intent(in) :: read_ctx
    procedure(itb_stream_write_fn), pointer, intent(in)  :: write_fn
    type(c_ptr),                       value, intent(in) :: write_ctx
    integer(itb_size_kind),            intent(in)  :: chunk_size
    integer(itb_status_kind),          intent(out) :: status
    integer(itb_byte_kind), allocatable, target :: cur(:)
    integer(itb_byte_kind), allocatable, target :: ct(:)
    integer(itb_byte_kind), target              :: sid(int(STREAM_ID_LEN))
    integer(itb_byte_kind), target              :: peek_byte(1)
    integer(itb_size_kind)                      :: cur_len, got, peek_got, hsz
    integer(c_int64_t)                          :: cum
    integer(c_int)                              :: rrc, wrc
    integer(c_int)                              :: is_final, hsz_status
    integer(itb_status_kind)                    :: emit_st, sid_st
    logical                                     :: eof
    integer                                     :: any_emitted

    if (enc%is_closed()) then
      status = STATUS_EASY_CLOSED
      return
    end if
    if (chunk_size <= 0) then
      status = STATUS_BAD_INPUT
      return
    end if

    hsz_status = STATUS_OK
    hsz = int(itb_easy_header_size_c(enc%raw_handle(), hsz_status), itb_size_kind)
    if (hsz_status /= STATUS_OK) then
      status = hsz_status
      return
    end if
    if (hsz == 0) then
      status = STATUS_INTERNAL
      return
    end if

    sid = 0_itb_byte_kind
    call auth_generate_stream_id(sid, sid_st)
    if (sid_st /= STATUS_OK) then
      status = sid_st
      return
    end if

    wrc = write_fn(write_ctx, c_loc(sid), STREAM_ID_LEN)
    if (wrc /= 0) then
      status = STATUS_INTERNAL
      return
    end if

    allocate (cur(chunk_size))
    cur = 0_itb_byte_kind
    cur_len = 0_itb_size_kind
    cum = 0_c_int64_t
    eof = .false.
    any_emitted = 0

    do while (.not. eof)
      do while (cur_len < chunk_size .and. .not. eof)
        got = 0_itb_size_kind
        rrc = read_fn(read_ctx, c_loc(cur(cur_len + 1)),                 &
                       chunk_size - cur_len, got)
        if (rrc /= 0) then
          cur = 0_itb_byte_kind
          status = STATUS_INTERNAL
          return
        end if
        if (got == 0) then
          eof = .true.
          exit
        end if
        cur_len = cur_len + got
      end do

      is_final = 0_c_int
      peek_got = 0_itb_size_kind
      if (cur_len == chunk_size .and. .not. eof) then
        rrc = read_fn(read_ctx, c_loc(peek_byte), 1_itb_size_kind, peek_got)
        if (rrc /= 0) then
          cur = 0_itb_byte_kind
          status = STATUS_INTERNAL
          return
        end if
        if (peek_got == 0) then
          eof = .true.
          is_final = 1_c_int
        end if
      else
        is_final = 1_c_int
      end if

      call auth_emit_chunk_easy(enc%raw_handle(), cur, cur_len, sid, cum,&
                                  is_final, ct, emit_st)
      if (emit_st /= STATUS_OK) then
        cur = 0_itb_byte_kind
        status = emit_st
        return
      end if

      cum = cum + pixels_from_header(ct, hsz)

      wrc = write_fn(write_ctx, c_loc(ct), int(size(ct), c_size_t))
      if (wrc /= 0) then
        cur = 0_itb_byte_kind
        ct = 0_itb_byte_kind
        status = STATUS_INTERNAL
        return
      end if
      ct = 0_itb_byte_kind
      cur = 0_itb_byte_kind
      cur_len = 0_itb_size_kind
      any_emitted = 1

      if (is_final == 1) then
        status = STATUS_OK
        return
      end if
      cur(1) = peek_byte(1)
      cur_len = 1_itb_size_kind
    end do

    if (any_emitted == 0) then
      call auth_emit_chunk_easy(enc%raw_handle(), cur, 0_itb_size_kind, &
                                  sid, cum, 1_c_int, ct, emit_st)
      if (emit_st /= STATUS_OK) then
        status = emit_st
        return
      end if
      wrc = write_fn(write_ctx, c_loc(ct), int(size(ct), c_size_t))
      if (wrc /= 0) then
        ct = 0_itb_byte_kind
        status = STATUS_INTERNAL
        return
      end if
      ct = 0_itb_byte_kind
    end if

    status = STATUS_OK
  end subroutine

  subroutine itb_encryptor_stream_decrypt_auth(enc,                     &
                                                  read_fn, read_ctx,    &
                                                  write_fn, write_ctx,  &
                                                  chunk_size, status)
    type(itb_encryptor_t),             intent(in)  :: enc
    procedure(itb_stream_read_fn),  pointer, intent(in)  :: read_fn
    type(c_ptr),                       value, intent(in) :: read_ctx
    procedure(itb_stream_write_fn), pointer, intent(in)  :: write_fn
    type(c_ptr),                       value, intent(in) :: write_ctx
    integer(itb_size_kind),            intent(in)  :: chunk_size
    integer(itb_status_kind),          intent(out) :: status
    integer(itb_byte_kind), allocatable, target :: read_buf(:)
    integer(itb_byte_kind), allocatable, target :: accum(:)
    integer(itb_byte_kind), allocatable :: tmp(:)
    integer(itb_byte_kind), allocatable, target :: hdr(:)
    integer(itb_byte_kind), allocatable, target :: pt(:)
    integer(itb_byte_kind), target              :: sid(int(STREAM_ID_LEN))
    integer(itb_size_kind) :: header_size, got, chunk_len, sid_have
    integer(itb_size_kind) :: copy_off, append_n, take, sid_need
    integer(c_int64_t)     :: cum, pixels
    integer(c_int)         :: rrc, wrc, hsz_status, ff
    integer(itb_status_kind) :: rc, drain_st
    logical                  :: seen_final
    integer                  :: i

    if (enc%is_closed()) then
      status = STATUS_EASY_CLOSED
      return
    end if
    if (chunk_size <= 0) then
      status = STATUS_BAD_INPUT
      return
    end if

    hsz_status = STATUS_OK
    header_size = int(itb_easy_header_size_c(enc%raw_handle(), hsz_status), &
                        itb_size_kind)
    if (hsz_status /= STATUS_OK) then
      status = hsz_status
      return
    end if
    if (header_size == 0) then
      status = STATUS_INTERNAL
      return
    end if

    allocate (read_buf(chunk_size))
    allocate (accum(0))
    ! Allocate the per-iteration header scratch buffer once; the
    ! header size is fixed for this stream, so reusing the same
    ! buffer every drain iteration avoids `allocate` / `deallocate`
    ! churn.
    allocate (hdr(int(header_size)))
    sid = 0_itb_byte_kind
    sid_have = 0_itb_size_kind
    cum = 0_c_int64_t
    seen_final = .false.

    do
      got = 0_itb_size_kind
      rrc = read_fn(read_ctx, c_loc(read_buf), chunk_size, got)
      if (rrc /= 0) then
        status = STATUS_INTERNAL
        return
      end if
      if (got == 0) then
        do while (size(accum) > 0 .and. .not. seen_final)
          if (int(size(accum), itb_size_kind) < header_size) exit
          do i = 1, int(header_size)
            hdr(i) = accum(i)
          end do
          chunk_len = 0_itb_size_kind
          rc = itb_parse_chunk_len_c(c_loc(hdr), header_size, chunk_len)
          if (rc /= STATUS_OK) then
            status = rc
            return
          end if
          if (chunk_len == 0_itb_size_kind .or.                          &
              int(size(accum), itb_size_kind) < chunk_len) exit
          pixels = pixels_from_header(accum, header_size)
          call auth_consume_chunk_easy(enc%raw_handle(), accum,           &
                                          chunk_len, sid, cum,             &
                                          pt, ff, drain_st)
          if (drain_st /= STATUS_OK) then
            status = drain_st
            return
          end if
          if (size(pt) > 0) then
            wrc = write_fn(write_ctx, c_loc(pt), int(size(pt), c_size_t))
            if (wrc /= 0) then
              pt = 0_itb_byte_kind
              status = STATUS_INTERNAL
              return
            end if
            pt = 0_itb_byte_kind
          end if
          cum = cum + pixels
          call slice_tail(accum, chunk_len, tmp)
          call move_alloc(tmp, accum)
          if (ff /= 0) then
            seen_final = .true.
            if (size(accum) > 0) then
              status = STATUS_STREAM_AFTER_FINAL
              return
            end if
          end if
        end do
        if (sid_have < STREAM_ID_LEN) then
          ! EOF before the 32-byte stream_id prefix landed: the wire
          ! is malformed at the protocol level rather than truncated
          ! mid-transcript. Surface as BAD_INPUT so the caller
          ! distinguishes "no header" from "no terminator".
          status = STATUS_BAD_INPUT
          return
        end if
        if (.not. seen_final) then
          status = STATUS_STREAM_TRUNCATED
          return
        end if
        status = STATUS_OK
        return
      end if

      copy_off = 0_itb_size_kind
      if (sid_have < STREAM_ID_LEN) then
        sid_need = STREAM_ID_LEN - sid_have
        if (got < sid_need) then
          take = got
        else
          take = sid_need
        end if
        do i = 1, int(take)
          sid(int(sid_have) + i) = read_buf(i)
        end do
        sid_have = sid_have + take
        copy_off = take
        if (got == take .and. sid_have < STREAM_ID_LEN) cycle
      end if

      append_n = got - copy_off
      if (append_n > 0) then
        call concat_bytes(accum, read_buf(int(copy_off) + 1:int(got)),  &
                            append_n, tmp)
        call move_alloc(tmp, accum)
      end if

      do
        if (seen_final) then
          if (size(accum) > 0) then
            status = STATUS_STREAM_AFTER_FINAL
            return
          end if
          exit
        end if
        if (int(size(accum), itb_size_kind) < header_size) exit
        do i = 1, int(header_size)
          hdr(i) = accum(i)
        end do
        chunk_len = 0_itb_size_kind
        rc = itb_parse_chunk_len_c(c_loc(hdr), header_size, chunk_len)
        if (rc /= STATUS_OK) then
          status = rc
          return
        end if
        if (chunk_len == 0_itb_size_kind .or.                            &
            int(size(accum), itb_size_kind) < chunk_len) exit
        pixels = pixels_from_header(accum, header_size)
        call auth_consume_chunk_easy(enc%raw_handle(), accum, chunk_len, &
                                        sid, cum, pt, ff, drain_st)
        if (drain_st /= STATUS_OK) then
          status = drain_st
          return
        end if
        if (size(pt) > 0) then
          wrc = write_fn(write_ctx, c_loc(pt), int(size(pt), c_size_t))
          if (wrc /= 0) then
            pt = 0_itb_byte_kind
            status = STATUS_INTERNAL
            return
          end if
          pt = 0_itb_byte_kind
        end if
        cum = cum + pixels
        call slice_tail(accum, chunk_len, tmp)
        call move_alloc(tmp, accum)
        if (ff /= 0) seen_final = .true.
      end do
    end do
  end subroutine

end module itb_streams
