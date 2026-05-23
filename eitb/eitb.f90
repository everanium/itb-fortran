! eitb.f90 -- Fortran-side eitb matrix runner.
!
! Mirrors `tools/eitb/main.go` for the Fortran binding. Eight examples
! crossed with three outer ciphers (aes / chacha / siphash) yields a
! 24-cell PASS/FAIL matrix. Every cell encrypts a CSPRNG plaintext
! (1024 bytes for single-message; 65536 bytes for streaming),
! seals the resulting ITB ciphertext under the chosen outer cipher,
! decrypts back through the wrap layer + the inner ITB layer, and
! verifies sha256 byte-equality of the recovered plaintext against
! the original.
!
! Examples (binding asymmetry: no Streaming No MAC IO-Driven cells
! because the Fortran binding has no unit-IO analogue for the
! No MAC streaming path):
!
!   1. aead-easy-io               Streaming AEAD Easy   (MAC Authenticated, IO-Driven)
!   2. aead-lowlevel-io           Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)
!   3. noaead-easy-userloop       Streaming Easy        (No MAC, User-Driven Loop)
!   4. noaead-lowlevel-userloop   Streaming Low-Level   (No MAC, User-Driven Loop)
!   5. message-easy-nomac         Easy Single Message      (No MAC)
!   6. message-easy-auth          Easy Single Message      (MAC Authenticated)
!   7. message-lowlevel-nomac     Low-Level Single Message (No MAC)
!   8. message-lowlevel-auth      Low-Level Single Message (MAC Authenticated)
!
! Default behaviour applies `itb_wrap_in_place` / `itb_unwrap_in_place`
! on the message-* examples (zero-allocation steady state); the
! immutable-input alternatives `itb_wrap` / `itb_unwrap` are kept as
! commented-out blocks alongside each call site so the tradeoff stays
! visible at the source.
!
! Streaming AEAD examples encrypt the inner-stream output into an
! in-memory sink, then wrap the entire emitted bytestream
! (32-byte streamID prefix + per-chunk wire) end-to-end through one
! `itb_wrap_stream_writer_t` session. Receiver mirrors with a single
! `itb_unwrap_stream_reader_t` feeding the inner-stream decoder via
! a paired in-memory source.
!
! Streaming No MAC examples follow the User-Driven Loop pattern:
! per-chunk Single Message `itb_encrypt` / `enc%encrypt` calls, with
! `u32_LE_len || ct` framed bytes written through the wrap-writer.
! Length prefix and chunk body both pass through the keystream XOR;
! no length appears in cleartext on the wire.

! ------------------------------------------------------------------
! In-memory source / sink callbacks for the Streaming AEAD path.
! Mirrors the existing test_easy_streams_auth helper module.
! ------------------------------------------------------------------

module eitb_io
  use, intrinsic :: iso_c_binding
  use itb_kinds
  implicit none
  public

  type, bind(C) :: src_t
    integer(c_size_t) :: total = 0
    integer(c_size_t) :: pos   = 0
    type(c_ptr)       :: data  = c_null_ptr
  end type

  type, bind(C) :: sink_t
    integer(c_size_t) :: cap = 0
    integer(c_size_t) :: pos = 0
    type(c_ptr)       :: data = c_null_ptr
  end type

contains

  function src_read(user_ctx, buf, cap, out_n) bind(C) result(rc)
    type(c_ptr),       value :: user_ctx
    type(c_ptr),       value :: buf
    integer(c_size_t), value :: cap
    integer(c_size_t)        :: out_n
    integer(c_int)           :: rc
    type(src_t),       pointer :: s
    integer(c_int8_t), pointer :: src_arr(:), dst_arr(:)
    integer(c_size_t) :: avail, take, i

    call c_f_pointer(user_ctx, s)
    avail = s%total - s%pos
    take  = min(cap, avail)
    if (take > 0) then
      call c_f_pointer(s%data, src_arr, [s%total])
      call c_f_pointer(buf,    dst_arr, [take])
      do i = 1, take
        dst_arr(i) = src_arr(s%pos + i)
      end do
      s%pos = s%pos + take
    end if
    out_n = take
    rc = 0_c_int
  end function

  function sink_write(user_ctx, buf, n) bind(C) result(rc)
    type(c_ptr),       value :: user_ctx
    type(c_ptr),       value :: buf
    integer(c_size_t), value :: n
    integer(c_int)           :: rc
    type(sink_t),      pointer :: s
    integer(c_int8_t), pointer :: src_arr(:), dst_arr(:)
    integer(c_size_t) :: i

    call c_f_pointer(user_ctx, s)
    if (s%pos + n > s%cap) then
      rc = 1_c_int
      return
    end if
    if (n > 0) then
      call c_f_pointer(buf,    src_arr, [n])
      call c_f_pointer(s%data, dst_arr, [s%cap])
      do i = 1, n
        dst_arr(s%pos + i) = src_arr(i)
      end do
      s%pos = s%pos + n
    end if
    rc = 0_c_int
  end function

end module eitb_io

! ------------------------------------------------------------------
! sha256 wrapper -- declares the C-side `itb_eitb_sha256` symbol and
! provides a Fortran-side helper that allocates a 32-byte digest
! buffer per call. Linked against bindings/c/eitb/sha256.c.
! ------------------------------------------------------------------

module eitb_sha256
  use, intrinsic :: iso_c_binding
  use itb_kinds
  implicit none
  public

  integer, parameter :: ITB_EITB_SHA256_DIGEST_LEN = 32

  interface
    subroutine itb_eitb_sha256_c(input, n, out) bind(C, name="itb_eitb_sha256")
      import
      type(c_ptr),       value :: input
      integer(c_size_t), value :: n
      type(c_ptr),       value :: out
    end subroutine
  end interface

contains

  ! Computes a 32-byte SHA-256 digest of `input(:)`. Returns a
  ! freshly-allocated `digest(:)` of length ITB_EITB_SHA256_DIGEST_LEN.
  subroutine sha256(input, digest)
    integer(itb_byte_kind), target, contiguous, intent(in)  :: input(:)
    integer(itb_byte_kind), allocatable, target, intent(out) :: digest(:)
    type(c_ptr) :: in_ptr
    allocate (digest(ITB_EITB_SHA256_DIGEST_LEN))
    in_ptr = c_null_ptr
    if (size(input) > 0) in_ptr = c_loc(input)
    call itb_eitb_sha256_c(in_ptr, int(size(input), c_size_t), c_loc(digest))
  end subroutine

  ! Compares two byte arrays. Returns .true. when both are the same
  ! length and every byte matches.
  pure function bytes_eq(a, b) result(eq)
    integer(itb_byte_kind), intent(in) :: a(:), b(:)
    logical :: eq
    integer :: i
    eq = .false.
    if (size(a) /= size(b)) return
    do i = 1, size(a)
      if (a(i) /= b(i)) return
    end do
    eq = .true.
  end function

end module eitb_sha256

! ------------------------------------------------------------------
! Main eitb program.
! ------------------------------------------------------------------

program eitb
  use, intrinsic :: iso_c_binding
  use, intrinsic :: iso_fortran_env, only: output_unit, error_unit
  use itb_kinds
  use itb_library
  use itb_seed
  use itb_mac
  use itb_cipher
  use itb_encryptor
  use itb_streams
  use itb_wrapper
  use itb_errors
  use eitb_io
  use eitb_sha256
  implicit none

  integer, parameter :: NUM_EXAMPLES = 8
  integer, parameter :: NUM_CIPHERS  = 3
  integer, parameter :: STREAM_BYTES = 65536
  integer, parameter :: SINGLE_BYTES = 1024
  integer, parameter :: STREAM_CHUNK = 16384

  integer, parameter :: CIPHERS(NUM_CIPHERS) = &
    [ITB_WRAPPER_CIPHER_AES_128_CTR,                     &
     ITB_WRAPPER_CIPHER_CHACHA20,                        &
     ITB_WRAPPER_CIPHER_SIPHASH24]
  character(len=9), parameter :: CIPHER_NAMES(NUM_CIPHERS) = &
    [character(len=9) :: "aescmac", "chacha20", "siphash24"]

  character(len=26), parameter :: EXAMPLE_NAMES(NUM_EXAMPLES) = &
    [character(len=26) ::                                       &
       "aead-easy-io",                                          &
       "aead-lowlevel-io",                                      &
       "noaead-easy-userloop",                                  &
       "noaead-lowlevel-userloop",                              &
       "message-easy-nomac",                                    &
       "message-easy-auth",                                     &
       "message-lowlevel-nomac",                                &
       "message-lowlevel-auth"]

  integer :: pass_count, fail_count
  integer :: e, c
  integer(itb_byte_kind), allocatable, target :: plaintext(:), recovered(:)
  integer :: pt_n, wire_n
  logical :: ok
  character(len=128) :: err_msg
  integer(itb_status_kind) :: rc

  ! Global ITB tunables -- libitb default workers (auto-detect).
  call itb_set_max_workers(0)

  pass_count = 0
  fail_count = 0

  do e = 1, NUM_EXAMPLES
    if (e <= 4) then
      pt_n = STREAM_BYTES
    else
      pt_n = SINGLE_BYTES
    end if
    do c = 1, NUM_CIPHERS
      ! Fresh CSPRNG plaintext per (example, cipher) cell.
      call csprng_plaintext(pt_n, plaintext, rc)
      if (rc /= STATUS_OK) then
        write (error_unit, "(A)") "csprng plaintext draw failed"
        stop 1
      end if

      err_msg = ""
      ok = .false.
      wire_n = 0

      select case (e)
      case (1); call run_aead_easy_io(CIPHERS(c), plaintext, recovered, wire_n, ok, err_msg)
      case (2); call run_aead_lowlevel_io(CIPHERS(c), plaintext, recovered, wire_n, ok, err_msg)
      case (3); call run_noaead_easy_userloop(CIPHERS(c), plaintext, recovered, wire_n, ok, err_msg)
      case (4); call run_noaead_lowlevel_userloop(CIPHERS(c), plaintext, recovered, wire_n, ok, err_msg)
      case (5); call run_message_easy_nomac(CIPHERS(c), plaintext, recovered, wire_n, ok, err_msg)
      case (6); call run_message_easy_auth(CIPHERS(c), plaintext, recovered, wire_n, ok, err_msg)
      case (7); call run_message_lowlevel_nomac(CIPHERS(c), plaintext, recovered, wire_n, ok, err_msg)
      case (8); call run_message_lowlevel_auth(CIPHERS(c), plaintext, recovered, wire_n, ok, err_msg)
      end select

      ! Verify via sha256 + length match.
      if (ok) then
        block
          integer(itb_byte_kind), allocatable :: pt_d(:), rcv_d(:)
          call sha256(plaintext, pt_d)
          if (allocated(recovered)) then
            call sha256(recovered, rcv_d)
          else
            allocate (rcv_d(ITB_EITB_SHA256_DIGEST_LEN))
            rcv_d = 0_itb_byte_kind
          end if
          if (.not. bytes_eq(pt_d, rcv_d)) then
            ok = .false.
            err_msg = "sha256 mismatch"
          end if
          deallocate (pt_d, rcv_d)
        end block
      end if

      ! Print one line per cell.
      if (ok) then
        pass_count = pass_count + 1
        write (output_unit, "(A,A,A,A,A,A,A,I0,A,I0)") &
            "[PASS] ", trim(EXAMPLE_NAMES(e)),                                   &
            repeat(" ", max(1, 26 - len_trim(EXAMPLE_NAMES(e)))),                &
            "+ ", trim(CIPHER_NAMES(c)),                                         &
            repeat(" ", max(1, 9 - len_trim(CIPHER_NAMES(c)))),                  &
            "  pt=", pt_n, " wire=", wire_n
      else
        fail_count = fail_count + 1
        write (output_unit, "(A,A,A,A,A,A,A,I0,A,I0,A,A)") &
            "[FAIL] ", trim(EXAMPLE_NAMES(e)),                                   &
            repeat(" ", max(1, 26 - len_trim(EXAMPLE_NAMES(e)))),                &
            "+ ", trim(CIPHER_NAMES(c)),                                         &
            repeat(" ", max(1, 9 - len_trim(CIPHER_NAMES(c)))),                  &
            "  pt=", pt_n, " wire=", wire_n,                                     &
            "  err: ", trim(err_msg)
      end if
      flush (output_unit)

      if (allocated(plaintext))  deallocate (plaintext)
      if (allocated(recovered))  deallocate (recovered)
    end do
  end do

  write (output_unit, "(A)") ""
  write (output_unit, "(A,I0,A,I0,A)") "=== Summary: ", pass_count, " PASS, ", fail_count, " FAIL ==="
  if (fail_count > 0) stop 1

contains

  ! ----------------------------------------------------------------
  ! CSPRNG plaintext draw -- /dev/urandom via stream-access read.
  ! ----------------------------------------------------------------
  subroutine csprng_plaintext(n, out, status)
    integer,                                     intent(in)  :: n
    integer(itb_byte_kind), allocatable, target, intent(out) :: out(:)
    integer(itb_status_kind),                    intent(out) :: status
    integer :: u, ios
    allocate (out(max(n, 1)))
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

  ! ----------------------------------------------------------------
  ! Easy Mode encryptor builder. Areion-SoEM-512, mode 1 (Single
  ! Ouroboros), nonce_bits=128, barrier_fill=4, bit_soup=1, lock_soup=1.
  ! ----------------------------------------------------------------
  subroutine make_easy_encryptor(with_mac, key_bits, enc)
    logical,               intent(in)  :: with_mac
    integer,               intent(in)  :: key_bits
    type(itb_encryptor_t), intent(out) :: enc
    if (with_mac) then
      call new_itb_encryptor(enc, "areion512", key_bits, "hmac-blake3", 1)
    else
      call new_itb_encryptor(enc, "areion512", key_bits, "", 1)
    end if
    call enc%set_nonce_bits(128)
    call enc%set_barrier_fill(4)
    call enc%set_bit_soup(1)
    call enc%set_lock_soup(1)
  end subroutine

  ! ----------------------------------------------------------------
  ! 1. aead-easy-io -- Streaming AEAD Easy (MAC Authenticated, IO-Driven)
  ! ----------------------------------------------------------------
  ! Sender uses `itb_encryptor_stream_encrypt_auth` backed by an
  ! in-memory sink. Then the entire emitted bytestream
  ! (32-byte stream prefix + per-chunk wire) is wrapped end-to-end
  ! through one `itb_wrap_stream_writer_t` session. Receiver reverses
  ! with `itb_unwrap_stream_reader_t` feeding the inner-stream
  ! decoder.
  subroutine run_aead_easy_io(cipher, plaintext, recovered, wire_n, ok, err_msg)
    integer,                                     intent(in)  :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: plaintext(:)
    integer(itb_byte_kind), allocatable, target, intent(out) :: recovered(:)
    integer,                                     intent(out) :: wire_n
    logical,                                     intent(out) :: ok
    character(*),                                intent(inout) :: err_msg
    type(itb_encryptor_t) :: enc, sib
    type(src_t),  target :: src_pt, src_inner
    type(sink_t), target :: sink_inner, sink_pt
    integer(itb_byte_kind), allocatable, target :: inner_buf(:), pt_buf(:)
    integer(itb_byte_kind), allocatable, target :: outer_key(:)
    integer(itb_byte_kind), allocatable, target :: nonce(:), wire(:)
    integer(itb_byte_kind), allocatable, target :: inner_recovered(:)
    integer(itb_byte_kind), allocatable, target :: tmp_in(:), tmp_out(:)
    type(itb_wrap_stream_writer_t)   :: ww
    type(itb_unwrap_stream_reader_t) :: ur
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_size_kind) :: cap_inner, cap_pt
    integer(itb_status_kind) :: rc, st
    integer :: nlen, body_len, plain_len

    ok = .false.
    wire_n = 0
    plain_len = size(plaintext)

    rfn => src_read
    wfn => sink_write

    call make_easy_encryptor(.true., 1024, enc)
    ! Sibling encryptor reproduced via export/import for the decrypt
    ! side (Easy Mode encryptors are not internally symmetric across
    ! independent constructors; export/import shares state.)
    block
      integer(itb_byte_kind), allocatable :: blob(:)
      blob = enc%export_state()
      call new_itb_encryptor(sib, "areion512", 1024, "hmac-blake3", 1)
      call sib%import_state(blob)
    end block

    cap_inner = int(plain_len, itb_size_kind) * 6_itb_size_kind +              &
                  262144_itb_size_kind
    cap_pt    = int(plain_len, itb_size_kind) + 1024_itb_size_kind
    allocate (inner_buf(cap_inner))
    allocate (pt_buf(cap_pt))

    src_pt%total = int(plain_len, c_size_t)
    src_pt%pos = 0; src_pt%data = c_loc(plaintext)
    sink_inner%cap = cap_inner; sink_inner%pos = 0
    sink_inner%data = c_loc(inner_buf)

    call itb_encryptor_stream_encrypt_auth(enc, rfn, c_loc(src_pt),            &
                                             wfn, c_loc(sink_inner),            &
                                             int(STREAM_CHUNK, itb_size_kind), &
                                             rc)
    if (rc /= STATUS_OK) then
      err_msg = "stream_encrypt_auth"
      goto 999
    end if

    ! Wrap the entire inner bytestream end-to-end.
    call itb_wrapper_generate_key(cipher, outer_key, rc)
    if (rc /= STATUS_OK) then
      err_msg = "generate_key"
      goto 999
    end if
    call itb_wrap_stream_writer_new(cipher, outer_key, ww, nonce, rc)
    if (rc /= STATUS_OK) then
      err_msg = "wrap_stream_writer_new"
      goto 999
    end if
    nlen = size(nonce)
    body_len = int(sink_inner%pos)
    allocate (wire(nlen + body_len))
    wire(1:nlen) = nonce(1:nlen)
    if (body_len > 0) then
      allocate (tmp_in(body_len))
      allocate (tmp_out(body_len))
      tmp_in(:) = inner_buf(1:body_len)
      call ww%update(tmp_in, tmp_out, rc)
      if (rc /= STATUS_OK) then
        err_msg = "wrap_stream_writer_update"
        call ww%destroy()
        goto 999
      end if
      wire(nlen + 1 : nlen + body_len) = tmp_out(:)
      deallocate (tmp_in, tmp_out)
    end if
    call ww%destroy()
    wire_n = size(wire)

    ! Receiver -- unwrap the body stream, feed to decrypt_auth.
    call itb_unwrap_stream_reader_new(cipher, outer_key, wire(1:nlen), ur, rc)
    if (rc /= STATUS_OK) then
      err_msg = "unwrap_stream_reader_new"
      goto 999
    end if
    allocate (inner_recovered(body_len))
    if (body_len > 0) then
      allocate (tmp_in(body_len))
      allocate (tmp_out(body_len))
      tmp_in(:) = wire(nlen + 1 : nlen + body_len)
      call ur%update(tmp_in, tmp_out, rc)
      if (rc /= STATUS_OK) then
        err_msg = "unwrap_stream_reader_update"
        call ur%destroy()
        goto 999
      end if
      inner_recovered(1:body_len) = tmp_out(:)
      deallocate (tmp_in, tmp_out)
    end if
    call ur%destroy()

    src_inner%total = int(body_len, c_size_t); src_inner%pos = 0
    src_inner%data = c_loc(inner_recovered)
    sink_pt%cap = cap_pt; sink_pt%pos = 0; sink_pt%data = c_loc(pt_buf)

    call itb_encryptor_stream_decrypt_auth(sib, rfn, c_loc(src_inner),         &
                                             wfn, c_loc(sink_pt),               &
                                             int(STREAM_CHUNK, itb_size_kind), &
                                             rc)
    if (rc /= STATUS_OK) then
      err_msg = "stream_decrypt_auth"
      goto 999
    end if

    allocate (recovered(int(sink_pt%pos)))
    recovered(:) = pt_buf(1:int(sink_pt%pos))
    ok = .true.

999 continue
    if (allocated(inner_buf))       deallocate (inner_buf)
    if (allocated(pt_buf))          deallocate (pt_buf)
    if (allocated(outer_key))       deallocate (outer_key)
    if (allocated(nonce))           deallocate (nonce)
    if (allocated(wire))            deallocate (wire)
    if (allocated(inner_recovered)) deallocate (inner_recovered)
    if (allocated(tmp_in))          deallocate (tmp_in)
    if (allocated(tmp_out))         deallocate (tmp_out)
    call enc%destroy()
    call sib%destroy()
    st = rc  ! avoid unused-warning; status surfaces via err_msg
  end subroutine

  ! ----------------------------------------------------------------
  ! 2. aead-lowlevel-io -- Streaming AEAD Low-Level (MAC Authenticated,
  ! IO-Driven). Three explicit Areion-SoEM-512 seeds + HMAC-BLAKE3 MAC.
  ! ----------------------------------------------------------------
  subroutine run_aead_lowlevel_io(cipher, plaintext, recovered, wire_n, ok, err_msg)
    integer,                                     intent(in)  :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: plaintext(:)
    integer(itb_byte_kind), allocatable, target, intent(out) :: recovered(:)
    integer,                                     intent(out) :: wire_n
    logical,                                     intent(out) :: ok
    character(*),                                intent(inout) :: err_msg
    type(itb_seed_t) :: noise, data_seed, start_seed
    type(itb_mac_t)  :: mac
    type(src_t),  target :: src_pt, src_inner
    type(sink_t), target :: sink_inner, sink_pt
    integer(itb_byte_kind), allocatable, target :: inner_buf(:), pt_buf(:)
    integer(itb_byte_kind), allocatable, target :: outer_key(:)
    integer(itb_byte_kind), allocatable, target :: nonce(:), wire(:)
    integer(itb_byte_kind), allocatable, target :: inner_recovered(:)
    integer(itb_byte_kind), allocatable, target :: tmp_in(:), tmp_out(:)
    integer(itb_byte_kind), target :: mac_key(32)
    integer(itb_byte_kind), allocatable :: mac_key_alloc(:)
    type(itb_wrap_stream_writer_t)   :: ww
    type(itb_unwrap_stream_reader_t) :: ur
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_size_kind) :: cap_inner, cap_pt
    integer(itb_status_kind) :: rc
    integer :: nlen, body_len, plain_len

    ok = .false.
    wire_n = 0
    plain_len = size(plaintext)

    rfn => src_read
    wfn => sink_write

    call itb_set_nonce_bits(128)
    call itb_set_barrier_fill(4)
    call itb_set_bit_soup(1)
    call itb_set_lock_soup(1)

    call new_itb_seed(noise,      "areion512", 1024)
    call new_itb_seed(data_seed,  "areion512", 1024)
    call new_itb_seed(start_seed, "areion512", 1024)
    call csprng_into_buf(mac_key, 32, rc)
    if (rc /= STATUS_OK) then
      err_msg = "csprng mac_key"
      goto 999
    end if
    allocate (mac_key_alloc(32))
    mac_key_alloc(:) = mac_key(:)
    call new_itb_mac(mac, "hmac-blake3", mac_key_alloc)

    cap_inner = int(plain_len, itb_size_kind) * 6_itb_size_kind +              &
                  262144_itb_size_kind
    cap_pt    = int(plain_len, itb_size_kind) + 1024_itb_size_kind
    allocate (inner_buf(cap_inner))
    allocate (pt_buf(cap_pt))

    src_pt%total = int(plain_len, c_size_t)
    src_pt%pos = 0; src_pt%data = c_loc(plaintext)
    sink_inner%cap = cap_inner; sink_inner%pos = 0
    sink_inner%data = c_loc(inner_buf)

    call itb_stream_encrypt_auth(noise, data_seed, start_seed, mac,            &
                                    rfn, c_loc(src_pt), wfn, c_loc(sink_inner),&
                                    int(STREAM_CHUNK, itb_size_kind), rc)
    if (rc /= STATUS_OK) then
      err_msg = "stream_encrypt_auth"
      goto 999
    end if

    call itb_wrapper_generate_key(cipher, outer_key, rc)
    if (rc /= STATUS_OK) then
      err_msg = "generate_key"
      goto 999
    end if
    call itb_wrap_stream_writer_new(cipher, outer_key, ww, nonce, rc)
    if (rc /= STATUS_OK) then
      err_msg = "wrap_stream_writer_new"
      goto 999
    end if
    nlen = size(nonce)
    body_len = int(sink_inner%pos)
    allocate (wire(nlen + body_len))
    wire(1:nlen) = nonce(1:nlen)
    if (body_len > 0) then
      allocate (tmp_in(body_len))
      allocate (tmp_out(body_len))
      tmp_in(:) = inner_buf(1:body_len)
      call ww%update(tmp_in, tmp_out, rc)
      if (rc /= STATUS_OK) then
        err_msg = "wrap_stream_writer_update"
        call ww%destroy()
        goto 999
      end if
      wire(nlen + 1 : nlen + body_len) = tmp_out(:)
      deallocate (tmp_in, tmp_out)
    end if
    call ww%destroy()
    wire_n = size(wire)

    call itb_unwrap_stream_reader_new(cipher, outer_key, wire(1:nlen), ur, rc)
    if (rc /= STATUS_OK) then
      err_msg = "unwrap_stream_reader_new"
      goto 999
    end if
    allocate (inner_recovered(body_len))
    if (body_len > 0) then
      allocate (tmp_in(body_len))
      allocate (tmp_out(body_len))
      tmp_in(:) = wire(nlen + 1 : nlen + body_len)
      call ur%update(tmp_in, tmp_out, rc)
      if (rc /= STATUS_OK) then
        err_msg = "unwrap_stream_reader_update"
        call ur%destroy()
        goto 999
      end if
      inner_recovered(1:body_len) = tmp_out(:)
      deallocate (tmp_in, tmp_out)
    end if
    call ur%destroy()

    src_inner%total = int(body_len, c_size_t); src_inner%pos = 0
    src_inner%data = c_loc(inner_recovered)
    sink_pt%cap = cap_pt; sink_pt%pos = 0; sink_pt%data = c_loc(pt_buf)

    call itb_stream_decrypt_auth(noise, data_seed, start_seed, mac,            &
                                    rfn, c_loc(src_inner), wfn, c_loc(sink_pt),&
                                    int(STREAM_CHUNK, itb_size_kind), rc)
    if (rc /= STATUS_OK) then
      err_msg = "stream_decrypt_auth"
      goto 999
    end if

    allocate (recovered(int(sink_pt%pos)))
    recovered(:) = pt_buf(1:int(sink_pt%pos))
    ok = .true.

999 continue
    if (allocated(inner_buf))       deallocate (inner_buf)
    if (allocated(pt_buf))          deallocate (pt_buf)
    if (allocated(outer_key))       deallocate (outer_key)
    if (allocated(nonce))           deallocate (nonce)
    if (allocated(wire))            deallocate (wire)
    if (allocated(inner_recovered)) deallocate (inner_recovered)
    if (allocated(tmp_in))          deallocate (tmp_in)
    if (allocated(tmp_out))         deallocate (tmp_out)
    if (allocated(mac_key_alloc))   deallocate (mac_key_alloc)
    call mac%destroy()
    call noise%destroy(); call data_seed%destroy(); call start_seed%destroy()
  end subroutine

  ! ----------------------------------------------------------------
  ! 3. noaead-easy-userloop -- Streaming Easy (No MAC, User-Driven Loop)
  ! ----------------------------------------------------------------
  ! Per-chunk Single Message enc.encrypt() / enc.decrypt(). Each
  ! `u32_LE_len || ct` pair goes through the wrap-writer; on the
  ! receiver side the unwrap-reader recovers `u32_LE_len`, reads
  ! `len` bytes, and decrypts the chunk.
  subroutine run_noaead_easy_userloop(cipher, plaintext, recovered, wire_n, ok, err_msg)
    integer,                                     intent(in)  :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: plaintext(:)
    integer(itb_byte_kind), allocatable, target, intent(out) :: recovered(:)
    integer,                                     intent(out) :: wire_n
    logical,                                     intent(out) :: ok
    character(*),                                intent(inout) :: err_msg
    type(itb_encryptor_t) :: enc, sib
    integer(itb_byte_kind), allocatable, target :: outer_key(:), nonce(:)
    integer(itb_byte_kind), allocatable :: wire_acc(:), tmp(:), pt_acc(:)
    integer(itb_byte_kind), allocatable :: chunk_pt(:), chunk_ct(:)
    integer(itb_byte_kind), allocatable, target :: in4(:), out4(:)
    integer(itb_byte_kind), allocatable, target :: ct_in(:), ct_out(:)
    type(itb_wrap_stream_writer_t)   :: ww
    type(itb_unwrap_stream_reader_t) :: ur
    integer(itb_status_kind) :: rc
    integer :: off, n, plain_len, total_pt, ct_len, len_xord, nlen
    integer :: i

    ok = .false.
    wire_n = 0
    plain_len = size(plaintext)

    call make_easy_encryptor(.false., 1024, enc)
    block
      integer(itb_byte_kind), allocatable :: blob(:)
      blob = enc%export_state()
      call new_itb_encryptor(sib, "areion512", 1024, "", 1)
      call sib%import_state(blob)
    end block

    call itb_wrapper_generate_key(cipher, outer_key, rc)
    if (rc /= STATUS_OK) then
      err_msg = "generate_key"
      goto 999
    end if

    call itb_wrap_stream_writer_new(cipher, outer_key, ww, nonce, rc)
    if (rc /= STATUS_OK) then
      err_msg = "wrap_stream_writer_new"
      goto 999
    end if
    nlen = size(nonce)
    allocate (wire_acc(nlen))
    wire_acc(:) = nonce(:)

    off = 0
    do while (off < plain_len)
      n = min(STREAM_CHUNK, plain_len - off)
      allocate (chunk_pt(n))
      chunk_pt(:) = plaintext(off + 1 : off + n)
      chunk_ct = enc%encrypt(chunk_pt)
      ct_len = size(chunk_ct)

      ! Emit `u32_LE_len || ct` through the wrap-writer.
      allocate (in4(4))
      allocate (out4(4))
      in4(1) = int(iand(ct_len,        255), itb_byte_kind)
      in4(2) = int(iand(ishft(ct_len, -8), 255), itb_byte_kind)
      in4(3) = int(iand(ishft(ct_len, -16), 255), itb_byte_kind)
      in4(4) = int(iand(ishft(ct_len, -24), 255), itb_byte_kind)
      call ww%update(in4, out4, rc)
      if (rc /= STATUS_OK) then
        err_msg = "ww%update length"
        deallocate (in4, out4, chunk_pt, chunk_ct)
        call ww%destroy()
        goto 999
      end if
      ! Append 4 wired-len bytes.
      allocate (tmp(size(wire_acc) + 4))
      tmp(1:size(wire_acc)) = wire_acc(:)
      tmp(size(wire_acc) + 1 : size(wire_acc) + 4) = out4(:)
      call move_alloc(tmp, wire_acc)
      deallocate (in4, out4)

      allocate (ct_in(ct_len))
      allocate (ct_out(ct_len))
      ct_in(:) = chunk_ct(:)
      call ww%update(ct_in, ct_out, rc)
      if (rc /= STATUS_OK) then
        err_msg = "ww%update body"
        deallocate (chunk_pt, chunk_ct, ct_in, ct_out)
        call ww%destroy()
        goto 999
      end if
      allocate (tmp(size(wire_acc) + ct_len))
      tmp(1:size(wire_acc)) = wire_acc(:)
      tmp(size(wire_acc) + 1 : size(wire_acc) + ct_len) = ct_out(:)
      call move_alloc(tmp, wire_acc)
      deallocate (ct_in, ct_out, chunk_pt, chunk_ct)
      off = off + n
    end do
    call ww%destroy()
    wire_n = size(wire_acc)

    ! Receiver -- read u32_LE prefixes, decrypt body.
    call itb_unwrap_stream_reader_new(cipher, outer_key, wire_acc(1:nlen), ur, rc)
    if (rc /= STATUS_OK) then
      err_msg = "unwrap_stream_reader_new"
      goto 999
    end if
    allocate (pt_acc(0))
    off = nlen
    total_pt = 0
    do while (off < size(wire_acc))
      ! Read 4-byte length through the unwrap-reader.
      allocate (in4(4))
      allocate (out4(4))
      in4(:) = wire_acc(off + 1 : off + 4)
      call ur%update(in4, out4, rc)
      if (rc /= STATUS_OK) then
        err_msg = "ur%update length"
        deallocate (in4, out4)
        call ur%destroy()
        goto 999
      end if
      len_xord = iand(int(out4(1)), 255)
      len_xord = ior(len_xord, ishft(iand(int(out4(2)), 255), 8))
      len_xord = ior(len_xord, ishft(iand(int(out4(3)), 255), 16))
      len_xord = ior(len_xord, ishft(iand(int(out4(4)), 255), 24))
      deallocate (in4, out4)
      off = off + 4

      allocate (ct_in(len_xord))
      allocate (ct_out(len_xord))
      ct_in(:) = wire_acc(off + 1 : off + len_xord)
      call ur%update(ct_in, ct_out, rc)
      if (rc /= STATUS_OK) then
        err_msg = "ur%update body"
        deallocate (ct_in, ct_out)
        call ur%destroy()
        goto 999
      end if
      off = off + len_xord
      block
        integer(itb_byte_kind), allocatable :: pt_chunk(:)
        pt_chunk = sib%decrypt(ct_out)
        allocate (tmp(size(pt_acc) + size(pt_chunk)))
        tmp(1:size(pt_acc)) = pt_acc(:)
        tmp(size(pt_acc) + 1 : size(pt_acc) + size(pt_chunk)) = pt_chunk(:)
        call move_alloc(tmp, pt_acc)
        total_pt = total_pt + size(pt_chunk)
        deallocate (pt_chunk)
      end block
      deallocate (ct_in, ct_out)
    end do
    call ur%destroy()

    allocate (recovered(size(pt_acc)))
    recovered(:) = pt_acc(:)
    ! Suppress unused-warning if chunk_pt, chunk_ct were the only refs
    i = total_pt
    if (i < 0) i = -i
    ok = .true.

999 continue
    if (allocated(outer_key)) deallocate (outer_key)
    if (allocated(nonce))     deallocate (nonce)
    if (allocated(wire_acc))  deallocate (wire_acc)
    if (allocated(pt_acc))    deallocate (pt_acc)
    call enc%destroy()
    call sib%destroy()
  end subroutine

  ! ----------------------------------------------------------------
  ! 4. noaead-lowlevel-userloop -- Streaming Low-Level (No MAC,
  ! User-Driven Loop). Per-chunk itb_encrypt / itb_decrypt with
  ! caller-side framing.
  ! ----------------------------------------------------------------
  subroutine run_noaead_lowlevel_userloop(cipher, plaintext, recovered, wire_n, ok, err_msg)
    integer,                                     intent(in)  :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: plaintext(:)
    integer(itb_byte_kind), allocatable, target, intent(out) :: recovered(:)
    integer,                                     intent(out) :: wire_n
    logical,                                     intent(out) :: ok
    character(*),                                intent(inout) :: err_msg
    type(itb_seed_t) :: noise, data_seed, start_seed
    integer(itb_byte_kind), allocatable, target :: outer_key(:), nonce(:)
    integer(itb_byte_kind), allocatable :: wire_acc(:), tmp(:), pt_acc(:)
    integer(itb_byte_kind), allocatable :: chunk_pt(:), chunk_ct(:)
    integer(itb_byte_kind), allocatable, target :: in4(:), out4(:)
    integer(itb_byte_kind), allocatable, target :: ct_in(:), ct_out(:)
    type(itb_wrap_stream_writer_t)   :: ww
    type(itb_unwrap_stream_reader_t) :: ur
    integer(itb_status_kind) :: rc
    integer :: off, n, plain_len, ct_len, len_xord, nlen

    ok = .false.
    wire_n = 0
    plain_len = size(plaintext)

    call itb_set_nonce_bits(128)
    call itb_set_barrier_fill(4)
    call itb_set_bit_soup(1)
    call itb_set_lock_soup(1)

    call new_itb_seed(noise,      "areion512", 1024)
    call new_itb_seed(data_seed,  "areion512", 1024)
    call new_itb_seed(start_seed, "areion512", 1024)

    call itb_wrapper_generate_key(cipher, outer_key, rc)
    if (rc /= STATUS_OK) then
      err_msg = "generate_key"
      goto 999
    end if

    call itb_wrap_stream_writer_new(cipher, outer_key, ww, nonce, rc)
    if (rc /= STATUS_OK) then
      err_msg = "wrap_stream_writer_new"
      goto 999
    end if
    nlen = size(nonce)
    allocate (wire_acc(nlen))
    wire_acc(:) = nonce(:)

    off = 0
    do while (off < plain_len)
      n = min(STREAM_CHUNK, plain_len - off)
      allocate (chunk_pt(n))
      chunk_pt(:) = plaintext(off + 1 : off + n)
      chunk_ct = itb_encrypt(noise, data_seed, start_seed, chunk_pt)
      ct_len = size(chunk_ct)

      allocate (in4(4))
      allocate (out4(4))
      in4(1) = int(iand(ct_len,           255), itb_byte_kind)
      in4(2) = int(iand(ishft(ct_len, -8),  255), itb_byte_kind)
      in4(3) = int(iand(ishft(ct_len, -16), 255), itb_byte_kind)
      in4(4) = int(iand(ishft(ct_len, -24), 255), itb_byte_kind)
      call ww%update(in4, out4, rc)
      if (rc /= STATUS_OK) then
        err_msg = "ww%update length"
        deallocate (in4, out4, chunk_pt, chunk_ct)
        call ww%destroy()
        goto 999
      end if
      allocate (tmp(size(wire_acc) + 4))
      tmp(1:size(wire_acc)) = wire_acc(:)
      tmp(size(wire_acc) + 1 : size(wire_acc) + 4) = out4(:)
      call move_alloc(tmp, wire_acc)
      deallocate (in4, out4)

      allocate (ct_in(ct_len))
      allocate (ct_out(ct_len))
      ct_in(:) = chunk_ct(:)
      call ww%update(ct_in, ct_out, rc)
      if (rc /= STATUS_OK) then
        err_msg = "ww%update body"
        deallocate (chunk_pt, chunk_ct, ct_in, ct_out)
        call ww%destroy()
        goto 999
      end if
      allocate (tmp(size(wire_acc) + ct_len))
      tmp(1:size(wire_acc)) = wire_acc(:)
      tmp(size(wire_acc) + 1 : size(wire_acc) + ct_len) = ct_out(:)
      call move_alloc(tmp, wire_acc)
      deallocate (ct_in, ct_out, chunk_pt, chunk_ct)
      off = off + n
    end do
    call ww%destroy()
    wire_n = size(wire_acc)

    call itb_unwrap_stream_reader_new(cipher, outer_key, wire_acc(1:nlen), ur, rc)
    if (rc /= STATUS_OK) then
      err_msg = "unwrap_stream_reader_new"
      goto 999
    end if
    allocate (pt_acc(0))
    off = nlen
    do while (off < size(wire_acc))
      allocate (in4(4))
      allocate (out4(4))
      in4(:) = wire_acc(off + 1 : off + 4)
      call ur%update(in4, out4, rc)
      if (rc /= STATUS_OK) then
        err_msg = "ur%update length"
        deallocate (in4, out4)
        call ur%destroy()
        goto 999
      end if
      len_xord = iand(int(out4(1)), 255)
      len_xord = ior(len_xord, ishft(iand(int(out4(2)), 255), 8))
      len_xord = ior(len_xord, ishft(iand(int(out4(3)), 255), 16))
      len_xord = ior(len_xord, ishft(iand(int(out4(4)), 255), 24))
      deallocate (in4, out4)
      off = off + 4

      allocate (ct_in(len_xord))
      allocate (ct_out(len_xord))
      ct_in(:) = wire_acc(off + 1 : off + len_xord)
      call ur%update(ct_in, ct_out, rc)
      if (rc /= STATUS_OK) then
        err_msg = "ur%update body"
        deallocate (ct_in, ct_out)
        call ur%destroy()
        goto 999
      end if
      off = off + len_xord
      block
        integer(itb_byte_kind), allocatable :: pt_chunk(:)
        pt_chunk = itb_decrypt(noise, data_seed, start_seed, ct_out)
        allocate (tmp(size(pt_acc) + size(pt_chunk)))
        tmp(1:size(pt_acc)) = pt_acc(:)
        tmp(size(pt_acc) + 1 : size(pt_acc) + size(pt_chunk)) = pt_chunk(:)
        call move_alloc(tmp, pt_acc)
        deallocate (pt_chunk)
      end block
      deallocate (ct_in, ct_out)
    end do
    call ur%destroy()

    allocate (recovered(size(pt_acc)))
    recovered(:) = pt_acc(:)
    ok = .true.

999 continue
    if (allocated(outer_key)) deallocate (outer_key)
    if (allocated(nonce))     deallocate (nonce)
    if (allocated(wire_acc))  deallocate (wire_acc)
    if (allocated(pt_acc))    deallocate (pt_acc)
    call noise%destroy(); call data_seed%destroy(); call start_seed%destroy()
  end subroutine

  ! ----------------------------------------------------------------
  ! 5. message-easy-nomac -- Easy Single Message, No MAC.
  ! Default: itb_wrap_in_place + itb_unwrap_in_place (zero allocation).
  ! Immutable alternative: itb_wrap + itb_unwrap (commented).
  ! ----------------------------------------------------------------
  subroutine run_message_easy_nomac(cipher, plaintext, recovered, wire_n, ok, err_msg)
    integer,                                     intent(in)  :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: plaintext(:)
    integer(itb_byte_kind), allocatable, target, intent(out) :: recovered(:)
    integer,                                     intent(out) :: wire_n
    logical,                                     intent(out) :: ok
    character(*),                                intent(inout) :: err_msg
    type(itb_encryptor_t) :: enc, sib
    integer(itb_byte_kind), allocatable, target :: outer_key(:)
    integer(itb_byte_kind), allocatable, target :: encrypted(:), wire(:), nonce(:)
    integer :: nlen, body_first, enc_len
    integer(itb_status_kind) :: rc

    ok = .false.
    wire_n = 0

    call make_easy_encryptor(.false., 2048, enc)
    block
      integer(itb_byte_kind), allocatable :: blob(:)
      blob = enc%export_state()
      call new_itb_encryptor(sib, "areion512", 2048, "", 1)
      call sib%import_state(blob)
    end block

    encrypted = enc%encrypt(plaintext)
    enc_len = size(encrypted)

    call itb_wrapper_generate_key(cipher, outer_key, rc)
    if (rc /= STATUS_OK) then
      err_msg = "generate_key"
      goto 999
    end if

    ! Default -- in-place mutation. The blob is XORed in place; nonce
    ! is returned in a separately-allocated buffer.
    !
    ! Immutable alternative -- itb_wrap allocates a fresh wire buffer:
    !   call itb_wrap(cipher, outer_key, encrypted, wire, rc)
    !   if (rc /= STATUS_OK) ...
    call itb_wrap_in_place(cipher, outer_key, encrypted, nonce, rc)
    if (rc /= STATUS_OK) then
      err_msg = "wrap_in_place"
      goto 999
    end if
    nlen = size(nonce)
    allocate (wire(nlen + enc_len))
    wire(1:nlen) = nonce(:)
    wire(nlen + 1 : nlen + enc_len) = encrypted(:)
    wire_n = size(wire)

    ! Default -- in-place unwrap. wire is mutated; body_first marks
    ! the first decrypted-payload byte.
    !
    ! Immutable alternative -- itb_unwrap allocates a fresh recovered buffer:
    !   call itb_unwrap(cipher, outer_key, wire, recovered_blob, rc)
    !   if (rc /= STATUS_OK) ...
    call itb_unwrap_in_place(cipher, outer_key, wire, body_first, rc)
    if (rc /= STATUS_OK) then
      err_msg = "unwrap_in_place"
      goto 999
    end if
    block
      integer(itb_byte_kind), allocatable :: pt(:)
      pt = sib%decrypt(wire(body_first : size(wire)))
      allocate (recovered(size(pt)))
      recovered(:) = pt(:)
      deallocate (pt)
    end block
    ok = .true.

999 continue
    if (allocated(outer_key))  deallocate (outer_key)
    if (allocated(encrypted))  deallocate (encrypted)
    if (allocated(wire))       deallocate (wire)
    if (allocated(nonce))      deallocate (nonce)
    call enc%destroy()
    call sib%destroy()
  end subroutine

  ! ----------------------------------------------------------------
  ! 6. message-easy-auth -- Easy Single Message, MAC Authenticated.
  ! ----------------------------------------------------------------
  subroutine run_message_easy_auth(cipher, plaintext, recovered, wire_n, ok, err_msg)
    integer,                                     intent(in)  :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: plaintext(:)
    integer(itb_byte_kind), allocatable, target, intent(out) :: recovered(:)
    integer,                                     intent(out) :: wire_n
    logical,                                     intent(out) :: ok
    character(*),                                intent(inout) :: err_msg
    type(itb_encryptor_t) :: enc, sib
    integer(itb_byte_kind), allocatable, target :: outer_key(:)
    integer(itb_byte_kind), allocatable, target :: encrypted(:), wire(:), nonce(:)
    integer :: nlen, body_first, enc_len
    integer(itb_status_kind) :: rc

    ok = .false.
    wire_n = 0

    call make_easy_encryptor(.true., 2048, enc)
    block
      integer(itb_byte_kind), allocatable :: blob(:)
      blob = enc%export_state()
      call new_itb_encryptor(sib, "areion512", 2048, "hmac-blake3", 1)
      call sib%import_state(blob)
    end block

    encrypted = enc%encrypt_auth(plaintext)
    enc_len = size(encrypted)

    call itb_wrapper_generate_key(cipher, outer_key, rc)
    if (rc /= STATUS_OK) then
      err_msg = "generate_key"
      goto 999
    end if

    ! See message-easy-nomac for the immutable-input alternative
    ! (itb_wrap / itb_unwrap allocate fresh buffers at the cost of one
    ! extra malloc per call).
    call itb_wrap_in_place(cipher, outer_key, encrypted, nonce, rc)
    if (rc /= STATUS_OK) then
      err_msg = "wrap_in_place"
      goto 999
    end if
    nlen = size(nonce)
    allocate (wire(nlen + enc_len))
    wire(1:nlen) = nonce(:)
    wire(nlen + 1 : nlen + enc_len) = encrypted(:)
    wire_n = size(wire)

    call itb_unwrap_in_place(cipher, outer_key, wire, body_first, rc)
    if (rc /= STATUS_OK) then
      err_msg = "unwrap_in_place"
      goto 999
    end if
    block
      integer(itb_byte_kind), allocatable :: pt(:)
      pt = sib%decrypt_auth(wire(body_first : size(wire)))
      allocate (recovered(size(pt)))
      recovered(:) = pt(:)
      deallocate (pt)
    end block
    ok = .true.

999 continue
    if (allocated(outer_key))  deallocate (outer_key)
    if (allocated(encrypted))  deallocate (encrypted)
    if (allocated(wire))       deallocate (wire)
    if (allocated(nonce))      deallocate (nonce)
    call enc%destroy()
    call sib%destroy()
  end subroutine

  ! ----------------------------------------------------------------
  ! 7. message-lowlevel-nomac -- Low-Level Single Message, No MAC.
  ! Three explicit Areion-SoEM-512 seeds.
  ! ----------------------------------------------------------------
  subroutine run_message_lowlevel_nomac(cipher, plaintext, recovered, wire_n, ok, err_msg)
    integer,                                     intent(in)  :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: plaintext(:)
    integer(itb_byte_kind), allocatable, target, intent(out) :: recovered(:)
    integer,                                     intent(out) :: wire_n
    logical,                                     intent(out) :: ok
    character(*),                                intent(inout) :: err_msg
    type(itb_seed_t) :: noise, data_seed, start_seed
    integer(itb_byte_kind), allocatable, target :: outer_key(:)
    integer(itb_byte_kind), allocatable, target :: encrypted(:), wire(:), nonce(:)
    integer :: nlen, body_first, enc_len
    integer(itb_status_kind) :: rc

    ok = .false.
    wire_n = 0

    call itb_set_nonce_bits(128)
    call itb_set_barrier_fill(4)
    call itb_set_bit_soup(1)
    call itb_set_lock_soup(1)

    call new_itb_seed(noise,      "areion512", 2048)
    call new_itb_seed(data_seed,  "areion512", 2048)
    call new_itb_seed(start_seed, "areion512", 2048)

    encrypted = itb_encrypt(noise, data_seed, start_seed, plaintext)
    enc_len = size(encrypted)

    call itb_wrapper_generate_key(cipher, outer_key, rc)
    if (rc /= STATUS_OK) then
      err_msg = "generate_key"
      goto 999
    end if

    ! See message-easy-nomac for the immutable-input alternative.
    call itb_wrap_in_place(cipher, outer_key, encrypted, nonce, rc)
    if (rc /= STATUS_OK) then
      err_msg = "wrap_in_place"
      goto 999
    end if
    nlen = size(nonce)
    allocate (wire(nlen + enc_len))
    wire(1:nlen) = nonce(:)
    wire(nlen + 1 : nlen + enc_len) = encrypted(:)
    wire_n = size(wire)

    call itb_unwrap_in_place(cipher, outer_key, wire, body_first, rc)
    if (rc /= STATUS_OK) then
      err_msg = "unwrap_in_place"
      goto 999
    end if
    block
      integer(itb_byte_kind), allocatable :: pt(:)
      pt = itb_decrypt(noise, data_seed, start_seed, wire(body_first : size(wire)))
      allocate (recovered(size(pt)))
      recovered(:) = pt(:)
      deallocate (pt)
    end block
    ok = .true.

999 continue
    if (allocated(outer_key))  deallocate (outer_key)
    if (allocated(encrypted))  deallocate (encrypted)
    if (allocated(wire))       deallocate (wire)
    if (allocated(nonce))      deallocate (nonce)
    call noise%destroy(); call data_seed%destroy(); call start_seed%destroy()
  end subroutine

  ! ----------------------------------------------------------------
  ! 8. message-lowlevel-auth -- Low-Level Single Message, MAC Authenticated.
  ! ----------------------------------------------------------------
  subroutine run_message_lowlevel_auth(cipher, plaintext, recovered, wire_n, ok, err_msg)
    integer,                                     intent(in)  :: cipher
    integer(itb_byte_kind), target,    contiguous, intent(in)  :: plaintext(:)
    integer(itb_byte_kind), allocatable, target, intent(out) :: recovered(:)
    integer,                                     intent(out) :: wire_n
    logical,                                     intent(out) :: ok
    character(*),                                intent(inout) :: err_msg
    type(itb_seed_t) :: noise, data_seed, start_seed
    type(itb_mac_t)  :: mac
    integer(itb_byte_kind), allocatable, target :: outer_key(:)
    integer(itb_byte_kind), allocatable, target :: encrypted(:), wire(:), nonce(:)
    integer(itb_byte_kind), allocatable :: mac_key_alloc(:)
    integer(itb_byte_kind), target :: mac_key(32)
    integer :: nlen, body_first, enc_len
    integer(itb_status_kind) :: rc

    ok = .false.
    wire_n = 0

    call itb_set_nonce_bits(128)
    call itb_set_barrier_fill(4)
    call itb_set_bit_soup(1)
    call itb_set_lock_soup(1)

    call new_itb_seed(noise,      "areion512", 2048)
    call new_itb_seed(data_seed,  "areion512", 2048)
    call new_itb_seed(start_seed, "areion512", 2048)
    call csprng_into_buf(mac_key, 32, rc)
    if (rc /= STATUS_OK) then
      err_msg = "csprng mac_key"
      goto 999
    end if
    allocate (mac_key_alloc(32))
    mac_key_alloc(:) = mac_key(:)
    call new_itb_mac(mac, "hmac-blake3", mac_key_alloc)

    encrypted = itb_encrypt_auth(noise, data_seed, start_seed, mac, plaintext)
    enc_len = size(encrypted)

    call itb_wrapper_generate_key(cipher, outer_key, rc)
    if (rc /= STATUS_OK) then
      err_msg = "generate_key"
      goto 999
    end if

    ! See message-easy-nomac for the immutable-input alternative.
    call itb_wrap_in_place(cipher, outer_key, encrypted, nonce, rc)
    if (rc /= STATUS_OK) then
      err_msg = "wrap_in_place"
      goto 999
    end if
    nlen = size(nonce)
    allocate (wire(nlen + enc_len))
    wire(1:nlen) = nonce(:)
    wire(nlen + 1 : nlen + enc_len) = encrypted(:)
    wire_n = size(wire)

    call itb_unwrap_in_place(cipher, outer_key, wire, body_first, rc)
    if (rc /= STATUS_OK) then
      err_msg = "unwrap_in_place"
      goto 999
    end if
    block
      integer(itb_byte_kind), allocatable :: pt(:)
      pt = itb_decrypt_auth(noise, data_seed, start_seed, mac,                  &
                              wire(body_first : size(wire)))
      allocate (recovered(size(pt)))
      recovered(:) = pt(:)
      deallocate (pt)
    end block
    ok = .true.

999 continue
    if (allocated(outer_key))     deallocate (outer_key)
    if (allocated(encrypted))     deallocate (encrypted)
    if (allocated(wire))          deallocate (wire)
    if (allocated(nonce))         deallocate (nonce)
    if (allocated(mac_key_alloc)) deallocate (mac_key_alloc)
    call mac%destroy()
    call noise%destroy(); call data_seed%destroy(); call start_seed%destroy()
  end subroutine

  ! ----------------------------------------------------------------
  ! Fixed-buffer CSPRNG read for MAC keys.
  ! ----------------------------------------------------------------
  subroutine csprng_into_buf(out, n, status)
    integer(itb_byte_kind), target, intent(out) :: out(:)
    integer,                        intent(in)  :: n
    integer(itb_status_kind),       intent(out) :: status
    integer :: u, ios
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

end program eitb
