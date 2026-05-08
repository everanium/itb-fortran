! test_streams_auth.f90 -- Streaming AEAD round-trip + tamper detection
! over the seed-based itb_stream_encrypt_auth / itb_stream_decrypt_auth
! free-function surface (Single + Triple Ouroboros).
!
! Mirrors bindings/c/tests/test_streams_auth.c on the Fortran surface.
! Per coverage class enumerated by the Streaming AEAD design surface:
!
!   * Round-trip across (chunk_size x Single / Triple x MAC primitive)
!   * Empty stream + single-chunk + chunk_size = 1
!   * Reorder of two chunks               -> STATUS_MAC_FAILURE
!   * Truncate-tail (drop last chunk)     -> STATUS_STREAM_TRUNCATED
!   * Cross-stream splice                  -> STATUS_MAC_FAILURE
!   * Stream-prefix tamper (flip 1 byte)   -> STATUS_MAC_FAILURE
!   * chunk_size = 0 rejected via STATUS_BAD_INPUT

module test_streams_auth_mod
  use, intrinsic :: iso_c_binding
  use itb_kinds
  implicit none
  public

  type, bind(C) :: src_t
    integer(c_size_t) :: total = 0
    integer(c_size_t) :: pos   = 0
    integer(c_size_t) :: rcap  = 0
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
    if (s%rcap > 0 .and. take > s%rcap) take = s%rcap
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

end module test_streams_auth_mod

program test_streams_auth
  use, intrinsic :: iso_c_binding
  use itb_kinds
  use itb_seed
  use itb_mac
  use itb_streams
  use itb_errors
  use itb_sys, only: itb_header_size_c, itb_parse_chunk_len_c
  use test_streams_auth_mod
  use itb_test_helpers
  implicit none

  character(*), parameter :: TEST_NAME = "test_streams_auth"
  integer(itb_size_kind), parameter :: SMALL_CHUNK = 4096_itb_size_kind

  call test_chunk_size_zero_rejected()
  call test_single_auth_roundtrip_kmac256()
  call test_single_auth_roundtrip_hmac_blake3()
  call test_single_auth_roundtrip_hmac_sha256()
  call test_single_auth_empty_stream()
  call test_single_auth_chunk_size_1()
  call test_single_auth_single_chunk()
  call test_triple_auth_roundtrip()
  call test_auth_reorder_two_chunks()
  call test_auth_truncate_tail()
  call test_auth_stream_prefix_tamper()
  call test_auth_stream_after_final()
  call test_auth_cross_stream_replay()

  call test_pass(TEST_NAME)

contains

  function pseudo_payload(n) result(p)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    integer(c_int64_t) :: v
    allocate (p(max(n, 1)))
    do i = 1, n
      v = iand(int(i - 1, c_int64_t) * 13_c_int64_t + 11_c_int64_t,      &
                255_c_int64_t)
      if (v >= 128_c_int64_t) then
        p(i) = int(v - 256_c_int64_t, itb_byte_kind)
      else
        p(i) = int(v, itb_byte_kind)
      end if
    end do
  end function

  ! Allocates a 32-byte deterministic key for the test harness so that
  ! a separate decrypt-side encryptor can be built under the same key
  ! for cross-stream tamper-test surgery.
  subroutine make_key(key)
    integer(itb_byte_kind), intent(out) :: key(32)
    integer(c_int64_t) :: v
    integer :: i
    do i = 1, 32
      v = iand(int(i - 1, c_int64_t) * 17_c_int64_t + 5_c_int64_t,       &
                255_c_int64_t)
      ! Re-anchor sign-bit values into int8's signed range so the
      ! literal narrowing does not trip -fno-range-check.
      if (v >= 128_c_int64_t) then
        key(i) = int(v - 256_c_int64_t, itb_byte_kind)
      else
        key(i) = int(v, itb_byte_kind)
      end if
    end do
  end subroutine

  ! Encrypts `plaintext` to a fresh ciphertext buffer using the
  ! Single-Ouroboros auth-stream surface; returns ciphertext + length.
  subroutine encrypt_single(ns, ds, ss, mac, plaintext, chunk_size,    &
                              ct_buf, ct_len)
    type(itb_seed_t), intent(in) :: ns, ds, ss
    type(itb_mac_t),  intent(in) :: mac
    integer(itb_byte_kind), target, intent(in) :: plaintext(:)
    integer(itb_size_kind), intent(in) :: chunk_size
    integer(itb_byte_kind), target, allocatable, intent(out) :: ct_buf(:)
    integer(itb_size_kind), intent(out) :: ct_len
    type(src_t),  target :: src_pt
    type(sink_t), target :: sink_ct
    integer(itb_size_kind) :: ct_cap
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_status_kind) :: status

    rfn => src_read
    wfn => sink_write

    ct_cap = int(size(plaintext), itb_size_kind) * 4_itb_size_kind +    &
              262144_itb_size_kind
    allocate (ct_buf(ct_cap))

    src_pt%total = int(size(plaintext), c_size_t)
    src_pt%pos = 0
    src_pt%rcap = 0
    src_pt%data = c_loc(plaintext)
    sink_ct%cap = ct_cap
    sink_ct%pos = 0
    sink_ct%data = c_loc(ct_buf)

    call itb_stream_encrypt_auth(ns, ds, ss, mac,                        &
                                   rfn, c_loc(src_pt),                    &
                                   wfn, c_loc(sink_ct),                    &
                                   chunk_size, status)
    call assert_status_ok(TEST_NAME, "stream_encrypt_auth", status)
    ct_len = sink_ct%pos
  end subroutine

  ! Drives the Single-Ouroboros auth-stream decrypt surface against a
  ! caller-supplied truncated / tampered ciphertext window and returns
  ! the resulting status code without asserting on it (caller owns the
  ! status assertion).
  subroutine decrypt_single_status(ns, ds, ss, mac, ct_buf, ct_len,    &
                                      chunk_size, status_out)
    type(itb_seed_t), intent(in) :: ns, ds, ss
    type(itb_mac_t),  intent(in) :: mac
    integer(itb_byte_kind), target, intent(in) :: ct_buf(:)
    integer(itb_size_kind), intent(in) :: ct_len, chunk_size
    integer(itb_status_kind), intent(out) :: status_out
    type(src_t),  target :: src_ct
    type(sink_t), target :: sink_pt
    integer(itb_byte_kind), target, allocatable :: pt_buf(:)
    integer(itb_size_kind) :: pt_cap
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()

    rfn => src_read
    wfn => sink_write

    pt_cap = int(size(ct_buf), itb_size_kind) + 1024_itb_size_kind
    allocate (pt_buf(pt_cap))

    src_ct%total = ct_len
    src_ct%pos = 0
    src_ct%rcap = 0
    src_ct%data = c_loc(ct_buf)
    sink_pt%cap = pt_cap
    sink_pt%pos = 0
    sink_pt%data = c_loc(pt_buf)

    call itb_stream_decrypt_auth(ns, ds, ss, mac,                        &
                                   rfn, c_loc(src_ct),                    &
                                   wfn, c_loc(sink_pt),                    &
                                   chunk_size, status_out)
  end subroutine

  ! Round-trip a single-Ouroboros plaintext through encrypt + decrypt
  ! under the supplied MAC primitive name. Both sides share the same
  ! deterministic key so a paired encryptor/decryptor materialises
  ! reliably.
  subroutine roundtrip_single(plaintext, chunk_size, mac_name)
    integer(itb_byte_kind), target, intent(in) :: plaintext(:)
    integer(itb_size_kind), intent(in) :: chunk_size
    character(*), intent(in) :: mac_name
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: mac
    integer(itb_byte_kind), target, allocatable :: ct_buf(:)
    integer(itb_byte_kind), target, allocatable :: pt_buf(:)
    integer(itb_byte_kind), allocatable :: pt_recovered(:)
    integer(itb_byte_kind), target :: key(32)
    type(src_t),  target :: src_ct
    type(sink_t), target :: sink_pt
    integer(itb_size_kind) :: ct_len, pt_cap
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_status_kind) :: status
    integer :: i

    rfn => src_read
    wfn => sink_write
    call make_key(key)

    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_mac(mac, mac_name, key)

    call encrypt_single(ns, ds, ss, mac, plaintext, chunk_size,         &
                          ct_buf, ct_len)
    call assert_true(TEST_NAME, "auth ct over 32 bytes",                 &
                       ct_len > 32_c_size_t)

    pt_cap = int(size(plaintext), itb_size_kind) + 1024_itb_size_kind
    allocate (pt_buf(pt_cap))
    src_ct%total = ct_len; src_ct%pos = 0; src_ct%rcap = 0
    src_ct%data = c_loc(ct_buf)
    sink_pt%cap = pt_cap; sink_pt%pos = 0; sink_pt%data = c_loc(pt_buf)
    call itb_stream_decrypt_auth(ns, ds, ss, mac,                        &
                                   rfn, c_loc(src_ct),                    &
                                   wfn, c_loc(sink_pt),                    &
                                   chunk_size, status)
    call assert_status_ok(TEST_NAME, "stream_decrypt_auth", status)
    call assert_size_eq(TEST_NAME, "auth recovered length", sink_pt%pos, &
                         int(size(plaintext), itb_size_kind))
    allocate (pt_recovered(int(sink_pt%pos)))
    do i = 1, int(sink_pt%pos)
      pt_recovered(i) = pt_buf(i)
    end do
    call assert_bytes_eq(TEST_NAME, "auth single roundtrip",              &
                          pt_recovered, plaintext)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call mac%destroy()
  end subroutine

  ! Triple counterpart of `roundtrip_single`.
  subroutine roundtrip_triple(plaintext, chunk_size)
    integer(itb_byte_kind), target, intent(in) :: plaintext(:)
    integer(itb_size_kind), intent(in) :: chunk_size
    type(itb_seed_t) :: ns, d1, d2, d3, st1, st2, st3
    type(itb_mac_t)  :: mac
    type(src_t),  target :: src_pt, src_ct
    type(sink_t), target :: sink_ct, sink_pt
    integer(itb_byte_kind), target, allocatable :: ct_buf(:)
    integer(itb_byte_kind), target, allocatable :: pt_buf(:)
    integer(itb_byte_kind), allocatable :: pt_recovered(:)
    integer(itb_byte_kind), target :: key(32)
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_size_kind) :: ct_cap, pt_cap
    integer(itb_status_kind) :: status
    integer :: i

    rfn => src_read
    wfn => sink_write
    call make_key(key)

    call new_itb_seed(ns,  "blake3", 1024)
    call new_itb_seed(d1,  "blake3", 1024)
    call new_itb_seed(d2,  "blake3", 1024)
    call new_itb_seed(d3,  "blake3", 1024)
    call new_itb_seed(st1, "blake3", 1024)
    call new_itb_seed(st2, "blake3", 1024)
    call new_itb_seed(st3, "blake3", 1024)
    call new_itb_mac(mac, "hmac-blake3", key)

    ct_cap = int(size(plaintext), itb_size_kind) * 6_itb_size_kind +    &
              262144_itb_size_kind
    pt_cap = int(size(plaintext), itb_size_kind) + 1024_itb_size_kind
    allocate (ct_buf(ct_cap))
    allocate (pt_buf(pt_cap))

    src_pt%total = int(size(plaintext), c_size_t); src_pt%pos = 0
    src_pt%rcap = 0; src_pt%data = c_loc(plaintext)
    sink_ct%cap = ct_cap; sink_ct%pos = 0; sink_ct%data = c_loc(ct_buf)
    call itb_stream_encrypt_auth_triple(ns, d1, d2, d3, st1, st2, st3,   &
                                          mac,                            &
                                          rfn, c_loc(src_pt),              &
                                          wfn, c_loc(sink_ct),              &
                                          chunk_size, status)
    call assert_status_ok(TEST_NAME, "stream_encrypt_auth_triple", status)

    src_ct%total = sink_ct%pos; src_ct%pos = 0; src_ct%rcap = 0
    src_ct%data = c_loc(ct_buf)
    sink_pt%cap = pt_cap; sink_pt%pos = 0; sink_pt%data = c_loc(pt_buf)
    call itb_stream_decrypt_auth_triple(ns, d1, d2, d3, st1, st2, st3,   &
                                          mac,                            &
                                          rfn, c_loc(src_ct),              &
                                          wfn, c_loc(sink_pt),              &
                                          chunk_size, status)
    call assert_status_ok(TEST_NAME, "stream_decrypt_auth_triple", status)
    call assert_size_eq(TEST_NAME, "auth triple recovered length",       &
                         sink_pt%pos, int(size(plaintext), itb_size_kind))
    allocate (pt_recovered(int(sink_pt%pos)))
    do i = 1, int(sink_pt%pos)
      pt_recovered(i) = pt_buf(i)
    end do
    call assert_bytes_eq(TEST_NAME, "auth triple roundtrip",              &
                          pt_recovered, plaintext)

    call ns%destroy()
    call d1%destroy();  call d2%destroy();  call d3%destroy()
    call st1%destroy(); call st2%destroy(); call st3%destroy()
    call mac%destroy()
  end subroutine

  subroutine test_chunk_size_zero_rejected()
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: mac
    type(src_t),  target :: src
    type(sink_t), target :: snk
    integer(itb_byte_kind), target :: dummy(1), key(32)
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_status_kind) :: status

    rfn => src_read
    wfn => sink_write
    call make_key(key)

    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_mac(mac, "hmac-blake3", key)

    src%total = 0; src%pos = 0; src%rcap = 0; src%data = c_loc(dummy)
    snk%cap = 0;   snk%pos = 0;               snk%data = c_loc(dummy)

    call itb_stream_encrypt_auth(ns, ds, ss, mac,                        &
                                   rfn, c_loc(src), wfn, c_loc(snk),     &
                                   0_itb_size_kind, status)
    call assert_status_eq(TEST_NAME, "auth encrypt chunk_size=0 rejected",&
                           status, STATUS_BAD_INPUT)
    call itb_stream_decrypt_auth(ns, ds, ss, mac,                        &
                                   rfn, c_loc(src), wfn, c_loc(snk),     &
                                   0_itb_size_kind, status)
    call assert_status_eq(TEST_NAME, "auth decrypt chunk_size=0 rejected",&
                           status, STATUS_BAD_INPUT)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call mac%destroy()
  end subroutine

  subroutine test_single_auth_roundtrip_kmac256()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    plaintext = pseudo_payload(int(SMALL_CHUNK) * 4 + 11)
    call roundtrip_single(plaintext, SMALL_CHUNK, "kmac256")
  end subroutine

  subroutine test_single_auth_roundtrip_hmac_blake3()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    plaintext = pseudo_payload(int(SMALL_CHUNK) * 3 + 7)
    call roundtrip_single(plaintext, SMALL_CHUNK, "hmac-blake3")
  end subroutine

  subroutine test_single_auth_roundtrip_hmac_sha256()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    character(*), parameter :: PT_TEXT = "auth stream short payload coverage"
    integer :: i
    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do
    call roundtrip_single(plaintext, SMALL_CHUNK, "hmac-sha256")
  end subroutine

  subroutine test_single_auth_empty_stream()
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: mac
    type(src_t),  target :: src_pt, src_ct
    type(sink_t), target :: sink_ct, sink_pt
    integer(itb_byte_kind), target, allocatable :: ct_buf(:), pt_buf(:)
    integer(itb_byte_kind), target :: dummy(1), key(32)
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_size_kind) :: ct_cap, pt_cap
    integer(itb_status_kind) :: status

    rfn => src_read
    wfn => sink_write
    call make_key(key)

    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_mac(mac, "hmac-blake3", key)

    ct_cap = 65536_itb_size_kind
    pt_cap = 1024_itb_size_kind
    allocate (ct_buf(ct_cap))
    allocate (pt_buf(pt_cap))

    src_pt%total = 0; src_pt%pos = 0; src_pt%rcap = 0
    src_pt%data = c_loc(dummy)
    sink_ct%cap = ct_cap; sink_ct%pos = 0; sink_ct%data = c_loc(ct_buf)
    call itb_stream_encrypt_auth(ns, ds, ss, mac,                        &
                                   rfn, c_loc(src_pt),                    &
                                   wfn, c_loc(sink_ct),                    &
                                   SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "empty encrypt", status)
    call assert_true(TEST_NAME, "empty stream emits prefix + chunk",     &
                       sink_ct%pos > 32_c_size_t)

    src_ct%total = sink_ct%pos; src_ct%pos = 0; src_ct%rcap = 0
    src_ct%data = c_loc(ct_buf)
    sink_pt%cap = pt_cap; sink_pt%pos = 0; sink_pt%data = c_loc(pt_buf)
    call itb_stream_decrypt_auth(ns, ds, ss, mac,                        &
                                   rfn, c_loc(src_ct),                    &
                                   wfn, c_loc(sink_pt),                    &
                                   SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "empty decrypt", status)
    call assert_size_eq(TEST_NAME, "empty recovered length",             &
                         sink_pt%pos, 0_itb_size_kind)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call mac%destroy()
  end subroutine

  subroutine test_single_auth_chunk_size_1()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    plaintext = pseudo_payload(7)
    call roundtrip_single(plaintext, 1_itb_size_kind, "hmac-blake3")
  end subroutine

  subroutine test_single_auth_single_chunk()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    plaintext = pseudo_payload(200)
    call roundtrip_single(plaintext, SMALL_CHUNK, "hmac-blake3")
  end subroutine

  subroutine test_triple_auth_roundtrip()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    plaintext = pseudo_payload(int(SMALL_CHUNK) * 3 + 19)
    call roundtrip_triple(plaintext, SMALL_CHUNK)
  end subroutine

  ! Builds a 3-chunk transcript (2 full + 1 short tail). Returns the
  ! wire bytes plus per-chunk byte offsets into the wire array (chunk
  ! 0 starts at offset 32, after the 32-byte stream_id prefix).
  subroutine build_three_chunk_wire(ns, ds, ss, mac, ct_buf, ct_len,    &
                                       offsets, lens)
    type(itb_seed_t), intent(in) :: ns, ds, ss
    type(itb_mac_t),  intent(in) :: mac
    integer(itb_byte_kind), target, allocatable, intent(out) :: ct_buf(:)
    integer(itb_size_kind), intent(out) :: ct_len
    integer(itb_size_kind), intent(out) :: offsets(3), lens(3)
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_size_kind) :: header_size, cur, cl
    integer(itb_byte_kind), allocatable, target :: hdr(:)
    integer(itb_status_kind) :: rc
    integer(c_int) :: hsz_int
    integer :: i, k

    plaintext = pseudo_payload(int(SMALL_CHUNK) * 3 - 7)
    call encrypt_single(ns, ds, ss, mac, plaintext, SMALL_CHUNK,        &
                          ct_buf, ct_len)

    hsz_int = itb_header_size_c()
    call assert_true(TEST_NAME, "header_size positive", hsz_int > 0)
    header_size = int(hsz_int, itb_size_kind)
    allocate (hdr(int(header_size)))

    cur = 32_itb_size_kind
    do k = 1, 3
      offsets(k) = cur
      do i = 1, int(header_size)
        hdr(i) = ct_buf(int(cur) + i)
      end do
      cl = 0_itb_size_kind
      rc = itb_parse_chunk_len_c(c_loc(hdr), header_size, cl)
      call assert_status_ok(TEST_NAME, "parse_chunk_len", rc)
      lens(k) = cl
      cur = cur + cl
    end do
    call assert_size_eq(TEST_NAME, "wire walk consumes all bytes",       &
                         cur, ct_len)
  end subroutine

  subroutine test_auth_reorder_two_chunks()
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: mac
    integer(itb_byte_kind), target, allocatable :: ct_buf(:)
    integer(itb_byte_kind), target, allocatable :: tmp(:)
    integer(itb_byte_kind), target :: key(32)
    integer(itb_size_kind) :: ct_len, offsets(3), lens(3)
    integer(itb_status_kind) :: status
    integer :: i

    call make_key(key)
    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_mac(mac, "hmac-blake3", key)

    call build_three_chunk_wire(ns, ds, ss, mac, ct_buf, ct_len,        &
                                  offsets, lens)
    call assert_size_eq(TEST_NAME, "chunks 0/1 same length",              &
                         lens(1), lens(2))

    ! Swap chunks 0 and 1 in place.
    allocate (tmp(int(lens(1))))
    do i = 1, int(lens(1))
      tmp(i) = ct_buf(int(offsets(1)) + i)
    end do
    do i = 1, int(lens(2))
      ct_buf(int(offsets(1)) + i) = ct_buf(int(offsets(2)) + i)
    end do
    do i = 1, int(lens(1))
      ct_buf(int(offsets(2)) + i) = tmp(i)
    end do

    call decrypt_single_status(ns, ds, ss, mac, ct_buf, ct_len,         &
                                 SMALL_CHUNK, status)
    call assert_status_eq(TEST_NAME, "reorder -> MAC failure", status,  &
                           STATUS_MAC_FAILURE)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call mac%destroy()
  end subroutine

  subroutine test_auth_truncate_tail()
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: mac
    integer(itb_byte_kind), target, allocatable :: ct_buf(:)
    integer(itb_byte_kind), target :: key(32)
    integer(itb_size_kind) :: ct_len, offsets(3), lens(3), truncated_len
    integer(itb_status_kind) :: status

    call make_key(key)
    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_mac(mac, "hmac-blake3", key)

    call build_three_chunk_wire(ns, ds, ss, mac, ct_buf, ct_len,        &
                                  offsets, lens)
    truncated_len = offsets(3)

    call decrypt_single_status(ns, ds, ss, mac, ct_buf, truncated_len,  &
                                 SMALL_CHUNK, status)
    call assert_status_eq(TEST_NAME, "truncate -> STREAM_TRUNCATED",     &
                           status, STATUS_STREAM_TRUNCATED)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call mac%destroy()
  end subroutine

  subroutine test_auth_stream_prefix_tamper()
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: mac
    integer(itb_byte_kind), target, allocatable :: ct_buf(:)
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target :: key(32)
    integer(itb_size_kind) :: ct_len
    integer(itb_status_kind) :: status

    call make_key(key)
    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_mac(mac, "hmac-blake3", key)

    plaintext = pseudo_payload(int(SMALL_CHUNK) + 5)
    call encrypt_single(ns, ds, ss, mac, plaintext, SMALL_CHUNK,        &
                          ct_buf, ct_len)
    ! Flip a byte inside the 32-byte stream_id prefix.
    ct_buf(6) = ieor(ct_buf(6), int(z'55', itb_byte_kind))

    call decrypt_single_status(ns, ds, ss, mac, ct_buf, ct_len,         &
                                 SMALL_CHUNK, status)
    call assert_status_eq(TEST_NAME, "prefix tamper -> MAC failure",     &
                           status, STATUS_MAC_FAILURE)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call mac%destroy()
  end subroutine

  subroutine test_auth_cross_stream_replay()
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: mac
    integer(itb_byte_kind), target, allocatable :: pt_a(:), pt_b(:)
    integer(itb_byte_kind), target, allocatable :: ct_a(:), ct_b(:)
    integer(itb_byte_kind), allocatable, target :: hdr(:)
    integer(itb_byte_kind), target :: key(32)
    integer(itb_size_kind) :: ct_a_len, ct_b_len, header_size, cl_a, cl_b
    integer(itb_status_kind) :: status, rc
    integer(c_int) :: hsz_int
    integer :: i

    call make_key(key)
    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_mac(mac, "hmac-blake3", key)

    pt_a = pseudo_payload(int(SMALL_CHUNK) * 2 + 3)
    allocate (pt_b(size(pt_a)))
    do i = 1, size(pt_a)
      pt_b(i) = ieor(pt_a(i), int(z'AA', itb_byte_kind))
    end do

    call encrypt_single(ns, ds, ss, mac, pt_a, SMALL_CHUNK, ct_a, ct_a_len)
    call encrypt_single(ns, ds, ss, mac, pt_b, SMALL_CHUNK, ct_b, ct_b_len)

    hsz_int = itb_header_size_c()
    header_size = int(hsz_int, itb_size_kind)
    allocate (hdr(int(header_size)))
    do i = 1, int(header_size)
      hdr(i) = ct_a(32 + i)
    end do
    cl_a = 0_itb_size_kind
    rc = itb_parse_chunk_len_c(c_loc(hdr), header_size, cl_a)
    call assert_status_ok(TEST_NAME, "parse_chunk_len A0", rc)
    do i = 1, int(header_size)
      hdr(i) = ct_b(32 + i)
    end do
    cl_b = 0_itb_size_kind
    rc = itb_parse_chunk_len_c(c_loc(hdr), header_size, cl_b)
    call assert_status_ok(TEST_NAME, "parse_chunk_len B0", rc)
    call assert_size_eq(TEST_NAME, "chunk-0 lengths match",              &
                         cl_a, cl_b)

    ! Splice A's chunk-0 into B's chunk-0 slot.
    do i = 1, int(cl_a)
      ct_b(32 + i) = ct_a(32 + i)
    end do

    call decrypt_single_status(ns, ds, ss, mac, ct_b, ct_b_len,         &
                                 SMALL_CHUNK, status)
    call assert_status_eq(TEST_NAME, "cross-stream splice -> MAC fail", &
                           status, STATUS_MAC_FAILURE)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call mac%destroy()
  end subroutine

  ! Builds a 2-chunk transcript (1 full + 1 short tail). Returns the
  ! wire bytes plus per-chunk byte offsets and lengths. Sized to
  ! surface the trailing-bytes-after-terminator decoder path with the
  ! minimum payload that produces two chunks.
  subroutine build_two_chunk_wire(ns, ds, ss, mac, ct_buf, ct_len,      &
                                     offsets, lens)
    type(itb_seed_t), intent(in) :: ns, ds, ss
    type(itb_mac_t),  intent(in) :: mac
    integer(itb_byte_kind), target, allocatable, intent(out) :: ct_buf(:)
    integer(itb_size_kind), intent(out) :: ct_len
    integer(itb_size_kind), intent(out) :: offsets(2), lens(2)
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_size_kind) :: header_size, cur, cl
    integer(itb_byte_kind), allocatable, target :: hdr(:)
    integer(itb_status_kind) :: rc
    integer(c_int) :: hsz_int
    integer :: i, k

    plaintext = pseudo_payload(int(SMALL_CHUNK) + 11)
    call encrypt_single(ns, ds, ss, mac, plaintext, SMALL_CHUNK,        &
                          ct_buf, ct_len)

    hsz_int = itb_header_size_c()
    call assert_true(TEST_NAME, "header_size positive", hsz_int > 0)
    header_size = int(hsz_int, itb_size_kind)
    allocate (hdr(int(header_size)))

    cur = 32_itb_size_kind
    do k = 1, 2
      offsets(k) = cur
      do i = 1, int(header_size)
        hdr(i) = ct_buf(int(cur) + i)
      end do
      cl = 0_itb_size_kind
      rc = itb_parse_chunk_len_c(c_loc(hdr), header_size, cl)
      call assert_status_ok(TEST_NAME, "parse_chunk_len", rc)
      lens(k) = cl
      cur = cur + cl
    end do
    call assert_size_eq(TEST_NAME, "wire walk consumes all bytes",       &
                         cur, ct_len)
  end subroutine

  subroutine test_auth_stream_after_final()
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: mac
    integer(itb_byte_kind), target, allocatable :: ct_buf(:)
    integer(itb_byte_kind), target, allocatable :: with_extra(:)
    integer(itb_byte_kind), target :: key(32)
    integer(itb_size_kind) :: ct_len, offsets(2), lens(2), extra_len, total_len
    integer(itb_status_kind) :: status
    integer :: i

    call make_key(key)
    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_mac(mac, "hmac-blake3", key)

    call build_two_chunk_wire(ns, ds, ss, mac, ct_buf, ct_len,          &
                                 offsets, lens)
    ! Append a duplicate of the terminator (chunk 1) past the
    ! terminating chunk. The decoder must observe the terminator and
    ! then surface STATUS_STREAM_AFTER_FINAL on the trailing bytes.
    extra_len = lens(2)
    total_len = ct_len + extra_len
    allocate (with_extra(int(total_len)))
    do i = 1, int(ct_len)
      with_extra(i) = ct_buf(i)
    end do
    do i = 1, int(extra_len)
      with_extra(int(ct_len) + i) = ct_buf(int(offsets(2)) + i)
    end do

    call decrypt_single_status(ns, ds, ss, mac, with_extra, total_len,  &
                                 SMALL_CHUNK, status)
    call assert_status_eq(TEST_NAME, "after-final -> STREAM_AFTER_FINAL",&
                           status, STATUS_STREAM_AFTER_FINAL)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call mac%destroy()
  end subroutine

end program test_streams_auth
