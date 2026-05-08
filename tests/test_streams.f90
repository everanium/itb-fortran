! test_streams.f90 -- chunked encrypt / decrypt over caller-owned I/O.
!
! Exercises the free-function plain stream surface
! (`itb_stream_encrypt` / `itb_stream_decrypt`) and the Triple
! Ouroboros counterparts. The membuf-style read / write callbacks
! mirror the C binding's pattern: the source returns data in
! caller-controlled-size slices (so the chunk loop crosses chunk
! boundaries on multiple iterations) and the sink grows on demand.
!
! Truncated stream coverage: reading only a header-prefix from the
! ciphertext and signaling EOF surfaces STATUS_BAD_INPUT through the
! decrypt's `status` out-argument, matching the cross-binding contract.

module test_streams_mod
  use, intrinsic :: iso_c_binding
  use itb_kinds
  implicit none
  public

  ! In-memory ring source. Read advances the cursor by min(cap, avail).
  ! `read_cap` (when > 0) bounds each individual read to short-read
  ! shape so the chunk loop crosses chunk boundaries.
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

end module test_streams_mod

program test_streams
  use, intrinsic :: iso_c_binding
  use itb_kinds
  use itb_seed
  use itb_streams
  use itb_errors
  use test_streams_mod
  use itb_test_helpers
  implicit none

  character(*), parameter :: TEST_NAME = "test_streams"

  call test_chunk_size_zero_rejected()
  call test_single_roundtrip_200kb()
  call test_single_roundtrip_short_payload()
  call test_class_roundtrip_default_nonce()
  call test_encrypt_stream_decrypt_stream()
  call test_class_roundtrip_default_nonce_triple()
  call test_encrypt_stream_triple_decrypt_stream_triple()
  call test_partial_chunk_at_close_raises()

  call test_pass(TEST_NAME)

contains

  function pseudo_payload(n, salt) result(p)
    integer, intent(in) :: n, salt
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    integer(c_int64_t) :: v
    allocate (p(n))
    do i = 1, n
      v = int(i - 1, c_int64_t) * 13_c_int64_t + 11_c_int64_t + int(salt, c_int64_t)
      p(i) = int(iand(v, 255_c_int64_t), itb_byte_kind)
    end do
  end function

  function pseudo_plaintext(n) result(p)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    allocate (p(n))
    do i = 1, n
      p(i) = int(iand(int(i - 1, c_int64_t), 255_c_int64_t), itb_byte_kind)
    end do
  end function

  subroutine roundtrip_single(plaintext, chunk_size, read_cap_enc, read_cap_dec)
    integer(itb_byte_kind), target, intent(in) :: plaintext(:)
    integer(itb_size_kind),         intent(in) :: chunk_size
    integer(itb_size_kind),         intent(in) :: read_cap_enc, read_cap_dec
    type(itb_seed_t) :: ns, ds, ss
    type(src_t),     target :: src_pt, src_ct
    type(sink_t),    target :: sink_ct, sink_pt
    integer(itb_byte_kind), target, allocatable :: ct_buf(:)
    integer(itb_byte_kind), target, allocatable :: pt_buf(:)
    integer(itb_byte_kind), allocatable :: pt_recovered(:)
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_size_kind) :: ct_cap, pt_cap
    integer(itb_status_kind) :: status
    integer :: i

    rfn => src_read
    wfn => sink_write

    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)

    ! Generous ciphertext / plaintext sink capacity (header overhead +
    ! per-chunk container expansion is bounded above by a few KiB).
    ct_cap = int(size(plaintext), itb_size_kind) * 4_itb_size_kind + &
              262144_itb_size_kind
    pt_cap = int(size(plaintext), itb_size_kind) + 1024_itb_size_kind
    allocate (ct_buf(ct_cap))
    allocate (pt_buf(pt_cap))

    src_pt%total = int(size(plaintext), c_size_t)
    src_pt%pos   = 0_c_size_t
    src_pt%rcap  = read_cap_enc
    src_pt%data  = c_loc(plaintext)
    sink_ct%cap  = ct_cap
    sink_ct%pos  = 0_c_size_t
    sink_ct%data = c_loc(ct_buf)

    call itb_stream_encrypt(ns, ds, ss, &
                              rfn, c_loc(src_pt), &
                              wfn, c_loc(sink_ct), chunk_size, status)
    call assert_status_ok(TEST_NAME, "stream_encrypt", status)
    call assert_true(TEST_NAME, "ct produced", sink_ct%pos > 0_c_size_t)

    src_ct%total = sink_ct%pos
    src_ct%pos   = 0_c_size_t
    src_ct%rcap  = read_cap_dec
    src_ct%data  = c_loc(ct_buf)
    sink_pt%cap  = pt_cap
    sink_pt%pos  = 0_c_size_t
    sink_pt%data = c_loc(pt_buf)

    call itb_stream_decrypt(ns, ds, ss, &
                              rfn, c_loc(src_ct), &
                              wfn, c_loc(sink_pt), chunk_size, status)
    call assert_status_ok(TEST_NAME, "stream_decrypt", status)
    call assert_size_eq(TEST_NAME, "recovered length", sink_pt%pos, &
                         int(size(plaintext), itb_size_kind))

    allocate (pt_recovered(int(sink_pt%pos)))
    do i = 1, int(sink_pt%pos)
      pt_recovered(i) = pt_buf(i)
    end do
    call assert_bytes_eq(TEST_NAME, "stream roundtrip", pt_recovered, plaintext)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
  end subroutine

  subroutine roundtrip_triple(plaintext, chunk_size, read_cap_enc, read_cap_dec)
    integer(itb_byte_kind), target, intent(in) :: plaintext(:)
    integer(itb_size_kind),         intent(in) :: chunk_size
    integer(itb_size_kind),         intent(in) :: read_cap_enc, read_cap_dec
    type(itb_seed_t) :: ns, d1, d2, d3, st1, st2, st3
    type(src_t),     target :: src_pt, src_ct
    type(sink_t),    target :: sink_ct, sink_pt
    integer(itb_byte_kind), target, allocatable :: ct_buf(:)
    integer(itb_byte_kind), target, allocatable :: pt_buf(:)
    integer(itb_byte_kind), allocatable :: pt_recovered(:)
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_size_kind) :: ct_cap, pt_cap
    integer(itb_status_kind) :: status
    integer :: i

    rfn => src_read
    wfn => sink_write

    call new_itb_seed(ns,  "blake3", 1024)
    call new_itb_seed(d1,  "blake3", 1024)
    call new_itb_seed(d2,  "blake3", 1024)
    call new_itb_seed(d3,  "blake3", 1024)
    call new_itb_seed(st1, "blake3", 1024)
    call new_itb_seed(st2, "blake3", 1024)
    call new_itb_seed(st3, "blake3", 1024)

    ct_cap = int(size(plaintext), itb_size_kind) * 4_itb_size_kind + &
              262144_itb_size_kind
    pt_cap = int(size(plaintext), itb_size_kind) + 1024_itb_size_kind
    allocate (ct_buf(ct_cap))
    allocate (pt_buf(pt_cap))

    src_pt%total = int(size(plaintext), c_size_t)
    src_pt%pos   = 0_c_size_t
    src_pt%rcap  = read_cap_enc
    src_pt%data  = c_loc(plaintext)
    sink_ct%cap  = ct_cap
    sink_ct%pos  = 0_c_size_t
    sink_ct%data = c_loc(ct_buf)

    call itb_stream_encrypt_triple(ns, d1, d2, d3, st1, st2, st3, &
                                     rfn, c_loc(src_pt), &
                                     wfn, c_loc(sink_ct), chunk_size, status)
    call assert_status_ok(TEST_NAME, "stream_encrypt_triple", status)

    src_ct%total = sink_ct%pos
    src_ct%pos   = 0_c_size_t
    src_ct%rcap  = read_cap_dec
    src_ct%data  = c_loc(ct_buf)
    sink_pt%cap  = pt_cap
    sink_pt%pos  = 0_c_size_t
    sink_pt%data = c_loc(pt_buf)

    call itb_stream_decrypt_triple(ns, d1, d2, d3, st1, st2, st3, &
                                     rfn, c_loc(src_ct), &
                                     wfn, c_loc(sink_pt), chunk_size, status)
    call assert_status_ok(TEST_NAME, "stream_decrypt_triple", status)
    call assert_size_eq(TEST_NAME, "triple recovered length", sink_pt%pos, &
                         int(size(plaintext), itb_size_kind))

    allocate (pt_recovered(int(sink_pt%pos)))
    do i = 1, int(sink_pt%pos)
      pt_recovered(i) = pt_buf(i)
    end do
    call assert_bytes_eq(TEST_NAME, "triple stream roundtrip", &
                          pt_recovered, plaintext)

    call ns%destroy()
    call d1%destroy();  call d2%destroy();  call d3%destroy()
    call st1%destroy(); call st2%destroy(); call st3%destroy()
  end subroutine

  subroutine test_chunk_size_zero_rejected()
    type(itb_seed_t) :: ns, ds, ss
    type(src_t),  target :: src
    type(sink_t), target :: snk
    integer(itb_byte_kind), target :: dummy(1)
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_status_kind) :: status

    rfn => src_read
    wfn => sink_write

    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)

    src%total = 0; src%pos = 0; src%rcap = 0; src%data = c_loc(dummy)
    snk%cap = 0;   snk%pos = 0;               snk%data = c_loc(dummy)

    call itb_stream_encrypt(ns, ds, ss, rfn, c_loc(src), wfn, c_loc(snk), &
                              0_itb_size_kind, status)
    call assert_status_eq(TEST_NAME, "encrypt chunk_size=0 rejected", &
                           status, STATUS_BAD_INPUT)
    call itb_stream_decrypt(ns, ds, ss, rfn, c_loc(src), wfn, c_loc(snk), &
                              0_itb_size_kind, status)
    call assert_status_eq(TEST_NAME, "decrypt chunk_size=0 rejected", &
                           status, STATUS_BAD_INPUT)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
  end subroutine

  subroutine test_single_roundtrip_200kb()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    plaintext = pseudo_plaintext(200 * 1024)
    call roundtrip_single(plaintext, 65536_itb_size_kind, &
                            0_itb_size_kind, 4096_itb_size_kind)
  end subroutine

  subroutine test_single_roundtrip_short_payload()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    character(*), parameter :: PT_TEXT = &
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
    integer :: i
    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do
    call roundtrip_single(plaintext, 65536_itb_size_kind, &
                            0_itb_size_kind, 0_itb_size_kind)
  end subroutine

  subroutine test_class_roundtrip_default_nonce()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_size_kind), parameter :: SMALL_CHUNK = 4096_itb_size_kind
    plaintext = pseudo_payload(int(SMALL_CHUNK) * 5 + 17, 1)
    call roundtrip_single(plaintext, SMALL_CHUNK, &
                            1000_itb_size_kind, 1024_itb_size_kind)
  end subroutine

  subroutine test_encrypt_stream_decrypt_stream()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_size_kind), parameter :: SMALL_CHUNK = 4096_itb_size_kind
    plaintext = pseudo_payload(int(SMALL_CHUNK) * 4, 2)
    call roundtrip_single(plaintext, SMALL_CHUNK, &
                            0_itb_size_kind, 0_itb_size_kind)
  end subroutine

  subroutine test_class_roundtrip_default_nonce_triple()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_size_kind), parameter :: SMALL_CHUNK = 4096_itb_size_kind
    plaintext = pseudo_payload(int(SMALL_CHUNK) * 4 + 33, 3)
    call roundtrip_triple(plaintext, SMALL_CHUNK, &
                            1000_itb_size_kind, 0_itb_size_kind)
  end subroutine

  subroutine test_encrypt_stream_triple_decrypt_stream_triple()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_size_kind), parameter :: SMALL_CHUNK = 4096_itb_size_kind
    plaintext = pseudo_payload(int(SMALL_CHUNK) * 5 + 7, 4)
    call roundtrip_triple(plaintext, SMALL_CHUNK, &
                            0_itb_size_kind, 0_itb_size_kind)
  end subroutine

  subroutine test_partial_chunk_at_close_raises()
    type(itb_seed_t) :: ns, ds, ss
    type(src_t),     target :: src_pt, src_ct
    type(sink_t),    target :: sink_ct, sink_pt
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: ct_buf(:)
    integer(itb_byte_kind), target, allocatable :: pt_buf(:)
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_size_kind), parameter :: SMALL_CHUNK = 4096_itb_size_kind
    integer(itb_status_kind) :: status
    character(*), parameter :: PT_TEXT = &
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    integer :: i

    rfn => src_read
    wfn => sink_write

    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)

    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do
    allocate (ct_buf(8192))
    allocate (pt_buf(4096))

    src_pt%total = int(size(plaintext), c_size_t)
    src_pt%pos   = 0_c_size_t; src_pt%rcap = 0_c_size_t
    src_pt%data  = c_loc(plaintext)
    sink_ct%cap  = 8192_c_size_t; sink_ct%pos = 0_c_size_t
    sink_ct%data = c_loc(ct_buf)
    call itb_stream_encrypt(ns, ds, ss, &
                              rfn, c_loc(src_pt), wfn, c_loc(sink_ct), &
                              SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "encrypt for truncate setup", status)
    call assert_true(TEST_NAME, "ct produced > 30", sink_ct%pos > 30_c_size_t)

    ! Decrypt only the first 30 bytes -- header is complete (>= 20)
    ! but the body is truncated. The chunk loop reports STATUS_BAD_INPUT.
    src_ct%total = 30_c_size_t
    src_ct%pos   = 0_c_size_t; src_ct%rcap = 0_c_size_t
    src_ct%data  = c_loc(ct_buf)
    sink_pt%cap  = 4096_c_size_t; sink_pt%pos = 0_c_size_t
    sink_pt%data = c_loc(pt_buf)
    call itb_stream_decrypt(ns, ds, ss, &
                              rfn, c_loc(src_ct), wfn, c_loc(sink_pt), &
                              SMALL_CHUNK, status)
    call assert_status_eq(TEST_NAME, "truncated stream rejected", &
                           status, STATUS_BAD_INPUT)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
  end subroutine

end program test_streams
