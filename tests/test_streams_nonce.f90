! test_streams_nonce.f90 -- streaming roundtrips across non-default
! nonce sizes.
!
! Mutates the process-global nonce_bits atomic to confirm the
! streaming path tracks the active nonce size on every chunk header.
! Per-binary process isolation gives this test program its own libitb
! global state, so the snapshot-and-restore discipline is internal
! hygiene rather than cross-test protection.

module test_streams_nonce_mod
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

end module test_streams_nonce_mod

program test_streams_nonce
  use, intrinsic :: iso_c_binding
  use itb_kinds
  use itb_seed
  use itb_streams
  use itb_library
  use itb_errors
  use test_streams_nonce_mod
  use itb_test_helpers
  implicit none

  character(*), parameter :: TEST_NAME = "test_streams_nonce"
  integer(itb_size_kind), parameter :: SMALL_CHUNK = 4096_itb_size_kind

  integer(itb_int32_kind) :: orig_nonce_bits

  orig_nonce_bits = itb_get_nonce_bits()

  call test_class_roundtrip_non_default_nonce_single()
  call test_encrypt_stream_across_nonce_sizes_single()
  call test_class_roundtrip_non_default_nonce_triple()
  call test_encrypt_stream_triple_across_nonce_sizes()

  call itb_set_nonce_bits(int(orig_nonce_bits))
  call test_pass(TEST_NAME)

contains

  function pseudo_payload(n) result(p)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    integer(c_int64_t) :: v
    allocate (p(n))
    do i = 1, n
      v = int(i - 1, c_int64_t) * 31_c_int64_t + 11_c_int64_t
      p(i) = int(iand(v, 255_c_int64_t), itb_byte_kind)
    end do
  end function

  subroutine roundtrip_single_for_nonce(plaintext, read_cap_enc, read_cap_dec)
    integer(itb_byte_kind), target, intent(in) :: plaintext(:)
    integer(itb_size_kind),         intent(in) :: read_cap_enc, read_cap_dec
    type(itb_seed_t) :: noise, dat, start
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
    call new_itb_seed(noise, "blake3", 1024)
    call new_itb_seed(dat,   "blake3", 1024)
    call new_itb_seed(start, "blake3", 1024)

    ct_cap = int(size(plaintext), itb_size_kind) * 4_itb_size_kind + &
              262144_itb_size_kind
    pt_cap = int(size(plaintext), itb_size_kind) + 1024_itb_size_kind
    allocate (ct_buf(ct_cap))
    allocate (pt_buf(pt_cap))

    src_pt%total = int(size(plaintext), c_size_t); src_pt%pos = 0
    src_pt%rcap = read_cap_enc; src_pt%data = c_loc(plaintext)
    sink_ct%cap = ct_cap; sink_ct%pos = 0; sink_ct%data = c_loc(ct_buf)
    call itb_stream_encrypt(noise, dat, start, &
                              rfn, c_loc(src_pt), wfn, c_loc(sink_ct), &
                              SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "encrypt non-default nonce", status)

    src_ct%total = sink_ct%pos; src_ct%pos = 0
    src_ct%rcap = read_cap_dec; src_ct%data = c_loc(ct_buf)
    sink_pt%cap = pt_cap; sink_pt%pos = 0; sink_pt%data = c_loc(pt_buf)
    call itb_stream_decrypt(noise, dat, start, &
                              rfn, c_loc(src_ct), wfn, c_loc(sink_pt), &
                              SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "decrypt non-default nonce", status)
    call assert_size_eq(TEST_NAME, "recovered length", sink_pt%pos, &
                         int(size(plaintext), itb_size_kind))

    allocate (pt_recovered(int(sink_pt%pos)))
    do i = 1, int(sink_pt%pos)
      pt_recovered(i) = pt_buf(i)
    end do
    call assert_bytes_eq(TEST_NAME, "single nonce roundtrip", &
                          pt_recovered, plaintext)
    call noise%destroy(); call dat%destroy(); call start%destroy()
  end subroutine

  subroutine roundtrip_triple_for_nonce(plaintext, read_cap_enc, read_cap_dec)
    integer(itb_byte_kind), target, intent(in) :: plaintext(:)
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

    src_pt%total = int(size(plaintext), c_size_t); src_pt%pos = 0
    src_pt%rcap = read_cap_enc; src_pt%data = c_loc(plaintext)
    sink_ct%cap = ct_cap; sink_ct%pos = 0; sink_ct%data = c_loc(ct_buf)
    call itb_stream_encrypt_triple(ns, d1, d2, d3, st1, st2, st3, &
                                     rfn, c_loc(src_pt), &
                                     wfn, c_loc(sink_ct), SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "triple encrypt non-default nonce", status)

    src_ct%total = sink_ct%pos; src_ct%pos = 0
    src_ct%rcap = read_cap_dec; src_ct%data = c_loc(ct_buf)
    sink_pt%cap = pt_cap; sink_pt%pos = 0; sink_pt%data = c_loc(pt_buf)
    call itb_stream_decrypt_triple(ns, d1, d2, d3, st1, st2, st3, &
                                     rfn, c_loc(src_ct), &
                                     wfn, c_loc(sink_pt), SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "triple decrypt non-default nonce", status)

    allocate (pt_recovered(int(sink_pt%pos)))
    do i = 1, int(sink_pt%pos)
      pt_recovered(i) = pt_buf(i)
    end do
    call assert_bytes_eq(TEST_NAME, "triple nonce roundtrip", &
                          pt_recovered, plaintext)

    call ns%destroy()
    call d1%destroy();  call d2%destroy();  call d3%destroy()
    call st1%destroy(); call st2%destroy(); call st3%destroy()
  end subroutine

  subroutine test_class_roundtrip_non_default_nonce_single()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer, parameter :: NONCES(2) = [256, 512]
    integer :: i

    plaintext = pseudo_payload(int(SMALL_CHUNK) * 3 + 100)
    do i = 1, size(NONCES)
      call itb_set_nonce_bits(NONCES(i))
      call roundtrip_single_for_nonce(plaintext, &
                                       1000_itb_size_kind, 0_itb_size_kind)
    end do
  end subroutine

  subroutine test_encrypt_stream_across_nonce_sizes_single()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer, parameter :: NONCES(3) = [128, 256, 512]
    integer :: i

    plaintext = pseudo_payload(int(SMALL_CHUNK) * 3 + 256)
    do i = 1, size(NONCES)
      call itb_set_nonce_bits(NONCES(i))
      call roundtrip_single_for_nonce(plaintext, &
                                       0_itb_size_kind, 0_itb_size_kind)
    end do
  end subroutine

  subroutine test_class_roundtrip_non_default_nonce_triple()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer, parameter :: NONCES(2) = [256, 512]
    integer :: i

    plaintext = pseudo_payload(int(SMALL_CHUNK) * 3)
    do i = 1, size(NONCES)
      call itb_set_nonce_bits(NONCES(i))
      call roundtrip_triple_for_nonce(plaintext, &
                                       1024_itb_size_kind, 0_itb_size_kind)
    end do
  end subroutine

  subroutine test_encrypt_stream_triple_across_nonce_sizes()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer, parameter :: NONCES(3) = [128, 256, 512]
    integer :: i

    plaintext = pseudo_payload(int(SMALL_CHUNK) * 3 + 100)
    do i = 1, size(NONCES)
      call itb_set_nonce_bits(NONCES(i))
      call roundtrip_triple_for_nonce(plaintext, &
                                       0_itb_size_kind, 0_itb_size_kind)
    end do
  end subroutine

end program test_streams_nonce
