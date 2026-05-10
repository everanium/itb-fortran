! test_easy_streams_auth.f90 -- encryptor-bound Streaming AEAD
! round-trip + tamper detection via itb_encryptor_stream_encrypt_auth
! and itb_encryptor_stream_decrypt_auth.
!
! Mirrors bindings/c/tests/test_easy_streams_auth.c on the Fortran
! surface. The encryptor's bound MAC closure is reused across every
! chunk; the helper supplies the Streaming AEAD binding components
! internally. Closed-state preflight surfaces as STATUS_EASY_CLOSED.

module test_easy_streams_auth_mod
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

end module test_easy_streams_auth_mod

program test_easy_streams_auth
  use, intrinsic :: iso_c_binding
  use itb_kinds
  use itb_encryptor
  use itb_streams
  use itb_errors
  use itb_library, only: itb_set_nonce_bits, itb_get_nonce_bits
  use itb_sys, only: itb_easy_parse_chunk_len_c
  use test_easy_streams_auth_mod
  use itb_test_helpers
  implicit none

  character(*), parameter :: TEST_NAME = "test_easy_streams_auth"
  integer(itb_size_kind), parameter :: SMALL_CHUNK = 4096_itb_size_kind

  call test_easy_auth_single_roundtrip_default()
  call test_easy_auth_triple_roundtrip()
  call test_easy_auth_empty_stream()
  call test_easy_auth_truncate_tail()
  call test_easy_auth_closed_encryptor_preflight()
  call test_easy_auth_chunk_size_zero_rejected()
  call test_easy_auth_stream_prefix_tamper()
  call test_easy_auth_roundtrip_non_default_nonce_single()
  call test_easy_auth_roundtrip_non_default_nonce_triple()
  call test_easy_auth_roundtrip_global_diverges_from_instance()

  call test_pass(TEST_NAME)

contains

  function pseudo_payload(n) result(p)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    integer(c_int64_t) :: v
    allocate (p(max(n, 1)))
    do i = 1, n
      v = iand(int(i - 1, c_int64_t) * 31_c_int64_t + 17_c_int64_t,      &
                255_c_int64_t)
      if (v >= 128_c_int64_t) then
        p(i) = int(v - 256_c_int64_t, itb_byte_kind)
      else
        p(i) = int(v, itb_byte_kind)
      end if
    end do
  end function

  ! Builds a paired pair of encryptors over the same primitive / mode
  ! / MAC + key material via export -> import on a sibling instance.
  subroutine make_paired(primitive, key_bits, mac_name, mode, e, sib)
    character(*),    intent(in)  :: primitive, mac_name
    integer,         intent(in)  :: key_bits, mode
    type(itb_encryptor_t), intent(out) :: e, sib
    integer(itb_byte_kind), allocatable :: blob(:)

    call new_itb_encryptor(e,   primitive, key_bits, mac_name, mode)
    blob = e%export_state()
    call new_itb_encryptor(sib, primitive, key_bits, mac_name, mode)
    call sib%import_state(blob)
  end subroutine

  subroutine roundtrip_easy(plaintext, mac_name, mode, chunk_size)
    integer(itb_byte_kind), target, intent(in) :: plaintext(:)
    character(*),                   intent(in) :: mac_name
    integer,                        intent(in) :: mode
    integer(itb_size_kind),         intent(in) :: chunk_size
    type(itb_encryptor_t) :: e, sib
    type(src_t),  target :: src_pt, src_ct
    type(sink_t), target :: sink_ct, sink_pt
    integer(itb_byte_kind), target, allocatable :: ct_buf(:), pt_buf(:)
    integer(itb_byte_kind), allocatable :: pt_recovered(:)
    integer(itb_size_kind) :: ct_cap, pt_cap
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_status_kind) :: status
    integer :: i

    rfn => src_read
    wfn => sink_write

    call make_paired("blake3", 1024, mac_name, mode, e, sib)

    ct_cap = int(size(plaintext), itb_size_kind) * 6_itb_size_kind +    &
              262144_itb_size_kind
    pt_cap = int(size(plaintext), itb_size_kind) + 1024_itb_size_kind
    allocate (ct_buf(ct_cap))
    allocate (pt_buf(pt_cap))

    src_pt%total = int(size(plaintext), c_size_t)
    src_pt%pos = 0; src_pt%data = c_loc(plaintext)
    sink_ct%cap = ct_cap; sink_ct%pos = 0; sink_ct%data = c_loc(ct_buf)
    call itb_encryptor_stream_encrypt_auth(e,                            &
                                              rfn, c_loc(src_pt),         &
                                              wfn, c_loc(sink_ct),         &
                                              chunk_size, status)
    call assert_status_ok(TEST_NAME, "encryptor_stream_encrypt_auth",    &
                           status)

    src_ct%total = sink_ct%pos; src_ct%pos = 0; src_ct%data = c_loc(ct_buf)
    sink_pt%cap = pt_cap; sink_pt%pos = 0; sink_pt%data = c_loc(pt_buf)
    call itb_encryptor_stream_decrypt_auth(sib,                          &
                                              rfn, c_loc(src_ct),         &
                                              wfn, c_loc(sink_pt),         &
                                              chunk_size, status)
    call assert_status_ok(TEST_NAME, "encryptor_stream_decrypt_auth",    &
                           status)
    call assert_size_eq(TEST_NAME, "easy auth recovered length",         &
                         sink_pt%pos, int(size(plaintext), itb_size_kind))

    allocate (pt_recovered(int(sink_pt%pos)))
    do i = 1, int(sink_pt%pos)
      pt_recovered(i) = pt_buf(i)
    end do
    call assert_bytes_eq(TEST_NAME, "easy auth roundtrip",                &
                          pt_recovered, plaintext)

    call e%destroy()
    call sib%destroy()
  end subroutine

  subroutine test_easy_auth_single_roundtrip_default()
    integer(itb_byte_kind), target, allocatable :: pt(:)
    pt = pseudo_payload(int(SMALL_CHUNK) * 3 + 13)
    call roundtrip_easy(pt, "", 1, SMALL_CHUNK)
  end subroutine

  subroutine test_easy_auth_triple_roundtrip()
    integer(itb_byte_kind), target, allocatable :: pt(:)
    pt = pseudo_payload(int(SMALL_CHUNK) * 2 + 47)
    call roundtrip_easy(pt, "kmac256", 3, SMALL_CHUNK)
  end subroutine

  subroutine test_easy_auth_empty_stream()
    type(itb_encryptor_t) :: e, sib
    type(src_t),  target :: src_pt, src_ct
    type(sink_t), target :: sink_ct, sink_pt
    integer(itb_byte_kind), target, allocatable :: ct_buf(:), pt_buf(:)
    integer(itb_byte_kind), target :: dummy(1)
    integer(itb_size_kind) :: ct_cap, pt_cap
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_status_kind) :: status

    rfn => src_read
    wfn => sink_write

    call make_paired("blake3", 1024, "", 1, e, sib)

    ct_cap = 65536_itb_size_kind
    pt_cap = 1024_itb_size_kind
    allocate (ct_buf(ct_cap))
    allocate (pt_buf(pt_cap))

    src_pt%total = 0; src_pt%pos = 0; src_pt%data = c_loc(dummy)
    sink_ct%cap = ct_cap; sink_ct%pos = 0; sink_ct%data = c_loc(ct_buf)
    call itb_encryptor_stream_encrypt_auth(e, rfn, c_loc(src_pt),        &
                                              wfn, c_loc(sink_ct),       &
                                              SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "easy empty encrypt", status)
    call assert_true(TEST_NAME, "easy empty emits prefix + chunk",      &
                       sink_ct%pos > 32_c_size_t)

    src_ct%total = sink_ct%pos; src_ct%pos = 0; src_ct%data = c_loc(ct_buf)
    sink_pt%cap = pt_cap; sink_pt%pos = 0; sink_pt%data = c_loc(pt_buf)
    call itb_encryptor_stream_decrypt_auth(sib, rfn, c_loc(src_ct),      &
                                              wfn, c_loc(sink_pt),       &
                                              SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "easy empty decrypt", status)
    call assert_size_eq(TEST_NAME, "easy empty recovered length",        &
                         sink_pt%pos, 0_itb_size_kind)

    call e%destroy()
    call sib%destroy()
  end subroutine

  subroutine test_easy_auth_truncate_tail()
    type(itb_encryptor_t) :: e, sib
    type(src_t),  target :: src_pt, src_ct
    type(sink_t), target :: sink_ct, sink_pt
    integer(itb_byte_kind), target, allocatable :: pt(:)
    integer(itb_byte_kind), target, allocatable :: ct_buf(:), pt_buf(:)
    integer(itb_byte_kind), allocatable :: hdr(:)
    integer(itb_size_kind) :: ct_cap, pt_cap, header_size, cur, cl
    integer(itb_size_kind) :: truncated_len
    integer :: hsz_int_local
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_status_kind) :: status
    integer :: i, k

    rfn => src_read
    wfn => sink_write

    call make_paired("blake3", 1024, "", 1, e, sib)
    pt = pseudo_payload(int(SMALL_CHUNK) * 3 - 5)

    ct_cap = int(size(pt), itb_size_kind) * 6_itb_size_kind +           &
              262144_itb_size_kind
    pt_cap = int(size(pt), itb_size_kind) + 1024_itb_size_kind
    allocate (ct_buf(ct_cap))
    allocate (pt_buf(pt_cap))

    src_pt%total = int(size(pt), c_size_t); src_pt%pos = 0
    src_pt%data = c_loc(pt)
    sink_ct%cap = ct_cap; sink_ct%pos = 0; sink_ct%data = c_loc(ct_buf)
    call itb_encryptor_stream_encrypt_auth(e, rfn, c_loc(src_pt),        &
                                              wfn, c_loc(sink_ct),       &
                                              SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "easy encrypt for truncate", status)

    hsz_int_local = e%header_size()
    header_size = int(hsz_int_local, itb_size_kind)
    allocate (hdr(int(header_size)))

    ! Walk the wire: skip 32-byte stream_id prefix, then 2 chunks; the
    ! third chunk is the terminating chunk.
    cur = 32_itb_size_kind
    do k = 1, 2
      do i = 1, int(header_size)
        hdr(i) = ct_buf(int(cur) + i)
      end do
      cl = e%parse_chunk_len(hdr)
      cur = cur + cl
    end do
    truncated_len = cur

    src_ct%total = truncated_len; src_ct%pos = 0; src_ct%data = c_loc(ct_buf)
    sink_pt%cap = pt_cap; sink_pt%pos = 0; sink_pt%data = c_loc(pt_buf)
    call itb_encryptor_stream_decrypt_auth(sib, rfn, c_loc(src_ct),      &
                                              wfn, c_loc(sink_pt),       &
                                              SMALL_CHUNK, status)
    call assert_status_eq(TEST_NAME, "easy truncate -> STREAM_TRUNCATED",&
                           status, STATUS_STREAM_TRUNCATED)

    call e%destroy()
    call sib%destroy()
  end subroutine

  subroutine test_easy_auth_closed_encryptor_preflight()
    type(itb_encryptor_t) :: e
    type(src_t),  target :: src
    type(sink_t), target :: snk
    integer(itb_byte_kind), target :: dummy(1)
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_status_kind) :: status

    rfn => src_read
    wfn => sink_write

    call new_itb_encryptor(e, "blake3", 1024, "", 1)
    call e%destroy()  ! closes + frees in one shot

    src%total = 0; src%pos = 0; src%data = c_loc(dummy)
    snk%cap = 0;   snk%pos = 0;            snk%data = c_loc(dummy)

    call itb_encryptor_stream_encrypt_auth(e, rfn, c_loc(src),           &
                                              wfn, c_loc(snk),           &
                                              SMALL_CHUNK, status)
    call assert_status_eq(TEST_NAME, "closed -> EASY_CLOSED (encrypt)", &
                           status, STATUS_EASY_CLOSED)

    call itb_encryptor_stream_decrypt_auth(e, rfn, c_loc(src),           &
                                              wfn, c_loc(snk),           &
                                              SMALL_CHUNK, status)
    call assert_status_eq(TEST_NAME, "closed -> EASY_CLOSED (decrypt)", &
                           status, STATUS_EASY_CLOSED)
  end subroutine

  subroutine test_easy_auth_chunk_size_zero_rejected()
    type(itb_encryptor_t) :: e
    type(src_t),  target :: src
    type(sink_t), target :: snk
    integer(itb_byte_kind), target :: dummy(1)
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_status_kind) :: status

    rfn => src_read
    wfn => sink_write

    call new_itb_encryptor(e, "blake3", 1024, "", 1)

    src%total = 0; src%pos = 0; src%data = c_loc(dummy)
    snk%cap = 0;   snk%pos = 0;            snk%data = c_loc(dummy)

    call itb_encryptor_stream_encrypt_auth(e, rfn, c_loc(src),           &
                                              wfn, c_loc(snk),           &
                                              0_itb_size_kind, status)
    call assert_status_eq(TEST_NAME, "easy chunk_size=0 rejected",       &
                           status, STATUS_BAD_INPUT)

    call e%destroy()
  end subroutine

  subroutine test_easy_auth_stream_prefix_tamper()
    type(itb_encryptor_t) :: e, sib
    type(src_t),  target :: src_pt, src_ct
    type(sink_t), target :: sink_ct, sink_pt
    integer(itb_byte_kind), target, allocatable :: pt(:)
    integer(itb_byte_kind), target, allocatable :: ct_buf(:), pt_buf(:)
    integer(itb_size_kind) :: ct_cap, pt_cap
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_status_kind) :: status

    rfn => src_read
    wfn => sink_write

    call make_paired("blake3", 1024, "", 1, e, sib)
    pt = pseudo_payload(500)

    ct_cap = 65536_itb_size_kind
    pt_cap = int(size(pt), itb_size_kind) + 1024_itb_size_kind
    allocate (ct_buf(ct_cap))
    allocate (pt_buf(pt_cap))

    src_pt%total = int(size(pt), c_size_t); src_pt%pos = 0
    src_pt%data = c_loc(pt)
    sink_ct%cap = ct_cap; sink_ct%pos = 0; sink_ct%data = c_loc(ct_buf)
    call itb_encryptor_stream_encrypt_auth(e, rfn, c_loc(src_pt),        &
                                              wfn, c_loc(sink_ct),       &
                                              SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "easy encrypt for tamper", status)

    ! Flip a byte inside the 32-byte stream_id prefix.
    ct_buf(11) = ieor(ct_buf(11), int(z'33', itb_byte_kind))

    src_ct%total = sink_ct%pos; src_ct%pos = 0; src_ct%data = c_loc(ct_buf)
    sink_pt%cap = pt_cap; sink_pt%pos = 0; sink_pt%data = c_loc(pt_buf)
    call itb_encryptor_stream_decrypt_auth(sib, rfn, c_loc(src_ct),      &
                                              wfn, c_loc(sink_pt),       &
                                              SMALL_CHUNK, status)
    call assert_status_eq(TEST_NAME, "easy prefix tamper -> MAC fail",   &
                           status, STATUS_MAC_FAILURE)

    call e%destroy()
    call sib%destroy()
  end subroutine

  ! Regression: per-instance nonce_bits must drive the auth-stream
  ! decoder's chunk-length parse, not the process-global setting.
  ! run_paired_auth_roundtrip_nonce_bits exercises encrypt + decrypt
  ! with a paired pair of encryptors at the requested per-instance
  ! nonce-bits value, over a multi-chunk plaintext.
  subroutine run_paired_auth_roundtrip_nonce_bits(nonce_bits, mode,    &
                                                    mac_name)
    integer,      intent(in) :: nonce_bits, mode
    character(*), intent(in) :: mac_name
    type(itb_encryptor_t) :: e, sib
    type(src_t),  target :: src_pt, src_ct
    type(sink_t), target :: sink_ct, sink_pt
    integer(itb_byte_kind), target, allocatable :: pt(:)
    integer(itb_byte_kind), target, allocatable :: ct_buf(:), pt_buf(:)
    integer(itb_byte_kind), allocatable :: blob(:), pt_recovered(:)
    integer(itb_size_kind) :: ct_cap, pt_cap
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_status_kind) :: status
    integer :: i, pt_len

    rfn => src_read
    wfn => sink_write

    call new_itb_encryptor(e,   "blake3", 1024, mac_name, mode)
    call e%set_nonce_bits(nonce_bits)
    blob = e%export_state()
    call new_itb_encryptor(sib, "blake3", 1024, mac_name, mode)
    call sib%set_nonce_bits(nonce_bits)
    call sib%import_state(blob)

    ! ~96 KiB plaintext -> multi-chunk wire at SMALL_CHUNK = 4096.
    pt_len = int(SMALL_CHUNK) * 24 + 17
    pt = pseudo_payload(pt_len)

    ct_cap = int(pt_len, itb_size_kind) * 6_itb_size_kind +              &
              262144_itb_size_kind
    pt_cap = int(pt_len, itb_size_kind) + 1024_itb_size_kind
    allocate (ct_buf(ct_cap))
    allocate (pt_buf(pt_cap))

    src_pt%total = int(pt_len, c_size_t); src_pt%pos = 0
    src_pt%data = c_loc(pt)
    sink_ct%cap = ct_cap; sink_ct%pos = 0; sink_ct%data = c_loc(ct_buf)
    call itb_encryptor_stream_encrypt_auth(e, rfn, c_loc(src_pt),         &
                                              wfn, c_loc(sink_ct),         &
                                              SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "non-default nonce_bits encrypt",   &
                           status)

    src_ct%total = sink_ct%pos; src_ct%pos = 0; src_ct%data = c_loc(ct_buf)
    sink_pt%cap = pt_cap; sink_pt%pos = 0; sink_pt%data = c_loc(pt_buf)
    call itb_encryptor_stream_decrypt_auth(sib, rfn, c_loc(src_ct),       &
                                              wfn, c_loc(sink_pt),         &
                                              SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "non-default nonce_bits decrypt",   &
                           status)
    call assert_size_eq(TEST_NAME, "non-default nonce_bits length",      &
                         sink_pt%pos, int(pt_len, itb_size_kind))

    allocate (pt_recovered(int(sink_pt%pos)))
    do i = 1, int(sink_pt%pos)
      pt_recovered(i) = pt_buf(i)
    end do
    call assert_bytes_eq(TEST_NAME, "non-default nonce_bits roundtrip",  &
                          pt_recovered, pt)

    call e%destroy()
    call sib%destroy()
  end subroutine

  subroutine test_easy_auth_roundtrip_non_default_nonce_single()
    integer :: nbs(2), k
    nbs = [256, 512]
    do k = 1, 2
      call run_paired_auth_roundtrip_nonce_bits(nbs(k), 1, "")
    end do
  end subroutine

  subroutine test_easy_auth_roundtrip_non_default_nonce_triple()
    integer :: nbs(2), k
    nbs = [256, 512]
    do k = 1, 2
      call run_paired_auth_roundtrip_nonce_bits(nbs(k), 3, "kmac256")
    end do
  end subroutine

  ! Pointed regression: pin the process-global at 128 (default) and
  ! flip the per-instance value to 512. Decryption must still succeed;
  ! if the auth-stream parser silently consults the global, chunk_len
  ! mismatches and the round-trip fails.
  subroutine test_easy_auth_roundtrip_global_diverges_from_instance()
    type(itb_encryptor_t) :: e, sib
    type(src_t),  target :: src_pt, src_ct
    type(sink_t), target :: sink_ct, sink_pt
    integer(itb_byte_kind), target, allocatable :: pt(:)
    integer(itb_byte_kind), target, allocatable :: ct_buf(:), pt_buf(:)
    integer(itb_byte_kind), allocatable :: blob(:), pt_recovered(:)
    integer(itb_size_kind) :: ct_cap, pt_cap
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer(itb_status_kind) :: status
    integer :: i, pt_len

    rfn => src_read
    wfn => sink_write

    call itb_set_nonce_bits(128)
    call assert_int_eq(TEST_NAME, "global pinned at 128",                &
                        itb_get_nonce_bits(), 128)

    call new_itb_encryptor(e,   "blake3", 1024, "", 1)
    call e%set_nonce_bits(512)
    blob = e%export_state()
    call new_itb_encryptor(sib, "blake3", 1024, "", 1)
    call sib%set_nonce_bits(512)
    call sib%import_state(blob)

    ! Per-instance set must not leak into the global.
    call assert_int_eq(TEST_NAME, "global still 128 after per-inst set", &
                        itb_get_nonce_bits(), 128)

    pt_len = int(SMALL_CHUNK) * 24 + 17
    pt = pseudo_payload(pt_len)

    ct_cap = int(pt_len, itb_size_kind) * 6_itb_size_kind +              &
              262144_itb_size_kind
    pt_cap = int(pt_len, itb_size_kind) + 1024_itb_size_kind
    allocate (ct_buf(ct_cap))
    allocate (pt_buf(pt_cap))

    src_pt%total = int(pt_len, c_size_t); src_pt%pos = 0
    src_pt%data = c_loc(pt)
    sink_ct%cap = ct_cap; sink_ct%pos = 0; sink_ct%data = c_loc(ct_buf)
    call itb_encryptor_stream_encrypt_auth(e, rfn, c_loc(src_pt),         &
                                              wfn, c_loc(sink_ct),         &
                                              SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "global divergence encrypt", status)

    src_ct%total = sink_ct%pos; src_ct%pos = 0; src_ct%data = c_loc(ct_buf)
    sink_pt%cap = pt_cap; sink_pt%pos = 0; sink_pt%data = c_loc(pt_buf)
    call itb_encryptor_stream_decrypt_auth(sib, rfn, c_loc(src_ct),       &
                                              wfn, c_loc(sink_pt),         &
                                              SMALL_CHUNK, status)
    call assert_status_ok(TEST_NAME, "global divergence decrypt", status)
    call assert_size_eq(TEST_NAME, "global divergence length",           &
                         sink_pt%pos, int(pt_len, itb_size_kind))

    allocate (pt_recovered(int(sink_pt%pos)))
    do i = 1, int(sink_pt%pos)
      pt_recovered(i) = pt_buf(i)
    end do
    call assert_bytes_eq(TEST_NAME, "global divergence roundtrip",       &
                          pt_recovered, pt)

    call e%destroy()
    call sib%destroy()
  end subroutine

end program test_easy_streams_auth
