! test_easy_streams.f90 -- streaming-style use of the high-level Easy
! Mode encryptor surface.
!
! Mirrors the C binding's test_easy_streams.c one-to-one. The Easy
! API does NOT expose dedicated stream helpers -- streaming over the
! Encryptor lives entirely on the binding-side: the consumer slices
! plaintext into chunks of the desired size and calls enc%encrypt
! per chunk; the decrypt side walks the concatenated chunk stream by
! reading enc%header_size() bytes, calling enc%parse_chunk_len() to
! learn the chunk's body length, and decrypting one whole chunk at
! a time.
!
! This file therefore differs from test_streams.f90 (Phase 5B), which
! exercises the seed-based itb_stream_encrypt / itb_stream_decrypt
! surface. The two surfaces are independent: test_streams.f90 covers
! the one-shot read_fn / write_fn callback pair; this file covers the
! Encryptor-driven chunk loop. Triple Ouroboros (mode = 3) and non-
! default nonce-bits configurations are covered explicitly so a
! regression in enc%header_size / enc%parse_chunk_len surfaces here.

program test_easy_streams
  use, intrinsic :: iso_c_binding
  use itb_kinds
  use itb_test_helpers
  use itb_encryptor
  use itb_errors
  use itb_sys, only: itb_easy_parse_chunk_len_c
  implicit none

  character(*), parameter :: TEST_NAME = "test_easy_streams"
  integer(itb_size_kind), parameter :: SMALL_CHUNK = 4096_itb_size_kind

  call test_roundtrip_default_nonce_single()
  call test_roundtrip_non_default_nonce_single()
  call test_triple_roundtrip_default_nonce()
  call test_triple_roundtrip_non_default_nonce()
  call test_partial_chunk_raises()
  call test_parse_chunk_len_short_buffer()
  call test_parse_chunk_len_zero_dim()

  call test_pass(TEST_NAME)

contains

  function token_bytes(n) result(p)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    integer(c_int64_t) :: v
    allocate (p(n))
    do i = 1, n
      v = int(i - 1, c_int64_t) * 71_c_int64_t + 31_c_int64_t
      p(i) = int(iand(v, 255_c_int64_t), itb_byte_kind)
    end do
  end function

  ! Encrypts plaintext chunk-by-chunk through enc%encrypt and returns
  ! the concatenated ciphertext stream. Uses a generous upper-bound
  ! pre-allocation (4x payload + 256 KiB) to avoid repeated re-grows
  ! on each chunk.
  subroutine stream_encrypt(enc, plaintext, chunk_size, out)
    class(itb_encryptor_t),                intent(in)  :: enc
    integer(itb_byte_kind), target,         intent(in)  :: plaintext(:)
    integer(itb_size_kind),                 intent(in)  :: chunk_size
    integer(itb_byte_kind), allocatable,    intent(out) :: out(:)
    integer(itb_byte_kind), allocatable :: scratch(:)
    integer(itb_byte_kind), allocatable :: chunk_pt(:)
    integer(itb_byte_kind), allocatable :: ct(:)
    integer :: i, end_pos, chunk_len, total_size, j, cap

    cap = size(plaintext) * 4 + 262144
    allocate (scratch(cap))

    total_size = 0
    i = 1
    do while (i <= size(plaintext))
      end_pos = i + int(chunk_size) - 1
      if (end_pos > size(plaintext)) end_pos = size(plaintext)
      chunk_len = end_pos - i + 1
      if (allocated(chunk_pt)) deallocate (chunk_pt)
      allocate (chunk_pt(chunk_len))
      do j = 1, chunk_len
        chunk_pt(j) = plaintext(i + j - 1)
      end do
      ct = enc%encrypt(chunk_pt)
      do j = 1, size(ct)
        scratch(total_size + j) = ct(j)
      end do
      total_size = total_size + size(ct)
      i = end_pos + 1
    end do

    allocate (out(total_size))
    do j = 1, total_size
      out(j) = scratch(j)
    end do
  end subroutine

  ! Drains the concatenated ciphertext stream chunk-by-chunk and
  ! returns the recovered plaintext. Sets `trailing` = .true. when
  ! the stream ends with a partial chunk.
  subroutine stream_decrypt(enc, ciphertext, out, trailing)
    class(itb_encryptor_t),                intent(in)  :: enc
    integer(itb_byte_kind), target,         intent(in)  :: ciphertext(:)
    integer(itb_byte_kind), allocatable,    intent(out) :: out(:)
    logical,                                intent(out) :: trailing
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable, target :: chunk_buf(:)
    integer(itb_byte_kind), target, allocatable :: header(:)
    integer(itb_byte_kind), target, allocatable :: scratch(:)
    integer(itb_int32_kind) :: hs
    integer(itb_size_kind)  :: chunk_len
    integer :: header_size, i, j, ct_len, total_pt, cap

    trailing = .false.
    hs = enc%header_size()
    header_size = int(hs)
    ct_len = size(ciphertext)

    cap = ct_len + 1024
    allocate (scratch(cap))
    total_pt = 0

    i = 1
    do while (i <= ct_len)
      if (ct_len - i + 1 < header_size) then
        trailing = .true.
        return
      end if
      if (allocated(header)) deallocate (header)
      allocate (header(header_size))
      do j = 1, header_size
        header(j) = ciphertext(i + j - 1)
      end do
      chunk_len = enc%parse_chunk_len(header)
      if (int(chunk_len) > ct_len - i + 1) then
        trailing = .true.
        return
      end if
      if (allocated(chunk_buf)) deallocate (chunk_buf)
      allocate (chunk_buf(int(chunk_len)))
      do j = 1, int(chunk_len)
        chunk_buf(j) = ciphertext(i + j - 1)
      end do
      pt = enc%decrypt(chunk_buf)
      do j = 1, size(pt)
        scratch(total_pt + j) = pt(j)
      end do
      total_pt = total_pt + size(pt)
      i = i + int(chunk_len)
    end do

    allocate (out(total_pt))
    do j = 1, total_pt
      out(j) = scratch(j)
    end do
  end subroutine

  subroutine test_roundtrip_default_nonce_single()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    logical :: trailing

    plaintext = token_bytes(int(SMALL_CHUNK) * 5 + 17)
    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    call stream_encrypt(enc, plaintext, SMALL_CHUNK, ct)
    call stream_decrypt(enc, ct, pt, trailing)
    call assert_false(TEST_NAME, "single trailing", trailing)
    call assert_bytes_eq(TEST_NAME, "single stream roundtrip", pt, plaintext)
    call enc%destroy()
  end subroutine

  subroutine test_roundtrip_non_default_nonce_single()
    integer, parameter :: NONCES(2) = [256, 512]
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    logical :: trailing
    integer :: k

    plaintext = token_bytes(int(SMALL_CHUNK) * 3 + 100)
    do k = 1, size(NONCES)
      call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
      call enc%set_nonce_bits(NONCES(k))
      call stream_encrypt(enc, plaintext, SMALL_CHUNK, ct)
      call stream_decrypt(enc, ct, pt, trailing)
      call assert_false(TEST_NAME, "single non-default trailing", trailing)
      call assert_bytes_eq(TEST_NAME, "single non-default roundtrip", &
                            pt, plaintext)
      call enc%destroy()
    end do
  end subroutine

  subroutine test_triple_roundtrip_default_nonce()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    logical :: trailing

    plaintext = token_bytes(int(SMALL_CHUNK) * 4 + 33)
    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 3)
    call stream_encrypt(enc, plaintext, SMALL_CHUNK, ct)
    call stream_decrypt(enc, ct, pt, trailing)
    call assert_false(TEST_NAME, "triple trailing", trailing)
    call assert_bytes_eq(TEST_NAME, "triple stream roundtrip", pt, plaintext)
    call enc%destroy()
  end subroutine

  subroutine test_triple_roundtrip_non_default_nonce()
    integer, parameter :: NONCES(2) = [256, 512]
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    logical :: trailing
    integer :: k

    plaintext = token_bytes(int(SMALL_CHUNK) * 3)
    do k = 1, size(NONCES)
      call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 3)
      call enc%set_nonce_bits(NONCES(k))
      call stream_encrypt(enc, plaintext, SMALL_CHUNK, ct)
      call stream_decrypt(enc, ct, pt, trailing)
      call assert_false(TEST_NAME, "triple non-default trailing", trailing)
      call assert_bytes_eq(TEST_NAME, "triple non-default roundtrip", &
                            pt, plaintext)
      call enc%destroy()
    end do
  end subroutine

  subroutine test_partial_chunk_raises()
    ! Feeding only a partial chunk to the streaming decoder must
    ! surface as a trailing-bytes failure on close.
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), allocatable :: ct(:)
    integer(itb_byte_kind), target, allocatable :: short_ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    logical :: trailing
    integer :: i

    allocate (plaintext(100))
    do i = 1, 100
      plaintext(i) = int(iachar('x'), itb_byte_kind)
    end do

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    call stream_encrypt(enc, plaintext, SMALL_CHUNK, ct)

    ! Feed only 30 bytes -- header complete (>= 20) but body
    ! truncated. The drain loop must report a trailing partial chunk.
    allocate (short_ct(30))
    do i = 1, 30
      short_ct(i) = ct(i)
    end do
    call stream_decrypt(enc, short_ct, pt, trailing)
    call assert_true(TEST_NAME, "partial-chunk trailing", trailing)

    call enc%destroy()
  end subroutine

  subroutine test_parse_chunk_len_short_buffer()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: short_buf(:)
    integer(itb_int32_kind) :: hs
    integer(itb_size_kind)  :: out_chunk
    integer(itb_status_kind) :: rc

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    hs = enc%header_size()
    allocate (short_buf(int(hs) - 1))
    short_buf(:) = 0_itb_byte_kind

    out_chunk = 0_itb_size_kind
    rc = itb_easy_parse_chunk_len_c(enc%raw_handle(),                            &
                                      c_loc(short_buf),                          &
                                      int(size(short_buf), itb_size_kind),       &
                                      out_chunk)
    call assert_status_eq(TEST_NAME, "short-buffer rejected", rc, STATUS_BAD_INPUT)
    call enc%destroy()
  end subroutine

  subroutine test_parse_chunk_len_zero_dim()
    ! A header_size byte buffer of all zeros encodes width = 0;
    ! parse_chunk_len must reject.
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: hdr(:)
    integer(itb_int32_kind) :: hs
    integer(itb_size_kind)  :: out_chunk
    integer(itb_status_kind) :: rc

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    hs = enc%header_size()
    allocate (hdr(int(hs)))
    hdr(:) = 0_itb_byte_kind

    out_chunk = 0_itb_size_kind
    rc = itb_easy_parse_chunk_len_c(enc%raw_handle(),                            &
                                      c_loc(hdr),                                &
                                      int(size(hdr), itb_size_kind),             &
                                      out_chunk)
    call assert_true(TEST_NAME, "zero-dim header rejected", rc /= STATUS_OK)
    call enc%destroy()
  end subroutine

end program test_easy_streams
